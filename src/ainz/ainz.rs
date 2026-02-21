use std::{mem::*, ptr::*, thread, time};
use std::mem::offset_of;
use ntapi::ntapi_base::*;
use winapi::shared::ntdef::*;
use ntapi::ntexapi::*;
use ntapi::ntzwapi::*;
use ntapi::ntpebteb::{PEB, PPEB};
use ntapi::ntpsapi::{ProcessBasicInformation, ThreadQuerySetWin32StartAddress, PEB_LDR_DATA, PROCESS_BASIC_INFORMATION};
use ntapi::ntldr::{ LDR_DATA_TABLE_ENTRY };
use winapi::ctypes::{c_void};
use winapi::shared::minwindef::{DWORD, ULONG};
use winapi_comm::LoadLibraryA;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows_win::sys::LARGE_INTEGER;

#[macro_export]
macro_rules! nt_success {
    ($status:expr) => {
        $status >= 0
    };
}


#[repr(u8)]
pub enum UnlinkError {
    InvalidHandle,
    InvalidPPEB,
    InvalidPEB,
    InvalidLdr,
    FailedReadPEB,
    FailedReadLdr,
    FailedHideEntry,
    FailedInternalReadCurrent,
    FailedInternalReadDllBuffer,
    FailedInternalReadEntryAddress,
    FailedMutate
}

#[repr(u8)]
pub enum HideError {
    FailedReadCurrent,
    FailedReadEntryAddress,
    FailedReadDllBuffer,
    FailedInternalMutate
}

#[repr(u8)]
pub enum MutateError {
    FailedNullifyFullDllLen,
    FailedNullifyBaseDllLen,
    FailedNullifyDllBaseAddress,
    FailedUpdateFlink,
    FailedUpdateBlink,
    FailedNullifySelfFlink,
    FailedNullifySelfBlink
}


#[repr(u8)]
pub enum InjectMode {
    Native,
}


#[repr(u8)]
pub enum InjectMethod {
    ExistingProcess,
    WaitProcess,
    LaunchProcess
}


pub struct FnCtx {
    pub p_load_library: PVOID,
}

#[repr(C)]
pub struct LdrLoadDllArg {
    pub dll_path: PWSTR,
    pub dll_characteristics: ULONG,
    pub dll_name: PUNICODE_STRING,
    pub dll_proc_handle: HANDLE,
}

impl LdrLoadDllArg {
    pub fn new(dll_name: PUNICODE_STRING) -> Self {
        Self {
            dll_path: null_mut(), dll_characteristics: 0,
            dll_name, dll_proc_handle: null_mut()
        }
    }
}

pub struct AinzCtx {
    fn_ctx: FnCtx,
    saved_threads: Vec<HANDLE>,
    client_id: CLIENT_ID,
    proc_handle: HANDLE,
    main_thread_handle: HANDLE,
    pub pid: DWORD,
    pub tid: DWORD
}
impl AinzCtx {
    pub fn new() -> Self {
        unsafe {
            Self {
                fn_ctx: FnCtx { p_load_library: null_mut() },
                saved_threads: vec![], client_id: zeroed(), proc_handle: null_mut(), main_thread_handle: null_mut(),
                pid: 0, tid: 0
            }
        }
    }
}

pub struct Ainz {
    pub dlls: Vec<String>,
    pub target_proc_name: String,
    pub ainz_ctx: AinzCtx,
    pub delay_between: u64,
    pub inject_mode: InjectMode,
    pub inject_method: InjectMethod,
    pub is_unlink_module: bool
}

impl Ainz {
    pub unsafe fn init(&mut self) -> Result<(), NTSTATUS> {
        let sys_class: SYSTEM_INFORMATION_CLASS = SystemProcessInformation;
        let mut buffer_sz: ULONG = 1024 * 1024;
        let mut status: NTSTATUS;
        unsafe {
            let buffer = vec![0u8; buffer_sz as usize];
            status = ZwQuerySystemInformation(sys_class, buffer.as_ptr() as *mut c_void, buffer_sz, &mut buffer_sz);
            if !nt_success!(status) { return Err(status); }

            let mut p_process_info: PSYSTEM_PROCESS_INFORMATION = buffer.as_ptr() as PSYSTEM_PROCESS_INFORMATION;
            if p_process_info.is_null() { panic!("Panicked at Ainz::init(&mut self): p_process_info is invalid") }

            while !p_process_info.is_null() {
                let proc_info = *p_process_info;
                let image_name: PWCH = proc_info.ImageName.Buffer;
                let image_name_sz: USHORT = proc_info.ImageName.Length;
                if !image_name.is_null() && image_name_sz > 0 {
                    let len_real = (image_name_sz / 2) as usize;
                    let wide_slice = std::slice::from_raw_parts(image_name, len_real);
                    let image_name_str = String::from_utf16_lossy(wide_slice);
                    if image_name_str.eq_ignore_ascii_case(&self.target_proc_name) {
                        self.ainz_ctx.pid = proc_info.UniqueProcessId as DWORD;
                        self.ainz_ctx.tid = proc_info.Threads[0].ClientId.UniqueThread as DWORD;
                        break;
                    }
                }
                if proc_info.NextEntryOffset == 0 { break; }
                p_process_info = (p_process_info as *const u8).add(proc_info.NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
            }

            let mut obj_attrs: OBJECT_ATTRIBUTES = zeroed();
            InitializeObjectAttributes(&mut obj_attrs as POBJECT_ATTRIBUTES, null_mut(),0, null_mut(), null_mut());
            self.ainz_ctx.client_id = CLIENT_ID {
                UniqueProcess: self.ainz_ctx.pid as HANDLE,
                UniqueThread: self.ainz_ctx.tid as HANDLE,
            };

            status = ZwOpenProcess(
                &mut self.ainz_ctx.proc_handle, PROCESS_ALL_ACCESS,
                &mut obj_attrs, &mut self.ainz_ctx.client_id
            );
            if !nt_success!(status) { return Err(status); }

            status = ZwOpenThread(
                &mut self.ainz_ctx.main_thread_handle, PROCESS_ALL_ACCESS,
                &mut obj_attrs, &mut self.ainz_ctx.client_id
            );
            if !nt_success!(status) { return Err(status); }

        }
        self.ainz_ctx.fn_ctx.p_load_library = LoadLibraryA as PVOID;
        Ok(())
    }

    pub unsafe fn suspend_thread_except(&mut self, tid: DWORD) -> Result<(), NTSTATUS> {
        unsafe {
            let h_snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.ainz_ctx.pid);
            let mut te32: THREADENTRY32 = zeroed();
            te32.dwSize = size_of::<THREADENTRY32>() as DWORD;

            while Thread32Next(h_snap, &mut te32 as *mut THREADENTRY32) > 0 {
                let mut h_thread: HANDLE = null_mut();
                let mut obj_attrs: OBJECT_ATTRIBUTES = zeroed();
                InitializeObjectAttributes(&mut obj_attrs as POBJECT_ATTRIBUTES, null_mut(),0, null_mut(), null_mut());
                ZwOpenThread(&mut h_thread, THREAD_QUERY_INFORMATION, &mut obj_attrs, &mut self.ainz_ctx.client_id);

                if !h_thread.is_null() {
                    let start_address: PVOID = null_mut();
                    let status: NTSTATUS = ZwQueryInformationThread(
                        h_thread, ThreadQuerySetWin32StartAddress,
                        start_address, size_of_val(&start_address) as ULONG, null_mut());
                    if nt_success!(status) {
                        if tid != te32.th32ThreadID {
                            let mut client_id = CLIENT_ID { UniqueProcess: null_mut(), UniqueThread: te32.th32ThreadID as HANDLE };
                            let mut obj_attrs: OBJECT_ATTRIBUTES = zeroed();
                            InitializeObjectAttributes(&mut obj_attrs as POBJECT_ATTRIBUTES, null_mut(),0, null_mut(), null_mut());
                            let mut target_thread: HANDLE = null_mut();
                            self.ainz_ctx.saved_threads.push(target_thread);
                            ZwOpenThread(
                                &mut target_thread, THREAD_QUERY_INFORMATION, &mut obj_attrs, &mut client_id
                            );
                            ZwSuspendThread(target_thread, null_mut());
                        }
                    }
                    ZwClose(h_thread);
                }
            }
            ZwClose(h_snap);
        }
        Ok(())
    }

    pub unsafe fn resume_threads(&mut self) -> Result<(), NTSTATUS> {
        unsafe {
            for th in &self.ainz_ctx.saved_threads {
                if !th.is_null() {
                    ZwResumeThread(*th, null_mut());
                    ZwClose(*th);
                }
            }
        }
        Ok(())
    }

    pub unsafe fn inject(&mut self) -> bool {
        let mut status: bool = false;
        unsafe {
            for dll in self.dlls.clone() {
                match self.inject_mode {
                    InjectMode::Native => {
                        status = self.inject_native(&dll).is_ok();
                    }
                }
                println!("dll: {}", dll);
                thread::sleep(time::Duration::from_millis(self.delay_between));
            }
            thread::sleep(time::Duration::from_millis(15000));
        }
        status
    }

    pub unsafe fn inject_native(&mut self, dll: &String) -> Result<(), NTSTATUS> {
        let mut status: NTSTATUS;
        unsafe {
            let mut remote_alloc: PVOID = null_mut();
            let mut region_sz = dll.len() + 1;

            status = ZwAllocateVirtualMemory(
                self.ainz_ctx.proc_handle,
                &mut remote_alloc,
                0,
                &mut region_sz,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            if !nt_success!(status) { return Err(status); }

            let mut bytes_written: usize = 0;
            status = ZwWriteVirtualMemory(
                self.ainz_ctx.proc_handle,
                remote_alloc,
                dll.as_ptr() as PVOID,
                region_sz,
                &mut bytes_written
            );
            if !nt_success!(status) { return Err(status); }

            ZwSuspendThread(self.ainz_ctx.main_thread_handle, null_mut());
            let mut h_thread_remote: HANDLE = null_mut();
            status = ZwCreateThreadEx(
                &mut h_thread_remote,
                THREAD_ALL_ACCESS,
                null_mut(),
                self.ainz_ctx.proc_handle,
                self.ainz_ctx.fn_ctx.p_load_library,
                remote_alloc,
                0, 0, 0, 0,
                null_mut()
            );
            if !nt_success!(status) { return Err(status); }
            ZwResumeThread(self.ainz_ctx.main_thread_handle, null_mut());


            ZwWaitForSingleObject(h_thread_remote as HANDLE, BOOLEAN::from(true), zeroed());
            ZwClose(h_thread_remote);
            ZwFreeVirtualMemory(self.ainz_ctx.proc_handle, remote_alloc as *mut PVOID, region_sz as *mut usize, MEM_RELEASE);
        }
        Ok(())
    }

    pub unsafe fn is_process_alive(&self) -> bool {
        let sys_class: SYSTEM_INFORMATION_CLASS = SystemProcessInformation;
        let mut buffer_sz: ULONG = 1024 * 1024;
        let status: NTSTATUS;
        unsafe {
            let buffer = vec![0u8; buffer_sz as usize];
            status = ZwQuerySystemInformation(sys_class, buffer.as_ptr() as *mut c_void, buffer_sz, &mut buffer_sz);
            if !nt_success!(status) { return false; }

            let mut p_process_info: PSYSTEM_PROCESS_INFORMATION = buffer.as_ptr() as PSYSTEM_PROCESS_INFORMATION;
            if p_process_info.is_null() { return false; }

            while !p_process_info.is_null() {
                let proc_info = *p_process_info;
                let image_name: PWCH = proc_info.ImageName.Buffer;
                let image_name_sz: USHORT = proc_info.ImageName.Length;
                if !image_name.is_null() && image_name_sz > 0 {
                    let len_real = (image_name_sz / 2) as usize;
                    let wide_slice = std::slice::from_raw_parts(image_name, len_real);
                    let image_name_str = String::from_utf16_lossy(wide_slice);
                    if image_name_str.eq_ignore_ascii_case(&self.target_proc_name) {
                        return true;
                    }
                }
                if proc_info.NextEntryOffset == 0 { break; }
                p_process_info = (p_process_info as *const u8).add(proc_info.NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
            }
        }
        false
    }

    pub unsafe fn get_peb(proc_handle: HANDLE) -> PPEB {
        unsafe {
            let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
            let ret_len: ULONG = 0;
            let status: NTSTATUS = ZwQueryInformationProcess(
                proc_handle,
                ProcessBasicInformation,
                &mut pbi as *mut PROCESS_BASIC_INFORMATION as PVOID,
                size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
                ret_len as PULONG
            );
            if !nt_success!(status) { return null_mut(); }
            pbi.PebBaseAddress
        }
    }

    pub unsafe fn unlink_module(&self) -> Result<(), UnlinkError> {
        unsafe {
            if self.ainz_ctx.proc_handle.is_null() {
                return Err(UnlinkError::InvalidHandle);
            }

            let p_peb = Self::get_peb(self.ainz_ctx.proc_handle);
            if p_peb.is_null() {
                return Err(UnlinkError::InvalidPPEB);
            }

            let mut peb: PEB = zeroed();
            if !nt_success!(ZwReadVirtualMemory(
                self.ainz_ctx.proc_handle,
                p_peb as PVOID,
                &mut peb as *mut PEB as PVOID,
                size_of_val(&peb),
                null_mut())) {
                return Err(UnlinkError::FailedReadPEB);
            }

            if peb.Ldr.is_null() {
                return Err(UnlinkError::InvalidLdr);
            }

            let mut ldr: PEB_LDR_DATA = zeroed();
            if !nt_success!(ZwReadVirtualMemory(
                self.ainz_ctx.proc_handle,
                peb.Ldr as PVOID,
                &mut ldr as *mut _ as PVOID,
                size_of_val(&ldr),
                null_mut())) {
                return Err(UnlinkError::FailedReadLdr);
            }

            for dll in &self.dlls {
                return match self.hide_entry(
                    dll, &ldr.InMemoryOrderModuleList,
                    offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as u64) {
                    Ok(_) => Ok(()),
                    Err(HideError::FailedReadCurrent) => Err(UnlinkError::FailedInternalReadCurrent),
                    Err(HideError::FailedReadDllBuffer) => Err(UnlinkError::FailedInternalReadDllBuffer),
                    Err(HideError::FailedReadEntryAddress) => Err(UnlinkError::FailedInternalReadEntryAddress),
                    Err(HideError::FailedInternalMutate) => Err(UnlinkError::FailedMutate)
                }
            }
        }
        Ok(())
    }

    pub unsafe fn hide_entry(&self, dll: &String, list_head: &LIST_ENTRY, list_offset: u64) -> Result<(), HideError> {
        unsafe {
            let head = list_head as *const LIST_ENTRY as *mut LIST_ENTRY;
            let mut current = (*list_head).Flink;

            while current != head && !current.is_null() {
                let mut current_entry: LIST_ENTRY = zeroed();
                if !nt_success!(ZwReadVirtualMemory(
                self.ainz_ctx.proc_handle,
                current as PVOID,
                &mut current_entry as *mut LIST_ENTRY as PVOID,
                size_of::<LIST_ENTRY>(),
                null_mut()
            )) { return Err(HideError::FailedReadCurrent); }

                let entry_addr = current as u64 - list_offset;

                let mut entry_data: LDR_DATA_TABLE_ENTRY = zeroed();
                if !nt_success!(ZwReadVirtualMemory(
                self.ainz_ctx.proc_handle,
                entry_addr as PVOID,
                &mut entry_data as *mut LDR_DATA_TABLE_ENTRY as PVOID,
                size_of::<LDR_DATA_TABLE_ENTRY>(),
                null_mut()
                )) {
                    current = current_entry.Flink;
                    continue;
                }

                let dll_name = entry_data.FullDllName;
                if !dll_name.Buffer.is_null() && dll_name.Length > 0 {
                    let buffer_len = dll_name.Length as usize;
                    let char_count = buffer_len / 2;


                    let mut name_buffer: Vec<u16> = vec![0; char_count + 1];

                    if nt_success!(ZwReadVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        dll_name.Buffer as PVOID,
                        name_buffer.as_mut_ptr() as PVOID,
                        buffer_len,
                        null_mut()
                    )) {
                        let wide_str = String::from_utf16_lossy(&name_buffer[..char_count]);
                        let clean_str = wide_str.trim_end_matches('\0');

                        if dll.contains(clean_str) {
                            return match self.mutate_entry(entry_addr, &mut entry_data) {
                                Ok(_) => Ok(()),
                                Err(_) => Err(HideError::FailedInternalMutate)
                            }
                        }

                    } else { return Err(HideError::FailedReadDllBuffer); }
                }
                current = current_entry.Flink;

                if current == (*list_head).Flink {
                    break;
                }
            }
        }
        Ok(())
    }

    pub unsafe fn mutate_entry(&self, entry_addr: u64, entry: &mut LDR_DATA_TABLE_ENTRY) -> Result<(), MutateError> {
        unsafe {
            if !entry.FullDllName.Buffer.is_null() {
                let zero_len: USHORT = 0;
                let full_dll_name_len_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, FullDllName) as u64
                    + offset_of!(UNICODE_STRING, Length) as u64;

                if !nt_success!(ZwWriteVirtualMemory(
                    self.ainz_ctx.proc_handle,
                    full_dll_name_len_addr as PVOID,
                    &zero_len as *const _ as PVOID,
                    size_of::<USHORT>(),
                    null_mut())) { return Err(MutateError::FailedNullifyFullDllLen); }


                if !entry.BaseDllName.Buffer.is_null() {
                    let zero_len: USHORT = 0;
                    let base_dll_name_len_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, BaseDllName) as u64
                        + offset_of!(UNICODE_STRING, Length) as u64;

                    if !nt_success!(ZwWriteVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        base_dll_name_len_addr as PVOID,
                        &zero_len as *const _ as PVOID,
                        size_of::<USHORT>(),
                        null_mut())) { return Err(MutateError::FailedNullifyFullDllLen); }
                }

                let null_ptr: PVOID = null_mut();
                let dll_base_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, DllBase) as u64;

                if !nt_success!(ZwWriteVirtualMemory(
                    self.ainz_ctx.proc_handle,
                    dll_base_addr as PVOID,
                    &null_ptr as *const _ as PVOID,
                    size_of::<PVOID>(),
                    null_mut()
                    )) { return Err(MutateError::FailedNullifyFullDllLen); }

                let zero_size: ULONG = 0;
                let size_of_image_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, SizeOfImage) as u64;

                if !nt_success!(ZwWriteVirtualMemory(
                    self.ainz_ctx.proc_handle,
                    size_of_image_addr as PVOID,
                    &zero_size as *const _ as PVOID,
                    size_of::<ULONG>(),
                    null_mut())) { return Err(MutateError::FailedNullifyDllBaseAddress); }

                let flink = entry.InMemoryOrderLinks.Flink;
                let blink = entry.InMemoryOrderLinks.Blink;

                if !flink.is_null() && !blink.is_null() {
                    if !nt_success!(ZwWriteVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        (blink as u64 + offset_of!(LIST_ENTRY, Flink) as u64) as PVOID,
                        &flink as *const _ as PVOID,
                        size_of::<*mut LIST_ENTRY>(),
                        null_mut())) { return Err(MutateError::FailedUpdateFlink); }

                    if !nt_success!(ZwWriteVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        (flink as u64 + offset_of!(LIST_ENTRY, Blink) as u64) as PVOID,
                        &blink as *const _ as PVOID,
                        size_of::<*mut LIST_ENTRY>(),
                        null_mut())) { return Err(MutateError::FailedUpdateBlink); }

                    let null_list_ptr: *mut LIST_ENTRY = null_mut();
                    let self_flink_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as u64
                        + offset_of!(LIST_ENTRY, Flink) as u64;
                    let self_blink_addr = entry_addr + offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as u64
                        + offset_of!(LIST_ENTRY, Blink) as u64;

                    if !nt_success!(ZwWriteVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        self_flink_addr as PVOID,
                        &null_list_ptr as *const _ as PVOID,
                        size_of::<*mut LIST_ENTRY>(),
                        null_mut())) { return Err(MutateError::FailedNullifySelfFlink); }

                    if !nt_success!(ZwWriteVirtualMemory(
                        self.ainz_ctx.proc_handle,
                        self_blink_addr as PVOID,
                        &null_list_ptr as *const _ as PVOID,
                        size_of::<*mut LIST_ENTRY>(),
                        null_mut())) { return Err(MutateError::FailedNullifySelfBlink); }
                }
            }
        }
        Ok(())
    }
}