## Ainz-rs
Modular Windows x64 Dynamic Link Library Injector written in Rust

#### Usage
[Process Name] [Config] [ProcessPath.txt (Opt)] [Injection Mode] [Delay (ms)] [Injection Method] [Unlink Module]

Example: notepad.exe ainz-run.cfg path.txt native 73 run false

#### Features
1. Support for attaching to an existing running process
2. Support for deferred execution (await mode)
3. Support for process creation and initialization at launch time
