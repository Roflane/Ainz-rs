use std::fs;

pub fn load_dlls_from_config(cfg_name: &String) -> Vec<String> {
    fs::read_to_string(cfg_name)
        .unwrap()
        .lines()
        .map(|s| {
                let str = s.to_string() + "\0";
                if !str.starts_with("/") || !str.starts_with("ㅡ") {
                    return str;
                }
                String::from("ㅡ")
        })
        .collect()
}

pub fn load_game_from_config(game_name_config: &String) -> String {
    fs::read_to_string(game_name_config).unwrap().to_string()
}