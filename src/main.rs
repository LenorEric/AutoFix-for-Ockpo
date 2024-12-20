use std::path::Path;
use std::{fs, env, io};
use std::io::prelude::*;
use std::process::Command;

const FAKE_ENCRYPTED_HEADER: [u8; 16] = [0x62, 0x14, 0x23, 0x65, 0x3f, 0x00, 0x13, 0x01,
    0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a];

fn are_same_file(path1: &str, path2: &str) -> io::Result<bool> {
    let canonical_path1 = fs::canonicalize(path1)?;
    let canonical_path2 = fs::canonicalize(path2)?;
    Ok(canonical_path1 == canonical_path2)
}

fn check_is_encrypted(src: &str) -> bool {
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        let mut buffer = [0u8; 4];
        let bytes_read = read_stream.read(&mut buffer).unwrap();
        if bytes_read == 4 {
            if buffer == FAKE_ENCRYPTED_HEADER[0..4] {
                return true;
            }
        }
    }
    false
}

fn decrypt_file(src: &str) -> io::Result<()> {
    let cmd_str = format!(".\\code.exe -s {}", src, ).to_string();
    Command::new("cmd").arg("/c").arg(cmd_str).output().expect("cmd exec error!");
    Ok(())
}


fn check_req() -> bool {
    let file_name = "code.exe";
    if Path::new(file_name).exists() {
        true
    } else {
        false
    }
}

fn recursive_decrypt(father_path: &Box<Path>, proc_path: &Box<Path>) -> io::Result<()> {
    let current_exe_path = env::current_exe()?;
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if are_same_file(current_exe_path.to_str().unwrap(), path.to_str().unwrap())? {
                continue;
            }
            println!("Checking: {:?}", path);
            if check_is_encrypted(path.to_str().unwrap()) {
                decrypt_file(path.to_str().unwrap())?;
            }
        } else if path.is_dir() {
            recursive_decrypt(father_path, &Box::from(path.clone()))?
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    if !check_req() {
        println!("Requirement not found");
        return Ok(());
    }
    let current_dir = env::current_dir()?;
    recursive_decrypt(&Box::from(current_dir.clone()), &Box::from(current_dir.clone()))?;
    Ok(())
}
