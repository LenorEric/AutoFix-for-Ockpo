use std::path::Path;
use std::{fs, env, io};
use std::io::{prelude::*, BufReader};
use std::process::{Command, Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const ENCRYPTED_HEADER: [u8; 16] = [0x62, 0x14, 0x23, 0x65, 0x3f, 0x00, 0x13, 0x01,
    0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a];

static PROCESSED_COUNT: AtomicUsize  = AtomicUsize::new(0);

fn read_skip_list() -> Vec<String> {
    let mut skip_list = Vec::new();
    if let Ok(file) = fs::File::open("list.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(ext) = line {
                skip_list.push(ext.trim().to_string());
            }
        }
    }
    skip_list
}

fn should_skip_file(path: &Path, skip_list: &[String]) -> bool {
    if let Some(extension) = path.extension() {
        if let Some(ext_str) = extension.to_str() {
            for skip_ext in skip_list {
                let skip_ext = skip_ext.trim_start_matches('.');
                if ext_str.eq_ignore_ascii_case(skip_ext) {
                    return true;
                }
            }
        }
    }
    false
}

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
            if buffer[1..4] == ENCRYPTED_HEADER[1..4] {
                return true;
            }
        }
    }
    false
}

fn check_req() -> bool {
    let file_name = "code.exe";
    if Path::new(file_name).exists() {
        true
    } else {
        false
    }
}

fn recursive_decrypt(
    father_path: &Box<Path>,
    proc_path: &Box<Path>,
    skip_list: &[String],
    children: &mut Vec<Child>,
) -> io::Result<()> {
    let current_exe = env::current_exe()?;
    let exe_dir = current_exe.parent().unwrap();
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        let path = entry.path();

        let rel = path.strip_prefix(exe_dir).unwrap_or(&path);

        if path.is_file() {
            PROCESSED_COUNT.fetch_add(1, Ordering::Relaxed);
            if PROCESSED_COUNT.load(Ordering::Relaxed) % 1000 == 0 {
                println!("Processed {} files...", PROCESSED_COUNT.load(Ordering::Relaxed));
            }
            let path_str = path.to_str().unwrap();

            // 跳过自己
            if are_same_file(current_exe.to_str().unwrap(), path_str)? {
                continue;
            }
            // 跳过扩展名
            if should_skip_file(&path, skip_list) {
                // println!("Skipping: {:?}", rel);
                continue;
            }

            if check_is_encrypted(path_str) {
                // 如果队列已满，先等待最早的一个
                if children.len() >= 4 {
                    let mut first = children.remove(0);
                    first.wait()?;
                }
                // spawn 解密进程
                println!("Decrypting: {:?}", rel);
                let child = Command::new("cmd")
                    .arg("/c")
                    .args([".\\code.exe", "-s", path_str])
                    .stdout(Stdio::null())     // 不打印 stdout
                    .stderr(Stdio::null())     // 不打印 stderr
                    .spawn()
                    .expect("cmd exec error!");
                children.push(child);
            }
        } else if path.is_dir() {
            recursive_decrypt(father_path, &Box::from(path.clone()), skip_list, children)?;
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    if !check_req() {
        println!("Requirement not found");
        return Ok(());
    }

    let skip_list = read_skip_list();
    let current_dir = env::current_dir()?;
    let mut children: Vec<Child> = Vec::new();

    recursive_decrypt(
        &Box::from(current_dir.clone()),
        &Box::from(current_dir.clone()),
        &skip_list,
        &mut children,
    )?;

    // 等待剩余的解密进程完成
    for mut c in children {
        c.wait()?;
    }

    Ok(())
}
