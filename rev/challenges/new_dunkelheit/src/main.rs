use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::PathBuf;
use std::time::Instant;
use fnv::FnvHasher;
use std::hash::Hasher;
use rand::Rng;

fn decode_str(encoded: &[u8], key: u8) -> String {
    encoded.iter().map(|&b| (b ^ key) as char).collect()
}

fn get_flag_piece_1() -> Vec<u8> {
    let mut state = 0;
    let mut result = Vec::new();
    let data = vec![0x34, 0x0e, 0x15, 0x12, 0x05, 0x2d, 0x0c, 0x35, 0x1b];

    loop {
        match state {
            0 => {
                result.extend_from_slice(&data);
                state = 1;
            }
            1 => {
                let _ = calculate_fibonacci_sequence(5);
                state = 2;
            }
            2 => {
                break;
            }
            _ => unreachable!(),
        }
    }

    result
}

fn get_fake_flag_piece() -> Vec<u8> {
    vec![0x34, 0x23, 0x36, 0x58, 0x37, 0x56, 0x58, 0x52, 0x44]
}

fn get_flag_piece_2() -> Vec<u8> {
    let mut accumulator = 0u8;
    let base = vec![
        0x43, 0x14, 0x1c, 0x28, 0x1a, 0x44, 0x40, 0x43,
        0x1b, 0x28, 0x3e, 0x04,
    ];

    let mut result = Vec::new();
    for (i, &b) in base.iter().enumerate() {
        accumulator = accumulator.wrapping_add(i as u8);
        result.push(b);
        if i % 3 == 0 {
            let _ = perform_meaningless_operations(10);
        }
    }

    result
}

fn get_flag_piece_3() -> Vec<u8> {
    let encoded = vec![0x40, 0x28, 0x3c, 0x05, 0x1e, 0x44, 0x10, 0x28, 0x43, 0x19];
    let mut output = Vec::new();
    let mut idx = 0;
    let mut state = 0;

    while idx < encoded.len() {
        match state {
            0 => {
                output.push(encoded[idx]);
                idx += 1;
                state = if idx % 2 == 0 { 1 } else { 0 };
            }
            1 => {
                let _ = bubble_sort(&mut vec![1, 3, 2]);
                state = 0;
            }
            _ => break,
        }
    }

    output
}

fn get_fake_flag_piece_2() -> Vec<u8> {
    vec![0x36, 0x39, 0x56, 0x50, 0x58, 0x5f, 0x51, 0x7f, 0x44]
}

fn get_flag_piece_4() -> Vec<u8> {
    let data = vec![0x13, 0x28, 0x21, 0x43, 0x05, 0x10, 0x28, 0x43, 0x07];
    let mut result = Vec::new();
    let mut dispatch = vec![0, 1, 2];

    for _ in 0..3 {
        let action = dispatch.remove(0);
        match action {
            0 => result.extend_from_slice(&data[0..3]),
            1 => result.extend_from_slice(&data[3..6]),
            2 => result.extend_from_slice(&data[6..9]),
            _ => {}
        }
    }

    result
}

fn get_flag_piece_5() -> Vec<u8> {
    let mut stage = 1;
    let part_a = vec![0x07, 0x05, 0x47, 0x01];
    let part_b = vec![0x44, 0x04, 0x28];
    let mut combined = Vec::new();

    loop {
        match stage {
            1 => {
                combined.extend_from_slice(&part_a);
                stage = 2;
            }
            2 => {
                let _ = compute_prime_factors(1009);
                stage = 3;
            }
            3 => {
                combined.extend_from_slice(&part_b);
                stage = 4;
            }
            4 => break,
            _ => break,
        }
    }

    combined
}

fn get_flag_piece_6() -> Vec<u8> {
    let data = vec![0x40, 0x1f, 0x1e, 0x04, 0x28, 0x56, 0x56, 0x0a];
    let mut output = Vec::new();

    for (i, &byte) in data.iter().enumerate() {
        if i % 2 == 0 {
            output.push(byte);
        } else {
            output.push(byte);
            let _ = perform_meaningless_operations(5);
        }
    }

    output
}

fn assemble_flag_obfuscated() -> String {
    let mut state = 0;
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let xor_key: u8 = 0x77;

    loop {
        match state {
            0 => {
                let _ = calculate_fibonacci_sequence(3);
                state = 1;
            }
            1 => {
                pieces.push(get_flag_piece_1());
                state = 2;
            }
            2 => {
                let _ = get_fake_flag_piece();
                state = 3;
            }
            3 => {
                pieces.push(get_flag_piece_2());
                state = 4;
            }
            4 => {
                let _ = perform_meaningless_operations(50);
                state = 5;
            }
            5 => {
                pieces.push(get_flag_piece_3());
                state = 6;
            }
            6 => {
                let _ = get_fake_flag_piece_2();
                state = 7;
            }
            7 => {
                pieces.push(get_flag_piece_4());
                state = 8;
            }
            8 => {
                let _ = compute_prime_factors(2017);
                state = 9;
            }
            9 => {
                pieces.push(get_flag_piece_5());
                state = 10;
            }
            10 => {
                pieces.push(get_flag_piece_6());
                state = 11;
            }
            11 => {
                break;
            }
            _ => unreachable!(),
        }
    }

    let mut combined = Vec::new();
    for piece in pieces {
        combined.extend_from_slice(&piece);
    }

    decode_str(&combined, xor_key)
}

#[cfg(target_os = "linux")]
fn check_ptrace() -> bool {
    use std::fs::read_to_string;
    if let Ok(status) = read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] != "0" {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn check_ptrace() -> bool {
    false
}

fn timing_check() -> bool {
    let start = Instant::now();
    let mut dummy = 0u64;
    for i in 0..100000 {
        dummy = dummy.wrapping_add(i);
    }
    let elapsed = start.elapsed();

    if elapsed.as_millis() > 10 {
        return true;
    }

    if dummy == 0 {
        return true;
    }

    false
}

fn calculate_fibonacci_sequence(n: u32) -> Vec<u64> {
    let mut fib: Vec<u64> = vec![0, 1];
    for i in 2..n {
        let next = fib[(i - 1) as usize].wrapping_add(fib[(i - 2) as usize]);
        fib.push(next);
    }
    fib
}

fn reverse_string_multiple_times(s: &str, times: usize) -> String {
    let mut result = s.to_string();
    for _ in 0..times {
        result = result.chars().rev().collect();
    }
    result
}

fn compute_prime_factors(mut n: u64) -> Vec<u64> {
    let mut factors = Vec::new();
    let mut d = 2;
    while d * d <= n {
        while n % d == 0 {
            factors.push(d);
            n /= d;
        }
        d += 1;
    }
    if n > 1 {
        factors.push(n);
    }
    factors
}

fn bubble_sort(arr: &mut [i32]) {
    let len = arr.len();
    for i in 0..len {
        for j in 0..len - i - 1 {
            if arr[j] > arr[j + 1] {
                arr.swap(j, j + 1);
            }
        }
    }
}

fn matrix_multiplication(a: &[Vec<i32>], b: &[Vec<i32>]) -> Vec<Vec<i32>> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let cols_b = b[0].len();

    let mut result = vec![vec![0; cols_b]; rows_a];

    for i in 0..rows_a {
        for j in 0..cols_b {
            for k in 0..cols_a {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }

    result
}

fn calculate_hash_chain(input: &str, iterations: usize) -> u64 {
    let mut hash = 0u64;
    for _ in 0..iterations {
        let mut hasher = FnvHasher::default();
        hasher.write(input.as_bytes());
        hasher.write_u64(hash);
        hash = hasher.finish();
    }
    hash
}

fn perform_meaningless_operations(complexity: usize) -> u64 {
    let mut rng = rand::thread_rng();
    let mut accumulator = 0u64;

    for _ in 0..complexity {
        let operation = rng.gen_range(0..4);
        let value = rng.gen_range(1..100);

        match operation {
            0 => accumulator = accumulator.wrapping_add(value),
            1 => accumulator = accumulator.wrapping_sub(value),
            2 => accumulator = accumulator.wrapping_mul(value),
            3 => accumulator ^= value,
            _ => unreachable!(),
        }
    }

    accumulator
}

fn fnv1_32_hash(data: &[u8]) -> u32 {
    const FNV_PRIME: u32 = 16777619;
    const FNV_OFFSET: u32 = 2166136261;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= byte as u32;
    }

    hash
}

fn verify_solution(input: &str) -> bool {
    let expected_hash = 0x13dc127e;
    let computed = fnv1_32_hash(input.as_bytes());

    computed == expected_hash
}

fn download_video(url: &str, output_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let msg_encoded: Vec<u8> = vec![0x3b, 0x24, 0x34, 0x23, 0x31, 0x20, 0x39, 0x38, 0x23];
    let _msg = decode_str(&msg_encoded, 0x5a);

    let _ = calculate_fibonacci_sequence(20);
    let _ = perform_meaningless_operations(1000);

    let mut file = File::create(output_path)?;
    let dummy_data = b"BURZUM_DUNKELHEIT_VIDEO_DATA_PLACEHOLDER";
    file.write_all(dummy_data)?;

    let _ = compute_prime_factors(9999991);

    Ok(())
}

fn create_video_copies(source: &PathBuf, tmp_dir: &PathBuf, count: usize) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut copies = Vec::new();

    let mut source_file = File::open(source)?;
    let mut content = Vec::new();
    source_file.read_to_end(&mut content)?;

    let _ = reverse_string_multiple_times("obfuscation", 10);

    for i in 0..count {
        let copy_path = tmp_dir.join(format!("dunkelheit_part_{}.mp4", i + 1));
        let mut copy_file = File::create(&copy_path)?;
        copy_file.write_all(&content)?;
        copies.push(copy_path);

        let _ = calculate_hash_chain("garbage", 100);
    }

    Ok(copies)
}

fn hide_flag_fragments(tmp_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let real_flag = assemble_flag_obfuscated();
    let flag_hash = fnv1_32_hash(real_flag.as_bytes());

    let hash_hex = format!("{:08x}", flag_hash);

    let partial_hint = &hash_hex[0..4];

    let mut dummy_arr = vec![42, 17, 93, 8, 64];
    bubble_sort(&mut dummy_arr);

    let text_path = tmp_dir.join("fragment_1.txt");
    let mut text_file = File::create(&text_path)?;
    let content = format!(
        "// Video integrity verification\n// CRC32: {}\n// Status: OK\n// Frame count: 8472\n",
        perform_meaningless_operations(50)
    );
    text_file.write_all(content.as_bytes())?;

    let text_path = tmp_dir.join("fragment_2.txt");
    let mut text_file = File::create(&text_path)?;
    let content = format!(
        "// Codec information\n// Format: H.264\n// Bitrate: 2500 kbps\n// Audio: AAC 44.1kHz\n// Duration: 05:47\n"
    );
    text_file.write_all(content.as_bytes())?;

    let text_path = tmp_dir.join("fragment_3.txt");
    let mut text_file = File::create(&text_path)?;
    let content = format!(
        "// Encryption seed\n// Algorithm: AES-256\n// Init vector: {}\n// Key derivation: PBKDF2\n// Checksum prefix: 0x{}\n// Iterations: 10000\n",
        perform_meaningless_operations(50),
        partial_hint
    );
    text_file.write_all(content.as_bytes())?;

    let text_path = tmp_dir.join("fragment_4.txt");
    let mut text_file = File::create(&text_path)?;
    let content = format!(
        "// Compression analysis\n// Ratio: 87.3%%\n// Original size: {} bytes\n// Compressed: {} bytes\n",
        perform_meaningless_operations(1000) + 50000000,
        perform_meaningless_operations(500) + 5000000
    );
    text_file.write_all(content.as_bytes())?;

    let matrix_a = vec![vec![1, 2], vec![3, 4]];
    let matrix_b = vec![vec![5, 6], vec![7, 8]];
    let _ = matrix_multiplication(&matrix_a, &matrix_b);

    Ok(())
}

fn execute_challenge() -> Result<(), Box<dyn std::error::Error>> {
    if check_ptrace() {
        println!("System integrity check failed [0x01]");
        std::process::exit(1);
    }

    if timing_check() {
        println!("System integrity check failed [0x02]");
        std::process::exit(1);
    }

    let _ = calculate_fibonacci_sequence(30);

    let tmp_dir_name = "dunkelheit_tmp";
    let tmp_path = std::env::temp_dir().join(tmp_dir_name);

    fs::create_dir_all(&tmp_path)?;

    let video_path = tmp_path.join("original_video.mp4");

    let video_url = "https://example.com/burzum_dunkelheit.mp4";

    println!("[*] Initializing dark atmosphere...");

    download_video(video_url, &video_path)?;

    println!("[*] Casting shadows...");

    let copies = create_video_copies(&video_path, &tmp_path, 4)?;

    println!("[*] Fragmenting the darkness...");

    hide_flag_fragments(&tmp_path)?;

    println!("[*] The dunkelheit is complete.");
    println!("[*] Files stored in: {}", tmp_path.display());
    println!("[*] Total video copies: {}", copies.len());

    let _ = compute_prime_factors(1234567891);
    let _ = perform_meaningless_operations(5000);

    if std::env::args().any(|arg| arg == "--verify") {
        if let Some(flag) = std::env::args().nth(2) {
            if verify_solution(&flag) {
                println!("\n[+] Correct flag! The darkness reveals itself.");
                println!("[+] Flag hash: {:08x}", fnv1_32_hash(flag.as_bytes()));
            } else {
                println!("\n[-] Incorrect flag. The darkness remains hidden.");
            }
        } else {
            println!("Usage: dunkelheit --verify <flag>");
        }
    }

    Ok(())
}

fn main() {
    println!("╔═══════════════════════════════════╗");
    println!("║         D U N K E L H E I T       ║");
    println!("║          [Darkness Falls]         ║");
    println!("╚═══════════════════════════════════╝\n");

    if check_ptrace() || timing_check() {
        println!("[!] Debugger detected. Exiting.");
        std::process::exit(1);
    }

    if let Err(e) = execute_challenge() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

