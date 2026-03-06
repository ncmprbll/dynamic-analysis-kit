use std::{
    cmp::{max, min},
    env,
    process::exit,
};

use malakit::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        help();
    }

    match args[1].as_str() {
        "ps" => ps(),
        "scan" => scan(&args),
        _ => help(),
    };
}

fn help() -> ! {
    println!("Usage: {0} [COMMAND]
\nCommands:
  ps                                        List processes in the system
  scan <pid> [--size int] <PATTERN> Scan the process for a given pattern (e.g. {0} scan 20300 \"FF ?? FF ?? 05 0C\"). Use optional parameter --size to specify the maximum amount of memory used while reading a single page.
\nPattern:
  Must be a valid sequence of hex bytes (without \"0x\" prefix) optionally separated by space. Special sequence \"??\" indicates ANY byte.",
    env!{"CARGO_CRATE_NAME"});
    exit(0);
}

fn ps() {
    let mut list = match process::list() {
        Ok(list) => list,
        Err(err) => {
            eprintln!("Failed to get a list of processes: {err}");
            exit(1);
        }
    };

    if list.len() == 0 {
        println!("Nothing to show");
        return;
    }

    list.sort_by(|a, b| a.th32ProcessID.cmp(&b.th32ProcessID));
    let width = list.last().unwrap().th32ProcessID.to_string().len();

    for process in list {
        println!(
            "{:<width$} {}",
            process.th32ProcessID,
            process.executable_name,
            width = width,
        );
    }
}

fn scan(args: &Vec<String>) {
    if args.len() < 4 {
        help();
    };

    let mut has_size: bool = false;

    if args[3] == "-s" || args[3] == "--size" {
        if args.len() < 6 {
            help();
        };

        has_size = true;
    }

    let process_id = match args[2].parse::<u32>() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("Failed to parse process id: {err}");
            exit(1);
        }
    };

    let handle = match process::handle_by_pid(process_id) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("Failed to get process's handle by id {process_id}: {err}");
            exit(1);
        }
    };

    let pattern = match aob::Pattern::new(&args[if has_size { 5 } else { 3 }]) {
        Ok(pattern) => pattern,
        Err(err) => {
            eprintln!("Failed to create pattern: {err}");
            exit(1);
        }
    };

    let pages = memory::list_every_readonly_page_by_handle(&handle);

    if has_size {
        let size = match args[4].parse::<usize>() {
            Ok(size) => size,
            Err(err) => {
                eprintln!("Failed to parse size: {err}");
                exit(1);
            }
        };

        let pattern_size = pattern.len();
        let size = max(pattern_size, size);

        for page in pages {
            let base_address = page.BaseAddress as usize;
            let size = min(size, page.RegionSize);

            for (i, buffer) in page
                .sized_reader(&handle, size, pattern_size - 1)
                .enumerate()
            {
                aob::scan(&buffer, &pattern)
                    .iter()
                    .for_each(|index| println!("0x{:X} +0x{:X}", base_address, i * size + index));
            }
        }

        return;
    }

    for page in pages {
        let base_address = page.BaseAddress as usize;

        let buffer = match page.read(&handle) {
            Some(buffer) => buffer,
            None => continue,
        };

        aob::scan(&buffer, &pattern)
            .iter()
            .for_each(|index| println!("0x{:X} +0x{:X}", base_address, index));
    }
}
