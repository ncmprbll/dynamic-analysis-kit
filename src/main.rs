use dynamic_analysis_kit::*;

fn main() {
    for entry in list_processes().unwrap() {
        println!(
            "{} {:?}",
            entry.executable_name, entry.process_entry.th32ProcessID
        );
    }

    println!("{:?}", process_handle_by_name("msedge.exe").unwrap());
}
