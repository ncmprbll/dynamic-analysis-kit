use dynamic_analysis_kit::*;

fn main() {
    for entry in list_processes().unwrap() {
        println!(
            "{} {:?}",
            entry.executable_name, entry.internal.th32ProcessID
        );
    }
}
