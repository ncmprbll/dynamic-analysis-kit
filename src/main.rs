use dynamic_analysis_kit::*;

fn main() {
    let processes = list_processes().unwrap();

    // for entry in processes.iter() {
    //     println!(
    //         "{} {:?}",
    //         entry.executable_name, entry.process_entry.th32ProcessID
    //     );
    // }

    let entry = processes
        .iter()
        .find(|x| x.executable_name == "msedge.exe")
        .unwrap();

    let handle = process_handle_by_id(entry.th32ProcessID).unwrap();

    for entry in process_modules_by_id(entry.th32ProcessID).unwrap() {
        if entry.module_name == "telclient.dll" {
            println!("{} 0x{:X}", entry.module_name, entry.modBaseAddr as i64);
            for info in get_readable_pages_by_address(&handle, entry.modBaseAddr) {
                println!("{:?}", info)
            }
        }
    }
}
