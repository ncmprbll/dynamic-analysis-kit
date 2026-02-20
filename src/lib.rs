use windows::{
    Win32::{Foundation::CloseHandle, System::Diagnostics::ToolHelp::*},
    core::Result,
};

#[derive(Debug)]
pub struct ProcessEntryWrapper {
    pub process_entry: PROCESSENTRY32W,
    pub executable_name: String,
}

fn u16_to_string(array: &[u16]) -> Result<String> {
    let first_null_position = array
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(array.len());

    Ok(String::from_utf16(&array[..first_null_position])?)
}

pub fn list_processes() -> Result<Vec<ProcessEntryWrapper>> {
    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    unsafe { Process32FirstW(snapshot, &mut process_entry) }?;

    let mut processes: Vec<ProcessEntryWrapper> = Vec::new();
    processes.push(ProcessEntryWrapper {
        process_entry: process_entry,
        executable_name: u16_to_string(&process_entry.szExeFile)?,
    });

    while let Ok(()) = unsafe { Process32NextW(snapshot, &mut process_entry) } {
        processes.push(ProcessEntryWrapper {
            process_entry: process_entry,
            executable_name: u16_to_string(&process_entry.szExeFile)?,
        });
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(processes)
}
