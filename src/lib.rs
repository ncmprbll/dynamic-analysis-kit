use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{Diagnostics::ToolHelp::*, Threading::*},
    },
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

#[derive(Debug)]
pub struct HandleWrapper {
    handle: HANDLE,
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        match unsafe { CloseHandle(self.handle) } {
            Ok(_) => (),
            Err(err) => panic!("Failed to close the handle with code: {}", err.code()),
        };
    }
}

pub fn process_handle_by_name(name: &str) -> Result<Option<HandleWrapper>> {
    match list_processes()?
        .iter()
        .find(|wrapper| wrapper.executable_name == name)
    {
        Some(wrapper) => Ok(Some(HandleWrapper {
            handle: unsafe {
                OpenProcess(
                    PROCESS_ALL_ACCESS,
                    false,
                    wrapper.process_entry.th32ProcessID,
                )
            }?,
        })),
        None => Ok(None),
    }
}

pub fn process_handle_by_id(process_id: u32) -> Result<Option<HandleWrapper>> {
    if !list_processes()?
        .iter()
        .any(|wrapper| wrapper.process_entry.th32ProcessID == process_id)
    {
        return Ok(None);
    }

    Ok(Some(HandleWrapper {
        handle: unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) }?,
    }))
}
