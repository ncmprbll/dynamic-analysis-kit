use std::ops::Deref;

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

impl ProcessEntryWrapper {
    fn u16_to_string(array: &[u16]) -> Result<String> {
        let first_null_position = array
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(array.len());

        Ok(String::from_utf16(&array[..first_null_position])?)
    }

    pub fn new(process_entry: PROCESSENTRY32W) -> Result<Self> {
        Ok(Self {
            process_entry,
            executable_name: Self::u16_to_string(&process_entry.szExeFile)?,
        })
    }
}

impl Deref for ProcessEntryWrapper {
    type Target = PROCESSENTRY32W;

    fn deref(&self) -> &Self::Target {
        &self.process_entry
    }
}

pub fn list_processes() -> Result<Vec<ProcessEntryWrapper>> {
    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    unsafe { Process32FirstW(snapshot, &mut process_entry) }?;

    let mut processes: Vec<ProcessEntryWrapper> = Vec::new();
    processes.push(ProcessEntryWrapper::new(process_entry)?);

    while let Ok(()) = unsafe { Process32NextW(snapshot, &mut process_entry) } {
        processes.push(ProcessEntryWrapper::new(process_entry)?);
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(processes)
}

#[derive(Debug)]
pub struct HandleWrapper {
    pub handle: HANDLE,
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        match unsafe { CloseHandle(self.handle) } {
            Ok(_) => (),
            Err(err) => panic!("Failed to close the handle with code: {}", err.code()),
        };
    }
}

impl Deref for HandleWrapper {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

/// A shortcut for a call to list_processes followed by a call to process_handle_by_id
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

pub fn process_handle_by_id(process_id: u32) -> Result<HandleWrapper> {
    Ok(HandleWrapper {
        handle: unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) }?,
    })
}

#[derive(Debug)]
pub struct ModuleEntryWrapper {
    pub module_entry: MODULEENTRY32W,
    pub module_name: String,
}

impl ModuleEntryWrapper {
    fn u16_to_string(array: &[u16]) -> Result<String> {
        let first_null_position = array
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(array.len());

        Ok(String::from_utf16(&array[..first_null_position])?)
    }

    pub fn new(module_entry: MODULEENTRY32W) -> Result<Self> {
        Ok(Self {
            module_entry,
            module_name: Self::u16_to_string(&module_entry.szModule)?,
        })
    }
}

impl Deref for ModuleEntryWrapper {
    type Target = MODULEENTRY32W;

    fn deref(&self) -> &Self::Target {
        &self.module_entry
    }
}

pub fn process_modules_by_id(process_id: u32) -> Result<Vec<ModuleEntryWrapper>> {
    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id) }?;

    unsafe { Module32FirstW(snapshot, &mut module_entry) }?;

    let mut modules: Vec<ModuleEntryWrapper> = Vec::new();
    modules.push(ModuleEntryWrapper::new(module_entry)?);

    while let Ok(()) = unsafe { Module32NextW(snapshot, &mut module_entry) } {
        modules.push(ModuleEntryWrapper::new(module_entry)?);
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(modules)
}
