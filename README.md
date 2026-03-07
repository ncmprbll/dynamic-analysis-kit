[![Crates Package Status](https://img.shields.io/crates/v/malakit.svg?logo=rust)](https://crates.io/crates/malakit)
[![Crates Documentation](https://img.shields.io/docsrs/malakit/latest.svg?logo=rust)](https://docs.rs/malakit/latest/malakit)

# Malakit
Malakit (**mal**ware **a**nalysis **kit**) is both a CLI utility and a library whose purpose is to simplify some of a boilerplate you come across when working with Windows's API.

The name sounds almost like *malachite* and it is also misleading. That is, you're not obliged to use it for malware analysis. It should suffice for any other goals you have in mind!

# Installation
`cargo install malakit --target x86_64-pc-windows-gnu`

# Usage
## Library
Refer to the [documentation](https://docs.rs/malakit/latest/malakit).

## CLI
```
PS > .\malakit.exe ps
0     [System Process]
4     System
...
33736 Code.exe
...
PS > .\malakit.exe scan 33736 "F8 C4 32 02 DB CA 2E ?? FA C4 59 02 ?? C7"
0x17ACBC20000 +0x1695DC
PS > .\malakit.exe scan 33736 --size 512 "F8 C4 32 02 DB CA 2E ?? FA C4 59 02 ?? C7"
0x17ACBC20000 +0x1695DC
```
