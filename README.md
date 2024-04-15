# sohook

## Introduction
sohook is an injector which can inject a dynamic library into a target executable.

Compared to existing implementations, sohook allows you to inject a library even if the target doesn't use libc as long as your system supports `LD_PRELOAD`. It also provides the possibility for you to call the function inside the target as long as you have disassembled it. So you can interact with the target executable in **any** high-level programming language that can generate a dynamic library with symtab exported. 

For now, sohook **only** supports dynamic injection using *ptrace*, and **only** works for *little-endian-x64-linux-executables*.

## Build
Just run the `make` command under the root directory of the project:
```sh
$ make
```

Make command     | Description
:-:|:-:
release | Build the project without debug information and enable O2 optimization, target name is `sohook`
debug | Build the project with debug information and optimizations, target name is `sohookd`
test | Generate `test.so` for `target`
clean | Remove `*.o`, `*.od`, `sohook` and `sohookd`
## 

## Usage
```
Usage: sohook [OPTIONS] EXECUTABLE
Inject dynamic library(.so) to target executable.

Options:
  -d, --dynamic        Enable dynamic mode.
  -e, --embedded       Use dynamic library embedded hook info.
  -h, --help           Display this information.
  -m, --metadata       Hook data.
  -s, --so             Dynamic library to be injected.
```

## Coding
For `C/C++`, you can simply include the `sohook.h` file and interact using the macros defined inside. For example, check for `test.c`.

For now, `gcc 11.4.0` is tested.