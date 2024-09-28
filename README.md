# MiniDB
A project for NYCU Unix Programming 2024.

## About the Debugger
MiniDB is an interactive debugger designed for debugging 64-bit `x86-64` assembly-level instructions. It supports debugging of static non-Position Independent Executable (non-PIE) programs on `x86-64` architecture.

You can run the following command to inspect its properties:
```
file <program_name>
```

## Usage
Load the target program before starting to debug: 
```
$ ./mdb <program_name>
```
```
$ ./mdb
(mdb) load <program_name>
```

## Supported Commands
- Step Instruction
- Continue Execution
- Show Registers Info
- Breakpoint: Set, Show Info, and Delete
- Patch Memory
- System Call

### Step Instruction
Execute a single assembly instruction.
```
(mdb) si
```

### Continue Execution
Continue the execution of the target program until it terminates or hits a breakpoint.
```
(mdb) cont
```

### Show Registers Info
Show all the registers and their corresponding values in hexadecimal format.
```
(mdb) info reg
```

### Breakpoint: Set, Show Info, and Delete
#### Set breakpoint
Sets a breakpoint at a specific memory address in hexadecimal format.
```
(mdb) break <hex address>
```
#### Show Breakpoints Info
Lists all active breakpoints, showing their ID and address.
```
(mdb) info break
```
#### Delete Breakpoint
Removes a breakpoint by its ID.
```
(mdb) delete <id>
```

### Patch Memory
Modifies the memory starting at a specified address. The value will be written in hexadecimal, and the length in bytes can be 1, 2, 4, or 8.
```
(mdb) patch <hex address> <hex value> <len>
```

### System Call
The program execution should break at every system call instruction unless it hits a breakpoint.
```
(mdb) syscall
```

<!-- ## Example Usage
```
$ ./mdb ./test_program
(mdb) break 0x400123
(mdb) cont
(mdb) info reg
(mdb) si
(mdb) patch 0x6000f8 0xdeadbeef 4
(mdb) syscall
``` -->