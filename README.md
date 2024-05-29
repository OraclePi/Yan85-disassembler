# Yan85-disassembler
A simple Yan85 disassembler used for pwn.college challs

## sample mapping:

change the key-value pair according to different situation.

**VM_SYSCALL**:
| num  | syscall     |
| ---- | ----------- |
| 0x2  | open        |
| 0x10 | read_code   |
| 0x20 | read_memory |
| 0x8  | write       |
| 0x1  | exit        |
| 0x4  | sleep       |

**VM_REGS**:
| num  | reg |
| ---- | --- |
| 0x20 | a   |
| 0x4  | b   |
| 0x1  | c   |
| 0x8  | d   |
| 0x40 | s   |
| 0x10 | i   |
| 0x2  | f   |

**VM_INST**:
| num  | inst |
| ---- | ---- |
| 0x40 | IMM  |
| 0x80 | ADD  |
| 0x2  | STK  |
| 0x1  | STM  |
| 0x4  | LDM  |
| 0x10 | CMP  |
| 0x20 | JMP  |
| 0x8  | SYS  |


    IMM b = 0x3a: store 0x3a in reg:b
    STM *b = a: store value of latter reg at former's reference mem
    ADD b c: add two regs and store at the former
    LDM b = *b: load value of latter's reference mem to former reg
    CMP a b: compare and set reg:f to result
    JMP N d:jmp to reg:d using method N
    STK NONE a:function as push or pop according to the args
    SYS 0x1 a: invoke syscall , return value to reg:a




## Dependency:
```bash
pip3 install -r requirements.txt
```

## Usage:
check `example/` for sample input
```bash
usage: ad85.py [-h] [-d | -a] [-b64] file

yan85 VM disassembler

positional arguments:
  file               file to process

options:
  -h, --help         show this help message and exit
  -d, --disassemble  disassemble the yan85 opcode
  -a, --assemble     assemble the yan85 instruction
  -b64, --base64     base64 encode the output
```
