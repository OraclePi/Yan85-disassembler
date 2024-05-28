# Yan85-disassembler
A simple Yan85 disassembler used for pwn.college challs

## mapping:
**VM_SYSCALL**:
| num  | syscall     |
| ---- | ----------- |
| 0x10 | open        |
| 0x4  | read_code   |
| 0x20 | read_memory |
| 0x2  | write       |
| 0x8  | exit        |
| 0x1  | sleep       |

**VM_REGS**:
| num  | reg |
| ---- | --- |
| 0x1  | a   |
| 0x2  | b   |
| 0x8  | c   |
| 0x40 | d   |
| 0x4  | s   |
| 0x20 | i   |
| 0x10 | f   |

**VM_INST**:
| num  | inst |
| ---- | ---- |
| 0x20 | IMM  |
| 0x4  | ADD  |
| 0x10 | STK  |
| 0x2  | STM  |
| 0x40 | LDM  |
| 0x80 | CMP  |
| 0x8  | JMP  |
| 0x1  | SYS  |


    IMM b = 0x3a: store 0x3a in reg:b
    SYS 0x1 a: invoke syscall , return value to reg:a
    STM *b = a: store value of latter reg at former's reference mem
    ADD b c: add two regs and store at the former
    LDM b = *b: load value of latter's reference mem to former reg
    CMP a b: compare and set reg:f to result
    JMP N d:jmp to reg:d using method N
    STK:function as push or pop according to the args



## Dependency:
```bash
pip install -r requirements.txt
```

## Usage:
```bash
./yan85_disasm.py -f FILE
```
