#!/usr/bin/env python3
import argparse
from pwn import info


def parse_args():
    parser = argparse.ArgumentParser(description="yan85 VM disassembler")
    parser.add_argument(
        "-f", "--file", help="opcode file to disassemble")
    args = parser.parse_args()

    if args.file is None:
        parser.print_help()
        exit()

    return args


vm_op = {
    "IMM": 0x20,
    "ADD": 0x4,
    "STK": 0x10,
    "STM": 0x2,
    "LDM": 0x40,
    "CMP": 0x80,
    "JMP": 0x8,
    "SYS": 0x1
}

vm_reg = {
    "a": 0x1,
    "b": 0x2,
    "c": 0x8,
    "d": 0x40,
    "s": 0x4,
    "i": 0x20,
    "f": 0x10,
    "NONE": 0x0
}

vm_syscall = {
    "open": 0x10,
    "read_code": 0x4,
    "read_memory": 0x20,
    "write": 0x2,
    "exit": 0x8,
    "sleep": 0x1
}

vm_jmp = {
    "L": 0x10,
    "G": 0x8,
    "E": 0x1,
    "N": 0x2,
    "Z": 0x4,
    "*": 0x0,
    "LG": 0x18,
    "LE": 0x11,
    "LN": 0x12,
    "LZ": 0x14
}


def reg(val):
    for k, v in vm_reg.items():
        if val == v:
            return k
    assert False, "Unknown register value"


class VM_OP:
    @staticmethod
    def imm(arg1, arg2):
        return "IMM", reg(arg1), hex(arg2)

    @staticmethod
    def add(arg1, arg2):
        return "ADD", reg(arg1), reg(arg2)

    @staticmethod
    def stk(arg1, arg2):
        return "STK", reg(arg1), reg(arg2)

    @staticmethod
    def stm(arg1, arg2):
        return "STM", reg(arg1), reg(arg2)

    @staticmethod
    def ldm(arg1, arg2):
        return "LDM", reg(arg1), reg(arg2)

    @staticmethod
    def cmp(arg1, arg2):
        return "CMP", reg(arg1), reg(arg2)

    @staticmethod
    def jmp(arg1, arg2):
        for k, v in vm_jmp.items():
            if arg1 == v:
                return "JMP", k, reg(arg2)
        assert False, "Unknown jmp type"

    @staticmethod
    def sys(arg1, arg2):
        for k, v in vm_syscall.items():
            if arg1 == v:
                for k1, v1 in vm_reg.items():
                    if arg2 == v1:
                        # return k, "", k1
                        return k, "", ""
                assert False, "Unknown register"
        assert False, "Unknown syscall"


def vm_disasm(opcode):
    assert len(opcode) % 3 == 0 and "Invalid opcode length"
    op, arg1, arg2 = opcode
    for k, v in vm_op.items():
        if op == v:
            if k == "IMM":
                return VM_OP.imm(arg2, arg1)
            elif k == "ADD":
                return VM_OP.add(arg2, arg1)
            elif k == "STK":
                return VM_OP.stk(arg2, arg1)
            elif k == "STM":
                return VM_OP.stm(arg2, arg1)
            elif k == "LDM":
                return VM_OP.ldm(arg2, arg1)
            elif k == "CMP":
                return VM_OP.cmp(arg2, arg1)
            elif k == "JMP":
                return VM_OP.jmp(arg2, arg1)
            elif k == "SYS":
                return VM_OP.sys(arg2, arg1)


def disasm_output(opcode):
    for i in range(0, len(opcode), 3):
        op, arg1, arg2 = vm_disasm(opcode[i:i+3])
        if op == "STM":
            info(f"{op} *{arg1} = {arg2}")
        elif op == "LDM":
            info(f"{op} {arg1} = *{arg2}")
        elif op == "IMM":
            info(f"{op} {arg1} = {arg2}")
        elif op == "STK":
            if arg1 == "NONE":
                info(f"push {arg2}")
            elif arg2 == "NONE":
                info(f"pop {arg1}")

        else:
            info(f"{op} {arg1} {arg2}")


if __name__ == "__main__":

    args = parse_args()

    with open(args.file, "rb") as f:
        vm_code = f.read()

    disasm_output(vm_code)
