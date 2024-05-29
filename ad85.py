#!/usr/bin/env python3
import argparse
import base64
from pwn import info


def parse_args():
    parser = argparse.ArgumentParser(description="yan85 VM disassembler")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--disassemble", action="store_true",
                       help="disassemble the yan85 opcode")
    group.add_argument("-a", "--assemble", action="store_true",
                       help="assemble the yan85 instruction")
    parser.add_argument("-b64", "--base64", action="store_true",
                        help="base64 encode the output")
    parser.add_argument(
        "file", help="file to process")
    args = parser.parse_args()

    if args.file is None:
        parser.print_help()
        exit()

    return args


vm_op = {
    "IMM": 0x40,
    "ADD": 0x80,
    "STK": 0x2,
    "STM": 0x1,
    "LDM": 0x4,
    "CMP": 0x10,
    "JMP": 0x20,
    "SYS": 0x8
}  # modified

vm_reg = {
    "a": 0x20,
    "b": 0x4,
    "c": 0x1,
    "d": 0x8,
    "s": 0x40,
    "i": 0x10,
    "f": 0x2,
    "NONE": 0x0
}  # modified

vm_syscall = {
    "open": 0x2,
    "read_code": 0x10,
    "read_memory": 0x20,
    "write": 0x8,
    "exit": 0x1,
    "sleep": 0x4
}  # modified

vm_jmp = {
    "L": 0x8,
    "G": 0x1,
    "E": 0x10,
    "N": 0x4,
    "Z": 0x2,
    "*": 0x0
}  # modified


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
                return VM_OP.imm(arg1, arg2)
            elif k == "ADD":
                return VM_OP.add(arg1, arg2)
            elif k == "STK":
                return VM_OP.stk(arg1, arg2)
            elif k == "STM":
                return VM_OP.stm(arg1, arg2)
            elif k == "LDM":
                return VM_OP.ldm(arg1, arg2)
            elif k == "CMP":
                return VM_OP.cmp(arg1, arg2)
            elif k == "JMP":
                return VM_OP.jmp(arg1, arg2)
            elif k == "SYS":
                return VM_OP.sys(arg1, arg2)


def vm_asm(instruction):
    op, arg1, arg2 = [ins.strip("\n").replace(" ", "")
                      for ins in instruction.split(" ")]
    for k, v in vm_op.items():
        if op == k:
            if k == "IMM":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        return (bytes([v]) + bytes([v1]) + bytes.fromhex(arg2.replace("0x", "")))
            elif k == "ADD":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "STK":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "STM":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "LDM":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "CMP":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_reg.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "JMP":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_jmp.items():
                    if arg1 == k1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])
            elif k == "SYS":
                info(f"{op} {arg1} {arg2}")
                for k1, v1 in vm_syscall.items():
                    if int(arg1, 16) == v1:
                        for k2, v2 in vm_reg.items():
                            if arg2 == k2:
                                return bytes([v, v1, v2])


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


def asm_output(insts):
    payload = b""
    insts = insts.split("\n")
    for inst in insts:
        op, arg1, arg2 = vm_asm(inst)
        payload += bytes([op, arg1, arg2])

    return payload


if __name__ == "__main__":

    args = parse_args()

    if args.disassemble:
        with open(args.file, "rb") as f:
            vm_code = f.read()
            disasm_output(vm_code)
    elif args.assemble:
        with open(args.file, "r") as f:
            ins = f.read()
            if args.base64:
                info(f"base64: {base64.b64encode(asm_output(ins))}")
            else:
                info(f"payload: {asm_output(ins)}")
