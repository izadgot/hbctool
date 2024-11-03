from .util import *
import hbctool.hbc as hbcl
import json
import os
import shutil
import re
from pathlib import Path

def write_func(f, func, i, hbc):
    functionName, paramCount, registerCount, symbolCount, insts, _ = func
    f.write(f"Function<{functionName}>{i}({paramCount} params, {registerCount} registers, {symbolCount} symbols):\n")
    for opcode, operands in insts:
        f.write(f"\t{opcode.ljust(20,' ')}\t")
        o = []
        ss = []
        for ii, v in enumerate(operands):
            t, is_str, val = v
            o.append(f"{t}:{val}")

            if is_str:
                s, _ = hbc.getString(val)
                ss.append((ii, val, s))
                
        
        f.write(f"{', '.join(o)}\n")
        if len(ss) > 0:
            for ii, val, s in ss:
                f.write(f"\t; Oper[{ii}]: String({val}) {repr(s)}\n")

            f.write("\n")

    f.write("EndFunction\n\n")

def dump(hbc, path, force=False):
    
    if os.path.exists(path) and not force:
        c = input(f"'{path}' exists. Do you want to remove it ? (y/n): ").lower().strip()
        if c[:1] == "y":
            shutil.rmtree(path)
        else:
            exit(1337)
    
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    
    # Write all obj to metadata.json
    with open(path / "metadata.json", "w") as f:
        json.dump(hbc.getObj(), f)
    
    stringCount = hbc.getStringCount()
    functionCount = hbc.getFunctionCount()

    ss = []
    for i in range(stringCount):
        val, header = hbc.getString(i)
        ss.append({
            "id": i,
            "isUTF16": header[0] == 1,
            "value": val
        })
    
    with open(path / "string.json", "w") as f:
        json.dump(ss, f, indent=4)

    with open(path / "instruction.hasm", "w") as f:
        for i in range(functionCount):
            write_func(f, hbc.getFunction(i), i, hbc)

def read_all_func(hasm, hbc):
    func_asms = [func_asm + "EndFunction" for func_asm in hasm.split("EndFunction\n\n")[:-1]]
    functionCount = hbc.getFunctionCount()

    rs = [''] * functionCount

    for func_asm in func_asms:
        m = re.search(r"Function<.*?>([0-9]+)\([0-9]+ params, [0-9]+ registers,\s?[0-9]+ symbols\):", func_asm)
        assert m, f"Malicious function header: {func_asm}"

        fid = int(m.group(1))

        assert fid >= 0 and fid < functionCount, f"Malicious function ID: {fid} (must lower than {functionCount})"

        rs[fid] = func_asm
    
    return rs


def read_func(func_asms, i):
    func_asm = func_asms[i]

    m = re.search(r"Function<.*?>([0-9]+)\(([0-9]+) params, ([0-9]+) registers,\s?([0-9]+) symbols\):\n(.+?)\nEndFunction", func_asm, re.DOTALL)
    assert m, f"Malicious function header: {func_asm}"

    functionName = m.group(1)
    paramCount = int(m.group(2))
    registerCount = int(m.group(3))
    symbolCount = int(m.group(4))
    insts_asm = m.group(5)

    inst_lines = insts_asm.split("\n")

    insts = []

    for inst_line in inst_lines:
        inst_line = inst_line.strip()

        if len(inst_line) == 0 or inst_line.startswith(";"):
            continue

        inst_words = inst_line.split()

        opcode = inst_words[0]

        operands = []
        for oper in inst_words[1:]:
            oper_t, val = oper.replace(",", "").split(":")
            
            if oper_t == 'Double':
                val = float(val)
            else:
                val = int(val)
            
            operands.append((oper_t, False, val))
        
        insts.append((opcode, operands))
    
    return functionName, paramCount, registerCount, symbolCount, insts, None


def load(path):
    path = Path(path)

    assert path.exists(), f"{path} does not exist."
    assert (path / "metadata.json").exists(), f"metadata.json not found."
    assert (path / "string.json").exists(), f"string.json not found."
    assert (path / "instruction.hasm").exists(), f"instruction.hasm not found."

    with open(path / "metadata.json", "r") as f:
        hbc = hbcl.loado(json.load(f))

    with open(path / "instruction.hasm", "r") as f:
        hasm_content = f.read()

    with open(path / "string.json", "r") as f:
        strings = json.load(f)

    for string in strings:
        hbc.setString(string["id"], string["value"])

    func_asms = read_all_func(hasm_content, hbc)
    for i in range(len(func_asms)):
        func = read_func(func_asms, i)
        hbc.setFunction(i, func)

    return hbc

