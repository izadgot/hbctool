from hbctool import hbc as hbcl, hasm
from .translator import assemble, disassemble
import unittest
import re
import pathlib
import json

basepath = pathlib.Path(__file__).parent.absolute()

class TestHBC62(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHBC62, self).__init__(*args, **kwargs)
        with open(basepath / "example" / "index.android.bundle", "rb") as f:
            self.hbc = hbcl.load(f)
        # with open(basepath / "example" / "objdump.out", "r") as f:
        #     self.objdump = f.read()
        with open(basepath / "example" / "pretty.out", "r") as f:
            self.pretty = f.read()
        with open(basepath / "example" / "raw.out", "r") as f:
            self.raw = f.read()

    def test_get_function(self):
        # hbcdump version 62 cannot fetch
        # target_offsets = re.findall(r"([0-9a-f]+) \<_[0-9]+\>", self.objdump)
        target_args = re.findall(r"Function<(.*?)>([0-9]+)\(([0-9]+) params, ([0-9]+) registers,\s?([0-9]+) symbols\):", self.pretty)

        functionCount = self.hbc.getFunctionCount()

        # self.assertEqual(functionCount, len(target_offsets))
        self.assertEqual(functionCount, len(target_args))

        for i in range(functionCount):
            # target_offset = target_offsets[i]
            target_functionName, _, target_paramCount, target_registerCount, target_symbolCount = target_args[i]

            try:
                functionName, paramCount, registerCount, symbolCount, _, funcHeader = self.hbc.getFunction(i)
            except AssertionError:
                self.fail()

            self.assertEqual(functionName, target_functionName)
            self.assertEqual(paramCount, int(target_paramCount))
            self.assertEqual(registerCount, int(target_registerCount))
            self.assertEqual(symbolCount, int(target_symbolCount))
            # self.assertEqual(funcHeader["offset"], int(target_offset, 16))
    
    def test_get_string(self):
        target_strings = re.findall(r"[isp][0-9]+\[([UTFASCI16-]+), ([0-9]+)..([0-9-]+)\].*?:\s?(.*)", self.pretty)
        stringCount = self.hbc.getStringCount()

        self.assertEqual(stringCount, len(target_strings))

        for i in range(stringCount):
            val, header = self.hbc.getString(i)
            isUTF16, offset, length = header

            t, target_start, target_end, target_val = target_strings[i]

            target_isUTF16 = t == "UTF-16"
            target_offset = int(target_start)
            target_length = int(target_end) - target_offset + 1

            self.assertEqual(isUTF16, target_isUTF16)
            self.assertEqual(offset, target_offset)
            self.assertEqual(length, target_length)

            # TODO : Implement this please
            # self.assertEqual(val, target_val)

    def test_translator(self):
        functionCount = self.hbc.getFunctionCount()

        for i in range(functionCount):
            _, _, _, _, bc, _ = self.hbc.getFunction(i, disasm=False)

            self.assertEqual(assemble(disassemble(bc)), bc)
            
class TestParser62(unittest.TestCase):
    def test_hbc(self):
        with open(basepath / "example" / "index.android.bundle", "rb") as f:
            hbc = hbcl.load(f)

        with open(pathlib.Path("/tmp") / "hbctool_test.android.bundle", "wb") as f:
            hbcl.dump(hbc, f)

        with open(basepath / "example" / "index.android.bundle", "rb") as f:
            a = f.read()

        with open(pathlib.Path("/tmp") / "hbctool_test.android.bundle", "rb") as f:
            b = f.read()

        self.assertEqual(a, b)

    def test_hasm(self):
        with open(basepath / "example" / "index.android.bundle", "rb") as f:
            a = hbcl.load(f)

        tmp_path = pathlib.Path("/tmp") / "hbctool_test"
        hasm.dump(a, tmp_path, force=True)
        b = hasm.load(tmp_path)

        self.assertEqual(json.dumps(a.getObj()), json.dumps(b.getObj()))