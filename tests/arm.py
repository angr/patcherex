#!/usr/bin/env python

import os
import subprocess
import unittest
import shutil
import tempfile
import logging

from patcherex import *

logging.getLogger("patcherex").setLevel("DEBUG")


class Tests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bin_location = str(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "./test_binaries/armhf",
            )
        )

    def test_raw_file_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x44C, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x1044C, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x103E2, "ldr r1, [pc, #0x14]"),
                ModifyInstructionPatch(0x103E4, "add r1, pc"),
                ModifyInstructionPatch(0x103E6, "mov r0, r1"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch(self):
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, =0x1044C
            mov r2, 3
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x103EC, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2(self):
        instrs = """
            mov r7, 0x1
            mov r0, 0x32
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs, is_thumb=True),
                ModifyInstructionPatch(0x103EC, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x1044B, num_bytes=4),
            ],
            expected_output=b"\xF0\x20\xE3",
            expected_returnCode=0,
        )

    def test_modify_data_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x1044C, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_data}
            mov r2, %s
            svc 0
        """ % hex(
            tlen
        )
        p2 = InsertInstructionPatch(0x103EC, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x1044D, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x52C, code)],
            expected_output=b"70707070",
            expected_returnCode=0,
        )

    def test_replace_function_patch_with_function_reference(self):
        code = """
        extern int add(int, int);
        extern int subtract(int, int);
        int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = subtract(c, a)) if(b <= 0) return c; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x588, code)],
            expected_output=b"-21-21",
            expected_returnCode=0,
        )

    def test_replace_function_patch_with_function_reference_and_rodata(self):
        code = """
        extern int printf(const char *format, ...);
        int multiply(int a, int b){ printf("%sWorld %s %s %s %d\\n", "Hello ", "Hello ", "Hello ", "Hello ", a * b);printf("%sWorld\\n", "Hello "); return a * b; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x588, code)],
            expected_output=b"Hello World Hello  Hello  Hello  21\nHello World\n2121",
            expected_returnCode=0,
        )

    def run_one(
        self,
        filename,
        patches,
        set_oep=None,
        inputvalue=None,
        expected_output=None,
        expected_returnCode=None,
    ):
        filepath = os.path.join(self.bin_location, filename)
        pipe = subprocess.PIPE

        with tempfile.TemporaryDirectory() as td:
            tmp_file = os.path.join(td, "patched")
            p = Patcherex(filepath)
            for patch in patches:
                p.patches.append(patch)
            p.apply_patches()
            p.binfmt_tool.save_binary(tmp_file)
            # os.system(f"readelf -hlS {tmp_file}")

            p = subprocess.Popen(
                ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", tmp_file],
                stdin=pipe,
                stdout=pipe,
                stderr=pipe,
            )
            res = p.communicate(inputvalue)
            if expected_output:
                if res[0] != expected_output:
                    self.fail(
                        f"AssertionError: {res[0]} != {expected_output}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(res[0], expected_output)
            if expected_returnCode:
                if p.returncode != expected_returnCode:
                    self.fail(
                        f"AssertionError: {p.returncode} != {expected_returnCode}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(p.returncode, expected_returnCode)

    def dump_file(self, file):
        shutil.copy(file, "/tmp/patcherex_failed_binary")
        return "/tmp/patcherex_failed_binary"


if __name__ == "__main__":
    unittest.main()
