import importlib.util
from pathlib import Path
import sys
import unittest
import json
import struct
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from sechost_structure import summarize, rip_indirect_slot

spec = importlib.util.spec_from_file_location('static_probe', Path(__file__).resolve().parents[2] / 'scripts/inspect_sechost_static.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class BoundedToolTests(unittest.TestCase):
    def test_success(self):
        self.assertEqual(module.bounded_run([sys.executable, '-c', 'print("ok")'], 8), b'ok\n')
    def test_size_limit(self):
        with self.assertRaisesRegex(ValueError, 'output_limit'):
            module.bounded_run([sys.executable, '-c', 'print("a"*100)'], 8)
    def test_timeout(self):
        with self.assertRaisesRegex(ValueError, 'time_limit'):
            module.bounded_run([sys.executable, '-c', 'import time; time.sleep(10)'], 8, .1)
    def test_nonzero(self):
        with self.assertRaisesRegex(ValueError, 'tool_failed'):
            module.bounded_run([sys.executable, '-c', 'raise SystemExit(2)'], 8)

def image_fixture():
    image = bytearray(1024)
    image[:2] = b'MZ'
    struct.pack_into('<I',image,60,128)
    image[128:132] = b'PE\0\0'
    struct.pack_into('<HHIIIHH',image,132,0x8664,1,0,0,0,240,0)
    struct.pack_into('<H',image,152,0x20b)
    struct.pack_into('<I',image,168,0x1000)
    struct.pack_into('<Q',image,176,0x180000000)
    struct.pack_into('<I',image,208,0x2000)
    struct.pack_into('<8sIIII',image,392,b'.text\0\0\0',512,0x1000,512,512)
    return bytes(image)

class StructureTests(unittest.TestCase):
    def test_branch_and_call_closure_without_raw_content(self):
        text = r"""PRIVATE C:\host\secret.pdb
  0000000180001000: E8 0B 00 00 00 call 0000000180001010
  0000000180001005: 74 02 je 0000000180001009
  0000000180001007: 33 C0 xor eax,eax
  0000000180001009: C3 ret
  0000000180001010: B8 00 00 00 00 mov eax,0
  0000000180001015: C3 ret
"""
        result = summarize(image_fixture(), text)
        self.assertTrue(any(x.get('targetRva') == 0x1010 for x in result['facts']))
        self.assertTrue(any(x.get('condition') == 'je' for x in result['facts']))
        self.assertEqual(sum(x['kind']=='eaxZeroPattern' for x in result['facts']),1)
        self.assertEqual(result['calleeSummaries'][0]['entryRva'],0x1010)
        encoded = json.dumps(result)
        for private in ['PRIVATE','secret','pdb','180001','33 C0','xor eax']:
            self.assertNotIn(private, encoded)
    def test_bad_pe_and_missing_entry_rejected(self):
        for image,text in [(b'MZ',''), (image_fixture(),'raw arbitrary output')]:
            with self.assertRaises(ValueError): summarize(image,text)
    def test_mov_eax_eax_not_zero(self):
        result = summarize(image_fixture(), '  0000000180001000: 8B C0 mov eax,eax\n  0000000180001002: C3 ret')
        self.assertFalse(any(x['kind']=='eaxZeroPattern' for x in result['facts']))

class IndirectTests(unittest.TestCase):
    def test_signed_rip_displacement_and_rex(self):
        self.assertEqual(rip_indirect_slot(b'\xff\x15'+struct.pack('<i',32),0x1000,0x2000),('call',0x1026))
        self.assertEqual(rip_indirect_slot(b'\xff\x25'+struct.pack('<i',-32),0x1000,0x2000),('jmp',0xfe6))
        self.assertEqual(rip_indirect_slot(b'\x48\xff\x25'+struct.pack('<i',32),0x1000,0x2000),('jmp',0x1027))
    def test_truncated_nonrip_and_out_of_image_rejected(self):
        for code,rva in [(b'\xff\x25',0x1000),(b'\xff\xe0'+b'\0'*4,0x1000),(b'\xff\x25'+struct.pack('<i',-100),0),(b'\xff\x15'+struct.pack('<i',0x1000),0x1000)]:
            self.assertIsNone(rip_indirect_slot(code,rva,0x2000))
    def test_register_calls_and_invalid_instruction_rva(self):
        for register in ['rax','r11']:
            result = summarize(image_fixture(),f'  0000000180001000: FF D0 call {register}')
            self.assertTrue(result['facts'][0]['indirect'])
        for rva in [-1,0x2000]:
            self.assertIsNone(rip_indirect_slot(b'\xff\x25'+struct.pack('<i',-10),rva,0x2000))
    def test_unknown_iat_and_mnemonic_mismatch_remain_unresolved(self):
        image = bytearray(image_fixture())
        image[512:518] = b'\xff\x25'+struct.pack('<i',32)
        for mnemonic in ['jmp','call']:
            result = summarize(bytes(image),f'  0000000180001000: FF 25 20 00 00 00 {mnemonic} qword ptr [0000000180001026]')
            self.assertNotIn('import',result['facts'][0])
            self.assertNotIn('targetRva',result['facts'][0])
    def test_real_pe_iat_resolution_without_operand_address(self):
        image = bytearray(image_fixture())
        struct.pack_into('<II',image,272,0x1100,40)
        struct.pack_into('<IIIII',image,768,0x1140,0,0,0x11c0,0x1180)
        struct.pack_into('<QQ',image,832,0x11a0,0)
        image[930:942] = b'NtOpenToken\0'
        image[512:518] = b'\xff\x25'+struct.pack('<i',0x1180-0x1006)
        result = summarize(bytes(image),'  0000000180001000: FF 25 7A 01 00 00 jmp qword ptr [rip+17Ah]')
        self.assertEqual(result['facts'][0]['import'],'NtOpenToken')

if __name__ == '__main__':
    unittest.main()
