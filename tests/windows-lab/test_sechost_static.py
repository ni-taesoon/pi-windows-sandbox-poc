import importlib.util
from pathlib import Path
import sys
import unittest
import json
import struct
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from sechost_structure import summarize

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
        self.assertEqual(sum(x['kind']=='eaxZeroPattern' for x in result['facts']),2)
        encoded = json.dumps(result)
        for private in ['PRIVATE','secret','pdb','180001','33 C0','xor eax']:
            self.assertNotIn(private, encoded)
    def test_bad_pe_and_missing_entry_rejected(self):
        for image,text in [(b'MZ',''), (image_fixture(),'raw arbitrary output')]:
            with self.assertRaises(ValueError): summarize(image,text)
    def test_mov_eax_eax_not_zero(self):
        result = summarize(image_fixture(), '  0000000180001000: 8B C0 mov eax,eax\n  0000000180001002: C3 ret')
        self.assertFalse(any(x['kind']=='eaxZeroPattern' for x in result['facts']))

if __name__ == '__main__':
    unittest.main()
