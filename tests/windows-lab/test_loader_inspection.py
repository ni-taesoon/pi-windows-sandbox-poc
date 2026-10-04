import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('loader',ROOT/'scripts/inspect_windows_loader.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def pe_fixture(name=b'python312.dll'):
    b=bytearray(1536);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',b,132,0x8664,1,0,0,0,240,0)
    struct.pack_into('<H',b,152,0x20b);struct.pack_into('<I',b,212,512);struct.pack_into('<I',b,260,16)
    struct.pack_into('<II',b,272,0x1000,40)
    struct.pack_into('<8sIIII',b,392,b'.rdata\0\0',512,0x1000,512,512)
    struct.pack_into('<IIIII',b,512,0,0,0,0x1060,0);b[608:608+len(name)+1]=name+b'\0'
    return bytes(b)

def event(path=m.STAGED_PYTHON,provider='Application Error',extra=''):
    return rf'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>1000</EventID><TimeCreated SystemTime="2026-10-04T11:00:05Z"/></System><EventData><Data Name="AppPath">{path}</Data><Data Name="ExceptionCode">c0000142</Data><Data Name="ModulePath">C:\private\python312.dll</Data><Data Name="UserSid">S-1-5-21-DO-NOT-EXPORT</Data><Data Name="Message">SECRET MESSAGE</Data>{extra}</EventData></Event>'''

def payload(xml):
    return {'window':{'start':'2026-10-04T11:00:00Z','end':'2026-10-04T11:00:15Z'},'records':[{'channel':'Application','xml':xml}]}

class LoaderInspectionTests(unittest.TestCase):
    def test_pe_import_without_execution(self):
        self.assertEqual(m.pe_imports(pe_fixture())['imports'],['python312.dll'])
        self.assertEqual(m.pe_imports(pe_fixture())['delayImports'],[])
    def test_pe_bad_bounds_and_names_fail(self):
        for data in [b'MZ',pe_fixture(b'..\\private.dll'),pe_fixture(b'not_a_dll.exe'),b'Z'*(m.MAX_IMAGE+1)]:
            with self.assertRaises(ValueError):m.pe_imports(data)
        b=bytearray(pe_fixture());struct.pack_into('<I',b,524,0xfffffff0)
        with self.assertRaises(ValueError):m.pe_imports(b)
    def test_event_whitelist_drops_sensitive_fields(self):
        result=m.sanitize_events(payload(event()));text=json.dumps(result)
        self.assertEqual(len(result['events']),1)
        self.assertEqual(result['events'][0]['moduleBasename'],'python312.dll')
        self.assertIn('c0000142',text)
        for forbidden in ['S-1-5','SECRET MESSAGE','C:',r'private',m.STAGED_PYTHON]:self.assertNotIn(forbidden,text)
    def test_pid_or_basename_alone_cannot_attribute(self):
        for path in ['python.exe',r'C:\other\python.exe','']:
            result=m.sanitize_events(payload(event(path,extra='<Data Name="ProcessId">1234</Data>')))
            self.assertEqual(result['events'],[])
    def test_unknown_provider_or_wrong_time_rejected(self):
        self.assertEqual(m.sanitize_events(payload(event(provider='Untrusted')))['events'],[])
        self.assertEqual(m.sanitize_events(payload(event().replace('11:00:05','11:01:05')))['events'],[])
    def test_conflicting_or_unsupported_attribution_is_not_guessed(self):
        extra='<Data Name="ProcessPath">C:\\other\\python.exe</Data>'
        self.assertEqual(m.sanitize_events(payload(event(extra=extra)))['events'],[])
        self.assertEqual(m.sanitize_events(payload(event(provider='SideBySide')))['events'],[])
        self.assertEqual(m.sanitize_events(payload(event().replace('<EventID>1000','<EventID>1001')))['events'],[])
    def test_status_encoding_is_preserved_not_reinterpreted(self):
        result=m.sanitize_events(payload(event(extra='<Data Name="ErrorCode">12345678</Data>')))
        self.assertIn({'field':'ErrorCode','encoded':'12345678'},result['events'][0]['statusCodes'])
    def test_xml_and_count_bounds(self):
        for xml in ['<!DOCTYPE x>'+event(),'x'*(m.MAX_XML+1),event(extra='<Data Name="AppPath">duplicate</Data>')]:
            self.assertEqual(m.sanitize_events(payload(xml))['invalidCount'],1)
        p=payload(event());p['records']*=m.MAX_EVENTS+1
        with self.assertRaises(ValueError):m.sanitize_events(p)
        p=payload(event());p['window']['end']='2026-10-04T11:03:00Z'
        with self.assertRaises(ValueError):m.sanitize_events(p)
    def test_probe_import_allowlist_is_kernel32_only(self):
        valid={'machine':'0x8664','imports':['kernel32.dll'],'delayImports':[]}
        m.validate_probe_imports(valid)
        for patch in [{'imports':[]},{'imports':['kernel32.dll','ucrtbase.dll']},{'imports':['kernel32.dll','msvcrt.dll']},{'delayImports':['python312.dll']},{'machine':'0x014C'}]:
            with self.assertRaises(ValueError):m.validate_probe_imports({**valid,**patch})
    def test_collector_has_no_trace_or_runtime_execution(self):
        source=(ROOT/'scripts/collect_windows_loader_events.ps1').read_text()
        for forbidden in ['New-WinEvent','wevtutil','logman','Set-Acl','Start-Process','Enable-']:
            self.assertNotIn(forbidden,source)
        self.assertIn('-MaxEvents 32',source)
        self.assertNotIn('subprocess',(ROOT/'scripts/inspect_windows_loader.py').read_text())
if __name__=='__main__':unittest.main()
