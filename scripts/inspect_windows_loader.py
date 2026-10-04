#!/usr/bin/env python3
"""Offline PE metadata and bounded existing-event sanitization; never runs a PE."""
import argparse
import datetime as dt
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import struct
import stat
import sys

MAX_IMAGE = 32 * 1024 * 1024
MAX_INPUT = 2 * 1024 * 1024
MAX_EVENTS = 128
MAX_XML = 16384
STAGED_PYTHON = r"C:\PiSandboxLab\runtime\python.exe"
MODULE = re.compile(r"[A-Za-z0-9_.-]{1,128}\.(?:dll|exe)", re.I | re.ASCII)
CHANNEL_PROVIDERS = {"Application": {"Application Error", "Windows Error Reporting", "SideBySide"}, "System": {"Application Popup"}}

def pe_imports(data):
    if len(data) > MAX_IMAGE or len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('invalid_pe')
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('invalid_pe_bounds')
        return struct.unpack_from(fmt, data, offset)
    pe = unpack('<I', 60)[0]
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid_pe_signature')
    machine, section_count, _, _, _, optional_size, _ = unpack('<HHIIIHH', pe+4)
    if not 1 <= section_count <= 96:
        raise ValueError('invalid_section_count')
    optional = pe + 24
    magic = unpack('<H', optional)[0]
    if magic == 0x20B:
        directories, count_offset = optional+112, optional+108
    elif magic == 0x10B:
        directories, count_offset = optional+96, optional+92
    else:
        raise ValueError('unsupported_pe_kind')
    if optional_size < directories-optional or optional+optional_size > len(data):
        raise ValueError('invalid_optional_header')
    count = unpack('<I', count_offset)[0]
    if count > 16 or directories + count*8 > optional+optional_size:
        raise ValueError('invalid_directories')
    headers_size = unpack('<I', optional+60)[0]
    sections = []
    for index in range(section_count):
        _, virtual_size, rva, raw_size, raw_offset = unpack('<8sIIII', optional+optional_size+40*index)
        if raw_offset + raw_size > len(data):
            raise ValueError('invalid_section_bounds')
        sections.append((rva, virtual_size, raw_size, raw_offset))
    def offset(rva, length):
        candidates = []
        if rva < headers_size and rva+length <= min(headers_size, len(data)):
            candidates.append(rva)
        for start, virtual, raw, file_offset in sections:
            delta = rva-start
            if 0 <= delta < max(virtual, raw) and delta+length <= raw:
                candidates.append(file_offset+delta)
        if len(candidates) != 1:
            raise ValueError('invalid_or_ambiguous_rva')
        return candidates[0]
    def name_at(rva):
        raw = bytearray()
        for index in range(133):
            byte = data[offset(rva+index, 1)]
            if byte == 0:
                value = raw.decode('ascii')
                if not MODULE.fullmatch(value) or not value.lower().endswith('.dll'):
                    raise ValueError('invalid_import_basename')
                return value.lower()
            raw.append(byte)
        raise ValueError('unbounded_import_name')
    def directory(index, width, name_index):
        if count <= index:
            return []
        rva, size = unpack('<II', directories+8*index)
        if rva == size == 0:
            return []
        if not rva or size < width or size > MAX_IMAGE:
            raise ValueError('invalid_import_directory')
        names = []
        for i in range(min(512, size//width)):
            values = unpack('<'+'I'*(width//4), offset(rva+i*width, width))
            if not any(values):
                return sorted(set(names))
            if index == 13 and values[0] != 1:
                raise ValueError('unsupported_delay_import_address_form')
            names.append(name_at(values[name_index]))
        raise ValueError('unterminated_import_directory')
    return dict(machine=f'0x{machine:04X}', imports=directory(1,20,3), delayImports=directory(13,32,1))

def inspect_staged_pe():
    if os.name != 'nt':
        return {'status':'not_windows', 'images':[]}
    root = Path(r'C:\PiSandboxLab\runtime')
    for parent in [root, root.parent]:
        if parent.lstat().st_file_attributes & 0x400:
            raise ValueError('reparse_root')
    pending, visited, images = ['python.exe'], set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        if len(visited) >= 8:
            raise ValueError('bounded_image_count')
        visited.add(name)
        item = root/name
        try:
            metadata = item.lstat()
        except FileNotFoundError:
            images.append({'name':name, 'status':'not_present_in_staged_root'})
            continue
        try:
            if metadata.st_file_attributes & 0x400 or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_IMAGE:
                raise ValueError('invalid_image_file')
            with item.open('rb') as handle:
                data = handle.read(MAX_IMAGE+1)
            parsed = pe_imports(data)
            images.append({'name':name,'status':'parsed','sha256':hashlib.sha256(data).hexdigest(), **parsed})
            for dependency in parsed['imports'] + parsed['delayImports']:
                if re.fullmatch(r'(?:python3\d{1,2}|vcruntime140(?:_1)?|ucrtbase)\.dll', dependency):
                    pending.append(dependency)
        except (OSError, ValueError, UnicodeError, struct.error) as error:
            images.append({'name':name, 'status':'unavailable','errorKind':type(error).__name__})
    return {'status':'offline_inventory','images':images,'limitation':'Static imports are not loaded-module or failing-DLL proof; system resolution is not attempted.'}

def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone_required')
    return parsed

def sanitize_events(payload):
    import xml.etree.ElementTree as ET
    start, end = timestamp(payload['window']['start']), timestamp(payload['window']['end'])
    if not 0 <= (end-start).total_seconds() <= 120:
        raise ValueError('invalid_window')
    records = payload.get('records', [])
    if not isinstance(records,list) or len(records) > MAX_EVENTS:
        raise ValueError('event_count_exceeded')
    accepted, unassigned, invalid = [], 0, 0
    ns = {'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
    for record in records:
        try:
            channel, text = record['channel'], record['xml']
            if channel not in CHANNEL_PROVIDERS or not isinstance(text,str) or len(text.encode('utf-8')) > MAX_XML or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                raise ValueError('invalid_event_xml')
            event = ET.fromstring(text)
            provider = event.find('e:System/e:Provider', ns).attrib['Name']
            created = timestamp(event.find('e:System/e:TimeCreated',ns).attrib['SystemTime'])
            event_id = int(event.find('e:System/e:EventID',ns).text)
            if provider not in CHANNEL_PROVIDERS[channel] or not start <= created <= end or not 0 <= event_id <= 65535:
                unassigned += 1; continue
            data = {}
            for node in event.findall('e:EventData/e:Data', ns):
                key = node.attrib.get('Name','')
                if key in data: raise ValueError('duplicate_event_field')
                data[key] = node.text or ''
            # Support only a known faulting-application field for a specific event schema.
            # Other queried provider/schema records remain unattributed, not guessed.
            attribution_field = {('Application Error',1000):'AppPath'}.get((provider,event_id))
            candidates = [data[key] for key in ('AppPath','ApplicationPath','ProcessPath','ImagePath') if data.get(key)]
            if attribution_field is None or data.get(attribution_field,'').casefold() != STAGED_PYTHON.casefold() or any(not value.isascii() or value.casefold() != STAGED_PYTHON.casefold() for value in candidates):
                unassigned += 1; continue
            statuses = []
            for key in ('ExceptionCode','Status','ErrorCode','ExitCode'):
                value = data.get(key,'')
                if re.fullmatch(r'(?:0x)?[0-9a-fA-F]{8}',value) or (re.fullmatch(r'\d{1,10}',value) and int(value) <= 0xffffffff):
                    statuses.append({'field':key, 'encoded':value.lower()})
            module = None
            for key in ('ModuleName','FaultingModuleName','ModulePath'):
                leaf = ntpath.basename(data.get(key,''))
                if MODULE.fullmatch(leaf): module=leaf.lower(); break
            accepted.append({'channel':channel,'provider':provider,'eventId':event_id,'exactStagedPathMatch':True,'statusCodes':statuses,'moduleBasename':module})
        except (KeyError, TypeError, ValueError, AttributeError, ET.ParseError):
            invalid += 1
    errors=[]
    for item in payload.get('queryErrors',[])[:4]:
        if item.get('channel') in CHANNEL_PROVIDERS and item.get('provider') in CHANNEL_PROVIDERS[item['channel']]:
            value=item.get('hresult')
            errors.append({'channel':item['channel'],'provider':item['provider'],'noMatchingEvents':item.get('noMatchingEvents') is True,'hresult':value if isinstance(value,int) and -(2**31)<=value<2**31 else None})
    return {'status':'existing_events_only','events':accepted,'unattributedCount':unassigned,'invalidCount':invalid,'queryErrors':errors,'limitation':'No attributable events is not evidence that initialization succeeded.'}

def validate_probe_imports(parsed):
    if parsed['machine']!='0x8664' or parsed['imports']!=['kernel32.dll'] or parsed['delayImports']:
        raise ValueError('probe_import_allowlist')

def verify_probe():
    item = Path('native/windows-sandbox/target/x86_64-pc-windows-msvc/debug/loader_probe.exe')
    metadata=item.lstat()
    if not stat.S_ISREG(metadata.st_mode) or getattr(metadata,'st_file_attributes',0) & 0x400 or metadata.st_size > MAX_IMAGE:
        raise ValueError('invalid_probe_file')
    with item.open('rb') as handle: data=handle.read(MAX_IMAGE+1)
    parsed=pe_imports(data)
    validate_probe_imports(parsed)
    return {'status':'probe_imports_verified','imports':parsed['imports'],'sha256':hashlib.sha256(data).hexdigest()}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('mode',choices=['pe','events','verify-probe']); args=parser.parse_args()
    try:
        if args.mode=='pe': result=inspect_staged_pe()
        elif args.mode=='verify-probe': result=verify_probe()
        else:
            raw=sys.stdin.buffer.read(MAX_INPUT+1)
            if len(raw)>MAX_INPUT: raise ValueError('input_bound')
            result=sanitize_events(json.loads(raw.decode('utf-8-sig')))
        print(json.dumps(result,sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'status':'unavailable','errorKind':type(error).__name__})); return 1
if __name__=='__main__': raise SystemExit(main())
