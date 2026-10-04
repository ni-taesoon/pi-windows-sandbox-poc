"""Reduce bounded PE/disassembler input to entry-reachable control-flow facts."""
import bisect
import re
import struct

NAME = re.compile(r'[A-Za-z_?@][A-Za-z0-9_?@$]{0,127}\Z', re.ASCII)
MNEMONIC = re.compile(r'\s(call|jmp|j[a-z]{1,4}|ret|retq|xor|mov)\s*(.*)$', re.ASCII)


def summarize(image, text):
    if len(image) > 8*1024*1024 or len(text) > 8*1024*1024 or image[:2] != b'MZ':
        raise ValueError('input_limit')
    def unpack(fmt, at):
        if at < 0 or at + struct.calcsize(fmt) > len(image):
            raise ValueError('pe_bounds')
        return struct.unpack_from(fmt, image, at)
    pe = unpack('<I', 60)[0]
    if image[pe:pe+4] != b'PE\0\0' or unpack('<H',pe+4)[0] != 0x8664:
        raise ValueError('pe_kind')
    count = unpack('<H',pe+6)[0]
    size = unpack('<H',pe+20)[0]
    opt = pe+24
    if not 1 <= count <= 96 or size < 128 or unpack('<H',opt)[0] != 0x20b:
        raise ValueError('pe_optional')
    entry = unpack('<I', opt+16)[0]
    base = unpack('<Q', opt+24)[0]
    image_size = unpack('<I', opt+56)[0]
    if not 0 < entry < image_size <= 128*1024*1024:
        raise ValueError('entry_bounds')
    sections = []
    for n in range(count):
        _, virtual, rva, raw_size, raw = unpack('<8sIIII',opt+size+n*40)
        if raw+raw_size > len(image):
            raise ValueError('section_bounds')
        sections.append((rva,raw_size,raw))
    def offset(rva, length):
        hits = [raw+rva-start for start,size,raw in sections if start <= rva and rva+length <= start+size]
        if len(hits) != 1:
            raise ValueError('rva_bounds')
        return hits[0]
    def name(rva):
        result = bytearray()
        for n in range(128):
            byte = image[offset(rva+n,1)]
            if not byte:
                decoded = result.decode('ascii')
                if not NAME.fullmatch(decoded):
                    raise ValueError('import_name')
                return decoded
            result.append(byte)
        raise ValueError('import_name_limit')
    import_rva, import_size = unpack('<II',opt+120)
    imports = {}
    thunk_budget = 16384
    if import_rva:
        terminated = False
        for n in range(min(import_size//20,512)):
            oft,stamp,chain,dll,iat = unpack('<IIIII',offset(import_rva+n*20,20))
            if not any((oft,stamp,chain,dll,iat)):
                terminated = True
                break
            for j in range(4096):
                thunk_budget -= 1
                if thunk_budget < 0:
                    raise ValueError('import_aggregate_limit')
                thunk = unpack('<Q',offset((oft or iat)+8*j,8))[0]
                if not thunk:
                    break
                if not 0 <= iat+8*j <= image_size-8:
                    raise ValueError('iat_bounds')
                if len(imports) >= 4096:
                    raise ValueError('import_total_limit')
                imports[iat+8*j] = 'ordinal' if thunk & (1<<63) else name(thunk+2)
            else:
                raise ValueError('import_thunk_limit')
        if not terminated:
            raise ValueError('import_descriptor_limit')
    instructions = {}
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9A-Fa-f]{16}):\s+(.*)$',line)
        if not match:
            continue
        rva = int(match[1],16)-base
        if not 0 <= rva < image_size:
            continue
        parsed = MNEMONIC.search(' '+match[2])
        mnemonic, operands = (parsed[1],parsed[2]) if parsed else ('other','')
        # Absolute destination text is used internally only, never serialized.
        addresses = re.findall(r'(?<![A-Za-z0-9])(?:0x)?([0-9A-Fa-f]{16})(?![A-Za-z0-9])',operands)
        target = int(addresses[-1],16)-base if addresses else None
        if target is not None and not 0 <= target < image_size:
            target = None
        instructions[rva] = (mnemonic,target,('[' in operands),bool((mnemonic == 'xor' and re.fullmatch(r'eax,\s*eax', operands)) or (mnemonic == 'mov' and re.fullmatch(r'eax,\s*0(?:x0)?', operands))))
        if len(instructions) > 200000:
            raise ValueError('instruction_limit')
    if entry not in instructions:
        raise ValueError('entry_not_disassembled')
    positions = sorted(instructions)
    pending = [entry]
    visited = set()
    facts = []
    while pending and len(visited) < 2048 and len(facts) < 256:
        at = pending.pop()
        if at in visited or at not in instructions:
            continue
        visited.add(at)
        mnemonic,target,indirect,zero = instructions[at]
        idx = bisect.bisect_right(positions,at)
        next_at = positions[idx] if idx < len(positions) and positions[idx]-at <= 15 else None
        if mnemonic.startswith('ret'):
            facts.append({'rva':at,'kind':'return'})
            continue
        if mnemonic == 'call':
            item = {'rva':at,'kind':'call','indirect':indirect}
            if target in imports:
                item['import'] = imports[target]
            elif target is not None:
                item['targetRva'] = target
                if not indirect:
                    pending.append(target)
            facts.append(item)
        elif mnemonic.startswith('j'):
            item = {'rva':at,'kind':'branch','condition':mnemonic}
            if target in imports:
                item['import'] = imports[target]
            if target is not None:
                item['targetRva'] = target
                if not indirect:
                    pending.append(target)
            facts.append(item)
            if mnemonic == 'jmp':
                continue
        elif zero and mnemonic in ('xor','mov'):
            facts.append({'rva':at,'kind':'eaxZeroPattern'})
        if next_at is not None:
            pending.append(next_at)
    return {'entryRva':entry,'facts':facts,'visitedInstructions':len(visited),'truncated':bool(pending), 'limitation':'Heuristic static entry closure includes branch alternatives; parsing gaps, indirect calls and bounds may omit paths. It does not identify the executed failure branch.'}
