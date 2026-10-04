"""Reduce bounded PE/disassembler input to entry-reachable control-flow facts."""
import bisect
import re
import struct

NAME = re.compile(r'[A-Za-z_?@][A-Za-z0-9_?@$]{0,127}\Z', re.ASCII)
MNEMONIC = re.compile(r'\s(call|jmp|j[a-z]{1,4}|ret|retq|xor|mov)\s*(.*)$', re.ASCII)


def rip_indirect_slot(code, rva, image_size):
    """Decode only x64 FF /2 or /4 RIP-relative forms, optionally REX.W."""
    if not 0 <= rva < image_size:
        return None
    prefix = 1 if code[:1] == b'\x48' else 0
    if len(code) < prefix+6 or code[prefix:prefix+1] != b'\xff':
        return None
    modrm = code[prefix+1]
    if modrm not in (0x15,0x25):
        return None
    displacement = struct.unpack_from('<i',code,prefix+2)[0]
    slot = rva+prefix+6+displacement
    if not 0 <= slot <= image_size-8:
        return None
    return ('call' if modrm == 0x15 else 'jmp',slot)


def initializer_table(code, start_rva, base, image_size, read_rva, executable):
    """Exact adjacent RIP-relative LEAs to RCX/RDX; no pattern fallback."""
    if len(code) != 14 or start_rva < 0 or start_rva+14 > image_size:
        raise ValueError('initializer_lea_bounds')
    arguments = {}
    for index in (0,7):
        instruction = code[index:index+7]
        if instruction[:2] != b'\x48\x8d' or instruction[2] not in (0x0d,0x15):
            raise ValueError('initializer_lea_pattern')
        register = instruction[2]
        if register in arguments:
            raise ValueError('initializer_lea_duplicate')
        arguments[register] = start_rva+index+7+struct.unpack_from('<i',instruction,3)[0]
    begin,end = arguments[0x0d],arguments[0x15]
    if begin%8 or end%8 or not 0 <= begin <= end <= image_size or end-begin > 64*8:
        raise ValueError('initializer_table_bounds')
    entries = []
    for slot in range(begin,end,8):
        value = struct.unpack('<Q',read_rva(slot,8))[0]
        if not value:
            continue
        rva = value-base
        if not 0 <= rva < image_size or not executable(rva):
            raise ValueError('initializer_pointer_bounds')
        entries.append({'slotRva':slot,'functionRva':rva})
    return {'startRva':begin,'endRva':end,'entries':entries}


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
    executable_sections = []
    for n in range(count):
        _, virtual, rva, raw_size, raw = unpack('<8sIIII',opt+size+n*40)
        if raw+raw_size > len(image):
            raise ValueError('section_bounds')
        sections.append((rva,raw_size,raw))
        characteristics = unpack('<I',opt+size+n*40+36)[0]
        if characteristics & 0x20000000:
            executable_sections.append((rva,raw_size))
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
        indirect = '[' in operands or bool(re.fullmatch(r'r(?:ax|bx|cx|dx|si|di|sp|bp|[89]|1[0-5])', operands.strip()))
        if indirect:
            target = None
        if mnemonic in ('call','jmp'):
            try:
                first = image[offset(rva,1)]
                width = 7 if first == 0x48 else 6
                code = image[offset(rva,width):offset(rva,width)+width]
                decoded = rip_indirect_slot(code,rva,image_size)
            except ValueError:
                decoded = None
            if decoded is not None and decoded[0] == mnemonic and decoded[1] in imports:
                target, indirect = decoded[1], True
        instructions[rva] = (mnemonic,target,indirect,bool((mnemonic == 'xor' and re.fullmatch(r'eax,\s*eax', operands)) or (mnemonic == 'mov' and re.fullmatch(r'eax,\s*0(?:x0)?', operands))))
        if len(instructions) > 200000:
            raise ValueError('instruction_limit')
    if entry not in instructions:
        raise ValueError('entry_not_disassembled')
    tables = []
    initializer_functions = []
    for at,(mnemonic,target,indirect,_) in instructions.items():
        if mnemonic != 'call' or indirect or target not in instructions:
            continue
        thunk_kind,slot,thunk_indirect,_ = instructions[target]
        if thunk_kind != 'jmp' or not thunk_indirect or imports.get(slot) != '_initterm_e':
            continue
        if len(tables) >= 4:
            raise ValueError('initializer_call_limit')
        record = {'callRva':at,'status':'unavailable'}
        try:
            call_at = offset(at,5)
            if image[call_at] != 0xe8 or at+5+struct.unpack_from('<i',image,call_at+1)[0] != target:
                raise ValueError('initializer_call_pattern')
            if at-14 not in instructions or at-7 not in instructions:
                raise ValueError('initializer_instruction_boundaries')
            before = offset(at-14,14)
            table = initializer_table(image[before:before+14],at-14,base,image_size,
                lambda r,n: image[offset(r,n):offset(r,n)+n],
                lambda r: any(start <= r < start+size for start,size in executable_sections))
            record.update(table)
            record['status'] = 'decoded'
            for item in table['entries']:
                if item['functionRva'] not in initializer_functions:
                    initializer_functions.append(item['functionRva'])
        except ValueError:
            pass
        tables.append(record)
    positions = sorted(instructions)
    functions = [entry]+initializer_functions
    seen_functions = set()
    summaries = []
    total_visited = 0
    total_facts = 0
    while functions and len(summaries) < 8 and total_visited < 2048 and total_facts < 256:
        function = functions.pop(0)
        if function in seen_functions or function not in instructions:
            continue
        seen_functions.add(function)
        pending = [function]
        visited = set()
        facts = []
        callees = []
        while pending and total_visited < 2048 and total_facts < 256 and len(facts) < 64:
            at = pending.pop()
            if at in visited or at not in instructions:
                continue
            visited.add(at)
            total_visited += 1
            mnemonic,target,indirect,zero = instructions[at]
            idx = bisect.bisect_right(positions,at)
            next_at = positions[idx] if idx < len(positions) and positions[idx]-at <= 15 else None
            item = None
            stop = False
            if mnemonic.startswith('ret'):
                item = {'rva':at,'kind':'return'}
                stop = True
            elif mnemonic == 'call':
                item = {'rva':at,'kind':'call','indirect':indirect}
                if target in imports:
                    item['import'] = imports[target]
                elif target is not None:
                    item['targetRva'] = target
                    if not indirect and target not in callees:
                        callees.append(target)
            elif mnemonic.startswith('j'):
                item = {'rva':at,'kind':'branch','condition':mnemonic}
                if target in imports:
                    item['import'] = imports[target]
                if target is not None:
                    item['targetRva'] = target
                    if not indirect:
                        pending.append(target)
                if mnemonic == 'jmp':
                    stop = True
            elif zero and mnemonic in ('xor','mov'):
                item = {'rva':at,'kind':'eaxZeroPattern'}
            if item is not None:
                facts.append(item)
                total_facts += 1
            if not stop and next_at is not None:
                pending.append(next_at)
        summaries.append({'entryRva':function,'facts':facts,'truncated':bool(pending),'directCalleeRvas':callees})
        functions.extend(x for x in callees if x not in seen_functions and x not in functions)
    first = summaries[0]
    return {'entryRva':entry,'facts':first['facts'],'entryTruncated':first['truncated'],
            'calleeSummaries':summaries[1:],'initializerTables':tables,'importSlots':len(imports),
            'visitedInstructions':total_visited,'truncated':bool(functions) or any(x['truncated'] for x in summaries),
            'limitation':'Entry-first heuristic static closure and up to seven direct-callee summaries; branch alternatives, parsing gaps, indirect calls and bounds prevent identifying the executed failure branch.'}
