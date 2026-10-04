"""Read-only fixed-DLL inspection; only structural facts leave bounded memory."""
import hashlib
import json
import os
from pathlib import Path
import stat
import re
from sechost_structure import summarize
import subprocess
import threading

LIMIT = 8 * 1024 * 1024
TIMEOUT = 30


def bounded_run(argv, limit=LIMIT, timeout=TIMEOUT):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    expired = threading.Event()
    def terminate():
        expired.set()
        try:
            process.kill()
        except OSError:
            pass
    timer = threading.Timer(timeout, terminate)
    timer.start()
    data = bytearray()
    try:
        while True:
            block = process.stdout.read(min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                process.kill()
                raise ValueError('output_limit')
        code = process.wait(timeout=5)
        if expired.is_set():
            raise ValueError('time_limit')
        if code != 0:
            raise ValueError('tool_failed')
        return bytes(data)
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()


def regular_no_reparse(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if info.st_file_attributes & 0x400:
            raise ValueError('reparse_refused')
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('not_regular')


def main():
    output = Path('lab-evidence')
    output.mkdir(exist_ok=True)
    result = {'status': 'unavailable', 'target': 'sechost.dll'}
    try:
        if os.name != 'nt' or os.environ.get('ImageOS') != 'win22':
            raise ValueError('unsupported_environment')
        target = Path(os.environ['SystemRoot']) / 'System32' / 'sechost.dll'
        regular_no_reparse(target)
        if target.stat().st_size > LIMIT:
            raise ValueError('image_limit')
        image = target.read_bytes()
        image_hash = hashlib.sha256(image).hexdigest()
        vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        regular_no_reparse(vswhere)
        installation = bounded_run([str(vswhere), '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], 4096).decode('utf-8-sig').strip()
        if not installation or '\n' in installation or '\r' in installation:
            raise ValueError('tool_location')
        version_file = Path(installation) / 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
        regular_no_reparse(version_file)
        version = version_file.read_text().strip()
        if not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}', version):
            raise ValueError('tool_version')
        dumpbin = Path(installation) / 'VC/Tools/MSVC' / version / 'bin/Hostx64/x64/dumpbin.exe'
        regular_no_reparse(dumpbin)
        data = bounded_run([str(dumpbin), '/nologo', '/headers', '/imports', '/disasm', str(target)])
        regular_no_reparse(target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != image_hash:
            raise ValueError('image_changed')
        structure = summarize(image, data.decode('ascii', errors='replace'))
        result = {'status': 'collected', 'target': 'sechost.dll', 'imageSha256': image_hash, 'outputBytes': len(data), 'outputSha256': hashlib.sha256(data).hexdigest(), 'structure': structure}
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError, KeyError):
        # Never print command output, host paths, disassembly or exception strings.
        result['status'] = 'collection_failed'
    (output / 'sechost-static-summary.json').write_text(json.dumps(result), encoding='utf-8')
    print('SECHOST_STATIC_COLLECTION_' + result['status'].upper())


if __name__ == '__main__':
    main()
