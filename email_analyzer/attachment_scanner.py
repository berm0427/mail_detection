"""Local attachment scanning without opening or executing attachment content."""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from functools import lru_cache

EXECUTABLE_EXTENSIONS={'.exe','.com','.scr','.msi','.bat','.cmd','.ps1','.vbs','.js','.jse','.hta','.lnk','.dll'}
DOCUMENT_EXTENSIONS={'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.hwp','.txt','.jpg','.jpeg','.png'}
SCRIPT_EXTENSIONS={'.bat','.cmd','.ps1','.vbs','.js','.jse','.hta'}
SCRIPT_INDICATORS=(
    b'powershell',b'frombase64string',b'invoke-expression',b'invoke-webrequest',b'downloadstring',
    b'wscript.shell',b'createobject',b'shell.application',b'cmd.exe',b'certutil',b'bitsadmin',
    b'regsvr32',b'rundll32',b'mshta',b'javascript:',b'autoopen',b'document_open',b'workbook_open',
)


def _sha256(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def _entropy(data):
    if not data:return 0.0
    counts=[0]*256
    for value in data:counts[value]+=1
    size=len(data)
    return -sum((count/size)*math.log2(count/size) for count in counts if count)


def static_findings(path):
    """Inspect content and container metadata without executing or extracting files."""
    path=Path(path);name=path.name.casefold();suffix=path.suffix.casefold();findings=[]
    suffixes=[x.casefold() for x in path.suffixes]
    if len(suffixes)>=2 and suffixes[-1] in EXECUTABLE_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS:
        findings.append('double_extension_executable')
    with path.open('rb') as stream: head=stream.read(4*1024*1024)
    if head.startswith(b'MZ') and suffix not in ('.exe','.dll','.scr','.com'):
        findings.append('executable_content_extension_mismatch')
    if suffix=='.pdf' and any(token in head for token in (b'/JavaScript',b'/JS',b'/OpenAction',b'/Launch')):
        findings.append('pdf_active_content')
    lowered=head.lower()
    indicator_count=sum(token in lowered for token in SCRIPT_INDICATORS)
    if suffix in SCRIPT_EXTENSIONS and indicator_count>=2:findings.append('script_download_or_execute_chain')
    if suffix not in SCRIPT_EXTENSIONS and indicator_count>=3:findings.append('embedded_script_command_chain')
    if suffix in EXECUTABLE_EXTENSIONS and len(head)>=4096 and _entropy(head)>7.65:
        findings.append('high_entropy_executable')
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                names=[item.filename.replace('\\','/').casefold() for item in archive.infolist()[:5000]]
                if any(Path(item).suffix in EXECUTABLE_EXTENSIONS for item in names):findings.append('archive_contains_executable')
                if any(item.endswith('vbaproject.bin') for item in names):findings.append('office_vba_macro')
                if any(item.endswith(('/externallinks/_rels/externallink1.xml.rels','/embeddings/oleobject1.bin')) for item in names):
                    findings.append('office_external_or_embedded_object')
                if len(archive.infolist())>5000:findings.append('archive_entry_limit_exceeded')
        except (OSError,zipfile.BadZipFile,RuntimeError):findings.append('archive_metadata_error')
    return sorted(set(findings))


def find_defender() -> Path | None:
    if sys.platform != 'win32':
        return None
    roots = []
    program_data = os.environ.get('ProgramData')
    if program_data:
        platform = Path(program_data) / 'Microsoft' / 'Windows Defender' / 'Platform'
        if platform.is_dir():
            roots.extend(sorted(platform.glob('*/MpCmdRun.exe'), reverse=True))
    program_files = os.environ.get('ProgramFiles')
    if program_files:
        roots.append(Path(program_files) / 'Windows Defender' / 'MpCmdRun.exe')
    return next((path.resolve() for path in roots if path.is_file()), None)


def _decode(data: bytes) -> str:
    if data.startswith((b'\xff\xfe',b'\xfe\xff')) or (data and data.count(b'\x00')>len(data)//4):
        try:return data.decode('utf-16')
        except UnicodeDecodeError:pass
    for encoding in ('utf-8', 'cp949'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode('utf-8', errors='replace')


@lru_cache(maxsize=1)
def defender_product_status(runner=subprocess.run):
    """Return enabled/disabled/unknown for the installed Defender service."""
    if sys.platform != 'win32':
        return 'unavailable'
    command=['powershell.exe','-NoProfile','-NonInteractive','-Command',
             '(Get-MpComputerStatus).AntivirusEnabled']
    try:
        completed=runner(command,capture_output=True,text=False,timeout=8,shell=False,
                         creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError,subprocess.TimeoutExpired):
        return 'unknown'
    output=_decode(completed.stdout or b'').strip().casefold()
    if completed.returncode==0 and output=='true':
        return 'enabled'
    if completed.returncode==0 and output=='false':
        return 'disabled'
    return 'unknown'


def scan_attachment(path, *, executable=None, timeout=90, runner=subprocess.run):
    """Run one Defender custom scan with remediation disabled.

    Exit code 2 is never sufficient to claim an infection. Defender also uses
    it when the product is disabled or a scan cannot start.
    """
    target = Path(path).resolve()
    base = {
        'engine': 'internal_static+optional_microsoft_defender', 'path_sha256': hashlib.sha256(str(target).encode()).hexdigest(),
        'file_sha256': None, 'status': 'error', 'safe': None, 'reason': None, 'static_findings': [],
    }
    if not target.is_file():
        return {**base, 'status': 'error', 'reason': 'attachment_missing'}
    base['file_sha256'] = _sha256(target)
    base['static_findings'] = static_findings(target)
    use_installed_defender=executable is None
    tool = Path(executable).resolve() if executable else find_defender()
    if not tool or not tool.is_file():
        return {**base, 'status': 'suspicious_structure' if base['static_findings'] else 'clean_static',
                'safe': None, 'reason': ', '.join(base['static_findings']) if base['static_findings'] else 'internal_static_scan_clean'}
    if use_installed_defender and defender_product_status()=='disabled':
        return {**base,'status':'suspicious_structure' if base['static_findings'] else 'clean_static',
                'safe':None,'reason':(', '.join(base['static_findings']) if base['static_findings']
                                      else 'internal_static_scan_clean; defender_product_disabled'),
                'scanner':str(tool),'external_scan_status':'disabled','external_error':'defender_product_disabled'}
    command = [str(tool), '-Scan', '-ScanType', '3', '-File', str(target), '-DisableRemediation']
    try:
        completed = runner(command, capture_output=True, text=False, timeout=timeout,
                           shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
    except subprocess.TimeoutExpired:
        return {**base, 'status': 'timeout', 'reason': f'scan_timeout_{timeout}s'}
    except OSError as exc:
        return {**base, 'status': 'error', 'reason': type(exc).__name__}
    output = (_decode(completed.stdout or b'') + '\n' + _decode(completed.stderr or b'')).strip()
    output_hash = hashlib.sha256(output.encode('utf-8')).hexdigest()
    error_code_match=re.search(r'0x[0-9a-f]{8}',output,re.I)
    details = {'return_code': int(completed.returncode), 'output_sha256': output_hash,
               'scanner': str(tool), 'remediation_disabled': True,
               'external_scan_status':'completed' if completed.returncode==0 else 'failed'}
    if error_code_match:
        details['external_error_code']=error_code_match.group(0).lower()
    if completed.returncode == 0:
        if base['static_findings']:
            return {**base, **details, 'status': 'suspicious_structure', 'safe': None,
                    'reason': ', '.join(base['static_findings'])}
        return {**base, **details, 'status': 'clean', 'safe': True, 'reason': 'Defender custom scan completed with no unremediated threat'}
    if completed.returncode == 2:
        detected = bool(re.search(r'(?:found|detected)\s+[1-9]\d*\s+threat|threat(?:s)?\s+(?:found|detected)|위협.{0,12}(?:발견|탐지)', output, re.I))
        if detected:
            return {**base, **details, 'status': 'threat_detected', 'safe': False,
                    'reason': 'Defender reported a threat'}
        product_disabled=bool(re.search(r'product\s*/?\s*feature\s+disabled|product.{0,12}disabled|기능.{0,12}사용.{0,6}안',output,re.I))
        if product_disabled:
            details['external_scan_status']='disabled'
            details['external_error']='defender_product_disabled'
        else:
            details['external_error']='defender_scan_failed'
        if base['static_findings']:
            return {**base, **details, 'status': 'suspicious_structure',
                    'reason': ', '.join(base['static_findings'])}
        return {**base, **details, 'status': 'clean_static',
                'reason': ('internal_static_scan_clean; defender_product_disabled' if product_disabled
                           else 'internal_static_scan_clean; defender_scan_failed')}
    if base['static_findings']:
        return {**base, **details, 'status': 'suspicious_structure', 'reason': ', '.join(base['static_findings'])}
    details['external_error']='defender_scan_failed'
    return {**base, **details, 'status': 'clean_static', 'reason': f'internal_static_scan_clean; defender_exit_{completed.returncode}'}
