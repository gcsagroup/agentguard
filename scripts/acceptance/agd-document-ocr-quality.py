#!/usr/bin/env python3
"""在准确受限容器中验证完整图片解析入口；参考文字和原始图像必须事先冻结。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import subprocess
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def distance(left, right):
    row = list(range(len(right) + 1))
    for index, char in enumerate(left, 1):
        following = [index]
        for j, other in enumerate(right, 1):
            following.append(min(following[-1] + 1, row[j] + 1, row[j-1] + (char != other)))
        row = following
    return row[-1]


def worker_timeout(report):
    """只暂停当前验收入口自己的 OCR 子进程，验证产品原有 15 秒截止。"""
    started = time.monotonic()
    process = subprocess.Popen(['/usr/bin/python3', '-I', '/parser/document_parser.py', 'png'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    worker = None
    evidence = {'passed': False, 'parent_pid': process.pid, 'signal': 'SIGSTOP'}
    report['worker_timeout'] = evidence
    try:
        while time.monotonic() - started < 5 and process.poll() is None and worker is None:
            for entry in Path('/proc').iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    status = (entry/'status').read_text()
                    args = (entry/'cmdline').read_bytes().split(b'\0')
                except FileNotFoundError:
                    continue
                if (re.search(r'^PPid:\s*' + str(process.pid) + r'$', status, re.M)
                        and args[:4] == [b'/usr/bin/python3', b'-I', b'/parser/document_parser.py', b'--ocr-worker']):
                    worker = int(entry.name)
                    os.kill(worker, signal.SIGSTOP)
                    evidence.update({'worker_pid': worker, 'injected_after_s': time.monotonic() - started})
                    break
            time.sleep(0.005)
        assert worker is not None, '没有找到准确的自有 OCR 子进程，不能算超时验收'
        stdout, stderr = process.communicate(timeout=20)
        evidence.update({'elapsed_s': time.monotonic() - started, 'exit': process.returncode,
                         'result': json.loads(stdout), 'worker_remaining': Path(f'/proc/{worker}').exists()})
        result = evidence['result']
        assert process.returncode == 0 and not stderr and 15 <= evidence['elapsed_s'] < 20
        assert result['status'] == 'timeout' and 'text' not in result
        assert result['source_sha256'] == digest(Path('/input/source').read_bytes())
        assert not evidence['worker_remaining'], '必须由产品入口回收停止中的子进程'
        evidence['passed'] = True
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def inside():
    parser = runpy.run_path('/parser/document_parser.py')
    manifest = json.loads(Path('/input/manifest.json').read_text())
    report = {'passed': False, 'scope': '完整图片解析及子进程，非 RAG、模型或原生验收', 'cases': [],
              'parser_sha256': digest(Path('/parser/document_parser.py').read_bytes()),
              'manifest_sha256': digest(Path('/input/manifest.json').read_bytes()), 'normalization': '仅去空白'}
    try:
        for case in manifest['cases']:
            data = (Path('/input') / case['file']).read_bytes()
            assert digest(data) == case['sha256']
            started = time.monotonic()
            result = parser['parse_bytes'](data, 'jpeg' if case['file'].endswith('.jpeg') else 'png')
            ref, actual = ''.join(case['expected'].split()), ''.join(result.get('text', '').split())
            errors = distance(ref, actual)
            passed = (result['status'] == ('parsed' if ref else 'partial') and errors / max(1, len(ref)) <= case['maximum_cer']
                      and result['source_sha256'] == case['sha256'] and result['source_bytes'] == len(data)
                      and result.get('text_sha256') == digest(result.get('text', '').encode())
                      and result.get('instruction_authority') == 'none' and bool(result.get('coverage', {}).get('uncovered')))
            report['cases'].append({'case': case['name'], 'expected': case['expected'], 'source_sha256': case['sha256'],
                                   'errors': errors, 'reference_characters': len(ref), 'cer': errors / max(1, len(ref)),
                                   'elapsed_s': time.monotonic() - started, 'passed': passed, 'result': result})
            Path('/evidence/report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        worker_timeout(report)
        report['memory_events'] = Path('/sys/fs/cgroup/memory.events').read_text()
        report['memory_peak'] = int(Path('/sys/fs/cgroup/memory.peak').read_text())
        events = dict(line.split() for line in report['memory_events'].splitlines())
        assert events['oom_kill'] == '0' and events['oom'] == '0', '准确完整流程不能用 OOM 后的部分成功冒充通过'
        assert int(Path('/sys/fs/cgroup/memory.max').read_text()) == 256 * 1024 * 1024
        assert int(Path('/sys/fs/cgroup/pids.max').read_text()) == 64 and os.getuid() != 0
        report['passed'] = len(report['cases']) == len(manifest['cases']) and all(c['passed'] for c in report['cases'])
    finally:
        Path('/evidence/report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': len(report['cases']), 'accepted': sum(c['passed'] for c in report['cases'])}))
    raise SystemExit(0 if report['passed'] else 1)


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument('--image', required=True)
    arg.add_argument('--fixtures', type=Path, required=True)
    arg.add_argument('--out', type=Path, required=True)
    args = arg.parse_args()
    assert re.fullmatch(r'sha256:[a-f0-9]{64}', args.image)
    out = args.out.resolve(); out.mkdir(exist_ok=False)
    frozen, inputs, evidence = out/'parser', out/'inputs', out/'results'
    for directory in [frozen, inputs, evidence]: directory.mkdir()
    repo = Path(__file__).resolve().parents[2]
    shutil.copyfile(repo/'crates/guard-gateway/src/document_parser.py', frozen/'document_parser.py')
    shutil.copyfile(__file__, frozen/'quality.py')
    shutil.copyfile(args.fixtures/'manifest.json', inputs/'manifest.json')
    for case in json.loads((inputs/'manifest.json').read_text())['cases']:
        assert Path(case['file']).name == case['file'] and not (args.fixtures/case['file']).is_symlink()
        data = (args.fixtures/case['file']).read_bytes(); assert digest(data) == case['sha256']
        (inputs/case['file']).write_bytes(data)
    source = next(c for c in json.loads((inputs/'manifest.json').read_text())['cases'] if c['name'] == 'simplified-png')
    shutil.copyfile(inputs/source['file'], inputs/'source')
    name = 'agentguard-document-acceptance'
    identity = out/'container.id'
    command = ['/usr/local/bin/docker', 'run', '--rm', '--name', name, '--cidfile', str(identity), '--pull=never', '--network=none', '--read-only',
               f'--user={os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
               '--pids-limit=64', '--memory=256m', '--memory-swap=256m', '--cpus=1',
               '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=67108864']
    for source, target, writable in [(frozen, '/parser', False), (inputs, '/input', False), (evidence, '/evidence', True)]:
        command.extend(['--mount', f'type=bind,src={source},dst={target}' + ('' if writable else ',readonly')])
    command.extend(['--entrypoint=/usr/bin/python3', args.image, '-I', '/parser/quality.py', '--inside'])
    (out/'command.json').write_text(json.dumps(command, indent=2) + '\n')
    try:
        with (out/'stdout.log').open('w') as stdout, (out/'stderr.log').open('w') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=240)
        print(json.dumps({'exit': result.returncode, 'out': str(out)}))
        raise SystemExit(result.returncode)
    finally:
        # 只回收本次 run 实际创建的容器；同名冲突时不触碰已经存在的其他验收进程。
        if identity.exists():
            container = identity.read_text().strip()
            assert re.fullmatch(r'[a-f0-9]{64}', container)
            removed = subprocess.run(['/usr/local/bin/docker', 'rm', '-f', container], capture_output=True, text=True, timeout=15)
            assert removed.returncode == 0 or 'No such container' in removed.stderr


if __name__ == '__main__':
    import sys
    inside() if sys.argv[1:] == ['--inside'] else main()
