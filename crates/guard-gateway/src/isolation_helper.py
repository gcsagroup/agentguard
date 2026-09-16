"""容器内固定工具入口；不读取宿主环境，不将参数拼成 shell。"""
import json
import base64
import os
import stat
import sys

LIMIT = 64 * 1024

def parent_directory(path, create=False):
    # 批准逻辑路径后不能通过快照内父链接改写落点；逐级打开并持有目录句柄。
    if not os.path.isabs(path):
        raise ValueError('文件工具只支持绝对路径')
    parts = path.split('/')[1:]
    if not parts or any(part in ('', '.', '..') for part in parts):
        raise ValueError('文件路径必须规范且包含文件名')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def regular(path, flags, mode=0o600, create_parents=False, single_link=False):
    parent, name = parent_directory(path, create=create_parents)
    try:
        fd = os.open(name, flags | os.O_NONBLOCK | os.O_NOFOLLOW, mode, dir_fd=parent)
    finally:
        os.close(parent)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or (single_link and metadata.st_nlink != 1):
        os.close(fd)
        raise ValueError('只支持符合当前链接限制的普通文件')
    return fd

def main():
    with open('/run/agentguard-request/call.json', encoding='utf-8') as stream:
        call = json.load(stream)
    single_link = call.pop('__agentguard_single_link', False)
    name, args = next(iter(call.items()))
    if name == 'RunShell':
        argv = args['argv']
        if not argv:
            raise ValueError('argv 为空')
        os.chdir(args.get('cwd') or '/tmp')
        os.execvp(argv[0], argv)
    path = args['path']
    truncated = False
    capture = None
    if name == 'ParseDocument':
        import runpy
        parser = runpy.run_path('/run/agentguard-request/document_parser.py')
        with os.fdopen(regular('/run/agentguard-request/document-source', os.O_RDONLY), 'rb') as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        report = parser['parse_bytes'](raw, args['format'])
        detail = json.dumps(report, ensure_ascii=False)
        ok = report['status'] in ('parsed', 'partial')
        print(json.dumps({'ok': ok, 'detail': detail, 'truncated': False,
                         'outcome': 'success' if ok else 'failed', 'dispatched': True}, ensure_ascii=False))
        return
    elif name in ('ReadFile', 'SearchFile'):
        scan_limit = LIMIT if name == 'ReadFile' else 4 * 1024 * 1024
        with os.fdopen(regular(path, os.O_RDONLY, single_link=single_link), 'rb') as stream:
            raw = stream.read(scan_limit + 1)
        truncated = len(raw) > scan_limit
        capture = {'version': 1, 'streams': [{'origin': 'file_bytes',
            'raw_base64': base64.b64encode(raw).decode('ascii'), 'complete': not truncated}]}
        prefix = raw[:scan_limit]
        try:
            text = prefix.decode('utf-8')
        except UnicodeDecodeError as error:
            # 只移除被上限截开的末尾字符；原有坏字节保留替换视图，宿主另报编码未知。
            if truncated and error.reason == 'unexpected end of data' and error.end == len(prefix):
                prefix = prefix[:error.start]
            text = prefix.decode('utf-8', errors='replace')
        if name == 'SearchFile':
            query = args['query']
            if not 1 <= len(query.encode()) <= 1024 or '\n' in query or '\r' in query:
                raise ValueError('query 必须是 1–1024 字节单行文本')
            found = []
            lines = text.split('\n')
            for i, line in enumerate(lines, 1):
                if i < len(lines) and line.endswith('\r'):
                    line = line[:-1]
                if query in line:
                    if len(found) == 200:
                        truncated = True
                        break
                    found.append(f'{i}:{line}\n')
            text = ''.join(found)
        encoded = text.encode()
        truncated |= len(encoded) > LIMIT
        detail = encoded[:LIMIT].decode('utf-8', errors='ignore')
    elif name == 'WriteFile':
        with os.fdopen(regular(path, os.O_WRONLY | os.O_CREAT, create_parents=True, single_link=single_link), 'wb') as stream:
            stream.truncate(0)
            stream.write(args['contents'].encode())
        detail = f'已写入隔离工作区副本：{path}；宿主原文件未回写'
    elif name == 'DeleteFile':
        parent, name = parent_directory(path)
        try:
            os.unlink(name, dir_fd=parent)
        finally:
            os.close(parent)
        detail = f'已删除隔离工作区副本：{path}；宿主原文件未回写'
    else:
        raise ValueError('未知工具')
    print(json.dumps({'ok': True, 'detail': detail, 'truncated': truncated, 'outcome': 'success', 'dispatched': True,
        'capture': capture}, ensure_ascii=False))

try:
    main()
except Exception as error:
    print(json.dumps({'ok': False, 'detail': f'隔离工具失败：{error}', 'truncated': False, 'outcome': 'failed', 'dispatched': True}, ensure_ascii=False))
    sys.exit(1)
