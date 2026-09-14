"""stdio 传输的合成服务；只操作测试传入的自有记录文件，不代表第三方隔离验收。"""
import json
import os
import signal
import sys
import time

mode, record = sys.argv[1:]


def emit(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()


def stall():
    time.sleep(60)


for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    with open(record, "a", encoding="utf-8") as output:
        output.write(json.dumps({"method": method}) + "\n")
    if method == "notifications/initialized":
        continue
    ident = request["id"]
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05" if mode == "version" else "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "合成传输服务", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "record", "description": "合成内容", "inputSchema": {"type": "object"},
                             "annotations": {"readOnlyHint": False}, "title": "保留原始字段"}]}
        if mode == "pagination":
            result["nextCursor"] = "next"
        if mode == "duplicate-tool":
            result["tools"] *= 2
        if mode == "many-tools":
            result["tools"] = [{"name": f"tool_{i}", "inputSchema": {"type": "object"}} for i in range(65)]
    else:
        result = {"content": [{"type": "text", "text": "已记录合成调用"}], "isError": False,
                  "structuredContent": {"recorded": True}}
        if mode == "timeout":
            stall()
        if mode == "eof":
            sys.exit(0)
        if mode == "partial":
            sys.stdout.write('{"jsonrpc":"2.0","id":')
            sys.stdout.flush()
            stall()
        if mode == "stderr":
            os.write(2, b"x" * (256 * 1024))
            stall()
        if mode == "oversize":
            os.write(1, b"x" * (256 * 1024))
            stall()
        if mode == "utf8":
            os.write(1, b"\xff\n")
            stall()
        if mode == "notification":
            emit({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            stall()
        if mode == "server-request":
            emit({"jsonrpc": "2.0", "id": "server-1", "method": "roots/list"})
            stall()
        if mode == "duplicate-response":
            wire = json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}) + "\n"
            os.write(1, (wire + wire).encode())
            stall()
        if mode == "rpc-error":
            emit({"jsonrpc": "2.0", "id": ident, "error": {"code": -32602, "message": "合成参数拒绝", "data": {"untrusted": True}}})
            continue
        if mode == "image":
            result["content"] = [{"type": "image", "data": "Zg==", "mimeType": "image/png"}]
        if mode == "bad-result":
            result["isError"] = "false"
        if mode == "wrong-id":
            ident += 1
    emit({"jsonrpc": "2.0", "id": ident, "result": result})
    if mode == "blocked-input" and method == "tools/list":
        # 在进入下一次管道 read 之前主动停止，避免父进程暂停时已有内核读取在途。
        os.kill(os.getpid(), signal.SIGSTOP)
        stall()
