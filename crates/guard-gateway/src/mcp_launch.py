"""编译进宿主的启动门禁；在任何第三方 JavaScript 运行前核对内核约束。"""
import os
import sys

try:
    uid, gid = int(sys.argv[1]), int(sys.argv[2])
    if sys.platform != "linux" or uid == 0 or os.getuid() != uid or os.getgid() != gid:
        raise RuntimeError("身份或平台不符")
    with open("/proc/self/status", encoding="ascii") as stream:
        status = dict(line.split(":", 1) for line in stream if ":" in line)
    if status["NoNewPrivs"].strip() != "1" or status["Seccomp"].strip() != "2":
        raise RuntimeError("内核约束未生效")
    if any(int(status[field].strip(), 16) != 0 for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise RuntimeError("进程能力未移除")
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    os.chdir("/tmp")
    os.execve("/usr/local/bin/node", ["node", "--", *sys.argv[3:]], environment)
except Exception:
    # 不回传路径、宿主配置或底层异常正文，不自动降级到原生进程。
    sys.stderr.write("AgentGuard 服务启动约束未满足\n")
    sys.exit(78)
