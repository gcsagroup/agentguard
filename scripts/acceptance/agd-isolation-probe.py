#!/usr/bin/env python3
"""AGD-002：仅使用本地镜像和测试哨兵验证 Docker VM 边界，不接触业务容器。"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

DEFAULT_IMAGE = "sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"
ROOT = Path(__file__).resolve().parents[2]

# 以下程序只访问本脚本创建的哨兵、临时工作区和本地测试监听器。
PROBE = r'''
import ctypes, errno, json, os, pathlib, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor
root=pathlib.Path("/workspace")
cfg=json.loads((root/"config.json").read_text())
checks=[]
def record(name, ok, detail=None):
    checks.append({"name":name,"passed":bool(ok),"detail":detail})
def denied_read(path):
    try:
        pathlib.Path(path).read_bytes()
        return False
    except OSError as exc:
        return exc.errno in (errno.ENOENT,errno.EACCES,errno.ENOTDIR,errno.EPERM)
def denied_write(path):
    try:
        pathlib.Path(path).write_text("UNAUTHORIZED_TEST_WRITE")
        return False
    except OSError as exc:
        return exc.errno in (errno.ENOENT,errno.EACCES,errno.ENOTDIR,errno.EPERM,errno.EROFS)
record("python_inside_read",(root/"input.txt").read_text()=="AGD_NORMAL_INPUT")
(root/"result.txt").write_text("AGD_NORMAL_OUTPUT")
record("python_inside_write",(root/"result.txt").read_text()=="AGD_NORMAL_OUTPUT")
record("python_host_private_read_denied",denied_read(cfg["outside_file"]))
record("python_host_private_write_denied",denied_write(cfg["outside_file"]))
record("absolute_symlink_read_denied",denied_read(root/"outside-link"))
record("absolute_symlink_write_denied",denied_write(root/"outside-link"))
record("relative_symlink_read_denied",denied_read(root/"relative-outside-link"))
record("relative_symlink_write_denied",denied_write(root/"relative-outside-link"))
record("rootfs_readonly",denied_write("/etc/agd-test-marker"))
record("host_test_token_not_in_environment",cfg["test_token"] not in str(dict(os.environ)))
record("environment_allowlist",set(os.environ)<=set(["PATH","HOME","TMPDIR","LANG","LC_CTYPE"]))
record("no_docker_socket",not pathlib.Path("/var/run/docker.sock").exists() and not pathlib.Path("/run/docker.sock").exists())
record("no_host_home_mount",not pathlib.Path(cfg["host_home"]).exists())
record("non_root",os.getuid()==65534)
status=pathlib.Path("/proc/self/status").read_text()
fields=dict(line.split(":",1) for line in status.splitlines() if ":" in line)
record("no_effective_capabilities",int(fields["CapEff"].strip(),16)==0)
record("no_new_privileges",fields["NoNewPrivs"].strip()=="1")
record("seccomp_enabled",fields["Seccomp"].strip()=="2")
record("pids_limit_configured",pathlib.Path("/sys/fs/cgroup/pids.max").read_text().strip()=="32")
record("memory_limit_configured",pathlib.Path("/sys/fs/cgroup/memory.max").read_text().strip()==str(128*1024*1024))
record("cpu_limit_configured",pathlib.Path("/sys/fs/cgroup/cpu.max").read_text().strip()=="100000 100000")
children=[]
try:
    limited=False
    for _ in range(48):
        try: children.append(subprocess.Popen(["/bin/sleep","10"]))
        except OSError as exc:
            limited=exc.errno==errno.EAGAIN
            break
    record("pids_limit_enforced",limited,{"started_children":len(children)})
finally:
    for child in children: child.terminate()
    for child in children: child.wait()
child_code="import pathlib,sys; p=pathlib.Path(sys.argv[1]); " + "\ntry: p.read_bytes(); sys.exit(9)\nexcept OSError: pass\ntry: p.write_text('UNAUTHORIZED'); sys.exit(10)\nexcept OSError: pass\n"
r=subprocess.run(["/usr/bin/python3","-c",child_code,cfg["outside_file"]],capture_output=True,text=True)
record("python_descendant_isolated",r.returncode==0,r.stderr)
r=subprocess.run(["/bin/sh","-c","cat \"$1\" >/tmp/agd-read && exit 9; printf child > /workspace/child.txt; printf x > \"$1\" && exit 10; exit 0","agd-child",cfg["outside_file"]],capture_output=True,text=True)
record("shell_descendant_isolated",r.returncode==0 and (root/"child.txt").read_text()=="child",r.stderr)
network=[]
for target in ["127.0.0.1","host.docker.internal","host.guard.test","192.0.2.1"]:
    try:
        with socket.create_connection((target,cfg["tcp_port"]),timeout=0.35) as sock:
            sock.sendall(b"AGD_UNAUTHORIZED_NETWORK_TEST")
            network.append({"target":target,"blocked":False})
    except OSError as exc:
        network.append({"target":target,"blocked":True,"error":str(exc)})
record("tcp_host_and_direct_ip_unreachable",all(x["blocked"] for x in network),network)
udp=[]
for target in ["host.guard.test","192.0.2.1"]:
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        try: sock.sendto(b"AGD_UNAUTHORIZED_UDP_TEST",(target,cfg["udp_port"])); udp.append(False)
        except OSError: udp.append(True)
record("udp_egress_unreachable",all(udp),udp)
try:
    socket.getaddrinfo("agd-isolation.invalid",443)
    dns_blocked=False
except OSError:
    dns_blocked=True
record("dns_external_resolution_unavailable",dns_blocked)
libc=ctypes.CDLL(None,use_errno=True)
abi=libc.syscall(444,0,0,1)
print(json.dumps({"checks":checks,"landlock_abi":abi,"landlock_errno":ctypes.get_errno(),"python":os.sys.version,"kernel":os.uname().release},ensure_ascii=False))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image",default=DEFAULT_IMAGE)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    docker=shutil.which("docker") or "/usr/local/bin/docker"
    if not args.image.startswith("sha256:") or len(args.image)!=71:
        parser.error("--image 必须是本地完整 sha256 镜像 ID，禁止隐式拉取")
    run_id=time.strftime("%Y%m%dT%H%M%S")+"-"+uuid.uuid4().hex[:8]
    out=(args.out or ROOT/"eval/out/AGD-002"/run_id).resolve()
    out.mkdir(parents=True,exist_ok=False)
    checks=[]
    containers=[]
    commands=[]
    def run(cmd,timeout=30,**kwargs):
        commands.append(cmd)
        return subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,**kwargs)
    image_result=run([docker,"image","inspect",args.image])
    if image_result.returncode:
        (out/"blocked.json").write_text(json.dumps({"state":"blocked","reason":"本地镜像不可用","detail":image_result.stderr},ensure_ascii=False,indent=2))
        raise SystemExit(2)
    info=json.loads(image_result.stdout)[0]
    running_before=run([docker,"ps","--format","{{.ID}} {{.Names}}"]).stdout.splitlines()
    version=run([docker,"version","--format","{{json .}}"])
    packets=[]
    stop=threading.Event()
    tcp=socket.socket(); tcp.bind(("0.0.0.0",0)); tcp.listen(); tcp.settimeout(0.1)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(("0.0.0.0",0)); udp.settimeout(0.1)
    def tcp_server():
        while not stop.is_set():
            try:
                conn,_=tcp.accept()
                with conn: packets.append(("tcp",conn.recv(1024).decode(errors="replace")))
            except socket.timeout: pass
    def udp_server():
        while not stop.is_set():
            try: packets.append(("udp",udp.recvfrom(1024)[0].decode(errors="replace")))
            except socket.timeout: pass
    ts=[threading.Thread(target=tcp_server),threading.Thread(target=udp_server)]
    for thread in ts: thread.start()
    report={"task":"AGD-002","image_id":info["Id"],"architecture":info["Architecture"],"docker":json.loads(version.stdout),"checks":checks}
    try:
        with tempfile.TemporaryDirectory(prefix="agd-isolation-") as tmp:
            temp=Path(tmp).resolve(); source=temp/"source"; snapshot=temp/"snapshot"; private=temp/"private"
            for path in [source,snapshot,private]: path.mkdir(mode=0o755)
            (source/"input.txt").write_text("AGD_NORMAL_INPUT")
            outside=private/"host-only.txt"; outside.write_text("AGD_SYNTHETIC_HOST_SECRET")
            token="AGD_SYNTHETIC_CONTROL_"+uuid.uuid4().hex
            (source/"outside-link").symlink_to(outside)
            (source/"relative-outside-link").symlink_to("../private/host-only.txt")
            shutil.copytree(source,snapshot,dirs_exist_ok=True,symlinks=True)
            # 只有一次性测试快照可写；源目录和私有哨兵均不挂载。
            snapshot.chmod(0o777)
            for path in snapshot.iterdir():
                if not path.is_symlink(): path.chmod(0o666)
            (snapshot/"probe.py").write_text(PROBE)
            cfg={"outside_file":str(outside),"host_home":str(Path.home()),"test_token":token,"tcp_port":tcp.getsockname()[1],"udp_port":udp.getsockname()[1]}
            (snapshot/"config.json").write_text(json.dumps(cfg))
            (snapshot/"probe.py").chmod(0o644); (snapshot/"config.json").chmod(0o644)
            for proto in ("tcp","udp"):
                if proto=="tcp":
                    with socket.create_connection(("127.0.0.1",cfg["tcp_port"])) as conn: conn.sendall(b"AGD_CONTROL")
                else:
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as conn: conn.sendto(b"AGD_CONTROL",("127.0.0.1",cfg["udp_port"]))
            def command(suffix,argv,memory="128m"):
                name="agd-isolation-"+run_id+"-"+suffix; containers.append(name)
                return [docker,"run","--name",name,"--pull","never","--network","none","--read-only","--user","65534:65534","--cap-drop","ALL","--security-opt","no-new-privileges:true","--pids-limit","32","--memory",memory,"--memory-swap",memory,"--cpus","1","--tmpfs","/tmp:rw,nosuid,nodev,noexec,size=32m","--mount",f"type=bind,source={snapshot},target=/workspace","--workdir","/workspace","--add-host","host.guard.test:host-gateway","--entrypoint","/usr/bin/env",args.image,"-i","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/tmp","TMPDIR=/tmp","LANG=C.UTF-8"]+argv
            env=os.environ.copy(); env["AGD_HOST_ONLY_TEST_TOKEN"]=token
            result=run(command("probe",["/usr/bin/python3","/workspace/probe.py"]),env=env)
            (out/"probe.stdout").write_text(result.stdout); (out/"probe.stderr").write_text(result.stderr)
            checks.append({"name":"probe_completed","passed":result.returncode==0,"detail":result.returncode})
            if result.returncode==0:
                parsed=json.loads(result.stdout); checks.extend(parsed.pop("checks")); report["runtime"]=parsed
            checks.append({"name":"host_private_unchanged","passed":outside.read_text()=="AGD_SYNTHETIC_HOST_SECRET"})
            checks.append({"name":"host_source_unchanged","passed":not (source/"result.txt").exists() and (source/"input.txt").read_text()=="AGD_NORMAL_INPUT"})
            checks.append({"name":"snapshot_result_visible","passed":(snapshot/"result.txt").read_text()=="AGD_NORMAL_OUTPUT" if (snapshot/"result.txt").exists() else False})
            oom=run(command("oom",["/usr/bin/python3","-c","a=bytearray(256*1024*1024); print(len(a))"],"64m"))
            oom_state=run([docker,"inspect",containers[-1],"--format","{{json .State}}"])
            state=json.loads(oom_state.stdout)
            checks.append({"name":"memory_limit_enforced","passed":state.get("OOMKilled")==True and oom.returncode!=0,"detail":state})
            late="import pathlib,time; time.sleep(3); pathlib.Path('/workspace/late-child.txt').write_text('BAD')"
            parent="import subprocess,time; subprocess.Popen(['/usr/bin/python3','-c',"+repr(late)+"],start_new_session=True); print('started',flush=True); time.sleep(30)"
            try:
                run(command("timeout",["/usr/bin/python3","-c",parent]),timeout=1)
                timed_out=False
            except subprocess.TimeoutExpired:
                timed_out=True
            removed=run([docker,"rm","--force",containers[-1]])
            time.sleep(3.1)
            gone=run([docker,"inspect",containers[-1]])
            checks.append({"name":"timeout_removes_container_and_descendants","passed":timed_out and removed.returncode==0 and gone.returncode!=0 and not (snapshot/"late-child.txt").exists()})
            time.sleep(0.2)
            checks.append({"name":"network_listener_control_received","passed":sorted(packets)==[("tcp","AGD_CONTROL"),("udp","AGD_CONTROL")],"detail":packets[:]})
            report["snapshot_outputs"]={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in snapshot.iterdir() if p.is_file() and not p.is_symlink() and p.name not in ["config.json","probe.py"]}
    except BaseException as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        for name in containers: run([docker,"rm","--force",name])
        stop.set()
        for thread in ts: thread.join(timeout=1)
        tcp.close(); udp.close()
        running_after=run([docker,"ps","--format","{{.ID}} {{.Names}}"]).stdout.splitlines()
        checks.append({"name":"existing_running_containers_unchanged","passed":set(running_before)<=set(running_after),"detail":{"before":running_before,"after":running_after}})
        report["state"]="passed" if checks and all(item["passed"] for item in checks) and "error" not in report else "failed"
        report["scope"]="Docker VM 本地后端候选；未证明网关已接入、Node 路径或发布条件"
        (out/"report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
        (out/"commands.json").write_text(json.dumps(commands,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"state":report["state"],"passed":sum(x["passed"] for x in checks),"total":len(checks),"report":str(out/"report.json")},ensure_ascii=False))
    raise SystemExit(0 if report["state"]=="passed" else 1)

if __name__=="__main__": main()
