#!/usr/bin/env python3
"""核对已下载依赖，用既有基础镜像离线构建固定文档运行时；不更新当前 App。"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    lock_path = Path(__file__).with_name("document-runtime-lock.json")
    lock = json.loads(lock_path.read_text())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    docker = "/usr/local/bin/docker"
    inspect = json.loads(subprocess.check_output([docker, "image", "inspect", lock["base_image"]]))[0]
    assert inspect["Id"] == lock["base_image"] and inspect["Architecture"] == lock["architecture"]
    context = out / "context"
    context.mkdir()
    for package in lock["packages"]:
        source = args.packages / package["path"]
        assert source.is_file() and not source.is_symlink()
        assert hashlib.sha256(source.read_bytes()).hexdigest() == package["sha256"], package["path"]
        destination = context / package["path"]
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(source, destination)
    # 同一镜像增加稳定的构建引用；不会下载或替换基础镜像。
    base_tag = "agentguard-local/agd-runtime-base:document"
    subprocess.run([docker, "image", "tag", lock["base_image"], base_tag], check=True)
    extract = "import pathlib,zipfile; target='/usr/local/lib/python3.11/dist-packages'; " \
              "[zipfile.ZipFile(p).extractall(target) for p in pathlib.Path('/tmp/agd-wheels').glob('*.whl')]"
    recipe = f"FROM {base_tag}\nCOPY debs/ /tmp/agd-debs/\nCOPY wheels/ /tmp/agd-wheels/\n" \
             "RUN dpkg -i /tmp/agd-debs/*.deb\n" \
             + "RUN " + json.dumps(["/usr/bin/python3", "-c", extract]) + "\n" \
             + "RUN rm -rf /tmp/agd-debs /tmp/agd-wheels\n" \
             + 'LABEL org.gcsa.agentguard.scope="development-acceptance" org.gcsa.agentguard.document="1"\n'
    (context / "Dockerfile").write_text(recipe)
    tag = "agentguard-local/agd-runtime:document"
    report = {"base_image": lock["base_image"], "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
              "tag": tag, "packages": len(lock["packages"]), "passed": False}
    try:
        with (out / "build.log").open("w") as log:
            built = subprocess.run([docker, "build", "--pull=false", "--network=none", "--tag", tag, str(context)],
                                   stdout=log, stderr=subprocess.STDOUT, timeout=300)
        report["build_exit_code"] = built.returncode
        assert built.returncode == 0, "离线运行时构建失败"
        image = subprocess.check_output([docker, "image", "inspect", tag, "--format", "{{.Id}}"], text=True).strip()
        report["image_id"] = image
        probe = "import json,subprocess,pypdf,PIL,defusedxml; print(json.dumps({'pypdf':pypdf.__version__," \
                "'Pillow':PIL.__version__,'defusedxml':defusedxml.__version__," \
                "'tesseract':subprocess.check_output(['/usr/bin/tesseract','--version'],text=True).splitlines()[0]," \
                "'languages':subprocess.check_output(['/usr/bin/tesseract','--list-langs'],text=True).splitlines()[1:]}))"
        result = subprocess.run([docker, "run", "--rm", "--name", "agentguard-document-runtime-probe",
            "--pull=never", "--network=none", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--pids-limit=64", "--memory=256m", "--memory-swap=256m",
            "--cpus=1", "--entrypoint=/usr/bin/python3", image, "-I", "-c", probe],
            capture_output=True, text=True, timeout=30)
        report["probe_exit_code"] = result.returncode
        assert result.returncode == 0, "解析运行时探测失败"
        versions = json.loads(result.stdout)
        assert versions["pypdf"] == "6.18.1" and versions["Pillow"] == "12.3.0" and versions["defusedxml"] == "0.7.1"
        assert versions["tesseract"] == "tesseract 5.3.0"
        assert {"eng", "chi_sim", "chi_tra"}.issubset(versions["languages"])
        report["runtime"] = versions
        report["passed"] = True
    finally:
        (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
