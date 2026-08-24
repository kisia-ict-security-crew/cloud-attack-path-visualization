"""
윈도우/맥/리눅스 어디서나 동작하는 실행 스크립트 (run.sh의 순수 Python 버전)

사용법 (윈도우 cmd/PowerShell에서도 동일):
  python run.py flaws_cloudtrail_logs.tar
  python run.py C:\\Users\\me\\Downloads\\flaws_cloudtrail_logs.tar
  python run.py C:\\extracted_folder
  python run.py flaws_cloudtrail_logs.tar --limit 5000
"""
import sys
import os
import shutil
import tarfile
import zipfile
import argparse
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="tar/zip 파일 경로 또는 이미 압축 푼 폴더 경로")
    ap.add_argument("--limit", type=int, default=None, help="앞 N건만 처리 (대용량 첫 테스트용)")
    args = ap.parse_args()

    input_path = os.path.abspath(args.input)
    data_dir = os.path.abspath("data")

    if os.path.abspath(input_path) == data_dir:
        print("[에러] 입력 경로가 data 폴더 자기 자신입니다. 다른 경로를 지정하세요.")
        sys.exit(1)

    if os.path.isdir(data_dir):
        shutil.rmtree(data_dir)
    os.makedirs(data_dir, exist_ok=True)

    if os.path.isfile(input_path) and input_path.lower().endswith(".tar"):
        print("[1/2] tar 압축 해제 중...")
        with tarfile.open(input_path) as t:
            t.extractall(data_dir)
    elif os.path.isfile(input_path) and input_path.lower().endswith((".zip",)):
        print("[1/2] zip 압축 해제 중...")
        with zipfile.ZipFile(input_path) as z:
            z.extractall(data_dir)
    elif os.path.isdir(input_path):
        print("[1/2] 폴더 복사 중...")
        shutil.copytree(input_path, data_dir, dirs_exist_ok=True)
    else:
        print(f"[에러] {input_path} 을 인식하지 못했습니다 (.tar, .zip, 폴더만 지원)")
        sys.exit(1)

    print("[2/2] 파싱 + 세션 생애주기 + 기법 매칭 + 시각화...")
    cmd = [sys.executable, "lineage_timeline.py", "--data-dir", data_dir]
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    subprocess.run(cmd, check=True)

    print("\n완료. cloudtrail_lineage_timeline.png 를 확인하세요.")


if __name__ == "__main__":
    main()
