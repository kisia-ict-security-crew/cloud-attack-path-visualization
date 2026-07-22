# -*- coding: utf-8 -*-
"""
flaws.cloud CloudTrail 로그 분석 스크립트 (Windows / Python 3.x)
사용법:
  1) 이 파일(analyze_flaws.py)을 로그가 있는 폴더 근처에 둔다.
  2) 명령프롬프트/PowerShell에서:  python analyze_flaws.py
  3) 스크립트가 현재 폴더 이하의 모든 .json을 자동으로 찾아 분석한다.
     특정 파일만 보려면:  python analyze_flaws.py 경로\flaws_cloudtrail00.json
"""
import json, sys, os, glob
from collections import Counter

def load_records(path):
    # 파일이 폴더면 건너뜀 (Errno 13 방지)
    if os.path.isdir(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except PermissionError:
        print(f"  [건너뜀] 권한 오류(폴더이거나 열려있는 파일): {path}")
        return None
    except json.JSONDecodeError as e:
        print(f"  [건너뜀] JSON 파싱 실패: {path} ({e})")
        return None
    # CloudTrail 파일은 {"Records":[...]} 구조
    if isinstance(data, dict) and 'Records' in data:
        return data['Records']
    return None

def analyze(recs, label):
    print("="*60)
    print(f"파일: {label}")
    print(f"전체 이벤트 수: {len(recs):,}")
    print("-"*60)

    # 1) 주체 종류 분포
    print("[주체 종류 userIdentity.type]")
    for t, c in Counter(r.get('userIdentity',{}).get('type','(없음)') for r in recs).most_common():
        print(f"   {t:15s} {c:>7,}  ({c/len(recs)*100:.1f}%)")

    # 2) 임시키(ASIA) vs 장기키(AKIA) 분포
    print("[accessKeyId 종류]")
    kinds = Counter()
    for r in recs:
        k = r.get('userIdentity',{}).get('accessKeyId') or ''
        if k.startswith('ASIA'): kinds['ASIA(임시키)'] += 1
        elif k.startswith('AKIA'): kinds['AKIA(장기키)'] += 1
        elif k == '': kinds['(키 없음: 서비스 등)'] += 1
        else: kinds['기타'] += 1
    for t, c in kinds.most_common():
        print(f"   {t:20s} {c:>7,}")

    # 3) AssumeRole 호출 주체 (IMDS 다리 문제 규모)
    callers = Counter(r.get('userIdentity',{}).get('type') for r in recs if r.get('eventName')=='AssumeRole')
    if callers:
        print("[AssumeRole 호출 주체 — AWSService면 발급자 추적 불가]")
        for t, c in callers.most_common():
            print(f"   {t:15s} {c:>7,}")

    # 4) 첫 AssumedRole 세션의 userIdentity 예쁘게 출력
    for r in recs:
        if r.get('userIdentity',{}).get('type')=='AssumedRole':
            print("[세션 주체(AssumedRole) userIdentity 예시]")
            print(json.dumps(r['userIdentity'], indent=2, ensure_ascii=False))
            break
    print()

def main():
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        # 현재 폴더 이하 모든 .json 자동 탐색
        targets = glob.glob('**/*.json', recursive=True)
        if not targets:
            print("현재 폴더 이하에서 .json 파일을 찾지 못했습니다.")
            print("스크립트를 로그 폴더 안에 두고 실행하거나, 경로를 인자로 주세요.")
            return
    print(f"분석 대상 {len(targets)}개 파일 발견\n")
    for path in targets:
        recs = load_records(path)
        if recs is not None:
            analyze(recs, os.path.basename(path))

if __name__ == '__main__':
    main()
