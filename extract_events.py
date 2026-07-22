# -*- coding: utf-8 -*-
"""
flaws.cloud CloudTrail 로그에서 특정 이벤트만 추출해 새 파일로 저장.

사용 예 (명령프롬프트/PowerShell):
  # AssumeRole 이벤트만, 현재 폴더 이하 모든 json에서
  python extract_events.py --name AssumeRole --out only_assumerole.json

  # 여러 이벤트명 동시에
  python extract_events.py --name AssumeRole CreateAccessKey --out issue_events.json

  # 특정 accessKeyId(세션) 하나 추적
  python extract_events.py --key ASIAJN8M37S7VGV495HZ --out one_session.json

  # 특정 Role(권한출처) 세션만
  python extract_events.py --issuer level6 --out level6.json

  # 주체 종류로 (AssumedRole / IAMUser / Root / AWSService)
  python extract_events.py --type AssumedRole --out sessions.json

  # 파일을 직접 지정
  python extract_events.py --name AssumeRole --files flaws_cloudtrail00.json --out a.json

조건을 여러 개 주면 AND로 결합됩니다.
"""
import json, argparse, glob, os

def get(r, *path):
    cur = r
    for p in path:
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    return cur

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', nargs='+', help='eventName (여러 개 가능)')
    ap.add_argument('--type', nargs='+', help='userIdentity.type')
    ap.add_argument('--key',  nargs='+', help='userIdentity.accessKeyId')
    ap.add_argument('--issuer', nargs='+', help='sessionIssuer.userName (권한출처 Role)')
    ap.add_argument('--start', help='eventTime 시작 (예: 2017-02-19T20:00)')
    ap.add_argument('--end',   help='eventTime 끝')
    ap.add_argument('--files', nargs='+', help='대상 파일 (기본: 현재 폴더 이하 모든 .json)')
    ap.add_argument('--out', required=True, help='저장할 파일명')
    args = ap.parse_args()

    files = args.files or glob.glob('**/*.json', recursive=True)
    files = [f for f in files if not os.path.isdir(f) and os.path.abspath(f) != os.path.abspath(args.out)]

    def match(r):
        if args.name and get(r,'eventName') not in args.name: return False
        if args.type and get(r,'userIdentity','type') not in args.type: return False
        if args.key  and get(r,'userIdentity','accessKeyId') not in args.key: return False
        if args.issuer and get(r,'userIdentity','sessionContext','sessionIssuer','userName') not in args.issuer: return False
        et = get(r,'eventTime') or ''
        if args.start and et < args.start: return False
        if args.end and et > args.end: return False
        return True

    collected = []
    for path in files:
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except (PermissionError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and 'Records' in data:
            collected.extend(r for r in data['Records'] if match(r))

    # 시간순 정렬 (그래프 재구성에 유용)
    collected.sort(key=lambda r: r.get('eventTime',''))

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'Records': collected}, f, indent=2, ensure_ascii=False)
    print(f"{len(files)}개 파일에서 조건에 맞는 {len(collected):,}건 추출 -> {args.out}")

if __name__ == '__main__':
    main()
