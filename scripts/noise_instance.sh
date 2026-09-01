#!/usr/bin/env bash
# =====================================================================
# 노이즈 생성기 A — 인스턴스가 '자기 역할 크리덴셜'로 정상 작업 수행
#   목적: 같은 크리덴셜(ASIA)이 '인스턴스 IP'에서 정상적으로 쓰이는 baseline 생성
#         → 공격자가 훔쳐서 '다른 IP'에서 쓰는 이벤트가 그 속의 needle이 된다
#         (v3 스키마의 ground-truth 탐지: 같은 키, 다른 IP)
# 사용:  ./noise_instance.sh <INSTANCE_ID> <VICTIM_BUCKET> [DURATION_SEC=600] [INTERVAL_SEC=10]
# 전제:  인스턴스 역할에 chain-pivot 정책(sts:GetCallerIdentity, s3:ListAllMyBuckets, s3:ListBucket) 부착됨
# 특징:  SSM으로 인스턴스 안에서 루프를 돌리므로, 호출은 전부 인스턴스 IP + ASIA 키로 기록된다
# =====================================================================
set -euo pipefail
INSTANCE_ID="${1:?INSTANCE_ID 필요}"
VICTIM_BUCKET="${2:?VICTIM_BUCKET 필요}"
DURATION="${3:-600}"
INTERVAL="${4:-10}"
REPS=$(( DURATION / INTERVAL )); [ "$REPS" -lt 1 ] && REPS=1

TMP=$(mktemp)
cat > "$TMP" <<JSON
{"commands":[
  "for i in \$(seq 1 ${REPS}); do aws sts get-caller-identity >/dev/null 2>&1; aws s3 ls >/dev/null 2>&1; aws s3 ls s3://${VICTIM_BUCKET}/ >/dev/null 2>&1; sleep ${INTERVAL}; done"
]}
JSON

echo "[noise-A] 인스턴스 ${INSTANCE_ID} 에서 ${DURATION}s 동안 ${INTERVAL}s 주기 정상 호출 시작"
CMD=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --timeout-seconds $(( DURATION + 120 )) \
  --parameters file://"$TMP" \
  --query "Command.CommandId" --output text)
rm -f "$TMP"
echo "[noise-A] SSM CommandId=${CMD} (인스턴스 내부에서 백그라운드로 진행)"
