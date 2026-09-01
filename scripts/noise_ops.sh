#!/usr/bin/env bash
# =====================================================================
# 노이즈 생성기 B — '정상 운영자'가 공격과 같은 엔티티를 정상 맥락으로 사용
#   목적: 인스턴스 노드 / victim 버킷 / IAM / 트레일을 정상 이벤트로도 등장시켜,
#         "그 엔티티를 건드림 = 공격"으로 못 거르게 한다 (행위 패턴으로만 판별 가능)
# 사용:  AWS_PROFILE=<정상운영프로파일> ./noise_ops.sh <INSTANCE_ID> <VICTIM_BUCKET> <DECOY_TRAIL> [DURATION=600] [INTERVAL=5]
# 전제:  이 프로파일은 정상 운영자(예: 관리자/데브옵스) — read + victim 버킷 get/put 권한 보유
# 백그라운드 실행 권장:  AWS_PROFILE=ops ./noise_ops.sh ... &   (컨트롤러가 자동 처리)
# =====================================================================
set -uo pipefail
INSTANCE_ID="${1:?INSTANCE_ID 필요}"
VICTIM_BUCKET="${2:?VICTIM_BUCKET 필요}"
DECOY_TRAIL="${3:?DECOY_TRAIL 필요}"
DURATION="${4:-600}"
INTERVAL="${5:-5}"

END=$(( $(date +%s) + DURATION ))
TMP=$(mktemp); echo "ops heartbeat $(date -u +%FT%TZ)" > "$TMP"
DL="${TMP}.dl"
i=0
echo "[noise-B] 정상 운영 활동 ${DURATION}s 시작 (주기 ${INTERVAL}s, 프로파일=${AWS_PROFILE:-default})"
while [ "$(date +%s)" -lt "$END" ]; do
  i=$((i+1))
  # --- 인스턴스 노드를 정상 조회 ---
  aws ec2 describe-instances --instance-ids "$INSTANCE_ID" >/dev/null 2>&1 || true
  # --- victim 버킷을 정상 읽기/쓰기 (같은 버킷을 공격만 건드리지 않게) ---
  aws s3 ls "s3://$VICTIM_BUCKET/" >/dev/null 2>&1 || true
  aws s3 cp "$TMP" "s3://$VICTIM_BUCKET/ops/heartbeat-$i.txt" >/dev/null 2>&1 || true   # PutObject
  aws s3 cp "s3://$VICTIM_BUCKET/ops/heartbeat-$i.txt" "$DL" >/dev/null 2>&1 || true     # GetObject
  # --- IAM 정상 조회 (정찰 API를 정상 맥락에도) ---
  aws iam list-users --max-items 20 >/dev/null 2>&1 || true
  # --- 트레일 정상 상태 확인 (StopLogging을 정상 read에 묻히게) ---
  aws cloudtrail get-trail-status --name "$DECOY_TRAIL" >/dev/null 2>&1 || true
  # --- 가끔 정상 키 로테이션 조회 (백도어 시그니처를 비유일하게) ---
  if [ $(( i % 12 )) -eq 0 ]; then aws iam list-access-keys >/dev/null 2>&1 || true; fi
  sleep "$INTERVAL"
done
rm -f "$TMP" "$DL"
echo "[noise-B] 종료 (총 ${i} 사이클)"
