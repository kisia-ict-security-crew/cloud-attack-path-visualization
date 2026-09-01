# 셸 스크립트 설명 — 5단계 킬체인 + 노이즈 생성

이 폴더의 스크립트 3개는 **크리덴셜 핸드오프 APT 체인(옵션 2)**을 정상 활동과 함께 실행해 `aws.5_chain_n1.json` 같은 데이터셋을 만든다. 설계 배경·단계별 명령은 상위 폴더 `CHAIN-option2-guide.md` 참고.

전제(Phase A): Stratus warmup 3종(steal-credentials / cloudtrail-stop / s3-ransomware-batch-deletion) + 인스턴스 역할에 `chain-pivot` 정책 부착 + 연구 트레일 running(다중 리전 + S3 데이터 이벤트 ON).

---

## 1. `aws.5_chain_n1_execute_with_noise.sh` — 메인 오케스트레이터

**노이즈 A·B를 백그라운드로 띄우고, 그 사이에 공격 5단계를 자동 실행**한다. 이 스크립트 하나로 데이터셋 전체가 생성된다. (`chain_with_noise.sh`에서 이름만 바뀐 동일 파일)

### 하는 일 (순서)
1. 엔티티 자동 탐색 — 인스턴스ID / decoy 트레일 / victim 버킷
2. 노이즈 A·B 백그라운드 시작
3. **pre-roll** — 공격 전 정상 트래픽만 쌓기(기본 60초)
4. **[1] 탈취** — SSM으로 IMDS 크리덴셜 추출 → `ASIA…`(Cred①) 자동 export
5. **[2] 정찰** — Cred①로 GetCallerIdentity / ListRoles / ListUsers / s3 ls
6. **[3] 권한상승** — Cred①로 CreateUser → AttachUserPolicy(AdministratorAccess) → CreateAccessKey → `AKIA…`(Cred②) 자동 캡처
7. **[4] 회피** — Cred②로 decoy 트레일 StopLogging
8. **[5] 임팩트** — Cred②로 victim 버킷 delete-objects
9. **post-roll** — 공격 후 정상 트래픽(기본 120초) → 노이즈 종료

### 사용
```bash
export OPS_PROFILE=<정상운영프로파일>       # 노이즈 B 신원 (미설정 시 default)
export AWS_DEFAULT_REGION=ap-northeast-2
./aws.5_chain_n1_execute_with_noise.sh
```

### 환경변수 (SNR·타이밍 조절)
| 변수 | 기본 | 의미 |
|---|---|---|
| `NOISE_DURATION` | 900 | 노이즈 총 지속(초) |
| `PREROLL` / `POSTROLL` | 60 / 120 | 공격 전/후 정상 트래픽 시간 |
| `OPS_INTERVAL` | 5 | 노이즈 B 주기(작을수록 진함) |
| `INST_INTERVAL` | 10 | 노이즈 A 주기 |
| `NO_NOISE=1` | — | 노이즈 없이 공격만(깨끗한 대조군) |
| `NO_ATTACK=1` | — | 노이즈만 |

### 의존성
- `jq` 필수 (탈취 크리덴셜·백도어 키 파싱). 없으면 실행 거부.
- 셸 기본 크리덴셜 = Stratus 운영자(IAM 쓰기 권한 필요). 공격 신원(ASIA/AKIA)은 런타임에 자동 주입되므로 프로파일 설정 불필요.

### 핵심 설계
- 공격 신원 전환은 프로파일 교체가 아니라 **명령별 env 주입**(`AWS_ACCESS_KEY_ID=… aws …`).
- decoy 트레일만 끄고 **연구 트레일은 계속 기록** → 임팩트까지 수집됨.

---

## 2. `noise_instance.sh` — 노이즈 A (인스턴스 자기 크리덴셜)

인스턴스가 **자기 역할 크리덴셜로 정상 호출**을 반복하게 해서, 같은 키(ASIA)가 **인스턴스 IP에서** 쓰이는 baseline을 만든다. → 공격자가 그 키를 훔쳐 **다른 IP에서** 쓰는 이벤트가 그 속의 needle이 된다(v3의 ground-truth 신호).

### 방식
SSM `SendCommand`로 인스턴스 내부에서 루프 실행: `sts get-caller-identity`, `s3 ls`, `s3 ls s3://victim`. 호출은 전부 인스턴스 IP + ASIA 키로 기록.

### 사용
```bash
./noise_instance.sh <INSTANCE_ID> <VICTIM_BUCKET> [DURATION=600] [INTERVAL=10]
```
> 전제: 인스턴스 역할에 chain-pivot 정책(sts:GetCallerIdentity, s3:ListAllMyBuckets, s3:ListBucket) 부착.
> 참고: 인스턴스의 SSM 에이전트도 같은 키로 하트비트(UpdateInstanceInformation)를 내므로, 이 baseline은 스크립트 없이도 일부 형성된다.

---

## 3. `noise_ops.sh` — 노이즈 B (정상 운영자)

**정상 운영자가 공격과 같은 엔티티(인스턴스·victim 버킷·IAM·트레일)를 정상 맥락으로** 사용한다. → "그 엔티티를 건드림 = 공격"으로 못 거르게 만든다. 판별이 엔티티가 아니라 **행위 패턴**이 되어야 한다.

### 발생 이벤트 (루프)
- `ec2:DescribeInstances`(인스턴스 노드) · `s3 ls`+`cp`(victim 버킷 List/Put/Get) · `iam:ListUsers` · `cloudtrail:GetTrailStatus` · 가끔 `iam:ListAccessKeys`

### 사용
```bash
AWS_PROFILE=<정상운영프로파일> ./noise_ops.sh <INSTANCE_ID> <VICTIM_BUCKET> <DECOY_TRAIL> [DURATION=600] [INTERVAL=5]
```
> 백그라운드 실행 권장(오케스트레이터가 자동 처리): `... ./noise_ops.sh ... &`
> 이 프로파일은 read + victim 버킷 get/put 권한이 있어야 한다. 권한 없는 호출은 조용히 스킵(`|| true`).

---

## 실행 방식 두 가지
- **자동**: `aws.5_chain_n1_execute_with_noise.sh` 하나 (노이즈+공격 전체)
- **수동**: `CHAIN-option2-guide.md` 3절을 손으로 + `noise_ops.sh`/`noise_instance.sh`를 별도 셸에서 병행

> ⚠️ 둘을 섞지 말 것 — 오케스트레이터가 공격까지 하므로 가이드 명령을 또 치면 중복 실행된다.

## 데이터셋 3종 (난이도별)
```bash
NO_NOISE=1     ./aws.5_chain_n1_execute_with_noise.sh   # 깨끗한 체인(경로 검증)
OPS_INTERVAL=8 ./aws.5_chain_n1_execute_with_noise.sh   # 중간 노이즈
OPS_INTERVAL=2 ./aws.5_chain_n1_execute_with_noise.sh   # 진한 노이즈
```
