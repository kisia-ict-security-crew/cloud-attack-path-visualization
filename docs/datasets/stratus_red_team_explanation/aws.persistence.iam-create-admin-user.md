# 관리자 IAM 사용자 생성 백도어 (Create an Administrative IAM User)

> 대상 로그: `aws.persistence.iam-create-admin-user.json`
> 원본: `raw_log/` 병합 후 시간 구간으로 분리
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.persistence.iam-create-admin-user`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1136.003** — Create Account: Cloud Account |
| 전술 | Persistence (지속성 확보) |
| 로그 레코드 수 | **6건** (세 기법 중 가장 작고 깨끗함) |
| 시간 범위 | `05:30:30Z` ~ `05:33:08Z` (KST 14:30~14:33) |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` |
| 생성된 백도어 사용자 | **`malicious-iam-user`** |
| 생성된 키 | **`AKIA52CDAKM4Z2EQLDV5`** (Active) |
| 부여된 권한 | `arn:aws:iam::aws:policy/**AdministratorAccess**` |
| **결정적 이벤트** | `CreateUser` → `AttachUserPolicy(AdministratorAccess)` → `CreateAccessKey` (3초 안에) |

**한 줄 요약:** 완전한 관리자 권한을 가진 **새 IAM 사용자와 영구 액세스 키**를 만든다. `iam-backdoor-user`(기존 사용자에 키 추가)보다 시끄럽지만 더 강력하다 — 처음부터 Admin 권한의 독립 계정이 생긴다.

---

## 2. 공격 기법 설명

### 2.1 원리와 위험

침투에 성공한 공격자는 원래 경로가 막혀도 다시 들어올 **뒷문**을 만든다. 이 기법은 그중 가장 직접적인 형태다.

```
iam:CreateUser          → 새 사용자 malicious-iam-user
iam:AttachUserPolicy    → AdministratorAccess 부착 (계정 전권)
iam:CreateAccessKey     → AKIA... 영구 키 발급
```

세 호출이면 **계정을 완전히 장악하는 독립 자격증명**이 생긴다. 위험한 이유:

- **영구성:** `AKIA` 키는 만료가 없다. 삭제 전까지 유효.
- **독립성:** 기존 사용자를 건드리지 않아, 원래 계정을 잠가도 이 사용자는 살아남는다.
- **전권:** `AdministratorAccess`라 이후 무엇이든 가능. 킬체인에서 이 노드 뒤로는 모든 것이 열린다.

### 2.2 `iam-backdoor-user`와의 차이

| | `iam-backdoor-user` | **`iam-create-admin-user`** |
|---|---|---|
| 방식 | **기존** 사용자에 2번째 키 추가 | **새** 사용자 생성 + Admin + 키 |
| 은밀성 | 높음 (기존 계정에 묻힘) | 낮음 (새 Admin 사용자는 눈에 띔) |
| 권한 | 대상 사용자의 기존 권한 | **AdministratorAccess (전권)** |
| 탐지 시그니처 | 호출자≠대상 키 발급 | `CreateUser`+`AttachUserPolicy(Admin)` 연쇄 |

### 2.3 킬체인에서의 위치

옵션 2 체인의 **Persistence 단계**다. 앞 단계(정찰)로 계정 구조를 파악한 뒤, 여기서 Admin 백도어를 심어 이후 방어 회피·임팩트로 나아간다.

> ⚠️ **이번 실행에는 cleanup이 없었다.** 로그에 `DeleteUser`/`DeleteAccessKey`가 없다. 즉 **`malicious-iam-user`와 키 `AKIA52CDAKM4Z2EQLDV5`가 계정에 아직 살아 있을 수 있다.** 학습이 끝나면 `stratus cleanup aws.persistence.iam-create-admin-user`로 반드시 정리할 것.

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
- **없음** (이 기법은 사전 리소스가 필요 없다)

### Detonation
1. `iam:CreateUser` → `malicious-iam-user`
2. `iam:AttachUserPolicy` → `AdministratorAccess`
3. `iam:CreateAccessKey` → `AKIA52CDAKM4Z2EQLDV5`

---

## 4. 로그 타임라인 분석

### 4.1 전체 흐름 (6건 전부)

| 시각 (UTC) | 이벤트 | 주체/UA | 의미 |
|---|---|---|---|
| 05:30:30 | `ec2:DescribeAccountAttributes` | stratus | 🔴 도구 기동 |
| **05:30:32** | **`iam:CreateUser`** (`malicious-iam-user`) | stratus | 🔴🔴 백도어 사용자 생성 |
| **05:30:32** | **`iam:AttachUserPolicy`** (`AdministratorAccess`) | stratus | 🔴🔴 전권 부여 |
| **05:30:33** | **`iam:CreateAccessKey`** → `AKIA52CDAKM4Z2EQLDV5` | stratus | 🔴🔴 영구 키 발급 |
| 05:30:43 | `notifications:ListManagedNotificationEvents` | console | ⚪ 배경 노이즈 |
| 05:33:08 | `notifications:ListManagedNotificationEvents` | console | ⚪ 배경 노이즈 |

**공격 4건 + 콘솔 노이즈 2건.** 오류 0건. 세 기법 중 가장 명확하다. IAM은 글로벌 서비스라 전부 `us-east-1`로 기록됐다.

### 4.2 결정적 이벤트

```json
{
  "eventTime": "2026-08-31T05:30:32Z",
  "eventName": "AttachUserPolicy",
  "awsRegion": "us-east-1",
  "userAgent": "stratus-red-team_...",
  "userIdentity": { "type": "IAMUser", "userName": "Huge-log-attack-simulation" },
  "requestParameters": {
    "userName": "malicious-iam-user",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"   // ← 🔴 전권
  }
}
```

```json
{
  "eventTime": "2026-08-31T05:30:33Z",
  "eventName": "CreateAccessKey",
  "requestParameters": { "userName": "malicious-iam-user" },
  "responseElements": {
    "accessKey": {
      "userName": "malicious-iam-user",
      "accessKeyId": "AKIA52CDAKM4Z2EQLDV5",   // ← 🔑 이후 이 키의 활동을 이 ID로 추적
      "status": "Active"
    }
  }
}
```

`responseElements.accessKey.accessKeyId`가 그래프에서 **이 사용자의 이후 모든 활동을 잇는 식별자**가 된다. `CreateUser -PRODUCED-> user`, `CreateAccessKey -ISSUED_CREDENTIAL-> credential -OF_IDENTITY-> user` 경로가 형성된다.

### 4.3 탐지 핵심 — 3개가 붙어 다닌다

`CreateUser` → `AttachUserPolicy(AdministratorAccess)` → `CreateAccessKey`가 **초 단위로 연쇄**하는 것이 시그니처다. 정상 운영에서 사용자를 만들자마자 Admin을 붙이고 키까지 즉시 발급하는 경우는 드물다.

---

## 5. 탐지

### 5.1 Sigma 룰

```yaml
title: New IAM User Granted Administrator Access
id: cc33dd44-create-admin-user-0001
status: stable
logsource: { product: aws, service: cloudtrail }
detection:
  attach_admin:
    eventSource: 'iam.amazonaws.com'
    eventName: 'AttachUserPolicy'
    requestParameters.policyArn|endswith: ':policy/AdministratorAccess'
  condition: attach_admin
falsepositives:
  - 승인된 IAM 관리자의 정당한 관리자 계정 생성 (관리자 ARN 화이트리스트)
level: high
```

```yaml
title: IAM CreateUser Followed By Admin Attach And Key
id: ee55ff66-create-admin-chain-0001
status: experimental
logsource: { product: aws, service: cloudtrail }
detection:
  chain:
    eventName: ['CreateUser', 'AttachUserPolicy', 'CreateAccessKey']
  condition: chain | count(eventName) by userIdentity.arn >= 3
  timeframe: 2m
level: high
```

### 5.2 Athena 쿼리

```sql
-- Admin 권한 부착 전수 조사
SELECT eventtime, useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.userName')  AS new_user,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy
FROM cloudtrail_logs
WHERE eventname = 'AttachUserPolicy'
  AND json_extract_scalar(requestparameters, '$.policyArn') LIKE '%AdministratorAccess'
ORDER BY eventtime DESC;
```

```sql
-- 백도어 키의 사후 활동 추적 (사고대응)
SELECT eventtime, eventsource, eventname, sourceipaddress, errorcode
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIA52CDAKM4Z2EQLDV5'
ORDER BY eventtime;
```

### 5.3 GuardDuty
- `Persistence:IAMUser/AnomalousBehavior` — 신규 주체의 이례적 IAM 활동
- 전용 탐지는 없으므로 위 Sigma/Athena 룰을 직접 운용하는 것이 확실하다.

---

## 6. 완화 방안

| 조치 | 내용 |
|---|---|
| **SCP로 CreateUser/AttachUserPolicy 제한** ⭐ | 지정된 IdentityAdmin 역할 외에는 Deny |
| IAM Identity Center(SSO) 전환 | 장기 IAM 사용자·키를 없애 백도어 사용자 자체를 무의미하게 |
| `AdministratorAccess` 부착 알림 | EventBridge로 실시간 감지 + 자동 대응 |
| MFA 강제 | IAM 쓰기에 `aws:MultiFactorAuthPresent` 조건 |
| Credential Report 정기 점검 | 미승인 사용자·키 상시 발견 |

```json
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser","iam:AttachUserPolicy","iam:CreateAccessKey"],
  "Resource": "*",
  "Condition": { "ArnNotLike": { "aws:PrincipalARN": "arn:aws:iam::*:role/IdentityAdministrator" } }
}
```

---

## 7. 대응 절차

1. 키 즉시 비활성화(`AKIA52CDAKM4Z2EQLDV5`) → 삭제보다 비활성화 먼저(조사 단서 보존)
2. 키 ID로 사후 활동 전수 조사 (5.2절 두 번째 쿼리)
3. `malicious-iam-user` 삭제 + 발급 주체 조사
4. 발급 주체가 어떻게 IAM 쓰기 권한을 얻었는지 근본 원인 추적

---

## 8. 참고 자료

- [Stratus Red Team — Create an Administrative IAM User](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-admin-user/)
- [MITRE ATT&CK T1136.003 — Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
