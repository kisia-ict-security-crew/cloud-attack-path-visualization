# IAM 사용자 백도어 액세스 키 생성 (Create an Access Key on an IAM User)

> 대상 로그: `aws.persistence.iam-backdoor-user.json`
> 원본: `raw_log/` 의 CloudTrail S3 로그 파일 12개를 병합 후 시간 구간으로 분리
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.persistence.iam-backdoor-user`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1098** — Account Manipulation (관련: T1078.004 Valid Accounts: Cloud Accounts) |
| 전술(Tactic) | Persistence (지속성 확보) |
| 로그 레코드 수 | **37건** |
| 시간 범위 | `2026-08-28T05:49:59Z` ~ `2026-08-28T05:54:46Z` (KST 14:49 ~ 14:54) |
| AWS 계정 | `949328302905` |
| 리전 | `us-east-1` (IAM 글로벌) + `ap-northeast-2` (배경 노이즈) |
| 소스 IP | `165.132.5.130` |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` |
| 백도어 대상 | IAMUser **`stratus-red-team-backdoor-u-user`** |
| 생성된 키 | **`AKIA52CDAKM4VUKRHGUR`** (05:51:28 생성 → 05:51:38 삭제, 수명 10초) |
| **결정적 이벤트** | `iam:CreateAccessKey` — `2026-08-28T05:51:28Z`, 단 1건 |

**한 줄 요약:** 이미 침투한 계정에서 **다른 IAM 사용자에게 새 액세스 키를 발급**한다. 원래 침투 경로가 차단돼도 이 키로 계속 들어올 수 있는 **영구 뒷문**이 된다. 이벤트는 딱 한 건이고, 정상적인 키 로테이션과 겉모습이 똑같다.

---

## 2. 공격 기법 설명

### 2.1 원리

IAM 사용자는 액세스 키를 **최대 2개**까지 가질 수 있다. 원래는 무중단 키 로테이션을 위한 기능이다(새 키 발급 → 애플리케이션 교체 → 옛 키 삭제).

공격자는 이 "2개 슬롯"을 노린다.

```
① 어떤 경로로든 IAM 쓰기 권한 획득
        │  (피싱, 유출된 키, 과도한 권한의 역할, 콘솔 세션 탈취 …)
        ▼
② iam:CreateAccessKey  ←── 【이 기법】
        │
        ▼
③ 새 AKIA... 키 확보
        │
        ├─▶ 원래 침투 경로가 막혀도 이 키로 재진입
        ├─▶ 만료가 없다 (임시 자격증명 ASIA... 와 결정적 차이)
        ├─▶ MFA가 걸려 있지 않다 (API 키에는 보통 MFA 조건이 없음)
        └─▶ 사용자 계정이 활성인 한 계속 유효
```

### 2.2 왜 무서운가 — 임시 자격증명과의 비교

| | 임시 자격증명 (`ASIA...`) | **액세스 키 (`AKIA...`)** |
|---|---|---|
| 만료 | 최대 12시간, 보통 1~6시간 | **없음. 삭제할 때까지 영구** |
| 세션 무효화 | `AWSRevokeOlderSessions` 정책으로 일괄 무효화 가능 | **불가능. 키를 찾아서 지워야만 함** |
| MFA | 세션 발급 시 MFA 강제 가능 | 보통 적용 안 됨 |
| 발급 흔적 | `AssumeRole` 이벤트가 반복 발생 | **`CreateAccessKey` 딱 한 번** |
| 탐지 난이도 | 사용할 때마다 흔적 | **만들 때 놓치면 이후엔 정상 API 호출과 구별 불가** |

즉 **한 번 놓치면 끝이다.** 사고 대응에서 "침해된 역할 세션을 전부 무효화했다"고 안심하는 사이, 백도어 키는 조용히 살아남는다.

### 2.3 Stratus 공식 문서의 경고

> "이 이벤트는 다른 지표와 상관분석하지 않는 한 그 자체로는 의심스럽다고 보기 어렵다."

정확한 지적이다. `CreateAccessKey`는 **정상 키 로테이션에서 매일 발생**한다. 그래서 이 기법의 탐지는 "이벤트가 발생했는가"가 아니라 **"누가 누구에게 발급했는가"** 를 봐야 한다. 4.2절이 그 핵심이다.

### 2.4 관련 지속성 기법 변형

| 기법 | API | 특징 |
|---|---|---|
| **액세스 키 백도어** | `iam:CreateAccessKey` | 이 로그. 가장 단순하고 흔함 |
| 콘솔 로그인 백도어 | `iam:CreateLoginProfile` / `UpdateLoginProfile` | 콘솔 비밀번호 설정. 기존 사용자에게 걸면 매우 은밀 |
| 역할 신뢰 정책 백도어 | `iam:UpdateAssumeRolePolicy` | **외부 계정**을 신뢰 주체로 추가. 계정 안에 흔적이 거의 없음 |
| 그룹 권한 상승 | `iam:AddUserToGroup` | 기존 사용자를 Admin 그룹에 추가 |
| 신규 사용자 생성 | `iam:CreateUser` + `AttachUserPolicy` | 가장 시끄러움 |

`iam:UpdateAssumeRolePolicy`가 실무에서 가장 놓치기 쉬운 변형이다. 새 자격증명이 만들어지지 않으므로 "키 감사"에 걸리지 않는다.

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. IAM 사용자 `stratus-red-team-backdoor-u-user` 생성 (태그 `StratusRedTeam=true`)

### Detonation
2. **`iam:CreateAccessKey`** 로 그 사용자에게 액세스 키 발급 → `AKIA52CDAKM4VUKRHGUR`

### Revert / Cleanup
3. `iam:ListAccessKeys` → `iam:DeleteAccessKey` 로 키 회수 (발급 10초 후)
4. 사용자 정리를 위한 조회 연쇄 (`ListGroupsForUser`, `ListSSHPublicKeys`, `ListVirtualMFADevices`, `ListMFADevices`, `ListSigningCertificates`, `DeleteLoginProfile`) 후 `iam:DeleteUser`

---

## 4. 로그 타임라인 분석

### 4.1 단계별 흐름

| 시각 (UTC) | 이벤트 | 리전 | 주체 / UA | 의미 |
|---|---|---|---|---|
| 05:49:59~05:50:50 | `s3:GetBucketAcl` ×12 | ap-northeast-2 | `cloudtrail.amazonaws.com` | ⚪ **CloudTrail 로그 배달 노이즈** (앞선 두 시나리오의 로그가 S3로 전달되는 중) |
| **05:50:59** | `ec2:DescribeAccountAttributes` | ap-northeast-2 | **stratus-red-team_51bd0fff** | 🔴 Stratus 도구 기동 |
| 05:51:09~11 | `notifications:ListManagedNotificationEvents` | us-east-1 | 콘솔 | ⚪ 배경 노이즈 |
| 05:51:12~14 | `iam:GetUser` ×2 | us-east-1 | Terraform | 🟡 Warm-up 시작 |
| **05:51:15** | **`iam:CreateUser`** (`stratus-red-team-backdoor-u-user`) | us-east-1 | Terraform | 🟡 백도어 대상 사용자 생성 |
| 05:51:16 | `iam:GetUser` | us-east-1 | Terraform | 🟡 생성 확인 |
| 05:51:27 | `ec2:DescribeAccountAttributes` | ap-northeast-2 | stratus-red-team_ab4313c5 | 🔴 detonate 직전 확인 |
| **05:51:28** | **`iam:CreateAccessKey`** → `AKIA52CDAKM4VUKRHGUR` | **us-east-1** | **stratus-red-team_e6f8c649** | 🔴🔴 **공격 실행** |
| 05:51:38 | `iam:ListAccessKeys` | us-east-1 | stratus-red-team_8132d3ae | 🔴 revert 준비 |
| **05:51:38** | **`iam:DeleteAccessKey`** (`AKIA52CDAKM4VUKRHGUR`) | us-east-1 | stratus-red-team_8132d3ae | 🔴 공격 원복 (실제 공격자라면 **증거 인멸**) |
| 05:51:40~49 | `GetUser`, `ListGroupsForUser`, `ListAccessKeys`, `ListSSHPublicKeys`, `ListVirtualMFADevices`, `ListMFADevices`, `DeleteLoginProfile`(`NoSuchEntityException`), `ListSigningCertificates` | us-east-1 | Terraform | 🟡 삭제 전 의존 리소스 조회 |
| **05:51:50** | **`iam:DeleteUser`** | us-east-1 | Terraform | 🟡 Cleanup |
| 05:52:37 | `sts:AssumeRole`, `glue:GetDatabases` | ap-northeast-2 | Resource Explorer | ⚪ 배경 노이즈 |
| 05:54:46 | `notifications:ListManagedNotificationEvents` | us-east-1 | 콘솔 | ⚪ 배경 노이즈 |

### 4.2 ⭐ 결정적 판단 근거 — 호출자 ≠ 대상

```json
{
  "eventTime": "2026-08-28T05:51:28Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "165.132.5.130",
  "userAgent": "stratus-red-team_e6f8c649-1dbe-4f08-8aa7-ca82d5f68e50",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "Huge-log-attack-simulation",            // ← 호출자
    "arn": "arn:aws:iam::949328302905:user/Huge-log-attack-simulation",
    "accessKeyId": "AKIA52CDAKM4W5UHPSX2"
  },
  "requestParameters": {
    "userName": "stratus-red-team-backdoor-u-user"       // ← 대상 (다른 사용자!)
  },
  "responseElements": {
    "accessKey": {
      "userName": "stratus-red-team-backdoor-u-user",
      "accessKeyId": "AKIA52CDAKM4VUKRHGUR",             // ← 🔑 생성된 키 ID
      "status": "Active",
      "createDate": "2026-08-28T05:51:28Z"
    }
  }
}
```

**두 값의 비교가 이 기법 탐지의 전부다.**

| 패턴 | `userIdentity.userName` vs `requestParameters.userName` | 판정 |
|---|---|---|
| 정상 키 로테이션 | **같음** (자기 키를 자기가 갱신) | 🟢 무해 — 대부분의 정상 트래픽 |
| **백도어 심기** | **다름** (남의 계정에 키 발급) | 🔴 **이 로그가 여기 해당** |

`requestParameters.userName`을 생략하면 호출자 자신에게 발급되므로, **`requestParameters`에 `userName`이 명시적으로 있고 그것이 호출자와 다르면** 그 자체로 조사 대상이다. 물론 IAM 관리자가 신입에게 키를 만들어 주는 정상 케이스도 있으므로, **승인된 관리자 주체 화이트리스트**와 결합해야 한다.

### 4.3 `responseElements.accessKey.accessKeyId` — 추적의 시작점

CloudTrail은 **비밀 키(SecretAccessKey)는 절대 기록하지 않는다.** 하지만 **액세스 키 ID는 그대로 남긴다.** 이게 사고 조사에서 결정적이다.

```
CreateAccessKey.responseElements.accessKey.accessKeyId  =  AKIA52CDAKM4VUKRHGUR
                              │
                              │  (이후 그 키로 호출한 모든 이벤트)
                              ▼
                    userIdentity.accessKeyId  =  AKIA52CDAKM4VUKRHGUR
```

즉 **백도어 키가 만들어진 순간부터 그 키가 한 모든 행위를 하나의 식별자로 이어붙일 수 있다.** 그래프 DB 관점에서는 아주 품질 좋은 엣지다.

```
(:User {name:"Huge-log-attack-simulation"})
        -[:CREATED_KEY {at:"05:51:28Z"}]->
(:AccessKey {id:"AKIA52CDAKM4VUKRHGUR"})
        -[:BELONGS_TO]->
(:User {name:"stratus-red-team-backdoor-u-user"})
```

> 이번 로그에서는 10초 뒤 `DeleteAccessKey`가 뒤따라 실제 사용 기록이 없다. 실제 침해였다면 이 키 ID로 이후 며칠~몇 달의 활동을 전부 되짚을 수 있다.

### 4.4 삭제 이벤트 — 증거 인멸 관점

```
05:51:28Z  CreateAccessKey   AKIA52CDAKM4VUKRHGUR  생성
05:51:38Z  DeleteAccessKey   AKIA52CDAKM4VUKRHGUR  삭제 (10초 후)
```

Stratus에서는 단순 원복이지만, 실제 공격에서 `CreateAccessKey` → 짧은 시간 내 `DeleteAccessKey` 패턴은 **"키를 뽑아서 외부에 저장한 뒤 콘솔에서 흔적을 지운" 정황**일 수 있다. IAM 콘솔의 사용자 화면을 보면 키가 없어서 깨끗해 보이지만, **키를 삭제해도 그 키로 이미 한 일은 되돌아가지 않는다.**

### 4.5 시그널 vs 노이즈

| 구분 | 건수 | 비율 | 판별 기준 |
|---|---|---|---|
| 🔴 **공격 (`CreateAccessKey`)** | **1** | **2.7%** | UA `stratus-red-team_e6f8c649` |
| 🔴 공격 도구 원복·부수 호출 (`DeleteAccessKey`, `ListAccessKeys`, `DescribeAccountAttributes`×2) | 4 | 10.8% | UA `stratus-red-team_<uuid>` |
| 🟡 Warm-up / Cleanup (Terraform) | 15 | 40.5% | UA `terraform-provider-aws` |
| ⚪ AWS 서비스 이벤트 | 14 | 37.8% | `cloudtrail.amazonaws.com`(12), `resource-explorer-2`(2) |
| ⚪ 콘솔 배경 노이즈 | 3 | 8.1% | `Mozilla/5.0 ... Chrome` |

오류는 1건뿐이다 — `DeleteLoginProfile` → `NoSuchEntityException`. 해당 사용자에게 콘솔 비밀번호가 없어서 나온 정상 응답이며, Terraform이 삭제 전에 "있으면 지우고 없으면 넘어가는" 방식으로 호출한 결과다.

> ⚠️ **분류상의 주의:** AWS 서비스 이벤트 14건 중 12건은 `cloudtrail.amazonaws.com`의 `GetBucketAcl`이다. 이건 **앞선 두 시나리오의 로그가 S3 버킷으로 배달되면서 발생한 것**으로, 이 공격과 인과관계가 없다. 시간 구간 기반으로 분류했기 때문에 함께 들어왔다. 분석 시 반드시 제외할 것.

### 4.6 리전 주의 — IAM은 전부 `us-east-1`

이 시나리오의 **공격 관련 이벤트는 전부 `awsRegion: "us-east-1"`** 이다. IAM이 글로벌 서비스이기 때문이다. 실험은 서울 리전에서 진행했지만, `ap-northeast-2`만 조회하면 **`CreateAccessKey`를 포함해 아무것도 보이지 않는다.**

이번에는 트레일이 `isMultiRegionTrail: true`, `includeGlobalServiceEvents: true`로 설정돼 있어 정상 수집됐다. IAM 관련 기법을 다룰 때 이 설정은 선택이 아니라 필수다.

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 | 비고 |
|---|---|---|
| **최상** | `CreateAccessKey` 에서 **`requestParameters.userName` ≠ `userIdentity.userName`** | 4.2절. 오탐이 극히 적다 |
| **최상** | 대상 사용자가 **평소 API를 쓰지 않는 계정**(콘솔 전용, 서비스 미사용 계정) | 백도어의 전형 |
| 상 | `CreateAccessKey` 호출 주체가 IAM 관리자가 아닌 경우 | 승인 목록 대조 |
| 상 | `CreateAccessKey` 후 **짧은 시간 내 `DeleteAccessKey`** | 흔적 제거 정황 |
| 상 | 새 키가 **생성 직후 다른 IP/지역에서 즉시 사용됨** | 키가 외부로 나갔다는 강한 증거 |
| 중 | `CreateLoginProfile` / `UpdateLoginProfile` / `UpdateAssumeRolePolicy` / `AddUserToGroup` | 같은 목적의 다른 지속성 기법 |
| 중 | 로깅 무력화(`DeleteTrail`, `DeleteFlowLogs`)와 **같은 주체가 근접 시간에 실행** | 이번 실험이 정확히 이 순서 |

> 💡 마지막 항목이 실전에서 가장 강력하다. 이번 실험은 `DeleteTrail`(05:40:28) → `DeleteFlowLogs`(05:45:35) → `CreateAccessKey`(05:51:28) 순서로, **같은 IAM 주체 `Huge-log-attack-simulation`·같은 IP `165.132.5.130`에서 정확히 11분 안에** 일어났다. 개별 이벤트는 전부 "애매"하지만, **묶으면 교과서적인 침투 후 행동 순서**(로그 끄기 → 네트워크 가리기 → 뒷문 만들기)다. 단일 이벤트 룰보다 이 상관관계가 훨씬 신뢰도 높다.

### 5.2 Sigma 룰

```yaml
title: IAM Access Key Created For Another User
id: 9d3c7a44-2e18-4b6f-95c0-iambackdoor00001
status: experimental
description: |
  한 IAM 주체가 자기 자신이 아닌 다른 사용자에게 액세스 키를 발급하는 경우를 탐지한다.
  정상 키 로테이션(자기 키 갱신)과 백도어 심기를 구분하는 핵심 조건이다.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateAccessKey'
    requestParameters.userName|exists: true   # 생략 시 자기 자신 = 정상 로테이션
  # 승인된 IAM 관리자는 환경에 맞게 채울 것
  approved_admins:
    userIdentity.arn|contains:
      - 'role/IAMAdministrator'
      - 'user/identity-automation'
  filter_error:
    errorCode|exists: true
  condition: selection and not approved_admins and not filter_error
  # 상관분석 단계에서 requestParameters.userName != userIdentity.userName 을 최종 확인할 것
falsepositives:
  - IAM 관리자의 정상적인 신규 사용자 온보딩
  - 키 로테이션 자동화 도구 (승인 목록에 추가)
level: high
```

```yaml
title: AWS Persistence After Logging Impairment
id: 1e6f9b02-5d47-4c3a-88b1-postevasion00001
status: experimental
description: |
  로깅 무력화 직후 같은 주체가 지속성 확보 행위를 수행하는 침투 후 행동 순서를 탐지한다.
logsource:
  product: aws
  service: cloudtrail
detection:
  evasion:
    eventName:
      - 'DeleteTrail'
      - 'StopLogging'
      - 'DeleteFlowLogs'
      - 'PutEventSelectors'
  persistence:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'CreateAccessKey'
      - 'CreateLoginProfile'
      - 'UpdateLoginProfile'
      - 'UpdateAssumeRolePolicy'
      - 'AddUserToGroup'
      - 'AttachUserPolicy'
  condition: evasion and persistence | count() by userIdentity.arn >= 2
  timeframe: 60m
level: critical
```

### 5.3 Athena 쿼리

```sql
-- ① 호출자 ≠ 대상 인 CreateAccessKey (핵심 룰)
SELECT
    eventtime,
    useridentity.username                                        AS caller,
    json_extract_scalar(requestparameters,  '$.userName')        AS target_user,
    json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS new_key_id,
    sourceipaddress,
    useragent
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname   = 'CreateAccessKey'
  AND errorcode IS NULL
  AND json_extract_scalar(requestparameters, '$.userName') IS NOT NULL
  AND json_extract_scalar(requestparameters, '$.userName') <> useridentity.username
ORDER BY eventtime DESC;
```

```sql
-- ② 백도어 키의 사후 활동 전수 추적 (사고 대응용)
--    ①에서 얻은 new_key_id 를 그대로 넣는다
SELECT eventtime, eventsource, eventname, awsregion,
       sourceipaddress, useragent, errorcode
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIA52CDAKM4VUKRHGUR'
ORDER BY eventtime;
```

```sql
-- ③ 침투 후 행동 순서 — 로깅 무력화 + 지속성 확보를 같은 주체가 1시간 내에
SELECT
    useridentity.arn AS actor,
    sourceipaddress,
    array_agg(DISTINCT eventname ORDER BY eventname) AS actions,
    min(eventtime) AS first_at,
    max(eventtime) AS last_at,
    count(*)       AS n
FROM cloudtrail_logs
WHERE eventname IN ('DeleteTrail','StopLogging','DeleteFlowLogs','PutEventSelectors',
                    'CreateAccessKey','CreateLoginProfile','UpdateAssumeRolePolicy',
                    'AddUserToGroup','AttachUserPolicy')
  AND errorcode IS NULL
GROUP BY 1, 2
HAVING count(DISTINCT eventname) >= 2
ORDER BY n DESC;
```

### 5.4 CloudWatch Logs Insights

```
fields @timestamp, userIdentity.userName, requestParameters.userName,
       responseElements.accessKey.accessKeyId, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateAccessKey"
| filter ispresent(requestParameters.userName)
| filter requestParameters.userName != userIdentity.userName
| sort @timestamp desc
```

### 5.5 GuardDuty

이 기법에 대한 **전용 탐지는 없다.** 다만 백도어 키가 실제로 사용되기 시작하면 다음이 걸릴 수 있다.

- `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`
- `Persistence:IAMUser/AnomalousBehavior` (신규 주체의 이례적 IAM 활동)

즉 **키 생성 시점의 탐지는 직접 룰을 만들어야 한다.**

---

## 6. 오탐 주의사항

- **자기 키 갱신(`requestParameters.userName` 생략 또는 호출자와 동일)은 전부 정상이다.** 이 조건 하나로 대부분의 오탐이 사라진다.
- **IAM 관리자의 온보딩 작업.** 신입에게 키를 만들어 주는 정상 행위다. 승인된 관리자 ARN 목록이 있어야 한다.
- **자동화 파이프라인.** 키 로테이션 도구가 여러 사용자의 키를 발급한다. 해당 역할을 화이트리스트에 등록한다.
- **`CreateAccessKey` 단독 알림은 피로도가 높다.** Stratus 문서 지적대로 상관분석 없이는 실용성이 떨어진다.

---

## 7. 완화 방안

| 조치 | 내용 |
|---|---|
| **장기 액세스 키 자체를 없애기** ⭐ | IAM 사용자 대신 **IAM Identity Center(SSO)** + 역할 기반 임시 자격증명. 키가 없으면 백도어 키도 없다. 가장 근본적 |
| **SCP로 키 생성 제한** | `iam:CreateAccessKey`를 지정된 관리 역할 외에는 Deny |
| MFA 조건 강제 | IAM 쓰기 작업에 `aws:MultiFactorAuthPresent: true` 조건 요구 |
| IAM Access Analyzer | 미사용 액세스 키·역할 상시 탐지 → 잊힌 백도어 발견 |
| 키 수명 정책 | 90일 초과 키 자동 비활성화 (Config + Lambda) |
| Credential Report 정기 점검 | 계정 전체 키 목록·최종 사용일 일괄 조회 |
| 조직 트레일 + 글로벌 이벤트 | IAM 이벤트는 `us-east-1` 기록. 이 설정 없이는 탐지 자체가 불가능 |

SCP 예시:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RestrictAccessKeyCreation",
    "Effect": "Deny",
    "Action": [
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:UpdateLoginProfile"
    ],
    "Resource": "*",
    "Condition": {
      "ArnNotLike": {
        "aws:PrincipalARN": "arn:aws:iam::*:role/IdentityAdministrator"
      }
    }
  }]
}
```

---

## 8. 대응 절차 (알럿 발생 시)

1. **키를 즉시 비활성화** — 삭제보다 `Inactive` 처리가 먼저다. 삭제하면 조사 단서가 줄어든다
2. **키 ID로 사후 활동 전수 조사** — 5.3절 ② 쿼리. **이게 피해 범위 산정의 전부다**
3. **호출자(발급한 주체)도 침해로 간주** — 그 주체의 키·세션도 함께 무효화
4. **대상 사용자 점검** — 다른 키, 콘솔 비밀번호(`LoginProfile`), MFA 디바이스, 소속 그룹, 연결된 정책 전부 확인
5. **다른 지속성 흔적 수색** — `UpdateAssumeRolePolicy`(외부 계정 신뢰 추가), `CreateLoginProfile`, `AddUserToGroup`, Lambda 함수, EC2 userdata
6. **로깅 무력화 동반 여부 확인** — 5.3절 ③ 쿼리. 있었다면 로그 공백 구간을 별도 조사
7. **근본 원인 추적** — 발급 주체는 어떻게 IAM 쓰기 권한을 얻었는가

---

## 9. 참고 자료

- [Stratus Red Team — Create an Access Key on an IAM User](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-user/)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [AWS — IAM 액세스 키 모범 사례](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [AWS — Getting credential reports for your AWS account](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
