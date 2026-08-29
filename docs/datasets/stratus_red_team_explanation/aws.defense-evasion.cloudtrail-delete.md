# CloudTrail 트레일 삭제 (Delete CloudTrail Trail)

> 대상 로그: `aws.defense-evasion.cloudtrail-delete.json`
> 원본: `raw_log/` 의 CloudTrail S3 로그 파일 12개를 병합 후 시간 구간으로 분리
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.defense-evasion.cloudtrail-delete`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1562.008** — Impair Defenses: Disable or Modify Cloud Logs |
| 전술(Tactic) | Defense Evasion (방어 회피) |
| 로그 레코드 수 | **56건** |
| 시간 범위 | `2026-08-28T05:39:11Z` ~ `2026-08-28T05:43:11Z` (KST 14:39 ~ 14:43) |
| AWS 계정 | `949328302905` |
| 리전 | `ap-northeast-2` (서울) |
| 소스 IP | `165.132.5.130` |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` |
| 삭제된 트레일 | `stratus-red-team-cloudtraild-trail-rvqavyspeb` |
| **결정적 이벤트** | `cloudtrail:DeleteTrail` — `2026-08-28T05:40:28Z`, 단 1건 |

**한 줄 요약:** 감사 로그 자체를 없앤다. 공격자가 침투 후 가장 먼저 하는 일 중 하나이며, **이 로그가 남아 있다는 사실 자체가 "트레일이 하나가 아니었다"는 증거**다.

---

## 2. 공격 기법 설명

### 2.1 원리

CloudTrail은 AWS 계정의 모든 API 호출을 기록하는 감사 로그다. 공격자 입장에서 이건 **자기 행적을 실시간으로 녹화하는 CCTV**다. 그래서 초기 침투에 성공하면 이걸 먼저 끄려 한다.

`cloudtrail:DeleteTrail` API 호출 **한 번**이면 트레일이 사라지고, 그 시점부터 해당 트레일은 아무것도 기록하지 않는다.

### 2.2 로깅을 무력화하는 4가지 방법

`DeleteTrail`은 그중 가장 시끄러운 방법이다. 실제 공격자는 더 조용한 쪽을 고르는 경우가 많다.

| API | 효과 | 은밀성 | 비고 |
|---|---|---|---|
| **`DeleteTrail`** | 트레일 완전 삭제 | 낮음 | 콘솔에서 트레일이 사라져 바로 눈에 띔 ← **이 로그** |
| `StopLogging` | 기록만 중단, 트레일은 남음 | **높음** | 콘솔 목록에 그대로 보여서 "잘 돌아가는 줄" 착각하기 쉬움 |
| `PutEventSelectors` | 셀렉터를 축소해 특정 이벤트만 제외 | **매우 높음** | 트레일도 살아있고 로깅도 "켜짐"인데 원하는 이벤트만 안 남음 |
| `UpdateTrail` | 로그 전송 대상 S3 버킷을 공격자 버킷으로 변경 | 높음 | 로그는 계속 쌓이지만 피해자가 볼 수 없음 |

**탐지 룰을 짤 때는 이 4개를 한 묶음으로 봐야 한다.** `DeleteTrail`만 감시하면 나머지 3개는 그대로 통과한다.

### 2.3 왜 위험한가 — 순환 문제

이 기법에는 다른 공격에 없는 구조적 딜레마가 있다.

```
로그 삭제를 탐지하려면 → 로그가 필요하다
그런데 공격자가 지운 게 바로 그 로그다
```

트레일이 **하나뿐인 계정**에서는 `DeleteTrail` 호출 자체는 기록되지만(삭제 직전까지는 살아 있으므로), **그 이후의 모든 활동은 흔적이 없다.** 공격자는 이 시점부터 자유롭게 움직인다.

이 로그가 그 해법을 그대로 보여준다. 아래 4.2절 참고.

### 2.4 실제 공격에서의 위치

```
① 자격증명 탈취 / 초기 침투
        │
        ▼
② 【이 기법】 CloudTrail 무력화 ← 여기서 관측 실패하면 이후는 전부 암흑
        │
        ▼
③ 자유로운 정찰 · 권한 상승 · 지속성 확보 · 데이터 유출
```

같은 폴더의 `aws.persistence.iam-backdoor-user`(지속성 확보)와 조합하면, "로그를 끄고 → 백도어 키를 심는" 전형적인 침투 후 행동 순서가 된다. 실제로 이번 실험은 그 순서로 실행됐다.

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. S3 버킷 `stratus-red-team-cloudtraild-bucket-rvqavyspeb` 생성 및 버킷 정책 설정
2. **자기 전용 트레일** `stratus-red-team-cloudtraild-trail-rvqavyspeb` 생성 (`isMultiRegionTrail: false`, 로그 파일 검증 비활성)
3. `StartLogging` 으로 기록 시작

### Detonation
4. **`cloudtrail:DeleteTrail`** 로 방금 만든 트레일 삭제

### Cleanup
5. S3 버킷 삭제 (`BucketNotEmpty` 오류 후 재시도 성공)

> ✅ **안전 확인:** Stratus는 **자기가 만든 트레일만** 지운다. 연구용 트레일 `stratus`(계정 루트가 콘솔에서 생성, 다중 리전)는 그대로 살아 있었고, 그래서 이 로그가 남았다. 다만 이름이 `stratus` vs `stratus-red-team-cloudtraild-trail-...` 로 접두사가 겹치므로, 앞으로도 헷갈리지 않게 연구용 트레일 이름은 확실히 구분되는 것으로 쓰는 편이 안전하다.

---

## 4. 로그 타임라인 분석

### 4.1 단계별 흐름

| 시각 (UTC) | 이벤트 | 주체 / UA | 의미 |
|---|---|---|---|
| 05:39:11 | `notifications:ListManagedNotificationEvents` | 콘솔 (Root) | ⚪ 배경 노이즈 (콘솔 열어둔 상태) |
| **05:39:49** | `ec2:DescribeAccountAttributes` | **stratus-red-team_a45e0a2b** | 🔴 Stratus 도구 기동 (AWS 연결 확인) |
| 05:40:07~09 | `iam:GetUser` ×2 | Terraform | 🟡 Warm-up 시작 |
| 05:40:10~12 | `s3:CreateBucket`, `PutBucketPolicy`, `PutBucketTagging`, `GetBucket*` 다수 | Terraform | 🟡 트레일용 S3 버킷 준비 |
| **05:40:12** | **`cloudtrail:CreateTrail`** | Terraform | 🟡 희생될 트레일 생성 |
| **05:40:12** | **`cloudtrail:StartLogging`** | Terraform | 🟡 기록 시작 |
| 05:40:13 | `GetTrailStatus`, `GetEventSelectors`, `ListTags`, `DescribeTrails` | Terraform | 🟡 상태 확인 |
| 05:40:28 | `ec2:DescribeAccountAttributes` | stratus-red-team_ad9c30e4 | 🔴 detonate 직전 확인 |
| **05:40:28** | **`cloudtrail:DeleteTrail`** | **stratus-red-team_057911ed** | 🔴🔴 **공격 실행** |
| 05:40:41~45 | `GetBucket*`, `DeleteBucket` ×2 (1회 `BucketNotEmpty`) | Terraform | 🟡 Cleanup |
| 05:41:43~53 | `s3:GetBucketAcl`, `DescribeTrails`, `GetBucketLogging`(`NoSuchBucket`) | CloudTrail 서비스 / Resource Explorer | ⚪ 삭제된 리소스를 뒤늦게 조회한 결과 |
| 05:43:11 | `notifications:ListManagedNotificationEvents` | 콘솔 | ⚪ 배경 노이즈 |

### 4.2 ⭐ 이 로그의 핵심 — 트레일의 수명은 16초였다

```
05:40:12Z  StartLogging   ← 트레일 기록 시작
05:40:28Z  DeleteTrail    ← 16초 뒤 삭제
```

**삭제된 트레일 `stratus-red-team-cloudtraild-trail-rvqavyspeb`는 자기 자신의 죽음을 기록하지 못했다.** CloudTrail은 이벤트를 S3에 전달하기까지 보통 5~15분이 걸리므로, 16초짜리 트레일은 아무것도 배달하지 못하고 사라졌다.

**그럼 이 `DeleteTrail` 이벤트는 누가 기록했나?** 계정에 별도로 존재하던 **연구용 다중 리전 트레일 `stratus`**다. 즉,

> **트레일이 하나뿐이었다면 이 공격은 로그에 남지 않았다.**

이게 이 기법의 실무적 교훈 전부다. 탐지 룰보다 **아키텍처(트레일을 몇 개, 어디에 두는가)가 먼저**다.

### 4.3 결정적 이벤트 — `DeleteTrail` 레코드

```json
{
  "eventTime": "2026-08-28T05:40:28Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "DeleteTrail",
  "awsRegion": "ap-northeast-2",
  "sourceIPAddress": "165.132.5.130",
  "userAgent": "stratus-red-team_057911ed-6840-4cb9-b084-9e3c3d9a2e3b",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::949328302905:user/Huge-log-attack-simulation",
    "accessKeyId": "AKIA52CDAKM4W5UHPSX2"
  },
  "requestParameters": { "name": "stratus-red-team-cloudtraild-trail-rvqavyspeb" },
  "responseElements": null,
  "eventCategory": "Management",
  "managementEvent": true,
  "readOnly": false
}
```

**보아야 할 것은 두 가지뿐이다.**

1. `requestParameters.name` → **어떤 트레일이 지워졌는가.** 이 값이 조직의 주 감사 트레일이면 즉시 최고 등급 사고다.
2. `userIdentity` → 이 주체가 CloudTrail을 관리할 정당한 이유가 있는가. 대부분의 계정에서 `DeleteTrail`을 호출할 사람은 **극소수**다.

`responseElements`가 `null`인 점도 알아두면 좋다. 삭제 API는 반환값이 없어서, **성공 여부는 `errorCode` 부재로만 판단**한다.

### 4.4 시그널 vs 노이즈

| 구분 | 건수 | 비율 | 판별 기준 |
|---|---|---|---|
| 🔴 **공격 (`DeleteTrail`)** | **1** | **1.8%** | UA `stratus-red-team_057911ed` |
| 🔴 공격 도구 부수 호출 (`DescribeAccountAttributes`) | 2 | 3.6% | UA `stratus-red-team_<uuid>` |
| 🟡 Warm-up / Cleanup (Terraform) | 43 | 76.8% | UA `terraform-provider-aws` |
| ⚪ AWS 서비스 이벤트 | 7 | 12.5% | `cloudtrail.amazonaws.com`, `resource-explorer-2` |
| ⚪ 콘솔 배경 노이즈 | 3 | 5.4% | `Mozilla/5.0 ... Chrome` |

오류 이벤트는 13건이며 전부 Terraform이 S3 버킷 속성을 조회하다 "설정 없음"으로 받은 정상 응답(`NoSuchTagSet`, `NoSuchCORSConfiguration`, `NoSuchWebsiteConfiguration`, `NoSuchLifecycleConfiguration`, `ReplicationConfigurationNotFoundError`, `ObjectLockConfigurationNotFoundError`)과 `BucketNotEmpty` 재시도다. 공격과 무관하다.

**56건 중 알림을 울려야 하는 건 1건이다.** 앞선 세 시나리오(1~4%)보다도 신호가 희박하다. 이 기법을 그래프/시퀀스 분석 데이터로 쓸 때는, **단일 이벤트를 어떻게 맥락과 연결할 것인가**가 문제의 본질이 된다.

> 참고: 이번 수집은 트레일 설정이 **관리 이벤트 전용**(`advancedEventSelectors`에 Management만)이라 전 레코드가 `eventCategory: "Management"`다. 데이터 이벤트는 0건이며, 이 기법에는 애초에 필요 없다.

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 | 비고 |
|---|---|---|
| **최상** | `DeleteTrail` / `StopLogging` / `UpdateTrail` / `PutEventSelectors` **4종 묶음 감시** | 하나만 보면 나머지로 우회당함 |
| **최상** | 대상 트레일이 **조직의 주 감사 트레일**인가 | 트레일 ARN 화이트리스트 필요 |
| 상 | 호출 주체가 CloudTrail 관리 권한을 가질 이유가 없는 경우 | 대부분 계정에서 정당한 호출자는 소수 |
| 상 | `DeleteTrail` 직후 다른 계정 활동이 이어지는가 | 로그 무력화 → 본 공격 패턴 |
| 중 | S3 로그 버킷에 대한 `DeleteBucket` / `PutBucketPolicy` / `PutLifecycleConfiguration` | 트레일은 살려두고 로그 저장소를 죽이는 우회 |
| 중 | `cloudtrail:DeleteEventDataStore` (CloudTrail Lake 사용 시) | 같은 목적의 다른 API |

### 5.2 GuardDuty

이 기법은 GuardDuty가 **기본으로 잡는 몇 안 되는 케이스**다.

- **`Stealth:IAMUser/CloudTrailLoggingDisabled`** — 트레일이 비활성화·삭제되었을 때 발생

CloudTrail 로그 파이프라인이 무력화된 상황에서도 GuardDuty는 별도 경로로 동작하므로, **이 기법에 한해서는 GuardDuty가 CloudTrail보다 신뢰도 높은 탐지 수단**이다.

### 5.3 Sigma 룰

```yaml
title: CloudTrail Logging Impaired
id: 2f4b8c19-7d63-4a02-9e51-cttamper0000001
status: stable
description: |
  CloudTrail 트레일의 삭제·중지·설정 변경을 탐지한다.
  DeleteTrail 단독이 아니라 로깅 무력화 4종을 함께 감시한다.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'DeleteTrail'
      - 'StopLogging'
      - 'UpdateTrail'
      - 'PutEventSelectors'
      - 'DeleteEventDataStore'
  filter_errors:
    errorCode|exists: true
  condition: selection and not filter_errors
falsepositives:
  - IaC(Terraform/CloudFormation)를 통한 정상적인 트레일 재구성
    → userAgent 가 terraform-provider-aws 이고 승인된 파이프라인 역할일 때만 제외할 것
  - 테스트/샌드박스 계정의 실습 트레일 정리
level: critical
```

```yaml
title: CloudTrail Log Bucket Tampering
id: c81a3f5d-9e02-4b77-a6d3-ctbuckettamper01
status: experimental
description: CloudTrail 로그가 저장된 S3 버킷 자체를 무력화하는 시도
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'DeleteBucket'
      - 'PutBucketPolicy'
      - 'PutBucketVersioning'
      - 'PutLifecycleConfiguration'
      - 'DeleteBucketPolicy'
  # 로그 버킷 이름 패턴은 환경에 맞게
  logbucket:
    requestParameters.bucketName|contains: 'cloudtrail-logs'
  condition: selection and logbucket
level: high
```

### 5.4 Athena 쿼리

```sql
-- 로깅 무력화 시도 전수 조사
SELECT
    eventtime,
    eventname,
    useridentity.arn                                  AS actor,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.name')  AS trail_name,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 'cloudtrail.amazonaws.com'
  AND eventname IN ('DeleteTrail','StopLogging','UpdateTrail',
                    'PutEventSelectors','DeleteEventDataStore')
ORDER BY eventtime DESC;
```

```sql
-- DeleteTrail 이후 같은 주체가 무엇을 했는가 (사후 활동 추적)
WITH kill AS (
    SELECT useridentity.arn AS actor, eventtime AS killed_at
    FROM cloudtrail_logs
    WHERE eventname IN ('DeleteTrail','StopLogging') AND errorcode IS NULL
)
SELECT k.actor, k.killed_at, c.eventtime, c.eventsource, c.eventname
FROM kill k
JOIN cloudtrail_logs c ON c.useridentity.arn = k.actor
WHERE c.eventtime > k.killed_at
  AND date_diff('hour', from_iso8601_timestamp(k.killed_at),
                        from_iso8601_timestamp(c.eventtime)) <= 24
  AND c.readonly = false
ORDER BY c.eventtime;
```

### 5.5 EventBridge 실시간 룰 (권장)

CloudTrail → S3 → Athena 경로는 **5~15분 지연**이 있다. 로깅이 꺼진 시점부터 그 지연 시간만큼은 사각지대다. EventBridge로 실시간 대응하는 편이 훨씬 낫다.

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": ["DeleteTrail", "StopLogging", "UpdateTrail", "PutEventSelectors"]
  }
}
```

→ 대상을 SNS/Lambda로 걸어 **즉시 알림 + 트레일 자동 복구**까지 구성할 수 있다.

---

## 6. 오탐 주의사항

- **IaC 파이프라인이 트레일을 재생성한다.** Terraform이 `DeleteTrail` → `CreateTrail`을 연속 수행하는 것은 정상 배포일 수 있다. 이 로그가 정확히 그 모양이다. **승인된 배포 역할 + `CreateTrail`이 곧바로 뒤따르는지**로 구분한다.
- **`PutEventSelectors`는 정상 운영에서도 흔하다.** 셀렉터를 넓히는 변경(데이터 이벤트 추가)은 정상이고, **좁히는 변경**이 의심스럽다. 변경 전후 셀렉터를 비교해야 의미가 있다.
- **다중 리전 트레일은 리전마다 이벤트가 보일 수 있다.** 중복 알림 방지 로직 필요.

---

## 7. 완화 방안

| 조치 | 내용 |
|---|---|
| **조직 트레일(Organization Trail)** ⭐ | 관리 계정에서 생성. 멤버 계정에서는 **삭제·변경이 불가능**하다. 이 기법에 대한 가장 확실한 방어 |
| **트레일 이중화** | 최소 2개(리전 트레일 + 조직 트레일). 이번 실험에서 로그가 남은 이유가 정확히 이것 |
| **로그 버킷을 별도 계정에** | 침해된 계정의 권한으로 로그 저장소에 손대지 못하게 분리 |
| SCP로 CloudTrail 변경 차단 | `cloudtrail:DeleteTrail`, `StopLogging`, `UpdateTrail`, `PutEventSelectors` 를 Deny |
| S3 Object Lock / MFA Delete | 이미 쌓인 로그 파일의 삭제 방지 |
| 로그 파일 검증(`enableLogFileValidation`) | 로그 변조 탐지. 참고로 Stratus가 만든 트레일은 이 옵션이 꺼져 있었다 |
| CloudTrail Lake | 별도 저장소에 불변 보관 |
| GuardDuty 활성화 | CloudTrail 파이프라인과 독립적인 탐지 경로 |

SCP 예시:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProtectAuditTrail",
    "Effect": "Deny",
    "Action": [
      "cloudtrail:DeleteTrail",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:DeleteEventDataStore"
    ],
    "Resource": "*",
    "Condition": {
      "ArnNotLike": {
        "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityBreakGlassRole"
      }
    }
  }]
}
```

---

## 8. 대응 절차 (알럿 발생 시)

1. **어떤 트레일인가 확인** — `requestParameters.name`. 주 감사 트레일이면 최고 등급
2. **즉시 재생성** — 백업 IaC 정의로 트레일 복구, `StartLogging` 확인
3. **로그 공백 구간 산정** — 삭제 시점부터 복구 시점까지가 사각지대. 그 구간은 **CloudTrail로 조사 불가**
4. **대체 데이터로 공백 메우기** — GuardDuty findings, VPC Flow Logs, S3 서버 액세스 로그, Config 이력, 요금 청구 이상치
5. **호출 주체 격리** — 해당 IAM 주체의 액세스 키 비활성화, 세션 무효화
6. **사후 활동 추적** — 5.4절 두 번째 쿼리로 같은 주체의 24시간 활동 전수 조사
7. **아키텍처 개선** — 트레일이 하나였다면 조직 트레일 도입을 사고 후속 조치로 등록

---

## 9. 참고 자료

- [Stratus Red Team — Delete CloudTrail Trail](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-delete/)
- [MITRE ATT&CK T1562.008 — Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [AWS GuardDuty — Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [AWS — Creating a trail for an organization](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
- [AWS — Validating CloudTrail log file integrity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
