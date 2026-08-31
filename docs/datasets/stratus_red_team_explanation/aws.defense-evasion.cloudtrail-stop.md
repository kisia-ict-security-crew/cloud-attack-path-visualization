# CloudTrail 로깅 중지 (Stop CloudTrail Trail)

> 대상 로그: `aws.defense-evasion.cloudtrail-stop.json`
> 원본: `raw_log/` 병합 후 시간 구간으로 분리
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.defense-evasion.cloudtrail-stop`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1562.008** — Impair Defenses: Disable or Modify Cloud Logs |
| 전술 | Defense Evasion (방어 회피) |
| 로그 레코드 수 | 39건 |
| 시간 범위 | `05:33:30Z` ~ `05:37:06Z` (KST 14:33~14:37) |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` |
| 중지된 트레일 | `stratus-red-team-ct-stop-trail-kgzjomghdb` (Stratus가 만든 자기 트레일) |
| **결정적 이벤트** | `cloudtrail:StopLogging` — `05:34:05Z`, 단 1건 |

**한 줄 요약:** 트레일을 **삭제하지 않고 기록만 중지**한다. `cloudtrail-delete`보다 은밀하다 — 콘솔 트레일 목록에는 그대로 보여서 "정상 작동 중"으로 착각하기 쉽다.

---

## 2. 공격 기법 설명

### 2.1 `DeleteTrail` vs `StopLogging`

같은 T1562.008이지만 은밀성이 다르다.

| | `cloudtrail-delete` (`DeleteTrail`) | **`cloudtrail-stop` (`StopLogging`)** |
|---|---|---|
| 트레일 | **삭제됨** — 콘솔 목록에서 사라짐 | **남아있음** — 목록에 그대로 보임 |
| 착시 | 없어진 게 바로 보임 | **"켜져 있는 것처럼" 보임** — 상태만 `Stopped` |
| 복구 | 재생성 필요 | `StartLogging` 한 번이면 재개 |
| 발각 난이도 | 낮음 | **높음** — 상태를 직접 확인해야 함 |
| GuardDuty | `Stealth:IAMUser/CloudTrailLoggingDisabled` | **동일하게 탐지됨** |

실제 공격자가 `DeleteTrail`보다 `StopLogging`을 선호하는 이유가 이 "정상처럼 보임"이다. 그래서 **트레일 존재 여부만 보는 감사는 이 기법을 놓친다.** `IsLogging` 상태를 직접 확인해야 한다.

### 2.2 순환 문제 (cloudtrail-delete와 동일)

로깅이 중지되면 그 트레일은 **자기 중지 이후를 기록하지 못한다.** 트레일이 하나뿐이면 `StopLogging` 이후 공격 활동이 전부 사각지대에 들어간다. 탐지의 전제는 **트레일 이중화**다.

### 2.3 킬체인에서의 위치

옵션 2 체인의 **Defense Evasion 단계**. Admin 백도어(앞 단계)를 심은 뒤 로깅을 꺼서, 이후 임팩트(랜섬웨어 등) 활동을 감춘다.

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. S3 버킷 `stratus-red-team-ct-stop-bucket-kgzjomghdb` 생성
2. **자기 트레일** `stratus-red-team-ct-stop-trail-kgzjomghdb` 생성 + `StartLogging`

### Detonation
3. **`cloudtrail:StopLogging`** 으로 그 트레일 기록 중지

> ✅ **안전 확인:** `StopLogging`은 **Stratus가 만든 트레일**만 껐다. 사용자의 연구용 트레일은 계속 동작했고(로그가 `05:37`까지 이어짐), 그 덕에 이 `StopLogging` 이벤트가 기록됐다.

---

## 4. 로그 타임라인 분석

### 4.1 주요 흐름

| 시각 (UTC) | 이벤트 | 주체/UA | 의미 |
|---|---|---|---|
| 05:33:30 | `ec2:DescribeAccountAttributes` | stratus | 🔴 도구 기동 |
| 05:34:00~03 | `s3:CreateBucket`, `PutBucketPolicy`, `GetBucket*` | Terraform | 🟡 트레일용 버킷 준비 |
| **05:34:03** | **`cloudtrail:CreateTrail`** (`ct-stop-trail-...`) | Terraform | 🟡 희생될 트레일 생성 |
| **05:34:03** | **`cloudtrail:StartLogging`** | Terraform | 🟡 기록 시작 |
| 05:34:04 | `GetEventSelectors`, `GetTrailStatus`, `ListTags` | Terraform | 🟡 상태 확인 |
| **05:34:05** | **`cloudtrail:StopLogging`** | **stratus** | 🔴🔴 **공격 실행** |
| 05:34:09~05:37:06 | `resource-explorer-2`, `ssm-agent`, `notifications` 등 | AWS 서비스/콘솔 | ⚪ 배경 노이즈 (연구 트레일이 계속 기록 중이라는 증거) |

### 4.2 이 로그의 핵심 — 트레일 수명 2초

```
05:34:03Z  StartLogging   ← 기록 시작
05:34:05Z  StopLogging    ← 2초 뒤 중지
```

`cloudtrail-delete`(수명 16초)와 마찬가지로, 대상 트레일은 **자기 중지를 기록하지 못했다.** 이 `StopLogging`을 남긴 건 별도의 연구용 트레일이다. 교훈은 동일하다: **트레일이 하나였다면 이 공격은 로그에 없다.**

### 4.3 결정적 이벤트

```json
{
  "eventTime": "2026-08-31T05:34:05Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "ap-northeast-2",
  "userAgent": "stratus-red-team_...",
  "userIdentity": { "type": "IAMUser", "userName": "Huge-log-attack-simulation" },
  "requestParameters": { "name": "stratus-red-team-ct-stop-trail-kgzjomghdb" },
  "responseElements": null,
  "readOnly": false
}
```

`requestParameters.name`이 **어떤 트레일이 꺼졌는지**를 말해준다. 이 값이 조직의 주 감사 트레일이면 즉시 최고 등급 사고다. `responseElements`가 `null`이라 성공 여부는 `errorCode` 부재로만 판단한다.

### 4.4 시그널 vs 노이즈

| 구분 | 건수 | 비율 | 판별 |
|---|---|---|---|
| 🔴 공격 (`StopLogging`) | 1 | 2.6% | UA `stratus-red-team` |
| 🔴 도구 기동 (`DescribeAccountAttributes`) | 1 | 2.6% | UA `stratus-red-team` |
| 🟡 Warm-up (Terraform) | 25 | 64.1% | UA `terraform-provider-aws` |
| ⚪ AWS 서비스 이벤트 | 8 | 20.5% | `resource-explorer-2` 등 |
| ⚪ SSM/콘솔 노이즈 | 4 | 10.3% | `ssm-agent`, `Mozilla` |

오류 6건은 전부 S3 버킷 속성 조회의 정상 "설정 없음" 응답(`NoSuchCORS` 등). 공격 무관.

---

## 5. 탐지

### 5.1 Sigma 룰 (로깅 무력화 4종 묶음)

```yaml
title: CloudTrail Logging Stopped Or Impaired
id: dd77ee88-cloudtrail-stop-0001
status: stable
logsource: { product: aws, service: cloudtrail }
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: ['StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors']
  filter: { errorCode|exists: true }
  condition: selection and not filter
falsepositives:
  - IaC 를 통한 트레일 재구성 (직후 StartLogging 이 따라옴, 승인된 역할)
level: critical
```

### 5.2 Athena 쿼리

```sql
SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress,
       json_extract_scalar(requestparameters, '$.name') AS trail
FROM cloudtrail_logs
WHERE eventsource = 'cloudtrail.amazonaws.com'
  AND eventname IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors')
ORDER BY eventtime DESC;
```

### 5.3 AWS Config (상태 기반 — StopLogging에 특히 유효)
`cloudtrail-enabled` 룰이 **"현재 로깅이 꺼져 있는 상태"**를 상시 감시한다. `StopLogging`은 트레일이 남아 있어 존재 여부 검사로는 안 잡히므로, 이 상태 기반 검사가 핵심이다. 위반 시 SSM Automation으로 자동 `StartLogging`.

### 5.4 EventBridge 실시간 대응
```json
{ "source": ["aws.cloudtrail"],
  "detail": { "eventSource": ["cloudtrail.amazonaws.com"],
              "eventName": ["StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors"] } }
```
→ Lambda로 즉시 재개 + 알림.

---

## 6. 완화 방안

| 조치 | 내용 |
|---|---|
| **조직 트레일(Organization Trail)** ⭐ | 멤버 계정에서 중지·변경 불가 |
| 트레일 이중화 | 최소 2개 (이번에 로그가 남은 이유) |
| SCP로 `StopLogging` 차단 | 보안 역할 외 Deny |
| AWS Config `cloudtrail-enabled` | 상태 기반 상시 감시 + 자동 교정 |
| GuardDuty | CloudTrail과 독립적 탐지 경로 |

---

## 7. 참고 자료

- [Stratus Red Team — Stop CloudTrail Trail](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/)
- [MITRE ATT&CK T1562.008 — Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [AWS Config — cloudtrail-enabled](https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html)
