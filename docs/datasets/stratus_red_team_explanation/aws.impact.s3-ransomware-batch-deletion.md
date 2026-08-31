# S3 랜섬웨어 — 배치 파일 삭제 (S3 Ransomware through batch file deletion)

> 대상 로그: `aws.impact.s3-ransomware-batch-deletion.json`
> 원본: `raw_log/` 병합 (단일 기법 실행)
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.impact.s3-ransomware-batch-deletion`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1486** — Data Encrypted for Impact (삭제형 랜섬웨어) |
| 전술 | Impact (임팩트) |
| 로그 레코드 수 | 300건 (**데이터 이벤트 269 / 관리 이벤트 31**) |
| 시간 범위 | `06:01:41Z` ~ `06:15:14Z` (KST 15:01~15:15) |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` (키 `AKIA52CDAKM4W5UHPSX2`) |
| 대상 버킷 | `stratus-red-team-ransomware-bucket-wlcudc` |
| **결정적 이벤트** | `s3:DeleteObjects` (배치) — `06:08:38Z`, 데이터 이벤트 |

**한 줄 요약:** SSE-C 암호화형이 계정 정책에 막혀서 **삭제형**으로 대체한 버전. 버킷의 모든 객체를 열거해 한 번의 `DeleteObjects` 배치 호출로 지운다. **이 공격은 데이터 이벤트를 켜야만 보인다** — 관리 이벤트만으론 `CreateBucket`/`DeleteBucket` 정도밖에 안 남는다.

---

## 2. 공격 기법 설명

### 2.1 원리 — "암호화" 없는 랜섬웨어

랜섬웨어의 본질은 "데이터를 접근 불가로 만들고 대가를 요구"하는 것이다. 반드시 암호화일 필요는 없다. 이 기법은 **삭제**로 같은 효과를 낸다.

```
s3:ListObjects / ListObjectVersions   → 버킷의 모든 객체 열거
s3:DeleteObjects (배치)                → 한 호출로 다수 객체 삭제
(+ 랜섬노트를 남기는 변형도 있음)
```

암호화형(`client-side-encryption`)과 비교:

| | 암호화형 (SSE-C) | **삭제형 (batch-deletion)** |
|---|---|---|
| 방식 | 공격자 키로 재암호화 → 복호화 대가 요구 | 삭제 → 백업 없으면 복구 대가 요구 |
| 핵심 이벤트 | `CopyObject` (SSE-C 헤더) | **`DeleteObjects`** |
| 환경 의존 | SSE-C 허용 필요 (이번에 **차단됨**) | 없음 — 어디서나 동작 |
| 복구 가능성 | 키 없으면 불가 | **버전 관리/백업 있으면 가능** |

> 이번 실험에서 암호화형은 `AccessDenied: bucket has blocked ... SSE-C`로 막혀서 삭제형으로 전환했다. 삭제형은 SSE-C에 의존하지 않아 그 통제를 우회한다.

### 2.2 버전 관리가 방어의 급소

이번 대상 버킷은 **버전 관리(versioning)가 켜져** 있었다(`PutBucketVersioning`). 버전 관리가 켜진 버킷에서 `DeleteObjects`는 객체를 진짜 지우는 대신 **삭제 마커(delete marker)**를 붙인다. 즉 이전 버전이 남아 있어 **복구가 가능**하다.

그래서 실제 공격자는 삭제 전에 `s3:PutBucketVersioning`으로 버전 관리를 끄거나, 버전까지 명시적으로 지운다. **탐지·방어의 핵심 포인트가 여기 있다** (5절).

### 2.3 킬체인에서의 위치

옵션 2 체인의 **Impact 단계**(최종). 앞 단계(정찰→백도어→로그 차단)를 거친 뒤, 데이터를 인질로 잡아 마무리한다.

> 이번엔 standalone 실행이라 공격 주체가 원래 IAM 사용자(`AKIA52CDAKM4W5UHPSX2`)다. **실제 체인에서는 훔친 크리덴셜로 이 삭제를 실행**해야 크리덴셜 스파인에 연결된다.

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up (Terraform)
1. `CreateBucket` → `stratus-red-team-ransomware-bucket-wlcudc`
2. `PutBucketVersioning` (버전 관리 ON)
3. `PutObject` ×약 50 — 무작위 내용·확장자 파일 업로드

### Detonation (06:08:37~38, 전부 stratus UA)
4. `ListObjectVersions` — 객체 전수 열거
5. 각 객체 `GetObject`/`HeadObject`/`GetObjectTagging` (51건씩) — 대상 확인
6. `DeleteObject` ×51 + **`DeleteObjects` 배치 1건** — 삭제 실행

### Cleanup
7. 버킷·잔여 버전 정리

---

## 4. 로그 타임라인 분석

### 4.1 데이터 이벤트 구성 (269건)

| 이벤트 | 건수 | 성격 |
|---|---|---|
| `PutObject` | 59 | 🟡 Warm-up 업로드(TF 51) + CloudTrail 로그배달(ct-svc 7) + 1 |
| `GetObject` | 51 | 🔴 삭제 전 각 객체 읽기 (stratus) |
| `HeadObject` | 51 | 🔴 각 객체 메타데이터 확인 (stratus) |
| `GetObjectTagging` | 51 | 🔴 각 객체 태그 확인 (stratus) |
| `DeleteObject` | 51 | 🔴 개별 삭제 (stratus) |
| `ListObjects`/`ListObjectVersions` | 3 | 🔴 열거 |
| **`DeleteObjects`** | **1** | 🔴🔴 **배치 삭제 (핵심)** |
| `HeadBucket` | 2 | 🟡 |

### 4.2 결정적 이벤트 — 배치 삭제

```json
{
  "eventTime": "2026-08-31T06:08:38Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObjects",
  "eventCategory": "Data",              // ← 데이터 이벤트 (관리 이벤트 켜기만 하면 안 보임)
  "managementEvent": false,
  "userAgent": "[stratus-red-team_...]",
  "userIdentity": { "type": "IAMUser", "accessKeyId": "AKIA52CDAKM4W5UHPSX2" },
  "requestParameters": {
    "bucketName": "stratus-red-team-ransomware-bucket-wlcudc",
    "delete": "",
    "x-id": "DeleteObjects"             // ← 배치 삭제 시그니처
  },
  "resources": [
    { "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::stratus-red-team-ransomware-bucket-wlcudc" }
  ]
}
```

**볼 것:**
- `eventCategory: "Data"` — 이 한 줄이 이 실습의 이유다. 데이터 이벤트를 안 켰다면 이 레코드는 존재하지 않는다.
- `resources[].ARN` — 대상 버킷이 정규 ARN으로 찍혀 있어, 그래프에서 `Event -TARGETS-> bucket` 엣지가 바로 만들어진다.
- `x-id: DeleteObjects` — 배치 삭제 API 식별자.

### 4.3 그래프 관점

```
Actor(IAMUser, AKIA52CDAKM4W5UHPSX2)
   └─PERFORMED─ DeleteObjects ─TARGETS─▶ bucket(stratus-red-team-ransomware-bucket-wlcudc)
   └─PERFORMED─ DeleteObject ×51 ─TARGETS─▶ (동일 버킷/객체)
```

standalone이라 지금은 Actor(원래 IAM 사용자)에 매달린다. **체인에서 훔친 크리덴셜로 실행하면** 이 `DeleteObjects` 노드가 크리덴셜 스파인 끝에 붙어 "정찰→백도어→회피→임팩트" 경로가 완성된다.

### 4.4 ⚠️ 노이즈 — CloudTrail 로그 버킷

데이터 이벤트를 **전체 S3**로 켰기 때문에, 예고한 대로 CloudTrail이 자기 로그를 저장하는 버킷에 대한 이벤트도 섞였다.

```
261건 → stratus-red-team-ransomware-bucket-wlcudc   (공격 대상, 진짜 신호)
  8건 → aws-cloudtrail-logs-949328302905-16b80b5b    (로그 배달, 노이즈)
```

분석·그래프 변환 시 **버킷명이 `aws-cloudtrail-logs-*`인 데이터 이벤트는 필터링**하면 된다. 실제 탐지 룰에서도 로그 버킷은 화이트리스트로 빼야 오탐이 줄어든다.

### 4.5 시그널 vs 노이즈

| 구분 | 건수(대략) | 판별 |
|---|---|---|
| 🔴 삭제 공격 (`DeleteObjects`,`DeleteObject`,`List*`,`GetObject` 등, stratus) | ~157 | UA `stratus-red-team`, 대상 버킷 |
| 🟡 Warm-up 업로드 (`PutObject`, TF) | ~51 | UA `terraform-provider-aws` |
| ⚪ CloudTrail 로그 배달 (`PutObject`, ct-svc) | 7~8 | 버킷명 `aws-cloudtrail-logs-*` |
| ⚪ 관리 이벤트/배경 | ~31 | `GetBucket*`, `notifications` 등 |

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 |
|---|---|
| **최상** | 짧은 시간에 **대량 `DeleteObject`/`DeleteObjects`** (한 주체·한 버킷) |
| **최상** | `PutBucketVersioning`(끄기) 또는 `DeleteBucketLifecycle` 직후 대량 삭제 — 복구 무력화 정황 |
| 상 | `DeleteObjects` 호출 주체가 평소 그 버킷을 삭제하지 않던 경우 |
| 상 | 대량 삭제 + 랜섬노트로 보이는 `PutObject`(예: `ransom`, `README`, `RECOVER`) |
| 중 | S3 `NumberOfObjects` CloudWatch 지표 급락 |

### 5.2 Sigma 룰

```yaml
title: S3 Mass Object Deletion (Ransomware)
id: ff88aa11-s3-batch-delete-0001
status: experimental
logsource: { product: aws, service: cloudtrail }
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: ['DeleteObjects', 'DeleteObject']
  filter_logbucket:
    requestParameters.bucketName|startswith: 'aws-cloudtrail-logs-'
  condition: selection and not filter_logbucket
             | count() by userIdentity.arn, requestParameters.bucketName > 50
  timeframe: 5m
falsepositives:
  - 라이프사이클 정책의 정상 대량 만료
  - 배치 작업/ETL 정리 (승인된 역할 화이트리스트)
level: high
```

```yaml
title: S3 Versioning Disabled Before Deletion
id: ff88aa11-s3-versioning-off-0002
status: experimental
logsource: { product: aws, service: cloudtrail }
detection:
  sel:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketVersioning'
    requestParameters.VersioningConfiguration.Status: 'Suspended'
  condition: sel
level: high
```

### 5.3 Athena 쿼리

```sql
-- 버킷별 대량 삭제 (로그 버킷 제외)
SELECT useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
       count(*) AS delete_calls,
       min(eventtime) AS first_at, max(eventtime) AS last_at
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('DeleteObject','DeleteObjects')
  AND json_extract_scalar(requestparameters, '$.bucketName') NOT LIKE 'aws-cloudtrail-logs-%'
GROUP BY 1,2
HAVING count(*) > 50
ORDER BY delete_calls DESC;
```

### 5.4 GuardDuty
- `Impact:S3/MaliciousIPCaller` / `Impact:S3/AnomalousBehavior.Delete`
- `Exfiltration:S3/AnomalousBehavior`

---

## 6. 완화 방안

| 조치 | 내용 |
|---|---|
| **버전 관리 + MFA Delete** ⭐ | 삭제해도 이전 버전 복구 가능. MFA Delete면 버전 삭제에 MFA 필요 |
| **S3 Object Lock (WORM)** | 보존 기간 동안 삭제 자체가 불가 — 랜섬웨어 방어의 최강 수단 |
| 별도 계정 백업 / 복제 | 침해 계정 권한으로 못 지우는 곳에 사본 |
| SCP로 `DeleteObjects`·`PutBucketVersioning` 제한 | 지정 역할 외 Deny |
| 라이프사이클로 버전 보존 | 실수/공격 삭제 후에도 일정 기간 버전 유지 |
| GuardDuty + CloudWatch 알람 | 대량 삭제·객체 수 급락 탐지 |

---

## 7. 대응 절차

1. **버전 관리 상태 확인** — 켜져 있으면 삭제 마커 제거로 즉시 복구 가능
2. 삭제 주체·키(`AKIA...`) 격리 및 사후 활동 조사
3. Object Lock/백업에서 복원, 복구 불가 데이터 범위 산정
4. 삭제 직전 `PutBucketVersioning(Suspended)`·라이프사이클 변경 여부 확인 (복구 무력화 시도)

---

## 8. 참고 자료

- [Stratus Red Team — S3 Ransomware through batch file deletion](https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [AWS — Using S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS — Using MFA delete](https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html)
