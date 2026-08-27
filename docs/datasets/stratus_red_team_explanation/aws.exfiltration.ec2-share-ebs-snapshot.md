# EBS 스냅샷 공유를 통한 데이터 유출 (Exfiltrate EBS Snapshot by Sharing It)

> 대상 로그: `aws.exfiltration.ec2-share-ebs-snapshot.json`
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.exfiltration.ec2-share-ebs-snapshot`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1537** — Transfer Data to Cloud Account (관련: T1578.001 Create Snapshot) |
| 전술(Tactic) | Exfiltration (유출) |
| 로그 레코드 수 | **20건** (세 로그 중 가장 작고 깨끗함) |
| 시간 범위 | `2026-08-25T06:30:03Z` ~ `2026-08-25T06:32:10Z` (약 2분) |
| AWS 계정 | `949328302905` |
| 리전 | `ap-northeast-2` (서울) |
| 소스 IP | `165.132.5.130` (전 레코드 동일) |
| 대상 리소스 | 볼륨 `vol-041892b8c4963929d` → 스냅샷 `snap-0e3bac79ac432d549` |
| 유출 대상 계정 | **`012345678912`** (가상의 외부 계정) |
| **결정적 이벤트** | `ec2:ModifySnapshotAttribute` — `createVolumePermission.add.items[].userId` |

**한 줄 요약:** 디스크(EBS 볼륨)의 스냅샷을 뜬 뒤, **스냅샷 접근 권한을 외부 AWS 계정에 부여**해서 데이터를 계정 밖으로 내보낸다. 네트워크로 파일을 전송하지 않으므로 **트래픽 기반 DLP에 전혀 걸리지 않는다.**

---

## 2. 공격 기법 설명

### 2.1 원리

EBS 스냅샷은 볼륨의 시점 백업이며, **다른 AWS 계정에 공유할 수 있다.** 정상적으로는 계정 간 AMI 배포, 백업 계정으로의 복제 등에 쓰이는 기능이다.

공격자 관점에서 이 흐름은 다음과 같다.

```
[피해 계정 949328302905]                      [공격자 계정 012345678912]
   EBS 볼륨 (DB 데이터, 소스코드, 키 파일...)
        │ ec2:CreateSnapshot
        ▼
   스냅샷 snap-0e3b...
        │ ec2:ModifySnapshotAttribute
        │   createVolumePermission.add → userId: 012345678912
        ▼
   ─────────── 권한 부여 ──────────────────▶  스냅샷이 보이기 시작
                                                    │ ec2:CopySnapshot / CreateVolume
                                                    ▼
                                              내 계정 볼륨으로 마운트 → 전부 읽음
```

### 2.2 왜 위험한가 (이 기법의 진짜 무서운 점)

| 특징 | 설명 |
|---|---|
| **네트워크 유출 흔적 없음** | S3 대량 다운로드나 대용량 아웃바운드 트래픽이 발생하지 않는다. VPC Flow Logs, DLP, 프록시 로그 어디에도 안 잡힌다. |
| **API 호출 딱 1건** | `ModifySnapshotAttribute` 한 번이면 끝. 노이즈에 묻히기 매우 쉽다. |
| **데이터는 원본 그대로** | 디스크 전체 이미지이므로 `/root/.ssh/`, `.aws/credentials`, DB 파일, 애플리케이션 시크릿까지 통째로 넘어간다. |
| **되돌려도 늦음** | 공유를 해제해도 공격자가 이미 `CopySnapshot`을 마쳤다면 복사본은 공격자 계정에 남는다. |
| **권한 문턱이 낮음** | `ec2:CreateSnapshot` + `ec2:ModifySnapshotAttribute` 만 있으면 된다. 백업 담당 역할이 흔히 갖고 있는 권한이다. |

### 2.3 변형 — 전체 공개(public) 공유

`createVolumePermission`에 `userId` 대신 **`group: all`** 을 넣으면 스냅샷이 **인터넷 전체에 공개**된다.

```json
"createVolumePermission": { "add": { "items": [ { "group": "all" } ] } }
```

실제로 공개된 EBS 스냅샷을 대량 스캔해 크리덴셜을 수집하는 도구(Rhino Security의 `Dufflebag` 등)가 존재하며, 실수로 공개된 스냅샷에서 기업 소스코드와 키가 발견된 사례가 꾸준히 보고된다. 이 때문에 AWS는 2023년 말 **"Block public access for EBS snapshots"** 계정 단위 설정을 도입했다.

### 2.4 실제 사례 맥락

Datadog Security Labs는 이 기법의 사례로 **2016년 DNC 침해**를 든다. 공격자가 AWS 자격증명을 탈취한 뒤 스냅샷을 통해 데이터를 빼낸 유형이다. 최근에도 Sysdig의 **SCARLETEEL** 캠페인처럼 클라우드 자격증명을 탈취한 뒤 스냅샷·이미지 계층에서 데이터를 훔치는 패턴이 반복적으로 관찰된다.

### 2.5 방어의 급소 — 암호화

공유 가능 여부는 **암호화 방식**이 결정한다.

| 스냅샷 상태 | 외부 계정 공유 | 비고 |
|---|---|---|
| 미암호화 | ✅ 가능 | **이 로그의 스냅샷이 여기 해당** (`encrypted: false`) |
| AWS 관리형 키(`aws/ebs`)로 암호화 | ❌ **불가능** | AWS 관리형 키는 공유 자체가 막힘 |
| 고객 관리형 키(CMK)로 암호화 | ⚠️ 가능하지만 KMS 키도 함께 공유해야 함 | 공유 조건이 2개로 늘어 난이도 상승 |

**즉, 모든 EBS 볼륨을 기본 암호화(EBS encryption by default)로 두면 이 기법의 상당수가 원천 차단된다.**

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. 1GiB EBS 볼륨 생성 (`StratusRedTeamVolume`, gp2, **미암호화**)
2. 그 볼륨의 스냅샷 생성
3. 스냅샷이 `completed` 상태가 될 때까지 폴링

### Detonation
4. **`ec2:ModifySnapshotAttribute`** 로 스냅샷을 외부 계정 `012345678912`에 공유

### Revert / Cleanup
5. `ec2:ModifySnapshotAttribute` 로 공유 권한 **제거**
6. 볼륨·스냅샷 삭제

---

## 4. 로그 타임라인 분석

### 4.1 전체 흐름 (20건 전부)

| # | 시각 (UTC) | 이벤트 | User-Agent | 의미 |
|---|---|---|---|---|
| 1 | 06:30:03 | `DescribeAvailabilityZones` | Terraform | 🟡 AZ 조회 |
| 2 | 06:30:04 | **`CreateVolume`** | Terraform | 🟡 1GiB gp2 볼륨 생성 (`encrypted: false`) |
| 3-5 | 06:30:15 | `DescribeVolumes` ×2, `DescribeSnapshots` | Terraform | 🟡 상태 확인 |
| 6 | 06:30:15 | **`CreateSnapshot`** | Terraform | 🟡 스냅샷 `snap-0e3bac79ac432d549` 생성 |
| 7-10 | 06:30:31~06:31:01 | `DescribeSnapshots` ×4 | Terraform | 🟡 스냅샷 완료 대기 폴링 (15초 간격) |
| 11 | 06:31:11 | `DescribeAccountAttributes` | **stratus-red-team_51a4...** | 🔴 공격 도구 첫 등장 |
| **12** | **06:31:11** | **`ModifySnapshotAttribute` (add)** | **stratus-red-team_68ca...** | 🔴🔴 **공격 실행 — 외부 계정에 공유** |
| **13** | **06:32:04** | **`ModifySnapshotAttribute` (remove)** | **stratus-red-team_d3b0...** | 🔴 공격 원복 (실제 공격자라면 **증거 인멸**로 해석) |
| 14-17 | 06:32:07~09 | `DescribeAvailabilityZones`, `DescribeVolumes`, `DescribeSnapshots` | Terraform | 🟡 삭제 전 확인 |
| 18-20 | 06:32:09~10 | `DeleteVolume`, `DeleteSnapshot`, `DescribeVolumes` | Terraform | 🟡 Cleanup |

> 오류는 단 1건: `DescribeVolumes` → `Client.InvalidVolume.NotFound` (이미 삭제된 볼륨 조회, 정상적인 Terraform 동작)

### 4.2 결정적 이벤트 — 공유 부여

```json
{
  "eventTime": "2026-08-25T06:31:11Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "ModifySnapshotAttribute",
  "sourceIPAddress": "165.132.5.130",
  "userAgent": "stratus-red-team_68ca6964-e6f1-41c8-ac76-892de844939d",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::949328302905:user/Huge-log-attack-simulation",
    "accessKeyId": "AKIA52CDAKM4W5UHPSX2"
  },
  "requestParameters": {
    "snapshotId": "snap-0e3bac79ac432d549",
    "attributeType": "CREATE_VOLUME_PERMISSION",
    "createVolumePermission": {
      "add": { "items": [ { "userId": "012345678912" } ] }   // ← 🔴 외부 계정 ID
    }
  },
  "responseElements": { "_return": true }                     // ← 성공
}
```

**봐야 할 것은 딱 세 가지다.**

1. `attributeType == "CREATE_VOLUME_PERMISSION"` → 스냅샷 접근 권한을 건드리는 중
2. `createVolumePermission.add.items[].userId` → **이 계정 ID가 우리 조직 소속인가?**
3. `responseElements._return == true` → 실제로 성공했는가

### 4.3 되돌리기 이벤트 — 증거 인멸 신호

```json
{
  "eventTime": "2026-08-25T06:32:04Z",
  "eventName": "ModifySnapshotAttribute",
  "requestParameters": {
    "snapshotId": "snap-0e3bac79ac432d549",
    "attributeType": "CREATE_VOLUME_PERMISSION",
    "createVolumePermission": {
      "remove": { "items": [ { "userId": "012345678912" } ] }  // ← 공유 해제
    }
  }
}
```

Stratus에서는 단순한 실습 원복이지만, **실제 침해에서는 이 `remove`가 훨씬 위험한 신호다.**
공유를 53초만 유지했다는 것은 "그동안 복사가 끝났고, 이제 흔적을 지운다"는 의미일 수 있다. 콘솔에서 스냅샷 권한을 확인하면 이미 깨끗해 보이기 때문에, **CloudTrail 없이는 사건 자체를 인지할 수 없다.** Elastic이 `AWS EC2 EBS Snapshot Access Removed`를 별도 탐지 룰로 두는 이유다.

### 4.4 User-Agent — 이 로그의 흥미로운 지점

| User-Agent | 건수 | 정체 |
|---|---|---|
| `APN/1.0 HashiCorp/1.0 Terraform/1.1.2 ... terraform-provider-aws/3.76.1` | 17 | Warm-up / Cleanup (Terraform) |
| `stratus-red-team_51a46b9c-...` | 1 | 공격 도구 |
| `stratus-red-team_68ca6964-...` | 1 | **공격 도구 (공유 부여)** |
| `stratus-red-team_d3b02b05-...` | 1 | 공격 도구 (공유 해제) |

Stratus Red Team은 **호출마다 UUID가 다른 User-Agent**를 쓴다. 실습 로그에서 공격 구간을 골라내는 데는 편리하지만, **실제 공격자는 절대 이렇게 표시하지 않으므로 탐지 룰의 근거로 삼으면 안 된다.** 탐지는 반드시 `requestParameters` 기반으로 작성해야 한다.

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 | 설명 |
|---|---|---|
| **최상** | `ModifySnapshotAttribute` + `createVolumePermission.add` + `userId`가 **조직 계정 목록 밖** | 사실상 확정적 |
| **최상** | `createVolumePermission.add.items[].group == "all"` | 공개 공유 = 즉시 대응 |
| 상 | `ModifySnapshotAttribute` + `remove` (부여 후 짧은 시간 내) | 증거 인멸 정황 |
| 중 | `CreateSnapshot` → `ModifySnapshotAttribute` 가 **짧은 시간 내 연속** 발생 | 이 로그에서는 56초 간격 |
| 중 | `ModifySnapshotAttribute` 를 평소 호출하지 않던 주체가 호출 | 베이스라인 기반 |
| 참고 | 공격자 계정 쪽에서 발생하는 `SharedSnapshotCopyInitiated`, `SharedSnapshotVolumeCreated` | 피해 계정 CloudTrail에도 기록됨 |

> ⚠️ **주의:** `SharedSnapshotVolumeCreated`는 오탐 요인이다. 공개 AMI로 EC2를 띄우기만 해도 발생한다. 실제로 이 폴더의 다른 두 로그(`ec2-instance-connect`, `ec2-steal-instance-credentials`)에는 **`RunInstances` 직후 `SharedSnapshotVolumeCreated`가 찍혀 있는데, 이는 Amazon Linux 공개 AMI의 스냅샷에서 볼륨이 만들어졌기 때문**이며 공격과 무관하다.

### 5.2 Sigma 룰

```yaml
title: EBS Snapshot Shared With External AWS Account
id: 5e2b91a4-7c33-4d0e-9f11-ebsshare000001
status: experimental
description: EBS 스냅샷의 CREATE_VOLUME_PERMISSION이 조직 외부 계정에 부여된 경우
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifySnapshotAttribute'
    requestParameters.attributeType: 'CREATE_VOLUME_PERMISSION'
  add_permission:
    requestParameters.createVolumePermission.add|exists: true
  # 조직 소유 계정 ID는 환경에 맞게 채울 것
  internal_accounts:
    requestParameters.createVolumePermission.add.items.userId:
      - '949328302905'
      - '111122223333'
  condition: selection and add_permission and not internal_accounts
falsepositives:
  - 승인된 백업/DR 계정으로의 정상 스냅샷 공유 (계정 ID 화이트리스트 관리 필요)
  - 마켓플레이스 AMI 배포 파이프라인
level: high
```

```yaml
title: EBS Snapshot Made Public
id: 9a4c1d76-88ef-4b22-a3c5-ebspublic00001
status: stable
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifySnapshotAttribute'
    requestParameters.createVolumePermission.add.items.group: 'all'
  condition: selection
falsepositives:
  - 거의 없음. 의도적인 공개 배포가 아니라면 즉시 대응.
level: critical
```

### 5.3 Athena 쿼리

```sql
-- 외부 계정으로 공유된 스냅샷 추적
SELECT
    eventtime,
    useridentity.arn                                    AS actor,
    sourceipaddress,
    json_extract_scalar(requestparameters, '$.snapshotId') AS snapshot_id,
    requestparameters
FROM cloudtrail_logs
WHERE eventname = 'ModifySnapshotAttribute'
  AND json_extract_scalar(requestparameters, '$.attributeType') = 'CREATE_VOLUME_PERMISSION'
  AND requestparameters LIKE '%"add"%'
  -- 조직 계정 ID가 아닌 대상만
  AND requestparameters NOT LIKE '%949328302905%'
ORDER BY eventtime DESC;
```

```sql
-- CreateSnapshot → ModifySnapshotAttribute 연쇄 탐지 (10분 이내)
WITH snaps AS (
    SELECT eventtime, useridentity.arn AS actor,
           json_extract_scalar(responseelements, '$.snapshotId') AS snapshot_id
    FROM cloudtrail_logs WHERE eventname = 'CreateSnapshot' AND errorcode IS NULL
),
shares AS (
    SELECT eventtime, useridentity.arn AS actor,
           json_extract_scalar(requestparameters, '$.snapshotId') AS snapshot_id
    FROM cloudtrail_logs
    WHERE eventname = 'ModifySnapshotAttribute' AND requestparameters LIKE '%"add"%'
)
SELECT s.actor, s.snapshot_id,
       s.eventtime AS created_at,
       h.eventtime AS shared_at,
       date_diff('second', from_iso8601_timestamp(s.eventtime),
                           from_iso8601_timestamp(h.eventtime)) AS gap_seconds
FROM snaps s
JOIN shares h ON s.snapshot_id = h.snapshot_id
WHERE date_diff('minute', from_iso8601_timestamp(s.eventtime),
                          from_iso8601_timestamp(h.eventtime)) BETWEEN 0 AND 10;
```

### 5.4 CloudWatch Logs Insights

```
fields @timestamp, userIdentity.arn, sourceIPAddress,
       requestParameters.snapshotId,
       requestParameters.createVolumePermission
| filter eventName = "ModifySnapshotAttribute"
| filter requestParameters.attributeType = "CREATE_VOLUME_PERMISSION"
| sort @timestamp desc
```

### 5.5 예방적 통제 (탐지보다 강력)

| 통제 | 내용 |
|---|---|
| **EBS 기본 암호화** ⭐ | AWS 관리형 키(`aws/ebs`)로 암호화된 스냅샷은 **외부 공유 자체가 불가능** |
| **Block public access for EBS snapshots** | 계정·리전 단위로 공개 공유를 차단. 시도 시 `Client.OperationNotPermitted` 오류가 CloudTrail에 남아 탐지 신호가 됨 |
| **SCP로 공유 차단** | `ec2:ModifySnapshotAttribute` 를 조건부로 Deny |
| AWS Config 룰 | `ebs-snapshot-public-restorable-check` 로 공개 스냅샷 상시 감시 |
| RAM 조직 외부 공유 비활성화 | 조직 밖 리소스 공유를 전역 차단 |

SCP 예시:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenySnapshotSharingOutsideOrg",
    "Effect": "Deny",
    "Action": "ec2:ModifySnapshotAttribute",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" }
    }
  }]
}
```

> 조직 계정 목록으로 대상 계정을 제한하려면 `ec2:Add/userId` 조건 키를 사용한다. 다만 이 조건 키의 동작은 리전/서비스 업데이트에 따라 달라질 수 있으므로 **실제 적용 전 반드시 테스트할 것.**

---

## 6. 오탐 주의사항

- **정상적인 계정 간 공유가 존재한다.** 백업 전용 계정, DR 계정, AMI 배포 파이프라인 등. → **조직 계정 ID 화이트리스트를 관리하는 것이 탐지의 전제 조건이다.**
- `SharedSnapshotVolumeCreated` / `SharedSnapshotCopyInitiated`는 **공개 AMI 사용 시에도 발생**한다 (5.1절 주의 참고). 단독으로 알럿을 걸면 오탐이 폭증한다.
- `CreateSnapshot` 자체는 백업 자동화에서 매일 대량 발생한다. **`ModifySnapshotAttribute`와 연결될 때만** 의미가 있다.

---

## 7. 대응 절차 (알럿 발생 시)

1. **즉시 공유 해제** — `aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission --operation-type remove ...`
2. **대상 계정 ID 확인** — 조직 소속인가? 아니라면 어떤 계정인가?
3. **이미 복사됐는지 확인** — CloudTrail에서 `SharedSnapshotCopyInitiated` / `SharedSnapshotVolumeCreated` 검색. **복사가 끝났다면 공유 해제는 사후약방문이다.**
4. **스냅샷 내용 평가** — 원본 볼륨에 무엇이 있었는가? 시크릿/PII 포함 여부에 따라 신고 의무가 달라진다.
5. **행위 주체 조사** — 해당 IAM 주체의 다른 활동, `accessKeyId` 침해 여부, 소스 IP 이상 여부
6. **자격증명 회전** — 스냅샷에 크리덴셜이 있었다면 전부 교체

---

## 8. 참고 자료

- [Stratus Red Team — Exfiltrate EBS Snapshot by Sharing It](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ebs-snapshot/)
- [Datadog Security Labs — Stealing an EBS snapshot by creating a snapshot and sharing it](https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/sharing-ebs-snapshot/)
- [Elastic — AWS EC2 EBS Snapshot Shared or Made Public](https://www.elastic.co/guide/en/security/8.19/aws-ec2-ebs-snapshot-shared-or-made-public.html)
- [Elastic — AWS EC2 EBS Snapshot Access Removed](https://www.elastic.co/guide/en/security/8.19/aws-ec2-ebs-snapshot-access-removed.html)
- [Hacking The Cloud — Loot Public EBS Snapshots](https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/)
- [MITRE ATT&CK T1537 — Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
