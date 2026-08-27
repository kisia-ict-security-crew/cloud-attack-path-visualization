# EC2 Instance Connect를 이용한 측면 이동 (Usage of EC2 Instance Connect on multiple instances)

> 대상 로그: `aws.lateral-movement.ec2-instance-connect.json`
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.lateral-movement.ec2-instance-connect`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | 전술: **Lateral Movement** / 기법 매핑: **T1021.004** (Remote Services: SSH) |
| 로그 레코드 수 | **302건** (세 로그 중 가장 큼) |
| 시간 범위 | `2026-08-25T06:18:35Z` ~ `2026-08-25T06:25:11Z` (약 6분 30초) |
| AWS 계정 | `949328302905` |
| 리전 | `ap-northeast-2` (서울) |
| 공격자(오퍼레이터) IP | `165.132.5.130` |
| NAT 게이트웨이 IP | `3.37.228.171` (인스턴스들의 아웃바운드 IP) |
| 대상 인스턴스 | `i-0964af316137d703b`, `i-09c589ebddf7a2204`, `i-04ee74779fa532da1` (3대) |
| **결정적 이벤트** | `ec2-instance-connect:SendSSHPublicKey` **×3, 2초 안에** |

**한 줄 요약:** AWS API 권한만으로 여러 EC2 인스턴스에 **임시 SSH 공개키를 밀어 넣어** SSH 접속 경로를 확보한다. 기존 키페어를 훔칠 필요도, 인스턴스에 미리 침투할 필요도 없다.

---

## 2. 공격 기법 설명

### 2.1 EC2 Instance Connect란

EC2 Instance Connect(EIC)는 **"SSH 키를 미리 심어두지 않고도 EC2에 SSH로 붙게 해주는"** AWS 기능이다.

동작 방식:

1. 사용자가 `ec2-instance-connect:SendSSHPublicKey` API를 호출하며 공개키를 전달한다.
2. AWS가 그 공개키를 인스턴스의 `~/.ssh/authorized_keys`에 **60초 동안만** 넣어준다.
   (실제로는 인스턴스에 설치된 `ec2-instance-connect` 패키지가 `AuthorizedKeysCommand`로 처리)
3. 사용자는 그 60초 안에 대응하는 개인키로 SSH 접속한다.
4. 세션이 수립되면 **연결이 끊길 때까지 유지**된다. 키가 만료돼도 이미 열린 세션은 살아 있다.

정상 용도로는 "키페어 관리 부담 없이, IAM 권한만으로 SSH 접근을 제어"하는 아주 좋은 기능이다.

### 2.2 공격자 관점에서 왜 매력적인가

| 특징 | 설명 |
|---|---|
| **키를 훔칠 필요가 없다** | 자기 키를 새로 만들어 밀어 넣으면 된다. `.pem` 파일 탈취 불필요. |
| **IAM 권한 하나면 끝** | `ec2-instance-connect:SendSSHPublicKey` + `ec2:DescribeInstances` 정도면 충분 |
| **대량 확산이 쉽다** | `DescribeInstances`로 인스턴스 목록을 뽑고 루프를 돌면 **수백 대에 동시에** 키를 밀어 넣을 수 있다 |
| **정상 기능이라 위화감이 적다** | 신뢰된 AWS API이며, 운영팀도 실제로 쓴다 |
| **CloudTrail이 SSH 자체는 못 본다** | 키 주입만 기록되고, **접속 성공/실패나 세션 내용은 CloudTrail에 없다** ← 4.4절 |
| **인스턴스 안에 흔적이 적다** | 임시 키는 60초 뒤 사라지고 `authorized_keys` 파일도 영구 변경되지 않는다 |

### 2.3 공격 체인에서의 위치

이 기법은 보통 **단독으로 쓰이지 않는다.**

```
① 초기 침투 (피싱, 유출된 액세스 키, SSRF로 IMDS 크리덴셜 탈취 …)
        │
        ▼
② 정찰: ec2:DescribeInstances 로 인스턴스 전수 조사
        │
        ▼
③ 【이 기법】 ec2-instance-connect:SendSSHPublicKey 로 여러 대에 키 주입
        │
        ▼
④ SSH 접속 → OS 레벨 장악 (CloudTrail 사각지대)
        │
        ├─▶ 인스턴스 내 IMDS에서 또 다른 역할 크리덴셜 탈취 (→ 권한 상승)
        ├─▶ 디스크의 시크릿·소스코드 수집
        └─▶ 크립토마이너 설치 / 백도어 지속성 확보
```

특히 ④→IMDS 경로는 이 폴더의 다른 로그(`aws.credential-access.ec2-steal-instance-credentials`)와 그대로 이어진다.

### 2.4 유사·관련 기법

| 기법 | 차이점 |
|---|---|
| `ec2-serial-console-send-ssh-public-key` | 시리얼 콘솔 경유. **네트워크 접근이 아예 없어도** 접속 가능 |
| `ssm:SendCommand` | SSH 없이 명령 실행. SSM 에이전트 필요 |
| `ssm:StartSession` | 대화형 셸. 네트워크 인바운드 불필요 |
| **EIC Endpoint 백도어** | EIC Endpoint를 만들어두면 **프라이빗 서브넷 인스턴스에도 인터넷 없이 접속** 가능한 지속성 확보 수단이 됨 |

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. VPC / 퍼블릭·프라이빗 서브넷 / IGW / NAT GW / 라우트 테이블 생성
2. IAM 역할 `stratus-red-team-ec2-sshpublickey-lateral-movement-role` 생성 후 `AmazonSSMManagedInstanceCore` 정책 연결
3. 인스턴스 프로파일 생성 및 역할 연결
4. ENI 3개 + **EC2 인스턴스 3대** 기동 (`ami-03739463891cc45ee`, t3.micro)
5. SSM 에이전트 등록 대기

### Detonation
6. **3대 모두에 동일한 SSH 공개키를 `SendSSHPublicKey`로 주입** (`instanceOSUser: ec2-user`)

### Cleanup
7. 인스턴스 종료, ENI·서브넷·NAT·IGW·VPC·IAM 리소스 전부 삭제

---

## 4. 로그 타임라인 분석

### 4.1 단계별 흐름

| 시각 (UTC) | 이벤트 | 주체 / UA | 소스 IP | 의미 |
|---|---|---|---|---|
| 06:18:35~06:19:15 | `Describe*` 다수 | Terraform | 165.132.5.130 | 🟡 기존 리소스 조회 |
| 06:19:16 | `CreateVpc`, `AllocateAddress`, **`iam:CreateRole`** | Terraform | 165.132.5.130 | 🟡 VPC + IAM 역할 생성 |
| 06:19:17 | `iam:AttachRolePolicy` (`AmazonSSMManagedInstanceCore`), `CreateInstanceProfile`, `CreateSubnet`, `CreateInternetGateway` | Terraform | 165.132.5.130 | 🟡 권한·네트워크 구성 |
| 06:19:18 | `CreateNetworkInterface` ×3, `AddRoleToInstanceProfile` | Terraform | 165.132.5.130 | 🟡 ENI 3개 |
| 06:19:19~06:19:24 | **`RunInstances` ×12 → 전부 실패** (`Client.InvalidParameterValue`) | Terraform | 165.132.5.130 | 🟡 IAM 전파 지연으로 재시도 (4.3절) |
| 06:19:29 | **`RunInstances` ×3 → 성공** | Terraform | 165.132.5.130 | 🟡 인스턴스 3대 생성 |
| 06:19:31 | `SharedSnapshotVolumeCreated` ×3 | `ec2.amazonaws.com` | ec2.amazonaws.com | 🟡 **공개 AMI 스냅샷에서 볼륨 생성 — 공격 아님** |
| 06:21:26~06:21:31 | `ssm:RegisterManagedInstance` ×3, `ssm:UpdateInstanceInformation` ×9 | AssumedRole (SSM 에이전트) | **3.37.228.171** | 🟡 인스턴스가 SSM에 등록 (NAT 경유) |
| **06:21:40** | **`SendSSHPublicKey` → `i-0964af316137d703b`** | stratus-red-team_0c7053a6 | 165.132.5.130 | 🔴 **공격 ①** |
| **06:21:40** | **`SendSSHPublicKey` → `i-09c589ebddf7a2204`** | stratus-red-team_0c7053a6 | 165.132.5.130 | 🔴 **공격 ②** |
| **06:21:41** | **`SendSSHPublicKey` → `i-04ee74779fa532da1`** | stratus-red-team_0c7053a6 | 165.132.5.130 | 🔴 **공격 ③** |
| 06:22:02~06:23:04 | `TerminateInstances`, `Delete*`, `DetachRolePolicy`, `DeleteRole` 등 | Terraform | 165.132.5.130 | 🟡 Cleanup |

### 4.2 결정적 이벤트 — `SendSSHPublicKey` 3연발

```json
{
  "eventTime": "2026-08-25T06:21:40Z",
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSSHPublicKey",
  "awsRegion": "ap-northeast-2",
  "sourceIPAddress": "165.132.5.130",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::949328302905:user/Huge-log-attack-simulation",
    "accessKeyId": "AKIA52CDAKM4W5UHPSX2"
  },
  "requestParameters": {
    "instanceId": "i-0964af316137d703b",
    "instanceOSUser": "ec2-user",
    "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu"
  },
  "responseElements": { "success": true }
}
```

**세 건이 공유하는 특징이 곧 탐지 시그니처다.**

| 관찰 | 왜 의심스러운가 |
|---|---|
| **동일한 `sSHPublicKey`** 가 3대에 그대로 재사용됨 | 운영자가 여러 대를 다룰 때도 흔하지만, **공격 도구의 전형적 패턴**이다. 이 공개키 문자열 자체가 IOC가 된다. |
| **2초 안에 3건** | 사람이 콘솔로 하나씩 접속하는 속도가 아니다. **스크립트/자동화**의 증거. |
| **동일 주체 · 동일 IP** | 한 IAM 주체가 짧은 시간에 여러 인스턴스를 대상으로 함 = "확산" 패턴 |
| `instanceOSUser: ec2-user` | Amazon Linux 기본 계정. 대상 OS를 정확히 몰라도 되는 무차별 시도일 수 있음 |
| `responseElements.success: true` | **주입 성공**. 실패였다면 우선순위가 낮았을 것 |

### 4.3 부수적 관찰 — RunInstances가 15번인데 인스턴스는 3대

```
RunInstances 총 15건 = 실패 12건 + 성공 3건
실패 사유: Client.InvalidParameterValue
  "Value (stratus-red-team-ec2-sshpublickey-lateral-movement-instance)
   for parameter iamInstanceProfile is invalid"
```

이건 공격이 아니라 **IAM의 결과적 일관성(eventual consistency)** 때문이다. 인스턴스 프로파일을 만든 직후에는 EC2 서비스가 아직 그것을 인식하지 못해 실패하고, Terraform이 재시도하다가 약 10초 뒤 성공한다. `clientToken`이 같은 요청이 반복되는 것으로 재시도임을 확인할 수 있다.

> **로그 분석 시사점:** "실패한 API 호출이 여러 번 반복됨"은 공격 정황일 수도, 이런 평범한 재시도일 수도 있다. `clientToken` 동일 여부와 `errorMessage` 내용을 봐야 구분된다. 이 로그의 오류 이벤트는 총 **28건**(전체 302건 중 9.3%)이며, 그중 12건이 이 `RunInstances` 재시도다. 전부 공격과 무관한 양성 노이즈다.

### 4.4 ⭐ 가장 중요한 한계 — CloudTrail은 SSH를 보지 못한다

이 로그에는 `SendSSHPublicKey` 3건이 있고, **그게 전부다.**

| 질문 | CloudTrail로 답할 수 있는가 |
|---|---|
| 누가 키를 주입했는가? | ✅ 예 |
| 어느 인스턴스에? | ✅ 예 |
| 어떤 공개키를? | ✅ 예 |
| **실제로 SSH 접속에 성공했는가?** | ❌ **아니오** |
| **접속해서 무슨 명령을 실행했는가?** | ❌ **아니오** |
| **얼마나 오래 붙어 있었는가?** | ❌ **아니오** |

이 사각지대를 메우려면 다른 데이터 소스가 필요하다.

- **VPC Flow Logs** — 22번 포트로의 인바운드 연결, 소스 IP, 세션 지속 시간
- **인스턴스 OS 로그** — `/var/log/secure` (Amazon Linux/RHEL), `/var/log/auth.log` (Ubuntu)의 `Accepted publickey ... ssh-ed25519 SHA256:...` 라인
- **GuardDuty Runtime Monitoring** — 인스턴스 내부 프로세스 행위
- **EDR / osquery** 등 호스트 에이전트

> 실무 팁: `SendSSHPublicKey`의 `sSHPublicKey` 값을 SHA256 지문으로 변환하면 `/var/log/secure`의 로그인 성공 기록과 **직접 매칭**할 수 있다. CloudTrail의 IAM 주체와 OS 로그인을 잇는 유일한 연결고리다.

### 4.5 이 로그의 부수적 관전 포인트 — NAT IP

SSM 에이전트 트래픽은 전부 `3.37.228.171`(NAT 게이트웨이 EIP)에서 나온다. 인스턴스의 사설 IP가 아니다.

이것은 **자격증명 탈취 탐지 룰(다른 로그의 5.3절 Sigma)의 대표적 오탐 원인**이다.
"인스턴스 역할 자격증명이 인스턴스 IP가 아닌 곳에서 쓰였다"는 룰만 놓고 보면, 프라이빗 서브넷의 정상 인스턴스는 전부 걸린다. **NAT EIP를 반드시 화이트리스트에 넣어야 한다.**

### 4.6 시그널 vs 노이즈

| 구분 | 건수 | 비율 | 판별 기준 (User-Agent) |
|---|---|---|---|
| 🔴 **실제 공격** (`SendSSHPublicKey`) | 3 | 1.0% | `stratus-red-team_0c7053a6...` |
| 🟡 Terraform Warm-up / Cleanup | 266 | 88.1% | `terraform-provider-aws/4.67.0` |
| 🟡 SSM 에이전트 자동 등록 | 16 | 5.3% | `amazon-ssm-agent/3.3.4624.0` |
| 🟡 AWS 서비스 자체 이벤트 | 15 | 5.0% | `ec2.amazonaws.com`, `resource-explorer-2` |
| 🟡 공격 도구의 부수 호출 (`DescribeAccountAttributes`) | 2 | 0.7% | `stratus-red-team_<uuid>` |

**302건 중 알럿 대상은 3건이다.** 이 비율(약 1%)이 실제 SOC가 겪는 현실을 잘 보여준다. 고유 이벤트 이름은 67종이지만, 룰을 걸어야 하는 건 딱 하나다.

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 | 근거 |
|---|---|---|
| **최상** | **한 주체가 짧은 시간(예: 5분) 안에 N대(예: 3대) 이상의 인스턴스에 `SendSSHPublicKey`** | 확산 패턴. 이 로그가 정확히 해당 |
| 상 | **동일한 `sSHPublicKey` 값이 여러 인스턴스에 반복 사용** | 공격 도구 패턴 + IOC 확보 |
| 상 | 평소 `SendSSHPublicKey`를 쓰지 않던 주체가 호출 (베이스라인 이탈) | 대부분의 조직에서 EIC 사용자는 소수 |
| 중 | `SendSSHPublicKey`의 `sourceIPAddress`가 신규/비정상 지역 | 크리덴셜 탈취 정황 |
| 중 | `DescribeInstances` → `SendSSHPublicKey` 연쇄 (정찰 후 이동) | 공격 체인 상관분석 |
| 중 | 태그상 **다른 환경/서비스**에 속한 인스턴스들에 동시에 주입 | 정상 운영자는 보통 한 서비스군만 다룸 |
| 참고 | `SendSSHPublicKey` 이후 해당 인스턴스로 22번 포트 인바운드 (VPC Flow Logs) | 실제 접속 성공 확인 |

### 5.2 Sigma 룰

```yaml
title: EC2 Instance Connect SSH Public Key Pushed To Multiple Instances
id: 7d21fa60-3c8b-4c1e-96ad-eicspray0000001
status: experimental
description: |
  단일 IAM 주체가 짧은 시간 안에 여러 EC2 인스턴스에 SSH 공개키를 주입하는
  측면 이동(Lateral Movement) 패턴을 탐지한다.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2-instance-connect.amazonaws.com'
    eventName: 'SendSSHPublicKey'
    responseElements.success: true
  condition: selection | count(requestParameters.instanceId) by userIdentity.arn > 2
  timeframe: 5m
falsepositives:
  - 운영팀의 정상 다중 인스턴스 점검 작업
  - CI/CD 또는 구성관리 자동화 (승인된 역할 화이트리스트 필요)
level: high
```

```yaml
title: EC2 Instance Connect Used By Unusual Principal
id: b3ff28d9-6a14-4f77-8e02-eicunusual00001
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2-instance-connect.amazonaws.com'
    eventName: 'SendSSHPublicKey'
  known_operators:
    userIdentity.arn|contains:
      - 'user/ops-'
      - 'role/BastionAdmin'
  condition: selection and not known_operators
falsepositives:
  - 신규 입사자 또는 신규 자동화 역할 (화이트리스트 갱신 필요)
level: medium
```

### 5.3 Athena 쿼리

```sql
-- ① 5분 내 3대 이상에 키를 주입한 주체 찾기
SELECT
    useridentity.arn AS actor,
    sourceipaddress,
    date_trunc('minute', from_iso8601_timestamp(eventtime)) AS minute_bucket,
    count(DISTINCT json_extract_scalar(requestparameters, '$.instanceId')) AS instance_count,
    array_agg(DISTINCT json_extract_scalar(requestparameters, '$.instanceId')) AS instances
FROM cloudtrail_logs
WHERE eventsource = 'ec2-instance-connect.amazonaws.com'
  AND eventname   = 'SendSSHPublicKey'
GROUP BY 1, 2, 3
HAVING count(DISTINCT json_extract_scalar(requestparameters, '$.instanceId')) >= 3
ORDER BY instance_count DESC;
```

```sql
-- ② 동일 공개키가 여러 인스턴스에 재사용된 경우 (IOC 추출)
SELECT
    json_extract_scalar(requestparameters, '$.sSHPublicKey') AS ssh_key,
    count(DISTINCT json_extract_scalar(requestparameters, '$.instanceId')) AS n_instances,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen,
    array_agg(DISTINCT useridentity.arn) AS actors
FROM cloudtrail_logs
WHERE eventname = 'SendSSHPublicKey'
GROUP BY 1
HAVING count(DISTINCT json_extract_scalar(requestparameters, '$.instanceId')) > 1
ORDER BY n_instances DESC;
```

```sql
-- ③ 정찰 → 측면 이동 연쇄 (DescribeInstances 후 10분 내 SendSSHPublicKey)
WITH recon AS (
    SELECT useridentity.arn AS actor, eventtime
    FROM cloudtrail_logs
    WHERE eventname = 'DescribeInstances' AND errorcode IS NULL
),
move AS (
    SELECT useridentity.arn AS actor, eventtime,
           json_extract_scalar(requestparameters, '$.instanceId') AS instance_id
    FROM cloudtrail_logs
    WHERE eventname = 'SendSSHPublicKey'
)
SELECT m.actor, r.eventtime AS recon_at, m.eventtime AS move_at, m.instance_id
FROM move m
JOIN recon r ON m.actor = r.actor
WHERE date_diff('minute', from_iso8601_timestamp(r.eventtime),
                          from_iso8601_timestamp(m.eventtime)) BETWEEN 0 AND 10;
```

### 5.4 CloudWatch Logs Insights

```
fields @timestamp, userIdentity.arn, sourceIPAddress,
       requestParameters.instanceId, requestParameters.instanceOSUser,
       requestParameters.sSHPublicKey
| filter eventSource = "ec2-instance-connect.amazonaws.com"
| filter eventName = "SendSSHPublicKey"
| stats count_distinct(requestParameters.instanceId) as instances,
        earliest(@timestamp) as first,
        latest(@timestamp)   as last
    by userIdentity.arn, sourceIPAddress
| sort instances desc
```

---

## 6. 오탐 주의사항

- **EIC는 정상 기능이다.** 특히 키페어 관리를 없애려고 EIC를 표준 접근 수단으로 채택한 조직에서는 `SendSSHPublicKey`가 일상적으로 발생한다. **"발생 여부"가 아니라 "누가, 몇 대에, 얼마나 빠르게"로 판단해야 한다.**
- **자동화 도구**(Ansible, CI 배포 잡)가 여러 대에 연속 주입할 수 있다. 해당 역할 ARN을 화이트리스트로 관리한다.
- **임계값 튜닝 필요.** 인스턴스 3대는 이 실습 기준이다. 실환경에서는 조직 평소 패턴의 95~99 퍼센타일로 잡는 것이 현실적이다.
- **`SharedSnapshotVolumeCreated`를 공격 신호로 오인하지 말 것.** 이 로그에서는 공개 AMI로 인스턴스를 띄우면서 발생한 정상 이벤트다.

---

## 7. 완화 방안

| 조치 | 내용 |
|---|---|
| **최소권한** ⭐ | `ec2-instance-connect:SendSSHPublicKey`를 소수 역할에만 부여. 개발자 기본 정책에서 제거 |
| **리소스 조건 제한** | IAM 정책에 `ec2:ResourceTag/Environment: dev` 같은 조건을 걸어 **운영 인스턴스에는 주입 불가**하게 함 |
| **OS 사용자 제한** | `ec2-instance-connect:osuser` 조건 키로 허용 계정을 제한 (`root` 차단 등) |
| **네트워크 차단** | 보안 그룹에서 22번 인바운드를 차단하면 키를 주입해도 접속 불가. **접근은 SSM Session Manager로 일원화** |
| **SSM Session Manager 전환** | 인바운드 포트 없이 접근 가능하고, **세션 내용 전체가 S3/CloudWatch에 로깅**된다 (CloudTrail 사각지대 해소) |
| VPC Flow Logs 활성화 | 22번 포트 접속 성공 여부 확인용 |
| OS 인증 로그 중앙 수집 | `/var/log/secure`를 CloudWatch Logs로 전송해 SSH 로그인과 CloudTrail을 상관분석 |
| GuardDuty Runtime Monitoring | 접속 이후 인스턴스 내부 행위 탐지 |

> **핵심 판단:** SSH 접근이 꼭 필요한지 재검토할 가치가 있다. **Session Manager로 전환하면 이 기법 자체가 무력화**되면서 감사 로그 품질도 함께 올라간다.

---

## 8. 대응 절차 (알럿 발생 시)

1. **주입된 공개키를 IOC로 확보** — `sSHPublicKey` 값과 그 SHA256 지문
2. **대상 인스턴스 전수 파악** — 같은 주체/같은 키가 쓰인 모든 `instanceId`
3. **실제 접속 여부 확인** — VPC Flow Logs(22/tcp)와 각 인스턴스 `/var/log/secure`에서 해당 키 지문의 `Accepted publickey` 검색
4. **접속이 확인된 인스턴스는 침해 가정** — 세션 중 실행된 명령, 신규 계정/cron/systemd 유닛, `authorized_keys` 영구 추가 여부 점검
5. **해당 인스턴스의 IAM 역할 자격증명 회수** — 인스턴스에서 IMDS로 크리덴셜을 뽑아갔을 수 있다. 역할 세션 무효화 후 정책 재검토
6. **행위 주체 조사** — `AKIA...` 키 침해 여부 확인, 즉시 비활성화·회전
7. **격리 및 포렌식** — 필요 시 인스턴스 격리 후 스냅샷 확보

---

## 9. 참고 자료

- [Stratus Red Team — Usage of EC2 Instance Connect on multiple instances](https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/)
- [Elastic — AWS EC2 Instance Connect SSH Public Key Uploaded](https://www.elastic.co/guide/en/security/current/aws-ec2-instance-connect-ssh-public-key-uploaded.html)
- [Uptycs — EC2 Instance Connect Lateral Movement Strategy for Data Exfiltration](https://www.uptycs.com/blog/ec2-instance-connect-lateral-movement-strategy-and-tactics-for-data-exfiltration)
- [Unit 42 — Navigating the Cloud: Exploring Lateral Movement Techniques](https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/)
- [HackTricks Cloud — EC2 Instance Connect Endpoint backdoor](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ec2-instance-connect-endpoint-backdoor.html)
- [MITRE ATT&CK T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
