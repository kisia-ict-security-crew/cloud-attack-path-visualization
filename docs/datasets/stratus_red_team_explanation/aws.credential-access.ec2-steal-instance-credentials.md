# EC2 인스턴스 자격증명 탈취 (Steal EC2 Instance Credentials)

> 대상 로그: `aws.credential-access.ec2-steal-instance-credentials.json`
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.credential-access.ec2-steal-instance-credentials`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API |
| 전술(Tactic) | Credential Access (자격증명 접근) |
| 로그 레코드 수 | 183건 |
| 시간 범위 | `2026-08-21T07:21:31Z` ~ `2026-08-21T07:26:30Z` (약 5분) |
| AWS 계정 | `949328302905` |
| 리전 | `ap-northeast-2` (서울) |
| 공격자(오퍼레이터) IP | `165.132.5.130` |
| 피해 인스턴스 | `i-06d1d3cface560abe` (공인 IP `43.202.133.180`) |
| 탈취된 역할 | `stratus-red-team-ec2-steal-credentials-role` |
| **결정적 이벤트** | `sts:GetCallerIdentity` / `ec2:DescribeInstances` — **인스턴스 역할 자격증명인데 인스턴스 밖 IP에서 호출됨** |

**한 줄 요약:** EC2 인스턴스 내부에서만 쓰여야 할 임시 자격증명(IMDS가 발급한 `ASIA...` 키)이 인스턴스 밖(공격자 노트북)에서 사용된 흔적이 CloudTrail에 그대로 남았다.

---

## 2. 공격 기법 설명

### 2.1 IMDS(인스턴스 메타데이터 서비스)란

EC2 인스턴스에 IAM 역할을 붙이면, 인스턴스 안에서 링크로컬 주소인 **`169.254.169.254`** 로 HTTP 요청을 보내 그 역할의 **임시 자격증명**을 받아올 수 있다.

```bash
# IMDSv1 (인증 없음 — 단순 GET 한 번이면 끝)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<역할명>
# → {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

이 설계는 "키를 디스크에 저장하지 않아도 된다"는 장점이 있지만, 치명적인 전제를 깔고 있다:
**인스턴스 안에서 HTTP 요청을 보낼 수 있는 주체 = 그 인스턴스를 정당하게 쓰는 주체.**

### 2.2 왜 위험한가

받아온 자격증명은 **평범한 문자열**이다. 복사해서 다른 컴퓨터에 붙여넣으면 만료(보통 최대 6시간, 자동 갱신됨)될 때까지 그대로 동작한다. 즉 **인스턴스에 코드 한 줄만 실행시킬 수 있으면, 인스턴스의 IAM 권한 전체를 계정 밖으로 들고 나갈 수 있다.**

공격자가 IMDS에 도달하는 경로는 다양하다:

| 경로 | 설명 |
|---|---|
| **SSRF** | 웹앱이 사용자 입력 URL을 그대로 요청 → `http://169.254.169.254/...` 를 대신 요청시킴 (Capital One 사례) |
| RCE / 웹셸 | 인스턴스에서 임의 명령 실행 |
| **SSM SendCommand** | `ssm:SendCommand` 권한만 있으면 SSH 없이 인스턴스에서 셸 명령 실행 ← **이 로그의 방식** |
| 컨테이너 탈출 | 인스턴스 위 컨테이너에서 IMDS가 차단되지 않은 경우 |
| 잘못 설정된 리버스 프록시 | 프록시가 메타데이터 주소로 요청을 포워딩 |

### 2.3 실제 사례 — Capital One (2019)

가장 유명한 사례다. WAF 역할을 하던 EC2 인스턴스에 **SSRF** 취약점이 있었고, 공격자는 이를 통해 IMDSv1에서 인스턴스 역할 자격증명을 뽑아냈다. 그 역할은 S3 버킷 목록/읽기 권한을 갖고 있었고, 결과적으로 **1억 명 이상의 신용카드 신청 데이터**가 유출됐다. 이 사건 이후 AWS는 세션 토큰을 요구하는 **IMDSv2**를 도입했다.

### 2.4 방어의 핵심 — IMDSv2

IMDSv2는 자격증명을 받기 전에 **PUT 요청으로 세션 토큰을 먼저 받도록** 강제한다.

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

이 한 단계가 **SSRF 계열 공격을 사실상 차단**한다. 대부분의 SSRF는 GET만 유도할 수 있고, 커스텀 헤더를 붙일 수 없기 때문이다. 또한 응답 패킷의 TTL이 1로 제한되어 컨테이너/프록시 밖으로 전달되지 않는다.

> 💡 **이 로그에서 IMDSv1 vs v2가 직접 드러난다.** 아래 4.3절 참고.

---

## 3. Stratus Red Team이 실제로 한 일

Stratus Red Team은 이 기법을 3단계로 시뮬레이션한다.

### Warm-up (사전 준비, 로그의 대부분)
1. VPC / 서브넷 / IGW / NAT GW / 라우트 테이블 생성 (Terraform)
2. `AmazonSSMManagedInstanceCore` 정책이 붙은 IAM 역할 `stratus-red-team-ec2-steal-credentials-role` 생성
3. 그 역할을 인스턴스 프로파일로 붙인 EC2 인스턴스 1대 기동
4. SSM 에이전트가 등록될 때까지 대기

> ⚠️ **이 로그의 실제 내용 주의:** 위 2번(IAM 역할·인스턴스 프로파일 생성)에 해당하는 `iam.amazonaws.com` 이벤트는 **이 로그 파일에 들어 있지 않다.** 로그의 `eventSource`는 `ec2`, `sts`, `ssm`, `s3`, `cloudtrail` 5종뿐이다. 트레일이 켜지기 전(07:21:32 이전)에 역할이 이미 만들어져 있었기 때문으로 보인다. 참고로 같은 폴더의 `aws.lateral-movement.ec2-instance-connect.json`에는 `CreateRole` / `AttachRolePolicy` 이벤트가 정상적으로 포함되어 있다.

### Detonation (실제 공격 — 여기가 핵심)
5. **`ssm:SendCommand`** 로 인스턴스에서 `AWS-RunShellScript` 실행 → IMDS를 curl 해서 자격증명 추출
6. `ssm:GetCommandInvocation` 으로 명령 출력(= 탈취한 자격증명)을 회수
7. **탈취한 자격증명으로, 인스턴스 밖에서** `sts:GetCallerIdentity` 호출 (키가 살아있는지 확인)
8. 같은 자격증명으로 `ec2:DescribeInstances` 호출 (정찰 흉내)

### Cleanup (정리)
9. 인스턴스 종료 및 VPC 등 모든 리소스 삭제

---

## 4. 로그 타임라인 분석

### 4.1 단계별 흐름

| 시각 (UTC) | 이벤트 | 주체 | 소스 IP | 의미 |
|---|---|---|---|---|
| 07:21:31~32 | `CreateBucket`, `PutBucketPolicy`, `PutBucketEncryption`, `CreateTrail`, `PutEventSelectors`, `StartLogging` | **Root** (콘솔, Chrome UA) | 165.132.5.130 | 🔧 **로그 수집용 CloudTrail 트레일 준비 — 공격 아님** |
| 07:22:06~07:22:26 | `CreateVpc`, `CreateSubnet`, `CreateRouteTable`, `CreateNatGateway`, `RunInstances` ×5 | IAMUser (Terraform UA) | 165.132.5.130 | 🟡 Warm-up: 실습 환경 구축 |
| 07:22:27 | `sts:AssumeRole` ×2 | `ec2.amazonaws.com` | ec2.amazonaws.com | 🟡 EC2 서비스가 인스턴스에 역할 자격증명 발급 (정상) |
| 07:23:49 | `ssm:RegisterManagedInstance`, `ssm:UpdateInstanceInformation` | AssumedRole (SSM 에이전트) | **43.202.133.180** | 🟡 인스턴스가 SSM에 등록 — **인스턴스 자신의 IP** |
| **07:23:56** | **`ssm:SendCommand`** | IAMUser `Huge-log-attack-simulation` | 165.132.5.130 | 🔴 **① 공격 시작 — 인스턴스에 셸 명령 주입** |
| 07:23:56 | `ssm:DescribeInstanceInformation` | 동일 | 165.132.5.130 | 🔴 대상 인스턴스가 SSM 관리 대상인지 확인 |
| 07:23:56 | `ssm:GetCommandInvocation` (`InvocationDoesNotExist`) | 동일 | 165.132.5.130 | 🔴 결과 폴링 — 아직 실행 전이라 실패 |
| **07:24:01** | **`sts:GetCallerIdentity`** | **AssumedRole (인스턴스 역할)** | **165.132.5.130** | 🔴 **② 탈취 성공 — 훔친 키를 밖에서 검증** |
| 07:24:01 | `ssm:GetCommandInvocation` (성공) | IAMUser | 165.132.5.130 | 🔴 명령 출력(자격증명) 회수 |
| **07:24:02** | **`ec2:DescribeInstances`** | **AssumedRole (인스턴스 역할)** | **165.132.5.130** | 🔴 **③ 훔친 권한으로 정찰 수행** |
| 07:24:09 | `ssm:ListInstanceAssociations` | AssumedRole (SSM 에이전트) | 43.202.133.180 | 🟡 인스턴스 내부 정상 동작 (대조군) |
| 07:24:29~07:25:33 | `TerminateInstances`, `Delete*` 다수 | IAMUser (Terraform) | 165.132.5.130 | 🟡 Cleanup |

### 4.2 결정적 증거 — 같은 인스턴스, 두 개의 IP

`i-06d1d3cface560abe` 인스턴스의 역할 자격증명이 **두 곳에서** 쓰였다:

| accessKeyId | 사용 IP | ec2RoleDelivery | User-Agent | 판정 |
|---|---|---|---|---|
| `ASIA52CDAKM45NGY7PUU` | `43.202.133.180` (인스턴스 자신) | **2.0** | `amazon-ssm-agent/3.3.4624.0` | ✅ 정상 |
| `ASIA52CDAKM45QARZ7EW` | `43.202.133.180` | **2.0** | `amazon-ssm-agent` | ✅ 정상 |
| **`ASIA52CDAKM456D2HKTH`** | **`165.132.5.130`** (외부) | **1.0** | `aws-sdk-go-v2/1.24.1` | 🔴 **탈취됨** |

**"인스턴스에 발급된 자격증명이 인스턴스의 IP가 아닌 곳에서 쓰였다"** — 이것이 이 공격의 시그니처다. 실제로 GuardDuty의 `InstanceCredentialExfiltration` 탐지도 정확히 이 논리를 사용한다.

### 4.3 핵심 필드 — `GetCallerIdentity` 레코드 전문 발췌

```json
{
  "eventTime": "2026-08-21T07:24:01Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "GetCallerIdentity",
  "sourceIPAddress": "165.132.5.130",              // ← 인스턴스 IP가 아님!
  "userAgent": "aws-sdk-go-v2/1.24.1 os/linux ... api/sts#1.26.2",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::949328302905:assumed-role/stratus-red-team-ec2-steal-credentials-role/i-06d1d3cface560abe",
    "accessKeyId": "ASIA52CDAKM456D2HKTH",
    "sessionContext": {
      "sessionIssuer": { "userName": "stratus-red-team-ec2-steal-credentials-role" },
      "ec2RoleDelivery": "1.0"                     // ← IMDSv1으로 받아간 자격증명
    },
    "inScopeOf": {
      "issuerType": "AWS::EC2::Instance",
      "credentialsIssuedTo": "arn:aws:ec2:ap-northeast-2:949328302905:instance/i-06d1d3cface560abe"
    }
  }
}
```

세 필드가 결정적이다.

- **`userIdentity.arn`의 세션명이 `i-`로 시작** → 이 자격증명은 EC2 인스턴스에 발급된 것이다. 세션명이 곧 인스턴스 ID다.
- **`inScopeOf.credentialsIssuedTo`** → CloudTrail이 "이 키는 어느 인스턴스 것인지"를 ARN으로 명시해 준다. 여기서 나온 인스턴스 ID로 실제 인스턴스의 IP를 조회해 `sourceIPAddress`와 비교하면 탈취 여부가 바로 나온다.
- **`sessionContext.ec2RoleDelivery`** → `1.0` = IMDSv1, `2.0` = IMDSv2. 이 로그에서 정상 SSM 에이전트는 `2.0`인데 탈취된 세션만 `1.0`이다. Stratus의 탈취 스크립트가 IMDSv1 방식으로 curl 했기 때문이다. **인스턴스에 IMDSv2를 강제(`HttpTokens=required`)했다면 이 요청 자체가 실패했을 것이다.**

### 4.4 시그널 vs 노이즈

183건 중 **실제 공격은 8건뿐**이다 (4.4%).

| 구분 | 건수 | 비율 | 판별 기준 (User-Agent) |
|---|---|---|---|
| 🔴 **공격 도구 호출** — `DescribeAccountAttributes`×2, `DescribeInstanceInformation`, `SendCommand`, `GetCommandInvocation`×2 | 6 | 3.3% | `stratus-red-team_<uuid>` |
| 🔴 **탈취한 자격증명 사용** — `GetCallerIdentity`, `DescribeInstances` | 2 | 1.1% | `aws-sdk-go-v2/1.24.1` |
| 🟡 Warm-up / Cleanup | 149 | 81.4% | `terraform-provider-aws/3.76.1` |
| 🟡 AWS 서비스 자체 이벤트 | 12 | 6.6% | `ec2.amazonaws.com`, `cloudtrail.amazonaws.com`, `resource-explorer-2` |
| 🟡 SSM 에이전트 (인스턴스 내부 정상 동작) | 5 | 2.7% | `amazon-ssm-agent/3.3.4624.0` |
| 🔧 트레일 준비 (Root 콘솔 작업) | 9 | 4.9% | `Mozilla/5.0 ... Chrome/150` |

오류 이벤트는 13건이며, 대부분 IAM 전파 지연으로 인한 `RunInstances` 재시도(4건)와 리전에서 지원하지 않는 ClassicLink 조회(4건)다. 공격과 무관한 양성 노이즈다.

**연구용으로 이 로그를 쓸 때 주의점:** Warm-up 노이즈를 제거하려면 `userAgent`가 Terraform인 레코드를 필터링하면 된다. 다만 실제 침해 상황에서는 공격자도 인프라를 만들기 때문에, 이 필터링은 "실습 로그 정제" 목적으로만 유효하다.

또 하나 짚을 점: **`SendCommand`의 `requestParameters.parameters`가 `HIDDEN_DUE_TO_SECURITY_REASONS`로 마스킹**되어 있다. 즉 CloudTrail만 봐서는 **인스턴스에서 무슨 명령이 실행됐는지 알 수 없다.** 실제 명령 내용을 보려면 SSM 세션 로깅(S3/CloudWatch Logs)을 별도로 켜야 한다.

---

## 5. 탐지

### 5.1 탐지 포인트 우선순위

| 우선순위 | 탐지 로직 | 오탐 가능성 |
|---|---|---|
| **최상** | `userIdentity.arn`의 세션명이 `i-*`인데 `sourceIPAddress`가 해당 인스턴스의 공인/사설 IP와 불일치 | 매우 낮음 |
| 상 | `inScopeOf.issuerType == "AWS::EC2::Instance"` 인데 `sourceIPAddress`가 AWS IP 대역 밖 | 낮음 (VPC 엔드포인트 미사용 시 주의) |
| 중 | `ec2RoleDelivery == "1.0"` (IMDSv1 사용 세션) | 중간 — 레거시 앱이 v1을 쓸 수 있음 |
| 중 | `ssm:SendCommand` + `documentName == "AWS-RunShellScript"` 를 평소 쓰지 않는 주체가 호출 | 중간 — 운영팀도 사용 |
| 참고 | 인스턴스 역할 세션의 User-Agent가 갑자기 바뀜 (`amazon-ssm-agent` → `aws-sdk-go-v2`) | 중간 |

### 5.2 GuardDuty (가장 실용적)

이 기법은 GuardDuty가 **기본으로 탐지**한다. 별도 룰 작성 없이 활성화만 하면 된다.

- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
  → 인스턴스 자격증명이 **AWS 밖 IP**에서 사용됨 (이 로그가 해당)
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
  → 인스턴스 자격증명이 **다른 AWS 계정**에서 사용됨

### 5.3 Sigma 룰

```yaml
title: EC2 Instance Role Credentials Used Outside The Instance
id: 8f1a0c2e-4b3d-4c9a-9b1a-ec2credtheft001
status: experimental
description: |
  EC2 인스턴스에 발급된 임시 자격증명(세션명이 인스턴스 ID)이
  해당 인스턴스가 아닌 소스 IP에서 사용된 경우를 탐지한다.
logsource:
  product: aws
  service: cloudtrail
detection:
  ec2_role_session:
    userIdentity.type: 'AssumedRole'
    userIdentity.sessionContext.ec2RoleDelivery|exists: true
  # 인스턴스 자신의 IP 목록은 자산 인벤토리에서 동적으로 채워야 한다.
  known_instance_ips:
    sourceIPAddress:
      - '10.*'
      - '172.16.*'
      - '192.168.*'
  aws_internal:
    sourceIPAddress|endswith: '.amazonaws.com'
  condition: ec2_role_session and not (known_instance_ips or aws_internal)
falsepositives:
  - VPC 엔드포인트를 쓰지 않고 NAT 게이트웨이를 통해 나가는 정상 워크로드
    (이 경우 소스 IP가 NAT의 EIP로 보임 — NAT EIP를 화이트리스트에 추가할 것)
  - 인스턴스에서 실행되는 정상 자동화 도구
level: high
```

```yaml
title: SSM SendCommand Used To Run Shell Script
id: 3c9d7e11-2a5f-4e88-b0c1-ssmsendcmd0001
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'SendCommand'
    requestParameters.documentName:
      - 'AWS-RunShellScript'
      - 'AWS-RunPowerShellScript'
  condition: selection
falsepositives:
  - 운영팀의 정상 원격 운영 작업 (승인된 주체 목록으로 필터링 필요)
level: medium
```

### 5.4 Athena 쿼리 (CloudTrail 로그가 S3에 있을 때)

```sql
-- 인스턴스 역할 세션이 인스턴스 밖에서 쓰인 정황
SELECT
    eventtime,
    eventsource,
    eventname,
    sourceipaddress,
    useragent,
    useridentity.arn                         AS role_session,
    useridentity.sessioncontext.ec2roledelivery AS imds_version
FROM cloudtrail_logs
WHERE useridentity.type = 'AssumedRole'
  AND useridentity.sessioncontext.ec2roledelivery IS NOT NULL
  -- 인스턴스는 보통 사설 IP나 자기 EIP로 나간다
  AND sourceipaddress NOT LIKE '10.%'
  AND sourceipaddress NOT LIKE '172.%'
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
ORDER BY eventtime;
```

```sql
-- IMDSv1으로 발급된 자격증명 세션 전수 조사 (IMDSv2 전환 대상 파악)
SELECT
    useridentity.sessioncontext.sessionissuer.username AS role_name,
    useridentity.accesskeyid,
    MIN(eventtime) AS first_seen,
    COUNT(*)       AS calls
FROM cloudtrail_logs
WHERE useridentity.sessioncontext.ec2roledelivery = '1.0'
GROUP BY 1, 2
ORDER BY calls DESC;
```

### 5.5 CloudWatch Logs Insights

```
fields @timestamp, eventName, sourceIPAddress, userIdentity.arn, userAgent
| filter userIdentity.type = "AssumedRole"
| filter ispresent(userIdentity.sessionContext.ec2RoleDelivery)
| filter userIdentity.arn like /assumed-role\/.*\/i-/
| stats count() as calls,
        earliest(@timestamp) as first,
        latest(@timestamp)   as last
    by userIdentity.accessKeyId, sourceIPAddress, userAgent
| sort calls desc
```

> 한 `accessKeyId`가 **두 개 이상의 소스 IP**에서 나타나면 그 자체로 강한 의심 신호다.

---

## 6. 오탐(False Positive) 주의사항

- **NAT 게이트웨이 / 프록시:** 프라이빗 서브넷 인스턴스는 NAT의 EIP로 나가므로 `sourceIPAddress`가 인스턴스 IP와 다르게 보인다. NAT EIP 목록을 화이트리스트에 넣어야 한다.
- **VPC 엔드포인트:** 엔드포인트를 통하면 `vpcEndpointId` 필드가 붙고 소스 IP가 사설 IP로 보인다. 이 로그 183건 중 `vpcEndpointId`가 붙은 레코드는 1건뿐이며, 나머지는 전부 인터넷(NAT/IGW) 경유였다.
- **`ec2RoleDelivery: 1.0` 단독 사용 금지:** 오래된 SDK나 레거시 애플리케이션이 IMDSv1을 쓰는 경우가 흔하다. 반드시 IP 불일치와 **AND 조건**으로 묶을 것.
- **`SendCommand` 단독 사용 금지:** 정상 운영 자동화에서 매우 흔하다.

---

## 7. 완화 방안

| 조치 | 효과 | 방법 |
|---|---|---|
| **IMDSv2 강제** ⭐ | SSRF 계열 탈취 사실상 차단 | 인스턴스 메타데이터 옵션 `HttpTokens=required`, `HttpPutResponseHopLimit=1` |
| IMDS 자체 비활성화 | 역할이 필요 없는 인스턴스는 완전 차단 | `HttpEndpoint=disabled` |
| SCP로 IMDSv1 강제 차단 | 계정 전체에 일괄 적용 | `ec2:RunInstances` 조건에 `ec2:MetadataHttpTokens: required` |
| 역할 권한 최소화 | 탈취되어도 피해 최소화 | 인스턴스 프로파일에 광범위한 `*` 권한 부여 금지 |
| IAM 조건 키로 출처 제한 | 인스턴스 밖 사용 원천 차단 | 역할 정책에 `aws:SourceVpc` / `aws:VpcSourceIp` / `ec2:SourceInstanceARN` 조건 추가 |
| GuardDuty 활성화 | 탐지 | 리전별 활성화 + Security Hub 연동 |
| SSM 세션/명령 로깅 | `SendCommand` 내용 가시화 | Run Command 출력을 S3/CloudWatch Logs로 전송 설정 |

> ⭐ **가장 중요:** IMDSv2 강제 하나만 제대로 해도 이 기법의 대부분 경로가 막힌다. 신규 인스턴스는 AWS가 기본값으로 v2를 요구하도록 바꾸고 있지만, **기존 인스턴스와 AMI/Launch Template은 직접 확인해야 한다.**

---

## 8. 참고 자료

- [Stratus Red Team — Steal EC2 Instance Credentials](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/)
- [MITRE ATT&CK T1552.005 — Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- [AWS 문서 — Use IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS GuardDuty — InstanceCredentialExfiltration findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Capital One 침해 사고 분석 (SSRF → IMDSv1)](https://linuxcent.com/ssrf-cloud-metadata-imds-capital-one/)
