# 침해된 EC2에서의 계정 정찰 (Execute Discovery Commands on an EC2 Instance)

> 대상 로그: `aws.discovery.ec2-enumerate-from-instance.json`
> 원본: `raw_log/` 병합 후 시간 구간으로 분리
> 생성 도구: [Stratus Red Team](https://stratus-red-team.cloud/) — `aws.discovery.ec2-enumerate-from-instance`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| MITRE ATT&CK | **T1580** Cloud Infrastructure Discovery / **T1526** Cloud Service Discovery |
| 전술 | Discovery (정찰) |
| 로그 레코드 수 | 271건 (실습 lifecycle 전체 + 배경 노이즈) |
| 시간 범위 | `05:18:19Z` ~ `05:29:45Z` (KST 14:18~14:29) |
| 공격 주체 | IAMUser `Huge-log-attack-simulation` (도구 조작) → **인스턴스 역할** (실제 정찰) |
| 대상 인스턴스 | `i-0b858e5a6b06ca2b9` (첫 시도 `i-0aa5b3cd5bbead71c`는 실패) |
| 인스턴스 역할 | `stratus-red-team-ec2-enumerate-role` |
| 정찰 크리덴셜 | `ASIA52CDAKM4X7BTXZVJ` (인스턴스 IP `54.116.28.21`에서 사용) |
| **결정적 이벤트** | 인스턴스 역할로 실행된 `GetCallerIdentity`(성공) + `ListBuckets`/`ListRoles`/`ListUsers`(전부 AccessDenied) |

**한 줄 요약:** 침해된 EC2 안에서 그 인스턴스의 역할 크리덴셜로 계정을 훑는다. CloudTrail에는 **인스턴스가 스스로 정찰하는** 형태(`arn`이 `i-*`로 끝남)로 남는다. 이번엔 역할에 권한이 없어 대부분 AccessDenied가 났고, 그 **거부 버스트 자체가 정찰 시그니처**다.

---

## 2. 공격 기법 설명

### 2.1 원리

공격자가 EC2에 발판을 잡으면(SSRF·RCE·SSH 등), 그 인스턴스에 붙은 IAM 역할 크리덴셜을 IMDS에서 꺼내 계정을 정찰한다. `sts:GetCallerIdentity`(나는 누구인가) → `iam:ListRoles`/`ListUsers`(누가 있나) → `s3:ListBuckets`(무엇이 있나) 순으로 지형을 파악한다.

핵심은 **이 호출들이 인스턴스 역할의 자격으로 실행**된다는 점이다. CloudTrail의 `userIdentity.arn`이 이렇게 찍힌다.

```
arn:aws:sts::949328302905:assumed-role/stratus-red-team-ec2-enumerate-role/i-0b858e5a6b06ca2b9
                                                                            └── 세션명 = 인스턴스 ID
```

세션명이 인스턴스 ID라는 것 = "이 API를 부른 주체는 사람이 아니라 EC2 인스턴스"라는 뜻이다.

### 2.2 그래프 관점에서 왜 중요한가 (체인의 앵커)

이 기법은 옵션 2 킬체인의 **Discovery 단계**이자, v3 스키마의 크리덴셜 계보 엣지가 걸리는 지점이다.

```
instance(i-0b858e5a6b06ca2b9)
   └─BOUND_TO─ Credential(ASIA52CDAKM4X7BTXZVJ)   ← inScopeOf.credentialsIssuedTo
                     └─PERFORMED─ GetCallerIdentity / ListRoles / ...
```

즉 "인스턴스 → 크리덴셜 → 정찰 이벤트"가 하나의 경로로 이어진다. 앞 단계(자격증명 탈취)에서 훔친 크리덴셜을 여기서 쓰면 방향성 체인이 완성되는 구조다.

### 2.3 이번 실행의 특징 — 정찰이 전부 실패했다

Stratus의 이 기법은 **일부러 권한 없는 역할**을 만든다. 그래서 `GetCallerIdentity`만 성공하고 나머지는 전부 `AccessDenied`가 난다. 이건 버그가 아니라 의도된 설계이며, 두 가지를 시사한다.

- **탐지 관점:** 한 주체가 짧은 시간에 여러 서비스에 걸쳐 열거를 시도하고 **연속으로 AccessDenied**를 받는 것 자체가 정찰의 강한 신호다. flaws.cloud 로그에서 98.9%가 실패였던 것과 같은 맥락이다.
- **체인 관점:** 실제 킬체인을 만들려면 이 역할에 읽기 권한을 부여해야 정찰이 성공하고 다음 단계로 이어진다. (지금은 학습용 standalone이라 실패해도 무방)

---

## 3. Stratus Red Team이 실제로 한 일

### Warm-up
1. IAM 역할 `stratus-red-team-ec2-enumerate-role` 생성 (권한 없음, 신뢰 주체 `ec2.amazonaws.com`)
2. VPC·인스턴스 프로파일·EC2 인스턴스 기동, SSM 등록 대기

### Detonation
3. `ssm:SendCommand`(`AWS-RunShellScript`)로 인스턴스 안에서 정찰 스크립트 실행 → 스크립트가 인스턴스 역할로 `GetCallerIdentity`, `ListBuckets`, `ListRoles`, `ListUsers`, `GetAccountSummary`, `GetAccountAuthorizationDetails` 호출

> ⚠️ **첫 detonate는 실패했다.** `05:18:21Z` `SendCommand`가 `InvalidInstanceId: Instances not in a valid state`로 거부됨 — SSM 에이전트 등록 전이었기 때문(사용자가 겪은 그 오류). 인스턴스를 정리하고 재실행해 `05:27:23Z`에 성공했다. 이 로그에는 **실패한 첫 시도와 성공한 재시도가 모두** 들어 있다.

---

## 4. 로그 타임라인 분석

### 4.1 주요 흐름

| 시각 (UTC) | 이벤트 | 주체/UA | 의미 |
|---|---|---|---|
| 05:18:21 | `ssm:SendCommand` (`InvalidInstanceId`) | stratus | 🔴 **첫 detonate 실패** (에이전트 미등록) |
| 05:18:36 | `ssm:RegisterManagedInstance` (`i-0aa5b3cd`) | ssm-agent | 🟡 첫 인스턴스가 뒤늦게 등록 |
| 05:18:55~05:19:47 | `TerminateInstances`, `DeleteVpc` 등 | Terraform | 🟡 첫 인스턴스 정리 |
| 05:19:03~05:20:46 | `DeleteBucket`, `LookupEvents`, `DeleteTrail`, `DescribeTrails` 등 | **console (jjsworkspace)** | ⚪ 사용자가 콘솔에서 조작한 배경 노이즈 |
| 05:23:53 | `ec2:DescribeAccountAttributes` | stratus | 🔴 재-warmup 시작 |
| 05:24:22 | **`iam:CreateRole`** (`ec2-enumerate-role`) | Terraform | 🟡 권한 없는 정찰 역할 생성 |
| 05:24:39 | `RunInstances` → `i-0b858e5a6b06ca2b9` | Terraform | 🟡 정찰 대상 인스턴스 (앞선 4회는 IAM 전파지연으로 실패) |
| 05:26:50 | `ssm:RegisterManagedInstance` (`i-0b858e...`) | ssm-agent | 🟡 이번엔 정상 등록 |
| **05:27:23** | **`ssm:SendCommand`** | **stratus** | 🔴🔴 **detonate 성공** |
| **05:27:32** | `sts:GetCallerIdentity` (성공) | **인스턴스 역할** | 🔴 "나는 누구인가" |
| **05:27:33~38** | `ListBuckets`,`GetAccountSummary`,`ListRoles`,`ListUsers`,`GetAccountAuthorizationDetails` (전부 **AccessDenied**) | **인스턴스 역할** | 🔴 정찰 시도 → 권한 거부 버스트 |

### 4.2 결정적 이벤트 — 인스턴스 역할의 정찰

```json
{
  "eventTime": "2026-08-31T05:27:36Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "ListRoles",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "54.116.28.21",
  "userAgent": "aws-cli/1.18.147 Python/... (인스턴스 내부 실행)",
  "errorCode": "AccessDenied",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::949328302905:assumed-role/stratus-red-team-ec2-enumerate-role/i-0b858e5a6b06ca2b9",
    "accessKeyId": "ASIA52CDAKM4X7BTXZVJ",
    "sessionContext": { "sessionIssuer": { "userName": "stratus-red-team-ec2-enumerate-role" } }
  }
}
```

**세 가지를 보라.**

1. `arn`의 세션명이 `i-0b858e5a6b06ca2b9` → 인스턴스가 주체. 세션명=인스턴스ID.
2. `sourceIPAddress` `54.116.28.21` → **인스턴스 자신의 egress IP** (도구 조작 IP `165.132.5.130`이 아님). 정찰이 인스턴스 내부에서 실행됐다는 증거.
3. `errorCode: AccessDenied` → 권한 없는 역할. 이 거부가 여러 서비스에 걸쳐 연속으로 나는 것이 시그니처.

### 4.3 시그널 vs 노이즈

| 구분 | 건수 | 비율 | 판별 |
|---|---|---|---|
| 🔴 인스턴스 역할 정찰 (`GetCallerIdentity`+거부 5건) | 6 | 2.2% | `arn`에 `enumerate-role/i-*` |
| 🔴 도구 조작 (`SendCommand`,`GetCommandInvocation`,`DescribeAccountAttributes`) | 8 | 3.0% | UA `stratus-red-team` |
| 🟡 Warm-up/Cleanup (Terraform) | 170 | 62.7% | UA `terraform-provider-aws` |
| 🟡 SSM 에이전트 정상 동작 | 12 | 4.4% | UA `amazon-ssm-agent` |
| ⚪ 콘솔 배경 노이즈 (사용자 수동 조작) | 54 | 19.9% | UA `Mozilla`, `jjsworkspace` |
| ⚪ AWS 서비스 이벤트 | 21 | 7.7% | `ec2.amazonaws.com`, `resource-explorer-2` |

오류 31건 중 대부분은 `RunInstances` IAM 전파지연 재시도(4건)와 ClassicLink 미지원(2건), 그리고 **정찰 AccessDenie 5건**이다. 마지막 5건만이 공격 신호다.

> **주의:** 콘솔 노이즈(54건)에 `DeleteBucket`, `DeleteTrail`, `LookupEvents`가 섞여 있다. 이건 사용자가 실습 중 콘솔에서 만진 것으로 공격과 무관하다. standalone 학습 로그의 현실적 한계다.

---

## 5. 탐지

### 5.1 탐지 포인트

| 우선순위 | 로직 |
|---|---|
| **최상** | 인스턴스 역할(`arn`이 `i-*`로 끝남)이 **여러 서비스에 걸쳐 열거 API를 호출**하고 **AccessDenied 버스트** 발생 |
| 상 | 인스턴스 역할이 평소 하지 않던 `iam:List*`, `s3:ListBuckets`, `GetAccountAuthorizationDetails` 호출 |
| 상 | `SendCommand`(`AWS-RunShellScript`) 직후 인스턴스 역할의 이례적 API 급증 |
| 중 | 인스턴스 역할 크리덴셜이 인스턴스 IP가 아닌 곳에서 사용 (탈취 후 외부 정찰) |

### 5.2 Sigma 룰

```yaml
title: EC2 Instance Role Performing Account Enumeration
id: aa11bb22-enum-from-instance-0001
status: experimental
logsource: { product: aws, service: cloudtrail }
detection:
  instance_role:
    userIdentity.arn|re: 'assumed-role/.+/i-[0-9a-f]+$'
  recon_calls:
    eventName:
      - 'GetCallerIdentity'
      - 'ListRoles'
      - 'ListUsers'
      - 'ListBuckets'
      - 'GetAccountSummary'
      - 'GetAccountAuthorizationDetails'
      - 'GetAccountAuthorizationDetails'
  condition: instance_role and recon_calls | count(eventName) by userIdentity.arn > 3
  timeframe: 5m
falsepositives:
  - 인스턴스에서 도는 정상 인벤토리/모니터링 에이전트 (역할 화이트리스트)
level: high
```

### 5.3 Athena 쿼리

```sql
-- 인스턴스 역할의 열거 + 거부 버스트
SELECT useridentity.arn AS instance_role,
       sourceipaddress,
       count(*) AS calls,
       count_if(errorcode = 'AccessDenied') AS denied,
       array_agg(DISTINCT eventname) AS actions
FROM cloudtrail_logs
WHERE regexp_like(useridentity.arn, 'assumed-role/.+/i-[0-9a-f]+$')
  AND eventname IN ('GetCallerIdentity','ListRoles','ListUsers','ListBuckets',
                    'GetAccountSummary','GetAccountAuthorizationDetails')
GROUP BY 1,2
HAVING count(*) > 3
ORDER BY denied DESC;
```

---

## 6. 완화 방안

| 조치 | 내용 |
|---|---|
| **인스턴스 역할 최소권한** ⭐ | 정찰에 쓰이는 `iam:List*`, `GetAccountAuthorizationDetails` 등을 인스턴스 역할에서 제거 |
| IMDSv2 강제 | 크리덴셜 탈취 경로 차단 (`HttpTokens=required`) |
| GuardDuty | `Discovery:IAMUser/AnomalousBehavior`, `Recon:IAMUser/*` |
| CloudTrail Insights | 이례적 API 호출량 급증 자동 탐지 |
| 세션 조건 제한 | 역할 정책에 `aws:SourceVpc`/`aws:VpcSourceIp` 조건으로 인스턴스 밖 사용 차단 |

---

## 7. 참고 자료

- [Stratus Red Team — Execute Discovery Commands on an EC2 Instance](https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/)
- [MITRE ATT&CK T1580 — Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
- [MITRE ATT&CK T1526 — Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
