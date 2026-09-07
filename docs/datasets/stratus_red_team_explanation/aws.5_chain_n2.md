# 5단계 크로스계정 데이터 탈취 킬체인 (노이즈 병행) — aws.5_chain_n2

> 대상 로그: `log_json/aws.5_chain_n2.json`
> 생성: `shell code/aws.5_chain_n2_execute_with_noise.sh` (노이즈 A/B 병행 + 공격 5단계 자동)
> 원본: `raw_log/` 의 CloudTrail 파일 12개 병합 (중복 eventID 제거, 배경 이벤트 전부 보존)
> 실행 가이드: `execution_aws.5_chain_a.md`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| 성격 | **단일 크리덴셜 스파인 + 크로스계정 엣지**로 엮은 APT 체인 (SCARLETEEL형) + 정상 노이즈 |
| 레코드 수 | **165건** (관리 165 / **데이터 0**), 중복 0, 오류 0 |
| 시간 범위 | `2026-09-07T05:22:03Z` ~ `05:44:12Z` (약 22분) |
| 공격 창 | `05:30:08Z`(SendCommand) ~ `05:32:56Z`(DeleteFlowLogs) (**약 3분**) |
| AWS 계정 | `949328302905` / 리전 `ap-northeast-2`(+us-east-1) |
| 공격자 단말 IP | `165.132.5.130` |
| 인스턴스 egress IP | `13.209.144.16` |
| 인스턴스 | `i-07eec8fec13e5ed60` |
| **크리덴셜 스파인** | `ASIA52CDAKM4RSR5IOBD` **1개** (탈취한 인스턴스 역할) |
| **크로스계정 대상** | 스냅샷 `snap-0ecc18035701ed34e` → **외부 계정 `012345678912`** |

**한 줄 요약:** 인스턴스 역할 크리덴셜(단 하나)을 훔쳐 시크릿 20개를 덤프하고, 디스크 스냅샷을 외부 계정으로 공유한 뒤 VPC 플로우로그를 삭제한다. n1(2-크리덴셜, 데이터이벤트)과 달리 **하나의 크리덴셜이 fan-out하고 계정 밖으로 나가는 엣지**가 핵심이며, 전부 관리 이벤트다.

---

## 2. n1과의 차이 (왜 별도 데이터셋인가)

| | 체인 n1 | **체인 n2 (이 문서)** |
|---|---|---|
| 크리덴셜 스파인 | **2개** (ASIA → CreateAccessKey → AKIA) | **1개** (ASIA 하나가 전부) |
| 그래프 모양 | 2-크리덴셜 방향성 사슬 | **1-크리덴셜 fan-out + 크로스계정 엣지** |
| 3단계 | create-admin-user (권한상승) | **secretsmanager 시크릿 덤프** |
| 4단계 | cloudtrail-stop | **ec2-share-ebs-snapshot (외부계정)** ★ |
| 5단계 | s3-ransomware (데이터이벤트) | **vpc-remove-flow-logs** |
| 데이터 이벤트 | 필요 | **불필요 (0건)** |

공유하는 것은 1·2단계(탈취·정찰)와 "훔친 크리덴셜로 실행"이라는 뼈대뿐이다.

---

## 3. 크리덴셜 스파인 — 단일 크리덴셜 fan-out

모든 악성 이벤트가 **같은 accessKeyId `ASIA52CDAKM4RSR5IOBD`**를 공유한다. 권한상승(2번째 키) 없이 하나의 크리덴셜이 정찰·시크릿·탈취·회피를 전부 수행한다.

```
instance(i-07eec8fec13e5ed60)
   └─BOUND_TO─ Cred①(ASIA52CDAKM4RSR5IOBD, 탈취한 인스턴스 역할)
                 ├─ [정찰]      GetCallerIdentity, ListSecrets, DescribeSnapshots, DescribeFlowLogs
                 ├─ [시크릿탈취] GetSecretValue ×20 ─TARGETS─▶ secret 노드들
                 ├─ [탈취]      ModifySnapshotAttribute ─TARGETS─▶ snap-0ecc18035701ed34e
                 │                                         └─TARGETS─▶ 외부계정(012345678912) ★ cross-account
                 └─ [회피]      DeleteFlowLogs ─TARGETS─▶ fl-058f80ae06dddb80a
```

### 공격 타임라인 (실측, spine 키 @ 공격자 IP 165.132.5.130)

| 시각 (UTC) | 이벤트 | 단계 |
|---|---|---|
| 05:30:08 | `ssm:SendCommand` (operator 키) | 1 탈취 트리거 |
| 05:31:19 | `sts:GetCallerIdentity` | 2 정찰 시작 |
| 05:31:22~36 | `ListSecrets` ×4, `DescribeSnapshots`, `DescribeFlowLogs` | 2 정찰 |
| 05:31:38~05:32:47 | **`GetSecretValue` ×20** | 3 시크릿 전수 탈취 |
| **05:32:51** | **`ModifySnapshotAttribute`** → 외부 계정 공유 | 4 크로스계정 탈취 ★ |
| **05:32:56** | **`DeleteFlowLogs`** | 5 회피 |

`GetSecretValue`가 **약 70초 안에 20건** 연속으로 나는 것이 "전 시크릿을 훑는" 공격 패턴이다. accessKeyId는 전부 ASIA 하나.

---

## 4. ⭐ 결정적 신호 — 같은 크리덴셜, 두 IP

이번엔 노이즈 A(인스턴스 자기 크리덴셜 루프)가 제대로 돌아, 대비가 선명하다.

```
ASIA52CDAKM4RSR5IOBD 가 사용된 IP:
  13.209.144.16   ← 인스턴스 egress (정상)   70건
     GetCallerIdentity×62(노이즈A 루프) + SSM 에이전트(UpdateInstanceInformation, ListInstanceAssociations)
  165.132.5.130   ← 공격자 단말 (탈취)      29건
     GetSecretValue×20, ListSecrets×4, ModifySnapshotAttribute, DeleteFlowLogs, Describe*, GetCallerIdentity
```

같은 인스턴스 역할 세션 키가 **인스턴스 IP에서 정상 사용**되는 동시에 **공격자 단말에서 악용**된다. 크리덴셜 노드 하나에 매달린 이벤트가 소스 IP로 갈라지는 것이 탐지 앵커 — v3가 ground-truth로 검증한 형태이며, n2에서는 정상 baseline(70건)이 두꺼워 더 현실적이다.

---

## 5. 신원/역할 구성 (165건 분해)

| 신원 | 건수 | accessKeyId | 역할 |
|---|---|---|---|
| 인스턴스역할 `/i-07eec8fec13e5ed60` | 130 | `ASIA…RSR5IOBD` (외 다수) | 🔴 **공격 스파인**(정찰·시크릿·탈취·회피) 🟡 **+ 노이즈A**(GetCallerIdentity×62, 인스턴스 IP) + SSM 하트비트 |
| `Huge-log-attack-simulation` | 13 | `AKIA…W5UHPSX2` | 🟡 operator/harness — SendCommand(탈취 트리거)×2, GetCommandInvocation 등 |
| `jjsworkspace` | 13 | SSO ASIA | ⚪ 콘솔 배경 — `ListManagedNotificationEvents`×13 |
| `AWSService` | 6 | None | ⚪ 서비스 이벤트 — AssumeRole×4, GetBucketAcl×2 |
| ResourceExplorer 역할 | 3 | ASIA | ⚪ AWS 자동 인덱싱 |

> ℹ️ 이번 노이즈는 **A(인스턴스 크리덴셜 baseline)가 강하게 실렸다**(62건). 반면 노이즈 B(정상 운영자 describe/시크릿 조회)는 로그에 거의 안 보인다 — jjsworkspace는 콘솔 폴링뿐. B를 두껍게 하려면 OPS_PROFILE에 `secretsmanager:GetSecretValue`·`ec2:Describe*` 권한을 주고 `OPS_INTERVAL`을 낮춰 재실행하면 된다.

---

## 6. 이벤트 구성 (관리 이벤트만, 데이터 0)

| eventName | 건수 | 성격 |
|---|---|---|
| `GetCallerIdentity` | 74 | 🟡 노이즈A(인스턴스)×62 + 🔴 공격 정찰 ×1 + operator 등 |
| `GetSecretValue` | 20 | 🔴 시크릿 전수 탈취 |
| `ListManagedNotificationEvents` | 13 | ⚪ 콘솔 배경 |
| `ListSecrets` | 4 (+정찰) | 🔴 시크릿 열거 |
| `UpdateInstanceInformation` / `ListInstanceAssociations` | 8 | 🟡 SSM 에이전트(인스턴스 IP) |
| `SendCommand` / `GetCommandInvocation` | 5 | 🟡 탈취 트리거·폴링 |
| `ModifySnapshotAttribute` | 1 | 🔴🔴 **크로스계정 스냅샷 공유** |
| `DeleteFlowLogs` | 1 | 🔴 회피 |
| 나머지(DescribeSnapshots/FlowLogs/Volumes, AssumeRole 등) | — | 정찰·서비스 |

**데이터 이벤트 0건** — 설계대로 전부 관리 이벤트라 트레일에 데이터 이벤트를 안 켜도 완전하다.

---

## 7. 결정적 이벤트 — 크로스계정 공유

```json
{
  "eventTime": "2026-09-07T05:32:51Z",
  "eventName": "ModifySnapshotAttribute",
  "eventSource": "ec2.amazonaws.com",
  "sourceIPAddress": "165.132.5.130",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::949328302905:assumed-role/stratus-red-team-ec2-steal-credentials-role/i-07eec8fec13e5ed60",
    "accessKeyId": "ASIA52CDAKM4RSR5IOBD"
  },
  "requestParameters": {
    "snapshotId": "snap-0ecc18035701ed34e",
    "attributeType": "CREATE_VOLUME_PERMISSION",
    "createVolumePermission": { "add": { "items": [ { "userId": "012345678912" } ] } }   // ★ 외부 계정
  }
}
```

`createVolumePermission.add.userId = 012345678912`가 **계정 밖으로 나가는 엣지**다. 그래프에서 이 외부 계정을 노드로 만들면 "데이터가 조직 경계를 넘는" 경로가 드러난다(v3의 `recipientAccountId`/크로스계정 설계).

---

## 8. 그래프 변환 시 기대 구조 & 검증 쿼리

```cypher
// 단일 크리덴셜 fan-out + 크로스계정
MATCH (i:Entity {entityType:'instance'})<-[:BOUND_TO]-(c:Actor {id:'ASIA52CDAKM4RSR5IOBD'})
MATCH (c)-[:PERFORMED]->(e:Event)-[:TARGETS]->(t:Entity)
WHERE e.eventName IN ['GetSecretValue','ModifySnapshotAttribute','DeleteFlowLogs']
RETURN c,e,t;

// 같은 키, 두 IP (탈취 판별)
MATCH (c:Actor {id:'ASIA52CDAKM4RSR5IOBD'})-[:PERFORMED]->(e:Event)
RETURN DISTINCT e.sourceIP;   // 13.209.144.16 와 165.132.5.130 둘 다
```

```
instance ─BOUND_TO─ Cred①(ASIA) ─▶ GetSecretValue ×20 ─▶ secret 노드들
                              ├─▶ ModifySnapshotAttribute ─▶ snapshot + 외부계정(012345678912) ★
                              └─▶ DeleteFlowLogs ─▶ flow-log
              (같은 키가 인스턴스 IP 13.209.144.16 에서도 PERFORMED = 노이즈A/SSM)  ← 탈취 판별 앵커
```

공격 이벤트 `accessKeyId`가 **전부 ASIA 하나**(n1은 ASIA→AKIA 2개)인 것이 단일 스파인의 증거. 외부 계정 ID가 `requestParameters`에 등장하는 것이 크로스계정 신호.

---

## 9. 참고
- 실행/재현: `execution_aws.5_chain_a.md`, `shell code/` (aws.5_chain_n2_execute_with_noise.sh + noise_*_chain_a.sh)
- 비교 데이터셋: `detail_md/aws.5_chain_n1.md` (2-크리덴셜, 데이터이벤트, 계정 내부)
- 개별 기법 상세: `detail_md/` 의 steal-instance-credentials, ec2-enumerate-from-instance, ec2-share-ebs-snapshot, vpc-remove-flow-logs
