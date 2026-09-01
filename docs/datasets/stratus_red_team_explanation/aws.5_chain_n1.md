# 5단계 크리덴셜 핸드오프 킬체인 (노이즈 병행) — aws.5_chain_n1

> 대상 로그: `log_json/aws.5_chain_n1.json`
> 생성: `shell code/aws.5_chain_n1_execute_with_noise.sh` (노이즈 A/B 병행 + 공격 5단계 자동)
> 원본: `raw_log/` 의 CloudTrail 파일 11개 병합 (중복 eventID 제거, 배경 이벤트 전부 보존)

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| 성격 | **여러 공격을 하나의 크리덴셜 스파인으로 엮은 APT 체인 + 정상 노이즈** |
| 레코드 수 | **129건** (데이터 93 / 관리 36), 중복 0, 오류 0 |
| 시간 범위 | `2026-09-01T07:36:21Z` ~ `07:53:43Z` (약 17분) |
| 공격 창 | `07:42:37Z` ~ `07:43:17Z` (**약 40초**) |
| AWS 계정 | `949328302905` / 리전 `ap-northeast-2`(+us-east-1 IAM) |
| 공격자 단말 IP | `165.132.5.130` |
| 인스턴스 egress IP | `15.165.110.124` |
| **크리덴셜 스파인** | 인스턴스역할 `ASIA…ZXTI44UW`(Cred①) → 백도어 `AKIA…XYTRAEEE`(Cred②) |
| **핵심 신호** | `ASIA…ZXTI44UW`가 **두 IP(인스턴스+공격자)에서** 사용됨 |

**한 줄 요약:** 인스턴스 역할 크리덴셜을 훔쳐(Cred①) 정찰·관리자 백도어 생성까지 하고, 그 백도어 키(Cred②)로 로그를 끄고 데이터를 삭제하는 **방향성 킬체인**이 정상 활동(같은 버킷 조회, 인스턴스 SSM 하트비트) 사이에 묻혀 있다.

---

## 2. 크리덴셜 스파인 — 이 데이터셋의 핵심

standalone 로그들과 결정적으로 다른 점: **연속 단계가 같은 accessKeyId를 이어받는다.** 공격이 두 크리덴셜 노드를 경유하는 하나의 경로가 된다.

```
instance(i-0e4edeef541a5f212)
   └─BOUND_TO─ Cred①(ASIA…ZXTI44UW)
                 ├─ [정찰]   GetCallerIdentity, ListRoles, ListUsers, ListBuckets, ListObjects
                 └─ [권한상승] CreateUser → AttachUserPolicy(AdministratorAccess) → CreateAccessKey
                                                    │  ISSUED_CREDENTIAL
                                                    ▼
                            Cred②(AKIA…XYTRAEEE = user/apt-backdoor-admin)
                              ├─ [회피]  StopLogging ─▶ decoy 트레일
                              └─ [임팩트] ListObjectVersions → DeleteObjects + DeleteObject×51 ─▶ victim 버킷
```

### 공격 타임라인 (실측)

| 시각 (UTC) | 이벤트 | 크리덴셜 | 소스IP | 단계 |
|---|---|---|---|---|
| 07:42:37 | `ssm:SendCommand` | operator `AKIA…PSX2` | 165.132.5.130 | 1 탈취 트리거 |
| 07:42:45 | `sts:GetCallerIdentity` | **Cred① ASIA…ZXTI** | 165.132.5.130 | 2 정찰 |
| 07:42:47 | `iam:ListRoles` / `ListUsers` | **Cred①** | 165.132.5.130 | 2 정찰 |
| 07:42:5x | `s3:ListBuckets` / `ListObjects`(victim) | **Cred①** | 165.132.5.130 | 2 정찰 |
| 07:42:58 | `iam:CreateUser`(apt-backdoor-admin) | **Cred①** | 165.132.5.130 | 3 권한상승 |
| 07:43:00 | `iam:AttachUserPolicy`(AdministratorAccess) | **Cred①** | 165.132.5.130 | 3 권한상승 |
| 07:43:05 | `iam:CreateAccessKey` → **Cred② 발급** | **Cred①** | 165.132.5.130 | 3 권한상승 |
| 07:43:14 | `cloudtrail:StopLogging` | **Cred② AKIA…XYTR** | 165.132.5.130 | 4 회피 |
| 07:43:17 | `s3:DeleteObjects` + `DeleteObject×51` | **Cred② AKIA…XYTR** | 165.132.5.130 | 5 임팩트 |

accessKeyId가 **ASIA(2·3단계) → AKIA(4·5단계)**로 넘어가는 것이 핸드오프의 증거다. `CreateAccessKey`(07:43:05)가 두 크리덴셜을 잇는 `ISSUED_CREDENTIAL` 엣지다.

---

## 3. ⭐ 결정적 신호 — 같은 크리덴셜, 두 IP

v3 스키마가 ground-truth로 검증한 바로 그 형태가 이 데이터셋에 실재한다.

```
ASIA52CDAKM4ZXTI44UW 가 사용된 IP:
  15.165.110.124  ← 인스턴스 egress (SSM 에이전트: UpdateInstanceInformation 등) = 정상
  165.132.5.130   ← 공격자 단말 (GetCallerIdentity, CreateUser 등)               = 탈취
```

같은 인스턴스 역할 세션 키가 **인스턴스 자신의 IP에서 정상 사용**되는 동시에 **공격자 단말에서 악용**된다. 크리덴셜 노드 하나에 매달린 이벤트가 소스 IP로 갈라지는 것이 탐지의 앵커다. (인스턴스의 SSM 하트비트가 이 baseline을 제공한다.)

---

## 4. 신원/역할 구성 (129건 분해)

| 신원 | 건수 | accessKeyId | 역할 |
|---|---|---|---|
| `apt-backdoor-admin` | 54 | `AKIA…XYTRAEEE` | 🔴 **Cred② — 회피+임팩트** (DeleteObject×51, DeleteObjects, StopLogging, ListObjectVersions) |
| `jjsworkspace` | 35 | ASIA(SSO) | 🟡 **노이즈 B** — victim 버킷 `ListObjects`×27(같은 엔티티!) + 콘솔 `ListManagedNotificationEvents`×8 |
| `AWSService` | 16 | None | ⚪ 서비스 이벤트 — `PutObject`×12(CloudTrail 로그 배달), AssumeRole, GetBucketAcl |
| 인스턴스역할 `/i-0e4edeef…` | 13 | `ASIA…ZXTI44UW` | 🔴 **Cred① 공격**(정찰+권한상승) 🟡 **+ SSM 하트비트**(인스턴스 IP) |
| `Huge-log-attack-simulation` | 7 | `AKIA…PSX2` | 🟡 operator/harness — SendCommand(탈취 트리거), GetCommandInvocation, Describe/List |
| ResourceExplorer 역할 | 4 | ASIA | ⚪ AWS 자동 인덱싱 노이즈 |

### 노이즈가 "의미 있는" 이유
- **jjsworkspace의 ListObjects×27이 victim 버킷을 조회**한다 → "그 버킷 접근 = 공격"으로 못 거른다. 대량 `DeleteObject`(백도어 키)만 튀어야 한다.
- **인스턴스 SSM 하트비트가 Cred① 키를 인스턴스 IP에서 계속 사용** → 탈취 이벤트가 그 baseline 속의 needle이 된다.

> ℹ️ 이번 실행에서 노이즈 볼륨은 가볍다(전용 노이즈 루프가 짧게 돌았고, 주된 정상 트래픽은 jjsworkspace의 버킷 조회 + SSM 하트비트). 노이즈를 더 두껍게 하려면 `OPS_INTERVAL`을 줄이고 `PREROLL`을 늘려 재실행하면 된다(shell code/README 참고).

---

## 5. 이벤트 구성

| eventName | 건수 | 비고 |
|---|---|---|
| `DeleteObject` | 51 | 🔴 임팩트 — 버전 삭제(버킷 versioning으로 delete marker) |
| `ListObjects` | 28 | 🟡 노이즈 B 27 + 공격 정찰 1 |
| `PutObject` | 12 | ⚪ CloudTrail 로그 배달(데이터 이벤트 노이즈) |
| `ListManagedNotificationEvents` | 8 | ⚪ 콘솔 배경 |
| `UpdateInstanceInformation` | 4 | 🟡 SSM 하트비트(인스턴스 IP) |
| `GetCommandInvocation` | 3 | 🟡 탈취 결과 폴링 |
| 나머지(공격 핵심 8종 등) | 각 1~2 | `SendCommand`,`GetCallerIdentity`,`ListRoles`,`ListUsers`,`CreateUser`,`AttachUserPolicy`,`CreateAccessKey`,`StopLogging`,`DeleteObjects` |

데이터 이벤트 93건은 대부분 임팩트(DeleteObject) + 버킷 조회/배달, 관리 36건은 공격 컨트롤플레인 + 정찰 + SSM.

---

## 6. 그래프 변환 시 기대 구조

```
(instance)─BOUND_TO─(Cred① ASIA)─PERFORMED─(CreateAccessKey)─ISSUED_CREDENTIAL─▶(Cred② AKIA=apt-backdoor-admin)
                        │  └PERFORMED─▶ 정찰/권한상승 이벤트                          ├PERFORMED─▶(StopLogging)─TARGETS─▶(trail)
                        │                                                            └PERFORMED─▶(DeleteObjects)─TARGETS─▶(bucket victim)
                        └(같은 키가 인스턴스 IP에서도 PERFORMED = SSM)  ← 탈취 판별 앵커
(jjsworkspace)─PERFORMED─▶ ListObjects ─TARGETS─▶(bucket victim)   ← 정상 활동이 같은 버킷 노드를 공유
```

### 검증 쿼리(예)
```cypher
// 크리덴셜 스파인
MATCH (c1:Actor {id:'ASIA52CDAKM4ZXTI44UW'})-[:PERFORMED]->(e:Event {eventName:'CreateAccessKey'})
      -[:ISSUED_CREDENTIAL]->(c2:Actor)-[:PERFORMED]->(imp:Event)
WHERE imp.eventName IN ['StopLogging','DeleteObjects']
RETURN c1,e,c2,imp;

// 같은 키, 두 IP
MATCH (c:Actor {id:'ASIA52CDAKM4ZXTI44UW'})-[:PERFORMED]->(e:Event)
RETURN DISTINCT e.sourceIP;   // 15.165.110.124 와 165.132.5.130 둘 다 나와야 함
```

---

## 7. 참고
- 실행 스크립트·재현 방법: `shell code/README.md`, `CHAIN-option2-guide.md`
- 개별 기법 상세: `detail_md/` 의 5개 문서(steal-instance-credentials, ec2-enumerate-from-instance, iam-create-admin-user, cloudtrail-stop, s3-ransomware-batch-deletion)
