# 6단계 인간 계정 탈취 & 신원 지속성 킬체인 (노이즈 병행) — aws.5_chain_n3

> 대상 로그: `log_json/aws.5_chain_n3.json`
> 생성: `shell code/aws.5_chain_n3_execute_with_noise.sh` (노이즈 병행 + 공격 자동)
> 원본: `raw_log/` CloudTrail 파일 9개 병합 (중복 eventID 제거, 배경 이벤트 전부 보존)
> 실행 가이드: `execution_aws.5_chain_d.md`

---

## 1. 한눈에 보기

| 항목 | 값 |
|---|---|
| 성격 | **순수 identity 그래프** — 유출된 IAM 사용자 키 하나로 계정 탈취·지속성·행사 (EC2·S3·시크릿 없음) |
| 레코드 수 | **138건** (관리 138 / **데이터 0**), 중복 0 |
| 시간 범위 | `2026-09-08T01:26:58Z` ~ `01:44:42Z` (약 18분) |
| 공격 창 | `01:33:36Z` ~ `01:34:54Z` (**약 80초**) |
| 계정 / IP | `949328302905` / 공격자 `165.132.5.130` |
| 공격 주체 | IAMUser **`apt-compromised-user`** (유출된 키 `AKIA…S52B6UE4`) |
| 탈취 대상 B | **`finance-admin`** (콘솔 비번 리셋 + 키 발급으로 이중 탈취) |
| **핵심(보완1)** | B가 발급받은 키 `AKIA…3SOQ62WJ`로 **실제 행동**(GetCallerIdentity, ListUsers) → 시작-종료 경로 완성 |

**한 줄 요약:** 유출된 IAM 사용자 키로 MFA 없이 콘솔에 들어와(페더레이션), 백도어 콘솔 계정을 만들고, 다른 사용자 B를 탈취해 **B로 실제 행동**한 뒤 로그를 지운다. n1/n2와 달리 모든 노드가 사람/크리덴셜이다.

---

## 2. 크리덴셜 구조 — 허브 + 3개 파생

```
apt-compromised-user (AKIA…S52B6UE4)  ← 유출된 허브
   ├─ GetFederationToken ─▶ FederatedUser(ASIA…3A27DRQF) ─▶ GetSigninToken ─▶ ConsoleLogin(MFAUsed=No)
   ├─ CreateLoginProfile ─▶ svc-batch-user         (콘솔 백도어, 지속성)
   ├─ UpdateLoginProfile ─▶ finance-admin(B)       (콘솔 비번 탈취 — '약한' 핸드오프)
   ├─ CreateAccessKey ─▶ B의 키(AKIA…3SOQ62WJ) ─▶ [B] GetCallerIdentity / ListUsers   ★ 키 기반 종단
   └─ DeleteTrail ─▶ decoy 트레일
```

### 공격 타임라인 (실측)

| 시각 (UTC) | 이벤트 | 주체 | 키 | 단계 |
|---|---|---|---|---|
| 01:33:36 | GetCallerIdentity | apt-compromised-user | AKIA…S52B6UE4 | 정찰 |
| 01:34:38 | **GetFederationToken** | apt-compromised-user | AKIA…S52B6UE4 | 1·2 초기침투/지속성 |
| 01:34:38 | GetSigninToken | **FederatedUser** | ASIA…3A27DRQF | 콘솔 로그인 준비 |
| 01:34:39 | **ConsoleLogin** (MFAUsed=No) | **FederatedUser** | ASIA…3A27DRQF | 1 초기침투 |
| 01:34:40 | **CreateLoginProfile**(svc-batch-user) | apt-compromised-user | AKIA…S52B6UE4 | 3 지속성 |
| 01:34:42 | **UpdateLoginProfile**(finance-admin) | apt-compromised-user | AKIA…S52B6UE4 | 4 권한상승(콘솔 탈취) |
| 01:34:43 | **CreateAccessKey**(finance-admin) → `AKIA…3SOQ62WJ` | apt-compromised-user | AKIA…S52B6UE4 | 5 계정 행사(키 발급) |
| **01:34:52** | **GetCallerIdentity** | **finance-admin(B)** | **AKIA…3SOQ62WJ** | 5 **B 행사** ★ |
| **01:34:53** | **ListUsers** | **finance-admin(B)** | **AKIA…3SOQ62WJ** | 5 **B 행사** ★ |
| 01:34:54 | **DeleteTrail**(decoy) | apt-compromised-user | AKIA…S52B6UE4 | 6 회피 |

---

## 3. ⭐ 보완1 — 시작-종료 경로가 실제로 완성됨

탈취가 "가능성"에 그치지 않고 **B가 진짜 행동**했다. 그리고 그 연결이 **키로** 이어진다:

```
CreateAccessKey.responseElements.accessKey.accessKeyId = AKIA…3SOQ62WJ   (attacker가 B의 키 발급)
        │  (같은 키가 이어서 행동)
        ▼
finance-admin(B) 가 AKIA…3SOQ62WJ 로 GetCallerIdentity → ListUsers
```

그래프에서 **`apt-compromised-user → CreateAccessKey → B의 accessKeyId → B의 ListUsers`** 라는 시작-종료 쌍이 만들어진다. `CreateAccessKey`의 발급 키 ID와 B가 사용한 키 ID가 **정확히 일치**(`AKIA…3SOQ62WJ`)하므로, accessKeyId 기반 브리지가 자동으로 걸린다.

---

## 4. 보완2 — 두 핸드오프 유형이 한 데이터셋에 (정직한 보고용)

같은 victim B가 **두 방식으로** 탈취돼, 모델의 보존율을 통제 비교할 수 있다.

| 핸드오프 | 이 로그의 실체 | 브리지 | 완결 여부 |
|---|---|---|---|
| **키 기반 (강함)** | `CreateAccessKey(B)` → `AKIA…3SOQ62WJ` → B의 GetCallerIdentity/ListUsers | **accessKeyId** 자동 | ✅ 행동까지 완결 |
| **페더레이션 콘솔 (중간)** | `GetFederationToken` → `FederatedUser(ASIA…3A27DRQF)` → ConsoleLogin | **accessKeyId(ASIA)** 존재 | ✅ 이어짐 |
| **콘솔 비번 탈취 (약함)** | `UpdateLoginProfile(finance-admin)` → (B의 콘솔 로그인) | **사용자 ARN만** | ❌ B는 콘솔이 아니라 키로 행동함 → 이 엣지의 '행동' 연속은 없음 |

관찰 포인트:
- **ConsoleLogin은 이 로그에선 accessKeyId(ASIA)가 있다.** 페더레이션 기반이라 GetFederationToken이 발급한 세션 키와 이어진다. (accessKeyId-less ConsoleLogin은 *비밀번호 기반* 콘솔 로그인의 경우이며, 여기선 그 경로를 쓰지 않았다.)
- **`UpdateLoginProfile → finance-admin` 은 "콘솔 비번을 바꿨다"는 사실만 남고**, B가 콘솔로 로그인해 행동한 기록은 없다(B는 키 경로로 행동). 즉 이 엣지는 **행동으로 이어지지 않는 '약한' 핸드오프**로, 사용자 ARN 노드를 매개로만 CreateAccessKey/행동과 같은 B에 연결된다.
- 논문 보고: **"키 기반 핸드오프는 행동까지 보존, 콘솔 비번 기반은 ARN 브리지에 의존해 행동 연속이 끊김"** 을 같은 B에 대해 보여줄 수 있다.

---

## 5. 신원/역할 구성 (138건)

| 신원 | 건수 | 역할 |
|---|---|---|
| `jjsworkspace` | 100 | 🟡 **노이즈** (정상 IT/HR 운영) — GetUser/ListUsers/GetLoginProfile/DescribeTrails + **UpdateLoginProfile(hr-selfservice)** + **GetFederationToken(ops-dashboard)** |
| `AWSService` | 21 | ⚪ 서비스 이벤트 (GetBucketAcl 등) |
| `apt-compromised-user` | 6 | 🔴 **공격 허브** (GetFederationToken, CreateLoginProfile, UpdateLoginProfile, CreateAccessKey, DeleteTrail, 정찰) |
| `AssumedRole` | 6 | ⚪ resource-explorer 등 |
| `FederatedUser` | 2 | 🔴 **콘솔 로그인** (GetSigninToken, ConsoleLogin) |
| `finance-admin` (B) | 2 | 🔴 **B의 행사** (GetCallerIdentity, ListUsers) |
| `Huge-log-attack-simulation` | 1 | ⚪ operator |

### 노이즈가 "의미 있게" 겹침
- jjsworkspace가 **`UpdateLoginProfile(hr-selfservice)`을 2번** 수행 → "UpdateLoginProfile = 공격"으로 못 거른다. 공격의 `UpdateLoginProfile(finance-admin)`은 **대상(finance-admin vs hr-selfservice)과 호출자(apt-compromised-user vs jjsworkspace)**로만 구분된다.
- jjsworkspace가 **`GetFederationToken(ops-dashboard-9)`** 수행 → 페더레이션 토큰 발급도 비유일. 공격과 정상이 같은 액션을 공유한다.

---

## 6. 그래프 변환 시 검증 쿼리 (ct_graph_v2, BASE_EVENT)

```cypher
// 공격 허브가 만든 identity 엣지 + B의 행위 (시간순)
MATCH (a:Actor)-[r:BASE_EVENT]->(b)
WHERE r.eventName IN ['GetFederationToken','ConsoleLogin','CreateLoginProfile',
                      'UpdateLoginProfile','CreateAccessKey','ListUsers','DeleteTrail']
  AND r.sourceIP = '165.132.5.130'
RETURN r.eventTime, r.eventName, a.id AS actor, b.id AS target ORDER BY r.eventTime;
```
```cypher
// 시작-종료 경로: CreateAccessKey 로 발급된 키를 B 가 사용했는가
MATCH (a)-[r:BASE_EVENT {eventName:'CreateAccessKey'}]->(:Actor)
MATCH (bk:Actor {id:'AKIA52CDAKM43SOQ62WJ'})-[r2:BASE_EVENT]->(x)
RETURN a.id AS attacker, bk.id AS issued_key, collect(r2.eventName) AS B_actions;
```

기대: `apt-compromised-user → CreateAccessKey → AKIA…3SOQ62WJ → [GetCallerIdentity, ListUsers]`.

---

## 7. 참고
- 실행/재현: `execution_aws.5_chain_d.md`, `shell code/aws.5_chain_n3_execute_with_noise.sh` + `noise_ops_chain_d.sh`
- 비교: `detail_md/aws.5_chain_n1.md`(2-크리덴셜 선형), `aws.5_chain_n2.md`(단일 크리덴셜 fan-out+크로스계정)
