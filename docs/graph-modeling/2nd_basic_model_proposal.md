# CloudTrail Base Graph — 스키마 v3

AWS CloudTrail 로그를 **정보 손실 없이** 속성 그래프로 변환해, 클라우드 공격 경로 분석의 공통 기반으로 쓰기 위한 스키마.

특정 분석 목적(사후조사 / 위험탐지 / 권한전환)에 종속되지 않는 **기반(base) 그래프**를 만들고, 목적별 해석은 그 위에 Cypher 뷰로 얹는 2계층 구조를 따른다.

```
원본 로그 ──파싱──▶ CSV 11장 ──LOAD CSV──▶ 기반 그래프 ──쿼리/enrich──▶ 목적별 뷰
                  └──── 판단 없이 보존 ────┘              └── 목적별 해석 ──┘
```

---

## 설계 원칙

### 1. Event 가 무손실 앵커다

`Event` 노드는 원본 CloudTrail 레코드와 1:1 대응하며, `requestParameters` · `responseElements` · `userIdentity` 등을 **JSON 문자열 그대로** 보유한다(`raw_*` 컬럼).

파싱 규칙이 놓친 필드도 그래프 안에 남으므로, 나중에 필요해지면 재수집 없이 꺼내 쓸 수 있다. 무손실 보장 지점을 한 곳으로 몰아넣은 것이다.

### 2. 엔티티 위상은 Event 위의 '파생 투영'이다

`Actor` / `Entity` 노드와 그 사이 관계는 Event 로부터 **추출한 결과**지 원본이 아니다. 추출 규칙을 개선하면 Event 노드는 그대로 두고 관계만 재생성하면 된다.

이 구분 덕분에 **"파생 투영에서 무언가를 빼는 것"과 "정보를 잃는 것"이 별개**가 된다. 예컨대 태그 키(`Name`, `StratusRedTeam`)를 엔티티 노드로 만들지 않는 것은 손실이 아니라 정제다 — 원본은 `Event.raw_requestParameters` 에 그대로 있다.

### 3. 라벨은 위상적 역할이 다른 것만 나눈다 (3개)

CloudTrail 은 400개 넘는 서비스에 수천 종의 리소스 타입을 다룬다. 리소스 종류마다 라벨을 만들면 **스키마가 데이터에 따라 무한히 자란다** — 새 서비스 로그가 들어올 때마다 스키마 변경이 필요하면 그건 플랫폼이 아니다.

그래서 라벨은 그래프에서 하는 역할이 근본적으로 다른 셋만 둔다.

| 라벨 | 역할 | 세부 분류 |
|---|---|---|
| `Event` | 사건. 모든 관계의 경유점이자 무손실 앵커 | — |
| `Actor` | 행위 주체 | `actorKind` (Credential / Identity) |
| `Entity` | 그 외 모든 대상 | `entityType` (role / instance / bucket / ...) |

**주체(Subject)와 객체(Object)로 나누지 않은 이유**가 핵심이다. 같은 실체가 둘 다이기 때문이다. 검증 데이터에서 직접 확인된 세 경우:

- **Role** — `sessionIssuer` 로 세션을 발급하는 주체이면서, 같은 이벤트의 `resources[].ARN` 에 `AWS::IAM::Role` 로 찍힌 대상
- **Instance** — `RunInstances` 의 생성 대상으로 태어나, `inScopeOf.credentialsIssuedTo` 를 통해 자격증명 보유 주체가 됨
- **Credential** — `responseElements.credentials` 에 담겨 발급된 대상이었다가, 곧바로 API 를 호출하는 주체가 됨

주체/객체는 그 실체의 고유 성질이 아니라 **특정 이벤트에서의 역할**이다. 역할은 관계에 속하지 노드에 속하지 않는다. 라벨로 쪼개면 같은 실체가 두 노드로 찢어지고, 하필 그 지점이 공격 경로가 지나가는 곳이다.

### 4. 해석은 하지 않는다

성공/실패 필터, READ/WRITE 세분, MITRE 매핑, 위험도, 정찰 여부 판단 — 전부 **재료만 보존하고 판단은 뷰로 미룬다**. 버린 정보는 후처리로 복원할 수 없기 때문이다.

검증 데이터가 이 원칙의 값어치를 보여준다. flaws.cloud 로그는 **98.9% 가 실패 이벤트**인데, 그 실패 버스트 자체가 공격이다. "성공만 보존"하는 설계였다면 공격이 통째로 사라진다.

---

## 노드

### `nodes_event.csv` — Event

원본 레코드 1:1. 무손실 앵커.

| 컬럼 | 원본 필드 | 설명 |
|---|---|---|
| `id` | `eventID` | **PK.** 역추적 키. CloudTrail 전 레코드에 존재 |
| `eventName` | `eventName` | 원본 API명. READ/MODIFY/PRIVESC 세분의 재료 |
| `eventSource` | `eventSource` | 서비스 엔드포인트 (`ec2.amazonaws.com`) |
| `eventTime` | `eventTime` | ISO 8601 UTC. 적재 시 `datetime` 으로 변환 |
| `awsRegion` | `awsRegion` | 리전 |
| `eventType` | `eventType` | `AwsApiCall` / `AwsServiceEvent` / `AwsConsoleSignIn` |
| `eventCategory` | `eventCategory` | `Management` / `Data` / `Insight` |
| `eventVersion` | `eventVersion` | 레코드 스키마 버전. 필드 유무 판정에 필요 |
| `managementEvent` | `managementEvent` | 관리 이벤트 여부 |
| `readOnly` | `readOnly` | **CloudTrail 이 직접 준 읽기/쓰기 플래그.** eventName 접두어 추측보다 정확 |
| `outcome` | (파생) | `errorCode` 유무로만 결정. 분류가 아니라 기계적 사실 |
| `errorCode` | `errorCode` | 실패 사유 원문. **뭉뚱그리지 않고 원문 보존** |
| `errorMessage` | `errorMessage` | 실패 상세 |
| `sourceIP` | `sourceIPAddress` | 요청 IP. 자격증명 탈취 탐지의 핵심 축 |
| `userAgent` | `userAgent` | 요청 도구. 자동화 도구/SDK 식별 |
| `requestID` | `requestID` | AWS 요청 ID |
| `sharedEventID` | `sharedEventID` | 여러 계정에 배달된 동일 사건을 잇는 키 |
| `recipientAccountId` | `recipientAccountId` | **수신 계정.** 행위자 계정이 아니다 — 크로스 계정 탐지 재료 |
| `vpcEndpointId`, `vpcEndpointAccountId` | 동일 | VPC 엔드포인트 경유 여부 |
| `sessionCredentialFromConsole` | 동일 | 콘솔 세션 여부. 노이즈 필터 재료 |
| `tlsVersion` | `tlsDetails.tlsVersion` | 자주 쓰는 값만 승격 |
| `apiVersion`, `addendum` | 동일 | 이 데이터셋엔 없지만 CloudTrail 스펙에 존재 |
| `null_fields` | (파생) | **명시적 `null` 과 '필드 부재'를 구분.** 이게 없으면 100% 라운드트립이 성립하지 않는다 |
| `raw_userIdentity` | `userIdentity` | 원본 JSON |
| `raw_requestParameters` | `requestParameters` | 원본 JSON. **정보 표면의 31%** |
| `raw_responseElements` | `responseElements` | 원본 JSON. **정보 표면의 54%** |
| `raw_additionalEventData` | 동일 | 원본 JSON |
| `raw_serviceEventDetails` | 동일 | `AwsServiceEvent` 의 유일한 대상 정보 |
| `raw_resources` | `resources` | 원본 JSON |
| `raw_tlsDetails` | `tlsDetails` | 원본 JSON |
| `raw_insightDetails` | `insightDetails` | Insight 이벤트용 |

> **`raw_*` 를 두는 이유.** 검증 데이터의 402개 distinct leaf path 중 **85% 가 `requestParameters` + `responseElements` 안에** 있었다. 이 둘을 추출 힌트로만 쓰고 버리면 "무손실 보존"이라는 전제가 성립하지 않는다.

### `nodes_actor.csv` — Actor

행위 주체. `actorKind` 로 두 입도를 구분한다.

| 컬럼 | 설명 |
|---|---|
| `id` | **PK.** Credential 은 `accessKeyId`, Identity 는 `userIdentity.arn` |
| `actorKind` | `Credential` \| `Identity` |
| `identityType` | (Identity) `IAMUser` / `AssumedRole` / `Root` / `AWSService` / `FederatedUser` / `AWSAccount` / `Anonymous` / `AWSServiceEvent` |
| `keyKind` | (Credential) `LongTermKey`(AKIA) / `TempKey`(ASIA) / `Other` |
| `accountId` | `userIdentity.accountId` — **행위자** 계정 |
| `principalId` | `userIdentity.principalId` |
| `userName` | `userIdentity.userName` |
| `invokedBy` | `userIdentity.invokedBy` — AWS 서비스가 대신 호출한 경우 |
| `roleSessionName` | AssumeRole 로 발급된 키의 세션명 |
| `synthetic` | `arn` 이 없어 id 를 합성했으면 `true` |

**Credential 과 Identity 를 나눈 이유.** 둘의 관계는 비대칭이다.

```
accessKeyId → arn : N:1  (키 하나는 신원 하나에만 속한다)
arn → accessKeyId : 1:N  (한 신원이 여러 키를 가질 수 있다)
```

검증 데이터에서 3개 ARN 이 각각 2개 키를 가졌고, 그중 하나가 결정적이었다.

```
arn:aws:sts::…:assumed-role/stratus-red-team-ec2-steal-credentials-role/i-06d1d3cface560abe
  ├─ ASIA…NGY7PUU → 43.202.133.180  (인스턴스 자신, SSM 에이전트)
  └─ ASIA…6D2HKTH → 165.132.5.130   (공격자 단말, aws-sdk-go-v2)
```

**동일 ARN · 동일 세션명 · 서로 다른 키 · 서로 다른 IP.** ARN 을 PK 로 썼다면 두 세션이 한 노드로 합쳐져 탈취 신호가 소멸한다. 그래서 최소 입도는 `accessKeyId` 여야 한다.

동시에 "이 신원의 모든 활동"도 자주 필요한 집계 축이다. 별도 노드로 두면 그 집계가 속성 groupby 가 아니라 **그래프 1홉**이 된다.

Identity id 폴백 계층:
```
userIdentity.arn                    (최우선)
  else svc:<userIdentity.invokedBy>  (AWSService, arn 없음)
  else anonymous:<sourceIPAddress>   (완전 익명, 최후)
```

### `nodes_entity.csv` — Entity

행위 대상이 되는 모든 것. 리소스 종류는 라벨이 아니라 `entityType` 속성으로 구분한다.

| 컬럼 | 설명 |
|---|---|
| `id` | **PK.** ARN 또는 합성 ARN (아래 규칙) |
| `entityType` | `role` / `instance` / `bucket` / `object` / `vpc` / `subnet` / `security-group` / `route-table` / `instance-profile` / `trail` / `api-endpoint` / … |
| `service` | `iam` / `ec2` / `s3` / `cloudtrail` / … |
| `name` | 사람이 읽는 이름 |
| `accountId` | 소속 계정. 크로스 계정 탐지 재료 |
| `region` | 리전 |
| `bucket` | (S3 object 전용) 소속 버킷 |
| `pseudo` | 실존하지 않는 IAM role 이면 `true` (`aws:ec2-instance` 등) |
| `synthetic` | id 를 합성했으면 `true` — **식별 신뢰도 구분** |

**id 생성 규칙 (우선순위):**

1. **정규 ARN** — `resources[].ARN` 또는 파라미터의 ARN 값. `synthetic=false`
2. **AWS 리소스 id** (`i-…`, `vpc-…`) — 계정·리전 스코프이므로 이벤트 봉투에서 스코프를 빌려 `arn:aws:ec2:<region>:<account>:<type>/<id>` 합성
3. **IAM 이름 참조** — `arn:aws:iam::<account>:<type>/<name>` 합성. IAM ARN 은 규칙이 확정적이라(리전 없음) 정확히 수렴한다
4. **S3 버킷명** — 전역 유일하므로 `arn:aws:s3:::<name>`
5. **그 외** — `arn:aws:<service>:<region>:<account>:<type>/<name>`

3~5 를 **ARN 형태로** 합성하는 것이 중요하다. 자체 형식(`svc:acct:region:type/name`)을 쓰면 같은 리소스가 이름으로 한 번·ARN 으로 한 번 참조될 때 **노드가 둘로 쪼개진다.** 실제로 초기 구현에서 instance-profile 과 trail 이 각각 중복 노드로 나왔다.

**`assumed-role` ARN 정규화.** `arn:aws:sts::…:assumed-role/ROLE/SESSION` 은 '세션'이지 role 자체가 아니다. `arn:aws:iam::…:role/ROLE` 로 정규화해야 같은 role 이 주체(세션 발급)이자 대상(정책 부착)일 때 한 노드로 합쳐진다.

**`api-endpoint`.** 대상도 산출물도 식별되지 않는 이벤트(`GetCallerIdentity`, `DescribeRegions` 등 스코프 없는 열거)의 수렴점. 이 노드에 '정찰'이라는 의미는 부여하지 않는다 — 그 판단은 뷰의 몫이다.

---

## 관계

관계 타입은 Cypher 파라미터로 넘길 수 없다. 그래서 파서는 **(출발라벨, 관계타입, 도착라벨) 조합마다 파일을 하나씩** 내보낸다. v3 는 8개 조합이다.

| 파일 | 관계 | 근거 필드 |
|---|---|---|
| `rel_actor_performed_event.csv` | `(:Actor)-[:PERFORMED]->(:Event)` | `userIdentity` |
| `rel_actor_of_identity_actor.csv` | `(:Actor)-[:OF_IDENTITY]->(:Actor)` | `accessKeyId` + `arn` |
| `rel_actor_derives_from_entity.csv` | `(:Actor)-[:DERIVES_FROM]->(:Entity)` | `sessionContext.sessionIssuer` / AssumeRole `roleArn` |
| `rel_actor_bound_to_entity.csv` | `(:Actor)-[:BOUND_TO]->(:Entity)` | `userIdentity.inScopeOf.credentialsIssuedTo` |
| `rel_event_targets_entity.csv` | `(:Event)-[:TARGETS]->(:Entity)` | `resources[]` / `requestParameters` / `serviceEventDetails` |
| `rel_event_produced_entity.csv` | `(:Event)-[:PRODUCED]->(:Entity)` | `responseElements` |
| `rel_event_issued_credential_actor.csv` | `(:Event)-[:ISSUED_CREDENTIAL]->(:Actor)` | `responseElements.credentials.accessKeyId` |
| `rel_entity_uses_entity.csv` | `(:Entity)-[:USES]->(:Entity)` | `responseElements.instancesSet[].iamInstanceProfile` |

모든 관계 파일은 `src_id`, `dst_id` 로 시작한다.

### 관계별 속성

**`PERFORMED`** — `eventTime`

**`TARGETS` / `PRODUCED`** — `ref_path`, `raw_value`

`ref_path` 는 그 식별자를 원본 JSON 의 **어느 경로에서 뽑았는지** 기록한다.

```
resources[0].ARN                                    → CloudTrail 정규 ARN
requestParameters.instancesSet.items[0].instanceId  → 요청이 명시한 대상
requestParameters.filterSet.items[0].valueSet…      → 질의 조건
responseElements.instancesSet.items[0].instanceId   → 생성된 산출물
```

`DescribeRouteTables` 의 `filterSet` 에 든 `vpc-xxx` 는 **질의 조건**이고 `routeTableIdSet` 의 값은 **명시적 대상**이다. 이 구분은 "무엇이 접근인가"라는 해석이므로 기반에서 결정하지 않고, 출처만 보존해 뷰가 판단하게 한다.

```cypher
WHERE NOT t.ref_path CONTAINS 'filterSet'   // 뷰가 직접 고른다
```

**`ISSUED_CREDENTIAL`** — `roleArn`, `roleSessionName`

**`DERIVES_FROM`** — `via`(`sessionIssuer` / `assumeRoleResponse` / `arnStructure`), `issuedAt`, `mfa`, `roleSessionName`

**`BOUND_TO`** — `issuerType` (`AWS::EC2::Instance` 등)

**`USES`** — `via`

### 엔티티간 관계는 사전 집계된다

`OF_IDENTITY`, `DERIVES_FROM`, `BOUND_TO`, `USES` 는 여러 이벤트가 **같은 사실을 반복 증거**한다. 관계를 N개 만드는 대신 1개로 합치고 증거를 속성으로 남긴다.

| 컬럼 | 설명 |
|---|---|
| `eventIDs` | 증거 이벤트 ID 목록. CSV 에선 `;` join, 적재 시 `split()` 으로 리스트화 |
| `evidenceCount` | 증거 개수 |

역추적은 그대로 가능하다.

```cypher
MATCH (c:Actor)-[r:OF_IDENTITY]->(i:Actor)
UNWIND r.eventIDs AS eid
MATCH (e:Event {id: eid}) RETURN e.eventName, e.eventTime;
```

Event 가 끼어있는 관계(`PERFORMED`, `TARGETS`, `PRODUCED`, `ISSUED_CREDENTIAL`)는 Event 노드 자체가 유일하므로 집계하지 않는다.

---

## 파서가 걸러내는 것

`requestParameters` 를 재귀 순회하며 식별자를 수집할 때, **리소스가 아닌 값**이 딸려 들어온다. 이걸 안 거르면 그래프가 오염된다.

초기 구현에서 실제로 노드가 됐던 것들:

| 값 | 출처 | 실체 |
|---|---|---|
| `StratusRedTeam`, `Name` | `tagSpecificationSet…tags[].key` | 태그 키 |
| `vpc-id`, `state`, `group-name` | `filterSet.items[].name` | 필터 **필드명** |
| `pending`, `running` | `instanceState.name` | 인스턴스 상태값 |
| `InstanceIds` | `filters[].key` | SSM 필터 키 |

경로 기반으로 제외한다 (`DENY_CONTEXTS`): `tagSet`, `tagSpecificationSet`, `filterSet`, `filters`, `instanceState`, `advancedEventSelectors`, `groupSet` 등.

**단, 형태로 판별되는 식별자(ARN, `i-xxx`)는 문맥과 무관하게 채택한다.** `filterSet` 안의 `vpc-xxx` 는 실제 리소스를 가리키므로 남기고, "질의 조건이냐 대상이냐"는 `ref_path` 를 보고 뷰가 판단한다.

이 필터링은 **정보 손실이 아니다.** 무손실은 `Event.raw_*` 가 보장하고, 여기서 빠지는 것은 파생 투영뿐이다.

결과: 검증 데이터에서 Entity 노드 **54개 → 34개**, `entityType=unknown` **25개 → 0개**.

---

## 중복 레코드 처리

CloudTrail 은 **at-least-once 전달**이라 같은 `eventID` 가 여러 번 도착할 수 있다.

flaws.cloud 데이터셋(10만 레코드)에서 **50,001건이 바이트 단위로 동일한 중복**이었다. 파서는 `eventID` 기준으로 한 번만 받아들이고 제거 건수를 보고한다. 적재 후에도 `MERGE (e:Event {id})` 가 한 번 더 방어한다.

---

## 검증 결과

두 데이터셋으로 확인했다.

| | Stratus Red Team | flaws.cloud |
|---|---|---|
| 성격 | 통제된 공격 재현 (ground truth 있음) | 실제 CTF 침해 로그 |
| 기법 | `ec2-steal-instance-credentials` (T1552.005) | 자격증명 남용 / 크립토마이닝 |
| 입력 레코드 | 183 | 100,000 (중복 제거 후 49,999) |
| Event / Actor / Entity | 183 / 16 / 34 | 49,999 / 15 / 23 |
| 관계 | 461 | 100,027 |
| **무손실 라운드트립** | **5,394 / 5,394 (100%)** | **2,992,958 / 2,992,958 (100%)** |
| 파싱 시간 | 즉시 | 약 19초 |

### Ground truth 복원

기반 그래프만으로 탈취된 자격증명이 특정된다.

```
[탐지] 같은 워크로드에 바인딩된 자격증명이 서로 다른 IP 에서 사용됨
  워크로드: arn:aws:ec2:ap-northeast-2:…:instance/i-06d1d3cface560abe
    ASIA…6D2HKTH  IP ['165.132.5.130']   UA aws-sdk-go-v2/1.24.1      ← 탈취
    ASIA…NGY7PUU  IP ['43.202.133.180']  UA aws-sdk-go/1.55.5 (SSM)
    ASIA…5QARZ7EW IP ['43.202.133.180']  UA aws-sdk-go/1.55.5 (SSM)
```

이 판정에 필요한 세 요소는 전부 v3 가 새로 보존한 것이다: `inScopeOf` 바인딩, 순방향 발급 링크(`responseElements.credentials`), 자격증명 단위 입도.

### 엣지 케이스 분포 (Stratus)

| 케이스 | 비율 |
|---|---|
| `resources[]` 부재 → `requestParameters` 폴백 필요 | **91.8%** |
| `accessKeyId` 부재 | 4.9% |
| `userIdentity.arn` 부재 | 4.9% |
| Root 주체 | 4.9% |
| `userIdentity.type` 부재 (`AwsServiceEvent`) | 1.6% |
| `readOnly` 부재 | 0% |
| `eventID` 부재 | 0% |

> **`resources[]` 는 주 경로가 아니다.** CloudTrail 이 정규화해준 목록이라 신뢰도는 가장 높지만 8.2% 의 이벤트에만 존재한다. 91.8% 는 `requestParameters` 파싱으로 처리해야 한다.

### 실패 이벤트의 의미 (flaws.cloud)

```
FAILURE 98,940 / SUCCESS 1,060   (98.9% 실패)

Client.RequestLimitExceeded        50,899   한도
Client.UnauthorizedOperation       29,390   권한 거부  ← 실제 정찰 신호
Client.Unsupported                 10,215   기능
Server.InsufficientInstanceCapacity 4,152   용량
Client.InstanceLimitExceeded        3,660   한도
```

Stratus 데이터에서는 실패 13건 중 **`AccessDenied` 가 0건**이었다(전부 기능·파라미터 오류). "FAILURE = 권한 정찰 실패"로 단순 매핑하는 뷰는 한 데이터셋에서 100% 오탐하고 다른 데이터셋에서는 맞는다. `errorCode` 를 **원문 그대로** 보존해야 하는 이유다.

---

## 사용법

```bash
# 파싱
python parse_cloudtrail.py logs/aws-cloudtrail.json ./csv
python parse_cloudtrail.py logs/ ./csv --stream      # 대용량(수백 MB), ijson 필요

# 검증
python verify.py logs/aws-cloudtrail.json ./csv

# 적재 (Docker + Neo4j)  — 자세한 절차는 SETUP.md
docker compose up -d
docker exec -i cloudtrail-graph cypher-shell -u neo4j -p cloudtrail123 < load.cypher
docker exec -i cloudtrail-graph cypher-shell -u neo4j -p cloudtrail123 < queries.cypher
```

| 파일 | 역할 |
|---|---|
| `parse_cloudtrail.py` | CloudTrail JSON → CSV 11장 |
| `verify.py` | 무손실 · ground truth · 엣지케이스 · 정규화 검증 |
| `docker-compose.yml` | Neo4j 5.26 + APOC, LOAD CSV 설정 포함 |
| `load.cypher` | 제약·인덱스·노드·관계 적재 |
| `queries.cypher` | 검산 · 탐지 · 뷰 파생 예시 |
| `SETUP.md` | Docker 설치부터 적재·검산까지 전체 절차 |

---

## 알려진 한계

1. **정적 인프라 부재.** CloudTrail 은 행위 기록이지 자산 목록이 아니다. "존재하지만 로그에 안 나타난" 리소스는 그래프에 없어 순방향 도달성이 과소추정된다. 완전한 backbone 은 IAM/Config 스냅샷 병합이 필요하다.

2. **instance-profile → role 매핑 불가.** `RunInstances` 는 instance-profile ARN 까지만 준다. profile→role 매핑은 로그에 없다(IAM API 필요). 그래서 `USES` 관계로 아는 만큼만 기록하고, role 연결은 끊긴 채로 둔다. 근거 없는 엣지를 만드는 것보다 정직하다.

3. **합성 id 의 계정 귀속 위험.** `vpc-xxx` 같은 스코프 의존 id 는 계정·리전을 이벤트 봉투에서 빌려 ARN 을 합성한다. 크로스 계정 참조 시 잘못된 계정으로 귀속될 수 있어 `synthetic='true'` 로 표시했다. 검증 데이터에 크로스 계정 이벤트가 없어 **미검증**이다.

4. **`filterSet` 참조의 성격.** `ref_path` 로 판단을 뷰에 넘겼지만, "어떤 filter 는 대상이고 어떤 건 조건인가"의 정답은 없다. API 별 사전이 있어야 정밀해진다.

5. **리스트형 이름 파라미터.** `DescribeTrails` 의 `trailNameList: ["stratus-red-team"]` 처럼 이름이 배열에 담긴 경우는 아직 수집하지 않는다. 키 화이트리스트를 늘리면 되지만 API 마다 다르다.

6. **저장 비용.** `raw_*` 가 원본 JSON 을 통째로 들고 있어 노드 수 대비 용량이 크다. 수십만 건을 넘기면 `raw_*` 를 별도 저장소(S3/Parquet)로 빼고 `eventID` 로 조인하는 구성이 현실적이다.

7. **라벨 축소의 비용.** 라벨이 3개라 라벨 스캔의 선택도가 낮다. `entityType`, `actorKind` 인덱스가 필수이며(`load.cypher` 에 포함), 라벨이 타입 제약 역할을 못 하므로 **파서 버그가 DB 단에서 안 잡힌다.** `verify.py` 의 정규화 검증이 그 역할을 대신한다.
