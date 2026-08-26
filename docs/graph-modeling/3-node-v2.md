# Neo4j Graph Database Specification — v2

**프로젝트명:** CloudTrail 기반 침해 사고 추적 그래프 데이터베이스
**데이터베이스 모델:** 3-Role Multi-Label Node + Semantic Context-Aware Edge Architecture
**파서:** `parser_node3_v2.py`

---

## 0. v1 대비 변경 요약

3-Node 체계(Actor / Resource / Service, 행위는 엣지 속성)는 그대로 유지하고
아래 셋만 고쳤다. Stratus 로그 183건 실측 비교다.

| | v1 | v2 | 변경 내용 |
| :--- | ---: | ---: | :--- |
| 노드 | 26 | 46 | ② 로 실제 자산이 드러나 늘었다 |
| ├ 같은 id 중복 노드 | **2** | **0** | ① 멀티라벨로 합침 |
| BASE_EVENT 엣지 | 197 | 258 | 이벤트 1건이 대상 N개면 N행 |
| **Service 수렴 비율** | **91.8%** | **4.3%** | ② 대상 추출 확대 |
| Resource 노드 | 7 | 29 | 같은 이유 |
| 발급 사슬 (OBTAINS) | **없음** | 4 | ③ |
| 워크로드 바인딩 (RUNS_ON) | **없음** | 7 | ③ |
| ISSUES 중복 배율 | 2.0× | 1.0× | CONTEXT 집계 |
| 공격자→탈취 자격증명 도달 | **단절** | **2홉** | ①③ 복합 효과 |

### ① 멀티라벨 단일 노드

v1 은 `actors` 사전과 `resources` 사전을 따로 두었다. 같은 role ARN 이 양쪽에
들어가면 Neo4j 에서 **두 개의 노드**가 된다. 실측으로 확인된 결과:

```
arn:aws:iam::...:role/stratus-red-team-ec2-steal-credentials-role
  v1  들어오는 엣지 2 → dst_label='Resource'  (ASSUME_ROLE)
      나가는 엣지  6 → src_label='Actor'     (ISSUES)
      → AssumeRole 은 Resource 복사본에 도착하고 발급은 Actor 복사본에서 출발.
        권한 체인이 정확히 role 에서 끊긴다.

  v2  같은 노드 하나. labels='Actor;Resource'
      들어오는 ASSUME_ROLE 4 + 나가는 ISSUES 2 가 한 노드에 붙는다.
```

Role 은 세션 발급 주체이면서 정책 부착 대상이고, Instance 는 생성 대상으로
태어나 자격증명 보유 주체가 된다. **같은 실체가 주체이자 객체**이므로 라벨로
쪼개면 안 된다. 3-Role 분류 자체는 유지하되, 라벨을 **배타적 분류가 아니라
겸할 수 있는 역할 표시**로 바꾼 것이다.

### ② 대상 추출 확대

v1 의 `parse_targets()` 는 `event["resources"]` 만 봤다. 그런데 CloudTrail 에서
`resources[]` 는 **183건 중 15건(8.2%)** 에만 존재한다. 나머지는 전부
`ec2.amazonaws.com` 같은 Service 노드 한 점으로 수렴했다 — 어떤 인스턴스를
건드렸는지가 그래프에서 사라진 것이다.

v2 는 `requestParameters` / `responseElements` / `serviceEventDetails` 를 재귀로
훑어 식별자를 수집한다(ARN 정규식, AWS id 정규식, 키 이름 화이트리스트).
`tagSet` · `filterSet` · `instanceState` 같은 컨테이너는 경로 기반으로 제외한다 —
태그 키나 상태 문자열이 노드가 되면 그래프가 오염된다.

Service 수렴은 **대상을 하나도 못 찾은 경우의 폴백**으로만 남는다.

### ③ 자격증명 체인 복원

v1 에 없던 두 연결을 추가했다.

```
OBTAINS   (호출 주체) → (발급된 키)     responseElements.credentials.accessKeyId
RUNS_ON   (자격증명)  → (워크로드)      userIdentity.inScopeOf.credentialsIssuedTo
```

`inScopeOf.credentialsIssuedTo` 는 AWS 가 직접 주는 자격증명↔워크로드 바인딩으로,
추측 없이 분석을 시작할 수 있는 유일한 지점이다. `RUNS_ON` 을 **역방향으로 읽으면**
"워크로드를 장악하면 거기 실린 자격증명을 얻는다"가 되어, 리소스에서 자격증명으로
넘어가는 경로가 생긴다.

실측 효과 — v1 에서 단절이던 경로가 2홉으로 이어진다:

```
AKIA…W5UHPSX2 --[ACCESS/write]--> i-06d1d3cface560abe --[RUNS_ON 역방향]--> ASIA…6D2HKTH
```

---

## 1. 개요

AWS CloudTrail 감사 로그를 저장·시각화·포렌식 추적하기 위한 그래프 DB 구조를
정의한다. 노드 폭발 방지를 위해 자산을 **3개 역할(Actor, Resource, Service)** 로
추상화하고, 행위 맥락은 **Semantic Edge** 속성으로 내재화한다.

v2 의 구조적 전제는 둘이다.

1. **노드 정체성은 `id` 하나가 결정한다.** 역할 라벨은 그 위에 얹히는 표시이며
   한 노드가 여럿을 겸할 수 있다.
2. **엣지는 두 종류다.** 시각이 있는 *일어난 일*(`BASE_EVENT`)과, 여러 이벤트에
   걸쳐 *성립하는 사실*(`CONTEXT`)을 분리한다. v1 은 `sessionIssuer` 같은 문맥
   정보를 이벤트마다 엣지로 만들어 중복 배율이 붙었다.

---

## 2. 노드 스키마

모든 노드는 공통 라벨 `:Node` 를 가지며, `id` 가 유일 키다.
그 위에 역할 라벨 `:Actor` / `:Resource` / `:Service` 를 **하나 이상** 가진다.

| 속성명 | 타입 | 필수 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| **`id` (PK)** | String | Y | 전역 유일 식별자. 주체는 `accessKeyId`/`svc:…`/ARN, 자산은 정규 ARN, 서비스는 엔드포인트 도메인 |
| `labels` | String | Y | 역할 라벨 목록 (`Actor`, `Resource`, `Actor;Resource`). 적재 시 실제 라벨로 변환 |
| `actorType` | String | N | `userIdentity.type` (`IAMUser`, `AssumedRole`, `Root`, `AWSService`, `Role`) |
| `arn` | String | N | 주체 ARN |
| `accountId` | String | N | 소유 AWS 계정 ID |
| `kind` | String | N | 자격증명 형태 (`LongTermKey`, `TempKey`, `Role`, `Service`, `Anonymous`, `Unknown`) |
| `resourceType` | String | N | 자산 세부 타입 (`bucket`, `object`, `role`, `instance`, `policy`, `secret` …) |
| `service` | String | N | 소속 AWS 서비스 (`s3`, `iam`, `ec2`) |
| `name` | String | N | 자산 식별 명칭 |
| `region` | String | N | 리전 |
| `synthetic` | String | N | id 를 합성했으면 `'true'`. 정규 ARN 관측 시 `'false'` 로 확정 |

### 2.1 역할 라벨의 의미

| 라벨 | 의미 |
| :--- | :--- |
| `:Actor` | API 행위를 유발한 주체로 관측된 적이 있다 |
| `:Resource` | API 호출의 대상 자산으로 관측된 적이 있다 |
| `:Service` | 대상이 특정되지 않은 접근의 수렴점 (폴백) |

**`:Actor` 와 `:Resource` 를 동시에 갖는 노드가 정상이다.** 실측에서 role 3개가
그렇다. 이 노드들이 곧 권한 체인이 통과하는 지점이다.

### 2.2 주체 `id` 규칙

주체 id 는 **`accessKeyId` 를 최우선**으로 쓴다. `arn → accessKeyId` 가 1:N 이기
때문이다. 검증 데이터에서 동일 ARN·동일 세션명인데 키가 다르고 출처 IP 가 다른
사례가 있었다 — ARN 을 PK 로 쓰면 그 신호가 소멸한다.

우선순위: `accessKeyId` > `svc:{invokedBy}` > `arn` > `anonymous:{sourceIP}`

> v1 은 `f"arn:{arn}"` 로 접두사를 붙여 `arn:arn:aws:…` 를 만들었다. `sessionIssuer`
> 쪽은 접두사가 없어 같은 role 이 또 갈라진다. v2 에서 제거했다.

### 2.3 자산 `id` 정규화

`정규 ARN > 계정·리전을 붙인 합성 ARN > service:name` 순으로 결정한다.
같은 리소스가 이름으로 한 번·ARN 으로 한 번 참조돼도 한 노드로 수렴시키기
위해서다. 특수 규칙 둘:

- **S3 ARN** 은 타입 접두어가 없다(`arn:aws:s3:::bucket/key`). 별도 처리하지 않으면
  버킷명이 `resourceType` 이 된다.
- **`assumed-role` ARN 은 세션이지 role 이 아니다.** `arn:aws:iam::…:role/{name}` 으로
  정규화해야 세션 발급자와 정책 부착 대상이 한 노드로 합쳐진다.

---

## 3. 관계 스키마

### 3.1 `:BASE_EVENT` — 일어난 일

출발 노드가 `:Actor` 로서, 도착 노드가 `:Resource`/`:Service`/`:Actor` 로서
참여한 **단일 API 호출**. 이벤트 하나가 대상 N개를 건드리면 N개 엣지가 생기고
`eventID` 를 공유한다. 같은 쌍 사이에 여러 엣지가 정상이므로 적재 시
`MERGE` 가 아니라 **`CREATE`** 를 쓴다.

| 속성명 | 타입 | 필수 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| `rel` | String | Y | 위상 타입 (아래 표) |
| **`actionL2`** | String | Y | **2계층 의미론적 행위 추상화** (`READ`, `CREATE`, `MODIFY`, `DELETE`, `ASSUME`, `EXECUTE`, `DENY`) |
| `dstAs` | String | Y | 도착 노드가 이 엣지에서 맡은 역할 (`Resource`, `Service`, `Actor`) |
| `refPath` | String | Y | **대상을 찾아낸 JSON 경로.** `requestParameters.instanceIds[0]`, `resources[].ARN` 등 |
| `eventID` | String | Y | CloudTrail 원본 Record PK (포렌식 역추적용) |
| `eventName` | String | Y | 원본 API 명칭 |
| `eventSource` | String | Y | 원본 API 서비스 소스 |
| `eventTime` | DateTime | Y | 발생 시각 |
| `sourceIP` | String | N | 요청자 IP. **항상 IP 가 아니다** — AWS 서비스 대리 호출이면 `ec2.amazonaws.com` 같은 도메인이 들어온다 |
| `outcome` | String | Y | `SUCCESS` / `FAILURE` |
| `readOnly` | Boolean | Y | 읽기 전용 플래그 |

**`rel` 값**

| 값 | 의미 | 출처 |
| :--- | :--- | :--- |
| `ACCESS` | 대상 자산에 대한 접근 | `resources[]`, `requestParameters`, `serviceEventDetails` |
| `PRODUCES` | 호출 결과로 생성·반환된 자산 | `responseElements` |
| `ASSUME_ROLE` | AssumeRole 계열이 role 을 향함 | 위와 동일, 대상이 role 일 때 |
| `OBTAINS` | **호출 주체가 자격증명을 획득** | `responseElements.credentials.accessKeyId` |

#### `refPath` 를 남기는 이유

`filterSet` 안의 `vpc-id` 는 **질의 조건**이고 `routeTableIdSet` 의 값은
**명시적 대상**이다. 이 구분에 정답이 없으므로(API 별 사전이 필요하다) 기반 층에서
결정하지 않고 출처만 남겨 뷰가 판단하게 한다. 예를 들어 `AssumeRole` 의
`requestParameters.roleSessionName` 이 인스턴스 ID 와 같아 인스턴스를 가리키게
되는데, 이게 "대상"인지는 뷰가 `refPath` 를 보고 정한다.

### 3.2 `:CONTEXT` — 성립하는 사실

시각이 하나로 정해지지 않고 여러 이벤트에 걸쳐 관측되는 관계. `(src, dst, rel)`
단위로 집계한다.

| 속성명 | 타입 | 필수 | 설명 |
| :--- | :--- | :---: | :--- |
| `rel` | String | Y | `ISSUES` \| `RUNS_ON` |
| `via` | String | Y | 근거 필드 (`sessionIssuer`, `assumeRoleResponse`, `AWS::EC2::Instance`) |
| `evidenceCount` | Integer | Y | 이 사실을 뒷받침한 이벤트 수 |
| `firstSeen` / `lastSeen` | DateTime | Y | 관측 구간 |
| `eventIDs` | List\<String\> | Y | 근거 eventID (기본 최대 20개, `--max-evidence`) |

| `rel` | 방향 | 의미 |
| :--- | :--- | :--- |
| `ISSUES` | (role) → (자격증명) | 이 role 이 이 키를 발급했다 |
| `RUNS_ON` | (자격증명) → (워크로드) | 이 키는 이 워크로드에 실려 있다 |

> **`RUNS_ON` 은 역방향으로 읽을 때 가치가 있다.** "워크로드를 장악하면 거기 실린
> 자격증명을 얻는다" 가 되어 리소스→자격증명 경로를 만든다. 영향 범위 분석의
> 핵심 간선이다.

---

## 4. 적재

```bash
python parser_node3_v2.py <log.json> -o ./csv
```

```cypher
// ── 제약 및 인덱스 ─────────────────────────────────────────────
CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE;

CREATE INDEX node_rtype IF NOT EXISTS FOR (n:Node) ON (n.resourceType);
CREATE INDEX node_kind  IF NOT EXISTS FOR (n:Node) ON (n.kind);
CREATE INDEX node_name  IF NOT EXISTS FOR (n:Node) ON (n.name);

// 이벤트 데이터가 전부 엣지에 있으므로 관계 인덱스가 필수다.
CREATE INDEX be_time IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventTime);
CREATE INDEX be_name IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventName);
CREATE INDEX be_act  IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.actionL2);
CREATE INDEX be_ip   IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.sourceIP);
CREATE INDEX be_eid  IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventID);

// ── 노드 ───────────────────────────────────────────────────────
LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
CALL (row) {
  MERGE (n:Node {id: row.id})
  SET n += apoc.map.clean(row, [], [''])
} IN TRANSACTIONS OF 5000 ROWS;

// ① 역할 라벨 부여. labels 속성을 실제 라벨로 바꾼다.
MATCH (n:Node) WHERE n.labels IS NOT NULL
CALL apoc.create.addLabels(n, split(n.labels, ';')) YIELD node
RETURN count(node) AS labeled;

// ── BASE_EVENT ────────────────────────────────────────────────
// MERGE 가 아니라 CREATE. 같은 주체가 같은 대상을 여러 번 호출하는 게 정상이다.
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
CALL (row) {
  MATCH (a:Node {id: row.src})
  MATCH (b:Node {id: row.dst})
  CREATE (a)-[r:BASE_EVENT]->(b)
  SET r += apoc.map.clean(row, ['src','dst'], ['']),
      r.eventTime = datetime(row.eventTime),
      r.readOnly  = toBoolean(row.readOnly)
} IN TRANSACTIONS OF 5000 ROWS;

// ── CONTEXT ───────────────────────────────────────────────────
LOAD CSV WITH HEADERS FROM 'file:///context.csv' AS row
CALL (row) {
  MATCH (a:Node {id: row.src})
  MATCH (b:Node {id: row.dst})
  MERGE (a)-[r:CONTEXT {rel: row.rel}]->(b)
  SET r += apoc.map.clean(row, ['src','dst'], ['']),
      r.evidenceCount = toInteger(row.evidenceCount),
      r.firstSeen     = datetime(row.firstSeen),
      r.lastSeen      = datetime(row.lastSeen),
      r.eventIDs      = split(row.eventIDs, '|')
} IN TRANSACTIONS OF 5000 ROWS;

// ── 적재 검증 ─────────────────────────────────────────────────
// 관계 적재는 MATCH 로 양끝을 찾는데, 못 찾으면 예외가 아니라 행을 건너뛴다.
// 엣지가 조용히 사라져도 모르므로 CSV 행수와 대조한다.
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row WITH count(*) AS csvN
MATCH ()-[r:BASE_EVENT]->() WITH csvN, count(r) AS dbN
RETURN 'BASE_EVENT' AS item, csvN, dbN,
       CASE WHEN csvN = dbN THEN 'OK' ELSE 'MISMATCH' END AS status;
```

`docker-compose.yml` 에 `dbms.import.csv.legacy_quote_escaping=false` 가 필요하다.
기본값 `true` 는 따옴표 안 백슬래시를 이스케이프로 소비해 `\uXXXX` 를 조용히 깨뜨린다.
IAM 정책 문서가 담긴 로그(`PutRolePolicy` 등)에서 대량 발생한다.

---

## 5. 기본 질의

```cypher
// 어떤 주체가 무엇을 했는가 — 1홉
MATCH (a:Actor)-[r:BASE_EVENT]->(x)
WHERE a.id = $actorId
RETURN r.eventTime, r.eventName, r.actionL2, r.outcome, x.name, x.resourceType
ORDER BY r.eventTime;

// 삭제 행위 전수 — 서비스별 지식 없이
MATCH (a)-[r:BASE_EVENT {actionL2:'DELETE'}]->(x) RETURN a.id, r.eventName, x.id;

// 자격증명 발급 사슬
MATCH p = (a)-[:BASE_EVENT {rel:'OBTAINS'}]->(c) RETURN p;

// 워크로드에 실린 자격증명 (RUNS_ON 역방향)
MATCH (w:Resource {resourceType:'instance'})<-[:CONTEXT {rel:'RUNS_ON'}]-(c:Actor)
RETURN w.name, collect(c.id);

// 주체이자 자산인 노드 — 권한 체인이 통과하는 지점
MATCH (n:Actor:Resource) RETURN n.id, n.resourceType;
```

---

## 6. 남은 한계 (v2 에서 안 고친 것)

| # | 내용 | 영향 |
| :--- | :--- | :--- |
| 1 | **`errorCode` 원문 미보존** | 실패가 전부 `actionL2='DENY'` 로 뭉개진다. 검증 데이터의 실패 13건 중 `AccessDenied` 는 0건(전부 기능·파라미터 오류)이라 "DENY = 권한 정찰" 로 읽으면 100% 오탐이다. 반대로 flaws.cloud 는 `UnauthorizedOperation` 이 29,390건이다. |
| 2 | **의도와 결과가 한 필드에 섞임** | `derive_action_l2` 가 `FAILURE` 를 최우선으로 봐서 **실패한 `DeleteBucket` 이 DELETE 가 아니라 DENY** 가 된다. `actionL2`(의도)와 `outcome`(결과)을 분리해야 한다. |
| 3 | **중복 레코드 제거 없음** | CloudTrail 은 at-least-once 전달이다. flaws.cloud 10만 건 중 5만 건이 바이트 단위 동일 중복이었다. `eventID` 기준 dedup 이 필요하다. |
| 4 | **무손실 아님** | `requestParameters` / `responseElements` 원문을 보관하지 않는다. 포렌식은 `eventID` 로 원본 JSON 을 되짚어야 하며 그래프가 자기충족적이지 않다. 저장 비용과 맞바꾼 의식적 선택이다. **검증 축을 "원본 대비 보존율" 이 아니라 "추출한 필드가 정확한가" 로 바꿔야 한다.** |
| 5 | **`sourceIP` 가 IP 가 아닐 수 있음** | 검증 데이터 183건 중 12건이 서비스 도메인이다. IP 기반 판정을 하는 뷰는 `CONTAINS '.amazonaws.com'` 을 걸러야 한다. |
| 6 | **합성 id 의 계정 귀속** | `vpc-xxx` 같은 스코프 의존 id 는 이벤트 봉투에서 계정·리전을 빌린다. 크로스 계정 참조 시 오귀속 가능. `synthetic='true'` 로 표시했으나 크로스 계정 이벤트가 없어 미검증이다. |
| 7 | **`filterSet` 참조의 성격** | `refPath` 로 판단을 뷰에 넘겼지만 "어떤 filter 가 대상이고 어떤 게 조건인가" 의 정답은 없다. API 별 사전이 필요하다. |
| 8 | **라벨 선택도** | 모든 노드가 `:Node` 를 공유해 라벨 스캔의 선택도가 낮다. `resourceType`/`kind` 인덱스가 필수이며, 라벨이 타입 제약 역할을 못 하므로 파서 버그가 DB 단에서 안 잡힌다. |
