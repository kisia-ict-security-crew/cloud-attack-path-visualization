# CloudTrail → Neo4j 기반 스키마 (플랫폼 모델)

CloudTrail 로그를 **목적 중립적으로** 그래프화하는 기반(base) 스키마 정의.
특정 분석 목적에 종속되지 않고, 여러 목적별 뷰가 그 위에서 후처리로 파생되는
플랫폼 형태를 지향한다.

## 설계 철학

### 2계층 구조

```
[원본 로그] → 파싱 → [기반 CSV] → import → [기반 그래프] → enrich/쿼리 → [목적별 뷰]
                       └─ 판단 없이 보존 ─┘         └─ 목적별 해석 ─┘
```

- **기반 층 (Base)**: CloudTrail 이벤트의 구조를 손실 없이 담는다. 성공/실패, 노이즈, 원본 API명을 모두 보존하며 어떤 해석·분류도 하지 않는다.
- **뷰 층 (View)**: 기반 위에 목적별 해석(사후조사, 위험 탐지, 권한 전환 등)을 enrich(속성 태깅)나 쿼리로 얹는다. 기반을 변경하지 않는다.

### 핵심 원칙 두 가지

1. **가장 세밀한 입도로 보존한다.** 후처리는 "세밀 → 집계" 방향(예: 키 단위를 role 단위로 묶기)은 자유롭지만, "집계 → 세밀" 방향(굵게 담은 것을 쪼개기)은 정보가 없어 불가능하다. 따라서 기반은 최소 단위(accessKeyId, 개별 이벤트)로 담는다.
2. **판단은 뷰로 미룬다.** "성공만 볼지", "무엇이 위험한지", "데이터인지 권한인지"는 목적이 정한다. 기반은 이 판단을 하지 않고 재료(eventName, outcome 등)만 보존한다. 버린 정보는 후처리로 복원할 수 없으므로 아무것도 버리지 않는다.

### 기반에 남는 것 vs 뷰로 내려가는 것

| 결정 | 성격 | 위치 |
|------|------|------|
| 주체를 accessKeyId로 식별 | 구조적 | 기반 |
| Role/Workload를 별도 노드로 | 구조적 | 기반 |
| arn 식별 규칙 | 구조적 | 기반 |
| 성공/실패 필터 | 목적적 | 뷰 |
| READ/MODIFY/PRIVESC 세분 | 목적적 | 뷰 |
| MITRE·위험도 분류 | 목적적 | 뷰 |
| 노이즈(대량 열거) 축약 | 목적적 | 뷰 |

구분선: **"이것이 무엇인가"(구조)는 기반, "이것을 어떻게 해석하는가"(의미)는 뷰.**

---

## 기반 노드 (5종)

| 노드 | 역할 | 비고 |
|------|------|------|
| Principal | 행위 주체 | 모든 userIdentity 유형 보존 (Session 통합) |
| Role | IAM role | 주체이자 대상인 구조적 허브 |
| Workload | Lambda/EC2 등 실행 객체 | Workload를 통한 권한 이동 표현 |
| Resource | 접근 대상 자산 | data/permission 미분리, resourceType으로 구분 |
| Service | 대상 없는 열거의 수렴점 | 정찰성 접근 집계 |

### 1. `principals.csv` — 행위 주체

기존 Principal + Session을 통합한다. 모든 `userIdentity.type`을 보존한다.

| 컬럼 | 타입 | PK | 의미 | 비고 |
|------|------|:--:|------|------|
| `id` | string | O | accessKeyId / `svc:<invokedBy>` / `arn:<arn>` (폴백 계층) | 최소 단위 식별자 |
| `principalType` | enum | | IAMUser / AssumedRole / Root / AWSService / FederatedUser / AWSAccount / Anonymous | 판단 없이 모든 유형 보존 |
| `arn` | string | | `userIdentity.arn` 원본 | 여러 키가 공유 가능(1:N) → PK 불가, 속성으로만 |
| `accountId` | string | | `userIdentity.accountId` | 크로스계정 분석 재료 |
| `kind` | enum | | LongTermKey(AKIA) / TempKey(ASIA) / Service / Unknown | id 접두어에서 파생 |

**id 폴백 계층** (accessKeyId가 없는 경우):

```
id = accessKeyId              (있으면 최우선)
   else svc:<invokedBy>       (AWSService)
   else arn:<arn>             (arn은 있으나 키 없는 경우: Root, 익명 등)
   else anonymous:<sourceIP>  (완전 익명 — 최후 폴백, 뷰에서 취급 주의)
```

> **주의**: accessKeyId 없는 이벤트는 성격이 크게 다르다. AWSService는 대체로 배경 잡음이지만, 공개 리소스 익명 접근은 유출의 시발점일 수 있다. 기반은 둘 다 `principalType`으로 구분해 보존하고, 취급은 뷰에서 결정한다.

**헤더**

```csv
id,principalType,arn,accountId,kind
```

### 2. `roles.csv` — IAM role

주체(권한 허브)이자 대상이 될 수 있는 이중 정체성을 가지므로, Resource와 분리해 별도 노드로 둔다. 같은 roleArn은 어느 소스(sessionIssuer, AssumeRole 대상, IAM 조작 대상)에서 왔든 하나의 노드로 MERGE한다.

| 컬럼 | 타입 | PK | 의미 |
|------|------|:--:|------|
| `id` | string | O | roleArn (accountId+name을 포함한 전역 유일키) |
| `roleName` | string | | 짧은 이름 (arn에서 파생, 가독성) |
| `accountId` | string | | 소속 계정 (크로스계정 assume 탐지 재료) |

**헤더**

```csv
id,roleName,accountId
```

### 3. `workloads.csv` — 실행 객체

Lambda/EC2/ECS 등 코드를 실행하는 컴퓨팅 객체. Workload를 장악하면 그 실행 role 권한을 획득하므로, 권한 이동 경로의 노드로 분리한다.

| 컬럼 | 타입 | PK | 의미 |
|------|------|:--:|------|
| `id` | string | O | arn (있으면) / `<service>:<name>` (폴백) |
| `workloadType` | enum | | function / instance / container / ... |
| `service` | enum | | lambda / ec2 / ecs / ... |
| `name` | string | | 실제 이름 |
| `accountId` | string | | 소속 계정 |
| `region` | string | | 실행 리전 |

**헤더**

```csv
id,workloadType,service,name,accountId,region
```

### 4. `resources.csv` — 접근 대상 자산

데이터성(bucket/object/secret)과 권한성(role/user/policy) 대상을 **분리하지 않고 통합**한다. 분류는 뷰에서 `resourceType`으로 수행한다. (단 Role은 구조적 이유로 별도 노드로 이미 분리했다.)

| 컬럼 | 타입 | PK | 의미 |
|------|------|:--:|------|
| `id` | string | O | arn (있으면) / `<service>:<name>` (폴백) |
| `resourceType` | enum | | bucket / object / user / policy / secret / instance / ... |
| `service` | enum | | s3 / iam / lambda / kms / ... (eventSource 기반) |
| `name` | string | | 실제 값 |
| `accountId` | string | | 소유 계정 (있으면) |
| `region` | string | | 리전 (있으면) |

**id 생성 우선순위** (정규화):

```
id = arn                                   (로그에 arn 있으면 최우선 — 완전 식별)
   else <service>:<accountId>:<region>:<name>   (스코프 정보 있으면 arn 근사)
   else <service>:<name>                   (전역 유일 리소스는 이걸로 충분)
```

> S3 버킷 이름은 전역 유일이라 `s3:name`으로 충분하나, Lambda/EC2는 계정+리전 스코프라 가능하면 accountId/region을 포함해야 유일성이 확보된다. 로그가 정보를 다 주지 않으면 불완전 식별을 감수한다(데이터 소스의 한계).

**헤더**

```csv
id,resourceType,service,name,accountId,region
```

### 5. `services.csv` — 서비스 수렴점

`ListBuckets`처럼 특정 대상이 없는 열거형 접근이 수렴하는 노드. 정찰성 접근 집계에 쓰인다.

| 컬럼 | 타입 | PK | 의미 |
|------|------|:--:|------|
| `id` | string | O | eventSource (예: s3.amazonaws.com) |
| `service` | string | | 서비스명 |

**헤더**

```csv
id,service
```

---

## 기반 엣지 (`edges.csv`)

엣지 타입은 **구조적 최소 집합**으로만 두고, 세부 판단 재료는 전부 **속성으로 원본 보존**한다. READ/MODIFY/위험도 같은 목적적 세분은 뷰에서 eventName·outcome·readOnly로 재현한다.

### 엣지 타입 (5종)

| rel | src → dst | 의미 |
|-----|-----------|------|
| `ACCESS` | Principal → Resource / Service | 리소스·서비스에 접근 (세분하지 않음) |
| `ASSUME_ROLE` | Principal → Role | role 취득 |
| `ISSUES` | Role → Principal | 임시 자격증명(세션) 발급 |
| `INVOKES` | Principal → Workload | workload 호출 |
| `RUNS_AS` | Workload → Role | workload가 실행되는 role |

> `SAME_CREDENTIAL`, `READ`/`MODIFY`, `LEADS_TO_ROLE` 등은 기반에 두지 않는다. 이들은 기반 관계로부터 후처리로 파생되는 뷰 층 관계다(아래 참조).

### 엣지 공통 컬럼

| 컬럼 | 타입 | 의미 | 뷰에서의 용도 |
|------|------|------|---------------|
| `src` | string | 출발 노드 id | 위상 골격 |
| `src_label` | string | 출발 라벨 | 노드 매칭 |
| `rel` | enum | 관계 타입 (위 5종) | 순회 |
| `dst` | string | 도착 노드 id | 위상 골격 |
| `dst_label` | string | 도착 라벨 | 노드 매칭 |
| `eventName` | string | 원본 API명 | READ/MODIFY/PRIVESC 세분, MITRE 매핑의 재료 |
| `eventSource` | string | 서비스 엔드포인트 | 서비스별 필터 |
| `eventTime` | datetime | 사건 시각 (ISO 8601, UTC) | 시간순 인과, 킬체인 순서 |
| `eventID` | string | 원본 CloudTrail 레코드 ID | **원본 로그 역추적** |
| `sourceIP` | string | 요청 IP | 유출 탐지, 공격자 상관 |
| `userAgent` | string | 요청 도구 | 자동화 도구/SDK 식별 |
| `outcome` | enum | SUCCESS / FAILURE | **성공/실패 필터의 재료** |
| `errorCode` | string | 실패 사유 (AccessDenied / NoSuchBucket / ...) | 실패 유형별 분석 |
| `readOnly` | boolean | CloudTrail readOnly 플래그 (있으면) | **READ/WRITE 판정** (접두어 추측보다 정확) |
| `issuedAt` | datetime | 세션 발급 시각 (ISSUES에만) | 발급-사용 시간차 |

**헤더**

```csv
src,src_label,rel,dst,dst_label,eventName,eventSource,eventTime,eventID,sourceIP,userAgent,outcome,errorCode,readOnly,issuedAt
```

> **보존 3요소(★)**: `eventID`(역추적), `outcome`/`errorCode`(실패 보존), `readOnly`(정확한 읽기/쓰기 판정)는 플랫폼의 핵심이다. 이 재료가 있어야 뷰 층이 목적별 해석을 재파싱 없이 파생할 수 있다.

---

## 파일 목록

| 파일 | 종류 |
|------|------|
| `principals.csv` | 노드 |
| `roles.csv` | 노드 |
| `workloads.csv` | 노드 |
| `resources.csv` | 노드 |
| `services.csv` | 노드 |
| `edges.csv` | 엣지 |

---

## 후처리 (뷰 층) — 기반을 목적별로 해석하는 방법

기반 그래프는 한 번만 적재하고, 목적별 해석은 **재import 없이** enrich(속성 태깅)나 쿼리로 얹는다. 아래는 대표 뷰의 파생 방법이다.

### 뷰 층 관계 파생 (기반에 없던 엣지 생성)

기반 관계로부터 계산해 새 엣지를 만든다. 기반은 변경하지 않는다.

**SAME_CREDENTIAL** — 발급된 세션이 다시 주체로 등장 (credential chaining):

```cypher
// 같은 accessKeyId가 발급 결과이자 이후 행위 주체인 경우 연결
MATCH (issued:Principal), (actor:Principal)
WHERE issued.id = actor.id AND issued.kind = 'TempKey'
// (동일 노드로 통합된 경우 이 파생은 불필요 — 통합 여부에 따라 선택)
MERGE (issued)-[:SAME_CREDENTIAL]->(actor);
```

**LEADS_TO_ROLE** — role 간 권한 전이 (권한 중심 뷰):

```cypher
// 키가 기반 주체여도, role→role 권한 흐름을 후처리로 오버레이
MATCH (r1:Role)-[:ISSUES]->(p:Principal)-[:ASSUME_ROLE]->(r2:Role)
MERGE (r1)-[:LEADS_TO_ROLE]->(r2);
```

**Identity 승격** — arn을 신원 노드로 올려 키들을 묶음 (신원 중심 뷰):

```cypher
MATCH (p:Principal) WHERE p.arn IS NOT NULL
MERGE (i:Identity {arn: p.arn})
MERGE (i)-[:OWNS]->(p);
```

### 뷰 층 속성 태깅 (enrich)

기반 엣지에 목적별 해석을 속성으로 덧붙인다. 원본은 그대로 둔다.

**읽기/쓰기 분류** (사후조사 뷰):

```cypher
MATCH ()-[r:ACCESS]->()
SET r.opClass = CASE
  WHEN r.readOnly = true THEN 'READ'
  WHEN r.eventName STARTS WITH 'Get' OR r.eventName STARTS WITH 'List'
       OR r.eventName STARTS WITH 'Describe' THEN 'READ'
  ELSE 'WRITE'
END;
```

**MITRE / 위험도 태깅** (위험 탐지 뷰):

```cypher
MATCH ()-[r]->()
WHERE r.eventName IN ['AttachUserPolicy','PassRole','UpdateAssumeRolePolicy']
SET r.mitreTactic = 'Privilege Escalation', r.riskLevel = 'HIGH';

MATCH ()-[r]->()
WHERE r.eventName IN ['StopLogging','DeleteTrail']
SET r.mitreTactic = 'Defense Evasion', r.riskLevel = 'HIGH';
```

> MITRE Tactic ↔ eventName은 N:N이므로 (예: AssumeRole = Credential Access + Privilege Escalation) 다중 값은 리스트 속성으로 보존한다. 태깅 기준이 바뀌면 `REMOVE` 후 재태깅하면 되며, 기반 재import는 불필요하다.

### 뷰 층 쿼리 (태깅 없이 즉석 필터)

**성공 경로만 순회** (사후조사):

```cypher
MATCH path = (p:Principal {id:'<키>'})-[rels:ACCESS|ASSUME_ROLE|ISSUES*1..8]->(end)
WHERE all(r IN rels WHERE r.outcome = 'SUCCESS')
RETURN path;
```

**MITRE 전술 시퀀스 = 킬체인 재구성** (위험 탐지 + 도달성 결합):

```cypher
MATCH path = (p:Principal)-[rels*1..10]->(target)
WHERE 'Credential Access' IN [r IN rels | r.mitreTactic]
  AND 'Privilege Escalation' IN [r IN rels | r.mitreTactic]
RETURN path;
```

---

## 후처리로 가능한 것과 불가능한 것

| 변형 | 가능? | 조건 |
|------|:-----:|------|
| 속성 추가·재분류 (READ/MODIFY, MITRE, 위험도) | O | eventName·outcome·readOnly가 보존돼 있으면 |
| 새 엣지 파생 (SAME_CREDENTIAL, LEADS_TO_ROLE) | O | 기반 관계로부터 계산 가능하면 |
| 새 노드 파생 (Identity 승격, 집계 노드) | O | 재료 속성(arn 등)이 보존돼 있으면 |
| 주체를 키 → role로 **집계** | O | 키가 기반이면 묶을 수 있음 |
| 주체를 role → 키로 **분해** | X | 굵게 담으면 세부 정보가 없음 |
| 버린 정보 복원 (실패, 원본 eventName) | X | 기반이 안 담았으면 불가 |
| 노드 라벨 골격 교체 | △ | 가능하나 재import에 준하는 비용 |

**두 원리**:
1. 후처리는 "세밀 → 집계" 방향은 자유, "집계 → 세밀"은 불가 → 기반은 최소 단위로 담는다.
2. 후처리는 "있는 것으로 새 구조 파생"은 가능, "없는 것 생성"은 불가 → 기반은 아무것도 버리지 않는다.

---

## 알려진 한계

1. **정적 인프라 부재**: CloudTrail은 행위 기록이지 자산 목록이 아니므로, "존재하지만 로그에 안 나타난" 리소스·권한은 그래프에 없다. 순방향 도달성이 과소추정될 수 있다. 완전한 backbone은 IAM/Config 스냅샷이 있어야 하며, 이는 별도 데이터 소스를 요한다(후순위 과제).
2. **불완전 식별**: Lambda/EC2 등 계정·리전 스코프 리소스는 로그에 스코프 정보가 없으면 전역 유일 식별이 불가능하다. 데이터 소스의 한계로 스키마로는 해결 불가.
3. **보존 필드의 로그 의존성**: `eventID`, `readOnly`, `errorCode`는 CloudTrail 버전·이벤트에 따라 없을 수 있다. 없으면 해당 뷰(정확한 읽기/쓰기 판정 등)는 대체 규칙(eventName 접두어)으로 폴백해야 한다. → 원본 로그로 실제 존재 여부 검증 필요.
4. **플랫폼의 비용**: "다 보존" 원칙상 기반 CSV는 목적 종속 모델보다 크다. 크기가 문제되면 노이즈 집계·엣지 분할·`neo4j-admin import` 등 축소 전략을 뷰/적재 단계에서 적용한다(정보 손실을 수반하므로 최후에).
