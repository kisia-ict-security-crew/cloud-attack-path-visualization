# 그래프 스키마 정의 — 사후조사용 성공 기반 도달성 그래프

CloudTrail 로그를 그래프로 변환해 공격 경로를 사후조사 관점에서 재구성하기 위한 Neo4j 스키마 정의.

## 설계 원칙

1. Credential 단일 주체 — 모든 실행은 장기/단기 관계없이 자격증명으로 이뤄지므로, 행위 주체를 Credential 하나로 통합한다.
2. 실행자의 이원 배치 — "누구인가"의 안정적 부분(arn 등)은 `Credential` 노드 속성으로, "어디서/무엇으로"의 사건별 부분(sourceIP, userAgent)은 엣지 속성으로 둔다.
3. 성공 기반 — 성공한 사건만 그래프에 넣는다. 모든 엣지가 "실제로 성공한 도달"이다.
4. 읽기/쓰기 분리 — 정보 조회(READ)와 실제 변경(MODIFIED)을 관계 타입으로 분리해 "정보 유출 범위"와 "실제 피해 범위"를 구분한다.



## 추가로 적용해야하는 핵심 내용
1. 권한 이동 또는 상승 체인에 맥락 부여
2. IMDS 연결. (예를 들면 [사용자] - runinstance - [리소스] - (IMDS 다리) - [세션] 이런 형태에서 [IMDS 다리] 는 로그에 없을 수 있음)


## 후속 연구

1. 실패한 로그를 포함한 개별 모델링 제작하여 공격 시도 분석 가능하도록
2. 권한 정적 분석 내용과 병합하여 도달 가능한 곳 + 실제로 도달한 곳 같이 분석
3. 대용량 로그 처리를 위한 모델링 경량화 
4. 로그 -> db 로 정규화. 로그 형식이 다 달라서 예외사항을 처리해야함. 예를 들면 accesskeyID가 없는 경우는 어떻게 처리?

---

## 노드 (4개 CSV 파일)

### 1. `credentials.csv` — 주체

행위 주체. 기존 `principals.csv` + `sessions.csv`를 하나로 통합한 것.

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
|------|------|:--:|------|-----------|
| `id` | string | O | accessKeyId. 없으면 `svc:<서비스>` 또는 `arn:<arn>` | 노드 식별·병합의 근간. 모든 엣지의 매칭 키  |
| `kind` | enum | | `LongTermKey`(AKIA) / `TempKey`(ASIA) / `AWSService` | 장기키(지속 위협) vs 세션(한정) 구분. 유출 위험도가 다름 |
| `arn` | string | | 자격증명의 소유 신원 ARN(useridentity.arn) | "누가 실행했나". 같은 신원의 여러 키를 arn으로 묶어 질의.  |
| `accountId` | string | | AWS 계정 번호 | 다계정 환경에서 경계 식별. *호출한 계정/명령이 수행되는 계정 구분해야함* |
| `identityType` | enum | | IAMUser / AssumedRole / AWSService / Root 등 | 주체 유형별 필터. 일반 IAM 모델 호환 |

**헤더**

```csv
id,kind,arn,accountId,identityType
```

**정규화 방법**
id : accesskeyID. 없는 경우는 아래에서 다룸
kind : ASIA, AKIA로 구분
arn : useridentity.arn. 없는 경우 아래에서 다룸
accountID : 사용자의 계정 ID인지 아니면 호출된 대상의 계정 ID인지 정해야함
identityType : userIdentity.type 


**accesskeyID나 arn이 없는 경우**


---

### 2. `roles.csv` — 권한 허브

IAM role. credential chaining의 중심 관절.

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
|------|------|:--:|------|-----------|
| `id` | string | O | roleArn | role 전역 식별. `CAN_ASSUME`/`PROVIDES` 매칭 키 |
| `roleName` | string | | 짧은 이름 | 가독성 |
| `accountId` | string | | 소속 계정 | 크로스계정 role 취득(권한상승 핵심 패턴) 식별 |

**헤더**

```csv
id,roleName,accountId
```

**정규화 방법**

로그 형태에 따라 다르다.
AssumeRole 이벤트에서는 requestparameter에 담긴다.
AssumedRole은 SessionContext에 담긴다.
Role이 객체로 동작하는 event는 resources/requestParameters에 담겨있다.

상황 A: AssumeRole 이벤트가 로그에 있다
상황 B: AssumeRole 이벤트는 없지만, 그 세션이 활동한다
상황 C: role이 IAM 조작의 대상으로만 등장 (GetRole, AttachRolePolicy 등)
   문제: 같은 role/flaws가 상황 B에선 Role 노드(주체 허브)이고, 상황 C에선 조작 대상(PermissionTarget)

---

### 3. `data_resources.csv` — 정보 종착지

정보가 담긴 실재 리소스. 순방향 질의의 종착점(유출 대상). 기존 `resources.csv` 중 데이터성 + 성공 접근분만.

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
|------|------|:--:|------|-----------|
| `id` | string | O | `<필드>:<값>` (예: `bucketName:flaws.cloud`) | 전역 고유 대상 식별 |
| `resType` | enum | | bucketName / functionName / objectKey 등 | 데이터 유형. 유출 대상 분류 |
| `name` | string | | 실제 값 | 판독·외부 조인 |

**포함 기준**: `outcome=SUCCESS`이고 resType이 데이터성(bucket, function, object 등)인 접근의 대상만. 실패한 대량 버킷 열거는 포함하지 않는다.

**헤더**

```csv
id,resType,name
```

**정규화 방법**
로그 내의 정보의 한계로 완전 정규화는 불가능(계정이나 리전이 로그에 없고 이름만 있는 경우가 있음. 다른 계정의 같은 이름과 구분 불가능)
후보 1: arn을 사용
후보 2: arn 이 없다면 service:name 형태로 합성해서 사용


**이 resource가 자격을 받아 동작을 수행하는 경우(IMDS 다리)**

---

### 4. `permission_targets.csv` — 권한 조작 대상

권한 변경/조회의 대상(IAM user/role/policy 등). 기존 `resources.csv` 중 IAM성 + 성공 접근분만.

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
|------|------|:--:|------|-----------|
| `id` | string | O | `<필드>:<값>` (예: `userName:Level6`, `roleName:flaws`) | 권한 대상 식별 |
| `resType` | enum | | userName / roleName / policyName / instanceProfile 등 | 조작 대상 유형 |
| `name` | string | | 실제 값 | 판독 |

**DataResource와 분리하는 이유**: 실제 권한 변경(`AttachRolePolicy`, `DeleteRole` 등)의 대상과 정보 유출 대상(bucket/object)은 사후조사 심각도가 다르다. 라벨로 분리하면 "권한이 조작된 지점"만 별도 질의할 수 있다.

**헤더**

```csv
id,resType,name
```

---

## 엣지 (1개 CSV 파일)

### `edges.csv` — 모든 관계

모든 관계를 한 파일에 담고 `rel` 컬럼으로 구분한다.

#### 공통 컬럼 (모든 엣지가 가짐)

| 컬럼 | 타입 | 의미 | 필요 이유 |
|------|------|------|-----------|
| `src` | string | 출발 노드 id | 위상 골격 |
| `src_label` | string | 출발 라벨 | 라벨+id로 O(1) 노드 매칭 |
| `rel` | enum | 관계 타입 (아래 6종) | 행위 추상화, 그룹 단위 질의 |
| `dst` | string | 도착 노드 id | 위상 골격 |
| `dst_label` | string | 도착 라벨 | 매칭 최적화 |
| `eventName` | string | 원본 API명 | 세부 행위, 관계 재분류 근거 |
| `eventTime` | datetime | 사건 시각 (ISO 8601, UTC) | 시간순 인과, chaining 순서 추적 |
| `sourceIP` | string | 요청 IP | "어디서 실행" — 유출 탐지, 공격자 상관 |
| `userAgent` | string | 요청 도구 | "무엇으로 실행" — 자동화 도구/SDK 식별 |
| `issuedAt` | datetime | 세션 발급 시각 (`PROVIDES`/`ISSUED`에만 값) | 발급-사용 시간차 분석 |

> 성공 기반이므로 `outcome` 컬럼은 제외한다(전부 SUCCESS이므로 죽은 컬럼). 실패 사건을 넣을 때 부활시킨다.

#### 관계 타입 (rel) 6종

| rel | src → dst | 의미 | 매핑 규칙 (eventName 기준) |
|-----|-----------|------|----------------------------|
| `CAN_ASSUME` | Credential → Role | role 실제 취득 | `AssumeRole*` (성공) |
| `PROVIDES` | Role → Credential | role이 세션 발급 | AssumeRole의 결과 세션 |
| `ISSUED` | Credential → Credential | 이 키가 저 세션키를 발급(체인) | `CAN_ASSUME` + `PROVIDES` 연쇄로 파생 |
| `READ` | Credential → DataResource / Service | 정보 조회(유출) | `Get*` / `List*` / `Describe*` / `Lookup*` / `Batch*` |
| `MODIFIED` | Credential → PermissionTarget / DataResource | 실제 변경(침해) | `Put*` / `Create*` / `Delete*` / `Update*` / `Attach*` / `Detach*` / `Add*` / `Remove*` / `Set*` |
| `ENUMERATED` | Credential → Service | 서비스 열거(정찰) | 대상 없는 List/Describe (dst가 Service) |

**READ vs MODIFIED**: 이 스키마의 핵심 판단축. 대부분의 성공 사건은 READ(정보 수집)지만, 소수의 MODIFIED(실제 권한 조작)가 실제 침해를 나타낸다. 순방향 질의에서 이 둘을 분리해 유출 범위와 피해 범위를 각각 추적한다.

**헤더**

```csv
src,src_label,rel,dst,dst_label,eventName,eventTime,sourceIP,userAgent,issuedAt
```

---

## 파일 목록 요약 (기존 6개 → 5개)

| 파일 | 종류 | 기존 대비 변화 |
|------|------|----------------|
| `credentials.csv` | 노드 | `principals.csv` + `sessions.csv` **통합** |
| `roles.csv` | 노드 | 유지 (`accountId` 추가) |
| `data_resources.csv` | 노드 | `resources.csv`에서 **데이터성·성공분만** 분리 |
| `permission_targets.csv` | 노드 | `resources.csv`에서 **IAM성·성공분만** 분리 |
| `edges.csv` | 엣지 | `outcome` 제거, `userAgent` 추가, `rel` 6종 재편, `SAME_CREDENTIAL` 제거 |

제거된 것: `sessions.csv`(credentials로 흡수), `services.csv`(ENUMERATED 대상으로 축소), `SAME_CREDENTIAL` 관계(Credential 통합으로 불필요).

---

## 그래프 구조 개요

```
   [실행자: Credential.arn 속성 + edge의 sourceIP/userAgent로 표현]

   ┌──────────────┐   CAN_ASSUME    ┌────────┐
   │  Credential  │────────────────>│  Role  │
   │ (id=keyId)   │<────────────────│        │
   │ arn,kind,... │    PROVIDES     └────────┘
   └──────────────┘
     │    │    └────── ISSUED ──────> (다른 Credential)   ← chaining
     │    │
     │ READ                       MODIFIED
     ▼                               ▼
  ┌──────────────┐          ┌───────────────────┐
  │ DataResource │          │ PermissionTarget  │
  │ (bucket 등)  │          │ (user/role/policy)│
  └──────────────┘          └───────────────────┘

  [Service] ← READ / ENUMERATED 대상 (정찰 집계, 종착지 아님, 선택적)
```

## 대표 질의 (도달성)

**순방향 (취약점 → 유출/침해 가능 지점)**

```cypher
MATCH path = (start:Credential {id:'<유출된 키>'})
             -[:CAN_ASSUME|PROVIDES|ISSUED|READ|MODIFIED*1..8]->(end)
WHERE end:DataResource OR end:PermissionTarget
RETURN path
```

**역방향 (유출지 → 도달 가능했던 출발점)**

```cypher
MATCH path = (d:DataResource {id:'<유출 데이터>'})
             <-[:CAN_ASSUME|PROVIDES|ISSUED|READ*1..8]-(origin:Credential)
RETURN origin, path
```

성공 기반이므로 경로 상 모든 엣지가 "실제 성공한 도달"이다.

---

## 알려진 한계

1. **Credential 통합의 원본 충실성 희생** — "발급 순간"과 "사용 순간"을 한 노드로 합치므로, 두 시점을 물리적으로 구분해야 하는 분석(예: 발급 후 미사용 세션 추적)은 별도 속성으로 처리해야 한다.
2. **정적 권한 부재** — 성공 사건만 그래프에 넣으므로 "실제 행사된 권한"만 나타난다. "가질 수 있었으나 사용하지 않은 권한"은 보이지 않아 순방향 도달성이 실제보다 좁게(과소) 추정될 수 있다. CloudTrail 로그만으로는 근본 해결이 불가능하며, IAM 정책 스냅샷으로 보완해야 한다.
3. **실패 사건 제외** — 현재 성공 사건만 다룬다. 정찰/권한상승 시도(실패)의 분석은 향후 `outcome` 컬럼과 `ATTEMPTED_*` 관계로 확장한다.
