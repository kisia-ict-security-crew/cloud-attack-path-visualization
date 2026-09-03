# 3-Node v2 — 그래프 데이터 모델

CloudTrail 로그를 그래프로 변환하는 기반(base) 모델의 스키마 정의다.
이 문서는 **어떤 노드·엣지가 있고 각각 어떤 속성을 갖는가**만 다룬다.
목적별 해석(분류·판정·추론)은 뷰 계층에 있다 — `enrich.md` 참조.

---

## 0. 설계 원칙

1. **노드 정체성은 `id` 하나가 결정한다.** 역할은 그 위에 얹는 라벨이며 한 노드가
   여럿을 겸할 수 있다.
2. **엣지는 두 종류다.** 시각이 있는 *일어난 일*(`:BASE_EVENT`)과, 여러 이벤트에
   걸쳐 *성립하는 사실*(`:CONTEXT`)을 분리한다.
3. **기반에는 판단이 없다.** 성공/실패 필터, 위험도, "공격이다" 같은 판정을 담지
   않는다. 그런 것은 전부 뷰 계층에서 얹는다.

---

## 1. 노드

모든 노드는 공통 라벨 `:Node` 를 가지며, `id` 가 유일 키다.
그 위에 역할 라벨 `:Actor` / `:Resource` / `:Service` 를 **하나 이상** 가진다.

### 1.1 역할 라벨

| 라벨 | 의미 |
| :--- | :--- |
| `:Actor` | API 행위를 유발한 주체로 관측된 적이 있다 |
| `:Resource` | API 호출의 대상 자산으로 관측된 적이 있다 |
| `:Service` | 대상이 특정되지 않은 접근의 수렴점 (폴백) |

**`:Actor` 와 `:Resource` 를 동시에 갖는 노드가 정상이다.** Role 은 세션 발급
주체(Actor)이면서 정책 부착 대상(Resource)이고, Instance 는 생성 대상으로
태어나 자격증명 보유 주체가 된다. 이 노드들이 곧 권한 체인이 통과하는 지점이라,
라벨로 쪼개면 하필 거기서 그래프가 끊긴다.

### 1.2 노드 속성

| 속성 | 타입 | 필수 | 설명 |
| :--- | :--- | :---: | :--- |
| **`id`** (PK) | String | Y | 전역 유일 식별자. 주체는 `accessKeyId`/`svc:…`/ARN, 자산은 정규 ARN, 서비스는 엔드포인트 도메인 |
| `labels` | String | Y | 역할 라벨 목록. `Actor` / `Resource` / `Actor;Resource`. 적재 시 실제 라벨로 변환 |
| `actorType` | String | N | `userIdentity.type` (`IAMUser`, `AssumedRole`, `Root`, `AWSService`, `Role`) |
| `arn` | String | N | 주체 ARN |
| `accountId` | String | N | 소유 AWS 계정 ID |
| `kind` | String | N | 자격증명 형태 (`LongTermKey`, `TempKey`, `Role`, `Service`, `Anonymous`, `Unknown`) |
| `resourceType` | String | N | 자산 세부 타입 (`bucket`, `object`, `role`, `instance`, `policy`, `secret`, `trail`, `flow-log` …) |
| `service` | String | N | 소속 AWS 서비스 (`s3`, `iam`, `ec2` …) |
| `name` | String | N | 자산 식별 명칭 |
| `region` | String | N | 리전 |
| `synthetic` | String | N | id 를 합성했으면 `'true'`, 정규 ARN 관측 시 `'false'` |

### 1.3 id 규칙

**주체 id** 는 `accessKeyId` 를 최우선으로 쓴다. `arn → accessKeyId` 가 1:N 이기
때문이다(같은 ARN·같은 세션명인데 키가 다르고 출처 IP 가 다른 경우가 실재한다).

```
우선순위: accessKeyId > svc:{invokedBy} > arn > anonymous:{sourceIP}
```

**자산 id** 는 `정규 ARN > 계정·리전을 붙인 합성 ARN > service:name` 순으로
결정한다. 같은 리소스가 이름으로 한 번·ARN 으로 한 번 참조돼도 한 노드로
수렴시키기 위해서다. 특수 규칙 둘:

- **S3 ARN** 은 타입 접두어가 없다(`arn:aws:s3:::bucket/key`). 별도 처리한다.
- **`assumed-role` ARN 은 세션이지 role 이 아니다.** `arn:aws:iam::…:role/{name}`
  으로 정규화해 세션 발급자와 정책 부착 대상을 한 노드로 합친다.

---

## 2. 엣지 — `:BASE_EVENT` (일어난 일)

출발 노드가 `:Actor` 로서, 도착 노드가 `:Resource`/`:Service`/`:Actor` 로서
참여한 **단일 API 호출**. 이벤트 하나가 **서로 다른** 대상 N개를 건드리면 `eventID`
를 공유하는 N개 엣지가 생긴다. **한 이벤트가 같은 대상을 여러 번 가리켜도(응답이
요청 값을 echo 하는 경우 등) 엣지는 하나다** — 요청 쪽(ACCESS)을 남기고 응답 echo
는 버린다. 서로 다른 이벤트가 같은 쌍을 건드리는 건 정상이므로 적재 시 `MERGE` 가
아니라 `CREATE` 를 쓴다.

| 속성 | 타입 | 필수 | 설명 |
| :--- | :--- | :---: | :--- |
| `rel` | String | Y | 위상 타입 (아래 표) |
| **`actionL2`** | String | Y | 의미론적 행위 추상화 — **'의도'만** (`READ`, `CREATE`, `MODIFY`, `DELETE`, `ASSUME`, `EXECUTE`). 결과는 `outcome`/`errorClass` 가 따로 들고 있다 |
| `dstAs` | String | Y | 도착 노드가 이 엣지에서 맡은 역할 (`Resource`, `Service`, `Actor`) |
| `refPath` | String | Y | 대상을 찾아낸 JSON 경로 (`requestParameters.instanceIds[0]`, `resources[].ARN` 등). 대상 여부 판단을 뷰로 미루기 위한 출처 정보 |
| `eventID` | String | Y | CloudTrail 원본 Record PK (포렌식 역추적용) |
| `eventName` | String | Y | 원본 API 명칭 |
| `eventSource` | String | Y | 원본 API 서비스 소스 |
| `eventTime` | DateTime | Y | 발생 시각 |
| `sourceIP` | String | N | 요청자 IP. **항상 IP 는 아니다** — 서비스 대리 호출이면 `ec2.amazonaws.com` 같은 도메인 |
| `outcome` | String | Y | `SUCCESS` / `FAILURE`. **대상별로 갈릴 수 있다** (§2.2) |
| `errorCode` | String | N | CloudTrail 원문 그대로 |
| `errorClass` | String | N | `errorCode` 를 세 갈래로 접은 것: `DENIED`(권한 없음) / `NOT_FOUND`(대상 없음) / `FAULT`(파라미터·기능 오류). 성공은 빈 값 |
| `readOnly` | Boolean | Y | 읽기 전용 플래그 |

### 2.1 `rel` 값

| 값 | 의미 | 출처 |
| :--- | :--- | :--- |
| `ACCESS` | 대상 자산에 대한 접근 | `resources[]`, `requestParameters`, `serviceEventDetails` |
| `PRODUCES` | 호출 결과로 새로 생성된 자산 (요청에 없고 응답에만 나온 것) | `responseElements` |
| `ASSUME_ROLE` | AssumeRole 계열이 role 을 향함 | 위와 동일, 대상이 role 일 때 |
| `OBTAINS` | **호출 주체가 자격증명을 획득** | STS `responseElements.credentials.accessKeyId` (임시키) / IAM `responseElements.accessKey.accessKeyId` (`CreateAccessKey` 의 영구키) |

### 2.2 대상별 성공/실패

배치 API(예: `DeleteFlowLogs`)는 여러 대상을 한 번에 처리하고 **일부만 실패**할 수
있다. 이때 최상위 `errorCode` 는 없고, 실패는 `responseElements.unsuccessful` 에만
담긴다. **이벤트가 노드가 아니라 엣지이므로 대상별로 나눠 기록한다** — 한 호출이
대상 A 는 성공, B 는 실패면 엣지가 둘로 갈라져 각각 다른 `outcome`·`errorCode` 를
갖는다.

```
DeleteFlowLogs  ACCESS  actionL2=DELETE  outcome=SUCCESS  ->  flow-log/fl-0aaa…
DeleteFlowLogs  ACCESS  actionL2=DELETE  outcome=FAILURE  ->  flow-log/fl-0bbb…
                                         errorCode=InvalidFlowLogId.NotFound
```

---

## 3. 엣지 — `:CONTEXT` (성립하는 사실)

시각이 하나로 정해지지 않고 여러 이벤트에 걸쳐 관측되는 관계. 이벤트의 *행위* 가
아니라 `userIdentity` 안의 **호출자 신원 설명**에서 나온다. `(src, dst, rel)`
단위로 집계한다.

| 속성 | 타입 | 필수 | 설명 |
| :--- | :--- | :---: | :--- |
| `rel` | String | Y | `ISSUES` \| `RUNS_ON` |
| `via` | String | Y | 근거·유형 표시. ISSUES: `assumed-role`/`iam-user`/`root`/`federated`/`assumed-root`/`assumeRoleResponse`. RUNS_ON: `AWS::EC2::Instance` 등 |
| `evidenceCount` | Integer | Y | 이 사실을 뒷받침한 이벤트 수 |
| `firstSeen` / `lastSeen` | DateTime | Y | 관측 구간. **성립 시각이 아니라 처음 관측된 시각**이다 |
| `eventIDs` | List\<String\> | Y | 근거 eventID (기본 최대 20개) |

| `rel` | 방향 | 의미 |
| :--- | :--- | :--- |
| `ISSUES` | (신원) → (자격증명) | 이 자격증명은 이 신원에 속한다 |
| `RUNS_ON` | (자격증명) → (워크로드) | 이 키는 이 워크로드에 실려 있다 |

### 3.1 `ISSUES` — 자격증명이 어느 신원에 속하는가

같은 IAM 주체가 이 모델에서는 두 좌표계로 나뉜다. **행위할 때는 `accessKeyId` 로
키잉된 `:Actor`(키 노드)** 이고, **대상이 될 때는 `arn` 으로 키잉된 `:Resource`
노드**다(예: `CreateUser` 로 만들어진 사용자). `ISSUES` 가 이 둘을 잇는다 — 키가
어느 신원의 것인지를, 그 키가 **쓰인** 이벤트의 `userIdentity` 에서 재구성한다.
발급 이벤트(`CreateAccessKey` 등)가 아니라 **키가 쓰인 흔적**이 트리거라, 발급이
로그에 없어도 성립하고 모든 신원 형태에 대칭으로 적용된다.

신원(`src`)은 `userIdentity` 유형에 따라 정해진다:

| 조건 | `src` 신원 | `via` |
| :--- | :--- | :--- |
| `sessionContext.assumedRoot = true` | 계정 `:root` | `assumed-root` |
| `sessionContext.sessionIssuer` 있음 | 그 issuer (보통 role) | `assumed-role` / `federated` |
| `type = IAMUser` (세션 아님) | `userIdentity.arn` (사용자) | `iam-user` |
| `type = Root` (세션 아님) | `userIdentity.arn` (`:root`) | `root` |
| `accessKeyId` 없음 (AWSService 등) | — (묶을 자격증명 노드가 없음) | — |

`dst` 는 언제나 그 이벤트의 주체 키다. `AssumeRole` 응답이 새로 발급한 임시키는
`assumeRoleResponse` 로도 별도 근거가 붙는다.

> **트리거가 '사용'이라 생긴 성질:** 발급만 되고 한 번도 쓰이지 않은 키는
> `userIdentity` 흔적이 없어 `ISSUES` 가 안 생긴다(발급 사실 자체는 `OBTAINS`
> base event 에 남는다). 그리고 **SAML/WebIdentity 같은 외부 IdP 세션**은 소유
> 신원이 AWS ARN 이 아니라 결합하지 않는다 — 한계는 `REPORT.md` 참조.

`RUNS_ON` 은 역방향으로 읽을 때 가치가 있다 — "워크로드를 장악하면 거기 실린
자격증명을 얻는다". 리소스→자격증명 경로를 만드는 근거이며, 뷰 계층의
`:CAN_OBTAIN` 이 이걸 쓴다.

---

## 4. 적재

```bash
python parser_node3_v2.py <log.json> -o ./csv
```

`nodes.csv` / `edges.csv` / `context.csv` 세 파일이 나온다. Neo4j 적재 Cypher 는
`load_3node_v2.cypher`, 그 위에 얹는 목적별 뷰는 `enrich.md` / `enrich_views.cypher`
참조.

주의점 두 가지:

- **리스트 구분자는 `|`.** `;` 는 cypher-shell 문장 구분자와 충돌한다. 단
  `labels` 컬럼은 `;` 를 쓰는데, Cypher 문장 안에서 `split()` 으로만 소비되고
  파일이 파이프로 넘어가지 않아 안전하다.
- **관계 적재는 양끝 노드를 못 찾으면 예외 없이 행을 건너뛴다.** CSV 행수와
  그래프 개수를 대조하는 검증 블록이 `load_3node_v2.cypher` 끝에 있다.
