## 1. 제안 배경

기존 구조Credential

```
Identity (Credential) → Execution (APIEvent) → Resource
```

하지만 공격 경로를 시각화하기 위해서 권환 전환과정에 집중

```
IAM User
  ↓ Access Key 사용
User Context
  ↓ AssumeRole
Admin Role Session
  ↓ InvokeFunction
Lambda
  ↓ Execution Role
Lambda Context
  ↓ GetSecretValue
Secret
```

기존 `Execution` 하나로는 IAM User의 직접 실행, AssumeRole을 통해 생성된 Role Session, Lambda와 같은 Workload의 실행 권한을 명확하게 구분하기 어려움

CSV를 구성

```
Identity        : 권한의 주체
Credential      : 인증에 사용되는 수단
SecurityContext : 실제 권한이 행사되는 실행 상태
Workload        : Lambda, EC2 등 코드를 실행하는 객체
Resource        : 접근·변경되는 대상 자산
```

API Event는 객체 간 관계로 변환 (엣지로 쓴다는 말과 거의 동일, 이후에 event는 원본을 놔두는 파일이 필요)

예시) `GetSecretValue` 이벤트

```
SecurityContext ──READS──-> Secret
```

(원본 API 이름과 Event ID는 관계에 저장하여 실제 CloudTrail 로그까지 역추적할 수 있도록 구성해야한다)

---

## 2. 정규화 CSV 구조

```
identities.csv
credentials.csv
security_contexts.csv
workloads.csv
resources.csv
relationships.csv
```

### `identities.csv`

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `identity_id` | string | O | Identity 고유 ID | 동일 User/Role을 하나의 노드로 연결 |
| `identity_type` | string |  | Identity 유형 | User, Role, Service 등을 구분 |
| `arn` | string |  | Identity ARN | Session 및 다른 객체와 정확하게 연결 |
| `name` | string |  | User/Role 이름 | 그래프 노드에 표시 |
| `account_id` | string |  | AWS Account ID | Cross-Account 흐름 식별 기반으로 사용 |

주요 `identity_type`

```
HUMAN_USER
ROLE
ROOT
FEDERATED_PRINCIPAL
SERVICE_PRINCIPAL
UNKNOWN
```

type의 경우에는 대표 type이 존재 (사람 서비스 루트 등을 구분하기 위해)

`AssumedRole`은 Role 자체가 아니라 특정 시점에 해당 Role 권한을 사용하는 실행 상태이므로 Identity가 아닌 `SecurityContext`로 분리한다

---

### `credentials.csv`

Access Key와 STS Temporary Credential처럼 인증에 사용되는 자격 증명을 저장한다

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `credential_id` | string | O | Credential 고유 ID | 동일 Credential의 사용 흐름 연결 |
| `credential_type` | string |  | Credential 유형 | 장기 Access Key와 임시 Credential 구분 |
| `owner_identity_id` | string |  | Credential 소유 Identity | Identity와 Credential 연결 |
| `temporary` | boolean |  | 임시 Credential 여부 | AssumeRole 전후 Credential을 구분 |

주요 유형

```
ACCESS_KEY
TEMP_ACCESS_KEY
FEDERATED_TOKEN
SERVICE_CREDENTIAL
UNKNOWN
```

예시) Alice가 가지고 있는 access key (발급행위가 아니라 기존에 가지고있던것)

```
Alice
  ↓ OWNS_CREDENTIAL
AccessKey
```

---

### `security_contexts.csv`

실제 API 호출이 어떤 Identity의 권한 상태에서 수행됐는지를 저장한다

사실상 이게 핵심!

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `context_id` | string | O | 실행 Context 고유 ID | 실제 API 행위의 주체를 식별 |
| `context_type` | string |  | Context 유형 | 직접 실행, Role Session, Workload 실행 구분 |
| `effective_identity_id` | string |  | 현재 권한 Identity | 해당 Context가 누구의 권한을 사용하는지 연결 |
| `credential_id` | string |  | 사용 Credential | Credential과 실행 Context 연결 |
| `parent_context_id` | string |  | 이전 Context | AssumeRole 및 Role Chaining의 권한 전환 추적 |
| `session_arn` | string |  | STS Session ARN | 동일 Role의 서로 다른 Session 구분 |
| `source_identity` | string |  | 최초 또는 원래 Identity | 여러 번 권한이 전환돼도 최초 행위자 역추적 |

주요 유형

```
DIRECT_USER_CONTEXT
ROLE_SESSION
FEDERATED_SESSION
WORKLOAD_CONTEXT
SERVICE_CONTEXT
UNKNOWN_CONTEXT
```

예시) alice가 admin role에 assume해서 session을 발급받음

```
AliceContext
   ↓ ASSUMES
AdminRole
   ↓
AdminSession
```

`parent_context_id`를 통해서 하나의 흐름을 지속적으로 잇는 것임

```
AliceContext
   ↓
AdminSession
   ↓
LambdaContext
```

---

### `workloads.csv`

Lambda, EC2, ECS와 같이 실제로 코드를 실행하는 컴퓨팅 객체를 저장

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `workload_id` | string | O | Workload 고유 ID | 동일 Workload를 하나의 노드로 연결 |
| `workload_type` | string |  | Workload 종류 | Lambda, VM, Container 등을 구분 |
| `arn` | string |  | Workload ARN | 로그 및 다른 객체와 정확하게 연결 |
| `name` | string |  | Workload 이름 | 그래프 화면에 표시 |
| `account_id` | string |  | 소속 Account | Account 경계 이동 분석 기반 |
| `region` | string |  | 실행 Region | Region 단위 시각화 및 객체 구분 |

예시

```
Lambda      → FUNCTION
EC2         → VIRTUAL_MACHINE
ECS Task    → CONTAINER_TASK
EKS Pod     → KUBERNETES_WORKLOAD
```

Lambda 자체와 Lambda Execution Role등에 대한 구분 예시 (헷갈림 방지용)

```
Lambda                = Workload
Lambda Execution Role = Identity
Lambda 실행 권한       = SecurityContext
```

---

### `resources.csv`

공격자가 최종적으로 접근하거나 변경하는 대상 자산을 저장한다

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `resource_id` | string | O | Resource 고유 ID | 동일 자산을 하나의 노드로 연결 |
| `resource_type` | string |  | Resource 유형 | Secret, Storage, Database 등을 구분 |
| `arn` | string |  | Resource ARN | CloudTrail Event 대상과 정확하게 연결 |
| `name` | string |  | Resource 이름 | 그래프 노드 표시 |
| `account_id` | string |  | Resource 소유 Account | Cross-Account 접근 분석 기반 |
| `region` | string |  | Resource Region | Region 간 접근 흐름 표현 |

예시

```
S3 Bucket       → STORAGE
S3 Object       → OBJECT
Secrets Manager → SECRET
KMS Key         → KEY
DynamoDB        → DATABASE
```

---

### `relationships.csv`

앞의 5개 객체를 연결하여 실제 공격 흐름을 구성하는 Edge를 저장한다.

| 컬럼 | 타입 | PK | 의미 | 필요 이유 |
| --- | --- | --- | --- | --- |
| `relationship_id` | string | O | 관계 고유 ID | 각각의 Edge 식별 |
| `relationship_type` | string |  | 관계 의미 | ASSUMES, INVOKES, READS 등의 공격 흐름 표현 |
| `source_id` | string |  | 시작 객체 ID | Edge 시작 노드 지정 |
| `source_type` | string |  | 시작 객체 유형 | 어떤 종류의 노드에서 시작했는지 구분 |
| `target_id` | string |  | 대상 객체 ID | Edge 도착 노드 지정 |
| `target_type` | string |  | 대상 객체 유형 | 연결되는 노드 종류 구분 |
| `event_id` | string |  | CloudTrail Event ID | 실제 원본 로그까지 역추적 |
| `event_time` | datetime |  | 행위 발생 시각 | 공격 흐름의 시간 순서 구성 |
| `event_name` | string |  | 실제 AWS API 이름 | 정규화 후에도 원본 행위 보존 |
| `outcome` | string |  | SUCCESS / FAILURE | 성공한 공격과 실패한 시도 구분 |
| `source_ip` | string |  | 요청 출발 IP | 공격 출처 분석 |
| `user_agent` | string |  | API 호출 환경 | CLI, SDK, Browser, AWS Service 등 구분 |

API 이름을 그대로 Edge Type으로 사용하지 않고 보안 의미 기준으로 정규화한다.

read에 해당하면 아래처럼 read로 포함

```
GetObject
GetSecretValue
GetItem
      ↓
    READS
```

**원본 API 이름은 `event_name`에 유지해야함

---

## 3. 관계 정의 및 공격 흐름

주요 관계는 다음과 같이 제한한다

| 관계 | 의미 |
| --- | --- |
| `OWNS_CREDENTIAL` | Identity가 Credential을 소유 |
| `ESTABLISHES_CONTEXT` | Credential을 이용해 실행 Context 형성 |
| `ACTS_AS` | Context가 특정 Identity 권한으로 실행 |
| `ASSUMES` | 다른 Role의 권한 획득 |
| `ISSUES_CONTEXT` | Role이 새로운 Role Session을 제공 |
| `DERIVES_CONTEXT` | 기존 Context에서 새로운 Context가 파생 |
| `INVOKES` | Workload 호출 |
| `RUNS_AS` | Workload가 특정 Identity 권한으로 실행 |
| `SPAWNS_CONTEXT` | Workload 실행으로 새로운 Context 생성 |
| `READS` | Resource 조회 |
| `WRITES` | Resource 데이터 기록 |
| `CREATES` | 객체 생성 |
| `MODIFIES` | 객체 또는 설정 변경 |
| `DELETES` | 객체 삭제 |

### IAM User 직접 실행

```
Identity
   ↓ OWNS_CREDENTIAL
Credential
   ↓ ESTABLISHES_CONTEXT
SecurityContext
   ↓ ACTS_AS
Identity
```

실제 Resource 접근

```
SecurityContext
   ↓ READS
Resource
```

---

### AssumeRole

```
AliceContext
   ↓ ASSUMES
AdminRole
   ↓ ISSUES_CONTEXT
AdminSession

AliceContext
   ↓ DERIVES_CONTEXT
AdminSession
```

이를 통해 `AdminSession`에서 발생한 API 요청도 최초 `AliceContext`까지 역추적할 수 있다

---

### Role Chaining

```
UserContext
   ↓
RoleA
   ↓
SessionA
   ↓
RoleB
   ↓
SessionB
```

`parent_context_id`와 `DERIVES_CONTEXT`를 통해 여러 단계의 Role 전환도 하나의 경로로 유지한다.

---

### Lambda를 이용한 이동

```
AdminSession
   ↓ INVOKES
Lambda
   ↓ RUNS_AS
LambdaRole

Lambda
   ↓ SPAWNS_CONTEXT
LambdaContext
   ↓ ACTS_AS
LambdaRole

LambdaContext
   ↓ READS
Secret
```

이 구조를 사용하면 단순히 lambda를 통해 secret을 읽은 그 과정 전체를

```
Alice
→ AdminRole
→ AdminSession
→ Lambda
→ LambdaExecutionRole
→ LambdaContext
→ Secret
```

이렇게 실제 권한 전환 과정을 시각화할 수 있게 됨

---

## 4. 기존 구조와의 차이?

기존 구조는 Credential과 API Event를 중심으로 진행되었다.

> 어떤 Credential이 어떤 API를 호출하여 어디까지 도달했는가?
> 

이번 구조의 목표

> 최초 Identity가 어떤 Credential을 이용했고, 어떤 권한 Context로 전환됐으며, 어떤 Workload를 거쳐 최종 Resource에 도달했는가?
> 

공격 경로를 구성하는 데 필요한 권한 Context와 Workload를 추가로 분리한 정규화 구조입니다.

특히 정규화 단계에서는 의미를 충분히 보존하고, 실제 Neo4j 시각화 단계에서는 필요에 따라 다음처럼 축약해서 보여줄 수 있게 된다.

```
Alice
  ↓ AssumeRole
AdminRole
  ↓ Invoke
Lambda
  ↓ RunAs
LambdaRole
  ↓ Read
Secret
```

정규화에서는 정보 손실을 최소화하고, 시각화에서는 목적에 맞게 축약하는 방식으로 구성는 것이 목적이다.

---

## 5. 최종 결과

최종 정규화 흐름

```
CloudTrail Raw Log
        ↓
Identity 추출
        ↓
Credential 추출
        ↓
SecurityContext 복원
        ↓
Workload 식별
        ↓
Resource 식별
        ↓
API 의미 정규화
        ↓
Relationship 생성
        ↓
CSV Export
```

생성 결과

```
identities.csv
credentials.csv
security_contexts.csv
workloads.csv
resources.csv
relationships.csv
```

최종적으로 다음과 같은 공격 경로를 표현할 수 있는 정규화 데이터를 만드는 것을 목표로한다.

```
Identity
   ↓
Credential
   ↓
SecurityContext
   ↓
Role / Session 전환
   ↓
Workload
   ↓
새로운 SecurityContext
   ↓
Resource
```

이를 통해 Identity와 권한 상태의 변화가 유지되는 공격 경로 그래프로 시각화할 수 있도록 하는 것이 목표이다.