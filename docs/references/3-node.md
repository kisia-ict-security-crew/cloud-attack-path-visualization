# Neo4j Graph Database Specification

**프로젝트명:** CloudTrail 기반 침해 사고 추적 그래프 데이터베이스  
**데이터베이스 모델:** 3-Node + Semantic Context-Aware Edge Architecture  

---

## 1. 개요 (Overview)

본 DB 명세서는 AWS CloudTrail 감사 로그를 효율적으로 저장, 시각화, 포렌식 추적하기 위해 설계된 그래프 데이터베이스 구조를 정의한다. 노드 폭발(Graph Bloat) 방지를 위해 엔티티를 **3개 핵심 노드(Actor, Resource, Service)**로 추상화하고, 행위 맥락은 **Semantic Edge(`BASE_EVENT`)** 속성으로 내재화하였다.

---

## 2. 노드 스키마 명세 (Node Specification)

### 2.1 `Actor` 노드
* **설명:** API 행위를 유발하는 모든 주체 (IAM User, Role, Workload Executable, External Anonymous 등)
* **주요 라벨:** `:Actor`, `:IDENTITY`

| 속성명 (Property) | 데이터 타입 | 필수 여부 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| **`id` (PK)** | String | Y | 주체 식별자 (`AKIA...`, `arn:aws:iam::...`, `svc:lambda`, `anonymous:1.2.3.4`) |
| `actorType` | String | Y | CloudTrail `userIdentity.type` (`IAMUser`, `AssumedRole`, `Root`, `FederatedUser`) |
| `arn` | String | N | 주체 Amazon Resource Name |
| `accountId` | String | Y | AWS 계정 ID (미확인 시 `""`) |
| `kind` | String | Y | 자격증명 세부 형태 (`LongTermKey`, `TempKey`, `Service`, `Unknown`) |
| `categoryL1` | String | Y | 1계층 대분류 추상화 개념 (`IDENTITY`) |

---

### 2.2 `Resource` 노드
* **설명:** API 호출의 대상이 되는 데이터, 권한, 인프라 자산
* **주요 라벨:** `:Resource`, `:RESOURCE`

| 속성명 (Property) | 데이터 타입 | 필수 여부 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| **`id` (PK)** | String | Y | 자산 ARN 또는 식별 키 (`arn:aws:s3:::my-bucket`, `arn:aws:iam::...:role/DevRole`) |
| `resourceType` | String | Y | 자산 세부 세그먼트 (`bucket`, `object`, `role`, `workload`, `policy`, `secret` 등) |
| `service` | String | Y | 해당 자산이 속한 AWS 서비스 (`s3`, `iam`, `secretsmanager`, `ec2`) |
| `name` | String | Y | 자산 식별 명칭 (`my-bucket`, `DevRole`, `GetSecretValue`) |
| `accountId` | String | Y | 소유 AWS 계정 ID |
| `categoryL1` | String | Y | 1계층 대분류 추상화 개념 (`RESOURCE`) |

---

### 2.3 `Service` 노드
* **설명:** 특정 대상 자산(Resource)이 명시되지 않는 정찰/열거성 API 접근 시 수렴점이 되는 노드
* **주요 라벨:** `:Service`, `:SERVICE`

| 속성명 (Property) | 데이터 타입 | 필수 여부 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| **`id` (PK)** | String | Y | 서비스 엔드포인트 도메인 (`s3.amazonaws.com`, `sts.amazonaws.com`) |
| `service` | String | Y | 서비스 모듈명 (`s3`, `sts`, `iam`, `ec2`) |
| `categoryL1` | String | Y | 1계층 대분류 추상화 개념 (`SERVICE`) |

---

## 3. 관계(Edge) 스키마 명세 (Relationship Specification)

### `BASE_EVENT` 관계
* **설명:** 출발 노드(`Actor`)와 도착 노드(`Actor`, `Resource`, `Service`) 간의 단일 API 호출 및 권한 위임 이벤트
* **타입 명칭:** `:BASE_EVENT`

| 속성명 (Property) | 데이터 타입 | 필수 여부 | 설명 및 예시 |
| :--- | :--- | :---: | :--- |
| `rel` | String | Y | 기반 위상 타입 (`ACCESS`, `ASSUME_ROLE`, `ISSUES`, `INVOKES`) |
| **`actionL2`** | String | Y | **2계층 의미론적 행위 추상화 (`READ`, `CREATE`, `MODIFY`, `DELETE`, `ASSUME`, `DENY`)** |
| `eventID` | String | Y | CloudTrail 원본 Record PK (포렌식 역추적용 UUID) |
| `eventName` | String | Y | 원본 AWS API 명칭 (`GetObject`, `PutRolePolicy`, `AssumeRole`) |
| `eventSource` | String | Y | 원본 API 서비스 소스 (`s3.amazonaws.com`, `iam.amazonaws.com`) |
| `eventTime` | DateTime | Y | 이벤트 발생 시각 (ISO8601 $\rightarrow$ Neo4j `datetime()`) |
| `sourceIP` | String | N | 요청자 IP 주소 (`192.0.2.1`) |
| `outcome` | String | Y | 행위 성공 여부 (`SUCCESS`, `FAILURE`) |
| `readOnly` | Boolean | Y | CloudTrail 읽기 전용 여부 플래그 (`true`, `false`) |

---