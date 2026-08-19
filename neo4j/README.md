# Neo4j

CloudTrail 로그에서 생성한 그래프 데이터를 Neo4j에 적재하고 조회하기 위한 파일을 관리합니다.

## 구조

```text
neo4j/
├─ README.md
├─ import.cypher
└─ queries/
   ├─ identity-credential.cypher
   ├─ identity-credential-execution.cypher
   ├─ created-credential.cypher
   ├─ credential-chain.cypher
   └─ credential-overview.cypher
```

## 데이터

Neo4j에 적재하는 CSV 파일은 다음과 같습니다.

```text
identity.csv
credential.csv
execution.csv
api_event.csv
resource.csv
edges.csv
```

## 파일 설명

### `import.cypher`

CSV 데이터를 읽어 다음 노드와 관계를 생성합니다.

노드:

* `Identity`
* `Credential`
* `Execution`
* `APIEvent`
* `Resource`

관계:

* `HAS_CREDENTIAL`
* `STARTED_EXECUTION`
* `CREATED_CREDENTIAL`

### `queries/identity-credential.cypher`

Identity와 연결된 Credential을 조회합니다.

### `queries/identity-credential-execution.cypher`

Identity에서 Credential을 거쳐 Execution으로 이어지는 구조를 조회합니다.

### `queries/created-credential.cypher`

APIEvent를 통해 생성된 Credential 관계를 조회합니다.

### `queries/credential-chain.cypher`

생성된 Credential이 이후 Execution으로 이어지는 흐름을 조회합니다.

### `queries/credential-overview.cypher`

여러 `CREATED_CREDENTIAL` 관계를 조회하여 전체적인 분포를 확인합니다.

## 실행

Neo4j import 디렉터리에 CSV 파일을 배치한 뒤 `import.cypher`를 순서대로 실행합니다.

데이터 적재가 완료되면 `queries/`의 Cypher 파일을 사용하여 그래프를 조회하고 시각화할 수 있습니다.
