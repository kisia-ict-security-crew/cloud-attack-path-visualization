# CISC 논문 보강을 위한 추가 모델링 지점

> 대상 초안: [cisc-paper-draft.md](cisc-paper-draft.md)  
> 우선순위는 CISC 3–4쪽 논문에서 인과 보존의 정량 근거를 완성하는 데 필요한
> 순서이다. 아래 항목의 결과가 나오기 전까지 초안의 공란 A–C는 비워 둔다.

## 1. 제출 전 우선 구현

### 1.1 Event-explicit 기준 그래프 — 공란 A

현재 모델을 즉시 교체하기 위한 것이 아니라 **평가 정답**을 만들기 위한 모델이다.

```text
(Credential)-[:PERFORMED]->(Event)
(Event)-[:USED|TARGETED]->(Entity_before)
(Event)-[:GENERATED|MODIFIED]->(Entity_after)
```

필요한 작업:

- `aws.5_chain_n1` 129개 레코드를 `eventID`당 Event 노드 하나로 생성
- request participant, response product, credential owner, state effect 역할을 분리
- 각 dependency에 `OBSERVED_DIRECT`, `RECONSTRUCTED`, `POSSIBLE` 라벨 부여
- 최소 두 명이 필수 dependency를 독립 라벨링하고 합의도 기록
- `W→L` 관측 손실과 `L→G` 모델링 손실을 별도 표기

이 기준 그래프가 없으면 Dependency Preservation 수치를 계산할 수 없다.

### 1.2 동일 데이터에 대한 모델 재생성 — 공란 C

JUNGJS-1은 flaws.cloud, JUNGJS-2 보고 결과는 6개 독립 Stratus 로그를 사용했다.
현재 수치는 모델 효과와 데이터셋 효과가 섞여 있어 직접 비교할 수 없다.

- 동일한 `aws.5_chain_n1`에서 JUNGJS-1 호환, JUNGJS-2 base/view를 모두 생성
- 파서 버전, 입력 SHA-256, 옵션, 노드·엣지 수를 manifest로 저장
- 방향 경로와 방향+시간 단조 경로를 각각 평가
- 정상 사용자→victim bucket과 시나리오 간 공유 노드를 negative control로 사용

### 1.3 시간 유효 경로

경로의 모든 홉에 `t_i≤t_(i+1)`을 적용한다. `CONTEXT`의 `firstSeen/lastSeen`은
관계의 실제 수명이 아닌 관측 구간이므로 다음을 분리한다.

- `observedAt`: 근거 이벤트 관측 시각
- `validFrom/validTo`: 모델이 주장하는 관계 유효 구간
- `inferredAt`: 추론 관계가 생성된 시각
- `supportEventIDs`: 추론 근거

`CAN_OBTAIN.at`은 가장 이른 control event가 아니라 선택된 인과 후보와 그 선택
규칙을 기록해야 한다.

## 2. 모델 개선 후보 — 공란 B

### 2.1 이벤트 재구체화(event reification)

모든 이벤트를 영구 노드로 바꾸지 않아도 된다. 다중 참여자 이벤트만 Event 노드로
승격하거나, 질의 시 같은 `eventID` 엣지를 임시 Event 노드로 복원할 수 있다.

우선 대상:

- `AttachUserPolicy`: user–policy 결합 관계
- `CreateAccessKey`: issuer–owner–credential 관계
- `AssumeRole`: caller–role–issued session 관계
- 배치 API: 한 호출과 대상별 성공/실패 관계

비교할 설계:

1. 모든 이벤트를 노드로 표현
2. 다항 이벤트만 선택적으로 노드화
3. 현 저장 모델을 유지하고 평가/표시 시에만 `eventID`로 복원

### 2.2 Entity state versioning

동일 리소스 노드에 이벤트를 누적하면 상태 변화의 원인과 결과가 보이지 않는다.
최소한 보안상 중요한 상태만 버전으로 분리한다.

```text
TrailState(logging=true)
  └─ StopLogging ─▶ TrailState(logging=false)

ObjectState(exists=true)
  └─ DeleteObject ─▶ ObjectState(exists=false/delete-marker)
```

우선 상태:

- CloudTrail `existence`, `logging-status`
- IAM principal의 attached policies
- access key의 active/inactive와 owner
- S3 object의 existence, version, delete marker

상태 전이를 도입하면 `DeleteTrail`과 `StopLogging`을 API 이름이 아니라 서로 다른
상태 효과로 정규화할 수 있다.

### 2.3 발급 시점의 credential ownership

현재 `ISSUES`는 키의 사용 흔적에서 소유자를 재구성한다. 다음 두 관계를 구분한다.

- `ISSUED_TO`: `CreateAccessKey`/`AssumeRole` 응답에서 직접 생성, 발급 시각부터 유효
- `ATTRIBUTED_TO`: 후속 `userIdentity` 사용 흔적으로 재확인

두 관계가 일치하면 신뢰도를 높이고, 불일치하면 조사 신호로 남긴다. 이렇게 하면
발급 후 한 번도 쓰이지 않은 백도어 키도 소유 관계가 유지된다.

### 2.4 관계의 증거 수준

모든 최종 엣지에 다음 메타데이터를 공통 적용한다.

| 필드 | 의미 |
| :--- | :--- |
| `evidenceType` | `OBSERVED_DIRECT`, `RECONSTRUCTED`, `POSSIBLE`, `TRANSITIVE` |
| `supportEventIDs` | 원본 또는 추론 근거 이벤트 |
| `ruleId/ruleVersion` | 관계 생성 규칙과 버전 |
| `confidence` | 증거 강도. 확률로 해석하지 않으면 ordinal로 사용 |
| `via` | shortcut이 숨긴 중간 노드/관계 |

`CAN_OBTAIN.exercised=false`는 탈취가 없다는 뜻이 아니므로 negative evidence로
취급하지 않는다.

### 2.5 이진 `advances`의 다축화

`readOnly=false`와 공격 전진을 동일시하지 않고 적어도 다음 역할을 분리한다.

- `changesState`: 리소스 상태를 바꾸는가
- `exposesInformation`: 정보가 주체에게 노출되는가
- `grantsCapability`: 새로운 권한/자격증명을 부여하는가
- `supportsDecision`: 후속 행위의 의사결정 근거로 라벨된 정찰인가
- `attackRelevant`: 특정 시나리오 ground truth에서 공격에 속하는가

기반 그래프에는 AWS가 제공하는 사실을 유지하고, 마지막 두 항목은 목적별 뷰에만
둔다.

## 3. 범위 확장 시 추가할 모델링

### 3.1 시나리오 및 수집 경계

공통 운영자 키나 버킷 때문에 독립 실험이 연결되지 않도록 데이터 출처를 보존한다.

- `datasetId`, `accountId`, `trailId`, `ingestBatchId`
- 시나리오 경계가 알려진 합성 로그의 `scenarioId`
- 실제 로그에서는 시나리오 ID를 ground truth와 모델 추론 값으로 분리

### 3.2 외부 계정과 위임 주체

현재 확인된 공백:

- `ModifySnapshotAttribute`의 외부 수신 계정
- SAML/WebIdentity 외부 IdP 소유자
- IAM Identity Center `onBehalfOf`
- delegated access의 `invokedByDelegate`

이들은 크로스 계정 유출과 위임 경로의 종착점이 사라지는 원인이 된다.

### 3.3 배치 효과와 cardinality

이벤트 하나와 대상 N개의 관계를 유지하고 다음을 구분한다.

- 요청된 대상 수
- 성공 대상 수
- 실패 대상 및 오류
- CloudTrail에서 보안상 숨겨져 복구할 수 없는 대상 수

복구 불가능한 cardinality를 임의 추정하지 말고 `unknown`으로 남긴다.

## 4. 논문 공란 완료 조건

| 공란 | 완료 조건 |
| :--- | :--- |
| A 기준 그래프 | 기준 그래프 파일, 노드·엣지 수, 라벨링 지침, 합의도 |
| B 보강 모델 | 스키마 그림, 관계 정의, 기존 모델과의 호환/비용 설명 |
| C 정량 결과 | 동일 입력의 4개 모델 결과와 Path/Dependency 지표 |

가장 작은 제출 가능 단위는 **1.1 기준 그래프 + 1.2 동일 데이터 재생성 + 1.3
시간 단조 경로**이다. 2장의 모든 개선안을 구현하지 않더라도 이 세 가지가 있으면
현재의 정성 분석을 검증 가능한 CISC 실험 논문으로 강화할 수 있다.
