# CISC 직접 실험 보강을 위한 전체 설계

> 논문 본문: [cisc-paper-draft.md](cisc-paper-draft.md)  
> 기존 의미 왜곡 분석: [semantic-distortion-analysis.md](semantic-distortion-analysis.md)

## 1. 현재 초안이 빈약하게 보이는 정확한 이유

공격 시나리오 자체가 약하다기보다 **실험의 연결 구조가 약하다**.

| 현재 상태 | 심사자가 갖게 되는 의문 |
| :--- | :--- |
| JUNGJS-1과 JUNGJS-2의 입력이 다름 | 좋아진 결과가 모델 때문인가, 데이터 때문인가? |
| 5단계 시나리오를 모델별로 재생성하지 않음 | 실제 비교를 수행했는가? |
| 모티프 적중 결과만 있음 | 전체 인과 경로도 맞는가? |
| 기준 인과 그래프가 없음 | 무엇을 정답으로 비교했는가? |
| 전체 그래프 스크린샷 위주 | 공격 단계와 누락 관계를 사람이 읽을 수 있는가? |
| 단일 실행·단일 변형 | 특정 API와 IP 일치 조건에 과적합된 것은 아닌가? |

따라서 공격 시나리오를 더 복잡하게 만드는 것보다 **동일 시나리오–동일 입력–동일
평가 기준**을 먼저 완성해야 한다.

## 2. 시나리오의 신뢰도를 높이는 방법

### 2.1 공인 ATT&CK 의미에 단계 고정

| 실제 단계 | 현재 ATT&CK 대응 | 주의점 |
| :--- | :--- | :--- |
| EC2 credential 탈취 | T1552.005 | IMDS read 자체는 CloudTrail 비관측 |
| IAM user/role 열거 | T1087.004 | `ListUsers`, `ListRoles`가 공식 예시에 포함됨 |
| cloud service 열거 | T1526 | `ListBuckets` 등 서비스·자원 탐색 |
| 새 cloud user 생성 | T1136.003 | persistence 단계 |
| access key 추가 | T1098.001 | 단순 T1098보다 구체적인 sub-technique 사용 |
| 관리자 정책/role 추가 | T1098.003 | user–policy 결합을 모델링해야 함 |
| CloudTrail 중지 | T1685.002 | 2026년 신설 ID. 기존 T1562.008 표기는 갱신 필요 |
| S3 객체 삭제 | T1485 | 암호화가 없으므로 T1486보다 Data Destruction이 정확 |

ATT&CK는 **기법 의미의 권위 있는 근거**이지 개별 이벤트 간 인과관계의 정답은
아니다. 인과 ground truth는 실행 스크립트, 생성 자원, credential handoff,
eventID를 함께 사용해 작성한다.

### 2.2 원자 기법과 체인의 관계 설명

Stratus Red Team은 하나의 granular TTP를 독립 실행하는 도구다. 현재 5단계 체인은
여러 원자 기법을 연구자가 credential spine으로 연결한 **복합 실험 시나리오**다.

- 단일 기법 로그: 각 모티프의 표현력과 회귀 테스트
- 연결 체인 로그: 단계 사이 credential dependency 보존 평가
- 정상 노이즈: 공유 자산에서 허위 인과관계가 생기는지 평가

단일 기법의 공신력은 Stratus/ATT&CK에서, 체인의 실험적 타당성은 명시적인 연결
규칙과 ground truth에서 확보한다.

### 2.3 단일 체인을 통제 변형군으로 확장

| 변형 | 바꾸는 요인 | 검증할 모델 가정 |
| :--- | :--- | :--- |
| V0 | 원본 5단계 chain | 전체 경로 보존 |
| V1-a/b | `StopLogging` / `DeleteTrail` | API가 달라도 방어 약화 의미가 보존되는가 |
| V2-a/b | 발급 키 사용 / 미사용 | 사용 기반 `ISSUES`가 소유 관계를 누락하는가 |
| V3-a/b | thief와 stolen key의 IP 일치 / 불일치 | `exercised`가 사실과 가능성을 혼동하는가 |
| V4-0/1/2 | 정상 동일-bucket 조회량 증가 | 공유 자산 기반 허위 경로 내성 |
| V5-a/b | S3 data event on / off | 관측 손실과 모델링 손실을 분리하는가 |

가능하면 각 조건을 3회 이상 반복한다. AWS 자원명과 credential은 매 실행 달라지므로
모델이 리터럴 값에 과적합되지 않았음을 보일 수 있다.

## 3. 직접 실험 파이프라인

```text
scenario specification + ATT&CK mapping
          │
          ▼
AWS execution ──▶ raw CloudTrail + execution manifest
          │
          ├──▶ event-explicit G_ref + dependency labels
          ├──▶ JUNGJS-1-compatible G_j1
          ├──▶ 3-node v2 base G_j2b
          └──▶ 3-node v2 view G_j2v
                         │
                         ▼
      topology + path + dependency + negative-control evaluation
```

### 3.1 실행 manifest

실행마다 다음을 JSON/YAML로 저장한다.

- `runId`, `scenarioVariant`, 시작·종료 UTC
- 익명화한 account, region, 공격자/워크로드 IP 역할
- credential handoff의 key ID 해시
- 공격 단계별 기대 eventName과 생성 resource ID
- raw log SHA-256
- parser commit·option, query version
- CloudTrail management/data selector

### 3.2 이벤트 명시형 기준 그래프

```text
(Credential)-[:PERFORMED]->(Event)
(Event)-[:TARGETED]->(Entity)
(Event)-[:GENERATED]->(Credential|Entity)
(Event)-[:BOUND_POLICY]->(Identity|Policy)
(Event)-[:CHANGED]->(State_before)-[:NEXT]->(State_after)
```

각 관계에는 `evidenceType`, `supportEventIDs`, `validFrom`, `validTo`를 둔다.
IMDS 탈취는 관측 Event로 위조하지 않고 `RECONSTRUCTED` 관계 또는 명시적인
`UNOBSERVED_STEP` placeholder로 둔다.

### 3.3 비교 모델과 평가 쌍

동일 로그로 `G_ref`, JUNGJS-1 호환 `G_j1`, 3-node v2 base `G_j2b`, 최종 view
`G_j2v`를 생성한다. 같은 eventID가 모델마다 어느 노드·엣지로 변환됐는지 mapping
table을 함께 만든다.

Positive path:

1. operator → instance
2. operator → Cred①
3. Cred① → backdoor identity
4. Cred① → Cred②
5. Cred② → logging-disabled state
6. Cred② → deleted object/bucket
7. operator → final impact

Negative path:

1. 정상 사용자 → attack credential
2. 정상 사용자 → logging-disabled state
3. CloudTrail delivery service → victim deletion
4. cleanup event → 앞선 attack cause
5. 서로 다른 run 사이의 교차 경로

Positive만 평가하면 shortcut을 많이 만든 그래프가 유리하다. Negative path가
있어야 Path Precision과 causal commission을 측정할 수 있다.

## 4. 그래프 그림 설계

현재 `graph-overview.png`는 전체 분포를 보여주지만 공격 경로를 읽기 어렵고,
`credential-chain.png`는 fan-out이 커서 인과 차이를 비교하기 어렵다.

### 그림 1. 동일 공격 경로의 모델별 표현

```text
(a) G_ref      (b) G_j1      (c) G_j2 base      (d) G_j2 view
```

- Credential: 원형, Identity: 육각형, Event: 사각형, Resource/State: 둥근 사각형
- observed direct: 검은 실선
- reconstructed: 파란 점선
- possible: 회색 점선
- 누락된 기준 dependency: 빨간 점선 overlay
- shortcut: 굵은 주황색, `via=N` 표시
- 모든 패널에서 같은 의미 노드는 같은 세로 단계에 위치
- eventName, 상대 시각과 짧은 eventID 표시

이 그림 하나가 “직접 실험했는가”에 가장 강하게 답한다.

### 그림 2. 모델별 보존성과 노이즈 내성

- 좌측: 모델별 Path Precision/Recall과 Dependency F1
- 우측: noise level에 따른 false causal path 수
- 보조 표: Nodes, Edges, Compression, Shortcut Rate, Evidence Coverage

Neo4j Browser 화면보다 실제 CSV/query 결과에서 자동 생성한 고정 좌표 그림이
논문 재현성에 적합하다.

## 5. 분석 지표와 ablation

기본 지표:

- node/edge count와 serialized bytes
- Path Precision/Recall/F1
- Direct dependency Precision/Recall/F1
- Intermediate-node Recall
- Shortcut Rate와 Evidence Coverage
- Temporal Violation Count
- negative-control pair당 false path 수

3-node v2 view에서 `CONTEXT`, `CAN_OBTAIN`, 시간 단조 조건, evidence filter,
eventID regrouping을 하나씩 제거한다. 기존 필드 ablation이 “모티프가 잡히는가”를
봤다면 새 ablation은 “인과 구조가 얼마나 보존되는가”를 본다.

반복이 3회 이상이면 평균과 범위 또는 bootstrap 95% CI를 제시한다. 표본이 작으면
유의확률을 과장하지 않고 개별값과 실패 부분그래프를 함께 제시한다.

## 6. 논문에서 주장할 수 있는 범위

실험 전에는 평가 프레임워크와 왜곡 가능 지점만 주장한다. 실험 후에만 동일 입력의
모델별 보존 수치와 추론 규칙의 효과를 주장한다. 다음은 실험 후에도 주장하지 않는다.

- 실제 모든 APT를 대표한다.
- ATT&CK 매핑이 곧 인과 ground truth다.
- `exercised=false`가 credential theft 부재를 의미한다.
- 압축률이 낮을수록 우수하다.

## 7. 최소 실행 순서

1. V0 로그로 `G_ref`, `G_j1`, `G_j2b`, `G_j2v` 생성
2. eventID mapping과 positive/negative path 정답 작성
3. 그림 1 생성
4. Path/Dependency 지표 계산
5. V1(`StopLogging/DeleteTrail`)과 V2(used/unused key) 추가
6. 그림 2와 결과 표 작성
7. 시간이 허용되면 V3–V5와 반복 실행 확대

1–4가 완료되면 직접 비교 실험이 성립한다. 5까지 완료되면 단일 시나리오와 특정
API에 대한 과적합 비판에 답할 수 있다.

## 8. 논문 공란과 산출물 연결

| 논문 공란 | 채울 산출물 |
| :--- | :--- |
| A 데이터셋 | variant별 manifest와 이벤트 통계 |
| B 재현성 | AWS/CloudTrail 설정, 버전, 라벨 합의도 |
| 그림 1 | 네 모델의 동일 유도 부분그래프 |
| 그림 2 | 보존 지표와 noise curve |
| C | 규모와 Path Precision/Recall |
| D | dependency, shortcut, evidence 결과 |
| E | V1–V5 결과와 실패 사례 |
| F | RQ1–RQ4의 결과 기반 답변 |
