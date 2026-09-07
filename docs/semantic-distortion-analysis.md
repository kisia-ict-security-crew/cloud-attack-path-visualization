# CloudTrail 공격 그래프의 의미 왜곡 분석

> 이 문서는 상위 [README](../README.md)의 연구 방향을 기준으로 JUNGJS-1과
> JUNGJS-2의 그래프 모델링 실험을 기억하기 위한 메모이자, 두 모델을 provenance
> graph의 인과 표현 및 실제 5단계 공격 시나리오와 비교한 연구 설계 초안이다.
>
> 1차 범위는 **Causal Distortion**, 2차 범위는 **Temporal Distortion**이다.
> 핵심 질문은 그래프를 얼마나 많이 줄였는지가 아니라 **얼마나 적은 왜곡으로
> 줄였는가**이다.

---

## 1. 연구 목표와 비교 경계

상위 README의 목표는 CloudTrail의 개별 API 호출을 연결하여 자격증명 전환,
실제 행위 경로, 영향 범위를 조사 가능한 그래프로 만드는 것이다. 따라서 최종
그래프의 품질은 공격 기법을 탐지했는지만으로 판단할 수 없다. 다음 두 질문을
분리해야 한다.

- **Path Preservation**: 공격자가 A에서 D까지 도달했다는 사실이 보존되는가?
- **Dependency Preservation**: A에서 D까지 도달하게 한 실제 의존 구조가
  보존되는가?

직접 `A → D`를 추가하면 Path Preservation은 높일 수 있지만, 실제 구조가
`A → B → C → D`였다면 Dependency Preservation은 낮아진다. 따라서 도달성만으로
인과 보존을 평가하면 안 된다.

### 1.1 왜곡을 측정할 세 층

```text
실제 실행 세계 W
  └─ 관측/수집 O ─▶ 원본 CloudTrail 이벤트 L
                       └─ 정규화/모델링 M ─▶ 기반 그래프 G_base
                                              └─ 합성/질의 V ─▶ 최종 뷰 G_view
```

이 연구의 주평가 구간은 `L → G_base → G_view`이다.

- IMDS에서 자격증명을 읽는 행위처럼 CloudTrail에 원래 없는 행위는
  **관측 손실**이다. 그래프 변환의 Causal Distortion으로 바로 세지 않는다.
- 로그에 있던 `AttachUserPolicy`의 사용자–정책 결합이 그래프에서 사라지는 것은
  **모델링 왜곡**이다.
- 두 홉을 `CAN_OBTAIN` 한 홉으로 접거나 `advances`로 일부 엣지만 순회하는 것은
  **뷰/질의 왜곡**이다.
- 관측 손실을 추론으로 보완할 수는 있지만, 그 엣지는 관측 사실과 같은 종류로
  표시하면 안 된다.

---

## 2. 모델링 실험 결과 메모

### 2.1 JUNGJS-1: 자격증명 체인 중심 5종 노드 모델

근거: [flaws.cloud Neo4j import](../JUNGJS-1/data/archive/neo4j/flaws.cloud%2019/README.md),
동일 디렉터리의 CSV 산출물.

| 산출물 | 개수 |
| :--- | ---: |
| Principal | 206 |
| Role | 6 |
| Session | 923 |
| Resource | 22,256 |
| Service | 118 |
| 전체 edge | 41,338 |

엣지는 `ACCESS` 38,284개, `HAS_ROLE` 1,208개, `ASSUME_ROLE` 923개,
`ISSUES` 923개이다. `ACCESS` 중 24,342개는 Resource, 13,942개는 Service로
향한다.

기억해야 할 모델링 경험은 다음과 같다.

- Principal, Role, Session을 분리하고 `Role -ISSUES→ Session`,
  `Session -SAME_CREDENTIAL→ Principal`로 세션 사용을 연결하려 했다.
- 개별 API 이벤트를 노드로 만들지 않고 `Principal → Resource/Service` 엣지의
  속성으로 넣었다.
- 같은 자격증명이 Session과 Principal 두 노드로 중복 표현되고, 같은 Role도
  행위 주체와 대상 좌표에서 갈릴 수 있었다. 이는 경로가 실제 의미 경계가 아닌
  타입 경계에서 끊어지는 원인이 되었다.
- `HAS_ROLE` 같은 상태 관계와 `ASSUME_ROLE` 같은 관측 이벤트 관계가 함께 있지만,
  CSV에서 같은 쌍의 반복과 관계의 유효 시간 범위가 명시되지 않았다.
- JUNGJS-1 산출물에는 엣지별 `eventID`가 없어 최종 엣지를 원본 레코드에
  일대일로 되짚는 provenance가 약하다.
- 실패 결과가 `SUCCESS/FAILURE`가 아니라 `NoSuchBucket`, `AccessDenied` 등 원문
  값과 섞여 있다. 성공 여부, 실패 종류, 행위 의도를 독립 축으로 비교하기 어렵다.

즉 JUNGJS-1은 **자격증명 전환 경로의 가능성을 확인한 초기 모델**이지만,
Entity split과 원본 근거 추적의 약점 때문에 Dependency Preservation을 정밀하게
평가하기 어려웠다.

### 2.2 JUNGJS-2: 3-node v2 기반 그래프와 목적별 뷰

근거: [연구 보고서](../JUNGJS-2/docs/graph-modeling/REPORT.md),
[3-node v2](../JUNGJS-2/docs/graph-modeling/3-node-v2.md),
[뷰 계층](../JUNGJS-2/docs/graph-modeling/enrich.md),
[질의](../JUNGJS-2/docs/graph-modeling/query.md).

JUNGJS-2는 JUNGJS-1의 단절을 다음과 같이 개선했다.

- 같은 `id`는 하나의 노드로 만들고 `Actor/Resource/Service` 역할을 멀티라벨로
  표현하여 Role의 복사본 분리를 줄였다.
- 주체 PK를 ARN이 아니라 `accessKeyId`로 두어 같은 신원의 서로 다른 키와 IP를
  구분했다.
- 단일 API 호출을 `BASE_EVENT` 엣지로 표현하고 `eventID`, `eventTime`, `refPath`,
  `actionL2`, `outcome`, `errorClass`, `readOnly`를 보존했다.
- 다중 대상 API는 이벤트–대상 단위의 병렬 엣지로 나누어 부분 성공/실패를
  대상별로 보존했다.
- `ISSUES`와 `RUNS_ON`은 여러 사용 흔적에서 재구성한 `CONTEXT`로 분리했다.
- 기반 그래프에 판단을 섞지 않고, 뷰에서 `advances`와 추론 관계
  `CAN_OBTAIN`을 추가했다. `CAN_OBTAIN`에는 경유 워크로드와 근거 시각을 남긴다.

보고서에 기록된 6개 Stratus 로그 실험 결과는 다음과 같다.

- 661개 원본 이벤트 → 123개 노드, 827개 `BASE_EVENT`, 39개 `CONTEXT`
- 대상 미해결 7.9%
- 원본 JSON 1,056KB → CSV 257KB, 원본의 24%
- 5개 공격 모티프가 정답과 정확히 일치
- `CAN_OBTAIN` 9개 중 `exercised=true`는 1개이며 ground truth와 일치
- 대상 추출 L1(ARN/AWS ID 정규식)에서 5개 모티프 중 4개 재현,
  L3(전체 키 화이트리스트)에서 5개 재현
- leave-one-out 결과 `readOnly` 제거 시 5개 모티프 중 4개가 깨짐

이는 **표현력과 최소 필드**를 검증한 좋은 파일럿이다. 다만 “모티프 정답 일치”는
기법 식별 결과이지 실제 인과 구조 전체가 보존되었다는 증거는 아니다.

### 2.3 현재 산출물의 재현성 주의점

현재 저장소 안의 결과 숫자는 세대가 섞여 있다.

- `REPORT.md`: 노드 123, `BASE_EVENT` 827, `advances` 263/564,
  종류 73/34/12/4
- `enrich_views.cypher`: 노드 93, `BASE_EVENT` 882, `advances` 316/566,
  종류 59/22/8/4
- `enrich.md`: `advances` 316/566이라고 쓰면서 종류는 73/34/12/4라고 기록

또한 보고서가 언급하는 `motifs.py`, `ablate.py`, `verifying script/`, 실험용
`csv/`는 현재 트리에 없다. 따라서 위 결과는 **기록된 실험 결과**로 인용할 수는
있지만 현재 체크아웃만으로 독립 재실행했다고 표현하면 안 된다. 후속 평가에서는
데이터셋 해시, 파서 커밋, 뷰 버전, 산출물 개수를 한 manifest에 고정해야 한다.

---

## 3. Provenance graph와의 의미 차이

[provenance 및 공격 재구성 조사](../JUNGJS-1/docs/references/provenance-and-reconstruction.md)의
SLEUTH 계열 모델은 프로세스·파일·소켓 같은 주체/객체 사이의 정보 흐름과
의존관계를 명시하고, 그 경로를 따라 태그를 전파한다. MGDA 계열의 시나리오
재구성은 저수준 이벤트를 상위 공격 단계로 다시 묶는다.

이를 기준으로 보면 현재 모델은 엄밀한 event-explicit provenance DAG보다는
**시간 속성이 있는 행위 멀티그래프 + 재구성 뷰**에 가깝다.

| 비교 항목 | Event-explicit provenance | JUNGJS-1/2 |
| :--- | :--- | :--- |
| 이벤트 표현 | Activity/Event 노드 | 주체→대상 엣지 속성 |
| 다항 관계 | 한 이벤트가 여러 입력·출력과 연결 | 같은 `eventID`의 병렬 엣지로 분해 |
| 객체 상태 변경 | 버전 객체 또는 생성/사용 관계 | 동일 리소스 노드에 여러 시각의 엣지 누적 |
| 직접 의존성 | `used`, `wasGeneratedBy` 등으로 구분 | `ACCESS/PRODUCES/OBTAINS`로 일부 표현 |
| 추론 관계 | 관측 관계와 별도 계층/근거 | JUNGJS-2의 `CAN_OBTAIN`이 별도 타입으로 표현 |
| 원본 추적 | 각 activity의 증거 유지 | JUNGJS-2는 `eventID/refPath`, JUNGJS-1은 약함 |

JUNGJS-2의 장점은 다중 대상의 결과를 대상별로 보존하는 것이다. 반대로 이벤트를
노드로 두지 않기 때문에 하나의 API가 결합한 여러 역할을 그래프 구조만으로 읽기
어렵다. `eventID`로 다시 묶어야만 원래의 한 사건이 복원된다. 따라서 비교 기준
그래프는 다음과 같이 두는 것이 적절하다.

```text
(Credential)-[:PERFORMED]->(Event)
(Event)-[:USED|TARGETED]->(Entity_before)
(Event)-[:GENERATED|MODIFIED]->(Entity_after)
```

최종 운영 모델을 반드시 이 형태로 바꾸자는 뜻은 아니다. 이 event-explicit
그래프를 **평가용 기준 그래프**로 두면 edge 기반 압축 모델이 무엇을 줄이고 무엇을
왜곡했는지 측정할 수 있다.

---

## 4. 실제 5단계 공격 시나리오의 기준 인과 구조

근거: [aws.5_chain_n1 상세 시나리오](../JUNGJS-1/docs/datasets/stratus_red_team_explanation/aws.5_chain_n1.md),
원본 129개 이벤트.

```text
operator key
  └─ SendCommand ─▶ EC2 instance
       └─ [CloudTrail 비관측: IMDS credential read]
            └─ Cred① 사용 ─▶ 정찰
                 ├─ CreateUser ─▶ backdoor identity
                 ├─ AttachUserPolicy ─▶ backdoor identity + AdministratorAccess
                 └─ CreateAccessKey ─▶ Cred②
                      ├─ StopLogging ─▶ trail state: logging → stopped
                      └─ DeleteObjects/DeleteObject×51 ─▶ victim bucket/objects
```

관측된 공격 창은 `07:42:37Z`부터 `07:43:17Z`까지 약 40초이며, 핵심 핸드오프는
`Cred① ASIA…ZXTI44UW → Cred② AKIA…XYTRAEEE`이다. 정상 노이즈의
`jjsworkspace`도 같은 버킷을 조회하므로 **같은 리소스를 공유한다는 사실은 인과
의존성을 뜻하지 않는다**.

이 기준 구조에서 특히 주의할 점은 다음과 같다.

- `ListRoles/ListUsers/ListBuckets/ListObjects`가 시간상 먼저 발생했어도 후속 행위의
  필수 원인이었는지는 별도 ground truth가 필요하다. 시간 선후를 곧바로 인과로
  바꾸면 안 된다.
- `AttachUserPolicy`와 `CreateAccessKey`는 둘 다 Cred②의 강한 후속 행위를
  가능하게 하는 조건이다. 단순 시간 순서대로 두 이벤트를 직렬 원인으로 놓는 것보다
  **백도어 신원에 권한과 키가 함께 결합됨**을 표현해야 한다.
- `StopLogging` 뒤의 삭제가 기록된 것은 별도 연구용 트레일이 있었기 때문이다.
  단일 트레일 환경에서 후속 로그가 사라지는 문제는 변환 왜곡이 아니라 관측 편향이다.

---

## 5. 의미 차이가 발생하는 구체적 지점

### 5.1 Causal Distortion — 1차 평가 대상

| 지점 | 현재 표현 | 실제/기준 의미 | 보존 영향 |
| :--- | :--- | :--- | :--- |
| 이벤트의 다항성 | 같은 `eventID`의 여러 주체→대상 엣지 | 한 이벤트가 여러 입력·대상·출력을 동시에 결합 | 도달은 남아도 결합 의존성이 약해짐 |
| `AttachUserPolicy` | Cred①→user, Cred①→policy 병렬 엣지 | policy가 **user에 부착**됨 | user→admin policy 의존성이 그래프 경로에 없음 |
| `CreateAccessKey` | Cred①→Cred② `OBTAINS`, Cred①→user | user의 credential이 생성됨 | 핸드오프 경로는 남지만 소유 관계는 후속 사용 전까지 불완전 |
| 사용 기반 `ISSUES` | key가 처음 쓰인 이벤트에서 identity→key 재구성 | 소유/발급은 `CreateAccessKey` 시점부터 성립 | 쓰이지 않은 키는 관계 누락, 사용 시각이 발급 시각처럼 오해될 수 있음 |
| `CAN_OBTAIN` | 주체→credential 한 홉 | 주체→workload, workload에 credential, 비관측 탈취 | Path는 강화하지만 중간 dependency는 축약됨 |
| `advances` | 성공·대상특정·(`OBTAINS` 또는 `readOnly=false`) | 모든 상태 변경이 공격 전진은 아니며 읽기도 공격 결정에 기여 가능 | benign 변경은 허위 전이, 정찰은 인과 경로에서 조기 종료 |
| 리소스 공유 | 여러 주체가 동일 bucket 노드에 연결 | 정상 조회와 악성 삭제가 같은 대상에서 독립 발생 | 무방향/시간 무시 순회 시 허위 인과 경로 생성 |
| 상태 버전 부재 | 동일 trail/bucket 노드에 시간 엣지 누적 | logging/on→off, object/existing→deleted 상태 전이 | 상태 전후 의존성과 효과가 구조로 보이지 않음 |
| 서비스 fallback | 대상을 못 찾으면 Service로 수렴 | 서로 다른 미해결 대상일 수 있음 | 허브를 통한 허위 도달과 entity merge 발생 |
| 통합 데이터셋 | 공통 키/리소스로 시나리오가 연결됨 | 시간대가 다른 독립 실험 | 시간 단조 조건 없는 reachability는 허위 경로 가능 |

#### 실제 시나리오에서 확인되는 일반화 실패

현재 `derive_action_l2` 규칙에서 `StopLogging`은 `DELETE`가 아니라 `EXECUTE`가 된다.
하지만 기존 M4 방어 회피 모티프는 `actionL2='DELETE'`인 trail/flow-log만 찾는다.
보고서의 6개 실험에는 `cloudtrail-delete`와 `vpc-remove-flow-logs`가 들어가지만
실제 5단계 체인은 `StopLogging`을 사용한다. 따라서:

- 공격 경로 순회에서는 `readOnly=false`라 `advances=true`로 남을 수 있다.
- 그러나 방어 회피 모티프 M4에서는 빠진다.
- 즉 **Path Preservation과 Technique-semantic/Dependency Preservation이 서로
  다른 결과를 보이는 구체적 사례**이다.

M4를 단순히 API 목록으로 보완하기보다 trail의 상태 전이
`logging=true → false`를 표현하고, `DeleteTrail`과 `StopLogging`을 각각
`existence`와 `logging-status`에 대한 상태 변경으로 정규화하는 편이 의미에 맞다.

### 5.2 Semantic Distortion

초안의 정의인 “원본 event semantics가 normalized relation으로 얼마나
축약됐는지”에 다음을 포함해야 한다.

- **predicate collapse**: `StopLogging`, `StartLogging`, 기타 이름이 모두
  `EXECUTE`가 될 수 있음
- **role loss**: request의 user와 policy가 각각 대상인 것은 남지만 “policy를
  user에 부착”했다는 역할 결합이 사라짐
- **effect loss**: API 의도는 남지만 리소스 상태가 실제로 어떻게 변했는지 없음
- **cardinality loss**: 배치 호출 한 건과 개별 효과 N개의 관계가 축약됨
- **outcome confusion**: 의도, 성공 여부, 실패 원인을 한 축으로 합치면 의미가 뒤집힘

JUNGJS-2가 `actionL2/outcome/errorClass`를 분리한 것은 JUNGJS-1보다 이 왜곡을
줄인 개선이다. 그러나 `actionL2`만 사용한 모티프가 원본 API의 서로 다른 상태
효과를 충분히 대체하는지는 별도 평가가 필요하다.

### 5.3 Entity Distortion

초안은 “여러 identity/session/resource가 동일 entity로 병합됐는지”만 다루지만,
실험에서는 **과병합과 과분할을 함께** 측정해야 한다.

- JUNGJS-1: Session과 Principal의 동일 credential 중복, Actor Role과 Resource
  Role의 분리는 과분할 사례다.
- JUNGJS-2: 멀티라벨 단일 노드로 Role 과분할을 줄였으나, 동일 IAM 주체를
  행위 좌표의 access key와 대상 좌표의 ARN으로 의도적으로 분리한다.
  `ISSUES`가 없거나 시각이 맞지 않으면 이 분리가 경로 단절로 이어진다.
- Service fallback은 서로 다른 미해결 대상을 한 서비스 노드에 모으므로
  과병합 사례다.
- 이름 기반 합성 ARN은 account/region/type 추론이 틀릴 때 실제 하나를 여러
  노드로 만들거나 서로 다른 것을 합칠 수 있다.

따라서 `D_e`는 최소한 `merge error`와 `split error` 두 항으로 나눈다.

### 5.4 Temporal Distortion — 2차 평가 대상

- `BASE_EVENT`는 시각을 보존하지만 이벤트 간 happens-before 관계는 명시하지 않는다.
- `CONTEXT`는 다수 이벤트를 `firstSeen/lastSeen/evidenceCount`로 집계한다.
  이는 관계의 실제 시작·종료가 아니라 **관측 구간**이다.
- `CONTEXT.eventIDs`는 기본 최대 20개라 장기 관계의 전체 근거를 잃을 수 있다.
- `CAN_OBTAIN.at`은 관련 control event의 최솟값을 사용한다. 실제 탈취에 가장 가까운
  `SendCommand`보다 앞선 `RunInstances` 등에 capability가 너무 일찍 부여될 수 있다.
- 동일 노드에 과거와 미래 엣지가 모두 붙으므로, 경로 질의가 각 홉에서
  `t₁ ≤ t₂ ≤ …`를 강제하지 않으면 미래의 원인이 과거의 결과로 이어질 수 있다.
- 초 단위가 같은 `DeleteObject` 다수는 순서인지 동시성인지 CloudTrail만으로
  결정하기 어렵다. 임의 정렬을 인과 순서로 평가하면 안 된다.

---

## 6. 왜곡 정의 수정안

| 종류 | 수정 정의 | 우선 측정 항목 |
| :--- | :--- | :--- |
| **Semantic Distortion `D_s`** | 원본 이벤트의 predicate, 참여자 역할, 결과, 효과, cardinality가 정규 관계에서 달라지거나 모호해진 정도 | 의미 구분 가능성, 역할 보존율, effect 보존율 |
| **Entity Distortion `D_e`** | 실제로 같은 엔티티의 과분할과 서로 다른 엔티티의 과병합 정도 | merge precision/recall, split rate, 연결 복구율 |
| **Temporal Distortion `D_t`** | 순서·간격·동시성·관계 유효 구간·시간 단조 경로가 소실되거나 잘못 생성된 정도 | order preservation, interval error, temporal-path precision |
| **Causal Distortion `D_c`** | 직접/추론/전이 관계의 구분, 실제 원인 구조, 방향, 중간 dependency가 최종 경로에서 누락되거나 추가·축약된 정도 | Path Preservation + Dependency Preservation |

`D_c`는 하나의 숫자로 바로 합치기보다 다음 오류 벡터로 먼저 보고하는 편이 낫다.

```text
D_c = (omission, commission, shortcut, direction, evidence, temporal-validity)
```

- `omission`: 실제 dependency가 없음
- `commission`: 실제로 없는 dependency가 추가됨
- `shortcut`: 중간 dependency가 한 홉으로 접힘
- `direction`: 원인과 결과 방향이 뒤집힘
- `evidence`: 관측/재구성/가능성의 구분 또는 원본 근거가 없음
- `temporal-validity`: 원인이 결과보다 늦거나 관계 유효 구간 밖임

---

## 7. 1차 평가 설계: Causal Distortion

### 7.1 기준 그래프 작성

준식형 로그마다 분석자가 다음 세 종류의 edge를 별도 표기한 event-explicit 기준
그래프 `G_ref`를 만든다.

1. `OBSERVED_DIRECT`: 원본 필드가 직접 지지하는 관계
2. `RECONSTRUCTED`: 여러 관측으로 재구성한 관계와 근거 eventID
3. `POSSIBLE`: 권한/구조상 가능하지만 행사 증거는 없는 관계

JUNGJS-2의 `BASE_EVENT`, `CONTEXT`, `CAN_OBTAIN`은 각각 위 세 종류와 대체로
대응하지만 완전히 같지는 않으므로, 변환 규칙별 대응표를 고정해야 한다.

### 7.2 Path Preservation

공격 단계의 시작–종료 쌍 집합을 `P_ref`라 할 때:

```text
Path Recall     = 최종 그래프에서 도달 가능한 기준 쌍 / |P_ref|
Path Precision  = 최종 그래프가 도달 가능하다고 한 쌍 중 기준에서도 가능한 쌍의 비율
D_c,path        = 1 - F1(Path Precision, Path Recall)
```

반드시 다음 세 조건으로 나누어 측정한다.

- 방향만 강제한 경로
- 방향 + 시간 단조를 강제한 경로
- 방향 + 시간 단조 + 관측/재구성 edge type을 제한한 경로

### 7.3 Dependency Preservation

기준 이벤트/엔티티를 최종 그래프에 매핑한 뒤 다음을 함께 측정한다.

- 직접 dependency edge precision/recall
- 기준 경로의 필수 중간 노드 보존율
- shortcut 비율: 기준에서 2홉 이상인데 최종에서 1홉인 관계
- event grouping 보존율: 같은 `eventID`의 참여자들을 다시 한 사건으로 복원 가능한 비율
- evidence coverage: 최종 관계에서 원본 eventID/refPath 또는 추론 근거를 찾을 수 있는 비율
- dependency type confusion matrix: direct / reconstructed / possible / transitive 간 오분류

### 7.4 첫 실험의 필수 대조군

같은 `aws.5_chain_n1`에 대해 다음 네 그래프를 비교한다.

1. 원본 event-explicit 기준 그래프
2. JUNGJS-1 방식 그래프
3. JUNGJS-2 base graph
4. JUNGJS-2 base + `advances` + `CAN_OBTAIN` 최종 뷰

그리고 아래 경로를 각각 채점한다.

- operator → instance → Cred①
- Cred① → backdoor identity → Cred②
- Cred② → trail logging-state change
- Cred② → victim bucket/object deletion
- 전체 operator → victim impact

정상 `jjsworkspace → victim bucket` 조회와 CloudTrail 로그 배달을 negative control로
두어, 리소스 공유만으로 공격 경로에 편입되는지 확인한다.

---

## 8. 우선 검증할 연구 가설

1. **JUNGJS-2는 JUNGJS-1보다 Entity split과 evidence loss를 줄여 전체 Path
   Recall을 높인다.**
2. **`CAN_OBTAIN`은 Path Recall을 높이지만 shortcut 증가로 Dependency
   Preservation을 낮출 수 있다.** 경유 워크로드를 경로에 펼쳐 평가하면 차이가
   줄어들 것이다.
3. **`advances`는 그래프 크기를 줄이지만 read-only 정찰의 실제 의존성을
   누락하고 정상 상태 변경을 과포함한다.**
4. **시간 단조 조건 없는 통합 그래프는 독립 시나리오와 공유 리소스 사이의
   Causal commission을 크게 만든다.**
5. **eventID 병렬 엣지 그룹을 event node로 일시 복원하면 저장 모델을 바꾸지
   않고도 Dependency Preservation 평가와 설명 가능성이 향상된다.**
6. **상태 전이 정규화가 단순 `actionL2`보다 `StopLogging/DeleteTrail` 변종을
   더 일관되게 보존한다.**

---

## 9. 현 단계 결론

JUNGJS-1에서 JUNGJS-2로의 변화는 단순 스키마 축소가 아니다. access key를 행위
주체로 유지하면서 Role 복사본을 합치고, 원본 조인 근거를 보존하고, 관측 사실과
추론 관계를 계층으로 분리한 것은 의미 왜곡을 줄이는 방향의 개선이다.

그러나 현재의 “5개 모티프 재현 성공”과 “원본의 24%로 축소”만으로는 1차 연구
질문에 답할 수 없다. 실제 5단계 체인에서는 `AttachUserPolicy`의 결합 관계,
credential 소유의 성립 시각, trail 상태 전이, read-only 정찰의 역할이 약화되고,
`CAN_OBTAIN`은 중간 구조를 한 홉으로 접는다. 동시에 `StopLogging`은 경로에는
남아도 기존 방어 회피 모티프에서는 빠진다.

따라서 다음 실험의 중심 지표는 압축률이나 기법 hit rate가 아니라
**시간 단조 조건을 만족하는 Path Precision/Recall과 직접 dependency 보존율**이어야
한다. 이 둘을 함께 측정해야 “공격자가 끝까지 도달했다”와 “왜 도달할 수 있었는가”를
구분할 수 있다.
