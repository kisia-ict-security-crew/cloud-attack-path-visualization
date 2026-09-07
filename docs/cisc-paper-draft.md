# CISC-W'26 논문 초안

> 편집 메모: CISC-W'26 대학원생 이상 기준인 3–4쪽을 상정한 내용 초안이다.
> 저자 정보와 `[실험 후 작성]` 표시는 제출 전에 채우거나 제거한다. 미실행 결과는
> 의도적으로 비워 두었으며 예상값을 결과처럼 쓰지 않는다.

## CloudTrail 공격 그래프의 인과 의미 보존 평가

**Evaluating Causal Semantic Preservation in CloudTrail Attack Graphs**

저자 1<sup>1</sup>, 저자 2<sup>1</sup>, 교신저자<sup>1*</sup>  
<sup>1</sup>소속  
이메일: `[작성 필요]`

### 요약

AWS CloudTrail은 개별 API 호출을 기록하지만 자격증명 전환과 공격 단계 사이의
인과관계를 직접 제공하지 않는다. 이를 그래프로 정규화하면 대규모 로그에서 조사
경로를 줄일 수 있으나, 노드 병합과 관계 정규화 및 추론 과정에서 원본 사건의
의존 구조가 달라질 수 있다. 기존 공격 그래프 실험은 공격 기법의 탐지 여부와
그래프 크기 감소를 주로 평가하여, 시작점에서 목적지까지의 도달 사실과 실제
도달을 가능하게 한 중간 의존성의 보존을 구분하지 못했다. 본 논문은 CloudTrail
그래프의 인과 왜곡을 경로 보존(Path Preservation)과 의존성 보존(Dependency
Preservation)으로 분해하는 평가 방법을 제안한다. 이를 위해 실제 AWS 환경에서
생성한 129개 CloudTrail 이벤트의 5단계 자격증명 핸드오프 시나리오를 MITRE
ATT&CK 기법에 대응시키고, 동일 로그를 이벤트 명시형 기준 그래프, 초기 자격증명
모델, 3-node v2 기반 그래프 및 추론 뷰로 변환하여 비교한다. 또한 정상 사용자의
동일 자산 접근을 음성 대조군으로 사용하여 시간과 방향을 무시한 허위 경로를
측정한다. `[실험 결과 및 결론 수치 작성]`

**키워드:** CloudTrail, 공격 그래프, 프로비넌스 그래프, 인과 왜곡, MITRE ATT&CK

---

## 1. 서론

클라우드 침해사고에서는 IAM 사용자, 역할, STS 임시 세션 및 워크로드 자격증명이
연속적으로 전환된다. AWS CloudTrail은 요청 주체, API, 시각, 대상 및 결과를
기록하지만 이벤트 사이의 직접 인과관계는 제공하지 않는다[1]. 따라서 조사자는
여러 레코드에 흩어진 자격증명과 리소스 참조를 연결하여 유입 경로와 영향 범위를
복원해야 한다.

프로비넌스 그래프(provenance graph)는 감사 로그를 주체와 객체 사이의 의존
그래프로 변환하여 공격의 원인과 영향을 연결한다. SLEUTH는 의존 그래프와 태그
전파를 이용해 공격 시나리오를 축약했고[2], ALASTOR는 분산된 서버리스 함수의
provenance를 결합하여 전역 흐름을 복원했다[3]. 그러나 그래프가 작아졌거나 공격
기법이 탐지되었다는 사실만으로 원래의 인과 구조가 보존되었다고 볼 수는 없다.
실제 경로 `A→B→C→D`를 합성 엣지 `A→D`로 줄이면 도달 사실은 유지되지만 B와
C의 의존성은 사라진다.

본 연구의 선행 실험은 CloudTrail 이벤트를 목적 중립적 기반 그래프로 변환하고
Stratus Red Team 기법을 부분그래프 모티프로 식별하였다. 6개 공격 기법 661개
이벤트에서 5종 모티프가 실험 정답과 일치했고, 변환 CSV는 원본 JSON의 24%였다.
이 결과는 표현력과 축약 가능성을 보이지만 다음 질문에는 답하지 않는다. (1)
공격 시작점에서 최종 피해까지의 경로가 보존되는가, (2) 그 경로를 성립시킨 직접
dependency와 증거가 보존되는가.

본 논문의 기여는 다음과 같다. 첫째, 실제 세계에서 로그가 되는 과정의 관측 손실과
로그에서 그래프가 되는 과정의 모델링 왜곡을 분리한다. 둘째, Causal Distortion을
Path Preservation과 Dependency Preservation으로 나누고 정량 지표를 정의한다.
셋째, 공인 ATT&CK 기법으로 구성된 동일 공격 로그를 서로 다른 그래프 모델로
변환하고, 공격 경로와 음성 대조 경로를 함께 비교하는 재현 가능한 실험을 설계한다.

> **[관련 연구 보강 후 제거]** 그래프 압축의 의미 보존 또는 provenance 축약
> 정확도를 직접 평가한 선행 연구 인용.

## 2. 배경 및 비교 모델

### 2.1 CloudTrail과 프로비넌스

CloudTrail의 `userIdentity`는 요청에 사용된 신원과 자격증명을, `eventTime`과
`eventName`은 완료 시각과 행위를, `resources`는 참조 자원을 나타낸다[1]. 일부
서비스 호출은 `inScopeOf.credentialsIssuedTo`를 통해 자격증명이 발급된 실행
환경을 제공한다[4]. 그러나 EC2 내부에서 IMDS에 접근해 자격증명을 읽는 행위는
AWS API 호출이 아니므로 CloudTrail에 나타나지 않는다.

W3C PROV-DM은 엔티티(entity), 활동(activity), 에이전트(agent)와 생성·사용
관계를 구분한다[5]. 이벤트 명시형 표현은 하나의 활동이 여러 입력·대상·출력을
결합한다는 사실을 구조로 보존한다. 반면 이벤트를 주체–대상 엣지로 압축하면
그래프는 작아지지만 하나의 사건이 여러 병렬 엣지로 분해된다. 본 연구는 이벤트
명시형 그래프를 운영 모델이 아닌 **평가 기준 그래프**로 사용한다.

### 2.2 JUNGJS-1과 3-node v2

초기 모델(JUNGJS-1)은 `Principal`, `Role`, `Session`, `Resource`, `Service`의
5종 노드와 `ACCESS`, `ASSUME_ROLE`, `ISSUES`, `HAS_ROLE` 관계를 사용했다.
flaws.cloud 산출물은 노드 23,509개와 엣지 41,338개로 구성되었으나 동일
자격증명이 Session과 Principal로, Role이 행위와 대상 좌표로 분리될 수 있었다.
또한 엣지에 원본 `eventID`가 없어 관계의 근거를 되짚기 어려웠다.

3-node v2는 동일 식별자를 하나의 노드로 병합하고 `Actor`, `Resource`,
`Service` 역할을 멀티라벨로 표현한다. 주체 PK는 ARN보다 `accessKeyId`를 우선해
같은 신원의 서로 다른 키와 출처 IP를 구분한다. API 호출은 `BASE_EVENT` 엣지로
저장되며 `eventID`, `eventTime`, `refPath`, `actionL2`, `outcome`을 보존한다.
`ISSUES`와 `RUNS_ON`은 사용 흔적을 집계한 `CONTEXT` 관계다. 뷰에서는 성공한
상태 변경을 `advances`로 표시하고, 워크로드 장악과 자격증명 바인딩을 접은
`CAN_OBTAIN` 관계를 합성한다.

## 3. 인과 의미 보존 평가

### 3.1 평가 경계와 관계의 증거 수준

변환 단계를 실제 실행 세계 `W`, 원본 로그 `L`, 기반 그래프 `G_base`, 최종 뷰
`G_view`로 구분한다. `W→L`의 비관측 행위는 Observation Loss이며, 본 연구의
주평가 범위는 `L→G_base→G_view`이다. 기준 그래프의 관계에는 다음 증거 수준을
부여한다.

| 증거 수준 | 정의 | 예시 |
| :--- | :--- | :--- |
| `OBSERVED_DIRECT` | 단일 로그가 직접 지지 | Cred①이 `CreateAccessKey` 수행 |
| `RECONSTRUCTED` | 복수 로그와 문맥으로 재구성 | operator가 워크로드의 Cred① 획득 |
| `POSSIBLE` | 구조상 가능하나 행사 증거 없음 | 워크로드 장악에 따른 키 획득 가능성 |

따라서 CloudTrail에 없는 IMDS 탈취를 `CAN_OBTAIN`으로 연결하는 것은 유용하지만,
관측 사실과 같은 직접성으로 평가하지 않는다.

### 3.2 평가 지표

기준 그래프의 공격 시작–종료 쌍 집합을 `P_ref`라 할 때, 최종 그래프가 같은 쌍을
방향 및 시간 단조 조건 `t_i≤t_(i+1)`으로 연결하는지 측정한다.

```text
Path Recall    = |G에서 도달 가능한 P_ref의 쌍| / |P_ref|
Path Precision = |G_ref와 G에서 모두 도달 가능한 쌍| / |G가 연결한 평가 쌍|
D_c,path       = 1 - F1(Path Precision, Path Recall)
```

Dependency Preservation은 직접 dependency precision/recall, 필수 중간 노드
보존율, 기준에서 2홉 이상인 관계가 1홉이 된 Shortcut Rate, 원본 eventID 또는
추론 근거를 찾을 수 있는 Evidence Coverage로 측정한다. 최종 인과 왜곡은 누락,
허위 추가, shortcut, 방향 오류, 근거 손실, 시간 위반의 벡터로 먼저 보고한다.

## 4. 실험 설계

### 4.1 연구 질문

- **RQ1:** 3-node v2는 JUNGJS-1보다 공격 단계 간 Path Preservation을 높이는가?
- **RQ2:** `CONTEXT`와 `CAN_OBTAIN`은 Path Recall을 높이는 대신 직접 dependency와
  경유 구조를 얼마나 축약하는가?
- **RQ3:** 시간 단조성과 증거 수준을 적용하면 공유 신원·자산에서 생기는 허위
  공격 경로가 얼마나 감소하는가?
- **RQ4:** 의미가 같은 ATT&CK 기법의 API 변형에서도 경로와 기법 의미가
  일관되게 보존되는가?

### 4.2 공격 시나리오와 공인 기법 대응

주 실험은 실제 AWS 시험 계정에서 실행한 `aws.5_chain_n1` 로그를 사용한다.
129개 이벤트 중 공격 구간은 약 40초이며, 운영자 키가 EC2 인스턴스에 명령을
실행한 뒤 임시 키 Cred①을 사용하고, Cred①이 관리자 백도어와 Cred②를 생성한
후 Cred②가 로깅을 중지하고 S3 객체를 삭제한다. 정상 사용자가 같은 버킷을
조회하고 EC2 에이전트가 Cred①을 정상 IP에서 사용하는 노이즈를 포함한다.

공격 단계는 특정 API 이름만으로 정답화하지 않고 표 1의 ATT&CK 의미와 실행
스크립트의 단계 경계를 함께 사용한다. 2026년 ATT&CK 기준으로 CloudTrail 로깅
중지는 `T1685.002`, S3 객체 삭제는 암호화가 아닌 삭제이므로 `T1485`에 대응한다.

**표 1. 주 시나리오의 ATT&CK 대응과 관측 증거**

| 단계 | ATT&CK | 핵심 행위 | CloudTrail 증거 |
| :--- | :--- | :--- | :--- |
| 자격증명 접근 | T1552.005 | EC2 IMDS credential 획득 | `SendCommand`, 탈취 후 Cred① 사용 |
| 정찰 | T1087.004, T1526 | 사용자·Role·서비스 열거 | `ListUsers`, `ListRoles`, `ListBuckets` |
| 백도어 생성 | T1136.003, T1098.001/.003 | 사용자·정책·키 생성 및 결합 | `CreateUser`, `AttachUserPolicy`, `CreateAccessKey` |
| 방어 기능 약화 | T1685.002 | CloudTrail logging 중지 | `StopLogging` |
| 데이터 파괴 | T1485 | S3 객체 대량 삭제 | `DeleteObjects`, `DeleteObject` |

주 시나리오 하나에 과적합되는 것을 막기 위해 다음 변형을 독립 입력으로 둔다.

- **V1 의미 동등 API:** `StopLogging`과 `DeleteTrail` 비교
- **V2 자격증명 사용 조건:** 발급 후 사용한 키와 미사용 키 비교
- **V3 출처 변화:** 탈취 주체와 훔친 키의 IP 일치/불일치 비교
- **V4 노이즈 강도:** 동일 자산의 정상 조회 및 IaC write event를 단계적으로 증가
- **V5 관측 조건:** S3 data event 포함/제외 비교

> **[실험 후 작성 — 데이터셋 공란 A]**  
> 각 변형의 실행 횟수, 이벤트 수, 입력 SHA-256, 공격/정상 이벤트 수.

### 4.3 비교군과 반복 절차

동일 입력을 다음 네 그래프로 각각 변환한다.

1. `G_ref`: eventID당 Activity 노드를 둔 이벤트 명시형 기준 그래프
2. `G_j1`: Principal/Role/Session 기반 JUNGJS-1 호환 그래프
3. `G_j2b`: 3-node v2 기반 그래프
4. `G_j2v`: `advances`, `CONTEXT`, `CAN_OBTAIN`을 포함한 최종 뷰

실험 단위는 한 번의 공격 실행이며, 각 기본/변형 시나리오를 반복 실행해 실행별
그래프와 manifest를 남긴다. 기준 dependency는 실행 스크립트의 단계·생성 자원,
CloudTrail `eventID`, ATT&CK 의미를 이용해 작성하고 두 분석자가 독립 검수한다.
정상 사용자→victim bucket 조회, CloudTrail 로그 배달, Terraform warm-up을 음성
대조군으로 지정한다.

> **[실험 후 작성 — 재현성 공란 B]**  
> AWS 구성, 리전, 수집 selector, 반복 횟수, 파서·쿼리 버전, 기준 그래프 라벨링
> 규칙 및 분석자 합의도.

### 4.4 그래프 비교 그림

전체 그래프 스크린샷 대신 공격 시작점에서 피해 자산까지의 유도 부분그래프를
사용한다. 네 모델을 동일한 노드 순서와 색으로 배치하고 관측 관계는 실선, 재구성
관계는 점선, 가능 관계는 옅은 점선으로 구분한다. JUNGJS-1의 분할 노드,
3-node v2의 `CAN_OBTAIN` shortcut, `AttachUserPolicy`의 누락 결합을 같은 위치에서
비교한다. 각 노드와 엣지는 익명화하되 실제 `eventID`의 짧은 접두사와 시각을
표시한다.

> **[실험 후 삽입 — 그림 1 공란]**  
> `(a) G_ref, (b) G_j1, (c) G_j2b, (d) G_j2v`의 동일 경로 비교.

두 번째 그림은 noise level에 따른 Path Precision/Recall 및 Dependency F1을
선그래프로, 모델별 Shortcut Rate와 Evidence Coverage를 막대로 제시한다.

> **[실험 후 삽입 — 그림 2 공란]**

## 5. 실험 결과

### 5.1 그래프 규모와 경로 보존

> **[실험 후 작성 — 결과 공란 C]**

| 모델 | Nodes | Edges | Compression | Path Precision | Path Recall |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `G_ref` |  |  |  |  |  |
| `G_j1` |  |  |  |  |  |
| `G_j2b` |  |  |  |  |  |
| `G_j2v` |  |  |  |  |  |

### 5.2 직접 의존성 및 추론 효과

> **[실험 후 작성 — 결과 공란 D]**

| 모델 | Direct dependency P/R/F1 | Intermediate-node recall | Shortcut rate | Evidence coverage |
| :--- | :---: | ---: | ---: | ---: |
| `G_j1` |  |  |  |  |
| `G_j2b` |  |  |  |  |
| `G_j2v` |  |  |  |  |

### 5.3 변형·노이즈 실험

> **[실험 후 작성 — 결과 공란 E]**  
> V1–V5별 결과, 실패 사례의 실제 부분그래프, 통계 요약.

## 6. 논의

> **[결과 확정 후 작성 — 공란 F]**  
> RQ1–RQ4에 대한 직접 답변과 모델 개선의 비용·효과. 아래 항목은 결과가 확인된
> 경우에만 포함한다.

- `CAN_OBTAIN`이 Path Recall과 Shortcut Rate에 미친 상반된 효과
- 시간 단조 조건이 정상 공유 자산의 허위 경로를 제거한 정도
- `StopLogging/DeleteTrail` 변형에서 `actionL2` 정규화가 보인 일반화 한계
- 미사용 credential에서 issuance-time ownership이 필요한지 여부

타당성 위협은 다음과 같다. 통제된 시나리오는 단계 정답을 알 수 있지만 실제
공격의 다양성을 모두 대표하지 않는다. ATT&CK는 행위의 공인 분류를 제공하지만
개별 이벤트 사이의 인과 정답을 제공하지 않으므로, dependency 라벨은 실행
스크립트와 분석자 판단에 의존한다. 또한 CloudTrail에 없는 호스트 내부 행위는
그래프 모델의 결함과 분리해 해석해야 한다. 이를 완화하기 위해 기법 변형, 반복
실행, 음성 대조군, 독립 라벨링 및 입력·파서 manifest를 사용한다.

## 7. 결론

본 논문은 CloudTrail 공격 그래프를 압축률과 모티프 적중률만으로 평가하는 한계를
지적하고, 도달 사실과 실제 의존 구조를 분리하는 인과 의미 보존 평가를 설계하였다.
공인 ATT&CK 기법으로 구성된 동일 로그를 네 그래프 모델에 적용하고, 정상 공유
자산을 음성 대조군으로 포함함으로써 Path Preservation과 Dependency Preservation을
함께 측정한다. `[실험 결과에 근거한 최종 결론 작성]`

## 참고문헌

[1] Amazon Web Services, “CloudTrail record contents for management, data, and
network activity events,” *AWS CloudTrail User Guide*, 2026.

[2] M. N. Hossain et al., “SLEUTH: Real-time attack scenario reconstruction from
COTS audit data,” in *26th USENIX Security Symposium*, pp. 487–504, 2017.

[3] P. Datta et al., “ALASTOR: Reconstructing the provenance of serverless
intrusions,” in *31st USENIX Security Symposium*, 2022.

[4] Amazon Web Services, “CloudTrail userIdentity element,” *AWS CloudTrail User
Guide*, 2026.

[5] W3C, “PROV-DM: The PROV Data Model,” W3C Recommendation, 2013.

[6] MITRE, “Unsecured Credentials: Cloud Instance Metadata API, T1552.005,”
*MITRE ATT&CK*, 2026.

[7] MITRE, “Account Discovery: Cloud Account, T1087.004,” *MITRE ATT&CK*, 2026.

[8] MITRE, “Create Account: Cloud Account, T1136.003,” *MITRE ATT&CK*, 2026.

[9] MITRE, “Account Manipulation: Additional Cloud Credentials, T1098.001,”
*MITRE ATT&CK*, 2026.

[10] MITRE, “Disable or Modify Tools: Disable or Modify Cloud Log, T1685.002,”
*MITRE ATT&CK*, 2026.

[11] MITRE, “Data Destruction, T1485,” *MITRE ATT&CK*, 2026.

[12] Datadog, “Stratus Red Team,” 2026.
