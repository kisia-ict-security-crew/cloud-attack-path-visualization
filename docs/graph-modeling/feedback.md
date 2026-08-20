# CloudTrail 그래프 모델링 — 3개 안 비교 및 회의 합의 안건

세 팀원이 각자 제안한 그래프 모델링을 비교하고, 회의에서 합의해야 할 쟁점을 정리한 문서.


---

## 1. 모델별 장단점

### 정준식 모델링

**장점**
- 순방향/역방향 경로 순회가 가능해 "공격 경로 재구성"에 직접 부합
- 성공만 필터링해 S3 버킷 열거 노이즈(전체의 약 75%)를 설계 단계에서 제거
- 구조가 단순해 원본 로그로 바로 구현 가능

**단점**
- 보안 심각도 구분이 약함 (READ/MODIFY로는 위험도가 안 드러남)
- Lambda 등 Workload를 통한 권한 상승 경로를 표현 못 함
- Credential 통합으로 "발급 시점 vs 사용 시점"의 원본 충실성 일부 희생

**추출 요소**
성공만 필터링 하는 것. 실패 로그도 따로 처리해야할 듯 하다. 단순한 구조

### 강인석 모델링 

**장점**
- 위험 온톨로지 보유 (LOG_TAMPERING, PRIVILEGE_ESCALATION, CREDENTIAL_ACCESS 등)
- 특히 LOG_TAMPERING(방어 회피)은 다른 두 모델에 없는 개념 — 사후조사에 중요
- IAM 주체를 대상과 동일 노드로 통일 (모델 A/C와 같은 결론에 독립 도달)

**단점**
- 도달성 순회 구조가 아님 — 산출물이 "위험 엣지 목록"이라 경로가 아니라 개별 점
- 성공/실패 미구분 — 노이즈 처리를 다음 단계로 미룸
- 위험 카테고리의 근거(표준 기반인지 임의인지)가 불명확 → MITRE로 정당화 필요


**추출 요소**
MITRE ATTACK 분류를 이용한 엣지에 맥락 부여.  
공식 자료를 활용함으로 정당성 부여할 수 있음. 하지만 MITRE ATTACK은 행위 분류지 관계 분류가 아님. 그래서 이 분류를 노드간의 관계로 볼지 아니면 엣지의 속성으로만 부여할지 얘기해 봐야할 듯 함.

### 서장훈 모델링 

**장점**
- Workload(Lambda/EC2)를 1급 노드로 분리 — Lambda를 통한 권한 획득 경로 표현 가능
- SecurityContext 분리로 "AssumedRole = 실행 상태"를 개념적으로 정확히 표현
- parent_context_id / source_identity로 다단계 Role Chaining의 최초 행위자 역추적

**단점**
- 복잡도 폭발 — API 호출 1건이 노드 4개 + 엣지 4개로 확장
- **구현 가능성 미검증** — SecurityContext 복원, parent_context 연결이 실제 로그로 되는지 확인 안 됨
- 성공/실패 필터, 노이즈 처리

**추출 요소**
workload를 개별 노드로 정의한 것. 
parent_context_id / source_identity 로 역추적성 부여

---

## 4. 회의에서 합의할 쟁점

### 쟁점 1 — 주체를 몇 층으로 둘 것인가 (최대 쟁점)
- 모델 A: Credential 1층 (단순, 구현 쉬움)
- 모델 C: Identity + Credential + SecurityContext 3층 (정밀, 복잡)
- **절충안 후보**: Credential 1층을 기본으로 하되, `source_identity` / `parent_context`를 노드·엣지 속성으로 흡수 → 3층을 만들지 않고 체인 역추적 이득만 취함
- **결정 기준**: SecurityContext를 실제 로그로 복원 가능한지 여부 (쟁점 5와 연결)

### 쟁점 2 — Workload 노드를 도입할 것인가
- 모델 C의 최대 기여. Lambda/EC2를 통한 권한 상승 경로 표현에 필요
- 꼭 들어가면 좋을 듯하다.

### 쟁점 3 — 위험도/MITRE를 엣지 타입으로 둘 것인가, 속성으로 둘 것인가
- eventName ↔ MITRE Tactic은 N:N (예: AssumeRole = Credential Access + Privilege Escalation)
- **속성 권장**: 구조는 엣지 타입(READ/MODIFY 등) 유지, MITRE(Tactic/Technique/위험도)는 엣지 속성으로 → N:N을 리스트로 수용, "MITRE 전술 시퀀스 = 공격 킬체인" 순회 가능
- **예외**: LOG_TAMPERING처럼 자주 질의되는 소수만 엣지 타입 승격 검토

### 쟁점 4 — 성공/실패 처리 방침
- 모델 A만 성공 기반. B/C는 전부 포함
- **제안**: 성공만으로 그래프 구성(사후조사 목적), 실패는 import 시 버리지 말고 `ATTEMPTED_*` 관계로 보존해 쿼리로 소환 가능하게
- S3 버킷 열거 노이즈(대량 실패)는 개별 노드화 대신 집계 처리

### 쟁점 5 — 구현 가능성 검증 (선결 과제)
아래를 원본 로그(`flaws_cloudtrail*.json`)로 확인해야 모델 선택이 근거를 가진다.
- SecurityContext의 parent를 이을 정보가 로그에 있는가 (sessionIssuer 체인 깊이)
- Workload(Lambda) 호출 → execution role 연결이 로그에 명시되는가
- source_identity가 로그에 직접 있는가, 추론이 필요한가
- **원칙**: 로그가 실제로 주는 정보로만 모델링한다. 정교한 설계가 로그에 없는 정보를 요구하면 무효

---
