# cloud-attack-path-visualization


클라우드 감사 로그를 그래프로 구성하여 침해 이후의 공격 경로와 영향 범위를 분석하는 연구 프로젝트입니다.

현재는 AWS CloudTrail 로그를 대상으로 자격 증명, 세션, 리소스 간 관계를 정의하고, 실제 로그에 기록된 행위를 하나의 흐름으로 연결하는 방법을 연구하고 있습니다.

<br>

## 연구 배경

클라우드 환경에서는 공격을 탐지한 이후에도 공격자가 어떤 권한을 거쳐 어디까지 접근했는지 파악하는 데 많은 시간이 필요합니다.

CloudTrail은 개별 API 호출을 기록하지만, 이벤트 사이의 인과관계나 자격 증명 전환 흐름을 직접 제공하지 않습니다. 따라서 사고 조사자는 여러 로그에 흩어진 세션과 권한 정보를 수작업으로 연결해야 합니다.

이 프로젝트는 이러한 로그를 그래프로 표현하여 공격 경로와 조사 범위를 보다 쉽게 확인하는 것을 목표로 합니다.

<br>

## 연구 방향

현재 다음 내용을 중심으로 연구를 진행하고 있습니다.

- CloudTrail 로그의 주체, 행위, 리소스에 대한 그래프 모델 정의
- IAM User, Role, STS Session 등 자격 증명 전환 관계 연결
- 실제 로그에서 관찰된 행위 경로 구성
- 권한상 접근 가능한 범위와 실제 실행된 경로의 구분
- 대규모 로그에서 조사에 필요한 경로를 선별하는 방법 검토

세부 모델과 연결 규칙은 데이터셋 분석 및 실험 결과에 따라 변경될 수 있습니다.

<br>

## 현재 진행 내용

- flaws.cloud CloudTrail 데이터셋 구조 분석
- 사용자, Role, Session 및 Access Key 정보 확인
- 조건별 CloudTrail 이벤트 추출
- 자격 증명 기반 그래프 모델 설계
- Provenance Graph 및 공격 재구성 관련 선행 연구 조사

<br>

## 프로젝트 구조

```text
cloud-attack-path-visualization/
├─ data/
│  ├─ archives/
│  └─ raw/
├─ docs/
│  ├─ datasets/
│  └─ references/
├─ scripts/
│  ├─ analyze_flaws.py
│  └─ extract_events.py
└─ README.md