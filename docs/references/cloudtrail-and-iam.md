# CloudTrail and IAM Graph Analysis

서버리스 환경의 실행 문맥 추적, CloudTrail 그래프 모델링 및 IAM 로그 기반 위협 탐지 연구를 정리합니다.

**목차**  
- ALASTOR
- Graph Neural Networks for AWS Cloud Security Analytics
- Graph Neural Network-Based Adaptive Threat Detection for Cloud IAM Logs


<br>

## ALASTOR

### 기본 정보

- 제목: **ALASTOR: Reconstructing the Provenance of Serverless Intrusions**
- 발표: USENIX Security 2022
- 원문: [ALASTOR PDF](https://www.usenix.org/system/files/sec22-datta.pdf)

### 연구 목적

서버리스 환경에서 여러 함수와 서비스에 걸쳐 발생하는 침해 행위의 provenance를 재구성하는 것을 목적으로 합니다.

### 핵심 내용

서버리스 환경에서는 하나의 요청이 여러 함수로 전달되고, 각 함수가 서로 다른 실행 환경과 권한을 사용할 수 있습니다.

또한 함수 인스턴스가 짧은 시간 동안 생성되고 사라지며, 실행 환경이 재사용될 수 있기 때문에 기존 호스트 중심 감사 방식만으로는 전체 흐름을 연결하기 어렵습니다.

ALASTOR는 함수 내부의 시스템 수준 행위와 애플리케이션 수준 행위를 함께 수집합니다. 이후 여러 함수에서 수집된 provenance를 중앙 저장소로 모아 하나의 전역 데이터 흐름 그래프로 연결합니다.

### 주요 특징

- 서버리스 환경 전용 provenance 수집
- 시스템 수준과 애플리케이션 수준 이벤트 결합
- 여러 함수의 흐름을 하나의 전역 그래프로 연결
- 함수와 구현 언어에 독립적인 구조
- 침해사고 조사와 원인 분석 지원

### 프로젝트에서 참고할 점

현재 프로젝트에서 다음 흐름을 연결할 때 직접 참고할 수 있습니다.

```text
IAM User
→ AssumeRole
→ Role Session
→ InvokeFunction
→ Lambda Execution Role
→ S3 접근
```

CloudTrail에는 Lambda를 호출한 주체와 Lambda가 실행 Role을 사용해 수행한 후속 행위가 서로 다른 이벤트로 기록됩니다.

ALASTOR는 이러한 실행 경계가 바뀌는 환경에서 전체 provenance를 연결해야 한다는 문제의식을 제공합니다.

다만 ALASTOR는 OpenFaaS 플랫폼 내부에 감사 기능을 추가하는 방식입니다. AWS CloudTrail만 사용하는 프로젝트에서는 함수 내부 시스템 행위까지 동일한 수준으로 확인하기 어렵습니다.

따라서 각 상황에서의 특정 관계를 잘 구분해야할 것 같습니다. 
- CloudTrail에서 직접 확인할 수 있는 관계
- AWS 설정과 실행 Role을 이용해 보완할 수 있는 관계
- 로그에 직접 남지 않아 추론해야 하는 관계


<br>

## Graph Neural Networks for AWS Cloud Security Analytics

### 기본 정보

- 제목: **Graph Neural Networks for AWS Cloud Security Analytics: Anomaly Detection Using CloudTrail Logs**
- 발표: ICAICCIT 2025
- 참고 파일: `Graph_Neural_Networks_for_AWS_Cloud_Security_Analytics_Anomaly_Detection_Using_CloudTrail_Logs.pdf`
- DOI: `10.1109/ICAICCIT68829.2025.11434233`

### 연구 목적

CloudTrail 로그에 포함된 사용자, API 호출, 리소스 간의 관계를 그래프로 표현하고, GNN을 이용해 비정상 행위를 탐지하는 것을 목적으로 합니다.

### 핵심 내용

개별 CloudTrail 이벤트를 독립적으로 분석하는 대신, 이벤트 간의 관계를 그래프로 변환합니다.

생성된 그래프는 GNN 모델의 입력으로 사용되며, 비인가 접근이나 권한 상승과 같은 행위를 탐지하는 방식이 제안됩니다.

### 프로젝트에서 참고할 점

현재 프로젝트에서 생성하는 공격 경로 그래프를,  
향후 위협 탐지 모델의 입력으로 활용할 수 있다는 가능성을 보여줍니다.

<br>

## Graph Neural Network-Based Adaptive Threat Detection for Cloud IAM Logs

### 기본 정보

- 제목: **Graph Neural Network-Based Adaptive Threat Detection for Cloud Identity and Access Management Logs**
- 공개: arXiv, 2025
- 원문: [arXiv PDF](https://arxiv.org/pdf/2512.10280)

### 연구 목적

IAM 감사 로그를 동적 그래프로 구성하고, 사용자와 리소스 간 관계의 변화를 학습하여 비정상 접근을 탐지하는 것을 목적으로 합니다.

### 핵심 내용

논문에서는 다음 요소를 서로 다른 노드 또는 관계로 구성합니다.

- 사용자
- Role
- 세션
- 리소스
- 접근 행위

그래프에는 이벤트 발생 시간과 접근 문맥이 함께 반영됩니다.

새로운 이벤트가 발생하면 그래프의 상태를 갱신하여, 고정된 규칙만 사용하는 방식보다 변화하는 IAM 환경에 대응할 수 있도록 설계합니다.  

### 프로젝트에서 참고할 점

현재 프로젝트의 그래프 구조와 직접 연결되는 부분이 여럿 존재합니다.  

- IAM User, Role, Session을 서로 다른 노드로 구분
- API 호출을 주체와 리소스 간 관계로 표현
- 세션 생성과 권한 전환을 별도 관계로 표현
- 단일 이벤트가 아니라 시간에 따른 관계 변화를 분석
- 권한 상승과 횡적 이동을 그래프 구조에서 탐지

IAM 로그를 동적 그래프로 표현하는 방법에서 참고할 수 있을듯 합니다.  