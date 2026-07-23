# Datasets and Tools

CloudTrail 로그 분석과 공격 경로 시각화 실험에 활용할 수 있는 도구와 공개 데이터셋을 정리합니다.


**목차**
- CloudTrail Event Viewer
- Invictus IR AWS Dataset
- IAM Dataset

<br>

## CloudTrail Event Viewer

### 기본 정보

- 유형: 브라우저 기반 CloudTrail 로그 확인 도구
- 링크: [CloudTrail Event Viewer](https://hidekazu-konishi.com/tools/cloudtrail_event_viewer_tool.html)

### 주요 기능

CloudTrail JSON 파일을 브라우저에서 불러와 이벤트를 확인하고 필터링할 수 있습니다.  

다음과 같은 CloudTrail 데이터 형식을 확인할 수 있습니다.  

- `aws cloudtrail lookup-events` 명령의 출력
- S3에 저장된 `Records` 형식의 CloudTrail JSON
- 단일 이벤트 객체
- JSON 배열
- JSON Lines

이벤트 이름, AWS 서비스, 사용자 유형, 오류 여부, 읽기쓰기 구분, 시간 범위 등을 기준으로 이벤트를 필터링할 수 있습니다.

필터링 결과를 CSV 또는 JSON 형식으로 내보낼 수도 있습니다.

### 프로젝트에서 참고할 점

- CloudTrail 이벤트 구조 확인
- 로그 추출 결과 검증
- 이벤트 상세정보 표시 방식 참고
- 주요 필터 조건과 화면 구성 참고
- 그래프 노드 선택 시 원본 이벤트를 보여주는 기능 참고



<br>

## Invictus IR AWS Dataset

### 기본 정보

- 저장소: [invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset)
- 유형: AWS 공격 시뮬레이션 CloudTrail 데이터셋

### 주요 내용

AWS 환경에서 공격 시나리오를 실행하고, 해당 과정에서 발생한 CloudTrail 이벤트를 수집한 데이터셋입니다.

일부 로그는 Stratus Red Team을 이용해 공격 행위를 발생시킨 뒤 수집되었습니다.

실제 AWS API 실행 과정에서 생성된 로그이기 때문에 공격 흐름 분석 실험에 활용할 수 있습니다.

### 프로젝트에서 참고할 점

- 공격 시나리오별 CloudTrail 이벤트 확인
- 공격 과정의 API 호출 순서 분석
- 주체, 세션, 리소스 연결 규칙 검증
- 공격 경로 그래프 생성 실험
- 정상 이벤트와 공격 이벤트 비교
- 시각화 결과의 타당성 확인


<br>

## IAM Dataset

### 기본 정보

- 저장소: [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset)
- 유형: 멀티 클라우드 IAM 구조 데이터셋

### 주요 내용

AWS, Azure, Google Cloud의 IAM 권한 정보를 구조화한 데이터셋입니다.

실제 사용자 행위를 기록한 감사 로그라기보다는, 클라우드별 API, 권한, Role, 정책 간 관계를 정리한 참조 데이터에 가깝습니다.

AWS 관련 데이터에는 다음 정보가 포함됩니다.

- SDK 호출과 IAM Action 간 매핑
- AWS IAM Action 정보
- AWS 관리형 정책
- 민감도가 높은 IAM Action
- 서비스별 권한 정보

Azure와 Google Cloud에서도 Role, Operation, Permission 간 관계를 확인할 수 있습니다.

### 프로젝트에서 참고할 점

CloudTrail에는 실제로 실행된 API 호출이 기록되지만, 해당 API를 실행하기 위해 어떤 권한이 필요했는지는 로그만으로 충분히 알기 어려울 수 있습니다.

IAM Dataset을 함께 사용하면 다음 정보를 보완할 수 있습니다.

- CloudTrail `eventName`과 IAM Action 연결
- API 호출에 필요한 권한 확인
- 관리형 정책과 민감 권한 간 관계 분석
- Role이 수행할 수 있는 잠재적 행위 확인
- 실제 실행 경로와 권한상 가능한 경로 비교
- 멀티 클라우드 환경으로 그래프 모델 확장
