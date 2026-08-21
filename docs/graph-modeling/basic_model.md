노드 설계 (기반)
주체 노드

Principal — 행위 주체 (기존 Credential 통합 유지)

id            : accessKeyId / svc:<invokedBy> / arn:<arn> (폴백 계층)
principalType : IAMUser / AssumedRole / Root / AWSService / FederatedUser / AWSAccount / Anonymous
arn           : userIdentity.arn (원본 그대로)
accountId     : userIdentity.accountId
kind          : LongTermKey(AKIA) / TempKey(ASIA) / Service / ...

기존과 차이: principalType에 모든 userIdentity.type을 보존(익명, 페더레이션 포함). 앞서 "arn 없는 게 AWSService만이 아니다"라고 한 것 — 그 모든 유형을 여기서 다 담아. 판단 없이.

대상 노드

기반에선 대상을 목적별로 안 쪼개. 앞서 DataResource/PermissionTarget 나눈 건 "목적적 판단"이었으니 뷰로 내려가. 기반은 통합:

Resource — 모든 접근 대상 (데이터든 IAM이든 통합)

id           : arn (있으면) / <service>:<name> (폴백)
resourceType : bucket / object / function / role / user / policy / secret / instance / ...
service      : s3 / lambda / iam / ec2 / ... (eventSource에서)
name         : 실제 값
accountId, region : (있으면)

핵심: 여기 resourceType에 role/user/policy(권한 대상)도, bucket/object(데이터)도 다 들어가. "이건 데이터, 저건 권한"이라는 분류는 뷰에서 resourceType으로 필터. 기반은 안 나눔.

단, Role만은 예외로 별도 노드 유지 권장. 왜냐하면 role은 대상이자 **주체(권한 허브)**라, 구조적으로 특별해(앞서 다룬 이중 정체성). role을 Resource에 섞으면 CAN_ASSUME/PROVIDES 관계의 양끝이 흐려져. 그래서:

Role — IAM role (구조적 허브라 유지)
Workload — Lambda/EC2 등 실행 객체 (모델 C에서 흡수, 구조적이라 기반)
Service — 대상 없는 열거의 수렴점 (유지)

노드 정리
노드	기반 유지?	비고
Principal	✓	모든 type 보존
Role	✓	구조적 허브
Workload	✓	모델 C 흡수
Resource	✓ (통합)	data/permission 안 나눔, resourceType으로 구분
Service	✓	열거 수렴점
Session	Principal에 통합	kind=TempKey
PermissionTarget	Resource에 통합	resourceType으로 구분
엣지 설계 (기반) — 여기가 가장 중요

플랫폼의 핵심은 엣지야. 엣지 타입은 최소로 추상화하고, 세부는 전부 속성으로 원본 보존.

엣지 타입 — 구조적 최소 집합만

목적적 세분(READ/MODIFY/PRIVESC...)은 다 빼. 기반엔 행위의 구조적 종류만:

ACCESS       : Principal → Resource/Service  (리소스에 뭔가 함, 세분 안 함)
ASSUME_ROLE  : Principal → Role              (role 취득)
ISSUES       : Role → Principal              (세션 발급, 기존 Role→Session)
INVOKES      : Principal → Workload          (workload 호출, 모델 C)
RUNS_AS      : Workload → Role               (workload의 실행 role, 모델 C)

5종. 앞서 6~8종으로 세분하려던 걸 다시 통합했어. 이유: READ/MODIFY/READ_PERMISSION 구분은 eventName만 있으면 뷰에서 언제든 재현 가능하니까, 기반에 박을 이유가 없어. 기반은 "무엇에 접근했나"의 구조만.

엣지 속성 — 여기에 원본을 다 보존

엣지 타입을 줄인 만큼, 모든 판단 재료를 속성으로 보존:

eventName    : 원본 API명 (READ/MODIFY 세분의 재료)
eventSource  : 서비스
eventTime    : 시각
eventID      : 원본 로그 역추적 키 ★ (모델 C가 강조한 것)
sourceIP     : 요청 IP
userAgent    : 요청 도구
outcome      : SUCCESS / errorCode (실패도 보존, 성공필터의 재료) ★
errorCode    : 구체적 실패 사유 (AccessDenied/NoSuchBucket...)
readOnly     : CloudTrail의 readOnly 플래그 (있으면, READ/WRITE 판정 보조) ★

주목할 신규 3개:

eventID: 모델 C의 핵심 통찰. 그래프의 엣지에서 원본 CloudTrail 레코드로 역추적하는 키. 플랫폼엔 필수 — "이 엣지가 어느 원본 로그냐"를 항상 되짚을 수 있어야 하니까.
outcome/errorCode: 성공만 버리지 않고 실패 사유까지 보존. 뷰에서 "성공만" "AccessDenied만" 등 자유 필터.
readOnly: CloudTrail이 각 이벤트에 주는 플래그. READ/WRITE 판정을 eventName 접두어로 추측하지 않고 이 플래그로 할 수 있어(더 정확). 앞서 "동사 기반 매핑의 부정확성"을 이게 완화해.
