# flaws.cloud CloudTrail 로그 분석


`flaws.cloud`에서 제공하는 CloudTrail 로그를 활용합니다.

데이터셋은 아래 블로그에서 다운받을 수 있습니다.

- https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/

<br>


## 데이터 준비

다운로드한 압축 파일을 해제한 후, 로그 파일을 아래와 같이 배치합니다.

```text
data/
└─ raw/
   └─ flaws_cloudtrail_logs/
      ├─ flaws_cloudtrail00.json
      ├─ flaws_cloudtrail01.json
      └─ ...
```

원본 로그는 커밋하지 않고 로컬에서만 관리합니다.  

<br>

## 분석 스크립트

### `analyze_flaws.py`

CloudTrail 로그의 권한 및 세션 관련 구조를 확인하기 위한 분석 스크립트입니다.  

**주요 분석항목**   
- 전체 이벤트 수
- `userIdentity.type`별 이벤트 분포
- 장기 Access Key와 임시 Access Key 분포
- `AssumeRole` 이벤트를 호출한 주체 유형
- 최초로 확인된 `AssumedRole` 주체의 `userIdentity` 구조

<br>

Access Key는 접두사를 기준으로 다음과 같이 분류합니다.  

| 접두사    | 분류                              |
| ------ | ------------------------------- |
| `ASIA` | STS에서 발급된 임시 Access Key         |
| `AKIA` | 장기 Access Key                   |
| 없음     | AWS 서비스 호출 등 Access Key가 없는 이벤트 |
| 기타     | 위 분류에 해당하지 않는 값                 |

<br>


### 전체 로그 분석

인자를 지정하지 않으면 현재 작업폴더 아래의 모든 `.json` 파일을 탐색합니다.

```bash
python scripts/analyze_flaws.py
```

따라서 프로젝트 루트에서 실행하면 `data/` 아래에 존재하는 JSON 파일도 함께 탐색됩니다.

분석 대상 중 json 형식이 아니거나, 최상위에 `Records` 배열이 없는 경우에는 건너뛰니 참고해주세요.  

<br>

### 특정 로그 파일 분석

하나의 CloudTrail 로그만 분석하려면 파일 경로를 인자로 전달합니다.

```bash
python scripts/analyze_flaws.py \
  data/raw/flaws_cloudtrail_logs/flaws_cloudtrail00.json
```

여러 파일을 동시에 지정할 수도 있습니다.

```bash
python scripts/analyze_flaws.py \
  data/raw/flaws_cloudtrail_logs/flaws_cloudtrail00.json \
  data/raw/flaws_cloudtrail_logs/flaws_cloudtrail01.json
```

<br>

### 출력 예시

```text
분석 대상 1개 파일 발견

============================================================
파일: flaws_cloudtrail00.json
전체 이벤트 수: 1,234
------------------------------------------------------------
[주체 종류 userIdentity.type]
   AssumedRole         720  (58.3%)
   IAMUser             310  (25.1%)
   AWSService          204  (16.5%)

[accessKeyId 종류]
   ASIA(임시키)          720
   AKIA(장기키)          310
   (키 없음: 서비스 등)  204
```

이 스크립트는 데이터셋의 전체적인 특성을 파악하기 위한 도구이며, 분석 결과를 별도의 파일로 저장하지 않습니다.

---

<br>

## 4. 조건별 이벤트 추출

### `extract_events.py`

`extract_events.py`는 CloudTrail 이벤트의 속성값을 기준으로 필요한 이벤트만 추출하여 새로운 JSON 파일로 저장합니다.

지원하는 필터 조건은 다음과 같습니다.

| 옵션         | CloudTrail 필드                                        | 설명                        |
| ---------- | ---------------------------------------------------- | ------------------------- |
| `--name`   | `eventName`                                          | 특정 API 이벤트 이름             |
| `--type`   | `userIdentity.type`                                  | IAM 사용자, Role 세션 등의 주체 유형 |
| `--key`    | `userIdentity.accessKeyId`                           | 특정 Access Key 또는 임시 세션    |
| `--issuer` | `userIdentity.sessionContext.sessionIssuer.userName` | 세션의 권한 출처 Role            |
| `--start`  | `eventTime`                                          | 추출 시작 시간                  |
| `--end`    | `eventTime`                                          | 추출 종료 시간                  |
| `--files`  | 입력 파일 경로                                             | 분석할 JSON 파일               |
| `--out`    | 출력 파일 경로                                             | 추출 결과를 저장할 파일             |
| `--ip`     | sourceIPAddress                                            | 요청 발신 IP       |

`--out`은 필수 옵션입니다.  

여러 필터 조건을 함께 지정하면 모든 조건을 만족하는 이벤트만 추출합니다.  

예를 들어 `AssumedRole` 주체가 실행한 `GetObject` 이벤트를 지정하면 다음 두 조건이 모두 일치해야 합니다.  

```text
eventName == GetObject
AND
userIdentity.type == AssumedRole
```

<br>

### 특정 이벤트 추출

현재 디렉터리 이하의 모든 JSON에서 `AssumeRole` 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --name AssumeRole \
  --out data/filtered/only-assume-role.json
```

여러 이벤트를 동시에 추출할 수도 있습니다.

```bash
python scripts/extract_events.py \
  --name AssumeRole CreateAccessKey \
  --out data/filtered/credential-events.json
```

`--name` 뒤에 여러 값을 입력하면 해당 이벤트 중 하나와 일치하는 이벤트를 추출합니다.

```text
eventName == AssumeRole
OR
eventName == CreateAccessKey
```

<br>

### 특정 주체 유형 추출

`AssumedRole` 세션에서 발생한 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --type AssumedRole \
  --out data/filtered/assumed-role-events.json
```

여러 주체 유형을 함께 지정할 수도 있습니다.

```bash
python scripts/extract_events.py \
  --type AssumedRole IAMUser \
  --out data/filtered/principal-events.json
```

지원되는 값은 데이터셋에 따라 달라질 수 있으며, 대표적인 값은 다음과 같습니다.

```text
IAMUser
AssumedRole
Root
AWSService
```

<br>

### 특정 세션 추적

특정 `accessKeyId`를 사용하는 이벤트만 추출하면 하나의 임시 세션에서 발생한 행위를 확인할 수 있습니다.

```bash
python scripts/extract_events.py \
  --key <ACCESS_KEY_ID> \
  --out data/filtered/one-session.json
```

예시:

```bash
python scripts/extract_events.py \
  --key ASIAEXAMPLE123456789 \
  --out data/filtered/one-session.json
```

실제 Access Key 값이 포함된 결과 파일을 외부에 공유할 때는 반드시 값을 마스킹해야 합니다.

<br>


### 특정 Role에서 발급된 세션 추출

`sessionIssuer.userName`을 기준으로 특정 IAM Role에서 발급된 세션의 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --issuer level6 \
  --out data/filtered/level6-sessions.json
```

이 옵션은 이벤트를 직접 호출한 세션 이름이 아니라, 해당 세션에 권한을 제공한 IAM Role의 이름을 기준으로 필터링합니다.

<br>

### 시간 범위 지정

특정 시간 이후 발생한 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --start 2017-02-19T20:00 \
  --out data/filtered/events-after-2000.json
```

특정 시간 이전 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --end 2017-02-19T21:00 \
  --out data/filtered/events-before-2100.json
```

시작 시간과 종료 시간을 함께 지정할 수도 있습니다.

```bash
python scripts/extract_events.py \
  --start 2017-02-19T20:00 \
  --end 2017-02-19T21:00 \
  --out data/filtered/events-2000-2100.json
```

시간 필터는 CloudTrail의 ISO 8601 형식 `eventTime` 문자열을 기준으로 비교합니다.

<br>

### 입력 파일 직접 지정

기본적으로 현재 작업폴더 아래의 모든 `.json` 파일을 대상으로 합니다.

특정 파일만 분석하려면 `--files`를 사용합니다.

```bash
python scripts/extract_events.py \
  --name AssumeRole \
  --files data/raw/flaws_cloudtrail_logs/flaws_cloudtrail00.json \
  --out data/filtered/assume-role.json
```

여러 파일을 지정할 수도 있습니다.

```bash
python scripts/extract_events.py \
  --name AssumeRole \
  --files \
    data/raw/flaws_cloudtrail_logs/flaws_cloudtrail00.json \
    data/raw/flaws_cloudtrail_logs/flaws_cloudtrail01.json \
  --out data/filtered/assume-role.json
```

<br>

### 여러 조건 결합

다음 명령은 특정 Role에서 발급된 `AssumedRole` 세션이 지정된 시간 범위에 실행한 `GetObject`와 `PutObject` 이벤트만 추출합니다.

```bash
python scripts/extract_events.py \
  --name GetObject PutObject \
  --type AssumedRole \
  --issuer level6 \
  --start 2017-02-19T20:00 \
  --end 2017-02-19T21:00 \
  --files data/raw/flaws_cloudtrail_logs/flaws_cloudtrail00.json \
  --out data/filtered/level6-s3-events.json
```

조건은 다음과 같이 적용됩니다.

```text
(eventName == GetObject OR eventName == PutObject)
AND
userIdentity.type == AssumedRole
AND
sessionIssuer.userName == level6
AND
eventTime >= 2017-02-19T20:00
AND
eventTime <= 2017-02-19T21:00
```

### 출력 파일 구조

추출된 이벤트는 `eventTime`을 기준으로 오름차순 정렬됩니다.

결과는 원본 CloudTrail 로그와 동일하게 최상위 `Records` 배열을 갖는 형태로 저장됩니다.

```json
{
  "Records": [
    {
      "eventTime": "2017-02-19T20:00:00Z",
      "eventName": "AssumeRole"
    }
  ]
}
```

출력 파일이 기존 입력 파일과 동일한 경로인 경우, 해당 파일은 입력 대상에서 자동으로 제외됩니다.


<br>
<br>

## 5. 활용 흐름

두 스크립트는 공격 경로 시각화 이전 단계에서 데이터셋을 조사하고 분석 대상을 축소하는 데 사용합니다.


1. flaws.cloud 원본 로그
2. analyze_flaws.py (데이터셋의 주체·권한·세션 구조 분석)
3. extract_events.py (특정 이벤트·세션·Role·시간 범위 추출)

<br>

이후에는 다음 과정을 예정입니다.   

4. 이벤트 정규화
5. 주체·세션·리소스 노드 생성
6. API 호출 및 권한 전환 엣지 생성
7. 공격 경로 그래프 시각화
