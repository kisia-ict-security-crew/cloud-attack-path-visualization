# Stratus Red Team — AWS 공격 시뮬레이션

안내 블로그 https://medium.com/@goodycyb/aws-cloud-detection-lab-1%EF%B8%8F%E2%83%A3-%EF%B8%8F-cloud-pen-testing-with-stratus-red-team-tool-69b4fab24743

[Datadog Stratus Red Team](https://stratus-red-team.cloud/)은 Go로 작성된 클라우드 공격 시뮬레이션 도구다. AWS / Azure / GCP / Kubernetes 대상의 공격 기법을 CLI로 실행하며, 모든 기법은 [MITRE ATT&CK](https://attack.mitre.org/)에 매핑되어 있다. 내부적으로 Terraform으로 필요 인프라를 생성·제거한다.

> ⚠️ 반드시 본인 소유의 **샌드박스(테스트) AWS 계정**에서만 실행할 것. 실제 리소스가 생성되며 비용이 발생할 수 있다.

## 공격 기법의 4가지 상태 (State Machine)

| 상태 | 설명 |
|------|------|
| **Warm up** | 공격에 필요한 인프라/조건만 준비 (아직 실행 X). 초기값은 cold |
| **Detonate** | 실제 환경에서 공격 기법 실행 |
| **Revert** | 부작용을 남기는(비멱등) 기법을 실행 후 원복 |
| **Clean up** | 생성된 모든 인프라 제거 → cold 상태로 복귀 |

---

## 1. 사전 준비

### AWS CLI v2 설치 (Linux)

```bash
# unzip 설치 (배포판 자동 판별)
if [ -f /etc/lsb-release ]; then sudo apt-get update -y && sudo apt-get install -y unzip; \
elif [ -f /etc/centos-release ]; then sudo yum update -y && sudo yum install -y unzip; \
else echo "Unsupported OS."; fi

# AWS CLI v2 다운로드 및 설치
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# 설치 확인
aws --version
```

> IAM 사용자를 만들고 Access Key를 발급받아 둔다. (콘솔 → IAM → Create user → 정책 연결 → Security credentials 탭에서 Access key 생성)

### AWS CLI 프로파일 설정

```bash
# 발급받은 Access Key로 프로파일 생성 (프로파일명은 임의)
aws configure --profile huge-simu-attack

# 자격 증명이 정상 동작하는지 확인
aws sts get-caller-identity --profile huge-simu-attack
```

### Stratus Red Team 설치

```bash
# GitHub 릴리스에서 다운로드 및 압축 해제 (버전은 최신으로 교체)
wget https://github.com/DataDog/stratus-red-team/releases/download/v2.14.0/stratus-red-team_Linux_x86_64.tar.gz
tar xvf stratus-red-team_Linux_x86_64.tar.gz

# 실행 파일을 PATH 디렉터리로 이동
sudo mv stratus /usr/local/bin/

# 설치 확인
stratus version
```

최신 릴리스: <https://github.com/DataDog/stratus-red-team/releases>

### AWS 자격 증명 연결 (환경 변수)

```bash
# Stratus는 환경 변수로 프로파일과 리전을 읽는다
export AWS_PROFILE=huge-simu-attack
export AWS_REGION=eu-west-1
```

---

## 2. Stratus 명령어

### list — 공격 기법 목록 조회

```bash
stratus list                                              # 전체 기법
stratus list --platform aws                               # AWS 기법만
stratus list --platform aws --mitre-attack-tactic persistence   # 특정 MITRE 전술만
```

> AWS만 해도 37개 이상의 기법이 있으며 Credential Access, Defense Evasion, Discovery, Execution, Privilege Escalation, Exfiltration, Impact 등의 전술을 다룬다.

### status — 각 기법의 현재 상태 확인

```bash
stratus status
```

### show — 특정 기법 상세 정보 출력

```bash
stratus show aws.credential-access.ec2-steal-instance-credentials
```

### warmup — 실행 없이 사전 인프라만 준비

```bash
# 단일 기법
stratus warmup aws.credential-access.ec2-steal-instance-credentials

# 여러 기법
stratus warmup aws.credential-access.ec2-steal-instance-credentials aws.credential-access.s3-backdoor-bucket-policy

# 이미 warm 상태여도 강제로 사전 조건 재확인
stratus warmup aws.credential-access.ec2-steal-instance-credentials --force
```

### detonate — 공격 기법 실제 실행

```bash
# 단일 기법 (warmup 안 됐으면 자동 warmup 후 실행)
stratus detonate aws.credential-access.ec2-steal-instance-credentials

# 여러 기법
stratus detonate aws.credential-access.ec2-steal-instance-credentials aws.defense-evasion.cloudtrail-stop

# 실행 후 생성된 리소스 자동 정리
stratus detonate aws.credential-access.ec2-steal-instance-credentials --cleanup
```

### revert — 비멱등 기법 원복

```bash
stratus revert aws.defense-evasion.cloudtrail-stop
```

> 부작용 때문에 재실행이 불가능한 기법(예: CloudTrail 중지)을 다시 실행 가능한 상태로 되돌린다.

### cleanup — 생성된 인프라 제거

```bash
# 특정 기법 정리
stratus cleanup aws.defense-evasion.cloudtrail-stop

# 정리 가능한 모든 기법 일괄 정리
stratus cleanup --all
```

---

## Revert vs Cleanup

| 구분 | Revert | Cleanup |
|------|--------|---------|
| 목적 | 공격의 **부작용**을 원복 (재실행 가능 상태로) | 생성된 **인프라 자체**를 제거 |
| 대상 | 비멱등(non-idempotent) 기법 | 모든 기법 |
| 결과 | 기법은 warm 상태 유지 | cold 상태로 복귀 |

---

## 참고

- 공식 문서: <https://stratus-red-team.cloud/user-guide/usage/>
- AWS 공격 기법 목록: <https://stratus-red-team.cloud/attack-techniques/AWS/>
- 실행된 API 호출은 **CloudTrail**에 기록되므로, 탐지 룰 검증·SIEM 실습에 활용할 수 있다.
