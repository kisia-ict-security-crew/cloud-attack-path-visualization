"""
통계적 이상치(surprisal) 대신, 알려진 AWS IAM 권한 상승 기법을 그래프 패턴으로
직접 매칭합니다. "확률이 낮다"가 아니라 "이 시퀀스가 기법 X와 정확히 일치한다"로
판단하므로 결과를 설명하기 쉽습니다 (Rhino Security Labs의 AWS 권한 상승 카탈로그,
MITRE ATT&CK Cloud 매트릭스 기반).
"""

# 패턴 1: 자기/타인의 IAM 정책·자격증명을 직접 조작 (단일 이벤트 패턴)
SELF_POLICY_EVENTS = {
    "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup",
}

# 패턴 2: 높은 권한 역할을 새 컴퓨트 리소스에 넘겨서 그 권한으로 행동 (단일 이벤트 패턴,
# PassRole 자체는 별도 이벤트가 아니라 이 호출들의 파라미터로만 나타나는 권한이라 후보로만 표시)
PASSROLE_EVENTS = {"RunInstances", "CreateFunction", "CreateStack", "CreateDevEndpoint", "CreateDataPipeline"}


def _actor_name(arn_or_id):
    if not arn_or_id:
        return None
    return arn_or_id.split("/")[-1].split(":")[-1]


def match_signatures(events):
    """
    events: attack_chain_surprisal.load_events()가 반환하는 형식 (subject, eventName,
    eventTime, requestParameters 포함). 시간순 정렬돼 있다고 가정.
    각 이벤트에 e["technique"] (매칭된 기법 이름 또는 None)를 채워 넣습니다.
    """
    for e in events:
        e["technique"] = None

    # RoleTrustPolicyBackdoor용: actor가 UpdateAssumeRolePolicy로 건드린 role과 시각을 기록
    trust_edits = {}  # actor -> {role_name: edit_time}

    for e in events:
        name = e["eventName"]
        actor = e["subject"]
        rp = e.get("requestParameters") or {}

        if name in SELF_POLICY_EVENTS:
            target_user = rp.get("userName")
            actor_short = _actor_name(actor)
            if target_user and target_user != actor_short:
                e["technique"] = f"SelfPolicyEscalation(target={target_user})"
            else:
                e["technique"] = "SelfPolicyEscalation"

        elif name in PASSROLE_EVENTS:
            e["technique"] = "PassRoleAbuse(candidate)"

        elif name == "UpdateAssumeRolePolicy":
            role = rp.get("roleName")
            if role:
                trust_edits.setdefault(actor, {})[role] = e["eventTime"]
                e["technique"] = f"TrustPolicyEdit(role={role})"

        elif name == "AssumeRole":
            role_arn = rp.get("roleArn", "")
            role_name = role_arn.split("/")[-1] if role_arn else None
            if role_name and actor in trust_edits and role_name in trust_edits[actor]:
                e["technique"] = f"RoleTrustPolicyBackdoor(role={role_name})"

    return events


def summarize(events):
    from collections import Counter
    counts = Counter(e["technique"].split("(")[0] for e in events if e["technique"])
    return counts
