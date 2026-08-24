"""
STS 이벤트(AssumeRole 등)를 파싱해서 '실제로 발급된 임시 세션'의 생애주기를 재구성합니다.

지금까지는 AssumeRole이 발생한 시점(점 하나)만 봤는데, STS 응답에는
credentials.expiration(정확한 만료 시각)이 그대로 찍혀 있습니다. 이걸 쓰면:
  - 이 세션이 언제부터 언제까지 '유효했는가' (발급 ~ 만료)
  - 그 중 실제로 언제부터 언제까지 '쓰였는가' (첫 사용 ~ 마지막 사용)
  - 발급만 되고 한 번도 안 쓰인 세션이 있는가 (예비적으로 만들어둔 백업 자격증명?)
  - 만료 이후에도 사용된 흔적이 있는가 (자격증명 탈취/재사용 의심 신호)
를 전부 재구성할 수 있습니다.
"""
from datetime import datetime, timedelta

STS_ISSUE_EVENTS = {
    "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "GetSessionToken", "GetFederationToken",
}
DEFAULT_DURATION_SECONDS = 3600  # durationSeconds가 로그에 없을 때의 AWS 기본값 추정


def parse_time(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def build_sessions(events):
    """
    STS 발급 이벤트에서 세션 레코드를 만들고, 이후 이벤트들에서 accessKeyId가
    일치하는 것들을 찾아 실제 사용 구간을 채워 넣습니다.

    반환: {accessKeyId: session_dict}
    session_dict 필드:
      - issuer, issued_at, expires_at (예상 만료 시각)
      - actual_first_use, actual_last_use, call_count
      - used_after_expiration, never_used, idle_before_first_use_sec
    """
    sessions = {}

    # 1) 발급 이벤트에서 세션 레코드 생성
    for e in events:
        if e["eventName"] not in STS_ISSUE_EVENTS or e.get("errorCode"):
            continue
        resp = (e.get("responseElements") or {}).get("credentials") or {}
        access_key = resp.get("accessKeyId")
        if not access_key:
            continue

        issued_at = parse_time(e["eventTime"])
        expires_at = parse_time(resp.get("expiration"))
        if expires_at is None and issued_at is not None:
            duration = (e.get("requestParameters") or {}).get("durationSeconds", DEFAULT_DURATION_SECONDS)
            expires_at = issued_at + timedelta(seconds=int(duration))

        sessions[access_key] = {
            "session_key": access_key,
            "issuer": e["subject"],
            "role_target": e["target"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "actual_first_use": None,
            "actual_last_use": None,
            "call_count": 0,
        }

    # 2) 이후 모든 이벤트를 훑어서 accessKeyId가 일치하는 사용 흔적을 채움
    for e in events:
        access_key = e.get("accessKeyId")
        if not access_key or access_key not in sessions:
            continue
        t = parse_time(e["eventTime"])
        if t is None:
            continue
        s = sessions[access_key]
        s["call_count"] += 1
        if s["actual_first_use"] is None or t < s["actual_first_use"]:
            s["actual_first_use"] = t
        if s["actual_last_use"] is None or t > s["actual_last_use"]:
            s["actual_last_use"] = t

    # 3) 생애주기 파생 지표 계산
    for s in sessions.values():
        s["never_used"] = s["call_count"] == 0
        s["used_after_expiration"] = bool(
            s["expires_at"] and s["actual_last_use"] and s["actual_last_use"] > s["expires_at"]
        )
        if s["issued_at"] and s["actual_first_use"]:
            s["idle_before_first_use_sec"] = (s["actual_first_use"] - s["issued_at"]).total_seconds()
        else:
            s["idle_before_first_use_sec"] = None

    return sessions


def attach_session_info(events, sessions):
    """각 이벤트에 자신이 속한 세션의 생애주기 요약을 붙여준다 (시각화/라벨링용)."""
    for e in events:
        access_key = e.get("accessKeyId")
        e["session"] = sessions.get(access_key)
    return events


def flag_replay_events(events, sessions):
    """
    세션의 예상 만료 시각 이후에 발생한 이벤트를 찾아 표시합니다.
    정상적으로는 AWS가 만료된 자격증명을 거부하므로, 로그에 이런 이벤트가
    남아있다는 것 자체가 (durationSeconds 파싱 오차가 아니라면) 자격증명
    탈취·재사용의 강한 신호입니다.
    """
    for e in events:
        s = e.get("session")
        if not s or not s.get("expires_at"):
            continue
        t = parse_time(e["eventTime"])
        if t and t > s["expires_at"] and not e.get("technique"):
            e["technique"] = "CredentialReplaySuspected(used-after-expiry)"
    return events


def flag_unused_sessions(events, sessions):
    """발급만 되고 한 번도 안 쓰인 세션의 '발급 이벤트'에 표시를 남긴다 (약한 신호)."""
    for e in events:
        if e["eventName"] not in STS_ISSUE_EVENTS:
            continue
        resp = (e.get("responseElements") or {}).get("credentials") or {}
        access_key = resp.get("accessKeyId")
        s = sessions.get(access_key)
        if s and s["never_used"]:
            e["session_note"] = "UnusedSessionIssued"
    return events


def prune_sessions(sessions, keep_identities):
    """
    대용량 로그에서는 발급된 세션 수 자체가 수만~수십만 개일 수 있습니다.
    top-N 이야기 선정 이후 살아남은 신원에 속한 세션만 남기고 나머지는 버려서,
    시각화(Gantt 막대)와 메모리 사용량이 '전체 세션 수'가 아니라 '선택된 이야기 수'에
    비례하게 만듭니다.
    """
    return {k: s for k, s in sessions.items() if s.get("role_target") in keep_identities}


def summarize(sessions):
    total = len(sessions)
    never_used = sum(1 for s in sessions.values() if s["never_used"])
    used_after_exp = sum(1 for s in sessions.values() if s["used_after_expiration"])
    return {
        "총 발급된 세션 수": total,
        "한 번도 안 쓰인 세션": never_used,
        "만료 이후 사용된 세션(의심)": used_after_exp,
    }
