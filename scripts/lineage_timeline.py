"""
Identity Lineage Timeline
- x축 = 시간 (스윔레인의 장점 유지)
- y축 = '행위자'가 아니라 '신원'(원본 IAM 계정 + AssumeRole로 파생된 각 임시 세션),
  부모-자식 계보 순서로 배치
- 부모 신원 -> 자식 신원으로 이어지는 연결선 = 실제 AssumeRole(권한 상승) 발생 시점
- 점 색 = 접근한 리소스 카테고리 (계정별로 '무엇에 접근했는지'를 유지)
"""
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import math
from datetime import datetime

from attack_chain_surprisal import JSONL_FILE_PATH, MAX_EVENTS, load_events, compute_surprisal, clean_name
from privesc_signatures import match_signatures
from session_lifecycle import build_sessions, attach_session_info, flag_replay_events, flag_unused_sessions

TECHNIQUE_MATCH_SCORE = 10.0   # 알려진 권한 상승 기법과 일치하면 이 고정 점수 (surprisal보다 항상 우선)


def build_unigram_rarity(events):
    """전체 이벤트 집합 기준 unigram 희귀도 함수를 만든다 (surprisal이 None인 경우의 보조 신호)."""
    action_counts = {}
    for e in events:
        action_counts[e["eventName"]] = action_counts.get(e["eventName"], 0) + 1
    total = max(len(events), 1)

    def unigram_rarity(event_name):
        p = action_counts.get(event_name, 1) / total
        return -math.log2(max(p, 1e-9))

    return unigram_rarity


UNUSED_SESSION_SCORE = 5.0     # 발급만 되고 안 쓰인 세션 - 완전한 기법 매칭보다는 약한 신호


def event_score(e, unigram_rarity):
    """
    이벤트 하나의 중요도 점수. 알려진 권한 상승 기법과 매칭됐으면(technique) 그게
    최우선 신호이고 (통계적으로 안 놀라워 보여도 기법이 확인되면 무조건 중요),
    매칭이 없으면 기존의 surprisal/희귀도로 fallback. 세션이 발급만 되고
    한 번도 안 쓰였다면(session_note) 중간 정도의 가산점을 준다.
    """
    if e.get("technique"):
        return TECHNIQUE_MATCH_SCORE
    base = max(e.get("surprisal") or 0, unigram_rarity(e["eventName"]))
    if e.get("session_note") == "UnusedSessionIssued":
        base = max(base, UNUSED_SESSION_SCORE)
    return base

OUTPUT_IMAGE_PATH = "cloudtrail_lineage_timeline.png"
TOP_LABEL_COUNT = 12
MAX_RESOURCE_CATEGORIES = 10   # 이보다 많은 리소스 종류가 나오면 나머지는 'other'로 합침
MIN_SESSION_EVENTS = 3         # 이보다 적게 행동한 세션은 별도 행을 안 만들고 부모 행에 합침
MIN_SESSION_SURPRISAL_TO_KEEP = 4.0  # 이벤트가 적어도 이 값 이상 놀라운 행동이 하나라도 있으면 절대 병합 안 함
TOP_N_STORIES = 3             # 가장 이례적인 뿌리(root) 상위 N개만 남기고 나머지는 그림에서 아예 제외
MIN_CONVERGENT_ROOTS = 2      # 같은 리소스에 이 개수 이상의 서로 다른 뿌리가 짧은 시간 안에 몰리면 '수렴'으로 간주
CONVERGENCE_TIME_BUCKET_MIN = 60  # 이 시간(분) 단위로 묶어서 '짧은 시간 안'을 판단
MAX_ROOT_IDENTITIES = 20       # 서로 무관한 '뿌리' 신원(계보 시작점)은 이 개수만 개별 표시, 나머지는 한 행으로 합침


def parse_time(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def collapse_minor_sessions(events, escalations, min_events=MIN_SESSION_EVENTS,
                             min_surprisal_to_keep=MIN_SESSION_SURPRISAL_TO_KEEP):
    """
    잠깐 쓰이고 버려진 세션(예: 2번만 호출하고 바로 다음 역할로 넘어간 징검다리 세션)에
    별도 행을 만들면 계보가 쓸데없이 길어집니다. 이런 세션은 events 수가 부족하면
    조상 중 events가 충분한 첫 신원으로 흡수시킵니다.
    단, 이벤트 수가 적어도 그 중 중요해 보이는 게 하나라도 있으면 병합하지 않습니다.
    주의: 세션의 유일한 행동은 '이전 행동 대비 전이 확률'(surprisal)을 계산할 '이전 행동'
    자체가 없어서 항상 surprisal=None이 됩니다 - 즉 세션이 짧을수록 surprisal로는
    절대 안 걸립니다(구조적 모순). 그래서 '이 행동이 전체 데이터셋에서 얼마나
    희귀한가'(단순 빈도, unigram)를 보조 신호로 같이 씁니다.
    """
    unigram_rarity = build_unigram_rarity(events)

    event_count = {}
    importance = {}
    for e in events:
        s = e["subject"]
        event_count[s] = event_count.get(s, 0) + 1
        score = event_score(e, unigram_rarity)
        importance[s] = max(importance.get(s, 0), score)
    parent_of = {child: parent for parent, child, _, _ in escalations}

    def is_mergeable(identity):
        return (event_count.get(identity, 0) < min_events and
                importance.get(identity, 0) < min_surprisal_to_keep)

    def resolve(identity):
        cur = identity
        seen = set()
        while is_mergeable(cur) and cur in parent_of and cur not in seen:
            seen.add(cur)
            cur = parent_of[cur]
        return cur

    remap = {ident: resolve(ident) for ident in event_count}
    for e in events:
        e["display_identity"] = remap[e["subject"]]
    return remap


def root_of(identity, parent_of):
    cur, seen = identity, set()
    while cur in parent_of and cur not in seen:
        seen.add(cur)
        cur = parent_of[cur]
    return cur


def compute_convergence_scores(events, parent_of, bucket_minutes=CONVERGENCE_TIME_BUCKET_MIN,
                                min_roots=MIN_CONVERGENT_ROOTS):
    """
    같은 리소스에 짧은 시간 안에 '서로 다른 뿌리(root) 신원'이 몰리는 패턴을 찾습니다.
    공격자가 여러 개의 도용된 자격증명을 나눠 써서 같은 표적에 접근하는 전형적인 지문입니다.
    개별 뿌리 하나하나의 행동은 평범해 보여도, 이 신호로 따로 잡아냅니다.

    주의: 정각 기준 고정 버킷(00:00, 01:00 ...)으로 나누면, 하나의 연속된 사건이
    마침 시(hour) 경계에 걸쳐 있을 때 두 버킷으로 쪼개져서 놓칠 수 있습니다.
    대신 '이벤트 간격이 bucket_minutes보다 벌어지면 새 클러스터'로 나누는
    gap 기반 클러스터링을 씁니다 - 시각과 무관하게 실제 연속성만 봅니다.
    """
    import math
    from datetime import timedelta

    by_target = {}
    for e in events:
        if not e["target"]:
            continue
        t = parse_time(e["eventTime"])
        if not t:
            continue
        r = root_of(e["display_identity"], parent_of)
        by_target.setdefault(e["target"], []).append((t, r))

    gap = timedelta(minutes=bucket_minutes)
    convergence_score = {}
    convergence_groups = []

    for target, items in by_target.items():
        items.sort(key=lambda x: x[0])
        cluster_roots, cluster_start, prev_t = set(), None, None

        def flush(end_marker):
            if len(cluster_roots) >= min_roots:
                bonus = math.log2(len(cluster_roots)) * 3
                convergence_groups.append((target, cluster_start, set(cluster_roots)))
                for r in cluster_roots:
                    convergence_score[r] = max(convergence_score.get(r, 0), bonus)

        for t, r in items:
            if prev_t is not None and (t - prev_t) > gap:
                flush(prev_t)
                cluster_roots = set()
                cluster_start = None
            if cluster_start is None:
                cluster_start = t
            cluster_roots.add(r)
            prev_t = t
        flush(prev_t)

    return convergence_score, convergence_groups


def select_top_stories(events, remap, surviving_escalations, top_n=TOP_N_STORIES):
    """
    서로 무관한 뿌리(root) 신원이 많을 때, 요약 행으로 뭉치는 것도 이제 그만두고
    아예 가장 이례적인 상위 top_n개 이야기만 남기고 나머지는 그림에서 제외합니다.
    '필요없는 내용을 줄이고 핵심만' 보여주는 게 목표라면, 굳이 배경 활동을
    한 줄로라도 남길 필요가 없습니다.
    """
    import math
    children = {}
    for parent, child, _, _ in surviving_escalations:
        children.setdefault(parent, []).append(child)
    child_set = set(c for lst in children.values() for c in lst)
    all_display = set(remap.values())
    roots = [i for i in all_display if i not in child_set]

    if len(roots) <= top_n:
        return set(remap.values()), 0  # 이미 적으니 전부 유지

    unigram_rarity = build_unigram_rarity(events)

    def subtree_identities(root):
        out, stack = set(), [root]
        while stack:
            n = stack.pop()
            if n in out:
                continue
            out.add(n)
            stack.extend(children.get(n, []))
        return out

    events_by_identity = {}
    for e in events:
        events_by_identity.setdefault(e["display_identity"], []).append(e)

    parent_of = {child: parent for parent, child, _, _ in surviving_escalations}
    convergence_score, convergence_groups = compute_convergence_scores(events, parent_of)

    root_importance = {}
    for r in roots:
        best = 0.0
        for ident in subtree_identities(r):
            for e in events_by_identity.get(ident, []):
                score = event_score(e, unigram_rarity)
                best = max(best, score)
        best = max(best, convergence_score.get(r, 0))  # 여러 자격증명 수렴 신호도 같이 반영
        root_importance[r] = best

    kept_roots = sorted(roots, key=root_importance.get, reverse=True)[:top_n]

    # 수렴 그룹은 하나의 이야기이므로, 그 중 일부만 뽑히면 안 됨 -
    # 선택된 root가 속한 수렴 그룹의 나머지 root도 같이 포함시킴
    kept_set = set(kept_roots)
    for target, bucket, group_roots in convergence_groups:
        if kept_set & group_roots:
            kept_set |= group_roots
    kept_roots = list(kept_set)

    keep_identities = set()
    for r in kept_roots:
        keep_identities |= subtree_identities(r)
    return keep_identities, len(roots) - len(kept_roots)


def build_lineage(events):
    """
    AssumeRole 이벤트에서 '부모 신원 -> 자식 신원' 관계를 추출.
    requestParameters.roleArn을 우선 사용합니다 - AssumeRole 호출의 필수 파라미터라
    거의 항상 존재합니다. responseElements.assumedRoleUser.arn은 일부 실환경 로그에서
    비어있거나 익명화돼 있을 수 있어 fallback으로만 씁니다.
    """
    escalations = []  # (parent, child, time, target_role_hint)
    for e in events:
        if e["eventName"] == "AssumeRole" and not e.get("errorCode"):
            rp = e.get("requestParameters") or {}
            role_arn = rp.get("roleArn")
            if role_arn:
                child = clean_name(role_arn)
                escalations.append((e["subject"], child, e["eventTime"], child))
                continue

            assumed = (e.get("responseElements") or {}).get("assumedRoleUser") or {}
            new_arn = assumed.get("arn")
            if new_arn:
                child = clean_name(new_arn)
                role_hint = new_arn.split("/")[-2] if new_arn.count("/") >= 2 else child
                escalations.append((e["subject"], child, e["eventTime"], role_hint))
    return escalations


def order_rows(events, escalations, key="subject"):
    """부모 바로 아래 자식이 오도록 DFS 순서로 행을 배치."""
    children = {}
    for parent, child, _, _ in escalations:
        children.setdefault(parent, []).append(child)

    all_identities = set(e[key] for e in events)
    for _, child, _, _ in escalations:
        all_identities.add(child)
    for parent, _, _, _ in escalations:
        all_identities.add(parent)
    roots = [i for i in all_identities if not any(c == i for _, c, _, _ in escalations)]

    order = []
    visited = set()

    def dfs(node):
        if node in visited:
            return
        visited.add(node)
        order.append(node)
        for c in children.get(node, []):
            dfs(c)

    for r in sorted(roots):
        dfs(r)
    for i in sorted(all_identities):  # 혹시 못 들어간 게 있으면 마지막에 추가
        dfs(i)
    return order


def raw_category(target):
    if not target:
        return "other"
    if target.endswith("amazonaws.com"):
        return target.split(".")[0]  # s3.amazonaws.com -> "s3"
    return target


def build_category_map(events, max_categories=MAX_RESOURCE_CATEGORIES):
    """
    서비스 도메인(s3, iam 등)은 항상 유지하고, 특정 리소스 이름(버킷명 등)은
    등장 빈도 상위 것만 남기고 나머지는 'other-resource'로 묶어서
    범례가 무한정 늘어나는 걸 막습니다.
    """
    domain_cats = set()
    specific_counts = {}
    for e in events:
        t = e["target"]
        if t and t.endswith("amazonaws.com"):
            domain_cats.add(raw_category(t))
        else:
            c = raw_category(t)
            specific_counts[c] = specific_counts.get(c, 0) + 1

    budget = max(max_categories - len(domain_cats), 0)
    top_specific = sorted(specific_counts, key=specific_counts.get, reverse=True)[:budget]
    keep = domain_cats | set(top_specific)

    def mapper(target):
        c = raw_category(target)
        return c if c in keep else "other-resource"

    return mapper


def visualize(events, sessions=None):
    events = [e for e in events if parse_time(e["eventTime"])]
    escalations = build_lineage(events)
    remap = collapse_minor_sessions(events, escalations)

    def build_surviving(escalations, remap):
        out = []
        for parent, child, t, role_hint in escalations:
            p2, c2 = remap.get(parent, parent), remap.get(child, child)
            if p2 != c2:
                out.append((p2, c2, t, role_hint))
        return out

    surviving_escalations = build_surviving(escalations, remap)
    keep_identities, dropped_root_count = select_top_stories(events, remap, surviving_escalations)
    if dropped_root_count:
        print(f"[*] 상위 {TOP_N_STORIES}개 이야기만 남기고, 나머지 {dropped_root_count}개는 그림에서 제외")
        events = [e for e in events if e["display_identity"] in keep_identities]
        surviving_escalations = [se for se in surviving_escalations
                                  if se[0] in keep_identities and se[1] in keep_identities]
        if sessions:
            from session_lifecycle import prune_sessions
            before = len(sessions)
            sessions = prune_sessions(sessions, keep_identities)
            print(f"[*] 세션도 함께 축소: {before}개 -> {len(sessions)}개")

    row_order = order_rows(events, surviving_escalations, key="display_identity")
    row_y = {name: -i for i, name in enumerate(row_order)}

    # 세션 생애주기 막대: 발급~예상 만료 구간을 옅은 막대로, 만료 이후에도 쓰인
    # '초과 구간'은 빨간 해칭으로 표시 (자격증명 재사용 의심 신호를 한눈에)
    if sessions:
        for s in sessions.values():
            row_name = s.get("role_target")
            if row_name not in row_y or not s.get("issued_at") or not s.get("expires_at"):
                continue
            y = row_y[row_name]
            plt.fill_betweenx([y - 0.18, y + 0.18], s["issued_at"], s["expires_at"],
                               color="#90CDF4", alpha=0.35, zorder=0, linewidth=0)
            if s["used_after_expiration"]:
                plt.fill_betweenx([y - 0.18, y + 0.18], s["expires_at"], s["actual_last_use"],
                                   color="#E53E3E", alpha=0.45, hatch="//", zorder=0, linewidth=0)


    cat_mapper = build_category_map(events)
    categories = sorted(set(cat_mapper(e["target"]) for e in events))
    cmap = plt.get_cmap("tab10")
    cat_color = {c: cmap(i % 10) for i, c in enumerate(categories)}

    fig_h = max(5, len(row_order) * 0.6)
    plt.figure(figsize=(15, fig_h))

    by_identity = {}
    for e in events:
        by_identity.setdefault(e["display_identity"], []).append(e)

    for identity, evs in by_identity.items():
        if identity not in row_y:
            continue
        evs.sort(key=lambda e: e["eventTime"])
        xs = [parse_time(e["eventTime"]) for e in evs]
        y = row_y[identity]
        plt.plot(xs, [y] * len(xs), color="#CBD5E0", linewidth=0.8, zorder=1)
        colors = [cat_color[cat_mapper(e["target"])] for e in evs]
        sizes = [110 if e.get("technique") else (60 if e.get("surprisal") and e["surprisal"] > 5 else 35) for e in evs]
        markers_star = [i for i, e in enumerate(evs) if e.get("technique")]
        markers_dot = [i for i, e in enumerate(evs) if not e.get("technique")]
        if markers_dot:
            plt.scatter([xs[i] for i in markers_dot], [y] * len(markers_dot),
                        s=[sizes[i] for i in markers_dot], c=[colors[i] for i in markers_dot],
                        edgecolors="#1A202C", linewidths=0.5, zorder=2)
        if markers_star:
            plt.scatter([xs[i] for i in markers_star], [y] * len(markers_star),
                        s=[sizes[i] for i in markers_star], c=[colors[i] for i in markers_star],
                        marker="*", edgecolors="#1A202C", linewidths=0.8, zorder=3)

    # 권한 상승(AssumeRole) 연결선 - 같은 (parent, child) 조합이 여러 번 반복되면
    # 선을 그 횟수만큼 다 그리지 않고 대표 시점 1개 + 횟수 라벨로 축약합니다.
    # (반복 횟수가 많을수록 색을 더 진하게 해서, 자주 반복된 '정상 패턴'과
    #  단 한 번뿐인 '이례적 상승'을 색으로 구분할 수 있게 합니다.)
    grouped = {}
    for parent, child, t, role_hint in surviving_escalations:
        if parent not in row_y or child not in row_y:
            continue
        g = grouped.setdefault((parent, child, role_hint), {"times": [], "role_hint": role_hint})
        g["times"].append(t)

    max_count = max((len(g["times"]) for g in grouped.values()), default=1)
    for (parent, child, role_hint), g in grouped.items():
        times = sorted(g["times"])
        x = parse_time(times[0])          # 첫 발생 시점을 대표로 표시
        y1, y2 = row_y[parent], row_y[child]
        count = len(times)
        alpha = 0.25 + 0.65 * (count / max_count) if count > 1 else 1.0
        lw = 1.2 if count == 1 else min(1.2 + count * 0.05, 4.0)
        plt.plot([x, x], [y1, y2], color="#E53E3E", linewidth=lw, zorder=3,
                  linestyle="--", alpha=alpha)
        plt.scatter([x], [y1], marker="D", s=90, color="#E53E3E", zorder=4,
                    edgecolors="#1A202C", alpha=alpha)
        label = f"AssumeRole -> {role_hint}" + (f" (x{count})" if count > 1 else "")
        plt.annotate(label, (x, (y1 + y2) / 2),
                     xytext=(8, 0), textcoords="offset points", fontsize=8,
                     color="#E53E3E", fontweight="bold", va="center", alpha=min(alpha + 0.3, 1.0))

    # 라벨: 같은 (신원, 기법) 조합이 여러 번 반복되면 1개 라벨 + 횟수로 압축
    # (안 그러면 매칭이 많은 신원은 라벨 수십 개가 겹쳐서 안 읽힘)
    technique_groups = {}
    for e in events:
        if e.get("technique") and e["display_identity"] in row_y:
            technique_groups.setdefault((e["display_identity"], e["technique"]), []).append(e)

    for (identity, technique), evs in technique_groups.items():
        evs.sort(key=lambda ev: ev["eventTime"])
        first = evs[0]
        label = technique + (f" (x{len(evs)})" if len(evs) > 1 else "")
        plt.annotate(label, (parse_time(first["eventTime"]), row_y[identity]),
                     xytext=(5, -12), textcoords="offset points", fontsize=7,
                     color="#742A2A", fontweight="bold")

    # 기법 매칭이 없는 경우에만 surprisal 상위로 보조 라벨 (개수 제한)
    other_scored = [e for e in events if not e.get("technique") and e.get("surprisal")]
    remaining = max(TOP_LABEL_COUNT - len(technique_groups), 0)
    for e in sorted(other_scored, key=lambda ev: ev["surprisal"], reverse=True)[:remaining]:
        if e["display_identity"] not in row_y:
            continue
        plt.annotate(e["eventName"], (parse_time(e["eventTime"]), row_y[e["display_identity"]]),
                     xytext=(5, -12), textcoords="offset points", fontsize=7,
                     color="#2D3748")

    plt.yticks(list(row_y.values()), list(row_y.keys()), fontsize=8)
    locator = mdates.AutoDateLocator()
    plt.gca().xaxis.set_major_locator(locator)
    plt.gca().xaxis.set_major_formatter(mdates.ConciseDateFormatter(locator))
    plt.gcf().autofmt_xdate()

    handles = [mpatches.Patch(color=cat_color[c], label=c) for c in categories[:12]]
    plt.legend(handles=handles, title="Resource", bbox_to_anchor=(1.02, 1), loc="upper left",
               fontsize=7, title_fontsize=8)

    plt.title("Identity Lineage Timeline\n"
              "row=identity (parent above child), red dashed=AssumeRole escalation, "
              "point color=resource, label=highest-surprisal events",
              fontsize=11, fontweight="bold")
    plt.xlabel("Time")
    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE_PATH, dpi=250, bbox_inches="tight")
    print(f"[+] 신원 계보 타임라인 완료: {OUTPUT_IMAGE_PATH}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=JSONL_FILE_PATH,
                     help="폴더(tar 풀어놓은 곳) 또는 단일 JSONL 파일 경로")
    ap.add_argument("--limit", type=int, default=MAX_EVENTS, help="앞 N건만 처리 (대용량 첫 테스트용)")
    args = ap.parse_args()

    events = load_events(args.data_dir, max_events=args.limit)
    events = compute_surprisal(events)
    events = match_signatures(events)

    sessions = build_sessions(events)
    events = attach_session_info(events, sessions)
    events = flag_replay_events(events, sessions)
    events = flag_unused_sessions(events, sessions)

    from privesc_signatures import summarize as summarize_techniques
    from session_lifecycle import summarize as summarize_sessions
    print(f"총 {len(events)}개 이벤트, AssumeRole 등장 횟수: "
          f"{sum(1 for e in events if e['eventName']=='AssumeRole')}")
    print(f"매칭된 권한 상승 기법: {dict(summarize_techniques(events))}")
    print(f"세션 생애주기 요약: {summarize_sessions(sessions)}")
    visualize(events, sessions)
