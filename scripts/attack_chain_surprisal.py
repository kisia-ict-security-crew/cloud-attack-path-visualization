import json
import os
import glob
import gzip
import math
import heapq
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# ==============================================================================
# [설정 항목] 분석할 의심 계정(시작점) 지정
# ==============================================================================
# 폴더 경로(run.py가 tar를 풀어놓는 곳)를 그대로 지정해도 되고,
# merged_cloudtrail.jsonl 같은 단일 JSONL 파일 경로를 지정해도 됩니다.
JSONL_FILE_PATH = "data"

# "AUTO"로 두면 사람이 정하지 않고, 그래프 전체에서 surprisal이 가장 높은 전이의
# 행위자를 자동으로 시작점(seed)으로 선택합니다. (bottom-up 방식)
# 특정 계정을 직접 지정하고 싶으면 기존처럼 문자열을 넣으면 됩니다. (예: "bert-jan")
SUSPICIOUS_START_NODE = "AUTO"

OUTPUT_IMAGE_PATH = "cloudtrail_attack_chain_analysis.png"

MIN_ACTOR_OBS = 5       # 이 Actor의 이전-이벤트 관측이 이 값보다 적으면 global 통계로 backoff
TOP_LABEL_RATIO = 0.15  # 서브그래프 안에서 surprisal 상위 몇 %까지 라벨을 붙일지
MAX_EVENTS = None       # 테스트 삼아 앞쪽 N건만 빠르게 돌려보고 싶으면 정수로 설정 (예: 200000)
MAX_RENDER_NODES = 150  # 이 값이 진짜 실행 속도를 좌우합니다 (spring_layout이 O(노드수^2))
MAX_EDGES_PER_NODE = 6  # 한 노드에서 뻗어나가는 엣지를 surprisal 상위 N개로 제한 (hairball 방지)


# ==============================================================================
# 1. JSONL 파싱 (Level 0: 로그 필드 그대로, 해석 없음)
# ==============================================================================
def clean_name(arn_or_id):
    if not arn_or_id:
        return "unknown"
    if ":assumed-role/" in arn_or_id:
        # arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
        # 세션 이름(SESSION_NAME)까지 그대로 쓰면, 같은 역할을 재사용할 때마다
        # 세션명이 매번 달라져서 "같은 역할인데 별개의 신원"으로 잘못 취급됩니다.
        # (AWSConfig 등 AWS 서비스가 자기 역할을 주기적으로 재-AssumeRole할 때 특히 심함)
        # 역할 이름(ROLE_NAME)으로만 그룹화합니다.
        parts = arn_or_id.split(":assumed-role/")[-1].split("/")
        return parts[0] if parts and parts[0] else arn_or_id
    if "/" in arn_or_id:
        return arn_or_id.split("/")[-1].split(":")[-1]
    if ":" in arn_or_id:
        return arn_or_id.split(":")[-1]
    return arn_or_id


def _iter_raw_records(path):
    """
    두 가지 입력 형태를 모두 지원:
    1) 폴더 - 실제 flaws.cloud tar를 풀면 나오는 형태. {"Records": [...]}로 감싸진
       .json / .json.gz 파일들이 하위 폴더에 흩어져 있음 (CloudTrail 표준 export 형식)
    2) 단일 파일 - 한 줄에 레코드 하나씩인 JSONL (merged_cloudtrail.jsonl 같은 것)
    """
    if os.path.isdir(path):
        file_paths = sorted(glob.glob(f"{path}/**/*.json", recursive=True)) + \
                     sorted(glob.glob(f"{path}/**/*.json.gz", recursive=True))
    else:
        file_paths = [path]

    for fp in file_paths:
        opener = gzip.open if fp.endswith(".gz") else open
        try:
            with opener(fp, "rt", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError, EOFError):
            continue

        stripped = content.lstrip()
        if stripped.startswith("{"):
            # CloudTrail 표준 export 파일: {"Records": [...]}
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and "Records" in data:
                for r in data["Records"]:
                    yield r
                continue
            # {"Records":...}가 아닌 단일 JSON 객체 한 줄짜리일 수도 있음
            if isinstance(data, dict):
                yield data
                continue

        # JSONL: 한 줄에 레코드 하나씩
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_events(path, max_events=None):
    events = []
    for r in _iter_raw_records(path):
        user_id = r.get("userIdentity", {}) or {}
        subject = user_id.get("arn") or user_id.get("principalId") or "Unknown_Principal"

        req_params = r.get("requestParameters") or {}
        target = req_params.get("bucketName") or req_params.get("roleArn") or r.get("eventSource")
        if not subject or not target:
            continue

        events.append({
            "eventTime": r.get("eventTime", ""),
            "eventName": r.get("eventName", "Unknown"),
            "eventSource": r.get("eventSource"),
            "errorCode": r.get("errorCode"),
            "subject": clean_name(subject),
            "target": clean_name(target),
            "accessKeyId": user_id.get("accessKeyId"),
            "responseElements": r.get("responseElements") or {},
            "requestParameters": req_params,
        })
        if max_events and len(events) >= max_events:
            break
    events.sort(key=lambda e: e["eventTime"])
    return events


# ==============================================================================
# 2. Bottom-up 통계: Actor별 마르코프 전이 확률 -> surprisal
#    (사람이 정한 "위험 API 목록" 없이, 이 로그 자신의 시퀀스 통계로만 계산)
# ==============================================================================
def compute_surprisal(events):
    actor_pair_counts = defaultdict(lambda: defaultdict(int))   # actor -> (prev,cur) -> count
    actor_prev_totals = defaultdict(lambda: defaultdict(int))   # actor -> prev -> total count
    global_pair_counts = defaultdict(int)                        # (prev,cur) -> count
    global_prev_totals = defaultdict(int)                        # prev -> total count
    vocab = set()

    last_event_by_actor = {}
    for e in events:
        vocab.add(e["eventName"])
        prev = last_event_by_actor.get(e["subject"])
        if prev is not None:
            actor_pair_counts[e["subject"]][(prev, e["eventName"])] += 1
            actor_prev_totals[e["subject"]][prev] += 1
            global_pair_counts[(prev, e["eventName"])] += 1
            global_prev_totals[prev] += 1
        last_event_by_actor[e["subject"]] = e["eventName"]

    vocab_size = max(len(vocab), 1)

    def transition_prob(actor, prev, cur):
        total_actor = actor_prev_totals[actor].get(prev, 0)
        if total_actor >= MIN_ACTOR_OBS:
            c = actor_pair_counts[actor].get((prev, cur), 0)
            return (c + 1) / (total_actor + vocab_size)  # add-1 스무딩 (actor 수준)
        # 이 Actor의 이력이 부족하면 전체 데이터셋 통계로 backoff
        c = global_pair_counts.get((prev, cur), 0)
        total_global = global_prev_totals.get(prev, 0)
        return (c + 1) / (total_global + vocab_size)

    last_event_by_actor = {}
    for e in events:
        prev = last_event_by_actor.get(e["subject"])
        if prev is None:
            e["surprisal"] = None  # 이 Actor의 첫 관측이라 전이 자체가 없음
        else:
            p = transition_prob(e["subject"], prev, e["eventName"])
            e["surprisal"] = -math.log2(p)
        last_event_by_actor[e["subject"]] = e["eventName"]

    return events


# ==============================================================================
# 3. 그래프 빌드 (AssumeRole은 여전히 STS 세션 노드로 특별 취급 -
#    이건 "위험하다"는 라벨이 아니라 로그 구조(sessionIssuer 발급 관계) 자체이므로 유지)
# ==============================================================================
def build_graph(events):
    G = nx.DiGraph()
    surprisal_values = [e["surprisal"] for e in events if e["surprisal"] is not None]
    max_s = max(surprisal_values) if surprisal_values else 1.0

    for e in events:
        s = e["surprisal"]
        norm = 0.0 if s is None else min(s / max_s, 1.0)

        if e["eventName"] == "AssumeRole" and not e["errorCode"]:
            assumed_user = e["responseElements"].get("assumedRoleUser") or {}
            new_sts_arn = assumed_user.get("arn")
            if new_sts_arn:
                sts_clean = clean_name(new_sts_arn)
                G.add_node(e["subject"], node_type="IAMUser")
                G.add_node(sts_clean, node_type="STS_Session")
                G.add_edge(e["subject"], sts_clean, relation="AssumeRole",
                           surprisal=s or 0.0, norm=norm)
                continue

        G.add_node(e["subject"], node_type="Identity")
        G.add_node(e["target"], node_type="Resource")
        G.add_edge(e["subject"], e["target"], relation=e["eventName"],
                   surprisal=s or 0.0, norm=norm)
    return G


# ==============================================================================
# 4. Seed 자동 선택: surprisal이 가장 높은 전이의 행위자 (bottom-up)
# ==============================================================================
def pick_seed(G, manual_seed):
    if manual_seed and manual_seed.upper() != "AUTO":
        matched = [n for n in G.nodes() if manual_seed.lower() in n.lower()]
        if matched:
            return matched[0]
        print(f"[!] '{manual_seed}'를 찾지 못해 자동 선택으로 대체합니다.")

    best = max(G.edges(data=True), key=lambda uvd: uvd[2].get("surprisal", 0), default=None)
    if best is None:
        return list(G.nodes())[0]
    u, v, d = best
    print(f"[*] 자동 선택된 seed: '{u}' (가장 놀라운 전이: {d['relation']}, surprisal={d['surprisal']:.2f})")
    return u


# ==============================================================================
# 5. 시각화 (색/굵기 = surprisal, 라벨 = 상위 N% 전이만)
# ==============================================================================
def bounded_expand(G, seed_node, max_nodes):
    """
    seed에서 시작해서, 매번 '아직 안 가본 노드로 가는 엣지 중 surprisal이 가장 높은 것'을
    우선적으로 따라가는 best-first 확장. nx.descendants(무제한)와 달리 max_nodes에서
    멈추기 때문에 그래프가 커도 실행 시간이 예측 가능합니다.
    """
    visited = {seed_node}
    # (-surprisal, 다음 노드, 통해서 온 엣지)
    heap = []
    for _, v, d in G.out_edges(seed_node, data=True):
        heapq.heappush(heap, (-d.get("surprisal", 0.0), v))
    for u, _, d in G.in_edges(seed_node, data=True):
        heapq.heappush(heap, (-d.get("surprisal", 0.0), u))

    while heap and len(visited) < max_nodes:
        neg_s, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        for _, v, d in G.out_edges(node, data=True):
            if v not in visited:
                heapq.heappush(heap, (-d.get("surprisal", 0.0), v))
        for u, _, d in G.in_edges(node, data=True):
            if u not in visited:
                heapq.heappush(heap, (-d.get("surprisal", 0.0), u))
    return visited


def trim_edges_for_display(sub, max_per_node):
    """
    스캐너류 계정(하나의 노드가 수백 개 서로 다른 서비스를 한 번씩 호출)이 seed로 잡히면
    방사형 '성게' 모양이 되어 읽을 수 없어집니다. 각 노드마다 surprisal 상위 N개
    엣지만 남겨서, 그 노드 입장에서 '가장 이례적이었던 행위'만 보이게 압축합니다.
    """
    keep_pairs = set()
    for node in sub.nodes():
        out_e = sorted(sub.out_edges(node, data=True), key=lambda e: e[2]["surprisal"], reverse=True)[:max_per_node]
        in_e = sorted(sub.in_edges(node, data=True), key=lambda e: e[2]["surprisal"], reverse=True)[:max_per_node]
        for u, v, _ in out_e + in_e:
            keep_pairs.add((u, v))

    H = nx.DiGraph()
    for u, v in keep_pairs:
        H.add_edge(u, v, **sub.edges[u, v])
    for n in H.nodes():
        H.nodes[n].update(sub.nodes[n])
    return H


def visualize(G, seed_node):
    reachable_nodes = bounded_expand(G, seed_node, MAX_RENDER_NODES)
    sub_raw = G.subgraph(reachable_nodes)
    sub = trim_edges_for_display(sub_raw, MAX_EDGES_PER_NODE)
    print(f"[*] 렌더링 대상: 노드 {sub.number_of_nodes()}개, 엣지 {sub.number_of_edges()}개 "
          f"(엣지 트리밍 전: 노드 {sub_raw.number_of_nodes()}개, 엣지 {sub_raw.number_of_edges()}개 / "
          f"전체 그래프: 노드 {G.number_of_nodes()}개, 엣지 {G.number_of_edges()}개)")

    plt.figure(figsize=(14, 8))
    pos = nx.spring_layout(sub, k=1.2, seed=42)

    node_colors = []
    for node in sub.nodes():
        node_type = G.nodes[node].get("node_type", "Identity")
        if node == seed_node:
            node_colors.append("#E53E3E")
        elif node_type == "STS_Session":
            node_colors.append("#DD6B20")
        elif node_type == "Resource":
            node_colors.append("#3182CE")
        else:
            node_colors.append("#4A5568")

    edges = list(sub.edges(data=True))
    cmap = plt.get_cmap("Reds")
    edge_colors = [cmap(0.25 + 0.75 * d["norm"]) for u, v, d in edges]
    edge_weights = [0.5 + 5.0 * d["norm"] for u, v, d in edges]

    nx.draw_networkx_nodes(sub, pos, node_size=1500, node_color=node_colors,
                            alpha=0.9, edgecolors="#1A202C")
    nx.draw_networkx_edges(sub, pos, width=edge_weights, edge_color=edge_colors,
                            arrowsize=15, alpha=0.85)
    nx.draw_networkx_labels(sub, pos, font_size=8, font_family="sans-serif",
                             font_color="#FFFFFF", font_weight="bold")

    # 사람이 정한 "위험 API 목록"이 아니라, 이 서브그래프 안에서 통계적으로
    # 가장 놀라운 상위 TOP_LABEL_RATIO만 자동으로 라벨링
    sorted_edges = sorted(edges, key=lambda e: e[2]["surprisal"], reverse=True)
    cutoff = max(1, int(len(sorted_edges) * TOP_LABEL_RATIO))
    top_edges = {(u, v): d["relation"] for u, v, d in sorted_edges[:cutoff]}
    nx.draw_networkx_edge_labels(sub, pos, edge_labels=top_edges, font_size=8,
                                  font_color="#742A2A", font_weight="bold",
                                  bbox=dict(facecolor="white", alpha=0.8, edgecolor="none", pad=2.0))

    plt.title(f"AWS Attack Chain Tracker: '{seed_node}' Downstream Flow "
              f"(color/width = actor-relative statistical surprise)", fontsize=13, fontweight="bold", pad=20)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE_PATH, dpi=300)
    print(f"[+] 역추적 시각화 완료: {OUTPUT_IMAGE_PATH}")


# ==============================================================================
# 실행
# ==============================================================================
if __name__ == "__main__":
    if not os.path.exists(JSONL_FILE_PATH):
        print(f"[!] 에러: '{JSONL_FILE_PATH}' 파일이 존재하지 않습니다.")
        raise SystemExit(1)

    events = load_events(JSONL_FILE_PATH, max_events=MAX_EVENTS)
    events = compute_surprisal(events)
    G = build_graph(events)
    seed_node = pick_seed(G, SUSPICIOUS_START_NODE)
    visualize(G, seed_node)
