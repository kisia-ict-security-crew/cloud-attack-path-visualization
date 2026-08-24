#!/usr/bin/env python3
"""
CloudTrail -> 3-Node + Semantic Edge Foundation Graph
Nodes: Actor, Resource, Service
Edges: BASE_EVENT with actionL2 semantic abstraction
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def derive_action_l2(event_name: str, read_only: bool, outcome: str) -> str:
    if outcome == "FAILURE":
        return "DENY"
    name_lower = event_name.lower()
    if "assumerole" in name_lower or event_name == "GetFederationToken":
        return "ASSUME"
    if read_only:
        return "READ"
    if any(name_lower.startswith(p) for p in ["create", "run", "put", "insert", "start"]):
        return "CREATE"
    if any(name_lower.startswith(p) for p in ["delete", "terminate", "remove", "drop"]):
        return "DELETE"
    if any(name_lower.startswith(p) for p in ["update", "modify", "set", "attach", "detach"]):
        return "MODIFY"
    return "EXECUTE"


def parse_actor(identity: Dict[str, Any], source_ip: str) -> Tuple[str, Dict[str, Any]]:
    arn = identity.get("arn", "")
    access_key_id = identity.get("accessKeyId", "")
    invoked_by = identity.get("invokedBy", "")

    if access_key_id:
        p_id = access_key_id
    elif invoked_by:
        p_id = f"svc:{invoked_by}"
    elif arn:
        p_id = f"arn:{arn}"
    else:
        p_id = f"anonymous:{source_ip or 'unknown'}"

    kind = "LongTermKey" if access_key_id.startswith("AKIA") else ("TempKey" if access_key_id.startswith("ASIA") else ("Service" if p_id.startswith("svc:") else "Unknown"))

    return p_id, {
        "id": p_id,
        "actorType": identity.get("type", "Unknown"),
        "arn": arn,
        "accountId": identity.get("accountId", ""),
        "kind": kind,
        "category_l1": "IDENTITY"
    }


def parse_targets(event: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    resources, services = [], []
    event_source = event.get("eventSource", "").replace(".amazonaws.com", "").lower()
    raw_resources = event.get("resources") or []
    recipient_account = event.get("recipientAccountId", "")

    for r in raw_resources:
        arn = r.get("ARN") or r.get("arn") or ""
        if not arn:
            continue
        arn_lower = arn.lower()
        r_type = "role" if ":role/" in arn_lower else ("workload" if any(w in arn_lower for w in [":function:", ":instance/", ":container/"]) else "resource")
        
        resources.append({
            "id": arn,
            "resourceType": r_type,
            "service": event_source,
            "name": arn.split("/")[-1] if "/" in arn else arn.split(":")[-1],
            "accountId": r.get("accountId") or recipient_account,
            "category_l1": "RESOURCE"
        })

    if not resources and event_source:
        services.append({
            "id": event_source,
            "service": event_source.split(".")[0],
            "category_l1": "SERVICE"
        })

    return resources, services


def load_events(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text: return
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "Records" in obj:
            yield from obj["Records"]
            return
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        if line.strip():
            try: yield json.loads(line)
            except json.JSONDecodeError: continue


def main():
    parser = argparse.ArgumentParser(description="Parse CloudTrail into 3-Node + Semantic Edge CSVs.")
    parser.add_argument("input", type=Path, help="Path to CloudTrail JSON")
    parser.add_argument("-o", "--output", type=Path, default=Path("base_3node_csv"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    actors, resources, services = {}, {}, {}
    edges = []

    for event in load_events(args.input):
        source_ip = event.get("sourceIPAddress", "")
        identity = event.get("userIdentity") or {}
        event_source = event.get("eventSource", "")
        event_name = event.get("eventName", "Unknown")
        event_id = event.get("eventID", "")
        event_time = event.get("eventTime", "")
        read_only_bool = str(event.get("readOnly", False)).lower() == "true"
        error_code = event.get("errorCode") or event.get("errorMessage") or ""
        outcome = "FAILURE" if error_code else "SUCCESS"

        action_l2 = derive_action_l2(event_name, read_only_bool, outcome)

        # 1. Actor 노드
        actor_id, actor_props = parse_actor(identity, source_ip)
        actors[actor_id] = actor_props

        # 2. SessionIssuer (Role -> Principal ISSUES 관계)
        session_ctx = identity.get("sessionContext") or {}
        session_issuer = session_ctx.get("sessionIssuer") or {}
        issuer_arn = session_issuer.get("arn", "")

        if issuer_arn and ":role/" in issuer_arn.lower():
            actors[issuer_arn] = {
                "id": issuer_arn,
                "actorType": "Role",
                "arn": issuer_arn,
                "accountId": session_issuer.get("accountId", ""),
                "kind": "Role",
                "category_l1": "IDENTITY"
            }
            edges.append({
                "src": issuer_arn, "src_label": "Actor",
                "rel": "ISSUES", "action_l2": "ASSUME",
                "dst": actor_id, "dst_label": "Actor",
                "eventName": event_name, "eventSource": event_source, "eventTime": event_time,
                "eventID": event_id, "sourceIP": source_ip, "outcome": outcome, "readOnly": str(read_only_bool).lower()
            })

        # 3. Target Nodes & Edges
        res_list, svc_list = parse_targets(event)

        for r in res_list:
            resources[r["id"]] = r
            edges.append({
                "src": actor_id, "src_label": "Actor",
                "rel": "ASSUME_ROLE" if "assumerole" in event_name.lower() else "ACCESS",
                "action_l2": action_l2,
                "dst": r["id"], "dst_label": "Resource",
                "eventName": event_name, "eventSource": event_source, "eventTime": event_time,
                "eventID": event_id, "sourceIP": source_ip, "outcome": outcome, "readOnly": str(read_only_bool).lower()
            })

        for s in svc_list:
            services[s["id"]] = s
            edges.append({
                "src": actor_id, "src_label": "Actor",
                "rel": "ACCESS",
                "action_l2": action_l2,
                "dst": s["id"], "dst_label": "Service",
                "eventName": event_name, "eventSource": event_source, "eventTime": event_time,
                "eventID": event_id, "sourceIP": source_ip, "outcome": outcome, "readOnly": str(read_only_bool).lower()
            })

    def write_csv(filepath: Path, headers: List[str], data: Iterable[Dict[str, Any]]):
        with filepath.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            w.writerows(data)

    write_csv(args.output / "actors.csv", ["id", "actorType", "arn", "accountId", "kind", "category_l1"], actors.values())
    write_csv(args.output / "resources.csv", ["id", "resourceType", "service", "name", "accountId", "category_l1"], resources.values())
    write_csv(args.output / "services.csv", ["id", "service", "category_l1"], services.values())
    
    edge_headers = ["src", "src_label", "rel", "action_l2", "dst", "dst_label", "eventName", "eventSource", "eventTime", "eventID", "sourceIP", "outcome", "readOnly"]
    write_csv(args.output / "edges.csv", edge_headers, edges)

    print(f"[3-NODE SEMANTIC GRAPH CREATED] Output dir: '{args.output}'")
    print(f" - Actors    : {len(actors):,}")
    print(f" - Resources : {len(resources):,}")
    print(f" - Services  : {len(services):,}")
    print(f" - Edges     : {len(edges):,}")

if __name__ == "__main__":
    main()