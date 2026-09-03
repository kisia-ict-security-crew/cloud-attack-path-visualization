#!/usr/bin/env python3
"""
CloudTrail -> 3-Node + Semantic Edge Foundation Graph  (v2)

v1 대비 변경 3가지
  ① 멀티라벨 단일 노드   같은 id 는 언제나 한 노드. 역할(Actor/Resource/Service)은
                        라벨로 겸한다. v1 에서는 role 이 Actor 복사본과 Resource
                        복사본으로 갈라져 권한 체인이 끊겼다.
  ② 대상 추출 확대       resources[] 뿐 아니라 requestParameters / responseElements /
                        serviceEventDetails 까지 훑는다. v1 은 ACCESS 엣지의 91.8%가
                        Service 로 뭉개졌다 (resources[] 는 183건 중 15건에만 존재).
  ③ 자격증명 체인 복원   responseElements.credentials 로 발급된 키(OBTAINS)와
                        userIdentity.inScopeOf 로 워크로드 바인딩(RUNS_ON)을 잇는다.
                        v1 에는 둘 다 없어 "리소스 장악 -> 자격증명 획득" 경로가 없었다.

출력
  nodes.csv     id 하나당 한 행. labels 컬럼에 역할 라벨이 세미콜론으로 들어간다.
  edges.csv     :BASE_EVENT — 일어난 일. 이벤트 하나가 대상 N개면 N행.
  context.csv   :CONTEXT    — 성립하는 사실. (src,dst,rel) 단위로 집계.

사용
  python parser_node3_v2.py <log.json> -o base_3node_csv
"""

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════
# 식별자 패턴 및 사전  (② 대상 추출에 쓰인다)
# ═══════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════
# 절제(ablation) 설정 — 실험용. 기본값은 전체 기능 켜짐이라 평소 동작은 같다.
#   EXTRACT_LEVEL 0 resources[] 만
#                 1 + ARN·AWS id 정규식
#                 2 + 핵심 이름 키 5개
#                 3 + 전체 키 화이트리스트 (기본)
#   DROPPED       특정 필드/경로를 비활성화 (leave-one-out 용)
# ═══════════════════════════════════════════════════════════════════
EXTRACT_LEVEL = 3
DROPPED: set = set()
CORE_NAME_KEYS = {'roleName', 'instanceProfileName', 'commandId',
                  'documentName', 'bucketName', 'userName'}

ARN_RE = re.compile(r'^arn:aws[a-z\-]*:[^:]*:[^:]*:[^:]*:.+$')
AWS_ID_RE = re.compile(
    r'^(i|vpc|subnet|sg|rtb|eni|ami|snap|vol|igw|nat|acl|eipalloc|eipassoc|'
    r'dopt|pl|cvpn|tgw|vpce|fl|vgw|cgw|vpn|lt|aclassoc|rtbassoc|subnetassoc|'
    r'eni-attach|vpc-cidr-assoc|vol-attach|tgw-attach|tgw-rtb)-[0-9a-f]{8,}$')

AWS_ID_TYPE = {
    'i': 'instance', 'vpc': 'vpc', 'subnet': 'subnet', 'sg': 'security-group',
    'rtb': 'route-table', 'eni': 'network-interface', 'ami': 'image',
    'snap': 'snapshot', 'vol': 'volume', 'igw': 'internet-gateway',
    'nat': 'nat-gateway', 'acl': 'network-acl', 'eipalloc': 'elastic-ip',
    'eipassoc': 'elastic-ip-association', 'dopt': 'dhcp-options',
    'pl': 'prefix-list', 'cvpn': 'client-vpn', 'tgw': 'transit-gateway',
    'vpce': 'vpc-endpoint', 'fl': 'flow-log', 'vgw': 'vpn-gateway',
    'cgw': 'customer-gateway', 'vpn': 'vpn-connection', 'lt': 'launch-template',
    'aclassoc': 'network-acl-association', 'rtbassoc': 'route-table-association',
    'subnetassoc': 'subnet-association', 'eni-attach': 'eni-attachment',
    'vpc-cidr-assoc': 'vpc-cidr-association', 'vol-attach': 'volume-attachment',
    'tgw-attach': 'transit-gateway-attachment', 'tgw-rtb': 'transit-gateway-route-table',
}

# 값의 형태만으로는 리소스인지 알 수 없을 때, 키 이름으로 건진다.
# 어떤 필드가 무엇을 가리키는지는 AWS API 스펙이 정한 구조적 사실이다.
KEY_TYPE_HINT = {
    'bucketName': 'bucket', 'roleArn': 'role', 'roleName': 'role',
    'functionName': 'function', 'instanceId': 'instance', 'vpcId': 'vpc',
    'subnetId': 'subnet', 'routeTableId': 'route-table',
    'networkInterfaceId': 'network-interface', 'imageId': 'image',
    'snapshotId': 'snapshot', 'volumeId': 'volume', 'groupId': 'security-group',
    'internetGatewayId': 'internet-gateway', 'natGatewayId': 'nat-gateway',
    'networkAclId': 'network-acl', 'allocationId': 'elastic-ip',
    'associationId': 'association', 'attachmentId': 'attachment',
    'trailName': 'trail', 'secretId': 'secret', 'keyId': 'kms-key',
    'tableName': 'table', 'queueUrl': 'queue', 'topicArn': 'topic',
    'policyArn': 'iam-policy', 'policyName': 'iam-policy',
    'userName': 'iam-user', 'instanceProfileName': 'instance-profile',
    'targetInstanceId': 'instance', 'documentName': 'ssm-document',
    'commandId': 'ssm-command', 'logGroupName': 'log-group',
    'streamName': 'stream', 'clusterName': 'cluster',
    'dbInstanceIdentifier': 'db-instance', 'stackName': 'stack',
    'repositoryName': 'repository', 'certificateArn': 'certificate',
    'targetGroupArn': 'target-group', 'loadBalancerName': 'load-balancer',
    'launchTemplateId': 'launch-template', 'launchTemplateName': 'launch-template',
    'key': 'object',
}
NAME_KEYS = set(KEY_TYPE_HINT)

CONTEXTUAL_KEYS = {'name'}
CONTEXT_TYPE_HINT = {'iamInstanceProfile': 'instance-profile'}

# EC2 의 일부 API 는 값을 {"tag": 1, "content": "..."} 로 한 겹 싸서 보낸다.
#   requestParameters.DeleteFlowLogsRequest.FlowLogId.content = "fl-..."
# 이때 leaf 이름이 'content' 라 키 이름 화이트리스트에 안 걸린다. 값이 ID 형태면
# 정규식으로 잡히지만(fl-/vpc-/i- 등), BucketName 처럼 ID 형태가 아닌 값은
# 놓친다. 그래서 leaf 가 'content' 면 **부모 키**를 화이트리스트에 대조한다.
# AWS 가 이 구조에서 PascalCase 를 쓰므로 소문자로 정규화해 비교한다.
WRAPPER_LEAVES = {'content', 'value'}
KEY_TYPE_HINT_CI = {k.lower(): v for k, v in KEY_TYPE_HINT.items()}

# 리소스가 아닌 것이 담기는 컨테이너. 태그 키, 필터 필드명, 상태 문자열 등은
# 식별자가 아니라 노드로 만들면 그래프가 오염된다.
DENY_CONTEXTS = (
    'tagSet', 'tagSpecificationSet', 'tags', 'Tags',
    'filterSet', 'filters', 'Filters',
    'advancedEventSelectors', 'eventSelectors',
    'instanceState', 'previousState', 'currentState', 'stateReason',
    'groupSet', 'placement', 'monitoring', 'blockDeviceMapping',
    'credentials',            # ③ 에서 따로 처리한다. 여기서 노드로 만들면 안 된다.
)

IAM_ARN_TYPES = {
    'role': 'role', 'instance-profile': 'instance-profile',
    'iam-user': 'user', 'iam-group': 'group', 'iam-policy': 'policy',
}
SERVICE_PRIMARY_TYPE = {
    'cloudtrail': 'trail', 'lambda': 'function', 's3': 'bucket',
    'sns': 'topic', 'sqs': 'queue', 'dynamodb': 'table',
    'logs': 'log-group', 'secretsmanager': 'secret', 'kms': 'kms-key',
}
ARN_TYPE_ALIAS = {
    'assumed-role': 'role', 'instance-profile': 'instance-profile',
    'user': 'iam-user', 'group': 'iam-group', 'policy': 'iam-policy',
    'root': 'account-root',
}


def parse_arn(arn: str) -> Dict[str, str]:
    p = arn.split(':', 5)
    if len(p) < 6:
        return {}
    rp = p[5]
    if '/' in rp:
        rtype, name = rp.split('/', 1)
    elif ':' in rp:
        rtype, name = rp.split(':', 1)
    else:
        rtype, name = '', rp
    return {'service': p[2], 'region': p[3], 'accountId': p[4],
            'resourceType': rtype.lower(), 'name': name}


def walk_leaves(obj, path=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_leaves(v, f'{path}.{k}' if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_leaves(v, f'{path}[{i}]')
    else:
        yield path, obj


def harvest_refs(blob, root: str) -> List[Tuple[str, str, Optional[str]]]:
    """② 중첩 구조 안의 리소스 식별자를 (refPath, value, typeHint) 로 전부 수집.

    refPath(프로버넌스)를 보존하는 이유: filterSet 안의 vpc-id 는 '질의 조건'이고
    routeTableIdSet 의 값은 '명시적 대상'이다. 이 구분은 해석이므로 기반에서
    결정하지 않고 출처만 남겨 뷰가 판단하게 한다.
    """
    out: List[Tuple[str, str, Optional[str]]] = []
    if not isinstance(blob, (dict, list)):
        return out
    for path, val in walk_leaves(blob, root):
        if not isinstance(val, str) or not val:
            continue
        segs = [s.split('[')[0] for s in path.split('.')]
        leaf = segs[-1]
        parent = segs[-2] if len(segs) > 1 else ''
        denied = any(c in segs for c in DENY_CONTEXTS)

        if ARN_RE.match(val) or AWS_ID_RE.match(val):
            if denied and 'credentials' in segs:
                continue
            if EXTRACT_LEVEL >= 1:
                out.append((path, val, None))
            continue
        if denied or EXTRACT_LEVEL < 2:
            continue
        if leaf in NAME_KEYS:
            if EXTRACT_LEVEL >= 3 or leaf in CORE_NAME_KEYS:
                out.append((path, val, KEY_TYPE_HINT[leaf]))
            continue
        # {tag, content} 래퍼 — 부모 키로 판단한다
        if leaf in WRAPPER_LEAVES and parent.lower() in KEY_TYPE_HINT_CI:
            if EXTRACT_LEVEL >= 3 or parent in CORE_NAME_KEYS:
                out.append((path, val, KEY_TYPE_HINT_CI[parent.lower()]))
            continue
        if leaf in CONTEXTUAL_KEYS and EXTRACT_LEVEL >= 3:
            if parent in CONTEXT_TYPE_HINT:
                out.append((path, val, CONTEXT_TYPE_HINT[parent]))
            elif len(segs) == 2:
                out.append((path, val, None))
    return out


def classify_resource(val: str, event_source: str, account: str, region: str,
                      type_hint: Optional[str] = None) -> Tuple[str, Dict[str, str]]:
    """리소스 식별자 문자열 -> (node_id, props)

    id 우선순위: 정규 ARN > 계정·리전을 붙인 합성 ARN > service:name
    합성한 경우 synthetic='true' 로 식별 신뢰도를 구분한다.
    같은 리소스가 이름으로 한 번·ARN 으로 한 번 참조돼도 한 노드로 수렴시킨다.
    """
    svc_short = event_source.replace('.amazonaws.com', '').split('.')[0] if event_source else 'unknown'

    if ARN_RE.match(val):
        a = parse_arn(val)
        rtype, name, svc = a.get('resourceType', ''), a.get('name', ''), a.get('service', '')

        if svc == 's3':
            rp = val.split(':', 5)[5]
            if '/' in rp:
                bucket, key = rp.split('/', 1)
                return val, {'resourceType': 'object', 'service': 's3',
                             'name': key, 'accountId': '', 'region': '', 'synthetic': 'false'}
            return val, {'resourceType': 'bucket', 'service': 's3',
                         'name': rp, 'accountId': '', 'region': '', 'synthetic': 'false'}

        # assumed-role ARN 은 '세션'이지 role 자체가 아니다 -> role ARN 으로 정규화.
        # 이래야 같은 role 이 세션 발급자이자 정책 부착 대상일 때 한 노드로 합쳐진다.
        if svc == 'sts' and rtype == 'assumed-role':
            base = name.split('/')[0]
            return (f"arn:aws:iam::{a['accountId']}:role/{base}",
                    {'resourceType': 'role', 'service': 'iam', 'name': base,
                     'accountId': a['accountId'], 'region': '', 'synthetic': 'false'})

        etype = ARN_TYPE_ALIAS.get(rtype, rtype or type_hint or 'unknown')
        return val, {'resourceType': etype, 'service': svc, 'name': name,
                     'accountId': a.get('accountId', ''), 'region': a.get('region', ''),
                     'synthetic': 'false'}

    m = AWS_ID_RE.match(val)
    if m:
        etype = AWS_ID_TYPE.get(m.group(1), type_hint or 'unknown')
        return (f"arn:aws:ec2:{region}:{account}:{etype}/{val}",
                {'resourceType': etype, 'service': 'ec2', 'name': val,
                 'accountId': account, 'region': region, 'synthetic': 'true'})

    etype = type_hint or SERVICE_PRIMARY_TYPE.get(svc_short) or 'unknown'

    if etype == 'bucket' or (svc_short == 's3' and type_hint is None):
        return (f"arn:aws:s3:::{val}",
                {'resourceType': 'bucket', 'service': 's3', 'name': val,
                 'accountId': '', 'region': '', 'synthetic': 'true'})

    if etype in IAM_ARN_TYPES and account:
        return (f"arn:aws:iam::{account}:{IAM_ARN_TYPES[etype]}/{val}",
                {'resourceType': etype, 'service': 'iam', 'name': val,
                 'accountId': account, 'region': '', 'synthetic': 'true'})

    if account:
        return (f"arn:aws:{svc_short}:{region}:{account}:{etype}/{val}",
                {'resourceType': etype, 'service': svc_short, 'name': val,
                 'accountId': account, 'region': region, 'synthetic': 'true'})
    return (f"{svc_short}:{region}:{etype}/{val}",
            {'resourceType': etype, 'service': svc_short, 'name': val,
             'accountId': '', 'region': region, 'synthetic': 'true'})


# ═══════════════════════════════════════════════════════════════════
# 의미론적 행위 추상화
# ═══════════════════════════════════════════════════════════════════

def derive_action_l2(event_name: str, read_only: bool) -> str:
    """의도(intent)만 판정한다. 결과는 outcome/errorClass 가 따로 들고 있다.

    v2 초판은 outcome=="FAILURE" 를 최우선으로 봐서 실패한 DeleteBucket 이
    DELETE 가 아니라 DENY 가 됐다. "삭제를 시도한 것 전부"가 질의되지 않는
    문제라, 의도와 결과를 분리했다. DENY 값 자체가 없어진다.
    """
    n = event_name.lower()
    if "assumerole" in n or event_name == "GetFederationToken":
        return "ASSUME"
    if read_only:
        return "READ"
    if any(n.startswith(p) for p in ["create", "run", "put", "insert", "start"]):
        return "CREATE"
    if any(n.startswith(p) for p in ["delete", "terminate", "remove", "drop"]):
        return "DELETE"
    if any(n.startswith(p) for p in ["update", "modify", "set", "attach", "detach"]):
        return "MODIFY"
    return "EXECUTE"


def harvest_failed_items(resp) -> Dict[str, str]:
    """배치 API 의 **부분 실패**를 수집한다. errorCode 없이 실패했을 수 있다.

    EC2 의 여러 배치 API 는 항목별 실패를 responseElements 안에 담는다.
        responseElements.DeleteFlowLogsResponse.unsuccessful.item
            .resourceId = "fl-..."
            .error.code  = "InvalidFlowLogId.NotFound"
    이때 최상위 errorCode 는 **없다**. 그래서 `errorCode` 유무로만 성공을 판정하면
    실패한 DeleteFlowLogs 가 SUCCESS 로 기록되고, 뷰에서 impact='CONTROL' 이 되어
    "공격자가 로깅을 껐다" 는 정반대 결론이 나온다. 방어 회피 분석에서 치명적이다.

    반환: {실패한 대상 값: errorCode}

    ※ 3-Node 모델이라 이걸 정확히 표현할 수 있다. 엣지가 '이벤트 × 대상' 단위라
      같은 호출 안에서 대상 A 는 성공, 대상 B 는 실패로 나눠 기록된다.
      이벤트가 노드인 모델에서는 이 구분이 한 노드 안에 뭉개진다.
    """
    out: Dict[str, str] = {}
    if not isinstance(resp, (dict, list)):
        return out
    buckets: Dict[str, Dict[str, str]] = {}
    for path, val in walk_leaves(resp, ''):
        segs = path.split('.')
        idx = next((i for i, s in enumerate(segs)
                    if 'unsuccessful' in s.split('[')[0].lower()), None)
        if idx is None or not isinstance(val, str) or not val:
            continue
        # 실패 항목 하나를 묶는 단위: unsuccessful 아래 두 단계까지의 경로
        key = '.'.join(segs[:idx + 2])   # unsuccessful + 항목 인덱스까지가 한 항목
        b = buckets.setdefault(key, {})
        leaf = segs[-1].split('[')[0]
        if ARN_RE.match(val) or AWS_ID_RE.match(val):
            b['id'] = val
        elif leaf in ('resourceId', 'resourceid'):
            b['id'] = val
        elif leaf in ('code', 'errorCode'):
            b['code'] = val
    for b in buckets.values():
        if b.get('id'):
            out[b['id']] = b.get('code', 'PartialFailure')
    return out


def classify_error(error_code: str) -> str:
    """errorCode 원문을 세 갈래로만 접는다. 원문은 별도 컬럼에 그대로 보존한다.

    DENIED     권한이 없다. '이 주체는 이걸 할 수 없다' — 권한 정찰의 신호
    NOT_FOUND  대상이 없다. 오타이거나 존재 여부를 떠보는 것. 권한과 무관
    FAULT      파라미터·기능 오류. 공격과 무관한 잡음인 경우가 많다

    검증 데이터(Stratus 3종)의 실패 75건은 전부 FAULT/NOT_FOUND 이고 DENIED 는
    0건이다. 반대로 flaws.cloud 는 UnauthorizedOperation 이 29,390건이다.
    같은 실패가 데이터셋에 따라 정반대 의미라, 뭉뚱그리면 한쪽에서 100% 오탐한다.
    """
    if not error_code:
        return ''
    ec = error_code.lower()
    if any(k in ec for k in ('accessdenied', 'unauthorized', 'forbidden',
                             'notauthorized', 'invalidclienttokenid',
                             'signaturedoesnotmatch', 'expiredtoken',
                             'authfailure')):
        return 'DENIED'
    if any(k in ec for k in ('notfound', 'nosuchentity', 'nosuch',
                             'doesnotexist', 'resourcenotfound')):
        return 'NOT_FOUND'
    return 'FAULT'


# ═══════════════════════════════════════════════════════════════════
# ① 멀티라벨 단일 노드 저장소
# ═══════════════════════════════════════════════════════════════════

NODE_COLS = ['id', 'labels', 'actorType', 'arn', 'accountId', 'kind',
             'resourceType', 'service', 'name', 'region', 'synthetic']


class NodeStore:
    """id 하나당 노드 하나. 역할은 라벨로 겸한다.

    v1 은 Actor 사전과 Resource 사전을 따로 두어, 같은 role ARN 이 양쪽에
    들어가면 Neo4j 에서 두 노드가 됐다. AssumeRole 은 Resource 복사본에
    도착하고 자격증명 발급은 Actor 복사본에서 출발해 체인이 끊겼다.
    """

    def __init__(self):
        self._n: Dict[str, Dict[str, Any]] = {}

    def add(self, node_id: str, label: str, props: Dict[str, Any]) -> str:
        if not node_id:
            return node_id
        cur = self._n.setdefault(node_id, {'id': node_id, '_labels': set()})
        cur['_labels'].add(label)
        for k, v in props.items():
            if v in (None, ''):
                continue
            # 먼저 쓰인 값을 유지한다. 단 'false' -> 'true' 같은 퇴행은 막고,
            # synthetic 은 한 번이라도 실제 ARN 으로 관측되면 false 로 확정한다.
            if k == 'synthetic':
                if cur.get('synthetic') == 'false' or v == 'false':
                    cur['synthetic'] = 'false'
                else:
                    cur.setdefault('synthetic', v)
            else:
                cur.setdefault(k, v)
        return node_id

    def rows(self) -> Iterable[Dict[str, Any]]:
        for n in self._n.values():
            r = {c: n.get(c, '') for c in NODE_COLS}
            r['labels'] = ';'.join(sorted(n['_labels']))
            yield r

    def label_stats(self):
        from collections import Counter
        return Counter(';'.join(sorted(n['_labels'])) for n in self._n.values())

    def __len__(self):
        return len(self._n)


# ═══════════════════════════════════════════════════════════════════
# 주체 파싱
# ═══════════════════════════════════════════════════════════════════

def parse_actor(identity: Dict[str, Any], source_ip: str) -> Tuple[str, Dict[str, Any]]:
    """주체 id 는 accessKeyId 를 최우선으로 쓴다.

    arn -> accessKeyId 가 1:N 이기 때문이다. 같은 ARN·같은 세션명인데 키가 다르고
    출처 IP 가 다른 경우가 실제로 존재하며, ARN 을 PK 로 쓰면 그 신호가 소멸한다.
    """
    arn = identity.get("arn", "") or ""
    access_key_id = identity.get("accessKeyId", "") or ""
    invoked_by = identity.get("invokedBy", "") or ""

    if access_key_id:
        p_id = access_key_id
    elif invoked_by:
        p_id = f"svc:{invoked_by}"
    elif arn:
        p_id = arn              # ⑦ v1 의 f"arn:{arn}" 이중 접두사 버그 수정.
    else:                       #    접두사를 붙이면 sessionIssuer 쪽 노드와 갈라진다.
        p_id = f"anonymous:{source_ip or 'unknown'}"

    if access_key_id.startswith("AKIA"):
        kind = "LongTermKey"
    elif access_key_id.startswith("ASIA"):
        kind = "TempKey"
    elif p_id.startswith("svc:"):
        kind = "Service"
    elif p_id.startswith("anonymous:"):
        kind = "Anonymous"
    else:
        kind = "Unknown"

    return p_id, {
        'actorType': identity.get("type", "Unknown"),
        'arn': arn,
        'accountId': identity.get("accountId", "") or "",
        'kind': kind,
    }


def load_events(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "Records" in obj:
            yield from obj["Records"]
            return
        if isinstance(obj, list):
            yield from obj
            return
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        if line.strip():
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ═══════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════

EDGE_COLS = ['src', 'dst', 'rel', 'actionL2', 'dstAs', 'refPath',
             'eventID', 'eventName', 'eventSource', 'eventTime',
             'sourceIP', 'outcome', 'errorCode', 'errorClass', 'readOnly']
CTX_COLS = ['src', 'dst', 'rel', 'via', 'evidenceCount', 'firstSeen', 'lastSeen', 'eventIDs']


def main():
    ap = argparse.ArgumentParser(description="CloudTrail -> 3-Node + Semantic Edge CSVs (v2)")
    ap.add_argument("input", type=Path, help="Path to CloudTrail JSON")
    ap.add_argument("-o", "--output", type=Path, default=Path("base_3node_csv"))
    ap.add_argument("--max-evidence", type=int, default=20,
                    help="context 엣지에 보존할 eventID 최대 개수 (기본 20)")
    ap.add_argument("--extract-level", type=int, default=3, choices=[0, 1, 2, 3],
                    help="대상 추출 강도 (절제 실험용). 0=resources[]만 3=전체")
    ap.add_argument("--drop", default="",
                    help="비활성화할 요소 (쉼표 구분): sourceIP,runsOn,issues,"
                         "readOnly,errorClass,obtains,responseElements,resources,refPath")
    args = ap.parse_args()

    global EXTRACT_LEVEL, DROPPED
    EXTRACT_LEVEL = args.extract_level
    DROPPED = {x.strip() for x in args.drop.split(',') if x.strip()}
    args.output.mkdir(parents=True, exist_ok=True)

    nodes = NodeStore()
    edges: List[Dict[str, Any]] = []
    ctx: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    stats = {'events': 0, 'svc_fallback': 0, 'obtains': 0, 'runs_on': 0,
             'issues': 0, 'no_identity': 0}

    def add_ctx(src, dst, rel, via, eid, etime):
        if not src or not dst or src == dst:
            return
        k = (src, dst, rel)
        c = ctx.get(k)
        if c is None:
            ctx[k] = {'src': src, 'dst': dst, 'rel': rel, 'via': via,
                      'evidenceCount': 1, 'firstSeen': etime, 'lastSeen': etime,
                      '_ids': [eid]}
        else:
            c['evidenceCount'] += 1
            if etime and etime < c['firstSeen']:
                c['firstSeen'] = etime
            if etime and etime > c['lastSeen']:
                c['lastSeen'] = etime
            if len(c['_ids']) < args.max_evidence:
                c['_ids'].append(eid)

    for event in load_events(args.input):
        stats['events'] += 1
        source_ip = event.get("sourceIPAddress", "") or ""
        identity = event.get("userIdentity") or {}
        event_source = event.get("eventSource", "") or ""
        event_name = event.get("eventName", "Unknown")
        event_id = event.get("eventID", "") or ""
        event_time = event.get("eventTime", "") or ""
        region = event.get("awsRegion", "") or ""
        account = event.get("recipientAccountId", "") or identity.get("accountId", "") or ""
        read_only = str(event.get("readOnly", False)).lower() == "true"
        # errorCode 는 원문 그대로 보존한다. errorMessage 만 있는 경우도 있어
        # outcome 판정에는 둘 다 쓰지만, errorCode 컬럼에는 errorCode 만 넣는다.
        error_code = event.get("errorCode") or ""
        has_error = bool(error_code or event.get("errorMessage"))
        outcome = "FAILURE" if has_error else "SUCCESS"
        error_class = classify_error(error_code) if has_error else ""
        if has_error and not error_class:
            error_class = "FAULT"          # errorMessage 만 있는 경우
        action_l2 = derive_action_l2(event_name, read_only)

        if not identity:
            stats['no_identity'] += 1

        # ── 주체 ────────────────────────────────────────────────
        actor_id, actor_props = parse_actor(identity, source_ip)
        nodes.add(actor_id, 'Actor', actor_props)

        base = {'actionL2': action_l2, 'eventID': event_id, 'eventName': event_name,
                'eventSource': event_source, 'eventTime': event_time,
                'sourceIP': '' if 'sourceIP' in DROPPED else source_ip,
                'outcome': outcome,
                'errorCode': '' if 'errorClass' in DROPPED else error_code,
                'errorClass': '' if 'errorClass' in DROPPED else error_class,
                'readOnly': '' if 'readOnly' in DROPPED else str(read_only).lower()}

        # ── 신원 -> 그 신원의 자격증명 : ISSUES (성립하는 사실) ──────
        # 자격증명(키)이 어느 신원에 속하는지를, 그 키를 쓴 흔적(userIdentity)에서
        # 재구성한다. 로그에 남은 '행위'가 아니라 흔적으로 세운 연결이라 CONTEXT 다.
        # 트리거는 특정 이벤트(예: CreateAccessKey)가 아니라 '키가 쓰인 사실'이라,
        # 발급 이벤트가 로그에 없어도 성립하고 모든 신원 형태에 대칭으로 적용된다.
        #   assumedRoot          소유 신원은 계정 root
        #   sessionIssuer 있음    그 issuer  (AssumedRole / Role / FederatedUser)
        #   IAMUser / Root        userIdentity.arn 자체 (세션 아닌 직접 주체)
        #   SAML/WebIdentity 등   외부 IdP라 AWS 신원 노드가 없다 -> 잇지 않는다(한계)
        # 빈 accessKeyId 엔 묶을 자격증명 노드가 없으므로 건너뛴다(AWSService 등).
        sess = identity.get("sessionContext") or {}
        issuer = sess.get("sessionIssuer") or {}
        issuer_arn = issuer.get("arn", "") or ""
        uid_type = identity.get("type", "") or ""
        access_key_id = identity.get("accessKeyId", "") or ""
        if access_key_id and 'issues' not in DROPPED:
            owner_arn, via = '', ''
            if sess.get("assumedRoot"):
                owner_arn = (f"arn:aws:iam::{account}:root" if account
                             else identity.get("arn", "") or "")
                via = 'assumed-root'
            elif issuer_arn:
                owner_arn = issuer_arn
                via = 'federated' if uid_type == 'FederatedUser' else 'assumed-role'
            elif uid_type == 'IAMUser':
                owner_arn, via = identity.get("arn", "") or "", 'iam-user'
            elif uid_type == 'Root':
                owner_arn, via = identity.get("arn", "") or "", 'root'
            if owner_arn:
                oid, oprops = classify_resource(owner_arn, 'iam.amazonaws.com',
                                                account, region)
                # role 은 발급자이자 대상이 될 수 있어 Actor 도 겸한다. 그 외 신원은
                # Resource(뷰에서 :Identity)로만 올린다 — 우리 모델의 '주체'는 키다.
                if oprops.get('resourceType') == 'role':
                    nodes.add(oid, 'Actor', {'actorType': 'Role', 'arn': owner_arn,
                                             'accountId': issuer.get('accountId', ''),
                                             'kind': 'Role'})
                nodes.add(oid, 'Resource', oprops)
                add_ctx(oid, actor_id, 'ISSUES', via, event_id, event_time)
                stats['issues'] += 1

        # ── ③ inScopeOf : 자격증명이 실려 있는 워크로드 ──────────
        scope = identity.get("inScopeOf") or {}
        issued_to = scope.get("credentialsIssuedTo", "") or ""
        if issued_to and 'runsOn' not in DROPPED:
            wid, wprops = classify_resource(issued_to, event_source, account, region)
            nodes.add(wid, 'Resource', wprops)
            add_ctx(actor_id, wid, 'RUNS_ON', scope.get('issuerType', 'inScopeOf'),
                    event_id, event_time)
            stats['runs_on'] += 1

        req = event.get("requestParameters")
        resp = event.get("responseElements")
        svc_details = event.get("serviceEventDetails")

        # 배치 API 의 부분 실패. errorCode 가 없어도 실패한 대상이 있을 수 있다.
        failed_items = harvest_failed_items(resp)
        if failed_items and outcome == "SUCCESS":
            # 전체를 실패로 뒤집지는 않는다. 실패한 '대상' 엣지만 아래에서 뒤집는다.
            stats['partial_failure'] = stats.get('partial_failure', 0) + 1

        # ── ③ responseElements.credentials : 발급된 자격증명 ────
        # "이 호출이 이 키를 만들었다". v1 에는 이 연결이 없어 발급 사슬이 끊겼다.
        # 발급 경로가 둘이다.
        #   STS  responseElements.credentials.accessKeyId  (AssumeRole 등, 임시 키)
        #   IAM  responseElements.accessKey.accessKeyId    (CreateAccessKey, 영구 키)
        # 후자를 빠뜨리면 '백도어 키 발급'(T1098)의 결정적 산출물이 그래프에 없다.
        # AKIA… 는 ARN 도 AWS id 패턴도 아니라 일반 추출 경로로는 절대 안 잡힌다.
        issued_key = ''
        issued_kind = 'TempKey'
        if isinstance(resp, dict) and 'obtains' not in DROPPED:
            creds = resp.get("credentials") or {}
            issued_key = (creds.get("accessKeyId") or "") if isinstance(creds, dict) else ""
            issued_ref = 'responseElements.credentials.accessKeyId'
            if not issued_key:
                ak = resp.get("accessKey") or {}
                if isinstance(ak, dict) and ak.get("accessKeyId"):
                    issued_key = ak["accessKeyId"]
                    issued_kind = 'LongTermKey'
                    issued_ref = 'responseElements.accessKey.accessKeyId'
            if issued_key:
                aru = resp.get("assumedRoleUser") or {}
                owner = ((resp.get("accessKey") or {}).get("userName")
                         if isinstance(resp.get("accessKey"), dict) else '') or ''
                nodes.add(issued_key, 'Actor', {
                    'actorType': 'AssumedRole' if issued_kind == 'TempKey' else 'IAMUser',
                    'arn': (aru.get('arn', '') if isinstance(aru, dict) else '')
                           or (f"arn:aws:iam::{account}:user/{owner}" if owner and account else ''),
                    'accountId': account, 'kind': issued_kind})
                edges.append({**base, 'src': actor_id, 'dst': issued_key,
                              'rel': 'OBTAINS', 'dstAs': 'Actor',
                              'refPath': issued_ref})
                stats['obtains'] += 1
                rarn = (req or {}).get('roleArn') if isinstance(req, dict) else None
                if rarn:
                    rid, rprops = classify_resource(rarn, 'iam.amazonaws.com', account, region)
                    nodes.add(rid, 'Resource', rprops)
                    nodes.add(rid, 'Actor', {'actorType': 'Role', 'kind': 'Role'})
                    add_ctx(rid, issued_key, 'ISSUES', 'assumeRoleResponse',
                            event_id, event_time)

        # ── ② 대상 추출 ─────────────────────────────────────────
        targets: List[Tuple[str, str, Optional[str], str]] = []   # (refPath, val, hint, rel)
        for r in (event.get("resources") or []) if 'resources' not in DROPPED else []:
            arn = r.get("ARN") or r.get("arn") or ""
            if arn:
                targets.append(('resources[].ARN', arn, None, 'ACCESS'))
        if EXTRACT_LEVEL >= 1:
            for p, v, h in harvest_refs(req, 'requestParameters'):
                targets.append((p, v, h, 'ACCESS'))
        if EXTRACT_LEVEL >= 1:
            for p, v, h in harvest_refs(svc_details, 'serviceEventDetails'):
                targets.append((p, v, h, 'ACCESS'))
        for p, v, h in (harvest_refs(resp, 'responseElements')
                        if EXTRACT_LEVEL >= 1 and 'responseElements' not in DROPPED else []):
            # 실패 보고 블록은 '생성된 자산'이 아니다. PRODUCES 로 잡으면 안 된다.
            if 'unsuccessful' in p.lower():
                continue
            targets.append((p, v, h, 'PRODUCES'))

        seen = set()
        emitted = 0
        for ref_path, val, hint, rel in targets:
            # hint 를 반드시 넘긴다. 안 넘기면 화이트리스트가 '수집 여부'만 정하고
            # '무슨 종류인가'는 버려져, 같은 자산이 user/… 와 unknown/… 두 노드로
            # 갈라진다. 검증 데이터에서 5건이 그렇게 갈라져 있었다.
            rid, rprops = classify_resource(val, event_source, account, region, hint)
            if not rid or rid == actor_id:
                continue
            nodes.add(rid, 'Resource', rprops)   # 속성 병합은 dedup 과 무관하게 항상
            # 한 이벤트가 같은 대상을 여러 번 가리켜도 엣지는 하나만 남긴다.
            # 대표적으로 응답이 요청의 값을 echo 하면(SendCommand 의 instanceIds/
            # documentName 등) 같은 노드가 요청(ACCESS)·응답(PRODUCES) 두 번 잡힌다.
            # targets 는 요청→응답 순이라 요청(ACCESS)이 남고 응답 echo 는 버려진다.
            # 이래야 (event,src,dst) 당 엣지가 하나다. 응답에만 나온 '진짜 산출물'은
            # 첫 등장이라 그대로 PRODUCES 로 남는다.
            if rid in seen:
                continue
            seen.add(rid)
            if rprops.get('resourceType') == 'role' and 'assumerole' in event_name.lower():
                edge_rel = 'ASSUME_ROLE'
            else:
                edge_rel = rel
            eb = base
            if val in failed_items:                       # 이 대상만 실패했다
                fc = failed_items[val]
                eb = {**base, 'outcome': 'FAILURE', 'errorCode': fc,
                      'errorClass': classify_error(fc) or 'FAULT'}
            edges.append({**eb, 'src': actor_id, 'dst': rid,
                          'rel': edge_rel, 'dstAs': 'Resource', 'refPath': '' if 'refPath' in DROPPED else ref_path})
            emitted += 1

        # ── 대상을 하나도 못 찾은 경우에만 Service 로 수렴 ───────
        if emitted == 0 and event_source:
            sid = event_source
            nodes.add(sid, 'Service', {'service': event_source.split('.')[0], 'name': event_source})
            edges.append({**base, 'src': actor_id, 'dst': sid,
                          'rel': 'ACCESS', 'dstAs': 'Service', 'refPath': 'eventSource'})
            stats['svc_fallback'] += 1

    # ── 출력 ────────────────────────────────────────────────────
    def write_csv(fp: Path, headers: List[str], rows: Iterable[Dict[str, Any]]):
        with fp.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
            w.writeheader()
            w.writerows(rows)

    ctx_rows = []
    for c in ctx.values():
        c = dict(c)
        c['eventIDs'] = '|'.join(c.pop('_ids'))
        ctx_rows.append(c)

    write_csv(args.output / "nodes.csv", NODE_COLS, nodes.rows())
    write_csv(args.output / "edges.csv", EDGE_COLS, edges)
    write_csv(args.output / "context.csv", CTX_COLS, ctx_rows)

    ls = nodes.label_stats()
    multi = sum(v for k, v in ls.items() if ';' in k)
    print(f"[3-NODE SEMANTIC GRAPH v2] -> '{args.output}'")
    print(f"  이벤트           : {stats['events']:,}")
    print(f"  노드             : {len(nodes):,}")
    for k, v in sorted(ls.items(), key=lambda kv: -kv[1]):
        print(f"      {k:<22} {v:,}")
    print(f"    └ 멀티라벨(①로 합쳐진 것) : {multi:,}")
    print(f"  BASE_EVENT 엣지  : {len(edges):,}")
    if edges:
        from collections import Counter
        for k, v in Counter(e['rel'] for e in edges).most_common():
            print(f"      {k:<22} {v:,}")
        svc = sum(1 for e in edges if e['dstAs'] == 'Service')
        print(f"    └ Service 수렴 : {svc:,} / {len(edges):,} "
              f"({100.0*svc/len(edges):.1f}%)   ← ② 지표, 낮을수록 좋다")
        ecs = Counter(e['errorClass'] for e in edges if e['errorClass'])
        if ecs:
            print(f"    └ 실패 분류 : " + "  ".join(f"{k} {v}" for k, v in ecs.most_common()))
    print(f"  CONTEXT 엣지     : {len(ctx_rows):,}  (ISSUES/RUNS_ON, 집계됨)")
    print(f"  ③ OBTAINS {stats['obtains']} / RUNS_ON {stats['runs_on']} "
          f"/ ISSUES 근거 {stats['issues']}건")
    if stats.get('partial_failure'):
        print(f"  ! 부분 실패 이벤트 {stats['partial_failure']}건 "
              f"(errorCode 없이 responseElements 에 실패 항목이 있음)")
    if stats['no_identity']:
        print(f"  ! userIdentity 부재 이벤트 {stats['no_identity']}건 (AwsServiceEvent 등)")


if __name__ == "__main__":
    main()
