# query — 목적별 활용 쿼리

기반 그래프 + 뷰 계층(`enrich_views.cypher` 실행 후) 위에서 목적별로 쓰는
Cypher 모음. **전제**: `load_3node_v2.cypher` → `enrich_views.cypher` 순으로 적재됨.

Neo4j Browser(<http://localhost:7474>)에서 그래프로 보려면 **노드·관계를
반환**해야 한다(`RETURN a, r, b`). 속성만 꺼내면(`RETURN n.name`) 표가 된다.
병렬 엣지가 많은 쌍은 `head(collect(r))` 로 대표 하나만 그린다(그래프 자체는
안 변함). 시드 id 는 리터럴로 박는다(cypher-shell `:param` 은 버전별 문법이 다름).

---

## 0. 준비·점검

```cypher
// 뷰 계층이 제대로 얹혔는지 (개수 표)
MATCH ()-[r:BASE_EVENT]->() RETURN r.advances AS advances, count(*) AS n ORDER BY advances;
MATCH ()-[r:CAN_OBTAIN]->() RETURN count(*) AS canObtain,
       sum(CASE WHEN r.exercised THEN 1 ELSE 0 END) AS exercised;
MATCH (n:Node) RETURN head([l IN labels(n)
  WHERE l IN ['Credential','Identity','Workload','Asset']]) AS kind,
  count(*) AS n ORDER BY n DESC;
```

```cypher
// 시나리오 구분 (파서에 출처 컬럼이 없어 시간 창으로 나눔)
MATCH ()-[r:BASE_EVENT]->()
RETURN CASE
  WHEN r.eventTime < datetime('2026-08-22') THEN 'steal-credentials'
  WHEN r.eventTime < datetime('2026-08-25T06:28:00Z') THEN 'instance-connect'
  WHEN r.eventTime < datetime('2026-08-26') THEN 'ebs-snapshot'
  WHEN r.eventTime < datetime('2026-08-28T05:44:00Z') THEN 'cloudtrail-delete'
  WHEN r.eventTime < datetime('2026-08-28T05:49:00Z') THEN 'vpc-remove-flow-logs'
  ELSE 'iam-backdoor-user' END AS scenario,
  count(DISTINCT r.eventID) AS events, count(*) AS edges
ORDER BY scenario;
```

---

## 1. 영향 범위 (blast radius)

> "이 자격증명이 탈취됐다면 무엇까지 연결되는가."
> `advances` 인 `BASE_EVENT` 와 `CAN_OBTAIN` 만 따라간다(전부 정방향).
> 읽기·실패·미해결(`advances=false`)은 잎이라 지나가지 않는다.

```cypher
// 1-1. 시드 후보 전수 — 부채꼴이 큰 자격증명이 곧 큰 시드다
MATCH (seed:Credential)
CALL { WITH seed
  MATCH (seed)-[:CAN_OBTAIN|BASE_EVENT*1..6]->(n)
  RETURN count(DISTINCT n) AS reached }
WITH seed, reached WHERE reached > 0
RETURN seed.id, seed.kind, reached ORDER BY reached DESC LIMIT 20;
```

```cypher
// 1-2. 한 시드의 영향 범위 유도 부분그래프 (그래프)
MATCH (seed:Node {id:'AKIA52CDAKM4W5UHPSX2'})
MATCH (seed)-[r1]->(a) WHERE type(r1)='CAN_OBTAIN' OR r1.advances
WITH seed, collect(DISTINCT a) AS h1
UNWIND h1 AS a
OPTIONAL MATCH (a)-[r2]->(b) WHERE type(r2)='CAN_OBTAIN' OR r2.advances
WITH [seed]+h1+collect(DISTINCT b) AS pool
WITH [x IN pool WHERE x IS NOT NULL] AS inside
UNWIND inside AS s
MATCH (s)-[r]->(t) WHERE t IN inside AND (type(r)='CAN_OBTAIN' OR r.advances)
WITH s, t, head(collect(r)) AS r
RETURN s, r, t;
```

```cypher
// 1-3. 자격증명 사이 도달만 — 권한 이동의 골격 (그래프)
MATCH (a:Credential)-[r:CAN_OBTAIN]->(b:Credential) RETURN a, r, b;
```

```cypher
// 1-4. 노출만 되고 통제 안 된 자산 — 읽기를 잎으로 둔 판단이 무엇을 잘랐나
MATCH (seed:Node {id:'AKIA52CDAKM4W5UHPSX2'})-[r1]->(a)
  WHERE type(r1)='CAN_OBTAIN' OR r1.advances
WITH seed, collect(DISTINCT a) AS h1
WITH [seed]+h1 AS inside
UNWIND inside AS s
MATCH (s)-[r:BASE_EVENT]->(leaf)
  WHERE NOT leaf IN inside AND r.readOnly=true AND r.outcome='SUCCESS' AND r.dstAs<>'Service'
WITH s, leaf, head(collect(r)) AS r
RETURN s, r, leaf;
```

---

## 2. 유입 경로 (upstream)

> "이 자격증명을 어떻게 훔치게 됐나." 같은 엣지를 거꾸로 탄다. 시드 + 기준 시각.

```cypher
// 2-1. 기준 시각 이전으로 상류 추적 (그래프)
MATCH (seed:Node {id:'ASIA52CDAKM456D2HKTH'})
MATCH (u1)-[r1]->(seed)
  WHERE (type(r1)='CAN_OBTAIN' AND r1.at        <= datetime('2026-08-21T07:24:01Z'))
     OR (r1.advances   AND r1.eventTime <= datetime('2026-08-21T07:24:01Z'))
WITH seed, collect(DISTINCT u1) AS up1
WITH [seed]+up1 AS inside
UNWIND inside AS s
MATCH (s)-[r]->(t) WHERE t IN inside
  AND ((type(r)='CAN_OBTAIN' AND r.at        <= datetime('2026-08-21T07:24:01Z'))
    OR (r.advances   AND r.eventTime <= datetime('2026-08-21T07:24:01Z')))
WITH s, t, head(collect(r)) AS r
RETURN s, r, t;
```

```cypher
// 2-2. 경계 직전 창을 통째로 (그래프) — 외부 IP 호출을 눈으로 찾는다
MATCH (a)-[r:BASE_EVENT]->(b)
WHERE r.eventTime >= datetime('2026-08-21T07:23:01Z')
  AND r.eventTime <= datetime('2026-08-21T07:24:01Z')
RETURN a, r, b;
```

```cypher
// 2-3. 실제 IP 만 (서비스 대리 호출 제외) — 표
MATCH ()-[r:BASE_EVENT]->()
WHERE r.sourceIP <> '' AND NOT r.sourceIP ENDS WITH '.amazonaws.com'
RETURN r.sourceIP AS ip, count(*) AS calls, count(DISTINCT r.eventName) AS apis,
       min(r.eventTime) AS firstSeen, max(r.eventTime) AS lastSeen
ORDER BY calls DESC;
```

---

## 3. 세션 신원 분열 (identity split)

> "같은 신원에서 나온 자격증명들이 서로 다른 곳에서 쓰이는가." 도달성이 아니라
> 이상 징후. `accessKeyId` 를 PK 로 잡은 설계의 실증(ARN 이면 한 노드로 합쳐진다).

```cypher
// 3-1. 출처가 갈린 워크로드와 그 키들 (그래프)
MATCH (k:Credential)-[r:CONTEXT {rel:'RUNS_ON'}]->(w:Workload)
WHERE w.finding = 'split-workload'
RETURN k, r, w;
```

```cypher
// 3-2. 그 키들이 실제로 무엇을 했나 (그래프)
MATCH (k:Credential)-[r:BASE_EVENT]->(x)
WHERE k.finding='split-identity'
  AND r.sourceIP <> '' AND NOT r.sourceIP ENDS WITH '.amazonaws.com'
WITH k, x, head(collect(r)) AS r
RETURN k, r, x;
```

```cypher
// 3-3. role 단위 대조군 — 공유 role 은 IP 가 갈려도 정상(오탐). 워크로드 단위와 대비
MATCH (role:Identity)-[r:CONTEXT {rel:'ISSUES'}]->(k:Credential)
WHERE role.resourceType='role' AND k.sourceIPs IS NOT NULL
RETURN role, r, k;
```

---

## 4. 공격 기법 모티프 (attack motif)

> 기법을 API 이름이 아니라 부분그래프 '모양'으로 잡는다. 정의·정답은 `motifs.py`.

```cypher
// M1 자격증명 탈취 (T1552.005) — 남의 워크로드 장악 + 그 키가 같은 IP 에서 쓰임
MATCH (thief:Credential)-[r:CAN_OBTAIN {exercised:true}]->(stolen:Credential)
MATCH (stolen)-[ro:CONTEXT {rel:'RUNS_ON'}]->(w:Workload)
MATCH (stolen)-[u:BASE_EVENT]->()
WITH thief, r, stolen, ro, w, min(u.eventTime) AS firstUse
MATCH (thief)-[e:BASE_EVENT {advances:true}]->(w) WHERE e.eventTime <= firstUse
WITH thief, r, stolen, ro, w, e ORDER BY e.eventTime DESC
WITH thief, r, stolen, ro, w, head(collect(e)) AS e
RETURN thief, r, stolen, ro, w, e;
```

```cypher
// M2 측면 이동 — 한 주체가 남의 워크로드 둘 이상에 원격 접근 주입
MATCH (a:Credential)-[e:BASE_EVENT {advances:true}]->(w:Workload)
WHERE e.eventSource IN ['ssm.amazonaws.com','ec2-instance-connect.amazonaws.com',
                        'ssmmessages.amazonaws.com','ec2messages.amazonaws.com']
  AND NOT (a)-[:CONTEXT {rel:'RUNS_ON'}]->(w)
WITH a, w, head(collect(e)) AS e
RETURN a, e, w;
```

```cypher
// M3 유출 — 저장 자산이 CREATE→MODIFY→DELETE 를 다 받음
MATCH (a:Credential)-[e:BASE_EVENT {advances:true}]->(x:Asset)
WHERE x.resourceType IN ['snapshot','volume','image','bucket','object']
WITH a, x, collect(DISTINCT e.actionL2) AS acts, collect(e) AS es
WHERE 'CREATE' IN acts AND 'MODIFY' IN acts AND 'DELETE' IN acts
UNWIND es AS e RETURN a, e, x;
```

```cypher
// M4 방어 회피 (T1562.008) — 관측 자산(트레일·플로우로그) 삭제
//   서로 다른 API(DeleteTrail / DeleteFlowLogs)를 한 모양으로 잡는다
MATCH (a:Credential)-[e:BASE_EVENT {advances:true}]->(x:Asset)
WHERE e.actionL2='DELETE' AND x.resourceType IN ['trail','flow-log']
RETURN a, e, x;
```

```cypher
// M5 지속성 (T1098) — 남의 신원에 만료 없는 키 발급
MATCH (a:Credential)-[e:BASE_EVENT {rel:'OBTAINS'}]->(k:Credential)
WHERE e.outcome='SUCCESS' AND k.kind='LongTermKey' AND a <> k
RETURN a, e, k;
```

```cypher
// M0 공통 뼈대 — 외부 주체가 남의 워크로드·저장자산을 건드림 (여기서 가지가 갈린다)
MATCH (a:Credential)-[e:BASE_EVENT {advances:true}]->(t)
WHERE (t:Workload OR t.resourceType IN ['snapshot','volume'])
  AND NOT (a)-[:CONTEXT {rel:'RUNS_ON'}]->(t)
WITH a, t, head(collect(e)) AS e RETURN a, e, t;
```

---

## 5. 기반 점검

```cypher
// 주체이자 자산인 노드 — 권한 체인이 통과하는 지점
MATCH (n:Actor:Resource)-[r]-(m) RETURN n, r, m;

// 삭제 행위 전수 — actionL2 하나로, 서비스별 지식 없이
MATCH (a)-[r:BASE_EVENT {actionL2:'DELETE'}]->(x) RETURN a, r, x;

// 권한 거부로 실패한 호출 — 권한 정찰 신호 (Stratus 에서는 0건이 정상)
//   errorClass='DENIED' 하나로 판별. flaws.cloud 면 여기가 대량으로 잡힌다.
MATCH (a)-[r:BASE_EVENT]->(x) WHERE r.errorClass='DENIED'
WITH a, x, head(collect(r)) AS r RETURN a, r, x;

// 대상을 특정 못 한 접근(서비스로 수렴) — 많으면 파서의 대상 추출에 구멍
MATCH (a)-[r:BASE_EVENT {dstAs:'Service'}]->(x)
WITH a, x, head(collect(r)) AS r RETURN a, r, x;
```
