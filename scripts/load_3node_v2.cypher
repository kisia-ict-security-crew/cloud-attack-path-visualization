// ═══════════════════════════════════════════════════════════════════════════
//  load_3node_v2.cypher — 3-Node v2 기반 그래프 적재
//
//  전제
//    - Neo4j 5.x + APOC Core (apoc.map.clean, apoc.create.addLabels)
//    - nodes.csv / edges.csv / context.csv 가 Neo4j 의 import 폴더에 평평하게 놓임
//    - docker-compose 에 dbms.import.csv.legacy_quote_escaping=false
//
//  실행 (PowerShell 은 '<' 리다이렉션을 지원하지 않는다)
//    Get-Content load_3node_v2.cypher | docker exec -i cloudtrail-graph `
//      cypher-shell -u neo4j -p <password> --format plain
//
//  주의
//    - `:auto` 를 쓰지 말 것. Neo4j 4.x 명령이라 5.x 에서 "Could not find command"
//      로 멈춘다. 5.x cypher-shell 은 기본이 암묵 트랜잭션이라 필요 없다.
//    - BASE_EVENT 는 MERGE 가 아니라 CREATE 다. 두 번 돌리면 엣지가 두 배가 된다.
//      재적재 전에 반드시 STEP 0 을 돌릴 것.
//    - `CALL { WITH row ... } IN TRANSACTIONS` 는 5.23+ 에서 deprecated 경고가
//      뜨지만 정상 동작한다. 경고가 거슬리면 `CALL (row) { ... }` 로 바꿔도 되나,
//      그 문법은 5.23 미만에서 파싱 실패한다. 호환성을 택했다.
// ═══════════════════════════════════════════════════════════════════════════


// ── STEP 0. 초기화 ─────────────────────────────────────────────────────────
// 빈 DB 에 처음 넣는 거라면 이 줄은 건너뛰어도 된다.
// 재적재라면 반드시 돌려야 한다 — 안 그러면 CREATE 가 엣지를 중복 생성한다.
MATCH (n) DETACH DELETE n;


// ── STEP 1. 제약 및 인덱스 ─────────────────────────────────────────────────
CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE;

CREATE INDEX node_rtype IF NOT EXISTS FOR (n:Node) ON (n.resourceType);
CREATE INDEX node_kind  IF NOT EXISTS FOR (n:Node) ON (n.kind);
CREATE INDEX node_name  IF NOT EXISTS FOR (n:Node) ON (n.name);

// 이벤트 데이터가 전부 엣지에 있으므로 관계 인덱스가 필수다.
// 노드 라벨은 전부 :Node 를 공유해 선택도가 낮으므로 라벨 스캔에 기댈 수 없다.
CREATE INDEX be_time IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventTime);
CREATE INDEX be_name IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventName);
CREATE INDEX be_act  IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.actionL2);
CREATE INDEX be_ip   IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.sourceIP);
CREATE INDEX be_eid  IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.eventID);
CREATE INDEX be_rel  IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.rel);
CREATE INDEX be_ecls IF NOT EXISTS FOR ()-[r:BASE_EVENT]-() ON (r.errorClass);
CREATE INDEX ctx_rel IF NOT EXISTS FOR ()-[r:CONTEXT]-()    ON (r.rel);

// 인덱스가 ONLINE 이 될 때까지 기다린다. 안 기다리면 첫 LOAD 가 인덱스 없이 돈다.
CALL db.awaitIndexes(300);


// ── STEP 2. 노드 ───────────────────────────────────────────────────────────
// apoc.map.clean(row, [], ['']) 로 빈 문자열을 제거한다.
// LOAD CSV 는 빈 칸을 null 이 아니라 '' 로 읽으므로, 그대로 두면 모든 노드가
// 빈 속성을 갖게 되고 `WHERE ... IS NULL` 질의가 전부 깨진다.
LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
CALL { WITH row
  MERGE (n:Node {id: row.id})
  SET n += apoc.map.clean(row, [], [''])
} IN TRANSACTIONS OF 5000 ROWS;

// 역할 라벨 부여. labels 속성('Actor;Resource')을 실제 라벨로 바꾼다.
// 세미콜론을 쓰는데도 안전한 이유: 이 문자열은 Cypher 문장 '안에서' split() 으로만
// 소비되고 파일이 cypher-shell 로 파이프되지 않기 때문이다.
MATCH (n:Node) WHERE n.labels IS NOT NULL
CALL apoc.create.addLabels(n, split(n.labels, ';')) YIELD node
RETURN count(node) AS labeled;


// ── STEP 3. BASE_EVENT (일어난 일) ─────────────────────────────────────────
// MERGE 가 아니라 CREATE. 같은 주체가 같은 대상을 여러 번 호출하는 게 정상이고,
// 이벤트 하나가 대상 N개를 건드리면 eventID 를 공유하는 N개 엣지가 생긴다.
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
CALL { WITH row
  MATCH (a:Node {id: row.src})
  MATCH (b:Node {id: row.dst})
  CREATE (a)-[r:BASE_EVENT]->(b)
  SET r += apoc.map.clean(row, ['src','dst'], ['']),
      r.eventTime = datetime(row.eventTime),
      r.readOnly  = toBoolean(row.readOnly)
} IN TRANSACTIONS OF 5000 ROWS;


// ── STEP 4. CONTEXT (성립하는 사실) ────────────────────────────────────────
LOAD CSV WITH HEADERS FROM 'file:///context.csv' AS row
CALL { WITH row
  MATCH (a:Node {id: row.src})
  MATCH (b:Node {id: row.dst})
  MERGE (a)-[r:CONTEXT {rel: row.rel}]->(b)
  SET r += apoc.map.clean(row, ['src','dst'], ['']),
      r.evidenceCount = toInteger(row.evidenceCount),
      r.firstSeen     = datetime(row.firstSeen),
      r.lastSeen      = datetime(row.lastSeen),
      r.eventIDs      = split(row.eventIDs, '|')
} IN TRANSACTIONS OF 5000 ROWS;
// 리스트 구분자가 ';' 가 아니라 '|' 인 이유: ';' 는 cypher-shell 의 문장
// 구분자와 같은 문자라, CSV 값에 들어가면 파이프 입력이 문장 중간에서 잘린다.


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 5. 적재 검증  — 전부 OK 여야 한다
//
//  관계 적재는 MATCH 로 양끝 노드를 찾는데, 못 찾으면 예외가 아니라 그 행을
//  '조용히' 건너뛴다. 엣지가 사라져도 아무도 모르므로 CSV 행수와 반드시 대조한다.
// ═══════════════════════════════════════════════════════════════════════════

LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
WITH count(*) AS csvN
MATCH (n:Node) WITH csvN, count(n) AS dbN
RETURN 'Node' AS item, csvN, dbN,
       CASE WHEN csvN = dbN THEN 'OK' ELSE 'MISMATCH' END AS status;

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH count(*) AS csvN
MATCH ()-[r:BASE_EVENT]->() WITH csvN, count(r) AS dbN
RETURN 'BASE_EVENT' AS item, csvN, dbN,
       CASE WHEN csvN = dbN THEN 'OK' ELSE 'MISMATCH' END AS status;

LOAD CSV WITH HEADERS FROM 'file:///context.csv' AS row
WITH count(*) AS csvN
MATCH ()-[r:CONTEXT]->() WITH csvN, count(r) AS dbN
RETURN 'CONTEXT' AS item, csvN, dbN,
       CASE WHEN csvN = dbN THEN 'OK' ELSE 'MISMATCH' END AS status;

// 라벨이 안 붙은 노드가 있으면 apoc.create.addLabels 가 실패한 것이다.
MATCH (n:Node)
WHERE NOT (n:Actor OR n:Resource OR n:Service)
WITH count(n) AS c
RETURN 'unlabeled' AS item, c,
       CASE WHEN c = 0 THEN 'OK' ELSE 'MISMATCH' END AS status;

// 라벨 조합 분포. 'Actor:Resource' 를 겸하는 노드가 있어야 정상이다 —
// 권한 체인이 통과하는 지점이고, 라벨로 쪼개면 하필 거기서 그래프가 끊긴다.
MATCH (n:Node)
RETURN n.labels AS labels, count(*) AS n ORDER BY n DESC;

// 고립 노드. 기반 그래프에는 없어야 한다.
MATCH (n:Node) WHERE NOT (n)--()
WITH count(n) AS c
RETURN 'orphan' AS item, c,
       CASE WHEN c = 0 THEN 'OK' ELSE 'CHECK' END AS status;

// eventTime 이 DateTime 으로 들어갔는지 (문자열이면 시간 질의가 전부 깨진다)
MATCH ()-[r:BASE_EVENT]->()
RETURN 'eventTime type' AS item, apoc.meta.cypher.type(r.eventTime) AS type,
       min(r.eventTime) AS firstEvent, max(r.eventTime) AS lastEvent LIMIT 1;
