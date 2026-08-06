// ============================================================
// CloudTrail 그래프 import 스크립트 (Neo4j 5.x)
// 사용법: 아래 5개 노드 CSV와 edges.csv를 Neo4j의 import 폴더에 넣고
//         Neo4j Browser에서 이 파일 내용을 순서대로 실행
// ============================================================

// ---- 0. 제약조건(중복 방지 + 조회 속도) ----
CREATE CONSTRAINT principal_id IF NOT EXISTS FOR (p:Principal) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT role_id      IF NOT EXISTS FOR (r:Role)      REQUIRE r.id IS UNIQUE;
CREATE CONSTRAINT session_id   IF NOT EXISTS FOR (s:Session)   REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT resource_id  IF NOT EXISTS FOR (x:Resource)  REQUIRE x.id IS UNIQUE;
CREATE CONSTRAINT service_id   IF NOT EXISTS FOR (v:Service)   REQUIRE v.id IS UNIQUE;

// ---- 1. 노드 적재 ----
LOAD CSV WITH HEADERS FROM 'file:///principals.csv' AS row
MERGE (p:Principal {id: row.id})
  SET p.kind = row.kind, p.arn = row.arn, p.identityType = row.identityType;

LOAD CSV WITH HEADERS FROM 'file:///roles.csv' AS row
MERGE (r:Role {id: row.id})
  SET r.roleName = row.roleName;

LOAD CSV WITH HEADERS FROM 'file:///sessions.csv' AS row
MERGE (s:Session {id: row.id})
  SET s.kind = row.kind, s.issuedByRole = row.issuedByRole, s.issuedAt = row.issuedAt;

LOAD CSV WITH HEADERS FROM 'file:///resources.csv' AS row
MERGE (x:Resource {id: row.id})
  SET x.kind = row.kind, x.resType = row.resType, x.name = row.name;

LOAD CSV WITH HEADERS FROM 'file:///services.csv' AS row
MERGE (v:Service {id: row.id})
  SET v.service = row.service;

// ---- 2. 엣지 적재 (관계 종류별로 분리 실행) ----
// 2a. ASSUME_ROLE : Principal -> Role
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.rel = 'ASSUME_ROLE'
MATCH (p:Principal {id: row.src}), (r:Role {id: row.dst})
CREATE (p)-[:ASSUME_ROLE {eventTime: row.eventTime, sourceIP: row.sourceIP, outcome: row.outcome}]->(r);

// 2b. ISSUES : Role -> Session
  LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
  WITH row WHERE row.rel = 'ISSUES'
  MATCH (r:Role {id: row.src}), (s:Session {id: row.dst})
  CREATE (r)-[:ISSUES {issuedAt: row.issuedAt}]->(s);

// 2c. HAS_ROLE : Principal -> Role  (속성 관계, 이벤트 아님)
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.rel = 'HAS_ROLE'
MATCH (p:Principal {id: row.src}), (r:Role {id: row.dst})
MERGE (p)-[:HAS_ROLE]->(r);

// 2d. ACCESS : Principal -> Resource 또는 Service
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.rel = 'ACCESS' AND row.dst_label = 'Resource'
MATCH (p:Principal {id: row.src}), (x:Resource {id: row.dst})
CREATE (p)-[:ACCESS {eventName: row.eventName, eventTime: row.eventTime, sourceIP: row.sourceIP, outcome: row.outcome}]->(x);

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.rel = 'ACCESS' AND row.dst_label = 'Service'
MATCH (p:Principal {id: row.src}), (v:Service {id: row.dst})
CREATE (p)-[:ACCESS {eventName: row.eventName, eventTime: row.eventTime, sourceIP: row.sourceIP, outcome: row.outcome}]->(v);

// ---- 3. [핵심] 세션 노드와 주체 노드를 연결 ----
// 발급된 Session(accessKeyId)이 나중에 주체(Principal)로 다시 등장하면 동일 자격증명.
// 이 SAME_CREDENTIAL 관계가 credential chaining 추적의 다리 역할.
MATCH (s:Session), (p:Principal)
WHERE s.id = p.id
MERGE (s)-[:SAME_CREDENTIAL]->(p);
