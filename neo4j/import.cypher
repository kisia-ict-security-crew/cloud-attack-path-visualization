// ============================================================
// CloudTrail Graph Import Script
// Neo4j 5.x
//
// Input:
//   identity.csv
//   credential.csv
//   execution.csv
//   api_event.csv
//   resource.csv
//   edges.csv
// ============================================================


// ------------------------------------------------------------
// 0. Constraints
// ------------------------------------------------------------

CREATE CONSTRAINT identity_id IF NOT EXISTS
FOR (i:Identity)
REQUIRE i.id IS UNIQUE;

CREATE CONSTRAINT credential_id IF NOT EXISTS
FOR (c:Credential)
REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT execution_id IF NOT EXISTS
FOR (e:Execution)
REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT api_event_id IF NOT EXISTS
FOR (a:APIEvent)
REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT resource_id IF NOT EXISTS
FOR (r:Resource)
REQUIRE r.id IS UNIQUE;


// ------------------------------------------------------------
// 1. Nodes
// ------------------------------------------------------------


// 1a. Identity

LOAD CSV WITH HEADERS FROM 'file:///identity.csv' AS row

MERGE (i:Identity {id: row.identity_id})

SET
    i.identityType = row.identity_type,
    i.accountId = row.account_id,
    i.principalId = row.principal_id,
    i.arn = row.arn,
    i.name = row.name;


// 1b. Credential

LOAD CSV WITH HEADERS FROM 'file:///credential.csv' AS row

MERGE (c:Credential {id: row.credential_id})

SET
    c.accessKeyId = row.access_key_id,
    c.credentialType = row.credential_type,
    c.identityId = row.identity_id;


// 1c. Execution

LOAD CSV WITH HEADERS FROM 'file:///execution.csv' AS row

MERGE (e:Execution {id: row.execution_id})

SET
    e.identityId = row.identity_id,
    e.credentialId = row.credential_id,
    e.sourceIP = row.source_ip,
    e.userAgent = row.user_agent,
    e.firstSeen = row.first_seen,
    e.lastSeen = row.last_seen,
    e.eventCount =
        CASE
            WHEN row.event_count = '' THEN null
            ELSE toInteger(row.event_count)
        END;


// 1d. APIEvent

LOAD CSV WITH HEADERS FROM 'file:///api_event.csv' AS row

MERGE (a:APIEvent {id: row.event_id})

SET
    a.eventName = row.event_name,
    a.eventSource = row.event_source,
    a.eventTime = row.event_time,
    a.awsRegion = row.aws_region,
    a.sourceIP = row.source_ip,
    a.userAgent = row.user_agent,
    a.errorCode =
        CASE
            WHEN row.error_code = '' THEN null
            ELSE row.error_code
        END,
    a.readOnly =
        CASE
            WHEN row.read_only = '' THEN null
            ELSE toBoolean(row.read_only)
        END,
    a.credentialId = row.credential_id,
    a.executionId = row.execution_id;


// 1e. Resource

LOAD CSV WITH HEADERS FROM 'file:///resource.csv' AS row

MERGE (r:Resource {id: row.resource_id})

SET
    r.resourceType = row.resource_type,
    r.resourceName = row.resource_name,
    r.arn = row.arn,
    r.accountId = row.account_id,
    r.region = row.region;


// ------------------------------------------------------------
// 2. Relationships
// ------------------------------------------------------------


// 2a. Identity -> Credential

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row

WITH row
WHERE row.relationship_type = 'HAS_CREDENTIAL'

MATCH (i:Identity {id: row.source_id})
MATCH (c:Credential {id: row.target_id})

MERGE (i)-[:HAS_CREDENTIAL]->(c);


// 2b. Credential -> Execution

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row

WITH row
WHERE row.relationship_type = 'STARTED_EXECUTION'

MATCH (c:Credential {id: row.source_id})
MATCH (e:Execution {id: row.target_id})

MERGE (c)-[:STARTED_EXECUTION]->(e);


// 2c. APIEvent -> Credential
// 새로운 자격 증명을 생성한 이벤트

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row

WITH row
WHERE row.relationship_type = 'CREATED_CREDENTIAL'

MATCH (a:APIEvent {id: row.source_id})
MATCH (c:Credential {id: row.target_id})

MERGE (a)-[:CREATED_CREDENTIAL]->(c);


// ------------------------------------------------------------
// 3. Validation
// ------------------------------------------------------------

// 노드 개수

MATCH (n)
RETURN
    labels(n) AS label,
    count(n) AS count
ORDER BY count DESC;


// 관계 개수

MATCH ()-[r]->()
RETURN
    type(r) AS relationship,
    count(*) AS count
ORDER BY count DESC;