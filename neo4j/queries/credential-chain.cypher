// ============================================================
// Credential chaining
//
// API 이벤트로 생성된 새로운 Credential이
// 이후 Execution으로 사용되는 흐름 확인
// ============================================================

MATCH p=
    (a:APIEvent)-[:CREATED_CREDENTIAL]->
    (c:Credential)-[:STARTED_EXECUTION]->
    (e:Execution)

RETURN p

LIMIT 50;