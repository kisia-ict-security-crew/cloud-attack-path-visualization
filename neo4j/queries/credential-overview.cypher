// ============================================================
// Credential creation overview
//
// CREATED_CREDENTIAL 관계를 넓은 범위에서 확인
// ============================================================

MATCH p=
    (a:APIEvent)-[:CREATED_CREDENTIAL]->
    (c:Credential)

RETURN p

LIMIT 200;