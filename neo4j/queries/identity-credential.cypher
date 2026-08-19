// ============================================================
// Identity -> Credential
//
// 하나의 Identity와 연결된 Credential 구조를 확인
// ============================================================

MATCH p=
    (i:Identity)-[:HAS_CREDENTIAL]->
    (c:Credential)

RETURN p

LIMIT 50;