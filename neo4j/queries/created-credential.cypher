// ============================================================
// APIEvent -> Credential
//
// 새로운 자격 증명을 생성한 CloudTrail 이벤트 확인
// ============================================================

MATCH p=
    (a:APIEvent)-[:CREATED_CREDENTIAL]->
    (c:Credential)

RETURN p

LIMIT 25;