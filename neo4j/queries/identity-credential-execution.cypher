// ============================================================
// Identity -> Credential -> Execution
//
// 주체에서 자격 증명을 거쳐 실제 실행 문맥으로 이어지는 구조 확인
// ============================================================

MATCH p=
    (i:Identity)-[:HAS_CREDENTIAL]->
    (c:Credential)-[:STARTED_EXECUTION]->
    (e:Execution)

RETURN p

LIMIT 50;