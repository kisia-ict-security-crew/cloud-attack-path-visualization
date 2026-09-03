// ═══════════════════════════════════════════════════════════════════════════
//  enrich_views.cypher  (v2) — 기반 그래프 위에 얹는 목적별 뷰
//
//  기반(3-Node v2)에는 판정이 없다. 목적성은 전부 이 파일에 있다.
//
//  ── 설계 원칙 (v1 에서 바뀐 것) ─────────────────────────────────────────
//  v1 은 기존 엣지를 방향만 뒤집어 복제했다(`runs_on_reverse`). 같은 사실이
//  그래프에 두 번 들어가 어느 쪽이 원본인지 흐려진다. v2 는 두 가지만 한다.
//
//    (A) 분류 — 이미 있는 것에 표시를 단다. 새로 만드는 게 없다.
//        · 노드에 종류 라벨 (:Credential / :Identity / :Workload / :Asset — 하나씩)
//        · BASE_EVENT 엣지에 `advances` 불리언 (도달 전이 여부)
//          true = 성공·대상특정·(자격증명 획득 또는 상태변경). 나머지 false.
//
//    (B) 합성 — 기반에 아예 없는 관계 하나만 새로 만든다.
//        · :CAN_OBTAIN — "이 주체는 저 자격증명을 손에 넣을 수 있다"
//          두 홉(주체가 워크로드를 장악 + 자격증명이 그 워크로드에 실림)을
//          한 엣지로 접은 것이다. 검증 데이터에서 이 9개 쌍 중
//          기반 BASE_EVENT 가 이미 존재하는 쌍은 0개다 — 복제가 아니다.
//
//  ── 시각화 ──────────────────────────────────────────────────────────────
//  모든 노드가 :Node 를 공유해 Browser 에서 전부 같은 색으로 보인다.
//  STEP 1 이 종류 라벨 네 개(:Credential / :Identity / :Workload / :Asset)를
//  **노드당 정확히 하나씩** 붙이고 `display` 캡션을 단다.
//  색은 두 방법 중 하나로 준다.
//    (a) browser-style.grass — `:style` 실행 → 결과 프레임의 Upload 버튼
//    (b) Browser 그래프 위 범례에서 라벨 칩을 클릭 → 색·크기·캡션 직접 선택
//  (b) 는 파일 없이도 되고 확실하다. 라벨이 네 개뿐이라 네 번만 클릭하면 된다.
//
//  ── 실행 ────────────────────────────────────────────────────────────────
//    docker cp .\enrich_views.cypher <container>:/tmp/enrich.cypher
//    docker exec -i <container> cypher-shell -u neo4j -p cloudtrail123 -f /tmp/enrich.cypher
//
//  질의(Q)는 전부 그래프로 그려지도록 노드·관계를 반환한다.
//  STEP 5 의 적재 검증만 예외로 표를 반환한다(개수 대조가 목적이므로).
// ═══════════════════════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 0. 뷰 층 초기화 — 재실행 시 필수
//  기반(:BASE_EVENT, :CONTEXT, :Node, :Actor, :Resource, :Service)은 안 건드린다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH ()-[r:CAN_OBTAIN]->() DELETE r;

// 종류 라벨 제거. 뒤쪽은 이전 판에서 쓰던 라벨이라, 남아 있으면 색이 꼬인다.
MATCH (n:Node)
REMOVE n:Credential:Identity:Workload:Asset:LongTermKey:TempKey:IAMRole:IAMAsset:Compute:Storage:Network:Audit:ServiceEndpoint:SplitIdentity:SplitWorkload;

MATCH (n:Node) REMOVE n.display, n.sourceIPs, n.splitIPs, n.finding;

MATCH ()-[r:BASE_EVENT]->() REMOVE r.impact, r.advances;


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 1. (A-1) 노드 종류 라벨 + 캡션
//
//  기반의 :Actor / :Resource / :Service 는 '역할'이지 '종류'가 아니다.
//  role 도 인스턴스도 VPC 도 전부 :Resource 라 화면에서 구분이 안 된다.
//
//  ── 왜 네 개인가 ────────────────────────────────────────────────────────
//  분류 기준은 "AWS 가 뭐라고 부르는가"가 아니라 **"이 그래프에서 무슨 역할을
//  하는가"** 다. 그래서 서비스별 종류(bucket/vpc/snapshot…)로 쪼개지 않는다.
//  그건 이미 `resourceType` 속성에 있고, 색으로 나눠봐야 읽는 사람이 외울 게
//  늘 뿐이다.
//
//    :Credential  행위의 출발점. 모든 BASE_EVENT 의 src 가 여기서 나온다.
//                 (AKIA 영구키 / ASIA 세션키 / svc: 서비스 주체)
//    :Identity    권한을 정의하는 IAM 객체. **:Actor 와 :Resource 를 겸하는
//                 유일한 부류**이고, 권한 체인이 통과하는 지점이다.
//                 (role / instance-profile / iam-user / iam-policy)
//    :Workload    자격증명이 실리는 곳. CAN_OBTAIN 이 경유하는 지점이자
//                 RUNS_ON 의 도착점이다. 이 모델의 회전축이라 따로 뗀다.
//                 (instance / launch-template)
//    :Asset       나머지 전부. 네트워크·저장소·감사로그·서비스 폴백.
//                 대상이긴 하지만 권한 흐름의 경유지는 아니다.
//
//  **노드 하나에 정확히 하나만 붙는다.** 여러 개가 붙으면 Browser 가 어느 색을
//  쓸지 정하지 못해 색이 뒤죽박죽 된다. 이전 판이 그랬다.
//  실측(combined 93): Asset 59 / Credential 22 / Identity 8 / Workload 4
// ═══════════════════════════════════════════════════════════════════════════

// ① 권한을 정의하는 IAM 객체 — 가장 먼저 잡는다.
//    role 은 kind='Role' 이면서 resourceType='role' 이라 ②와 겹칠 수 있는데,
//    권한 출처로 보는 쪽이 맞으므로 여기가 이긴다.
MATCH (n:Node)
WHERE n.resourceType IN ['role', 'instance-profile', 'iam-user', 'iam-policy']
SET n:Identity;

// ② 자격증명 — 행위의 출발점
MATCH (n:Node)
WHERE n.kind IN ['LongTermKey', 'TempKey', 'Service', 'Anonymous'] AND NOT n:Identity
SET n:Credential;

// ③ 워크로드 — 자격증명이 실리는 곳
MATCH (n:Node)
WHERE n.resourceType IN ['instance', 'launch-template']
  AND NOT (n:Identity OR n:Credential)
SET n:Workload;

// ④ 나머지 전부
MATCH (n:Node)
WHERE NOT (n:Identity OR n:Credential OR n:Workload)
SET n:Asset;

// 캡션. Browser 는 노드 안에 짧은 글자만 넣을 수 있다.
// 자격증명은 뒤 8자리로 구분된다. 앞자리(AKIA/ASIA)는 kind 속성에 남아 있다.
MATCH (n:Credential) SET n.display = right(n.id, 8);
MATCH (n:Identity)   SET n.display = last(split(coalesce(n.name, n.id), '/'));
MATCH (n:Node) WHERE n.display IS NULL
SET n.display = CASE
  WHEN n.name IS NOT NULL AND size(n.name) <= 24 THEN n.name
  WHEN n.name IS NOT NULL THEN right(n.name, 22)
  ELSE right(n.id, 22) END;


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 2. (A-2) 엣지 분류 — 기존 BASE_EVENT 에 `advances` 불리언을 단다
//
//  새 엣지를 만들지 않는다. 이미 있는 엣지에 "이 호출이 공격자를 전진시키는가"를
//  하나의 불리언으로 표시할 뿐이다. 공격 경로 순회가 따라갈 엣지를 고르는 술어다.
//
//    advances=true   성공 ∧ 대상특정됨 ∧ (자격증명 획득 OR 상태변경)
//                    → 영향·권한이 전이된다. blast radius·CAN_OBTAIN 이 이것만 탄다.
//    advances=false  읽기(노출)·실패·대상미특정. 잎이라 순회가 멈춘다.
//
//  ★ readOnly 하나로 전이/조회가 갈리므로 서비스별 지식이 필요 없다.
//    400개 서비스의 수천 API 에 그대로 확장된다.
//
//  ★ 이전의 5버킷(CONTROL/OBSERVE/DENIED_ATTEMPT/ATTEMPT/UNRESOLVED)은 없앴다.
//    도달성에 필요한 건 '전이 여부' 하나뿐이고, 나머지 구분은 전부 base 속성으로
//    그때그때 뽑을 수 있어 뷰에 중복 저장할 이유가 없다. 필요할 때:
//      노출        r.readOnly = true AND r.outcome = 'SUCCESS'
//      권한거부(정찰)  r.errorClass = 'DENIED'   ← flaws.cloud 면 대량으로 잡힌다
//      대상미특정   r.dstAs = 'Service'
// ═══════════════════════════════════════════════════════════════════════════

MATCH ()-[r:BASE_EVENT]->()
SET r.advances =
      r.outcome = 'SUCCESS'
  AND r.dstAs  <> 'Service'
  AND (r.rel = 'OBTAINS' OR r.readOnly = false);


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 2b. (A-3) 주체별 출처 IP 집합
//
//  sourceIP 는 항상 IP 가 아니다 — AWS 서비스 대리 호출이면 도메인이 들어온다.
//  실제 IP 만 모아 노드에 얹는다. 이후 STEP 3b 와 STEP 4 가 이걸 쓴다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH (a:Actor)-[r:BASE_EVENT]->()
WHERE r.sourceIP <> '' AND NOT r.sourceIP ENDS WITH '.amazonaws.com'
WITH a, collect(DISTINCT r.sourceIP) AS ips
SET a.sourceIPs = ips;


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 3. (B) 합성 관계 :CAN_OBTAIN — 기반에 없는 유일한 새 엣지
//
//  "이 주체가 저 자격증명을 손에 넣을 수 있다."
//
//  근거 두 개를 곱한 것이다.
//    ① (주체)-[BASE_EVENT {advances:true}]->(워크로드)   워크로드를 장악했다
//    ② (자격증명)-[CONTEXT {rel:'RUNS_ON'}]->(워크로드)     그 키가 거기 실려 있다
//    ⇒ 주체는 그 키를 얻을 수 있다
//
//  이 쌍 사이에는 기반 엣지가 없다. 공격자가 탈취한 키를 '호출'한 기록은
//  로그에 남지만 '훔친' 기록은 남지 않기 때문이다. 탈취 행위 자체가
//  CloudTrail 에 존재하지 않는 것이 이 연구의 출발점이고, 이 엣지가 그
//  빈칸을 명시적인 추론으로 채운다.
//
//  ※ 추론이므로 근거를 반드시 실어야 한다. `viaWorkload` 에 어느 워크로드를
//    거쳤는지(`viaWorkloads`), 그 장악이 언제였는지(`at`), 근거 이벤트가 몇 건인지
//    (`controlEvents`) 남긴다. 그래야 사람이 반박할 수 있다.
//
//  ※ 트레이드오프: 두 홉을 한 엣지로 접으므로 경유한 워크로드가 경로에서
//    사라진다. 화면에서 '인스턴스를 거쳐 갔다'가 선으로 안 보인다는 뜻이다.
//    `viaWorkloads` 속성으로 복구할 수 있고, 그 워크로드 자체는 보통
//    CONTROL 엣지의 대상으로 같은 화면에 이미 들어와 있다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH (a:Node)-[r:BASE_EVENT {advances: true}]->(w:Node)
MATCH (cred:Credential)-[x:CONTEXT {rel: 'RUNS_ON'}]->(w)
WHERE a <> cred
  // ★ 같은 워크로드에 실린 키끼리는 제외한다.
  //   인스턴스에 실린 키는 그 인스턴스에 CONTROL 을 남기게 마련이라(SSM 에이전트의
  //   RegisterManagedInstance 등), 규칙을 그대로 두면 같은 인스턴스의 키들이
  //   서로를 CAN_OBTAIN 하는 엣지가 쌍방향으로 생긴다. combined 19개 중 10개가
  //   그것이었고, 화면에서 "EC2 키가 사용자 키를 얻는다"처럼 방향이 뒤집혀 보였다.
  //   같은 워크로드 안은 이미 같은 신뢰 경계라 '획득'이라 부를 게 없다.
  AND NOT (a)-[:CONTEXT {rel: 'RUNS_ON'}]->(w)
WITH a, cred, w, min(r.eventTime) AS controlAt, x.firstSeen AS bindSeen, count(r) AS n
MERGE (a)-[g:CAN_OBTAIN]->(cred)
  ON CREATE SET g.viaWorkloads = [w.id], g.at = controlAt,
                g.bindFirstSeen = bindSeen, g.controlEvents = n
  ON MATCH  SET g.viaWorkloads = CASE WHEN w.id IN g.viaWorkloads
                                      THEN g.viaWorkloads ELSE g.viaWorkloads + w.id END,
                g.at = CASE WHEN controlAt < g.at THEN controlAt ELSE g.at END,
                g.controlEvents = g.controlEvents + n;



// ═══════════════════════════════════════════════════════════════════════════
//  STEP 3b. (A-4) CAN_OBTAIN 에 `exercised` 표시
//
//  ★ CAN_OBTAIN 은 '가능성'이지 '행위'가 아니다. 그래서 원래 권한이 큰 주체
//    (인스턴스를 만든 관리자 키 등)에서 부채꼴로 퍼진다 — 자기가 만든 워크로드의
//    자격증명을 얻을 수 있는 건 당연하기 때문이다. 그 부채꼴 안에서 '실제로
//    행사된 것'을 골라내려면 증거가 하나 더 필요하다.
//
//  증거: 얻을 수 있었던 주체의 출처 IP 와, 그 자격증명이 실제로 쓰인 IP 가 겹치는가.
//        겹치면 그 키가 주체의 단말에서 쓰였다는 뜻이다.
//
//  검증 데이터 실측 — CAN_OBTAIN 9개 중 겹치는 것은 **1개뿐**이고,
//  그게 ground truth 인 AKIA…W5UHPSX2 → ASIA…6D2HKTH 다.
//  나머지 8개는 대상 키가 인스턴스 자신의 IP 에서만 쓰였다(= 탈취 안 됨).
//
//  ※ 한계: 공격자가 훔친 키를 다른 단말·프록시에서 쓰면 안 겹친다. 즉 이 표시가
//    false 라고 탈취가 없었다는 뜻은 아니다. '증거가 있는 것'을 고르는 필터지
//    '없는 것'을 배제하는 필터가 아니다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH (a:Node)-[g:CAN_OBTAIN]->(c:Node)
SET g.exercised = CASE
  WHEN a.sourceIPs IS NOT NULL AND c.sourceIPs IS NOT NULL
   AND size([x IN a.sourceIPs WHERE x IN c.sourceIPs]) > 0
  THEN true ELSE false END,
    g.sharedIPs = CASE
  WHEN a.sourceIPs IS NOT NULL AND c.sourceIPs IS NOT NULL
  THEN [x IN a.sourceIPs WHERE x IN c.sourceIPs] ELSE [] END;


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 4. 뷰 3 의 표시 — '판정'은 라벨이 아니라 속성으로 남긴다
//
//  같은 워크로드에 실린 자격증명들이 서로 다른 출처 IP 에서 쓰였다면,
//  자격증명이 그 워크로드 밖으로 나갔다는 뜻이다.
//
//  ★ 이전 판은 이걸 :SplitWorkload / :SplitIdentity 라벨로 찍었는데, 그러면
//    '종류'와 '판정'이 같은 색 자리를 두고 싸운다. 실제로 화면에서 인스턴스
//    하나만 색이 튀고 나머지 종류 구분이 전부 죽었다.
//    **종류는 라벨(색), 판정은 속성(질의).** 둘을 섞지 않는다.
//
//  질의는 `WHERE n.finding = 'split-workload'` 로 한다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH (key:Credential)-[:CONTEXT {rel: 'RUNS_ON'}]->(w:Node)
WHERE key.sourceIPs IS NOT NULL
WITH w, collect(key) AS keys,
     apoc.coll.toSet(apoc.coll.flatten(collect(key.sourceIPs))) AS allIps
WHERE size(allIps) >= 2
SET w.finding = 'split-workload', w.splitIPs = allIps
WITH keys UNWIND keys AS k SET k.finding = 'split-identity';


// ═══════════════════════════════════════════════════════════════════════════
//  STEP 5. 뷰 층 검증  — 여기만 표를 반환한다 (개수 대조가 목적)
//  `simulate_views.py` 가 같은 규칙을 파이썬으로 재현한다. 두 값이 다르면
//  둘 중 하나가 틀린 것이다.
// ═══════════════════════════════════════════════════════════════════════════

MATCH ()-[r:BASE_EVENT]->()
RETURN 'advances' AS layer, r.advances AS bucket, count(*) AS n ORDER BY bucket;
// combined 기대값: true 316 / false 566  (합 882)
//   도달 전이(true)만 blast radius·CAN_OBTAIN·모티프가 따라간다.

MATCH ()-[r:CAN_OBTAIN]->()
WITH count(*) AS c, sum(CASE WHEN r.exercised THEN 1 ELSE 0 END) AS ex
RETURN 'CAN_OBTAIN' AS layer, c AS total, ex AS exercised,
       CASE WHEN c = 9 AND ex = 1 THEN 'OK(combined)' ELSE 'CHECK' END AS status;

MATCH (n:Node)
RETURN 'nodeKind' AS layer,
       head([l IN labels(n) WHERE l IN ['Credential','Identity','Workload','Asset']]) AS bucket,
       count(*) AS n ORDER BY n DESC;
// combined 기대값: Asset 59 / Credential 22 / Identity 8 / Workload 4  (합 93)

// 종류 라벨이 두 개 이상 붙은 노드가 있으면 색이 꼬인다. 0 이어야 한다.
MATCH (n:Node)
WITH n, size([l IN labels(n) WHERE l IN ['Credential','Identity','Workload','Asset']]) AS k
WHERE k <> 1
WITH count(n) AS c
RETURN 'nodeKind 중복/누락' AS layer, c,
       CASE WHEN c = 0 THEN 'OK' ELSE 'MISMATCH' END AS status;


// ═══════════════════════════════════════════════════════════════════════════
//  ┃ 뷰 1 — 영향 범위 (blast radius)
//  ┃ "이 자격증명이 탈취됐다면 무엇까지 연결되는가"
//  ┃
//  ┃ 순회 규칙: advances 인 BASE_EVENT + CAN_OBTAIN 만 따라간다. 전부 정방향이다.
//  ┃ 전이 아닌 엣지(읽기·실패·미해결)는 잎이라 지나가지 않는다.
//  ┃ 읽기를 잎으로 두는 게 중요하다 — 아니면 공용 VPC 를 거쳐 그래프 전체가
//  ┃ 하나로 이어져 '영향 범위'라는 개념이 무의미해진다.
// ═══════════════════════════════════════════════════════════════════════════

// ── V1-Q1 : 시드 후보 전수 + 각자의 1차 확산 (그래프) ─────────────────────
// 결과의 크기와 모양은 시드 선택이 사실상 결정한다. 그러니 '규칙이 옳은가'
// 만으로는 평가할 수 없고 시드 선정까지가 분석이다. 먼저 전수를 눈으로 본다.
// 화면에서 부채꼴이 큰 자격증명이 곧 영향 범위가 큰 시드다.
MATCH (seed:Credential)-[r:BASE_EVENT {advances: true}]->(x)
WITH seed, x, head(collect(r)) AS r          // 병렬 엣지는 대표 하나만 (신규 생성 아님)
RETURN seed, r, x;

// ── V1-Q2 : 한 시드의 영향 범위 유도 부분그래프 (그래프) ★ ────────────────
// 3홉까지 도달 노드를 모은 뒤, 그 안쪽 엣지만 골라 되돌린다.
// 경로를 그대로 반환하면 병렬 엣지 때문에 경로 수가 폭발하므로 집합으로 접는다.
// ※ seed id 를 바꿔가며 실행할 것. cypher-shell 의 :param 은 버전별 문법이
//   달라 리터럴로 박는 게 안전하다.
MATCH (seed:Node {id: 'AKIA52CDAKM4W5UHPSX2'})
MATCH (seed)-[r1]->(a)
  WHERE type(r1) = 'CAN_OBTAIN' OR r1.advances
WITH seed, collect(DISTINCT a) AS h1
UNWIND h1 AS a
OPTIONAL MATCH (a)-[r2]->(b)
  WHERE type(r2) = 'CAN_OBTAIN' OR r2.advances
WITH seed, h1, collect(DISTINCT b) AS h2
UNWIND (CASE WHEN size(h2) = 0 THEN [null] ELSE h2 END) AS b
OPTIONAL MATCH (b)-[r3]->(c)
  WHERE type(r3) = 'CAN_OBTAIN' OR r3.advances
WITH [seed] + h1 + h2 + collect(DISTINCT c) AS pool
WITH [x IN pool WHERE x IS NOT NULL] AS inside
UNWIND inside AS s
MATCH (s)-[r]->(t)
WHERE t IN inside AND (type(r) = 'CAN_OBTAIN' OR r.advances)
WITH s, t, head(collect(r)) AS r
RETURN s, r, t;
// combined 기대: 노드 60, CAN_OBTAIN 9, 전이(advances) 대표 엣지 58
// ※ 이 데이터에서는 도달이 전부 h1 이다 — AKIA 가 모든 리소스를 직접 건드렸고
//   CAN_OBTAIN 이 두 홉을 접었기 때문이다. 깊이 3 순회는 다른 데이터셋 대비다.

// ── V1-Q3 : 자격증명 사이의 '가능성' 전체 (그래프) ────────────────────────
// 리소스를 걷어내고 "어느 키에서 어느 키로 갈 수 있는가"만 남긴다.
// ★ 원래 권한이 큰 주체(인스턴스를 만든 관리자 키)에서 부채꼴이 나오는 게 정상이다.
//   자기가 만든 워크로드의 자격증명을 얻을 수 있는 건 당연하기 때문이다.
//   이 그림은 '공격'이 아니라 '권한 구조'를 보여준다.
MATCH (a:Credential)-[r:CAN_OBTAIN]->(b:Credential)
RETURN a, r, b;

// ── V1-Q3b : 그중 실제로 행사된 흔적이 있는 것만 (그래프) ★ ───────────────
// 부채꼴에서 증거가 있는 것만 남긴다. 얻을 수 있었던 주체의 IP 와 그 키가
// 실제로 쓰인 IP 가 겹치는 경우다. combined 에서 9개 중 1개만 남고,
// 그게 ground truth 다. 경유한 워크로드까지 같이 그려 근거를 보인다.
MATCH (a:Credential)-[r:CAN_OBTAIN {exercised: true}]->(b:Credential)
OPTIONAL MATCH (b)-[ro:CONTEXT {rel:'RUNS_ON'}]->(w:Node)
RETURN a, r, b, ro, w;

// ── V1-Q3c : 행사 흔적이 없는 나머지 (그래프) — 대조군 ────────────────────
// 이쪽이 8개다. 대상 키가 인스턴스 자신의 IP 에서만 쓰였다는 뜻이라,
// "얻을 수 있었지만 얻은 흔적은 없다" 로 읽는다.
MATCH (a:Credential)-[r:CAN_OBTAIN {exercised: false}]->(b:Credential)
RETURN a, r, b;

// ── V1-Q4 : 노출만 되고 통제되지 않은 자산 (그래프) ───────────────────────
// 영향 범위 안에서 '읽히기만 한' 것들. 잎으로 둔 판단이 무엇을 잘라냈는지 보인다.
MATCH (seed:Node {id: 'AKIA52CDAKM4W5UHPSX2'})-[r1]->(a)
  WHERE type(r1) = 'CAN_OBTAIN' OR r1.advances
WITH seed, collect(DISTINCT a) AS h1
WITH [seed] + h1 AS inside
UNWIND inside AS s
MATCH (s)-[r:BASE_EVENT]->(leaf)
WHERE NOT leaf IN inside AND r.readOnly = true AND r.outcome = 'SUCCESS' AND r.dstAs <> 'Service'
WITH s, leaf, head(collect(r)) AS r
RETURN s, r, leaf;


// ═══════════════════════════════════════════════════════════════════════════
//  ┃ 뷰 2 — 유입 경로 (upstream)
//  ┃ "이 자격증명을 어떻게 훔치게 됐나"
//  ┃
//  ┃ 파라미터가 둘 필요하다: 시드 + 기준 시각.
//  ┃ 상한이 없으면 사후 정리 작업까지 딸려 온다.
//  ┃
//  ┃ ★ 기준 시각의 의미에 주의. CAN_OBTAIN 의 `at` 은 '장악한 시각'이고
//  ┃   CONTEXT 의 firstSeen 은 '관계가 성립한 시각'이 아니라 '처음 관측된
//  ┃   시각'이다. RUNS_ON 은 그 키가 처음 쓰일 때 로그에 나타나므로,
//  ┃   상한을 1초만 앞당겨도 상류가 통째로 날아가는 구간이 있다.
// ═══════════════════════════════════════════════════════════════════════════

// ── V2-Q1 : 시간 상한을 건 상류 추적 (그래프) ─────────────────────────────
// 방향을 거꾸로 탄다. cutoff 는 보통 '시드가 처음 이상하게 쓰인 시각'으로 잡는다.
// 발급 시각으로 잡으면 탈취 행위가 잘리고, 상한을 안 걸면 사후 작업이 섞인다.
MATCH (seed:Node {id: 'ASIA52CDAKM456D2HKTH'})
MATCH (u1)-[r1]->(seed)
  WHERE (type(r1) = 'CAN_OBTAIN' AND r1.at <= datetime('2026-08-21T07:24:01Z'))
     OR (r1.advances   AND r1.eventTime <= datetime('2026-08-21T07:24:01Z'))
WITH seed, collect(DISTINCT u1) AS up1
UNWIND up1 AS u1
OPTIONAL MATCH (u2)-[r2]->(u1)
  WHERE (type(r2) = 'CAN_OBTAIN' AND r2.at <= datetime('2026-08-21T07:24:01Z'))
     OR (r2.advances   AND r2.eventTime <= datetime('2026-08-21T07:24:01Z'))
WITH [seed] + up1 + collect(DISTINCT u2) AS pool
WITH [x IN pool WHERE x IS NOT NULL] AS inside
UNWIND inside AS s
MATCH (s)-[r]->(t)
WHERE t IN inside
  AND ((type(r) = 'CAN_OBTAIN' AND r.at <= datetime('2026-08-21T07:24:01Z'))
    OR (r.advances   AND r.eventTime <= datetime('2026-08-21T07:24:01Z')))
WITH s, t, head(collect(r)) AS r
RETURN s, r, t;

// ── V2-Q2 : 경계 직전 창에서 일어난 모든 일 (그래프) ──────────────────────
// 상류 노드만 보면 '누가' 는 알아도 '무엇을 했는지' 가 안 보인다.
// 기준 시각 앞 60초를 통째로 그린다. 여기서 외부 IP 의 호출을 눈으로 찾는다.
// 실패 호출(ATTEMPT)도 포함한다 — 시도 자체가 단서다.
MATCH (a)-[r:BASE_EVENT]->(b)
WHERE r.eventTime <= datetime('2026-08-21T07:24:01Z')
  AND r.eventTime >= datetime('2026-08-21T07:23:01Z')
RETURN a, r, b;

// ── V2-Q3 : 출처 IP 별로 주체를 묶어 보기 (그래프) ────────────────────────
// 서비스 대리 호출(도메인)을 걷어내고 실제 IP 만 남긴다.
// 한 IP 에서 여러 자격증명이 쓰였는지, 한 자격증명이 여러 IP 에서 쓰였는지가
// 한눈에 보인다. 후자가 뷰 3 의 신호다.
MATCH (a:Credential)-[r:BASE_EVENT]->(b)
WHERE r.sourceIP <> '' AND NOT r.sourceIP ENDS WITH '.amazonaws.com'
WITH a, b, r ORDER BY r.eventTime
WITH a, b, head(collect(r)) AS r
RETURN a, r, b;


// ═══════════════════════════════════════════════════════════════════════════
//  ┃ 뷰 3 — 세션 신원 분열 (identity split)
//  ┃ "같은 신원에서 나온 자격증명들이 서로 다른 곳에서 쓰이고 있는가"
//  ┃
//  ┃ 도달성이 아니라 이상 징후를 본다. 그리고 3-Node v2 의 설계 판단 하나에
//  ┃ 직접 의존한다 — 주체 id 를 ARN 이 아니라 accessKeyId 로 잡은 것.
//  ┃ arn → accessKeyId 는 1:N 이라, ARN 을 PK 로 썼으면 키들이 한 노드로
//  ┃ 합쳐져 이 질문 자체가 성립하지 않는다.
//  ┃
//  ┃ ★ 이 뷰는 CAN_OBTAIN 도 advances 도 쓰지 않는다. 기반 관계만 읽는다.
//  ┃   즉 후처리 없이 쿼리만으로 성립하는 목적도 있다는 사례다.
// ═══════════════════════════════════════════════════════════════════════════

// ── V3-Q1 : 출처가 갈린 워크로드와 그 자격증명들 (그래프) ★ ───────────────
// STEP 4 가 찍어둔 `finding` 속성으로 고른다. 종류 색은 그대로 유지된다.
MATCH (k:Credential)-[r:CONTEXT {rel:'RUNS_ON'}]->(w:Workload)
WHERE w.finding = 'split-workload'
RETURN k, r, w;

// ── V3-Q2 : 그 키들이 실제로 무엇을 했나 (그래프) ─────────────────────────
// 분열이 확인된 키에서 나가는 호출을 붙여 본다. 인스턴스 자신의 IP 로 온 호출
// (SSM 에이전트)과 외부 IP 로 온 호출이 같은 워크로드에 매달린 게 보인다.
MATCH (k:Credential)-[r:BASE_EVENT]->(x)
WHERE k.finding = 'split-identity'
  AND r.sourceIP <> '' AND NOT r.sourceIP ENDS WITH '.amazonaws.com'
WITH k, x, head(collect(r)) AS r
RETURN k, r, x;

// ── V3-Q3 : role 단위 대조군 (그래프) ─────────────────────────────────────
// 같은 role 이 발급한 키들. 워크로드 단위(V3-Q1)와 비교하면 왜 RUNS_ON 이
// 더 나은 기준인지 보인다 — 공유 role 은 IP 가 갈리는 게 정상이라 오탐이 난다.
MATCH (role:Identity)-[r:CONTEXT {rel:'ISSUES'}]->(k:Credential)
WHERE role.resourceType = 'role' AND k.sourceIPs IS NOT NULL
RETURN role, r, k;


// ═══════════════════════════════════════════════════════════════════════════
//  ┃ 기반 층 점검용 (전부 그래프)
// ═══════════════════════════════════════════════════════════════════════════

// 주체이자 자산인 노드와 그 이웃 — 권한 체인이 통과하는 지점
MATCH (n:Actor:Resource)-[r]-(m) RETURN n, r, m;

// 삭제 행위 전수 — 서비스별 지식 없이 actionL2 하나로
MATCH (a)-[r:BASE_EVENT {actionL2:'DELETE'}]->(x) RETURN a, r, x;

// 권한 거부로 실패한 호출 — 권한 정찰의 신호. Stratus 에서는 0건이 정상이다
MATCH (a)-[r:BASE_EVENT]->(x) WHERE r.errorClass = 'DENIED'
WITH a, x, head(collect(r)) AS r RETURN a, r, x;

// 그 밖의 실패 (파라미터 오류·대상 없음) — errorCode 원문이 엣지에 실려 있다
MATCH (a)-[r:BASE_EVENT]->(x) WHERE r.outcome <> 'SUCCESS' AND r.errorClass <> 'DENIED'
WITH a, x, head(collect(r)) AS r RETURN a, r, x;

// 대상을 특정하지 못한 접근 — 이게 많으면 파서의 대상 추출에 구멍이 있다
MATCH (a)-[r:BASE_EVENT {dstAs:'Service'}]->(x)
WITH a, x, head(collect(r)) AS r RETURN a, r, x;


// ═══════════════════════════════════════════════════════════════════════════
//  ┃ 뷰 4 — 공격 기법 모티프 (attack motif)
//  ┃ "이 로그에 어떤 기법이 들어 있는가"
//  ┃
//  ┃ 설계 원칙: **기법을 API 이름 목록이 아니라 '부분그래프의 모양'으로 정의한다.**
//  ┃ eventName 목록으로 매칭하면 그건 탐지 룰이지 그래프가 필요 없고, Stratus 에
//  ┃ 없는 변종은 못 잡는다. 모양으로 정의하면 같은 목적을 다른 API 로 달성해도
//  ┃ 걸린다 — 실제로 아래 M1 과 M2 는 SendCommand 와 SendSSHPublicKey 라는
//  ┃ 서로 다른 API 인데 같은 모티프의 변형으로 잡힌다.
//  ┃
//  ┃ 세 기법은 공통 뼈대를 공유한다.
//  ┃   공통  외부 주체가 '자기가 실려 있지 않은' 워크로드에 실행·접근을 주입
//  ┃   M1    그 뒤 그 워크로드의 자격증명이 주입한 주체와 같은 IP 에서 쓰임 → 탈취
//  ┃   M2    주입이 여러 워크로드로 퍼짐, 자격증명 재사용은 없음      → 측면 이동
//  ┃   M3    저장 자산이 만들어지고 권한이 바뀐 뒤 곧 지워짐          → 유출
// ═══════════════════════════════════════════════════════════════════════════

// ── M1 : 자격증명 탈취 (T1552.005) ────────────────────────────────────────
// 모양만으로 정의된다. API 이름이 한 번도 안 나온다.
//   (주체)-[CONTROL]->(워크로드) + (자격증명)-[RUNS_ON]->(같은 워크로드)
//   + 주체와 그 자격증명의 출처 IP 가 겹침
// combined 기대: 1건 (AKIA…W5UHPSX2 → ASIA…6D2HKTH, 인스턴스 i-06d1d3…)
// ★ 대표 엣지를 아무거나 고르면 안 된다. 이 도둑은 같은 인스턴스에 CONTROL 을
//   7번 남겼다 — RunInstances 2, SendCommand 2, ModifyInstanceAttribute 1,
//   TerminateInstances 2. head(collect(e)) 로 아무거나 뽑으면 화면이
//   "도둑이 인스턴스를 종료했다" 같은 엉뚱한 이야기를 할 수 있다.
//   **훔친 키가 처음 쓰이기 직전의 마지막 CONTROL** 을 고른다. 인과적으로
//   가장 가까운 행위이고, 검증 데이터에서는 SendCommand(07:23:56)가 나온다.
MATCH (thief:Credential)-[r:CAN_OBTAIN {exercised: true}]->(stolen:Credential)
MATCH (stolen)-[ro:CONTEXT {rel: 'RUNS_ON'}]->(w:Workload)
MATCH (stolen)-[u:BASE_EVENT]->()
WITH thief, r, stolen, ro, w, min(u.eventTime) AS firstUse
MATCH (thief)-[e:BASE_EVENT {advances: true}]->(w)
WHERE e.eventTime <= firstUse
WITH thief, r, stolen, ro, w, e ORDER BY e.eventTime DESC
WITH thief, r, stolen, ro, w, head(collect(e)) AS e
RETURN thief, r, stolen, ro, w, e;

// ── M1-b : 같은 사건의 전체 맥락 (그래프) ─────────────────────────────────
// M1 은 결론만 보여준다. 왜 그 결론인지 보려면 대조군이 필요하다.
// 같은 인스턴스에 실린 키 3개를 전부 그리고, 도둑의 CONTROL 을 하나도 안 빼고
// 그린다. 그러면 이렇게 읽힌다.
//   · 도둑 → 인스턴스 : RunInstances → SendCommand → Modify → Terminate (7개)
//   · 인스턴스에 실린 키 3개 중 CAN_OBTAIN 이 굵은(exercised) 것은 하나뿐
//   · 나머지 2개는 같은 조건인데 IP 가 안 겹쳐서 흔적이 없다
// combined 기대: 노드 7 (도둑 1 + 인스턴스 1 + 키 3 + role 2)
//                CONTROL 7 / RUNS_ON 3 / ISSUES 3 / CAN_OBTAIN 3
MATCH (thief:Credential)-[r:CAN_OBTAIN]->(cred:Credential)
MATCH (cred)-[ro:CONTEXT {rel: 'RUNS_ON'}]->(w:Workload)
WHERE w.finding = 'split-workload'
MATCH (thief)-[e:BASE_EVENT {advances: true}]->(w)
OPTIONAL MATCH (role:Identity)-[iss:CONTEXT {rel: 'ISSUES'}]->(cred)
RETURN thief, r, cred, ro, w, e, role, iss;

// ── M2 : 측면 이동 — 워크로드로의 실행·접근 주입 ──────────────────────────
// eventSource 로 정의한다. API 이름이 아니라 '그 서비스의 존재 목적'이 기준이다.
// ssm / ec2-instance-connect 는 인스턴스 안으로 명령이나 접근을 밀어넣는 게
// 전부인 서비스다. 목록이 짧고 잘 안 변한다.
//   + 자기가 실려 있는 워크로드는 제외 (에이전트의 자기 보고를 걸러낸다)
// combined 기대: SendSSHPublicKey 3개 워크로드 + SendCommand 1개 워크로드.
// 한 주체에서 워크로드로 부채꼴이 크게 벌어지면 측면 이동이다.
MATCH (a:Credential)-[e:BASE_EVENT {advances: true}]->(w:Workload)
WHERE e.eventSource IN ['ssm.amazonaws.com', 'ec2-instance-connect.amazonaws.com',
                        'ssmmessages.amazonaws.com', 'ec2messages.amazonaws.com']
  AND NOT (a)-[:CONTEXT {rel: 'RUNS_ON'}]->(w)
WITH a, w, head(collect(e)) AS e
RETURN a, e, w;

// ── M3 : 유출 — 저장 자산의 짧은 생애주기 + 권한 변경 ─────────────────────
// actionL2 만으로 모양을 잡는다. 같은 저장 자산이 CREATE → MODIFY → DELETE 를
// 다 받았다면, 만들어서 권한을 열고 곧 지운 것이다. 흔적을 남기지 않으려는 형태다.
//
// ★ resourceType 을 저장 계열로 좁히는 이유: 좁히지 않으면 combined 에서 10건이
//   나오고 대부분 Terraform 의 인프라 생성·철거다(VPC, IGW, 인스턴스). Stratus 가
//   환경을 만들고 부수기 때문에 생애주기가 짧은 게 기본값이라 그렇다.
//   저장 계열로 좁히면 1건만 남고 그게 유출 대상 스냅샷이다.
//
// ★ 한계: 어느 계정으로 공유했는지는 그래프에 없다. ModifySnapshotAttribute 의
//   createVolumePermission.add.items[].userId(외부 계정 12자리)를 파서가 수집하지
//   않기 때문이다. 즉 "권한을 열었다"까지만 보이고 "누구에게"는 안 보인다.
// combined 기대: 1건 (snapshot/snap-0e3bac79ac432d549, 06:30:15 ~ 06:32:09)
MATCH (a:Credential)-[e:BASE_EVENT {advances: true}]->(x:Asset)
WHERE x.resourceType IN ['snapshot', 'volume', 'image', 'bucket', 'object']
WITH a, x, collect(DISTINCT e.actionL2) AS acts, collect(e) AS es
WHERE 'CREATE' IN acts AND 'MODIFY' IN acts AND 'DELETE' IN acts
UNWIND es AS e
RETURN a, e, x;

// ── M0 : 세 기법의 공통 뼈대만 (그래프) ───────────────────────────────────
// "외부 주체가 남의 워크로드·자산을 건드렸다" 까지만 본다. 여기서 가지가 갈린다.
// 화면에서 주체 하나에 워크로드 4개와 스냅샷 1개가 매달린 모양이 나온다.
MATCH (a:Credential)-[e:BASE_EVENT {advances: true}]->(t)
WHERE (t:Workload OR t.resourceType IN ['snapshot', 'volume'])
  AND NOT (a)-[:CONTEXT {rel: 'RUNS_ON'}]->(t)
WITH a, t, head(collect(e)) AS e
RETURN a, e, t;
