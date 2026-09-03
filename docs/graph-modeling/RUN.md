# RUN — CloudTrail JSON 로그를 그래프로 (A to Z)

**아무 CloudTrail JSON 로그 하나가 주어졌을 때, 그것을 그래프로 변환해 Neo4j 에
적재하고 눈으로 보기까지의 전체 절차.** 특정 로그에 종속되지 않는다 — 아래에서
`<LOG>` 자리에 파일 경로만 바꾸면 어떤 로그든 그대로 따라 하면 된다.

- 환경: Windows + Docker Desktop + PowerShell
- 컨테이너 이름: `cloudtrail-graph-3node-v2` · 계정: `neo4j` / `cloudtrail123`
- 전제 파일: `parser_node3_v2.py`, `load_3node_v2.cypher`, `enrich_views.cypher`,
  `docker-compose.yml`, `browser-style.grass` (여러 로그 합칠 때 `merge_logs.py`)
  가 이 폴더에 있어야 한다.

> **파이프라인 한눈에**
> ```
> <LOG>.json ──파서──▶ csv/<name>/{nodes,edges,context}.csv ──복사──▶ import/
>            ──load_3node_v2.cypher──▶ 기반 그래프 ──enrich_views.cypher──▶ 뷰
> ```

---

## STEP 0. 컨테이너 준비 (최초 1회 / 껐다 켤 때)

```powershell
cd "C:\google_drive\cloud research\ct_graph_v2"
docker compose up -d
docker compose ps          # STATUS 가 healthy 될 때까지 대기 (보통 30~60초)
```

<http://localhost:7474> 접속 → `neo4j` / `cloudtrail123` 로 로그인되면 준비 완료.

> `import/` 마운트에 `:ro` 를 붙이면 안 된다 — neo4j 엔트리포인트의 chown 이
> 실패해 컨테이너가 `Exited (1)` 로 죽는다. `docker-compose.yml` 은 이미 안 붙어 있다.

---

## STEP 1. 로그 → CSV (파싱)

**여기서 먼저 정한다 — 로그를 하나만 올릴지, 여러 개를 한 그래프로 합칠지.**
합칠지 여부는 파싱하기 *전에* 정해야 한다. 그래프에 합치는 일은 CSV 가 아니라
JSON 단계에서 일어나기 때문이다(같은 자산이 여러 로그에 나오면 한 노드로 합쳐져야
하는데, CSV 를 이어붙이면 그 병합이 안 된다).

### 1-A. 로그 하나만 (기본)

```powershell
# <LOG> 와 <name> 만 바꾼다. <name> 은 이 로그를 부를 짧은 이름(폴더명이 됨).
python parser_node3_v2.py "<LOG>.json" -o .\csv\<name>
```

예시 — 체인 로그 하나를 변환:

```powershell
python parser_node3_v2.py "..\stratus-red-team\log_json\aws.5_chain_n1.json" -o .\csv\chain_n1
```

### 1-B. 여러 로그를 한 그래프로 (합치기)

여러 로그를 한 그래프에 넣어 비교하고 싶을 때만. `merge_logs.py` 가 원본 JSON 의
`Records` 배열을 하나로 합치고 `eventID` 중복까지 제거한다. 그다음 **합친 파일을
한 번** 파싱한다.

```powershell
# 폴더 안의 모든 json 을 하나로 (또는:  a.json b.json c.json  처럼 골라서)
python merge_logs.py -o combined_src.json "..\stratus-red-team\log_json\*.json"
python parser_node3_v2.py combined_src.json -o .\csv\combined
```

> PowerShell 은 `*` 를 자동으로 풀어주지 않지만 `merge_logs.py` 가 안에서 편다.
> `"...\*.json"` 을 따옴표로 감싸 그대로 넘기면 된다.

---

1-A 든 1-B 든 결과는 같다 — `csv\<name>\` 에 `nodes.csv` / `edges.csv` /
`context.csv` 세 파일. 파서가 출력하는 요약(노드·엣지 수, Service 수렴 %,
OBTAINS/RUNS_ON 개수)을 눈으로 확인한다. **Service 수렴 %가 비정상적으로
높으면**(예: 50%+) 그 로그에 파서가 대상을 못 찾는 API 가 많다는 뜻이니 STEP 5 로.

### (선택) 필드 정확성 검증

```powershell
python ".\verifying script\verify_fields_v2.py" "<LOG>.json" .\csv\<name>
```

26개 검사. 종료 코드 0(`FAIL 0`)이면 파싱이 원본과 일치한다. 새 유형의 로그를
처음 넣을 때 특히 돌려볼 것 — 파서가 조용히 놓친 걸 여기서 잡는다.

---

## STEP 2. CSV → import 폴더

Neo4j 는 `import/` 안의 `nodes.csv`/`edges.csv`/`context.csv` **딱 세 파일**만
읽는다. 한 번에 한 그래프만 올라가므로, 올릴 CSV 를 이 폴더로 복사한다.

```powershell
Remove-Item .\import\*.csv -ErrorAction SilentlyContinue
Copy-Item .\csv\<name>\*.csv .\import\
```

> STEP 1 에서 1-A 를 했든 1-B(합치기)를 했든, 여기서는 그때 만든 `csv\<name>\`
> (합쳤다면 `csv\combined\`)를 그대로 복사하기만 한다. **CSV 를 여기서
> 이어붙이지 않는다** — 로그를 합치는 일은 이미 STEP 1-B 에서 JSON 단계에 끝냈다.

---

## STEP 3. 기반 그래프 적재

**PowerShell 은 `<` 리다이렉션을 지원하지 않는다.** 파일을 컨테이너에 복사해
`-f` 로 실행하는 게 인코딩까지 안전하다(파이프 방식은 한글·특수문자에서 깨질 수 있음).

```powershell
docker cp .\load_3node_v2.cypher cloudtrail-graph-3node-v2:/tmp/load.cypher
docker exec -i cloudtrail-graph-3node-v2 cypher-shell -u neo4j -p cloudtrail123 --format plain -f /tmp/load.cypher
```

이 스크립트가 하는 일: 기존 그래프 초기화(STEP 0 의 `DETACH DELETE`) → 제약·인덱스
생성 → 빈 문자열 제거 → 노드 적재 후 라벨 물질화 → `BASE_EVENT`·`CONTEXT` 적재 →
**적재 검증**.

### 반드시 확인 — 마지막 검증 출력

```
item        csvN  dbN  status
Node          ..   ..  OK
BASE_EVENT   ..   ..  OK
CONTEXT       ..   ..  OK
unlabeled      0       OK
orphan         0       OK
```

`csvN`(CSV 행수)과 `dbN`(그래프 개수)이 같아 전부 `OK` 여야 한다. 하나라도
`MISMATCH` 면 **관계가 조용히 사라진 것**이다(관계 적재는 양끝 노드를 못 찾으면
예외 없이 행을 건너뛴다). 그 경우 STEP 5 참고.

> **기대값은 로그마다 다르다.** 파서 STEP 1 이 출력한 노드·엣지 수와
> `csvN` 이 일치하는지만 보면 된다.

---

## STEP 4. 목적별 뷰 얹기

```powershell
docker cp .\enrich_views.cypher cloudtrail-graph-3node-v2:/tmp/enrich.cypher
docker exec -i cloudtrail-graph-3node-v2 cypher-shell -u neo4j -p cloudtrail123 --format plain -f /tmp/enrich.cypher
```

기반 위에 종류 라벨(`:Credential`/`:Identity`/`:Workload`/`:Asset`), `impact` 속성,
합성 관계 `:CAN_OBTAIN`, 신원 분열 표시(`finding`)를 얹는다. 상세는 `enrich.md`.

끝에 뜨는 요약 표(`impact` 분포, `CAN_OBTAIN` 개수, 종류 라벨 분포)로 정상 적용을
확인한다. 파이썬 재현값과 대조하려면:

```powershell
python ".\verifying script\simulate_views.py" .\csv\<name>
```

---

## STEP 5. 그래프 보기

`cypher-shell` 은 텍스트만 뱉는다. 그래프는 <http://localhost:7474> Browser 에서 본다.

**색 입히기 (둘 중 하나)**

- **grass 파일**: 명령창에 `:style` 실행 → 결과 프레임의 **Upload** 버튼으로
  `browser-style.grass` 선택. (끌어다 놓기는 안 됨)
- **범례에서 직접**: 그래프 위쪽 라벨 칩(`Credential` 등)을 클릭해 색·캡션 지정.
  종류 라벨이 4개뿐이라 네 번이면 끝. 캡션은 `display` 선택.

**질의**는 `query.md` 를 쓴다. 목적별(영향 범위·유입 경로·신원 분열·공격 모티프)로
정리돼 있다. Browser 는 **노드·관계를 반환할 때만** 그래프를 그린다
(`RETURN a, r, b`). 속성만 꺼내면(`RETURN n.name`) 표가 된다.

우선 전체 골격부터 보려면:

```cypher
// 자격증명 · 워크로드 · IAM 만 (Asset 은 수가 많아 뺌)
MATCH (a)-[r:BASE_EVENT]->(b)
WHERE (a:Credential OR a:Identity) AND (b:Credential OR b:Identity OR b:Workload)
RETURN a, r, b LIMIT 300;
```

> Browser 설정의 노드 표시 상한(`maxVizNodes`, 기본 1000)에 걸리면 잘려 보인다.

---

## 재실행 · 초기화

```powershell
# 다른 로그로 갈아끼우기: STEP 1~4 를 새 <LOG>/<name> 으로 다시
# 기반만 다시 (load 파일 STEP 0 의 DETACH DELETE 가 기존 그래프를 지움)
docker exec -i cloudtrail-graph-3node-v2 cypher-shell -u neo4j -p cloudtrail123 -f /tmp/load.cypher
# 뷰만 다시 (enrich STEP 0 이 뷰 층만 지움)
docker exec -i cloudtrail-graph-3node-v2 cypher-shell -u neo4j -p cloudtrail123 -f /tmp/enrich.cypher
```

`BASE_EVENT` 는 `MERGE` 가 아니라 `CREATE` 로 넣는다. **초기화 없이 load 를 두 번
돌리면 엣지가 정확히 두 배**가 된다. STEP 3 을 다시 돌리면 앞의 `DETACH DELETE`
가 알아서 지우니 문제없지만, 수동으로 `LOAD CSV` 만 재실행하지는 말 것.

---

## 자주 걸리는 것

| 증상 | 원인 · 해결 |
| :--- | :--- |
| 컨테이너가 `Exited (1)`, 로그에 `chown: … Read-only file system` | `import` 마운트에 `:ro` 를 붙였다. 떼기 |
| `docker exec` 이 `No such container` | 컨테이너 이름 확인 (`docker compose ps`). 이 가이드는 `cloudtrail-graph-3node-v2` |
| `Could not find command :auto` | `:auto` 는 Neo4j 4.x 명령. 5.x 엔 없고 필요도 없음 |
| `Couldn't load the external resource … file:///nodes.csv` | `import/` 에 CSV 3개를 안 넣었거나 파일명이 다름 (STEP 2) |
| `Unknown function 'apoc.map.clean'` | APOC 플러그인 미탑재. `docker compose logs neo4j` 확인 |
| STEP 3 검증이 `MISMATCH` | 엣지 양끝 노드가 nodes.csv 에 없다. 파서 출력 재확인, `verify_fields_v2.py` 로 진단 |
| 엣지 수가 정확히 2배 | 초기화 없이 load 를 두 번 돌림. STEP 3 재실행(앞의 DETACH DELETE 가 정리) |
| Service 수렴 %가 매우 높다 | 그 로그에 파서가 대상을 못 찾는 API 가 많다. `verify_fields_v2.py` 의 refPath 검사로 확인 후 파서 화이트리스트 보강 |
| Browser 에 표만 나온다 | 속성을 반환 중. `RETURN a, r, b` 로 |
| 노드가 전부 같은 색 | grass 미적용 또는 enrich 미실행. STEP 4 → STEP 5 순서 확인 |
| `Get-Content` 파이프에서 1행 syntax error | 인코딩 문제. 이 가이드처럼 `docker cp` + `-f` 방식을 쓸 것 |
