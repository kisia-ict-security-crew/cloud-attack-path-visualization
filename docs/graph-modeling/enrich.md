# enrich — 뷰 계층 후처리

`enrich_views.cypher` 가 기반 그래프 위에 하는 일을 설명한다. 기반(`3-node-v2.md`)
에는 판단이 없다. **목적성은 전부 이 후처리에 있다.**

뷰 계층이 그래프에 손대는 방식은 **두 가지뿐**이다.

| 방식 | 무엇을 하나 | 새 노드/엣지 생성 |
| :--- | :--- | :---: |
| **(A) 분류** | 이미 있는 것에 표시를 단다 (라벨·속성) | 없음 |
| **(B) 합성** | 기반에 **없는** 관계를 새로 잇는다 | `:CAN_OBTAIN` 하나 |

기반 엣지(`:BASE_EVENT`, `:CONTEXT`)와 기반 라벨(`:Node`/`:Actor`/`:Resource`/
`:Service`)은 **절대 수정하지 않는다.** 뷰가 마음에 안 들면 STEP 0 으로 지우고
다시 만든다.

---

## STEP 1 — 노드 종류 라벨 (분류)

기반의 `:Actor`/`:Resource`/`:Service` 는 '역할'이지 '종류'가 아니다. role 도
인스턴스도 VPC 도 전부 `:Resource` 라 화면·질의에서 구분이 안 된다. 이미 저장된
`kind`/`resourceType` 을 **종류 라벨로 승격**시킨다(새 정보를 만드는 게 아니라
있는 걸 다시 표시).

분류 기준은 "AWS 가 뭐라 부르는가"가 아니라 **"이 그래프에서 무슨 역할을 하는가"**
다. 그래서 서비스별 종류(bucket/vpc/snapshot…)로 쪼개지 않는다 — 그건 이미
`resourceType` 속성에 있다.

| 라벨 | 뜻 | 판정 기준 | combined |
| :--- | :--- | :--- | ---: |
| `:Credential` | 행위의 출발점 | `kind` ∈ {LongTermKey, TempKey, Service, Anonymous} | 34 |
| `:Identity` | 권한을 정의하는 IAM 객체 (Actor 이자 Resource) | `resourceType` ∈ {role, instance-profile, iam-user, iam-policy} | 12 |
| `:Workload` | 자격증명이 실리는 곳 (CAN_OBTAIN 경유지) | `resourceType` ∈ {instance, launch-template} | 4 |
| `:Asset` | 나머지 대상 전부 (네트워크·저장소·감사로그·서비스폴백) | 위 어디에도 안 걸림 | 73 |

**노드 하나에 정확히 하나만 붙는다.** 여러 개가 붙으면 Browser 가 색을 못 정한다.
`:Identity` 를 가장 먼저 잡아 role 이 우선하게 하고, 나머지를 순서대로 채운다.

같이 `display` 캡션도 단다(자격증명은 키 뒤 8자리, IAM 은 name).

---

## STEP 2 — 엣지 분류: `advances` 마커

기존 `:BASE_EVENT` 에 **"이 호출이 공격자를 전진시키는가"**를 불리언 하나로 단다.
새 엣지를 만들지 않는다. 공격 경로 순회가 따라갈 엣지를 고르는 술어다.

| `advances` | 뜻 | 판정 |
| :--- | :--- | :--- |
| `true` | 자격증명 획득 또는 상태 변경 → 영향·권한이 전이된다 | `outcome=SUCCESS` ∧ `dstAs≠Service` ∧ (`rel=OBTAINS` 또는 `readOnly=false`) |
| `false` | 읽기(노출)·실패·대상미특정 → 순회의 잎 | 위에 안 걸리는 나머지 |

**`readOnly` 하나로 전이/조회가 갈리므로 서비스별 지식이 필요 없다.** 400개
서비스의 수천 API 에 그대로 확장된다. (combined: `advances` true 316 / false 566)

이전엔 5버킷(CONTROL/OBSERVE/DENIED_ATTEMPT/ATTEMPT/UNRESOLVED)이었으나, 도달성에
필요한 건 **'전이 여부' 하나뿐**이라 불리언으로 줄였다. 나머지 구분은 뷰에 중복
저장하지 않고 필요할 때 base 속성으로 뽑는다 — 노출 `readOnly=true`, 권한 정찰
`errorClass=DENIED`, 대상미특정 `dstAs=Service` (질의는 `query.md`).

---

## STEP 2b — 주체별 출처 IP 집합

각 `:Actor` 에 그 주체가 쓴 실제 IP 목록을 `sourceIPs` 로 얹는다. 서비스 대리
호출(`*.amazonaws.com` 도메인)은 IP 가 아니므로 제외한다. STEP 3b·STEP 4 가 쓴다.

---

## STEP 3 — 합성 관계 `:CAN_OBTAIN` (합성)

**"이 주체가 저 자격증명을 손에 넣을 수 있다."** 기반에 없는 유일한 새 엣지다.

```
(주체)-[BASE_EVENT {advances:true}]->(워크로드)     워크로드를 장악했다
(자격증명)-[CONTEXT {rel:RUNS_ON}]->(같은 워크로드)   그 키가 거기 실려 있다
  ⇒ (주체)-[CAN_OBTAIN]->(자격증명)
```

두 홉을 한 엣지로 접은 것이다. **이 쌍 사이에는 기반 엣지가 없다** — 공격자가
탈취한 키를 *호출한* 기록은 남지만 *훔친* 기록은 로그에 없기 때문이다. 탈취 행위
자체가 CloudTrail 에 존재하지 않는 것이 이 연구의 출발점이고, 이 엣지가 그 빈칸을
명시적 추론으로 채운다. (combined 에서 이 9개 쌍 중 기반 `BASE_EVENT` 가 이미
있는 쌍은 0개 — 복제가 아니다.)

**같은 워크로드에 실린 키끼리는 제외한다.** 인스턴스에 실린 키는 그 인스턴스에
전이(advances) 엣지를 남기게 마련이라(SSM 에이전트의 자기 보고 등), 그대로 두면 같은
인스턴스 키들이 서로를 향해 쌍방향으로 붙는다. 같은 워크로드 안은 이미 같은
신뢰 경계라 '획득'이라 부를 게 없다.

추론이므로 근거를 싣는다 — `viaWorkloads`(경유 워크로드), `at`(장악 시각),
`controlEvents`(근거 이벤트 수).

### STEP 3b — `exercised` 표시

`:CAN_OBTAIN` 은 '가능성'이지 '행위'가 아니다. 원래 권한이 큰 주체(인스턴스를
만든 관리자 키 등)에서는 부채꼴로 퍼지는 게 정상이다. 그중 **실제로 행사된
흔적**을 골라내려면 증거가 하나 더 필요하다 — 얻을 수 있었던 주체의 IP 와 그
자격증명이 실제 쓰인 IP 가 겹치는가.

`exercised=true` 면 그 키가 주체의 단말에서 쓰였다는 뜻이다. combined 에서
`CAN_OBTAIN` 9개 중 `exercised` 는 1개뿐이고, 그게 ground truth 다.

> 한계: 공격자가 훔친 키를 다른 단말·프록시에서 쓰면 IP 가 안 겹친다. 즉
> `exercised=false` 가 "탈취 없음"을 뜻하지는 않는다. 증거가 있는 것을 고르는
> 필터지 없는 것을 배제하는 필터가 아니다.

---

## STEP 4 — 판정은 라벨이 아니라 속성으로

세션 신원 분열(같은 워크로드에 실린 키들이 서로 다른 출처 IP 에서 쓰임)을 노드에
`finding` 속성으로 남긴다.

- `finding='split-workload'` — 출처가 갈린 워크로드
- `finding='split-identity'` — 거기 실린 자격증명들

**종류는 라벨(색), 판정은 속성(질의).** 둘을 섞으면 종류 구분이 죽는다. 질의는
`WHERE n.finding = 'split-workload'` 로 한다.

---

## 관계 타입이 어디에 정의되는가

| 관계/속성 | 계층 | 정의 위치 |
| :--- | :--- | :--- |
| `:BASE_EVENT`, `:CONTEXT` | 기반 | 파서 → CSV (`3-node-v2.md`) |
| 종류 라벨, `advances`, `sourceIPs`, `finding` | 뷰 | `enrich_views.cypher` STEP 1·2·2b·4 |
| `:CAN_OBTAIN` (+`exercised`) | 뷰 | `enrich_views.cypher` STEP 3·3b |

뷰 계층 산출물은 STEP 0 을 돌리면 전부 사라지고, 기반은 그대로 남는다.
목적별 뷰 질의(영향 범위·유입 경로·신원 분열·공격 모티프)는 `query.md` 참조.
