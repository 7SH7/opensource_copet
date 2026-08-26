# forensicagent

[보안 정책](SECURITY.md) · [기여 안내](CONTRIBUTING.md) ·
[외부 구성요소 고지](THIRD_PARTY_NOTICES.md)

> 포렌식 자동 분류 CLI 에이전트 — 결정론 Scanner가 증거를 식별하고,
> 형식 gate와 선택적 RAG/로컬 LLM이 도구 순서를 보강한다. 외부 도구 결과는
> 근거 기반 규칙으로 의심 항목을 추출해 JSON/Markdown 리포트로 제시한다.

아래 화면은 출력 형식을 보여주는 예시이며, 실제 도구 수와 실행 plugin은 증거,
대상 OS, scenario, 설치 상태에 따라 달라진다.

```
$ cd ~/ctf/forensics-challenge-03/
$ forensicagent

[*] 작업 디렉토리: ~/ctf/forensics-challenge-03/
[*] 증거 스캔 중...
[+] 발견: memory.raw (메모리 덤프, 1.2 GiB)
[+] 발견: Security.evtx (Windows 이벤트 로그)
[+] 발견: NTUSER.DAT (레지스트리 하이브)

[*] 적용 가능한 도구 선별됨:
    1. volatility3 (Windows pslist, cmdline, netscan, malfind, pstree)
    2. chainsaw (채널별 Event ID search)
    3. regripper (userassist, run keys)
    ...
계속 진행할까요? [Y/n] y

[*] [1/N] volatility3 pslist 실행 중... ✓ (12.3s)
    └─ 의심항목 2 개 발견
...

[chainsaw] 의심항목 5건
  - 비업무시간 RDP 로그온 (이벤트 4624 Type 10), 외부 IP 185.x.x.x
  - PowerShell 인코딩된 명령 실행 (이벤트 4104)
  ...
```

---

## 목적과 비목적

**해결하려는 문제.** 포렌식 분석가가 50+ 개 도구를 머리에 외워두고 매번
직접 결정 (어떤 증거에 어떤 도구를) 하는 것은 비효율이고, 신입에게는 진입
장벽이다. 동시에 "전부 다 돌리기" 도 분명 낭비 (메모리 덤프에 RegRipper
를 돌릴 필요는 없다).

**우리가 푸는 좁은 문제.** CWD 디렉토리만 보고 → 어떤 도구를 → 어떤 증거에
→ 어떤 순서로 돌릴지 결정하고, 도구 출력에서 **알려진 의심 패턴** 만 자동
으로 뽑아 리포트로 묶는 **triage** 단계.

**의도적으로 안 하는 것.**
- 전체 사건의 인과관계 자동 재구성 또는 무제한 원본 이벤트 보관
  (시간이 있는 아티팩트의 정규화된 bounded preview와 finding 타임라인은 제공)
- 새로운 익스플로잇/악성코드 탐지 (알려진 패턴만)
- 증거 획득·서명·WORM 보관까지 포함하는 완전한 chain of custody
  (포함 증거 SHA-256/크기/mtime manifest와 실행 provenance는 제공)
- Sigma/YARA 오프라인 규칙팩 버전 관리자와 STIX/CSV/Timesketch 외부 export
- 실시간 모니터링 (사후 분석 전용)

---

## 어떤 흐름으로 만들었나

전체 사이클을 5 단계로 쪼개고, 각 단계가 다음 단계에 dict 한 묶음만 넘기는
**순수 함수 + 데이터클래스** 구조로 만들었다. 그래서 어느 단계든 stub 으로
교체해도 다른 단계의 코드가 깨지지 않는다 (테스트/오프라인 개발 가능).

```
Scanner → Selector → (사용자 승인) → Executor → Analyzer → Reporter
   ↑                                                            ↓
   └────────────── observability (Stopwatch / stage_ms) ────────┘
```

| 단계 | 책임 | 디렉토리 |
|---|---|---|
| **Scanner** | CWD의 파일을 magic bytes + 확장자 + 파일명 + 부모 디렉터리 힌트로 식별한다. 포함 증거는 SHA-256/크기/mtime을 기록하고, **1.5 GiB 이상은 hash 없이 경로·크기·제외 이유를 남긴 뒤 자동 제외**한다. 깊이 제한, unreadable path, symlink/junction/reparse skip도 coverage 상태로 기록한다. | `forensicagent/scanner/` |
| **Selector** | 3 단계 하이브리드. **Stage 1** = 결정론 매칭 (evidence_type ∩ applicable_evidence_types) — 실행 자격 게이트. **RAG** = 증거+시나리오로 도구 메타데이터 컬렉션을 벡터 검색해 후보를 관련도순 재정렬하고 도메인 스니펫을 프롬프트에 주입. **Stage 2** = LLM 에게 우선순위 + 보강된 reason 을 JSON 으로 요청. RAG 는 순서/컨텍스트에만 영향(자격 게이트는 불변), 의존성/질의 실패 시 결정론+LLM 경로로 자동 폴백. LLM 파싱 실패 시 Stage 1 결과 그대로 fallback. | `forensicagent/selector/` |
| **Executor** | artifact별 최고 우선순위 도구 하나만 소유하며 설치되지 않은 소유자를 다른 도구로 대체하지 않는다. `shell=False`, 격리 job dir, Windows Job Object/POSIX process group을 사용하고 timeout·취소·출력 상한을 구분한다. 정확한 입력/settings hash와 산출물 재검증이 일치할 때만 완료 작업을 재사용한다. | `forensicagent/executor/` |
| **Analyzer** | 출력 크기에 따라 Case A/B/C로 나누고 등록된 `suspicious_indicators.id` matcher만 실행한다. 실패·취소·상한 초과의 부분 산출물도 분석하되 coverage를 명시한다. 코드 보안 출력과 analyst notes는 LLM에 보내지 않는다. | `forensicagent/analyzer/` |
| **Reporter** | terminal + JSON + Markdown 동시 출력. finding 타임라인(UTC+원문 시각), artifact coverage ledger, 도구/rule/executable provenance, 비인과적 user/IP/process correlation, fingerprint 기반 analyst annotation을 보존한다. | `forensicagent/reporter/` |

### 왜 이렇게 쪼갰나

- **Scanner / Selector 분리**: "무엇이 있는가" 와 "무엇을 돌릴까" 는 다른
  결정이다. Selector 는 Scanner 결과 + 도구 메타데이터만 보면 되고, 파일
  시스템에 다시 접근하지 않는다.
- **Scanner 경계가 실행 경계**: Bandit·Semgrep·Gitleaks도 inventory에서
  host/evidence/input gate를 통과한 파일만 하나씩 받는다. 공통 VCS/dependency/cache/
  output 디렉터리는 정책상 제외하고, 신뢰된 `PROJECT_ROOT` 자체를 scan할 때만
  project-local runtime state를 제외한다.
  외부 증거 트리의 같은 이름은 scan한다. 깊이 밖·unreadable·reparse 경로는
  coverage로 알리며, 큰 소스 트리에서는 파일별 프로세스 비용이 커질 수 있다.
- **Selector 의 다단계**: 결정론 필터 단계가 현재 등록된 도구 중 증거에 맞는
  후보만 남겨주므로,
  LLM 컨텍스트가 작아지고 비용/속도가 보존된다. 그 사이에 RAG 가 도구
  메타데이터 코퍼스를 벡터 검색해 (i) 후보를 관련도순으로 재정렬하고
  (ii) 로컬 LLM 의 약한 포렌식 도메인 지식을 검색된 스니펫으로 보강한다.
  **RAG 는 절대 자격을 바꾸지 않는다** — Stage 1 을 통과한 도구의 순서와
  프롬프트 컨텍스트에만 영향을 준다. LLM 은 우선순위만 정한다 (도구를 직접
  호출하지 않으니 hallucinate 한 도구가 실행될 위험 없음).
- **RAG 는 옵션이자 폴백-안전**: chromadb / sentence-transformers / 임베딩
  모델 / 인덱스가 없으면 조용히 결정론+LLM 경로로 폴백한다. 즉 **RAG 가
  없어도 파이프라인은 항상 동작**하고, `--no-llm` 과도 독립적으로 조합된다.
  런타임 활성화는 도구 코퍼스 인덱싱 1 회가 전제: `forensicagent rag index-tools`.
- **Executor 의 어댑터 패턴**: 도구마다 출력 포맷이 다 다르므로, 새 도구를
  추가하는 비용 = YAML 1 개 작성 (혹은 어댑터 클래스 1 개) 수준이다.
- **Analyzer 의 Case A/B/C**: 로컬 LLM 의 컨텍스트 길이 제약을 코드 흐름에
  녹였다. Volatility pslist 같은 대용량 출력을 LLM 에 통째로 넣지 않는다.
- **Reporter 의 3 포맷 동시 출력**: 분석가의 워크플로우 — 터미널에서 보고,
  JSON 으로 후속 처리하고, Markdown 으로 보고서에 붙인다.

### 왜 로컬 LLM (Ollama) 인가

- 포렌식 증거는 외부 API 로 보내면 안 되는 경우가 많다 (사내 사고, 격리 랩).
- 도구별 의심 지표는 RAG (`suspicious_indicators` 섹션) 로 주입할 수 있어,
  도메인 지식 자체는 모델이 아닌 YAML 에 있다.
- 비용/속도/JSON 신뢰성 트레이드오프는 코드가 흡수한다 — `format="json"`,
  1 회 재시도, 그래도 실패하면 룰 fallback.

---

## 도구 메타데이터 (RAG 의 진실 원천)

각 도구는 `tools_metadata/<tool_id>.yaml` 한 파일로 표현된다. Pydantic
스키마 (`forensicagent/tools/schema.py`) 로 strict 검증.

```yaml
tool_id: chainsaw
display_name: Chainsaw
category: log_analysis
applicable_evidence_types: [evtx_log]      # Selector 결정론 필터의 키
platform: [windows, linux, macos]
output_format: jsonl
output_size_estimate: large                # 스트리밍 규칙 분석으로 라우팅
parallelizable: true
estimated_runtime: short

install_check:                              # Executor 가 prerequisites 검증
  command: "chainsaw --version"
  expected_pattern: "chainsaw"

command_templates:                          # Executor 가 build_command 에 사용
  - name: "Channel-aware Event ID search"
    template: "chainsaw search -t {channel_event_ids} --match-any --jsonl --output {output_dir}/chainsaw.jsonl {evidence_path}"
    when: "EVTX 채널별 주요 Event ID를 빠르게 확인할 때"

usage_description: |
  ... (LLM 시스템 프롬프트에 들어가는 자연어 설명)

suspicious_indicators:                      # Analyzer 의 룰 dispatch + 프롬프트
  - id: service_install_4697
    pattern: "EventID 4697 + 사용자 쓰기 가능 경로의 ServiceFileName"
    severity_baseline: high
  - id: rdp_logon_offhours
    pattern: "EventID 4624 + LogonType 10 + 설정된 조직 현지 업무시간 밖"
    severity_baseline: medium

known_false_positives:                      # LLM 시스템 프롬프트에 음성 제약
  - "관리자가 PowerShell 로 정상 작업"
```

이 YAML이 Selector / Executor / LLM 프롬프트를 구동한다. Analyzer finding을
추가하려면 YAML indicator와 같은 ID의 concrete matcher 및 회귀 테스트도 필요하다.

`platform`은 도구를 실행할 수 있는 host OS다. 증거의 대상 OS 지원은 별도
`applicable_evidence_platforms` gate이며, 현재 Volatility 실행 metadata는
Windows plugin만 선언하므로 Linux/macOS 메모리 증거를 자동 선택하지 않는다.

현재 실행 metadata는 15개다. 각 도구의 정확한 입력 gate와 지원 범위는
[`tools_metadata/`](tools_metadata/)의 YAML을 기준으로 한다.
기본 metadata가 선언하는 고유 indicator는 34개이고 matcher registry는 custom
metadata 호환 ID까지 41개를 지원한다. AmcacheParser·EvtxECmd·MFTECmd·PECmd·RECmd
같은 EZTools 실행 metadata는 Windows host 전용이다.

---

## 측정 (Observability)

모든 단계가 `Stopwatch` / `StageTimings` 에 ms 를 누적해 리포트에 박힌다.
"수치/성능을 처음부터 끝까지 측정 가능하게" 라는 설계 원칙의 구현체.

각 사이클 끝에 리포트의 `stage_ms` 키에 들어가는 값:
- `scan_walk`, `scan_detect` — Scanner
- `select_filter`, `select_rag`, `select_rank`, `select_force` — Selector
- `execute` — Executor 전체 (도구별 duration_seconds 는 ExecutionResult)
- `analyze_parse:<tool_id>`, `analyze_rules:<tool_id>`, `analyze_llm:<tool_id>` — Analyzer 도구별

JSON 리포트의 `summary.total_ms` 가 모든 stage 의 합.

---

## Benchmark / RAG performance

**"RAG 로 도구 선별" 이 결정론 베이스라인 대비 실제로 순서 품질을 개선하는가?**
를 정량화하는 하니스가 `bench/` 에 있다. 이 하니스는 Analyzer나 외부 도구를
실행하지 않는 **도구 선택 순위 benchmark**이며 탐지 precision/recall이 아니다.

### 어떻게 측정했나 (방법론)

- **골든셋**: **14 개 합성·손라벨 영어 케이스** (`bench/goldenset.json`). 각
  케이스 = 증거 인벤토리(evidence_type + 파일명) + (선택) 영어 시나리오 +
  **도구별 relevance 등급**(2=핵심 / 1=보조 / 0=무관하지만 자격은 있음).
  실제 CTF 가 아니라 한 명이 손으로 라벨한 합성 데이터.
- **이번 측정 모드**: `deterministic` / `rag`. LLM 비교는
  `--with-llm`을 명시했을 때만 추가된다.
- **핵심 통제**: Stage 1 결정론 자격 게이트는 **모드 간 동일**하다 (같은 도구
  집합만 통과). 따라서 모드 간 차이는 순전히 **"순서 품질"** 이지, 어떤 도구가
  자격을 얻느냐가 아니다.
- **지표**: NDCG@k (지수 gain `(2^rel-1)/log2(rank+1)`), MRR, Precision@k,
  Recall@k (k=3,5; relevant 임계값 등급≥1). 여기에 핵심 도구만 보는
  `core_mrr`와 `core_r@k` (등급=2)를 별도로 계산한다. 선택 결과에서 누락된
  gold 도구도 NDCG의 이상 순위와 Recall 분모에 포함하며, 값은 케이스 평균이다.
- **임베딩**: `all-MiniLM-L6-v2` (CPU). 도구 코퍼스는 도구 YAML 자체
  (`rag/tool_indexer.py`).

### 핵심 결과

2026-08-19에 Windows 11 AMD64 / CPython 3.12.4에서 14개 케이스와 11개
도구를 1회 재측정했다.

| metric | deterministic | RAG | delta |
|---|---:|---:|---:|
| NDCG@3 | 0.9295 | 0.9242 | -0.0053 |
| NDCG@5 | 0.9485 | 0.9442 | -0.0043 |
| MRR | 1.0000 | 1.0000 | 0.0000 |
| Core MRR (grade=2) | 0.8929 | 0.8571 | -0.0357 |
| Recall@3 | 0.9714 | 0.9714 | 0.0000 |
| Recall@5 | 1.0000 | 1.0000 | 0.0000 |

RAG는 3/14 케이스의 순서를 바꿨지만 이번 측정에서는 aggregate NDCG와 Core
MRR을 **개선하지 못하고 낮췄다**. 첫 index rebuild는 48.26초(embedding
43,094ms, Chroma write 716ms), 케이스당 RAG 선택 평균은 220.7ms였다. 이 값은
해당 로컬 환경의 1회 측정이며, 외부 도구와 Analyzer를 실행하지 않는 **도구
선택 순위**다. finding precision/recall 또는 end-to-end 탐지율이 아니다. 전체
재현 정보와 케이스별 결과는 `bench/bench_report.md`와
`bench/bench_result.json`에 있다.

### 재현

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[rag]"
.\.venv\Scripts\python.exe -m forensicagent rag index-tools
.\.venv\Scripts\python.exe -m forensicagent bench
# 선택: Ollama까지 준비한 뒤 --with-llm
.\.venv\Scripts\python.exe -m forensicagent bench --with-llm
# metadata/index freshness 검사를 통과하는 기존 index만 재사용
.\.venv\Scripts\python.exe -m forensicagent bench --no-rebuild
```

`forensicagent bench`를 실행하면 전체 표(집계 + delta + 케이스별 + 방법론 +
한계)가 `bench/bench_report.md`와 `bench/bench_result.json`에 새로 저장된다.

### 한계 (수치를 믿기 전에)

- **n=14 합성·단일 라벨러** — 통계적으로 견고하지 않은 지표(indicative). 라벨은
  분석가 한 명의 판단.
- 이 측정 당시 도구는 11개뿐이었다(현재 등록 15개). 일부 evidence type 은 자격
  도구가 1개라 순서가 자명(지표=1.0,
  모드 무관) → 측정 delta 를 희석. 신호는 다-도구 케이스(registry_hive /
  evtx_log / source_code_*)에 있다.
- `all-MiniLM-L6-v2` 는 영어 중심이고 벤치도 영어다. 한국어 시나리오는 성능이
  낮을 수 있으므로 별도 평가가 필요하다(`BAAI/bge-m3` 같은 다국어 모델로 교체 가능).
- **순서 품질만** 측정 — end-to-end triage 정확도·도구 실행·finding 품질은 아님.
- RAG 안전속성(자격 밖 도구 승격 불가)·폴백은 이 벤치가 아니라 단위테스트로
  회귀 검증한다.

---

## 현재 진행 상태

| Phase | 명세 책정 | 실제 |
|---|---|---|
| 1. 기초 인프라 (CLI / Ollama / doctor) | 2주 | ✅ 완료 |
| 2. Scanner | 1주 | ✅ 완료 |
| 3. 도구 메타데이터 스키마 + 우선 5개 | 2~3주 | ✅ 스키마 + 실행 metadata 15개 |
| 4. 단일 도구 end-to-end | 2주 | ✅ 실제 내장 browser SQLite 파이프라인 + 합성 외부도구 회귀 검증 |
| 5. 다중 도구 확장 (5→20→50) | 3~4주 | ⏳ 15개 등록; PCAP/disk는 TShark/fls 설치 시 실행 |
| 6. 평가 / 튜닝 | 2주 | ⏳ 선택 순위 하니스와 별도 finding E2E 하니스 구현; 공개 EVTX 실행은 corpus/Chainsaw 필요 |

## 선택적 외부 corpus 수집

공개 저장소에는 외부 사이트에서 수집한 corpus 본문이나 URL 목록을 포함하지 않는다.
사용자가 라이선스와 이용약관을 확인해 한 줄에 URL 하나인 `urls.txt`를 준비하면
`scripts/ingest_sample.py`로 필요한 자료만 로컬에서 직접 수집할 수 있다.

```powershell
# 먼저 소량으로 소스별 응답과 파서를 확인
.\.venv\Scripts\python.exe -m pip install -e ".[crawlers]"
.\.venv\Scripts\python.exe scripts\ingest_sample.py urls.txt --limit 20
```

산출물은 ignored `seed_docs/`에 저장된다. URL 목록은 본문의 재배포 허가를
의미하지 않으므로, 수집·사용 전에 각 사이트의 최신 라이선스와 이용약관, robots
정책을 직접 확인해야 한다. 이 corpus는 현재 5단계 런타임의 필수 입력이 아니며,
도구 선택 RAG는 `tools_metadata/*.yaml`을 별도로 인덱싱한다.

---

## 빠른 시작

### 1. 의존성 설치

Windows PowerShell에서는 저장소 전용 가상환경을 먼저 만든다.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
# 선택: Ollama + RAG
.\.venv\Scripts\python.exe -m pip install -e ".[llm,rag]"
```

Linux에서는 `python-magic`이 사용하는 시스템 `libmagic`도 필요하다. 배포판에
맞게 설치한 뒤 같은 방식으로 `.venv`를 사용한다(예: Debian/Ubuntu는
`sudo apt-get install libmagic1`).

> **RAG 보안 주의 (2026-08-19):** 현재 선택 의존성 `chromadb 1.5.9`는
> 서버 API를 외부에 노출할 때 pre-auth code injection이 가능한
> CVE-2026-45829의 영향 범위이고 아직 수정 버전이 없다. forensicagent는
> in-process `PersistentClient`만 사용하며 Chroma HTTP 서버를 시작하지 않는다.
> 패치 전에는 `chroma run`을 실행하거나 해당 API를 신뢰되지 않은 네트워크에
> 공개하지 말고, 필요하면 core-only 설치와 `--no-rag`를 사용한다.

### 2. Ollama 데몬 + 모델 준비

```bash
# 한 번만
ollama pull qwen2.5:7b       # 기본값. 14b 등은 FORENSICAGENT_LLM_MODEL 로 지정
ollama serve                  # http://localhost:11434
```

다른 모델/엔드포인트는 PowerShell 환경 변수나 프로젝트의 `.env`로 지정한다.
```powershell
$env:FORENSICAGENT_LLM_MODEL = "llama3.1:8b"
$env:FORENSICAGENT_LLM_BASE_URL = "http://localhost:11434"
```

### 3. 환경 점검

```powershell
.\.venv\Scripts\python.exe -m forensicagent doctor
```

설치 안 된 의존성 / Ollama 미접속 / 포렌식 도구(volatility3, chainsaw, ...)
PATH 미등록을 모두 보여준다. 각 missing 도구 옆에 install 방법 (pip 명령
또는 다운로드 URL) 이 같이 뜬다. RAG·LLM 의존성은 선택 기능이므로 core-only
설치에서는 `miss`로 표시돼도 `doctor` 자체는 성공한다.

### 3-A. 포렌식 도구 설치 도우미

`doctor` 가 잡은 missing 도구를 자동으로 채워주는 헬퍼:

```powershell
.\.venv\Scripts\python.exe -m forensicagent install
.\.venv\Scripts\python.exe -m forensicagent install chainsaw
.\.venv\Scripts\python.exe -m forensicagent install --all
```

- **Python package** (`volatility3`, `bandit`; `semgrep`은 격리 tool venv) →
  registry에 고정된 버전을 프로젝트 내부에 설치
- **zip 다운로드** (`chainsaw`, `gitleaks`) → 고정된 release URL을 HTTPS로 받고 게시된
  SHA-256을 확인한 뒤 경로 탈출·비정상 member·크기 제한을 검사해 교체 설치
- **Gitleaks** → 기본 규칙이 전부 무탐지되는 upstream v8.30.1을 제외하고,
  실제 가짜 AWS 키 탐지를 검증한 v8.30.0만 설치·실행
- **Binwalk** → 오래된 PyPI 패키지를 자동 설치하지 않고 공식 v3 설치를 안내
- **수동 설치 필요** (`yara`, `exiftool`, `tshark`, `fls`, `plaso`, `regripper`,
  `strings`, `tcpdump`) → 다운로드 URL + `curl` 예시를 출력
  (라이선스 마법사 / MSVC Build Tools / 버전 매번 바뀌는 URL 등이라 자동 불가)

이 저장소의 로컬 `.env`에서 `FORENSICAGENT_HOME=.forensicagent`로 두면 ZIP과
격리 venv 도구는 저장소의 `.forensicagent/tools_bin/` 아래에만 설치되고 PATH를
수정하지 않는다. pip형 도구도 위 명령을 실행한 `.venv`에 설치된다. 이 두
디렉터리는 Git에서 제외된다. 프로젝트 밖 기본 사용자 상태 경로를 쓰지 않으려면
`.env.example`을 복사해 이 설정을 유지한다.

### 4. 분석 실행 — 두 가지 방식

#### (A) 인터랙티브 REPL — 탐색적 분석

```powershell
Set-Location C:\cases\case03
.\.venv\Scripts\python.exe -m forensicagent   # 인자 없이 + TTY 면 REPL
# 또는 명시적으로
.\.venv\Scripts\python.exe -m forensicagent shell --path C:\cases\case03

# REPL 안에서
forensic> /help                        # 슬래시 명령 목록
forensic> /scan                        # Scanner
forensic> /plan                        # Selector
forensic> /run                         # Executor
forensic> /analyze                     # Analyzer
forensic> /report                      # Reporter (JSON+MD)
forensic> /summary                     # 최근 /report 핵심 요약 (+ LLM, 가용 시)
forensic> /annotate 1a2b3c4d confirmed 검토 완료
                                        # finding fingerprint 상태/노트 보존
forensic> /auto                        # scan -> plan -> run -> analyze -> report 한 번에
forensic> /show findings               # 직전 결과 다시 보기
forensic> /set no_llm true             # 옵션 토글
forensic> /set max_job_output_mib 512  # job별 출력 상한
forensic> /quit

# 자연어도 가능 (LLM 가용 시 — 첫 호출 5~20초)
forensic> 이 폴더 스캔하고 빠른 도구만 돌려줘
forensic> 발견된 high severity 만 다시 보여줘
```

REPL 의 자연어 라우터는 입력을 `{"actions":[...], "message":"..."}` JSON 으로
변환해 같은 슬래시 핸들러를 호출한다. `--no-llm` 또는 Ollama 부재면 슬래시
명령 모드로 자동 폴백.

#### (B) One-shot 파이프라인 — 배치 / CI

```powershell
.\.venv\Scripts\python.exe -m forensicagent --auto
.\.venv\Scripts\python.exe -m forensicagent --quick
.\.venv\Scripts\python.exe -m forensicagent --tools chainsaw,volatility3
.\.venv\Scripts\python.exe -m forensicagent --dry-run
.\.venv\Scripts\python.exe -m forensicagent --no-llm
.\.venv\Scripts\python.exe -m forensicagent --no-rag
.\.venv\Scripts\python.exe -m forensicagent --scenario "로그인 실패 후 성공 흔적 조사"
.\.venv\Scripts\python.exe -m forensicagent --path C:\cases\case03 --output-dir C:\reports
.\.venv\Scripts\python.exe -m forensicagent --max-job-output-mib 512 --max-total-output-mib 2048 --min-free-disk-mib 512
```

- `--tools`는 RAG/LLM 순위만 건너뛰고 지정 도구를 우선 선택한다. host OS,
  evidence type, input format 안전 gate는 우회하지 않는다. 같은 artifact에 여러
  도구가 겹치면 우선순위(동률이면 나열 순서)가 가장 높은 하나만 실행하며,
  해당 도구가 설치되지 않았으면 다른 도구로 대체하지 않고 skip한다.
- `--no-llm`은 Selector/Analyzer LLM만 끈다. RAG는 `--no-rag`도 지정해야 꺼진다.
- `--no-rag`은 RAG 재정렬과 검색 context만 끈다. LLM은 `--no-llm`도 지정해야 꺼진다.
- `--scenario`는 RAG query와 Selector/Analyzer LLM context에 들어가지만,
  결정론 matcher나 도구 자격 gate를 바꾸지 않는다.
- 성공한 동일 job은 입력 SHA-256, 실행 설정, tool/rule/executable provenance와
  기존 산출물 hash가 모두 일치할 때만 자동 재사용한다. 변경되거나 불완전한 job은
  새 UUID 디렉터리에서 다시 실행하고 이전 부분 산출물은 보존한다.
- 실행기는 같은 입력을 실행 전·후 SHA-256으로 다시 확인하고 job 사이에는
  size/mtime/file identity를 검사한다. 검사 사이에 파일을 바꿨다가 원래 바이트와
  metadata로 완전히 복구하는 악의적 ABA 변경까지 막으려면 읽기 전용 snapshot이
  필요하므로, 운영 원본에는 별도 snapshot/WORM 절차를 적용한다.

> **결정 규칙**: 인자 없이 + TTY = REPL. 플래그 하나라도 있거나 stdin 이
> 파이프 = one-shot. `forensicagent shell` 은 무조건 REPL.

#### 보조 명령

```powershell
.\.venv\Scripts\python.exe -m forensicagent tools list
.\.venv\Scripts\python.exe -m forensicagent tools info chainsaw
.\.venv\Scripts\python.exe -m forensicagent doctor
.\.venv\Scripts\python.exe -m forensicagent rag index-tools
.\.venv\Scripts\python.exe -m forensicagent rag status
.\.venv\Scripts\python.exe -m forensicagent --version
```

LLM이 없어도 `--no-llm`으로 실행할 수 있다. 이 플래그는 Selector Stage 2와
Analyzer LLM만 건너뛰고 룰 matcher와 RAG 설정은 그대로 둔다.

**RAG 활성화 (선택)**: `.\.venv\Scripts\python.exe -m pip install -e ".[rag]"`
후 `.\.venv\Scripts\python.exe -m forensicagent rag index-tools`로 도구
코퍼스를 1회 인덱싱하면, Selector가
런타임에 벡터 검색으로 후보를 관련도순 재정렬하고 Analyzer 에 도메인 스니펫을
제공한다(LLM이 허용된 비-code-security 분석에만 사용). 의존성/인덱스가 없으면 자동으로 결정론+LLM 경로로 폴백하므로,
설치하지 않아도 파이프라인은 그대로 동작한다.

---

## 도구 추가하기

```powershell
# 1. YAML 작성
$EDITOR tools_metadata/yara.yaml

# 2. 검증
.\.venv\Scripts\python.exe -c "from forensicagent.tools import load_tool; print(load_tool('tools_metadata/yara.yaml'))"

# 3. 끝. CLI 가 다음 실행 때 자동으로 픽업.
```

기본 `GenericAdapter` 로는 부족하다면 (예: 도구 출력이 매우 특이한 포맷)
어댑터 서브클래스를 만들어 `register_adapter("yara", YaraAdapter)` 호출.

---

## 프로젝트 구조

```
forensicagent/
├── cli/                  # Typer 진입점, Rich UI, doctor
│   ├── main.py           # 전 파이프라인 default 명령
│   ├── doctor.py         # 환경 점검
│   └── ui.py             # render_inventory, human-readable size
├── scanner/              # Layer 1 — CWD 증거 식별
│   ├── detectors.py      # magic / ext / filename / parent dir 시그니처
│   ├── scanner.py        # 깊이 제한 BFS, symlink/junction 미추적, coverage 계수
│   └── types.py          # Evidence, Inventory
├── selector/             # Layer 3 — 도구 선택 (결정론 → RAG → LLM)
│   ├── filter.py         # Stage 1 결정론 (자격 게이트)
│   ├── llm_rank.py       # Stage 2 LLM (+ RAG 스니펫 컨텍스트)
│   └── selector.py       # 오케스트레이션 + RAG 재정렬 + --quick/--tools/--no-rag
├── executor/             # Layer 4 — 도구 실행
│   ├── adapter.py        # GenericAdapter + register_adapter
│   ├── browser_sqlite_adapter.py # 내장 read-only browser SQLite 실행
│   ├── state.py          # strict/atomic resume manifest + case lock
│   ├── runner.py         # subprocess tree 종료 + timeout/cancel/output-limit
│   └── executor.py       # 단일 owner, 자원 budget, exact resume
├── analyzer/             # Layer 4 — 의심항목 추출
│   ├── rules.py          # id 기반 명시적 matcher registry
│   ├── llm_extract.py    # format=json + severity 가이드라인
│   └── analyzer.py       # Case A/B/C 분기 + dedup
├── reporter/             # Layer 5 — 리포트
│   ├── annotations.py    # fingerprint 기반 analyst 상태/노트 저장
│   ├── builder.py        # 단계 결과를 Report 로 묶기
│   ├── terminal.py       # Rich 출력
│   ├── json_out.py       # JSON 직렬화
│   ├── md_out.py         # Markdown 직렬화
│   └── reporter.py       # 오케스트레이션
├── rag/                  # 런타임 도구 선별 RAG (ChromaDB)
│   ├── vector_store.py   # PersistentClient + cosine hnsw
│   ├── embedder.py       # SentenceTransformer + OpenAI 라우팅
│   ├── tool_indexer.py   # tools_metadata/*.yaml → TOOL_COLLECTION 인덱싱
│   └── retrieval.py      # 런타임 검색 (Selector/Analyzer 공유, 폴백-안전)
├── llm/                  # Ollama 클라이언트
│   └── ollama_client.py  # chat / json_chat (재시도 + 예외 분리)
├── observability/        # cross-cutting
│   └── metrics.py        # Stopwatch / StageTimings / percentile
├── tools/                # 도구 메타데이터 스키마/로더
│   ├── browser_sqlite.py # stdlib SQLite history/download parser
│   ├── schema.py         # Pydantic ToolMetadata
│   └── loader.py         # load_tool, load_all_tools
├── config.py             # env-override 가능한 전역 설정
├── __init__.py           # __version__
└── __main__.py           # `python -m forensicagent`

tools_metadata/           # 실행 metadata YAML 15개 (AppCompat/browser_sqlite/tshark/fls 포함)
eval/                     # 공개 출처·라이선스·gold label E2E manifest (본문은 ignored)
scripts/ingest_sample.py  # 사용자 제공 URL 목록의 선택적 외부 자료 수집
```

---

## 평가 / 측정 (Phase 6)

`bench/`는 **도구 선택 순위**만 측정한다. 실제 `rule_id` 라벨 탐지율은 별도
`forensicagent.e2e_detection` 하니스가 scanner→selector→실제 executor→analyzer→
report 전체를 실행한 뒤 `rule_id` 라벨의 중복 개수를 포함한 precision/recall/F1을
계산한다. 이는 **이벤트 발생 위치·시각 localization 정확도는 측정하지 않는다**.

```powershell
# eval/e2e_manifest.json의 pinned URL/라이선스를 확인하고 corpus를 수동 배치
.\.venv\Scripts\python.exe -m forensicagent.e2e_detection eval\e2e_manifest.json
```

corpus 본문과 실행 산출물은 각각 `eval/corpus/`, `eval/runs/`에 두며 Git에서
제외된다. SHA-256이 고정되지 않았거나, 필요한 외부 도구가 없거나, evidence hash가
다르거나, 분석 coverage가 불완전한 case는 분모에 넣지 않고 명시적으로 skip/error
처리한다. 실행 성공 case가 0개면
`metrics_available=false`, aggregate metric은 `null`이므로 **0점 성능으로 해석하면
안 된다**. 현재 manifest는 commit-pinned 공개 EVTX log-clear URL을 담고 있지만
독립 검증된 파일 SHA-256은 아직 `null`이므로 점수화되지 않는다. 실제 대회 수치로
쓰려면 SHA-256을 검증·고정하고 corpus와 Chainsaw를 준비한 뒤
`executed_cases > 0`을 먼저 확인해야 한다.

향후 비교 베이스라인은 (A) 분석가 수동 triage, (B) 선택 없이 전부 자동 실행,
(C) forensicagent의 시간·finding 품질이다. 실행 시간은 JSON의 `summary.total_ms`와
`stage_ms`로 분리한다.

---

## 알려진 한계

- **로컬 LLM JSON 신뢰성**: `json_chat` 이 1 회 재시도하고 그래도 실패하면
  `JsonRetryFailed` 를 던지는데, 호출자(Selector/Analyzer)가 잡아 룰
  fallback 으로 분기한다. 그래도 LLM 의 우선순위 보강이 빠지는 경우는 생긴다.
- **컨텍스트 길이**: Case C (>4 MB) 에서는 LLM 을 아예 부르지 않는다. 자연어
  보강 없이 룰만 작동. 더 큰 모델 (128K) 도입 시 재조정 가능.
- **도구 metadata 의 인덱싱 부담**: 50 개 도구 YAML 은 사람 검토 대상이고, 이
  부분은 코드로 해결 못 한다. 현재 YAML 변환과 검토는 수작업이다.
- **공개 증거 점수는 아직 없음**: 내장 browser SQLite는 실제 subprocess를 포함한
  전체 파이프라인 회귀를 통과하지만, 공개 저장소에는 EVTX corpus 본문과 외부
  분석 도구를 포함하지 않는다. 검증된 corpus를 별도로 배치해 `executed_cases > 0`을
  확인하기 전에는 공개 `rule_id` 라벨 precision/recall/F1을 주장하지 않는다.
- **coverage는 성공과 별개**: scan의 `depth_limit_hit`, `unreadable_paths`,
  `reparse_paths` 또는 분석의 `coverage_truncated`가 있으면 보고서가 생성돼도
  전체 증거를 다 본 것이 아니다. 원본 artifact와 누락 경로를 검토해야 한다.
- **1.5 GiB scan 상한**: 그 이상 파일은 자동 제외되고 hash도 계산하지 않는다.
  메모리·디스크 이미지처럼 큰 증거는 지원 도구에 넣기 전에 복제본을 분할하거나
  상한 정책을 별도로 조정해야 하며, 제외 목록을 보고서에서 확인해야 한다.

---

## CI와 공개 상태

`.github/workflows/ci.yml`은 Windows/Python 3.10·3.14와 Ubuntu/Python 3.12에서
lint, 테스트, wheel build/install, source tree 밖 CLI smoke test를 수행한다.
배포·릴리스·클라우드 자격증명을 사용하는 단계는 없으며 **CI만 있고 CD는 없다**.

이 공개 저장소는 허용목록으로 만든 sanitized fresh tree다. 외부 corpus 본문,
악성 증거, 생성 분석 산출물, 로컬 환경설정과 기존 개발 이력은 포함하지 않는다.
합성 회귀 fixture의 자격증명 형태 문자열은 실제 secret이 아니다.

그 밖의 공개 전 확인 항목은 다음과 같다.

- 로컬에서 corpus를 재수집할 때 각 출처의 최신 라이선스·이용약관을 확인한다.
- RAG 선택 의존성은 core-only/`--no-rag` 운용으로 격리할 수 있다.
- 외부 도구와 네트워크 기반 ruleset은 제출 환경에서 별도로 버전·라이선스·취약점을
  확인한다.
- GitHub private vulnerability reporting, push protection, branch protection은 저장소
  관리자 설정에서 켠다.
- 합성 선택 benchmark를 실제 사건 finding precision/recall 또는 수상 가능성의
  증거로 표현하지 않는다. E2E 하니스도 `metrics_available=true`인 실행 결과만
  `rule_id` 라벨 탐지 근거로 사용하며 사건 발생 위치 정확도로 확대 해석하지 않는다.

---

## 남은 운영 작업과 의도적 제외 범위

1. pinned 공개 EVTX를 수동 배치하고 프로젝트 내부 Chainsaw 설치가 가능한 환경에서
   E2E 수치를 생성한다. PCAP/disk case도 라이선스와 gold label이 확인된 뒤 추가한다.
2. GitHub 저장소 설정에서 private vulnerability reporting, push protection,
   branch protection을 켠다.
3. 정규화 아티팩트 타임라인은 bounded preview만 보존한다. 전체 사건 인과관계
   자동 재구성, Sigma/YARA 오프라인 규칙팩 버전 관리자,
   STIX/CSV/Timesketch export는 이번 범위에서 의도적으로 제외했다.

---

## License

MIT. 자세한 조건은 [LICENSE](LICENSE), 취약점 제보 절차는
[SECURITY.md](SECURITY.md), 기여 절차는 [CONTRIBUTING.md](CONTRIBUTING.md),
외부 도구·데이터 고지는
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를 참조한다.
