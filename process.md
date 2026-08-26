# ForensicAgent 테스트 방법

Windows PowerShell에서 저장소 루트로 이동한 뒤 실행한다. 실제 원본 증거가 아니라
복제본이나 테스트 파일을 사용한다.

## 1. 가장 빠른 자동 검증

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m pytest --basetemp .pytest_cache/tmp
.\.venv\Scripts\python.exe -m pip check
```

2026-08-27 공개본 기준 전체 테스트 결과는 `531 passed, 3 skipped`다. Windows에서
symlink 생성 권한이 없으면 보안 링크 테스트 3개가 skip될 수 있다.

## 2. 실행 환경 확인

```powershell
.\.venv\Scripts\python.exe -m forensicagent doctor
```

`core checks passed`인지 확인한다. 외부 포렌식 도구가 `miss`이면 그 도구가 소유한
증거는 다른 도구로 대체하지 않고 skip되는 것이 정상이다.

## 3. 실제 기능을 순서대로 테스트

```powershell
.\.venv\Scripts\python.exe -m forensicagent shell --path C:\cases\test-case
```

REPL이 열리면 다음 순서로 입력한다.

```text
/scan
/plan
/run
/analyze
/report
/summary
```

확인할 항목:

- `/scan`: 1.5 GiB 이상 파일은 경로·크기·제외 이유를 표시하고 계속 진행한다.
- `/plan`: artifact마다 우선순위가 가장 높은 도구 하나만 선택한다.
- `/run`: 성공했지만 내용이 없는 job 폴더는 남기지 않는다. 실패·timeout·부분
  산출물은 진단을 위해 보존한다. 0바이트 `chainsaw.jsonl`은 generated 결과
  목록과 이후 분석 대상에서 제외하고 정상적인 탐지 0건으로 기록하며, 해당
  raw job 폴더도 제거한다.
- `/analyze`: CSV의 비정상 추가 열이 있어도 중단되지 않아야 한다.
- `/report`: JSON과 Markdown에 정규화 아티팩트 타임라인 preview, finding 타임라인,
  원문 시각, coverage ledger, 입력·출력 hash와 provenance가 기록된다.
- `/summary`: 최근 `/report`의 상위 finding에 대해 시각·관련 파일명·이벤트
  namespace·탐지 방식·규칙·근거·신뢰도·대안 설명과 분석 한계를 요약한다.
  원본 증거·명령·secret은 모델에 보내지 않는다.

분석가 판정도 시험하려면 `/show findings`에서 fingerprint를 확인한 뒤 실행한다.

```text
/annotate <fingerprint> confirmed 검토 완료
/report
```

새 보고서에 annotation이 유지되는지 확인한다.

## 4. 기능별 회귀 테스트

```powershell
# EvtxECmd CSV, 대용량 batch, artifact 무결성
.\.venv\Scripts\python.exe -m pytest tests\test_analyzer_regressions.py -q

# 안전한 resume, 출력 상한, 취소, 빈 폴더 정리
.\.venv\Scripts\python.exe -m pytest tests\test_executor_resume.py tests\test_executor_integration.py -q

# Chrome/Edge/Firefox SQLite 전체 파이프라인
.\.venv\Scripts\python.exe -m pytest tests\test_browser_sqlite.py -q

# timeframe, 통합 timeline, rule prefilter, report, annotation, summary
.\.venv\Scripts\python.exe -m pytest tests\test_time_scope.py tests\test_timeline_parser.py tests\test_rule_prefilter.py tests\test_reporter.py tests\test_annotations.py tests\test_summary.py -q

# 1.5 GiB 자동 제외
.\.venv\Scripts\python.exe -m pytest tests\test_scanner.py -q
```

## 5. 공개 corpus E2E 평가

```powershell
.\.venv\Scripts\python.exe -m forensicagent.e2e_detection eval\e2e_manifest.json
```

현재 corpus 본문과 검증된 SHA-256이 없으므로 `executed_cases=0`,
`metrics_available=false`, metric `null`이 정상이다. 실제 precision/recall/F1을
제출 자료에 쓰려면 manifest의 출처·라이선스·SHA-256을 검증하고 필요한 외부 도구를
프로젝트 내부에 준비한 다음 `executed_cases > 0`을 먼저 확인한다.

## 6. 결과 위치

로컬 `.env` 기본값을 사용하면 실행 결과는 `.forensicagent/output/` 아래에 생성된다.
각 실행의 `raw/`, JSON 보고서, Markdown 보고서를 함께 확인한다. `.env`, corpus,
실행 산출물과 cache는 Git에 올리지 않는다.

## 7. 현재 한계와 제출 전 확인사항

- 공개 corpus와 고정된 SHA-256이 아직 없어 E2E 탐지 성능은 측정되지 않았다.
  `executed_cases=0`의 null metric을 precision·recall·F1처럼 발표하면 안 된다.
- TShark, `fls` 등 일부 외부 도구가 없으면 해당 artifact는 대체 도구 없이 skip된다.
  제출 환경에서 `doctor`로 필요한 도구를 먼저 확인한다.
- `pip-audit`은 advisory 네트워크 접근이 가능한 환경에서 다시 실행해야 한다.
- Windows symlink 보안 테스트 3개는 symlink 생성 권한이 없는 환경에서 skip된다.
- 실행 출력은 바이트 수로 제한하지만 파일 개수 제한은 아직 없다. 또한 분석 중
  원본이 동시에 교체되는 상황까지 막으려면 향후 불변 evidence snapshot이 필요하다.
- 정규화 타임라인은 메모리 사용을 제한하기 위해 전체 건수와 bounded preview를
  기록한다. parser별 컬럼 구조가 다르면 일부 필드가 coverage warning으로 남을 수 있다.
- 전체 사건 인과관계 자동 재구성, Sigma/YARA 오프라인 규칙팩 버전 관리,
  외부 포맷 내보내기는 이번 범위에서 의도적으로 제외했다.
- 공개 저장소에는 악성 증거, corpus 본문, 생성 산출물, 로컬 설정과 기존 개발 이력을
  포함하지 않는다.

## 8. 증거 안전

증거 파일 안의 스크립트·매크로·명령·바이너리를 실행하거나 import하지 않는다.
복제본을 네트워크가 격리된 환경에서 신뢰할 수 있는 read-only parser의 데이터 입력으로만
다룬다. parser가 증거 내용을 실행할 가능성이 있으면 사용하지 않는다.
