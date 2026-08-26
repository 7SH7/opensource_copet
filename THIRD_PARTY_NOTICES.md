# Third-party notices

Dependencies declared in `pyproject.toml` retain their respective upstream
licenses. Optional LLM models and external forensic tools are not vendored by
this repository; users must follow each upstream project's license and terms.

## Evaluation data reference

`eval/e2e_manifest.json` references one file from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) at
commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`, identified upstream as
GPL-3.0. The evidence body is not vendored or downloaded by forensicagent;
only its pinned source/download URLs, license URL, and gold label are tracked.
