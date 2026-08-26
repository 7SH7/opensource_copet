"""pytest 공통 픽스처.

대부분의 테스트는 결정론적 (Scanner detectors, Selector filter, Analyzer
rules) 이라 LLM / 네트워크 / GPU 없이 작동한다. Ollama / chromadb /
sentence-transformers 가 깔려있지 않아도 통과해야 한다.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path so `import forensicagent` works when
# pytest is run from anywhere.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
