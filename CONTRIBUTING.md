# Contributing

Open a focused issue before changing the public protocol or trust boundary. Keep the core policy
dependency-free, preserve unknown OpenAI-compatible fields, and add behavior-first tests for every
policy change. Never add expected benchmark answers, hidden fixtures, real secrets, private raw
transcripts, model files, or host-specific configuration.

Before submitting a change, run:

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src tests scripts
uv run mypy src
```

Container changes should also pass `scripts/docker-smoke.sh` with the scripted fake upstream. A
maintainer must explicitly authorize public release or registry publication.
