# Contributing

Thanks for helping harden agent memory. The bar for merging: zero runtime
dependencies in the core, and every behavior change covered by a test.

## Setup

```bash
git clone https://github.com/gbayerv26/memwall && cd memwall
pip install -e ".[dev,judge]"
python -m unittest discover -s tests -t . -v
```

## Adding a detection rule

1. Add the rule to `memwall/heuristics.py` with the next `MWxxx` id, a
   severity, and a one-line description of the attack shape it catches.
2. Add tests in `tests/test_heuristics.py` in **both directions**: strings it
   must flag, and near-miss benign strings it must not flag. False-positive
   tests are as important as detection tests.
3. If the rule represents an instruction or an outbound destination, decide
   whether it belongs in `INSTRUCTION_RULES` / `VECTOR_RULES` (the MW000
   combo escalation) and whether instruction files should skip it.

## Adding a store adapter

Create `memwall/adapters/<store>.py` exposing `load(path) -> list[MemoryRecord]`,
register it in `memwall/adapters/__init__.py` (ADAPTERS + detection), and add
a fixture plus a count test in `tests/test_adapters.py`. Most wanted: Zep,
Letta, LangGraph checkpoints.

## Style

Stdlib only in the core (`anthropic` stays behind the `[judge]` extra).
Match the existing code: type hints, small modules, no framework.
