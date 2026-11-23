# Agent instructions

Use the shared Code Quality rules when the agent profile supplies them. Put
runtime modules in `security_runtime/`, CI helpers in `.github/scripts/`, and
benchmark code in `benchmarks/`. Keep `main.py`, `runtime.py`, and `triage.py`
as small launchers for their existing commands.

Put automated tests in `tests/`. Run the suite from the repository root.

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

