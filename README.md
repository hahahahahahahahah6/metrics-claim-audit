# metrics-claim-audit

MIT licensed. Version 0.1.0. Requires Python 3.9 or later; runtime uses only the standard library.

Audit documentation promises against static Python AST evidence of project-defined
Prometheus-format series wired to a serving channel. Source is never executed.

```sh
python3 -m pip install .
metrics-claim-audit /path/to/project
python3 -m metrics_claim_audit /path/to/project --json
```

The root README.md and Markdown under any docs path component are scanned.
Fenced blocks are excluded; inline code counts. Paragraph lines are joined,
case and whitespace are normalized, contractions expanded, and hyphens replaced
with spaces. Exact phrase templates use word boundaries; negative spans are
removed before checking positive templates.

Positive templates deliberately require Prometheus-specific wording. Generic
“exposes metrics” is outside scope because other backends cannot be verified.
Negative templates are broader: project-defined serving evidence can contradict
a generic denial. Bare nouns alone are not claims.

Production evidence requires both a supported metric constructor and a serving
call, in one module or with an import from the serving module to the definition
module's top-level name. Test-only wiring produces a MEDIUM positive mismatch;
production mismatches and contradicted denials are HIGH. At most one finding
per family is emitted. A denial in test documentation can still produce HIGH.
Positive statements in test documentation alone do not produce findings.

Supported constructors are Counter, Gauge, Histogram, Summary, Info and Enum.
The latter two require a qualified client binding or an explicit client import.
Serving calls are start_http_server, start_wsgi_server, make_wsgi_app,
make_asgi_app and generate_latest. Gateway pushes and collection alone do not count.

Limitations: this is a syntax-level heuristic, with no control-flow or registry
analysis. Import edges match top-level names, not full dependency graphs.
Default process/GC collectors alone do not satisfy a project-defined wiring
promise: a bare server call is flagged. Other backends are outside scope.
Invalid source is skipped and reported in verbose output. Tests are analyzed
separately; fixtures, docs, examples and symlinked source files are excluded.
Environment files are never opened.

Options: --json emits machine-readable output; --verbose includes evidence;
--ignore GLOB is repeatable and matches root-relative paths; --fail-on HIGH
(default) or MEDIUM controls failure threshold. --version prints 0.1.0.
Exit codes: 0 pass, 2 threshold reached, 1 usage or root access error.

Run checks with `python3 -m unittest discover`. Build with `python3 -m build`.
