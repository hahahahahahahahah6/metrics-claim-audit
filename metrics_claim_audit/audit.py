"""Documentation extraction and conservative static wiring checks."""
import ast
import fnmatch
import re
from pathlib import Path

POSITIVE = (
    'exposes prometheus metrics', 'exports prometheus metrics',
    'provides prometheus metrics', 'serves prometheus metrics',
    'ships with prometheus metrics', 'exposes metrics in prometheus format',
    'metrics in prometheus format', 'prometheus metrics endpoint',
    'prometheus compatible metrics', 'prometheus instrumentation',
    'instrumented with prometheus', 'prometheus metrics', 'prometheus endpoint')
NEGATIVE = (
    'does not expose prometheus metrics', 'does not expose metrics',
    'does not provide metrics', 'does not export metrics',
    'does not provide prometheus metrics', 'no prometheus instrumentation',
    'no prometheus metrics', 'no prometheus endpoint', 'no metrics endpoint',
    'metrics are not exposed', 'not instrumented with prometheus',
    'without prometheus metrics', 'no metrics')


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(s) for s in
                      sorted(phrases, key=len, reverse=True)) + r')\b')


POS_RE, NEG_RE = pattern(POSITIVE), pattern(NEGATIVE)


def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
            lines.append('')
        elif match:
            fence = match[1]
            lines.append('')
        else:
            lines.append(line)
    positive = negative = False
    for para in re.split(r'\n\s*\n', '\n'.join(lines)):
        normalized = ' '.join(para.lower().replace("n't", ' not').replace('-', ' ').split())
        negative |= bool(NEG_RE.search(normalized))
        positive |= bool(POS_RE.search(NEG_RE.sub(' ', normalized)))
    return positive, negative


def evidence(text):
    tree = ast.parse(text)
    imports, clients, bindings = set(), set(), {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split('.')[0])
                if alias.name == 'prometheus_client':
                    clients.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imports.add(node.module.split('.')[0])
            if node.module == 'prometheus_client':
                for alias in node.names:
                    bindings[alias.asname or alias.name] = alias.name
    metric = exposition = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ''
        if name in {'start_http_server', 'start_wsgi_server', 'make_wsgi_app', 'make_asgi_app', 'generate_latest'} or bindings.get(name) in {'start_http_server', 'start_wsgi_server', 'make_wsgi_app', 'make_asgi_app', 'generate_latest'}:
            exposition = True
        if isinstance(func, ast.Name):
            metric |= (bindings.get(name) in {'Counter', 'Gauge', 'Histogram', 'Summary', 'Info', 'Enum'} or
                       ('prometheus_client' in imports and name in {'Counter', 'Gauge', 'Histogram', 'Summary'}))
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            metric |= func.value.id in clients and name in {'Counter', 'Gauge', 'Histogram', 'Summary', 'Info', 'Enum'}
    return metric, exposition, imports


def is_test(path):
    return 'tests' in path.parts or path.name.startswith('test_') or path.name.endswith('_test.py')


def paired(modules):
    definitions = set()
    for path, metric, _, _ in modules:
        if metric:
            parts = Path(path).parts
            if 'tests' in parts:
                parts = parts[parts.index('tests') + 1:]
            top = parts[0]
            definitions.add(top[:-3] if top.endswith('.py') else top)
    return any(exposition and (metric or bool(imports & definitions))
               for _, metric, exposition, imports in modules)


def audit(root, ignores=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('root must be a readable directory')
    prod_claim = negative_claim = False
    claim_paths, modules, test_modules, errors = [], [], [], []
    # Explicit walk avoids following directory symlinks and never opens .env.
    import os
    def walk_error(error):
        raise ValueError(str(error))
    for base, dirs, names in os.walk(str(root), onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink())
        for name in sorted(names):
            path = Path(base) / name
            rel = path.relative_to(root)
            if path.is_symlink() or any(fnmatch.fnmatch(rel.as_posix(), g) for g in ignores):
                continue
            doc = rel.as_posix() == 'README.md' or ('docs' in rel.parts[:-1] and rel.suffix == '.md')
            source = rel.suffix == '.py' and not {'fixtures', 'docs', 'examples'} & set(rel.parts[:-1])
            if not (doc or source):
                continue
            try:
                text = path.read_text(encoding='utf-8')
                if doc:
                    pos, neg = claims(text)
                    prod_claim |= pos and not is_test(rel)
                    negative_claim |= neg
                    if pos or neg:
                        claim_paths.append({'path': rel.as_posix(), 'positive': pos, 'negative': neg})
                if source:
                    metric, exposition, imports = evidence(text)
                    (test_modules if is_test(rel) else modules).append((rel.as_posix(), metric, exposition, imports))
            except (OSError, UnicodeError, SyntaxError) as exc:
                errors.append({'path': rel.as_posix(), 'error': str(exc)})
    prod, test = paired(modules), paired(test_modules)
    findings = []
    if prod_claim and not prod:
        findings.append({'rule': 'documented-metrics-claim-false', 'severity': 'MEDIUM' if test else 'HIGH',
                         'message': 'Serving wiring exists only in tests.' if test else 'No paired project metric and exposition evidence.'})
    if negative_claim and prod:
        findings.append({'rule': 'documented-no-metrics-claim-false', 'severity': 'HIGH',
                         'message': 'A documented denial contradicts production serving wiring.'})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'verdict': 'FAIL' if failed else 'PASS', 'findings': findings,
            'claims': claim_paths, 'evidence': [dict(path=p, metric=m, exposition=e, imports=sorted(i), scope=s)
                for s, group in [('production', modules), ('test', test_modules)] for p, m, e, i in group if m or e],
            'errors': errors}
