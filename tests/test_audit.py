import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from metrics_claim_audit.audit import audit, claims, POSITIVE, NEGATIVE

ROOT = Path(__file__).resolve().parents[1]
CLAIM = 'exposes Prometheus metrics'
METRIC = 'from prometheus_client import Counter\nx = Counter("x", "x")\n'
GOOD = METRIC + 'start_http_server(8000)\n'


class AuditTests(unittest.TestCase):
    def fixture(self, doc=CLAIM, files=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name, text in dict({'README.md': doc}, **(files or {})).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def check(self, root, severity=None, rule='documented-metrics-claim-false'):
        result = audit(root)
        expected = [] if severity is None else [(rule, severity)]
        self.assertEqual([(f['rule'], f['severity']) for f in result['findings']], expected)
        self.assertEqual(result['verdict'], 'FAIL' if severity == 'HIGH' else 'PASS')
        return result

    def cli(self, root, *args):
        return subprocess.run([sys.executable, '-m', 'metrics_claim_audit', str(root), *args], capture_output=True, text=True)

    def test_01_one_module(self):
        root = self.fixture(files={'app.py': GOOD})
        self.check(root)
        self.assertEqual(self.cli(root).returncode, 0)

    def test_02_split(self):
        self.check(self.fixture(files={'metrics.py': METRIC, 'app.py': 'import metrics\nstart_http_server(8)'}))

    def test_03_generate_latest(self):
        self.check(self.fixture('Prometheus metrics', {'app.py': 'import prometheus_client\nx=Gauge("x","x")\ndef handler():\n return generate_latest()'}))

    def test_04_wsgi(self):
        self.check(self.fixture('Prometheus endpoint', {'app.py': 'import prometheus_client\nx=Histogram("x","x")\nmake_wsgi_app()'}))

    def test_05_metric_only(self):
        root = self.fixture(files={'app.py': METRIC})
        self.check(root, 'HIGH')
        self.assertEqual(self.cli(root).returncode, 2)

    def test_06_exposition_only(self):
        self.check(self.fixture(files={'app.py': 'from prometheus_client import start_http_server\nstart_http_server(8)'}), 'HIGH')

    def test_07_import_only(self):
        self.check(self.fixture(files={'app.py': 'import prometheus_client'}), 'HIGH')

    def test_08_log_only(self):
        self.check(self.fixture(files={'app.py': 'logger.info("metrics exported")'}), 'HIGH')

    def test_09_push(self):
        self.check(self.fixture(files={'app.py': METRIC + 'push_to_gateway("x")'}), 'HIGH')

    def test_10_denial(self):
        self.check(self.fixture('does not expose Prometheus metrics', {'app.py': GOOD}), 'HIGH', 'documented-no-metrics-claim-false')

    def test_11_no_claim(self):
        self.check(self.fixture('A useful application.', {'app.py': GOOD}))

    def test_12_no_source(self):
        self.check(self.fixture(), 'HIGH')
        self.check(self.fixture('does not expose metrics'))

    def test_13_non_evidence(self):
        for source in ['import statsd', 'class Counter: pass\nCounter()\nstart_http_server(8)',
                       'path="/metrics"', 'from prometheus_client import multiprocess\nmultiprocess.MultiProcessCollector(registry)',
                       'import prometheus_client\nimport enum\nEnum("X", "a b")\nstart_http_server(8)']:
            with self.subTest(source=source):
                self.check(self.fixture(files={'app.py': source}), 'HIGH')

    def test_14_enum(self):
        self.check(self.fixture(files={'app.py': 'import prometheus_client\nprometheus_client.Enum("x","x")\nstart_http_server(8)'}))

    def test_15_unpaired(self):
        self.check(self.fixture(files={'a.py': METRIC, 'b.py': 'start_http_server(8)'}), 'HIGH')

    def test_16_test_only(self):
        root = self.fixture(files={'tests/app.py': GOOD})
        self.check(root, 'MEDIUM')
        self.assertEqual(self.cli(root).returncode, 0)
        self.assertEqual(self.cli(root, '--fail-on', 'MEDIUM').returncode, 2)

    def test_17_fences_inline(self):
        for fence in ['```', '~~~~']:
            self.check(self.fixture(fence + '\n' + CLAIM + '\n' + fence))
        self.check(self.fixture('`' + CLAIM + '`'), 'HIGH')

    def test_18_negative_spans(self):
        self.assertEqual(claims('does not expose Prometheus metrics'), (False, True))
        for phrase in NEGATIVE:
            self.assertEqual(claims(phrase), (False, True), phrase)

    def test_19_nouns(self):
        for noun in ['metrics', 'prometheus', 'instrumentation', 'endpoint']:
            self.check(self.fixture(noun))

    def test_20_generic(self):
        self.check(self.fixture('exposes metrics'))

    def test_21_cli(self):
        root = self.fixture('Nothing.', {'docs/guide.md': CLAIM, 'app.py': GOOD})
        version = subprocess.run([sys.executable, '-m', 'metrics_claim_audit', '--version'], capture_output=True, text=True)
        self.assertEqual((version.returncode, version.stdout.strip()), (0, '0.1.0'))
        self.assertEqual(json.loads(self.cli(root, '--json').stdout)['verdict'], 'PASS')
        self.assertIn('app.py', self.cli(root, '--verbose').stdout)
        bad = self.fixture('Nothing.', {'docs/guide.md': CLAIM})
        self.assertEqual(self.cli(bad).returncode, 2)
        self.assertEqual(self.cli(bad, '--ignore', 'docs/*').returncode, 0)
        self.assertEqual(self.cli(root / 'missing').returncode, 1)
        self.assertEqual(self.cli(root, '--unknown').returncode, 1)

    def test_22_self_audit(self):
        result = self.check(ROOT)
        self.assertEqual(result['claims'], [])
        self.assertFalse(claims((ROOT / 'README.md').read_text())[0])

    def test_23_env_guard(self):
        root = self.fixture('Nothing.', {'.env': 'MARKER_ONLY', 'tests/fixtures/.env': 'MARKER_ONLY'})
        original = Path.read_text
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', guarded):
            self.check(root)

    def test_24_packaging_and_interpreter(self):
        config = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('setuptools>=77', config)
        self.assertIn('license = "MIT"', config)
        self.assertIn('recursive-include tests', (ROOT / 'MANIFEST.in').read_text())
        forbidden = re.compile(r'\b' + 'py' + r'thon\b')
        for folder in [ROOT / 'metrics_claim_audit', ROOT / 'tests']:
            for path in folder.rglob('*.py'):
                self.assertIsNone(forbidden.search(path.read_text()), str(path))
        self.assertIsNone(forbidden.search((ROOT / 'README.md').read_text()))

    def test_25_aliases_and_channels(self):
        for constructor in ['Counter', 'Gauge', 'Histogram', 'Summary', 'Enum', 'Info']:
            for channel in ['start_http_server', 'start_wsgi_server', 'make_wsgi_app', 'make_asgi_app', 'generate_latest']:
                with self.subTest(constructor=constructor, channel=channel):
                    self.check(self.fixture(files={'app.py': 'import prometheus_client as pc\nx=pc.%s("x","x")\npc.%s()' % (constructor, channel)}))
            self.check(self.fixture(files={'app.py': 'from prometheus_client import %s as C, generate_latest as serve\nx=C("x","x")\nserve()' % constructor}))
        self.check(self.fixture(files={'app.py': 'import prometheus_client\nInfo("x","x")\ngenerate_latest()'}), 'HIGH')

    def test_26_normalization_boundaries(self):
        for phrase in POSITIVE:
            self.assertEqual(claims(phrase), (True, False))
        self.assertEqual(claims("DOESN'T expose Prometheus-metrics"), (False, True))
        self.assertEqual(claims('exposes\nPrometheus metrics'), (True, False))
        self.assertEqual(claims('exposes Prometheus\n\nmetrics'), (False, False))
        self.assertEqual(claims('xprometheus metricsx'), (False, False))

    def test_27_scopes(self):
        for name in ['fixtures/a.py', 'examples/a.py', 'docs/a.py']:
            self.check(self.fixture(files={name: GOOD}), 'HIGH')
        for name in ['test_app.py', 'app_test.py']:
            self.check(self.fixture(files={name: GOOD}), 'MEDIUM')
        self.check(self.fixture('Nothing.', {'tests/docs/a.md': CLAIM, 'app.py': GOOD}))
        self.check(self.fixture('Nothing.', {'tests/docs/a.md': 'no metrics', 'app.py': GOOD}), 'HIGH', 'documented-no-metrics-claim-false')
        root = self.fixture(files={'app.py': GOOD})
        (root / 'app.py').rename(root / 'target.txt')
        (root / 'app.py').symlink_to(root / 'target.txt')
        self.check(root, 'HIGH')

    def test_28_package_pair_and_maximum(self):
        self.check(self.fixture(files={'pkg/metrics.py': METRIC, 'app.py': 'import pkg.metrics\nstart_http_server(8)'}))
        root = self.fixture(CLAIM + '\n\nno metrics', {'tests/app.py': GOOD})
        self.check(root, 'MEDIUM')
        self.check(self.fixture(CLAIM + '\n' + CLAIM), 'HIGH')


if __name__ == '__main__':
    unittest.main()
