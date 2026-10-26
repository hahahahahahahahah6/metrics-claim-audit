import argparse
import json
import sys
from . import __version__
from .audit import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, '%s: error: %s\n' % (self.prog, message))


def main(argv=None):
    parser = Parser(description='Audit documentation against static serving wiring.')
    parser.add_argument('root')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='HIGH')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore, args.fail_on)
    except (ValueError, OSError) as exc:
        if args.json:
            print(json.dumps({'error': str(exc)}))
        else:
            print(str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result))
    else:
        print(result['verdict'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        if args.verbose:
            print('Evidence: ' + json.dumps(result['evidence']))
            print('Claims: ' + json.dumps(result['claims']))
            print('Errors: ' + json.dumps(result['errors']))
    return 2 if result['verdict'] == 'FAIL' else 0
