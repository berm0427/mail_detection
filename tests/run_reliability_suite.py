import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


DEFAULT_TIMEOUT_SECONDS = 240


def run(cmd, env=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    print('RUN', ' '.join(cmd), flush=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(cmd, cwd=ROOT, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        print(f'TIMEOUT after {elapsed:.1f}s', flush=True)
        return 124
    elapsed = time.monotonic() - started
    print(f'EXIT {completed.returncode} after {elapsed:.1f}s', flush=True)
    return completed.returncode


def main():
    env = os.environ.copy()
    env['EMAIL_DISABLE_REMOTE_AI'] = '1'
    env.setdefault('QT_QPA_PLATFORM', 'offscreen')
    py = sys.executable
    failures = []
    for name, cmd, timeout in [
        ('core_unittest', [py, '-B', '-m', 'unittest',
                           'tests.test_attachment_scanner', 'tests.test_clamav_bootstrap',
                           'tests.test_auth_display', 'tests.test_decision', 'tests.test_dns_path',
                           'tests.test_evidence', 'tests.test_html_decision',
                           'tests.test_homepage_comparison', 'tests.test_link_auth_boundaries',
                           'tests.test_official_site_discovery', 'tests.test_page_structure',
                           'tests.test_semantic_ml', '-v'], 180),
        ('real_analyzer_gui_integration', [py, '-B', 'tests/real_analyzer_gui_integration.py'], 300),
    ]:
        rc = run(cmd, env, timeout=timeout)
        if rc != 0:
            failures.append((name, rc))
            break
    if failures:
        print('FAILURES', failures, flush=True)
        raise SystemExit(failures[0][1])
    print('ALL PASSED', flush=True)
    raise SystemExit(0)


if __name__ == '__main__':
    main()
