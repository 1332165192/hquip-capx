"""Fake Frida only: never imports installed Frida or attaches to an OS target."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FAKE_FRIDA = r'''
import os
from pathlib import Path
import threading
MODE = os.environ['CAPX_FAKE_FRIDA_MODE']
LOG = Path(os.environ['CAPX_FAKE_FRIDA_LOG'])
def record(value):
    with LOG.open('a', encoding='utf8') as f: f.write(value + '\n')
def spawn(argv):
    record('spawn-fixture')
    return 4000000011
def resume(pid): record('resume-fixture:' + str(pid))
def attach(pid):
    record('attach-fixture:' + str(pid))
    if MODE == 'attach-error': raise RuntimeError('fixture attach denied')
    return Session()
class Session:
    def on(self, event, fn): self.detached = fn
    def create_script(self, source):
        if MODE == 'create-error': raise RuntimeError('fixture create_script failed')
        return Script(self)
    def detach(self):
        record('detach-fixture')
        self.detached('application-requested')
class Script:
    def __init__(self, session): self.session = session
    def on(self, event, fn): self.message = fn
    def load(self):
        if MODE == 'top-error':
            self.message({'type':'error','description':'fixture top-level JS failure'}, None)
            return  # Frida may report JS failure without raising from load().
        if MODE == 'fatal-send':
            self.message({'type':'send','payload':{'event':'wxredirect','stage':'error','fatal':True,'msg':'fixture no hooks'}}, None)
            return
        self.message({'type':'send','payload':{'event':'wxredirect','stage':'ready','hooks':['connect']}}, None)
        threading.Timer(0.08, lambda: self.session.detached('fixture-process-terminated')).start()
'''


class DriverTests(unittest.TestCase):
    def run_fixture(self, mode, spawn=False):
        with tempfile.TemporaryDirectory(prefix='capx-frida-fixture-') as folder:
            folder = Path(folder)
            (folder / 'frida.py').write_text(FAKE_FRIDA, encoding='utf8')
            agent = folder / 'fixture.js'
            agent.write_text('// fake script; not executed against a process', encoding='utf8')
            log = folder / 'calls.log'
            env = dict(os.environ, PYTHONPATH=str(folder), CAPX_FAKE_FRIDA_MODE=mode,
                       CAPX_FAKE_FRIDA_LOG=str(log), CAPX_HOOK_DEBUG='')
            target = ['--spawn', 'fixture-only.exe'] if spawn else ['--pid', '4000000001']
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name('driver.py')), *target, '--agent', str(agent)],
                env=env, text=True, capture_output=True, timeout=4,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            events = [json.loads(line) for line in result.stdout.splitlines()]
            calls = log.read_text(encoding='utf8') if log.exists() else ''
            return result, events, calls

    def test_top_level_js_failure_exits_without_loaded(self):
        result, events, calls = self.run_fixture('top-error')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue(any('top-level JS failure' in e.get('msg', '') for e in events))
        self.assertFalse(any(e['event'] == 'loaded' for e in events))
        self.assertIn('detach-fixture', calls)
        self.assertNotIn('resume-fixture', calls)

    def test_fatal_agent_payload_exits(self):
        result, events, calls = self.run_fixture('fatal-send')
        self.assertEqual(result.returncode, 3)
        self.assertFalse(any(e['event'] == 'loaded' for e in events))
        self.assertIn('detach-fixture', calls)

    def test_load_and_detach_are_reported(self):
        result, events, calls = self.run_fixture('ready-detach')
        self.assertEqual(result.returncode, 3)
        self.assertTrue(any(e['event'] == 'loaded' for e in events))
        self.assertTrue(any(e.get('stage') == 'ready' for e in events))
        self.assertTrue(any(e.get('stage') == 'detached' for e in events))
        self.assertNotIn('resume-fixture', calls)

    def test_attach_error_is_explicit(self):
        result, events, _ = self.run_fixture('attach-error')
        self.assertEqual(result.returncode, 3)
        self.assertTrue(any(e.get('stage') == 'attach' and e.get('fatal') for e in events))

    def test_failed_spawn_setup_resumes_only_its_own_fixture(self):
        result, _, calls = self.run_fixture('create-error', spawn=True)
        self.assertEqual(result.returncode, 3)
        self.assertIn('resume-fixture:4000000011', calls)
        self.assertIn('detach-fixture', calls)


if __name__ == '__main__':
    unittest.main()
