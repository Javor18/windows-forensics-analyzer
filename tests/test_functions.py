from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = next((ROOT / 'scripts').glob('*.sh'))
BASH = os.environ.get('PORTFOLIO_BASH') or shutil.which('bash')

class FunctionTests(unittest.TestCase):
    def evaluate(self, expression):
        env = dict(os.environ)
        import sys
        env['PORTFOLIO_PYTHON'] = Path(sys.executable).as_posix()
        command = 'source "$1"; shift; python3() { "$PORTFOLIO_PYTHON" "$@"; }; ' + expression
        return subprocess.run([BASH, '-c', command, 'function-test', SCRIPT.as_posix()],
                              capture_output=True, text=True, env=env, timeout=15)

    def test_integrity_match_and_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image with spaces.img'
            log = Path(tmp) / 'report.txt'
            image.write_bytes(b'original synthetic evidence')
            import hashlib
            initial = hashlib.sha256(image.read_bytes()).hexdigest()
            expression = f'IMAGE_FILE="{image.as_posix()}"; REPORT_FILE="{log.as_posix()}"; INITIAL_HASH="{initial}"; verify_image_integrity'
            self.assertEqual(self.evaluate(expression).returncode, 0)
            image.write_bytes(b'changed synthetic evidence')
            result = self.evaluate(expression)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('MISMATCH', result.stdout)

    def test_integrity_failure_does_not_create_success_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'changed.img'
            image.write_bytes(b'changed synthetic evidence')
            report = Path(tmp) / 'report.txt'
            marker = Path(tmp) / 'archive-called'
            expression = f'IMAGE_FILE="{image.as_posix()}"; REPORT_FILE="{report.as_posix()}"; INITIAL_HASH=invalid; OUTPUT_DIR="{Path(tmp).as_posix()}"; RUN_USER=root; zip() {{ touch "{marker.as_posix()}"; }}; finish_analysis'
            result = self.evaluate(expression)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_missing_image_is_rejected(self):
        result = self.evaluate('choose_image /portfolio-nonexistent-image.img')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('File not found', result.stdout)
