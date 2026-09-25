"""Read-only Razor catalogue checks; never reports or revokes messages."""
import subprocess
import tempfile
from pathlib import Path
from email import policy
from email.message import EmailMessage
from email_analyzer.engines.base import BaseEngine, EngineResult


class RazorEngine(BaseEngine):
    def __init__(self, command=None, timeout=25):
        self.command = list(command or [])
        self.timeout = timeout

    @property
    def name(self):
        return 'razor'

    def analyze(self, email: EmailMessage) -> EngineResult:
        if not self.command:
            return EngineResult(self.name, 'skipped', error='Razor command not configured')
        try:
            with tempfile.TemporaryDirectory(prefix='email-razor-') as folder:
                path = Path(folder) / 'message.eml'
                path.write_bytes(email.as_bytes(policy=policy.SMTP))
                result = subprocess.run(self.command + [str(path)],
                                        capture_output=True, timeout=self.timeout, shell=False,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired:
            return EngineResult(self.name, 'error', error='Razor check timed out')
        except OSError as exc:
            return EngineResult(self.name, 'error', error=f'Razor unavailable: {type(exc).__name__}')
        if result.returncode not in (0,1):
            return EngineResult(self.name, 'error', error=f'Razor exit code {result.returncode}')
        # A catalogue miss is not evidence of legitimacy; no risk score assigned.
        return EngineResult(self.name, 'ok', details={
            'catalogue_match': result.returncode == 0, 'returncode': result.returncode,
            'note': 'Catalogue membership only; a miss does not establish safety',
        })
