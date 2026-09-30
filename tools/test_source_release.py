"""Exercise release publication gates without calling GitHub or creating tags."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / '.github/workflows/release.yml').read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\n          PY', 1)[0]
CODE = compile(textwrap.dedent(SOURCE), 'release-workflow', 'exec')


class SourceReleaseTests(unittest.TestCase):
    def execute(self, version='v0.9.0', status='success', changelog=True, tag='revision'):
        runs = [{'path': f'.github/workflows/{name}', 'id': index, 'status': 'completed',
                 'conclusion': status} for index, name in enumerate(('murmur.yml', 'build.yml'))]
        def run(command, **kwargs):
            if command[:3] == ['git', 'rev-parse', '--verify']:
                return subprocess.CompletedProcess(command, 0 if tag else 1, stdout=(tag or '') + '\n')
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                Path('CHANGELOG.md').write_text('## v0.9.0\n\nChanges.\n\n## v0.8.0\nOld.\n' if changelog else '## Unreleased\nChanges.\n')
                with patch.dict(os.environ, {'RELEASE_VERSION': version, 'GITHUB_SHA': 'revision',
                                             'GITHUB_REPOSITORY': 'owner/repo'}), \
                     patch('subprocess.check_output', return_value=json.dumps({'workflow_runs': runs}).encode()), \
                     patch('subprocess.run', side_effect=run) as calls:
                    try:
                        exec(CODE, {})
                    except SystemExit:
                        self.assertFalse(any(call.args[0][:3] == ['gh', 'release', 'create'] for call in calls.call_args_list))
                        raise
                    notes = Path('release-notes.md').read_text()
                    return calls.call_args_list, notes
            finally:
                os.chdir(previous)

    def test_only_checked_revision_and_numbered_notes_are_published(self):
        calls, notes = self.execute()
        command = calls[-1].args[0]
        self.assertEqual(command[:4], ['gh', 'release', 'create', 'v0.9.0'])
        self.assertEqual(command[command.index('--target') + 1], 'revision')
        self.assertIn('Changes.', notes)
        self.assertNotIn('Old.', notes)
        self.assertNotIn('--attach', command)

    def test_rejects_invalid_version(self):
        with self.assertRaises(SystemExit):
            self.execute(version='v1; echo bad')

    def test_rejects_failed_checks(self):
        with self.assertRaises(SystemExit):
            self.execute(status='failure')

    def test_rejects_missing_numbered_changelog(self):
        with self.assertRaises(SystemExit):
            self.execute(changelog=False)

    def test_never_moves_existing_tag(self):
        with self.assertRaises(SystemExit):
            self.execute(tag='another-revision')

    def test_can_create_new_tag_at_checked_revision(self):
        calls, _ = self.execute(tag=None)
        self.assertEqual(calls[-1].args[0][:3], ['gh', 'release', 'create'])


if __name__ == '__main__':
    unittest.main()
