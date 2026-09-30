"""Exercise the actual pre-build script with an isolated SCons environment."""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PYTHON_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PYTHON_DIR))
from murmur_key import derive_key


class BuildEnv(dict):
    def Append(self, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, list):
                self.setdefault(key, []).extend(value)
            else:
                self[key] = value

    def subst(self, value):
        return str(self['build_dir']) if value == '$BUILD_DIR' else value

    def GetOption(self, option):
        return False


class ProvisioningTests(unittest.TestCase):
    def run_build(self, phrase=None, user='', overrides='', flags=None, wifi_password=None):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'user_defines.txt').write_text(user)
            (root / 'super_defines.txt').write_text(overrides)
            env = BuildEnv(BUILD_FLAGS=list(flags or []), PIOENV='Unified_ESP32_2400_TX_via_WIFI',
                           build_dir=root / 'build')
            helper = types.SimpleNamespace(get_git_version=lambda: {'sha': 'test', 'version': 'test'})
            output = io.StringIO()
            previous = Path.cwd()
            variables = {} if phrase is None else {'MURMUR_BINDING_PHRASE': phrase}
            if wifi_password is not None:
                variables['MURMUR_WIFI_PASSWORD'] = wifi_password
            try:
                os.chdir(root)
                with patch.dict(os.environ, variables, clear=True), \
                     patch.dict(sys.modules, {'elrs_helpers': helper}), contextlib.redirect_stdout(output):
                    runpy.run_path(str(PYTHON_DIR / 'build_flags.py'),
                                   init_globals={'Import': lambda _: None, 'env': env})
                header = root / 'build/murmur_key_generated.h'
                wifi_header = root / 'build/murmur_wifi_generated.h'
                env['_wifi_header'] = wifi_header.read_text() if wifi_header.exists() else None
                return env, header.read_text() if header.exists() else None, output.getvalue()
            finally:
                os.chdir(previous)

    def test_stock_build_has_no_key(self):
        env, header, _ = self.run_build()
        self.assertIsNone(header)
        self.assertNotIn('-DMURMUR_ENCRYPT', env['BUILD_FLAGS'])

    def test_stock_build_does_not_provision_wifi_credential(self):
        env, _, _ = self.run_build(wifi_password='a' * 32)
        self.assertIsNone(env['_wifi_header'])

    def test_encrypted_wifi_is_unprovisioned_by_default(self):
        env, _, log = self.run_build(phrase='packet secret')
        self.assertIn('murmur_wifi_password[] = ""', env['_wifi_header'])
        self.assertNotIn('expresslrs', env['_wifi_header'])
        self.assertIn('Wi-Fi management disabled', log)

    def test_wifi_credential_is_separate_and_not_logged_or_in_options(self):
        password = '0123456789abcdef' * 2
        env, key_header, log = self.run_build(phrase='packet secret', wifi_password=password)
        self.assertIn(password, env['_wifi_header'])
        self.assertNotIn(password, log)
        self.assertNotIn(password, str(env['BUILD_FLAGS']))
        self.assertNotIn(password, str(env['OPTIONS_JSON']))
        self.assertNotIn(password, key_header)
        self.assertNotIn('packet secret', env['_wifi_header'])

    def test_wifi_credential_rejects_empty_short_nonhex_and_injection(self):
        for password in ('', 'a' * 31, 'a' * 33, 'g' * 32, 'a' * 31 + '\n', '";inject();//'):
            with self.subTest(length=len(password)), self.assertRaisesRegex(ValueError, '32 random'):
                self.run_build(phrase='packet secret', wifi_password=password)

    def test_wifi_credential_rejects_binding_phrase_reuse(self):
        with self.assertRaisesRegex(ValueError, 'separate'):
            self.run_build(phrase='a' * 32, wifi_password='A' * 32)

    def test_wifi_secret_rejected_in_compiler_flags_or_user_defines(self):
        with self.assertRaisesRegex(ValueError, 'environment'):
            self.run_build(flags=['-DMURMUR_WIFI_PASSWORD="secret"'])
        with self.assertRaisesRegex(ValueError, 'environment'):
            self.run_build(user='-DMURMUR_WIFI_PASSWORD="secret"\n')

    def test_encryption_without_phrase_fails(self):
        for flag in ('-DMURMUR_ENCRYPT', '-DMURMUR_ENCRYPT=1', '-DMURMUR_ENCRYPT=0'):
            with self.assertRaisesRegex(ValueError, 'nonempty'):
                self.run_build(flags=[flag])

    def test_empty_phrase_fails(self):
        with self.assertRaisesRegex(ValueError, 'nonempty'):
            self.run_build(phrase='')

    def test_phrase_in_compiler_flags_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'do not put binding phrases'):
            self.run_build(phrase='valid', flags=['-DMY_BINDING_PHRASE="secret"'])

    def test_environment_and_file_provision_identical_key(self):
        phrase = 'correct horse 🐎 battery staple'
        env, header, log = self.run_build(phrase=phrase)
        other, file_header, _ = self.run_build(user='-DMY_BINDING_PHRASE="' + phrase + '"\n')
        self.assertEqual(header, file_header)
        self.assertEqual(env['OPTIONS_JSON']['uid'], other['OPTIONS_JSON']['uid'])
        self.assertNotIn(phrase, log)
        self.assertNotIn(derive_key(phrase).hex(), log)
        self.assertNotIn(phrase, str(env['BUILD_FLAGS']))
        self.assertNotIn(phrase, header)
        self.assertIn('-DMURMUR_ENCRYPT', env['BUILD_FLAGS'])

    def test_overrides_use_final_phrase(self):
        _, expected, _ = self.run_build(phrase='final')
        _, actual, _ = self.run_build(user='-DMY_BINDING_PHRASE="first"\n',
                                       overrides='-DMY_BINDING_PHRASE="final"\n')
        self.assertEqual(expected, actual)

    def test_full_phrase_not_uid_is_key_input(self):
        phrase = 'a high entropy phrase'
        expected = hashlib.sha256(b'MurmurLRS/packet-key/v1\x00' + phrase.encode()).digest()[:16]
        self.assertEqual(expected, derive_key(phrase))
        self.assertNotEqual(derive_key(phrase), derive_key(phrase + '!'))
        # Even a UID collision must not make the encryption keys collide.
        with patch('hashlib.md5', return_value=types.SimpleNamespace(digest=lambda: bytes(16))):
            a, ka, _ = self.run_build(phrase='first phrase')
            b, kb, _ = self.run_build(phrase='second phrase')
        self.assertEqual(a['OPTIONS_JSON']['uid'], b['OPTIONS_JSON']['uid'])
        self.assertNotEqual(ka, kb)


if __name__ == '__main__':
    unittest.main()
