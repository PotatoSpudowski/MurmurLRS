import hashlib
import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest

from build_pair import build_environment, bundle_role, profile_config, validate_output


class PairBuildTests(unittest.TestCase):
    def test_requires_explicit_pair_phrase(self):
        with self.assertRaises(ValueError):
            build_environment({'MY_BINDING_PHRASE': 'ignored'}, 'ISM_2400')

    def test_environment_drops_upload_and_bench_settings(self):
        env = build_environment({'PATH': '/bin', 'MURMUR_BINDING_PHRASE': 'private',
                                 'MURMUR_WIFI_PASSWORD': 'separate',
                                 'MURMUR_BENCH_FREERUN': '1', 'ELRS_UNIFIED_CONFIG': 'old',
                                 'PLATFORMIO_BUILD_FLAGS': '-DMURMUR_LINK_DIAGNOSTICS',
                                 'PLATFORMIO_UPLOAD_PORT': '/dev/device'}, 'ISM_2400')
        self.assertEqual(env, {'PATH': '/bin', 'MURMUR_BINDING_PHRASE': 'private',
                               'MURMUR_WIFI_PASSWORD': 'separate',
                               'PLATFORMIO_BUILD_FLAGS': '-DRegulatory_Domain_ISM_2400'})

    def test_rejects_in_repo_or_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for output in (root, root / 'private'):
                with self.assertRaises(ValueError):
                    validate_output(output, root)
            with self.assertRaises(ValueError):
                validate_output(root, root / 'repo')

    def test_private_bundle_with_exact_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'firmware.bin').write_bytes(b'secret-bearing-firmware')
            (source / 'key.h').write_text('must not be copied')
            destination = root / 'tx'
            files = bundle_role(source, destination)
            self.assertEqual(files, [{'file': 'firmware.bin', 'sha256': hashlib.sha256(b'secret-bearing-firmware').hexdigest()}])
            self.assertFalse((destination / 'key.h').exists())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / 'firmware.bin').stat().st_mode & 0o777, 0o600)

    def test_missing_firmware_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'bootloader.bin').write_bytes(b'boot')
            with self.assertRaises(ValueError):
                bundle_role(source, root / 'rx')

    def test_compressed_esp8285_image_has_plain_wired_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            image = b'configured-encrypted-esp8285-image'
            (source / 'firmware.bin.gz').write_bytes(gzip.compress(image))
            destination = root / 'rx'
            files = bundle_role(source, destination)
            self.assertEqual((destination / 'firmware.bin').read_bytes(), image)
            self.assertEqual({item['file'] for item in files}, {'firmware.bin', 'firmware.bin.gz'})
            self.assertEqual((destination / 'firmware.bin').stat().st_mode & 0o777, 0o600)

    def test_rejects_wrong_target_or_role_or_missing_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            hardware = Path(directory)
            (hardware / 'targets.json').write_text(json.dumps({'vendor': {'rx': {
                'firmware': 'Unified_ESP8285_2400_RX', 'layout_file': 'board.json'}}}))
            (hardware / 'RX').mkdir()
            (hardware / 'RX/board.json').write_text('{}')
            profile_config(hardware, 'vendor.rx', 'Unified_ESP8285_2400_RX_via_WIFI', 'rx')
            for target, role in [('Unified_ESP32_2400_RX_via_WIFI', 'rx'),
                                 ('Unified_ESP8285_2400_RX_via_WIFI', 'tx')]:
                with self.assertRaises(ValueError):
                    profile_config(hardware, 'vendor.rx', target, role)
            (hardware / 'RX/board.json').unlink()
            with self.assertRaises(ValueError):
                profile_config(hardware, 'vendor.rx', 'Unified_ESP8285_2400_RX_via_WIFI', 'rx')


if __name__ == '__main__':
    unittest.main()
