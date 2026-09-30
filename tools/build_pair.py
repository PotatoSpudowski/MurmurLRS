#!/usr/bin/env python3
"""Build a private TX/RX bundle from a committed revision; never flash devices."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def build_environment(original, domain):
    phrase = original.get('MURMUR_BINDING_PHRASE')
    if not phrase:
        raise ValueError('Set MURMUR_BINDING_PHRASE in the environment')
    env = {name: value for name, value in original.items()
           if not name.startswith(('MURMUR_', 'PLATFORMIO_', 'ELRS_'))}
    env['MURMUR_BINDING_PHRASE'] = phrase
    if 'MURMUR_WIFI_PASSWORD' in original:
        env['MURMUR_WIFI_PASSWORD'] = original['MURMUR_WIFI_PASSWORD']
    env['PLATFORMIO_BUILD_FLAGS'] = f'-DRegulatory_Domain_{domain}'
    return env


def validate_output(output, root=ROOT):
    output = output.resolve()
    root = root.resolve()
    if output == root or root in output.parents:
        raise ValueError('Choose an output directory outside the repository')
    if output.exists():
        raise ValueError('Output directory already exists; choose a new directory')
    return output


def profile_config(hardware, profile, target, role):
    config = json.loads((hardware / 'targets.json').read_text())
    for part in profile.split('.'):
        config = config[part]
    expected = target.split('_via_')[0]
    if config['firmware'] != expected or f'_{role.upper()}' not in expected:
        raise ValueError(f'{role} profile does not match its firmware target')
    layout = hardware / role.upper() / config['layout_file']
    if not layout.is_file():
        raise ValueError(f'{role} hardware layout is missing')
    return config


def bundle_role(source, destination):
    destination.mkdir(mode=0o700)
    files = []
    artifacts = sorted(list(source.glob('*.bin')) + list(source.glob('*.bin.gz')))
    for artifact in artifacts:
        copied = destination / artifact.name
        shutil.copyfile(artifact, copied)
        copied.chmod(0o600)
        files.append({'file': copied.name, 'sha256': hashlib.sha256(copied.read_bytes()).hexdigest()})
    compressed = destination / 'firmware.bin.gz'
    plain = destination / 'firmware.bin'
    if compressed.is_file() and not plain.exists():
        with gzip.open(compressed, 'rb') as firmware:
            plain.write_bytes(firmware.read())
        plain.chmod(0o600)
        files.append({'file': plain.name, 'sha256': hashlib.sha256(plain.read_bytes()).hexdigest()})
    if not any(item['file'] == 'firmware.bin' for item in files):
        raise ValueError('Build produced no firmware.bin')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ('tx', 'rx'):
        parser.add_argument(f'--{role}-target', required=True)
        parser.add_argument(f'--{role}-profile', required=True)
    parser.add_argument('--domain', required=True, choices=['ISM_2400', 'EU_CE_2400', 'FCC_915', 'EU_868', 'IN_866'])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--pio', default=str(ROOT / 'venv/bin/pio'))
    args = parser.parse_args()
    try:
        output = validate_output(args.output)
        env = build_environment(os.environ, args.domain)
        if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT):
            raise ValueError('Commit tracked changes before building a pair')
        hardware = ROOT / 'src/hardware'
        for role in ('tx', 'rx'):
            profile_config(hardware, getattr(args, f'{role}_profile'), getattr(args, f'{role}_target'), role)
        pio = shutil.which(args.pio)
        if not pio:
            raise ValueError('PlatformIO executable not found; use --pio PATH')
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        os.umask(0o077)
        output.mkdir(parents=True, mode=0o700)
        manifest = {'revision': revision, 'domain': args.domain,
                    'platformio': subprocess.check_output([pio, '--version'], text=True).strip(),
                    'wifi_management': bool(env.get('MURMUR_WIFI_PASSWORD')), 'roles': {}}
        with tempfile.TemporaryDirectory(prefix='murmurlrs-pair-') as directory:
            checkout = Path(directory) / 'source'
            subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(ROOT), str(checkout)], check=True)
            subprocess.run(['git', 'checkout', '--quiet', '--detach', revision], cwd=checkout, check=True)
            shutil.copytree(hardware, checkout / 'src/hardware', ignore=shutil.ignore_patterns('.git'))
            for role in ('tx', 'rx'):
                target = getattr(args, f'{role}_target')
                profile = getattr(args, f'{role}_profile')
                env['ELRS_UNIFIED_CONFIG'] = profile
                with (output / f'{role}-build.log').open('w') as log:
                    subprocess.run([pio, 'run', '-e', target], cwd=checkout / 'src', env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
                files = bundle_role(checkout / 'src/.pio/build' / target, output / role)
                config = profile_config(hardware, profile, target, role)
                shutil.copyfile(hardware / role.upper() / config['layout_file'], output / role / 'hardware.json')
                files.append({'file': 'hardware.json', 'sha256': hashlib.sha256((output / role / 'hardware.json').read_bytes()).hexdigest()})
                manifest['roles'][role] = {'target': target, 'profile': profile, 'files': files}
                print(f'{role.upper()} built successfully')
            shutil.copyfile(checkout / 'src/lua/elrs.lua', output / 'elrs.lua')
            manifest['lua_sha256'] = hashlib.sha256((output / 'elrs.lua').read_bytes()).hexdigest()
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(f'Private pair ready: {output}\nNo devices were flashed. Keep this bundle private; firmware contains keys.')
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Pair build failed ({type(error).__name__}); no complete bundle published. Check inputs or private build logs.\n')


if __name__ == '__main__':
    main()
