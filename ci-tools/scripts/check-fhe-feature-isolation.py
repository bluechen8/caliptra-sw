#!/usr/bin/env python3
"""Compare feature-disabled runtime load images against an explicit Git baseline.

Requires the normal firmware toolchain and cached Cargo dependencies. Source paths
are normalized; this compares objcopy binary output, not debug ELF or signed-image
metadata. Output must be outside the source tree. No checkout is modified.
"""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'riscv32imc-unknown-none-elf'


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error('--out must be outside the source tree')
    out.mkdir(parents=True, exist_ok=True)
    base = out / 'baseline'
    base.mkdir()  # Refuse to mix this run with a stale snapshot.
    revision = git('rev-parse', args.baseline + '^{commit}').decode().strip()
    with tarfile.open(fileobj=io.BytesIO(git('archive', revision))) as archive:
        archive.extractall(base)
    for line in git('ls-tree', '-r', revision).decode().splitlines():
        metadata, path = line.split('\t')
        mode, kind, oid = metadata.split()
        if mode != '160000':
            continue
        actual = subprocess.check_output(['git', '-C', str(ROOT / path), 'rev-parse', 'HEAD']).decode().strip()
        if actual != oid:
            raise RuntimeError(f'submodule {path} differs from baseline; use matching dependency checkouts')
        dest = base / path
        if dest.exists():
            dest.rmdir()
        dest.symlink_to(ROOT / path, target_is_directory=True)
    config = ROOT / '.cargo/config.toml'
    if config.read_bytes() != (base / '.cargo/config.toml').read_bytes():
        raise RuntimeError('Cargo configuration differs; compare build settings explicitly')
    # This repository stores target flags as a literal string array.
    flags = ast.literal_eval(re.search(r'rustflags\s*=\s*(\[[\s\S]*?\])', config.read_text()).group(1))
    flags += [f'--remap-path-prefix={ROOT}=/caliptra-sw', f'--remap-path-prefix={base}=/caliptra-sw']
    env = os.environ.copy()
    if env.get('RUSTFLAGS') or env.get('CARGO_ENCODED_RUSTFLAGS'):
        raise RuntimeError('unset custom Rust flags for this controlled comparison')
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    env['CARGO_TARGET_DIR'] = str(out / 'target')
    profiles = {
        'standard': 'emu,riscv',
        'no_mldsa': 'emu,riscv,no-mldsa',
        # Protected profiles are not compared: they change with the protocol by
        # design, and older baselines may lack the current profile features.
    }
    report = {'baseline': revision, 'artifact': 'runtime objcopy -O binary', 'profiles': {}}
    for name, features in profiles.items():
        images = []
        for side, source in [('baseline', base), ('current', ROOT)]:
            with (out / f'{name}-{side}.log').open('w') as log:
                subprocess.run(['cargo', 'build', '--offline', '--profile', 'firmware', '--target', TARGET,
                                '--no-default-features', '-p', 'caliptra-runtime', '--bin', 'caliptra-runtime',
                                '--features', features], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            image = out / f'{name}-{side}.bin'
            subprocess.run(['riscv64-unknown-elf-objcopy', '-O', 'binary',
                            str(out / 'target' / TARGET / 'firmware/caliptra-runtime'), str(image)], check=True)
            images.append(image.read_bytes())
        result = {'features': features, 'identical': images[0] == images[1],
                  'bytes': [len(x) for x in images], 'sha256': [hashlib.sha256(x).hexdigest() for x in images]}
        report['profiles'][name] = result
        (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name, result, flush=True)
    if not all(x['identical'] for x in report['profiles'].values()):
        raise SystemExit('FAIL: feature-disabled runtime changed')


if __name__ == '__main__':
    main()
