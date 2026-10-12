#!/usr/bin/env python3
"""Compare feature-disabled firmware load images against an explicit Git baseline.

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

# name -> (package, features). Feature-disabled builds must match the baseline byte for byte.
PROFILES = {
    'standard': ('caliptra-runtime', 'emu,riscv'),
    'fmc': ('caliptra-fmc', 'emu,riscv'),
    'rom': ('caliptra-rom', 'emu,riscv'),
    # Without emu, matching production builds where cprintln! compiles away.
    'standard_noemu': ('caliptra-runtime', 'riscv'),
    'fmc_noemu': ('caliptra-fmc', 'riscv'),
    'rom_noemu': ('caliptra-rom', 'riscv'),
    'no_mldsa': ('caliptra-runtime', 'emu,riscv,no-mldsa'),
    'software_psk': ('caliptra-runtime', 'emu,riscv,no-mldsa,fhe-psk'),
    # Registered APP_FHE_PSK_ML_CLEAR image used by the default protected tests.
    'software_psk_ml_clear': ('caliptra-runtime', 'emu,riscv,no-mldsa,fhe-psk,ml-clear'),
}
DEFAULT_PROFILES = ['rom', 'fmc', 'standard', 'rom_noemu', 'fmc_noemu', 'standard_noemu']


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--current', type=Path, default=ROOT, help='Optional staged source tree; Git baselines still come from this repository')
    parser.add_argument('--profiles', nargs='+', choices=sorted(PROFILES), default=DEFAULT_PROFILES,
                        help='Default: ROM/FMC/runtime with and without emu. The no_mldsa/software_psk profiles '
                             'need a baseline that already has those features (8efce033 does not)')
    args = parser.parse_args()
    current = args.current.resolve()
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents or out == current or current in out.parents:
        parser.error('--out must be outside the source tree')
    out.mkdir(parents=True, exist_ok=True)
    base = out / 'baseline'
    base.mkdir()  # Refuse to mix this run with a stale snapshot.
    revision = git('rev-parse', args.baseline + '^{commit}').decode().strip()
    with tarfile.open(fileobj=io.BytesIO(git('archive', revision))) as archive:
        archive.extractall(base)
    def snapshot_dependencies(repo, rev, destination):
        # Use each baseline's pinned sources without changing any live checkout.
        for line in subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-r', rev]).decode().splitlines():
            metadata, path = line.split('\t')
            mode, _, oid = metadata.split()
            if mode != '160000':
                continue
            dest = destination / path
            dest.mkdir(parents=True, exist_ok=True)
            data = subprocess.check_output(['git', '-C', str(repo / path), 'archive', oid])
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.extractall(dest)
            snapshot_dependencies(repo / path, oid, dest)
    snapshot_dependencies(ROOT, revision, base)
    config = current / '.cargo/config.toml'
    base_config = base / '.cargo/config.toml'
    # This repository stores target flags as a literal string array.
    flags = ast.literal_eval(re.search(r'rustflags\s*=\s*(\[[\s\S]*?\])', config.read_text()).group(1))
    baseline_flags = ast.literal_eval(re.search(r'rustflags\s*=\s*(\[[\s\S]*?\])', base_config.read_text()).group(1))
    if flags != baseline_flags:
        raise RuntimeError('Rust target flags differ; normalize explicitly before comparison')
    if config.read_bytes() != base_config.read_bytes():
        raise RuntimeError('Cargo configuration differs; compare build settings explicitly')
    flags += [f'--remap-path-prefix={current}=/caliptra-sw', f'--remap-path-prefix={base}=/caliptra-sw']
    env = os.environ.copy()
    if env.get('RUSTFLAGS') or env.get('CARGO_ENCODED_RUSTFLAGS'):
        raise RuntimeError('unset custom Rust flags for this controlled comparison')
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    profiles = {name: PROFILES[name] for name in args.profiles}
    report = {'baseline': revision, 'current_source': str(current), 'artifact': 'firmware objcopy -O binary; package recorded per profile',
              'pinned_baseline_dependencies': True,
              'cargo_config_identical': True,
              'profiles': {}}
    for name, (package, features) in profiles.items():
        images = []
        for side, source in [('baseline', base), ('current', current)]:
            # Separate Cargo targets prevent remapped paths reusing stale build-script output.
            env['CARGO_TARGET_DIR'] = str(out / ('target-' + side))
            log_path = out / f'{name}-{side}.log'
            with log_path.open('w') as log:
                rc = subprocess.run(['cargo', 'build', '--offline', '--profile', 'firmware', '--target', TARGET,
                                     '--no-default-features', '-p', package, '--bin', package,
                                     '--features', features], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
            if rc != 0:
                raise SystemExit(f'ERROR: {side} build of profile {name} ({package} {features}) failed; see {log_path}')
            image = out / f'{name}-{side}.bin'
            subprocess.run(['riscv64-unknown-elf-objcopy', '-O', 'binary',
                            str(Path(env['CARGO_TARGET_DIR']) / TARGET / 'firmware' / package), str(image)], check=True)
            images.append(image.read_bytes())
        result = {'package': package, 'features': features, 'identical': images[0] == images[1],
                  'bytes': [len(x) for x in images], 'sha256': [hashlib.sha256(x).hexdigest() for x in images]}
        report['profiles'][name] = result
        (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name, result, flush=True)
    if not all(x['identical'] for x in report['profiles'].values()):
        changed = [name for name, x in report['profiles'].items() if not x['identical']]
        raise SystemExit('FAIL: feature-disabled firmware changed: ' + ', '.join(changed))


if __name__ == '__main__':
    main()
