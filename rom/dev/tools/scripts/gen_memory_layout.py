#!/usr/bin/env python3
"""Generate memory layout files for Caliptra with configurable ICCM/DCCM sizes.

Strategy: position NSTACK/ESTACK/STACK from the TOP of DCCM downward.
PersistentData size is NOT computed here — the Rust compiler handles it
via size_of::<PersistentData>() and will catch mismatches at compile time.

Files patched:
    - drivers/src/memory_layout.rs  (ICCM_SIZE, DCCM_SIZE, STACK_SIZE, ROM_STACK_SIZE)
    - rom/dev/src/rom.ld            (addresses + sizes)
    - rom/dev/tools/test-fmc/src/fmc.ld  (addresses + sizes)
    - rom/dev/tools/test-rt/src/rt.ld    (addresses + sizes)
    - common/src/lib.rs             (FMC_SIZE / RUNTIME_SIZE, only if --lib-fmc-kb given)

Usage:
    # Verify defaults produce no changes:
    python3 gen_memory_layout.py --dry-run

    # Minimal demo (32K ICCM, 128K DCCM):
    python3 gen_memory_layout.py --iccm-kb 32 --dccm-kb 128 \\
        --fmc-kb 8 --rt-kb 24 \\
        --total-stack-kb 10 --rom-stack-kb 10 --fmc-rt-stack-kb 10 \\
        --lib-fmc-kb 8 --lib-rt-kb 24
"""

import argparse
import os
import re
import sys

# Fixed addresses
ICCM_ORG = 0x40000000
DCCM_ORG = 0x50000000
ESTACK_SIZE_KB = 1
NSTACK_SIZE_KB = 1


def compute_layout(args):
    """Compute all addresses from the top of DCCM down."""
    dccm_end = DCCM_ORG + args.dccm_kb * 1024

    # Top of DCCM: NSTACK then ESTACK
    nstack_org = dccm_end - NSTACK_SIZE_KB * 1024
    estack_org = nstack_org - ESTACK_SIZE_KB * 1024

    # ROM stack: sits just below ESTACK in rom.ld
    # (rom.ld STACK_SIZE = rom_stack_kb, positioned below ESTACK)
    rom_stack_org = estack_org - args.rom_stack_kb * 1024

    # FMC/RT stack: also just below ESTACK in fmc.ld/rt.ld
    fmc_rt_stack_org = estack_org - args.fmc_rt_stack_kb * 1024

    # ICCM partitioning
    rt_org = ICCM_ORG + args.fmc_kb * 1024

    return {
        'dccm_end': dccm_end,
        'nstack_org': nstack_org,
        'estack_org': estack_org,
        'rom_stack_org': rom_stack_org,
        'fmc_rt_stack_org': fmc_rt_stack_org,
        'rt_org': rt_org,
    }


def validate(args, L):
    """Sanity checks."""
    errors = []
    if L['rom_stack_org'] < DCCM_ORG:
        errors.append(f"ROM stack underflows DCCM: 0x{L['rom_stack_org']:08X}")
    if L['fmc_rt_stack_org'] < DCCM_ORG:
        errors.append(f"FMC/RT stack underflows DCCM: 0x{L['fmc_rt_stack_org']:08X}")
    if args.fmc_kb + args.rt_kb > args.iccm_kb:
        errors.append(f"FMC ({args.fmc_kb}K) + RT ({args.rt_kb}K) > ICCM ({args.iccm_kb}K)")
    if args.rom_stack_kb > args.total_stack_kb:
        errors.append(f"ROM_STACK ({args.rom_stack_kb}K) > total STACK ({args.total_stack_kb}K)")

    # Warn if ICCM is too small for common/lib.rs FMC_SIZE+RUNTIME_SIZE defaults
    # (36K + 146K = 182K) but user didn't provide --lib-fmc-kb to override
    DEFAULT_LIB_FMC_KB = 36
    DEFAULT_LIB_RT_KB = 146
    if args.lib_fmc_kb is None and args.iccm_kb < DEFAULT_LIB_FMC_KB + DEFAULT_LIB_RT_KB:
        errors.append(
            f"ICCM ({args.iccm_kb}K) < common/lib.rs FMC_SIZE+RUNTIME_SIZE "
            f"({DEFAULT_LIB_FMC_KB}K+{DEFAULT_LIB_RT_KB}K = {DEFAULT_LIB_FMC_KB + DEFAULT_LIB_RT_KB}K). "
            f"You must pass --lib-fmc-kb and --lib-rt-kb to resize them.")

    return errors


def print_layout(args, L):
    """Print human-readable summary with ASCII memory map diagrams."""
    iccm_end = ICCM_ORG + args.iccm_kb * 1024
    rt_end = L['rt_org'] + args.rt_kb * 1024
    fmc_end = ICCM_ORG + args.fmc_kb * 1024
    iccm_unused = args.iccm_kb - args.fmc_kb - args.rt_kb

    print(f"=== Memory Layout: ICCM={args.iccm_kb}KB, DCCM={args.dccm_kb}KB ===")
    print()

    # --- ICCM diagram ---
    #   --fmc-kb           --rt-kb
    #   |                  |
    #   v                  v
    print("  ICCM (instruction memory — code runs here)")
    print(f"  --fmc-kb={args.fmc_kb}        --rt-kb={args.rt_kb}")
    print()
    print(f"  0x{ICCM_ORG:08X} ┌─────────────────────────────────┐")
    print(f"               │  test-fmc code     ({args.fmc_kb:>3d} KB)     │  ICCM_SIZE in fmc.ld")
    print(f"  0x{fmc_end:08X} ├─────────────────────────────────┤")
    print(f"               │  test-rt  code     ({args.rt_kb:>3d} KB)     │  ICCM_SIZE in rt.ld")
    if iccm_unused > 0:
        print(f"  0x{rt_end:08X} ├─────────────────────────────────┤")
        print(f"               │  (unused)          ({iccm_unused:>3d} KB)     │")
    print(f"  0x{iccm_end:08X} └─────────────────────────────────┘")
    print()

    # --- DCCM diagram ---
    #   Compute the "DATA+STACK" middle region that depends on PersistentData
    #   We show ROM view and FMC/RT view side by side conceptually
    pd_org = 0x50000400
    # The gap between PersistentData end and the stacks is DATA + STACK in
    # memory_layout.rs. We can't know PD size, so show it as "~113 KB (Rust)"
    print("  DCCM (data memory — stacks, persistent state)")
    print(f"  --total-stack-kb={args.total_stack_kb}  --rom-stack-kb={args.rom_stack_kb}  --fmc-rt-stack-kb={args.fmc_rt_stack_kb}")
    print()
    print(f"  0x{DCCM_ORG:08X} ┌─────────────────────────────────┐")
    print(f"               │  Header (CFI, boot status) 1 KB  │  (fixed, not configurable)")
    print(f"  0x{pd_org:08X} ├─────────────────────────────────┤")
    print(f"               │  PersistentData    (~113 KB)     │  size_of::<PersistentData>()")
    print(f"               │  (manifests, certs, DPE, etc.)   │  (determined by Rust compiler)")
    print(f"               ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤")
    print(f"               │  DATA (relaxation ptrs, residual)│  DATA_SIZE (auto-computed)")
    print(f"               │  must be >= 2 KB                 │  = DCCM - PD - header - stacks")

    # Show the total STACK region from memory_layout.rs perspective
    # STACK_ORG (memory_layout.rs) = DATA_ORG + DATA_SIZE
    # Then within STACK: FMC/RT portion at bottom, ROM portion at top
    fmc_rt_only = args.total_stack_kb - args.rom_stack_kb
    print(f"               ├─────────────────────────────────┤  ← STACK_ORG (memory_layout.rs)")
    if fmc_rt_only > 0:
        print(f"               │  FMC/RT stack      ({fmc_rt_only:>3d} KB)     │  STACK_SIZE - ROM_STACK_SIZE")
    print(f"  0x{L['rom_stack_org']:08X} ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤  ← STACK_ORG in rom.ld")
    print(f"               │  ROM stack         ({args.rom_stack_kb:>3d} KB)     │  --rom-stack-kb")
    print(f"  0x{L['estack_org']:08X} ├─────────────────────────────────┤")
    print(f"               │  ESTACK (exception) ({ESTACK_SIZE_KB:>2d} KB)     │  (fixed)")
    print(f"  0x{L['nstack_org']:08X} ├─────────────────────────────────┤")
    print(f"               │  NSTACK (NMI)       ({NSTACK_SIZE_KB:>2d} KB)     │  (fixed)")
    print(f"  0x{L['dccm_end']:08X} └─────────────────────────────────┘")
    print()

    # --- FMC/RT linker view ---
    print("  FMC/RT linker script view (fmc.ld / rt.ld):")
    print(f"    STACK_ORG  = 0x{L['fmc_rt_stack_org']:08X}  ({args.fmc_rt_stack_kb} KB)  --fmc-rt-stack-kb")
    print(f"    ESTACK_ORG = 0x{L['estack_org']:08X}")
    print(f"    NSTACK_ORG = 0x{L['nstack_org']:08X}")
    print()

    # --- Arg -> file mapping ---
    print("  Argument -> file mapping:")
    print(f"    --iccm-kb={args.iccm_kb:>3d}          -> ICCM_SIZE in memory_layout.rs, rom.ld")
    print(f"    --dccm-kb={args.dccm_kb:>3d}          -> DCCM_SIZE in memory_layout.rs, rom.ld, fmc.ld, rt.ld")
    print(f"    --fmc-kb={args.fmc_kb:>3d}           -> ICCM_SIZE in fmc.ld")
    print(f"    --rt-kb={args.rt_kb:>3d}            -> ICCM_SIZE & ICCM_ORG in rt.ld")
    print(f"    --total-stack-kb={args.total_stack_kb:>3d}  -> STACK_SIZE in memory_layout.rs")
    print(f"    --rom-stack-kb={args.rom_stack_kb:>3d}    -> ROM_STACK_SIZE in memory_layout.rs,")
    print(f"                            STACK_ORG & STACK_SIZE in rom.ld")
    print(f"    --fmc-rt-stack-kb={args.fmc_rt_stack_kb:>2d}  -> STACK_ORG & STACK_SIZE in fmc.ld, rt.ld")
    if args.lib_fmc_kb is not None:
        print(f"    --lib-fmc-kb={args.lib_fmc_kb:>3d}       -> FMC_SIZE in common/lib.rs")
        print(f"    --lib-rt-kb={args.lib_rt_kb:>3d}        -> RUNTIME_SIZE in common/lib.rs")
    print()


def patch_file(path, replacements, dry_run):
    """Apply regex replacements to a file. Returns True if changes were made."""
    with open(path, 'r') as f:
        original = f.read()

    content = original
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content, count=1, flags=re.MULTILINE)

    if content == original:
        print(f"  No changes: {path}")
        return False

    if dry_run:
        # Show what changed
        orig_lines = original.splitlines()
        new_lines = content.splitlines()
        print(f"  Would patch {path}:")
        for i, (ol, nl) in enumerate(zip(orig_lines, new_lines)):
            if ol != nl:
                print(f"    - {ol.strip()}")
                print(f"    + {nl.strip()}")
    else:
        with open(path, 'w') as f:
            f.write(content)
        print(f"  Patched {path}")
    return True


def patch_memory_layout_rs(args, L, repo_root, dry_run):
    """Patch drivers/src/memory_layout.rs — only ICCM_SIZE, DCCM_SIZE, STACK_SIZE, ROM_STACK_SIZE.
    DATA_SIZE is computed automatically by Rust from these + size_of::<PersistentData>()."""
    path = os.path.join(repo_root, "drivers/src/memory_layout.rs")
    patch_file(path, [
        (r'^(pub const ICCM_SIZE: u32 = ).*?;',
         rf'\g<1>{args.iccm_kb} * 1024;'),
        (r'^(pub const DCCM_SIZE: u32 = ).*?;',
         rf'\g<1>{args.dccm_kb} * 1024;'),
        (r'^(pub const STACK_SIZE: u32 = ).*?;',
         rf'\g<1>{args.total_stack_kb} * 1024;'),
        (r'^(pub const ROM_STACK_SIZE: u32 = ).*?;',
         rf'\g<1>{args.rom_stack_kb} * 1024;'),
    ], dry_run)


def patch_rom_ld(args, L, repo_root, dry_run):
    """Patch rom/dev/src/rom.ld.
    rom.ld STACK_ORG = ROM_STACK_ORG (where ROM's stack begins).
    rom.ld STACK_SIZE = ROM_STACK_SIZE (ROM uses only its portion)."""
    path = os.path.join(repo_root, "rom/dev/src/rom.ld")
    patch_file(path, [
        (r'^(STACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["rom_stack_org"]:08X};'),
        (r'^(ESTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["estack_org"]:08X};'),
        (r'^(NSTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["nstack_org"]:08X};'),
        (r'^(ICCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.iccm_kb}K;'),
        (r'^(DCCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.dccm_kb}K;'),
        (r'^(STACK_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.rom_stack_kb}K;'),
    ], dry_run)


def patch_fmc_ld(args, L, repo_root, dry_run):
    """Patch rom/dev/tools/test-fmc/src/fmc.ld.
    DATA_ORG/DATA_SIZE left unchanged — test firmware has no .data/.bss."""
    path = os.path.join(repo_root, "rom/dev/tools/test-fmc/src/fmc.ld")
    patch_file(path, [
        (r'^(STACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["fmc_rt_stack_org"]:08X};'),
        (r'^(ESTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["estack_org"]:08X};'),
        (r'^(NSTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["nstack_org"]:08X};'),
        (r'^(ICCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.fmc_kb}K;'),
        (r'^(DCCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.dccm_kb}K;'),
        (r'^(STACK_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.fmc_rt_stack_kb}K;'),
    ], dry_run)


def patch_rt_ld(args, L, repo_root, dry_run):
    """Patch rom/dev/tools/test-rt/src/rt.ld.
    DATA_ORG/DATA_SIZE left unchanged — test firmware has no .data/.bss."""
    path = os.path.join(repo_root, "rom/dev/tools/test-rt/src/rt.ld")
    patch_file(path, [
        (r'^(ICCM_ORG\s*=\s*).*?;(.*)',
         rf'\g<1>0x{L["rt_org"]:08X}; /* Range [0x40000000 - 0x{L["rt_org"] - 1:08X}] is reserved for FMC */'),
        (r'^(STACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["fmc_rt_stack_org"]:08X};'),
        (r'^(ESTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["estack_org"]:08X};'),
        (r'^(NSTACK_ORG\s*=\s*).*?;',
         rf'\g<1>0x{L["nstack_org"]:08X};'),
        (r'^(ICCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.rt_kb}K;'),
        (r'^(DCCM_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.dccm_kb}K;'),
        (r'^(STACK_SIZE\s*=\s*).*?;',
         rf'\g<1>{args.fmc_rt_stack_kb}K;'),
    ], dry_run)


def patch_common_lib(args, repo_root, dry_run):
    """Patch common/src/lib.rs FMC_SIZE and RUNTIME_SIZE (only if --lib-fmc-kb given)."""
    if args.lib_fmc_kb is None:
        return
    path = os.path.join(repo_root, "common/src/lib.rs")
    patch_file(path, [
        (r'^(pub const FMC_SIZE: u32 = ).*?;(.*)',
         rf'\g<1>{args.lib_fmc_kb} * 1024; // Must be 4k aligned'),
        (r'^(pub const RUNTIME_SIZE: u32 = ).*?;',
         rf'\g<1>{args.lib_rt_kb} * 1024;'),
    ], dry_run)


def main():
    parser = argparse.ArgumentParser(
        description="Patch Caliptra memory layout for custom ICCM/DCCM sizes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify defaults are a no-op:
  python3 gen_memory_layout.py --dry-run

  # Minimal demo (32K ICCM, 128K DCCM):
  python3 gen_memory_layout.py \\
      --iccm-kb 32 --dccm-kb 128 \\
      --fmc-kb 8 --rt-kb 24 \\
      --total-stack-kb 10 --rom-stack-kb 10 --fmc-rt-stack-kb 10 \\
      --lib-fmc-kb 8 --lib-rt-kb 24

  # Full firmware, no-MLDSA (192K ICCM, 192K DCCM):
  python3 gen_memory_layout.py \\
      --iccm-kb 192 --dccm-kb 192 \\
      --fmc-kb 16 --rt-kb 112 \\
      --total-stack-kb 40 --rom-stack-kb 40 --fmc-rt-stack-kb 14 \\
      --lib-fmc-kb 36 --lib-rt-kb 146
""")
    # ICCM / DCCM total sizes
    parser.add_argument("--iccm-kb", type=int, default=256,
                        help="Total ICCM size in KB (default: 256)")
    parser.add_argument("--dccm-kb", type=int, default=256,
                        help="Total DCCM size in KB (default: 256)")

    # ICCM partitioning (test firmware linker scripts)
    parser.add_argument("--fmc-kb", type=int, default=16,
                        help="test-fmc ICCM_SIZE in KB (default: 16)")
    parser.add_argument("--rt-kb", type=int, default=112,
                        help="test-rt ICCM_SIZE in KB (default: 112)")

    # DCCM stack sizes
    parser.add_argument("--total-stack-kb", type=int, default=106,
                        help="STACK_SIZE in memory_layout.rs — total stack region for "
                             "ROM+FMC+RT (default: 106)")
    parser.add_argument("--rom-stack-kb", type=int, default=62,
                        help="ROM_STACK_SIZE — ROM's portion of the stack, also used "
                             "as STACK_SIZE in rom.ld (default: 62)")
    parser.add_argument("--fmc-rt-stack-kb", type=int, default=14,
                        help="FMC/RT STACK_SIZE in fmc.ld/rt.ld (default: 14)")

    # common/lib.rs (optional — only patched if --lib-fmc-kb is given)
    parser.add_argument("--lib-fmc-kb", type=int, default=None,
                        help="FMC_SIZE in common/lib.rs (default: don't change)")
    parser.add_argument("--lib-rt-kb", type=int, default=None,
                        help="RUNTIME_SIZE in common/lib.rs (default: don't change)")

    parser.add_argument("--dry-run", action="store_true",
                        help="Show changes without writing files")
    parser.add_argument("--repo-root", type=str, default=None,
                        help="Path to caliptra-sw repo root (default: auto-detect)")
    args = parser.parse_args()

    # If one lib arg given, require both
    if (args.lib_fmc_kb is None) != (args.lib_rt_kb is None):
        parser.error("--lib-fmc-kb and --lib-rt-kb must be specified together")

    # Auto-detect repo root
    if args.repo_root:
        repo_root = args.repo_root
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.normpath(os.path.join(script_dir, "../../../.."))

    if not os.path.isfile(os.path.join(repo_root, "drivers/src/memory_layout.rs")):
        print(f"ERROR: Cannot find caliptra-sw repo at {repo_root}", file=sys.stderr)
        sys.exit(1)

    L = compute_layout(args)
    errors = validate(args, L)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print_layout(args, L)

    if args.dry_run:
        print("=== Dry run — showing changes ===")
    else:
        print("=== Patching files ===")

    patch_memory_layout_rs(args, L, repo_root, args.dry_run)
    patch_rom_ld(args, L, repo_root, args.dry_run)
    patch_fmc_ld(args, L, repo_root, args.dry_run)
    patch_rt_ld(args, L, repo_root, args.dry_run)
    patch_common_lib(args, repo_root, args.dry_run)

    print()
    if not args.dry_run:
        print("Done. Verify with:")
        print("  cargo test -p caliptra-drivers -- mem_layout")
        print("  make build NO_MLDSA=1")
    else:
        print("No files were modified (dry run).")


if __name__ == "__main__":
    main()
