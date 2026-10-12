#!/usr/bin/env python3
"""Decode a nias binary fault log into readable records.

The log is a stream of length-prefixed records: a little-endian uint32 length
followed by that many bytes of a compact FaultRecord (see include/nias/record.hh).
Only {module_base, rva} pairs are stored, never symbols, so resolution to
file/line happens here, offline, against the matching PDB/exe.

Usage:
    nias_symbolize.py LOG [--exe PATH] [--symbolizer llvm-symbolizer]

With --exe, each RIP/frame RVA is resolved via llvm-symbolizer (the PDB must sit
next to the exe). Without it, raw module+RVA is printed.
"""

import argparse
import shutil
import struct
import subprocess
import sys

MAGIC = 0x5341494E
VERSION = 1
MAX_FRAMES = 32

# Matches include/nias/record.hh (explicit padding, natural alignment).
HEADER_FMT = "<IHHQIIBBBBIQQQQ16QII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 200
FRAME_FMT = "<QQ"
FRAME_SIZE = struct.calcsize(FRAME_FMT)  # 16

FAULT_CLASS = [
    "access_violation", "illegal_instruction", "divide_by_zero", "int_overflow",
    "misalignment", "stack_overflow", "breakpoint", "cpp_exception", "other",
]
ACTION = [
    "pass_through", "unwind_one", "unwind_to_safepoint", "skip_instruction",
    "stub_redirect", "fast_fail", "terminate",
]
AV_ACCESS = {0: "read", 1: "write", 8: "execute", 0xFF: "n/a"}


def name(table, idx):
    return table[idx] if 0 <= idx < len(table) else f"?{idx}"


def read_records(path):
    with open(path, "rb") as f:
        blob = f.read()
    off, out = 0, []
    while off + 4 <= len(blob):
        (length,) = struct.unpack_from("<I", blob, off)
        off += 4
        if length < HEADER_SIZE or off + length > len(blob):
            break
        out.append(blob[off:off + length])
        off += length
    return out


def parse(rec):
    h = struct.unpack_from(HEADER_FMT, rec, 0)
    d = {
        "magic": h[0], "version": h[1], "frame_count": h[2], "timestamp": h[3],
        "thread_id": h[4], "native_code": h[5], "fault_class": h[6],
        "av_access": h[7], "action": h[8], "insn_length": h[9],
        "fault_address": h[11], "rip": h[12], "rip_module_base": h[13],
        "rip_rva": h[14], "gpr": h[15:31], "eflags": h[31],
    }
    frames = []
    n = min(d["frame_count"], MAX_FRAMES)
    for i in range(n):
        mb, rva = struct.unpack_from(FRAME_FMT, rec, HEADER_SIZE + i * FRAME_SIZE)
        frames.append((mb, rva))
    d["frames"] = frames
    return d


def resolve(symbolizer, exe, rva):
    try:
        out = subprocess.run(
            [symbolizer, "--obj", exe, "--relative-address", f"0x{rva:x}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip().splitlines()
    except (OSError, subprocess.SubprocessError):
        return None
    return out[0] if out else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--exe", help="image with matching PDB for RVA resolution")
    ap.add_argument("--symbolizer", default="llvm-symbolizer")
    args = ap.parse_args()

    sym = None
    if args.exe:
        sym = shutil.which(args.symbolizer)
        if sym is None:
            print(f"warning: {args.symbolizer} not found; printing raw RVAs",
                  file=sys.stderr)

    records = read_records(args.log)
    print(f"{len(records)} record(s) in {args.log}\n")
    for i, raw in enumerate(records):
        r = parse(raw)
        if r["magic"] != MAGIC or r["version"] != VERSION:
            print(f"#{i}: bad magic/version, skipping")
            continue
        print(f"#{i}  {name(FAULT_CLASS, r['fault_class'])}  "
              f"code=0x{r['native_code']:08X}  action={name(ACTION, r['action'])}")
        print(f"     tid={r['thread_id']}  ts={r['timestamp']}  "
              f"insn_len={r['insn_length']}  "
              f"av={AV_ACCESS.get(r['av_access'], '?')}")
        if r["fault_address"]:
            print(f"     fault_address=0x{r['fault_address']:016X}")
        loc = f"base=0x{r['rip_module_base']:X} rva=0x{r['rip_rva']:X}"
        if sym:
            resolved = resolve(sym, args.exe, r["rip_rva"])
            if resolved:
                loc += f"  {resolved}"
        print(f"     rip=0x{r['rip']:016X}  {loc}")
        for depth, (mb, rva) in enumerate(r["frames"]):
            line = f"       [{depth}] base=0x{mb:X} rva=0x{rva:X}"
            if sym:
                resolved = resolve(sym, args.exe, rva)
                if resolved:
                    line += f"  {resolved}"
            print(line)
        print()


if __name__ == "__main__":
    main()
