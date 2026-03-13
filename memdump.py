#!/usr/bin/env python3
"""
memdump.py — ADB Memory Dumper + ELF Fixer (All-in-One)
========================================================
Dumps a .so library from a running Android app's memory via ADB,
then optionally rebuilds ELF section headers for IDA analysis.

Requirements: Python 3.7+, ADB connected to a rooted Android device.

Usage:
  python memdump.py com.example.app libUE4.so                        # dump only
  python memdump.py com.example.app libUE4.so --fix                   # dump + fix
  python memdump.py com.example.app libUE4.so -o out.bin --fix        # custom output
  python memdump.py com.example.app libUE4.so --fix --stop            # SIGSTOP during dump
  python memdump.py com.example.app libUE4.so --segments              # each region separate
  python memdump.py --fix-only dumped.bin 0x740004D000 fixed.so      # fix existing dump
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PART 1 — ADB MEMORY DUMPER                                               ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

TEMP_DIR = "/data/local/tmp/_memdump"
ADB = "adb"


def adb(*args, check=True, timeout=300):
    r = subprocess.run(
        [ADB] + list(args), capture_output=True, text=True, timeout=timeout
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"ADB failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout.strip()


def adb_root(cmd_str, check=True, timeout=300):
    r = subprocess.run(
        [ADB, "shell", "su", "-c", cmd_str],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"su -c failed: {cmd_str}\n{r.stderr.strip()}")
    return r.stdout.strip()


def get_pid(package):
    print(f"[*] Looking up PID for: {package}")
    out = adb_root(f"pidof {package}", check=False)
    if out:
        pid = int(out.split()[0])
        print(f"[+] PID: {pid}")
        return pid
    out = adb_root("ps -A")
    for line in out.splitlines():
        if package in line:
            parts = line.split()
            try:
                pid = int(parts[1])
                print(f"[+] PID (via ps): {pid}")
                return pid
            except (IndexError, ValueError):
                continue
    raise RuntimeError(f"Process '{package}' not found. Is the app running?")


def parse_maps(pid, lib_name):
    print(f"[*] Reading /proc/{pid}/maps")
    raw = adb_root(f"cat /proc/{pid}/maps")
    if not raw:
        raise RuntimeError(f"Cannot read /proc/{pid}/maps")
    regions = []
    pat = re.compile(
        r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxsp-]+)\s+"
        r"[0-9a-fA-F]+\s+\S+\s+\d+\s+(.*)$"
    )
    for line in raw.splitlines():
        m = pat.match(line.strip())
        if m and lib_name in m.group(4).strip():
            regions.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    if not regions:
        raise RuntimeError(f"'{lib_name}' not found in memory maps.")
    return regions


def plan_chunks(regions, chunk_size):
    chunks = []
    for ri, (start, end, _) in enumerate(regions):
        off = 0
        while off < end - start:
            csz = min(chunk_size, end - start - off)
            chunks.append((ri, start + off, csz, off))
            off += csz
    return chunks


def dump_chunk_dd(pid, addr, size, out_path):
    cmd = (
        f"dd if=/proc/{pid}/mem of={out_path} "
        f"bs=4096 iflag=skip_bytes,count_bytes "
        f"skip={addr} count={size} 2>/dev/null"
    )
    try:
        adb_root(cmd, check=False, timeout=60)
        stat = adb_root(f"stat -c %s {out_path} 2>/dev/null", check=False, timeout=10)
        return stat and stat.isdigit() and int(stat) > 0
    except subprocess.TimeoutExpired:
        return False


def dump_all(pid, regions, chunk_size, stop_process=False):
    chunks = plan_chunks(regions, chunk_size)
    total_bytes = sum(c[2] for c in chunks)
    total_chunks = len(chunks)

    adb_root(f"mkdir -p {TEMP_DIR}", check=False)

    if stop_process:
        print(f"[*] SIGSTOP → PID {pid}")
        adb_root(f"kill -STOP {pid}")

    region_data = {ri: bytearray(e - s) for ri, (s, e, _) in enumerate(regions)}
    done_bytes = 0
    failed = 0
    t0 = time.time()

    print(
        f"\n[*] Dumping {total_chunks} chunks ({total_bytes / 1024 / 1024:.1f} MB)...\n"
    )

    for ci, (ri, addr, csz, off_in_region) in enumerate(chunks):
        remote = f"{TEMP_DIR}/c{ci:04d}.bin"
        local_tmp = "_tmp_chunk.bin"

        ok = dump_chunk_dd(pid, addr, csz, remote)
        if ok:
            try:
                adb_root(f"chmod 644 {remote}", check=False, timeout=10)
                adb("pull", remote, local_tmp, check=False, timeout=30)
                if os.path.exists(local_tmp):
                    with open(local_tmp, "rb") as f:
                        data = f.read()
                    region_data[ri][off_in_region : off_in_region + len(data)] = data
                    done_bytes += len(data)
                else:
                    failed += 1
            except Exception:
                failed += 1
            finally:
                if os.path.exists(local_tmp):
                    os.remove(local_tmp)
            adb_root(f"rm -f {remote}", check=False, timeout=10)
        else:
            failed += 1
            done_bytes += csz

        elapsed = time.time() - t0
        pct = (ci + 1) / total_chunks * 100
        speed = done_bytes / elapsed / 1024 / 1024 if elapsed > 1 else 0
        sys.stdout.write(
            f"\r    [{ci+1:>4}/{total_chunks}] {pct:5.1f}%  "
            f"{done_bytes/1024/1024:.0f}/{total_bytes/1024/1024:.0f} MB  "
            f"({speed:.1f} MB/s)"
        )
        sys.stdout.flush()

    if stop_process:
        adb_root(f"kill -CONT {pid}", check=False)
        print(f"\n[*] SIGCONT → PID {pid}")

    elapsed = time.time() - t0
    print(
        f"\n[+] Dump complete: {elapsed:.0f}s"
        + (f" ({failed} chunks failed)" if failed else "")
    )
    return region_data


def write_merged(regions, region_data, output_path):
    base = regions[0][0]
    print(f"\n[*] Writing merged output → {output_path}")
    with open(output_path, "wb") as out:
        current = base
        for ri, (start, end, _) in enumerate(regions):
            gap = start - current
            if gap > 0:
                out.write(b"\x00" * gap)
            out.write(region_data.get(ri, b"\x00" * (end - start)))
            current = end
    fsize = os.path.getsize(output_path)
    print(f"[+] Output: {fsize:,} bytes ({fsize/1024/1024:.1f} MB)")


def write_segments(regions, region_data, output_base):
    stem = Path(output_base).stem
    ext = Path(output_base).suffix or ".bin"
    files = []
    for ri, (start, end, perms) in enumerate(regions):
        name = f"{stem}_seg{ri:02d}_{perms.replace('-','')}_0x{start:x}{ext}"
        with open(name, "wb") as f:
            f.write(region_data.get(ri, b"\x00" * (end - start)))
        files.append(name)
    return files


def print_regions(regions, lib_name):
    mapped = sum(e - s for s, e, _ in regions)
    base, top = min(r[0] for r in regions), max(r[1] for r in regions)
    gap = (top - base) - mapped
    print(f"\n[+] {len(regions)} regions for '{lib_name}':")
    print(f"    {'Start':>18}  {'End':>18}  {'Size':>12}  Perms")
    print(f"    {'─'*18}  {'─'*18}  {'─'*12}  ─────")
    for s, e, p in regions:
        print(f"    0x{s:016X}  0x{e:016X}  {e-s:>10,} B  {p}")
    print(f"\n    Mapped : {mapped:>12,} bytes ({mapped/1024/1024:.1f} MB)")
    if gap > 0:
        print(f"    Gaps   : {gap:>12,} bytes ({gap/1024/1024:.1f} MB)")


def cleanup_device():
    adb_root(f"rm -rf {TEMP_DIR}", check=False)
    print("[+] Device cleaned up.")


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  PART 2 — ELF SECTION HEADER FIXER (port of elf-dump-fix/sofix)           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# ELF constants
_ELFCLASS32, _ELFCLASS64 = 1, 2
_PT_LOAD, _PT_DYNAMIC, _PT_LOPROC = 1, 2, 0x70000000
_DT_NULL, _DT_PLTRELSZ, _DT_PLTGOT, _DT_HASH = 0, 2, 3, 4
_DT_STRTAB, _DT_SYMTAB, _DT_RELA, _DT_RELASZ = 5, 6, 7, 8
_DT_RELAENT, _DT_STRSZ, _DT_SYMENT, _DT_INIT = 9, 10, 11, 12
_DT_REL, _DT_RELSZ, _DT_RELENT, _DT_TEXTREL = 17, 18, 19, 22
_DT_JMPREL, _DT_INIT_ARRAY, _DT_FINI_ARRAY = 23, 25, 26
_DT_INIT_ARRAYSZ, _DT_FINI_ARRAYSZ = 27, 28

_SHT_PROGBITS, _SHT_STRTAB, _SHT_HASH = 1, 3, 5
_SHT_DYNAMIC, _SHT_REL, _SHT_DYNSYM = 6, 9, 11
_SHT_RELA, _SHT_LOPROC = 4, 0x70000001

_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 1, 2, 4
_PF_X, _STT_FUNC, _STT_OBJECT, _STT_FILE = 1, 2, 1, 4
_R_ARM_JUMP_SLOT, _R_ARM_RELATIVE = 22, 23
_R_AARCH64_JUMP_SLOT, _R_AARCH64_RELATIVE = 1026, 1027

_SHDRS = 16
_SEC = dict(
    NONE=0,
    DYNSYM=1,
    DYNSTR=2,
    HASH=3,
    RELDYN=4,
    RELPLT=5,
    PLT=6,
    TEXT=7,
    ARMEXIDX=8,
    FINIARRAY=9,
    INITARRAY=10,
    DYNAMIC=11,
    GOT=12,
    DATA=13,
    BSS=14,
    STRTAB=15,
)

_SHSTRTAB_SEARCH = (
    "\0\0.dynsym\0.dynstr\0.hash\0.rel.dyn\0.rel.plt\0.plt\0"
    ".text\0.ARM.exidx\0.fini_array\0.init_array\0.dynamic\0"
    ".got\0.data\0.bss\0.shstrtab\0.rela.dyn\0.rela.plt\0"
)
_SHSTRTAB_BYTES = (
    b"\0.dynsym\0.dynstr\0.hash\0.rel.dyn\0.rel.plt\0.plt\0"
    b".text\0.ARM.exidx\0.fini_array\0.init_array\0.dynamic\0"
    b".got\0.data\0.bss\0.shstrtab\0.rela.dyn\0.rela.plt\0"
)


def _sn(name):
    """Get offset of section name in shstrtab."""
    i = _SHSTRTAB_SEARCH.find(name)
    return i if i >= 0 else 0


def _paddup(v, a):
    return v if v % a == 0 else (v + a) & ~(a - 1)


def _r32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _r64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _rs32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def _rs64(b, o):
    return struct.unpack_from("<q", b, o)[0]


def _w32(b, o, v):
    struct.pack_into("<I", b, o, v & 0xFFFFFFFF)


def _w64(b, o, v):
    struct.pack_into("<Q", b, o, v & 0xFFFFFFFFFFFFFFFF)


def _ra(b, o, is32):
    return _r32(b, o) if is32 else _r64(b, o)


def _wa(b, o, v, is32):
    _w32(b, o, v) if is32 else _w64(b, o, v)


class _Shdr:
    __slots__ = (
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    )

    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, 0)

    def pack(self, is32):
        if is32:
            return struct.pack(
                "<IIIIIIIIII",
                self.sh_name,
                self.sh_type,
                self.sh_flags,
                self.sh_addr & 0xFFFFFFFF,
                self.sh_offset & 0xFFFFFFFF,
                self.sh_size & 0xFFFFFFFF,
                self.sh_link,
                self.sh_info,
                self.sh_addralign,
                self.sh_entsize,
            )
        return struct.pack(
            "<IIQQQQIIqq",
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize,
        )


def fix_elf(src_path, out_path, base_addr):
    """
    Rebuild ELF section headers from a memory dump.
    Port of elf-dump-fix/sofix by maiyao1988.
    Returns True on success.
    """
    with open(src_path, "rb") as f:
        buf = bytearray(f.read())
    flen = len(buf)

    if buf[0:4] != b"\x7fELF":
        print("[!] Not an ELF file!")
        return False

    is32 = buf[4] == _ELFCLASS32
    print(f"[*] ELF class: {'ELF32' if is32 else 'ELF64'}")

    S = _SEC
    addr_sz = 4 if is32 else 8
    dyn_esz = 8 if is32 else 16
    rel_esz = 8 if is32 else 24
    sym_esz = 16 if is32 else 24
    shdr_sz = 40 if is32 else 64

    # ── Parse ELF header ──
    if is32:
        e_phoff = _r32(buf, 28)
        e_phnum = struct.unpack_from("<H", buf, 44)[0]
        ehdr_sz = 52
    else:
        e_phoff = _r64(buf, 32)
        e_phnum = struct.unpack_from("<H", buf, 56)[0]
        ehdr_sz = 64

    # ── Parse program headers ──
    ph_sz = 32 if is32 else 56

    class PH:
        __slots__ = (
            "p_type",
            "p_flags",
            "p_offset",
            "p_vaddr",
            "p_paddr",
            "p_filesz",
            "p_memsz",
            "p_align",
            "_off",
        )

        def __init__(self, off):
            self._off = off
            if is32:
                self.p_type = _r32(buf, off)
                self.p_offset = _r32(buf, off + 4)
                self.p_vaddr = _r32(buf, off + 8)
                self.p_paddr = _r32(buf, off + 12)
                self.p_filesz = _r32(buf, off + 16)
                self.p_memsz = _r32(buf, off + 20)
                self.p_flags = _r32(buf, off + 24)
                self.p_align = _r32(buf, off + 28)
            else:
                self.p_type = _r32(buf, off)
                self.p_flags = _r32(buf, off + 4)
                self.p_offset = _r64(buf, off + 8)
                self.p_vaddr = _r64(buf, off + 16)
                self.p_paddr = _r64(buf, off + 24)
                self.p_filesz = _r64(buf, off + 32)
                self.p_memsz = _r64(buf, off + 40)
                self.p_align = _r64(buf, off + 48)

        def write_back(self):
            o = self._off
            if is32:
                struct.pack_into(
                    "<IIIIIIII",
                    buf,
                    o,
                    self.p_type,
                    self.p_offset,
                    self.p_vaddr,
                    self.p_paddr,
                    self.p_filesz,
                    self.p_memsz,
                    self.p_flags,
                    self.p_align,
                )
            else:
                struct.pack_into(
                    "<IIQQQQQQ",
                    buf,
                    o,
                    self.p_type,
                    self.p_flags,
                    self.p_offset,
                    self.p_vaddr,
                    self.p_paddr,
                    self.p_filesz,
                    self.p_memsz,
                    self.p_align,
                )

    phdrs = [PH(e_phoff + i * ph_sz) for i in range(e_phnum)]

    # ── Find bias ──
    bias = 0
    for ph in phdrs:
        if ph.p_type == _PT_LOAD:
            bias = ph.p_vaddr
            break
    print(f"[*] Load bias: 0x{bias:X}")

    # ── Init section headers ──
    sh = [_Shdr() for _ in range(_SHDRS)]

    # ── Fix PHDRs and collect info ──
    last_load = None
    load_idx = 0
    dyn_off = 0
    dyn_size = 0

    for ph in phdrs:
        ph.p_vaddr -= bias
        ph.p_paddr = ph.p_vaddr
        ph.p_offset = ph.p_vaddr
        ph.p_filesz = ph.p_memsz

        if ph.p_type == _PT_LOAD:
            load_idx += 1
            if ph.p_vaddr > 0 and load_idx == 2:
                last_load = ph
        elif ph.p_type == _PT_DYNAMIC:
            sh[S["DYNAMIC"]].sh_name = _sn(".dynamic")
            sh[S["DYNAMIC"]].sh_type = _SHT_DYNAMIC
            sh[S["DYNAMIC"]].sh_flags = _SHF_WRITE | _SHF_ALLOC
            sh[S["DYNAMIC"]].sh_addr = sh[S["DYNAMIC"]].sh_offset = ph.p_vaddr
            sh[S["DYNAMIC"]].sh_size = ph.p_memsz
            sh[S["DYNAMIC"]].sh_link = S["DYNSTR"]
            sh[S["DYNAMIC"]].sh_addralign = addr_sz
            sh[S["DYNAMIC"]].sh_entsize = dyn_esz
            dyn_off = ph.p_vaddr
            dyn_size = ph.p_memsz
        elif ph.p_type in (_PT_LOPROC, _PT_LOPROC + 1):
            sh[S["ARMEXIDX"]].sh_name = _sn(".ARM.exidx")
            sh[S["ARMEXIDX"]].sh_type = _SHT_LOPROC
            sh[S["ARMEXIDX"]].sh_flags = _SHF_ALLOC
            sh[S["ARMEXIDX"]].sh_addr = sh[S["ARMEXIDX"]].sh_offset = ph.p_vaddr
            sh[S["ARMEXIDX"]].sh_size = ph.p_memsz
            sh[S["ARMEXIDX"]].sh_link = 7
            sh[S["ARMEXIDX"]].sh_addralign = addr_sz
            sh[S["ARMEXIDX"]].sh_entsize = 8
        ph.write_back()

    if dyn_off == 0:
        print("[!] No PT_DYNAMIC — cannot rebuild sections")
        return False

    # ── Walk dynamic section ──
    got_addr = 0
    n_syms = 0

    def _dyn_read(off):
        if is32:
            return _rs32(buf, off), _r32(buf, off + 4)
        return _rs64(buf, off), _r64(buf, off + 8)

    def _dyn_wval(off, v):
        if is32:
            _w32(buf, off + 4, v)
        else:
            _w64(buf, off + 8, v)

    for i in range(dyn_size // dyn_esz):
        o = dyn_off + i * dyn_esz
        if o + dyn_esz > flen:
            break
        tag, val = _dyn_read(o)
        if tag == _DT_NULL:
            break

        if tag == _DT_SYMTAB:
            val -= bias
            _dyn_wval(o, val)
            sh[S["DYNSYM"]].sh_name = _sn(".dynsym")
            sh[S["DYNSYM"]].sh_type = _SHT_DYNSYM
            sh[S["DYNSYM"]].sh_flags = _SHF_ALLOC
            sh[S["DYNSYM"]].sh_addr = sh[S["DYNSYM"]].sh_offset = val
            sh[S["DYNSYM"]].sh_link = 2
            sh[S["DYNSYM"]].sh_info = 1
            sh[S["DYNSYM"]].sh_addralign = addr_sz
        elif tag == _DT_SYMENT:
            sh[S["DYNSYM"]].sh_entsize = val
        elif tag == _DT_STRTAB:
            val -= bias
            _dyn_wval(o, val)
            sh[S["DYNSTR"]].sh_name = _sn(".dynstr")
            sh[S["DYNSTR"]].sh_type = _SHT_STRTAB
            sh[S["DYNSTR"]].sh_flags = _SHF_ALLOC
            sh[S["DYNSTR"]].sh_addr = sh[S["DYNSTR"]].sh_offset = val
            sh[S["DYNSTR"]].sh_addralign = 1
        elif tag == _DT_STRSZ:
            sh[S["DYNSTR"]].sh_size = val
        elif tag == _DT_HASH:
            val -= bias
            _dyn_wval(o, val)
            sh[S["HASH"]].sh_name = _sn(".hash")
            sh[S["HASH"]].sh_type = _SHT_HASH
            sh[S["HASH"]].sh_flags = _SHF_ALLOC
            sh[S["HASH"]].sh_addr = sh[S["HASH"]].sh_offset = val
            sh[S["HASH"]].sh_link = S["DYNSYM"]
            sh[S["HASH"]].sh_addralign = addr_sz
            sh[S["HASH"]].sh_entsize = 4
            if val + 8 <= flen:
                nb, nc = _r32(buf, val), _r32(buf, val + 4)
                sh[S["HASH"]].sh_size = (nb + nc + 2) * 4
                n_syms = nc
        elif tag in (_DT_REL, _DT_RELA):
            val -= bias
            _dyn_wval(o, val)
            sh[S["RELDYN"]].sh_flags = _SHF_ALLOC
            sh[S["RELDYN"]].sh_addr = sh[S["RELDYN"]].sh_offset = val
            sh[S["RELDYN"]].sh_link = S["DYNSYM"]
            sh[S["RELDYN"]].sh_addralign = addr_sz
            if tag == _DT_REL:
                sh[S["RELDYN"]].sh_name = _sn(".rel.dyn")
                sh[S["RELDYN"]].sh_type = _SHT_REL
            else:
                sh[S["RELDYN"]].sh_name = _sn(".rela.dyn")
                sh[S["RELDYN"]].sh_type = _SHT_RELA
        elif tag in (_DT_RELSZ, _DT_RELASZ):
            sh[S["RELDYN"]].sh_size = val
        elif tag in (_DT_RELENT, _DT_RELAENT):
            sh[S["RELPLT"]].sh_entsize = sh[S["RELDYN"]].sh_entsize = val
        elif tag == _DT_JMPREL:
            val -= bias
            _dyn_wval(o, val)
            sh[S["RELPLT"]].sh_flags = _SHF_ALLOC
            sh[S["RELPLT"]].sh_addr = sh[S["RELPLT"]].sh_offset = val
            sh[S["RELPLT"]].sh_link = S["DYNSYM"]
            sh[S["RELPLT"]].sh_info = S["PLT"]
            sh[S["RELPLT"]].sh_addralign = addr_sz
            if is32:
                sh[S["RELPLT"]].sh_name = _sn(".rel.plt")
                sh[S["RELPLT"]].sh_type = _SHT_REL
            else:
                sh[S["RELPLT"]].sh_name = _sn(".rela.plt")
                sh[S["RELPLT"]].sh_type = _SHT_RELA
        elif tag == _DT_PLTRELSZ:
            sh[S["RELPLT"]].sh_size = val
        elif tag == _DT_PLTGOT:
            val -= bias
            _dyn_wval(o, val)
            got_addr = val
            sh[S["GOT"]].sh_name = _sn(".got")
            sh[S["GOT"]].sh_type = _SHT_PROGBITS
            sh[S["GOT"]].sh_flags = _SHF_WRITE | _SHF_ALLOC
            sh[S["GOT"]].sh_addr = sh[S["DYNAMIC"]].sh_addr + sh[S["DYNAMIC"]].sh_size
            sh[S["GOT"]].sh_offset = sh[S["GOT"]].sh_addr
            sh[S["GOT"]].sh_addralign = addr_sz
        elif tag == _DT_FINI_ARRAY:
            val -= bias
            _dyn_wval(o, val)
            sh[S["FINIARRAY"]].sh_name = _sn(".fini_array")
            sh[S["FINIARRAY"]].sh_type = 15
            sh[S["FINIARRAY"]].sh_flags = _SHF_WRITE | _SHF_ALLOC
            sh[S["FINIARRAY"]].sh_addr = sh[S["FINIARRAY"]].sh_offset = val
            sh[S["FINIARRAY"]].sh_addralign = addr_sz
        elif tag == _DT_FINI_ARRAYSZ:
            sh[S["FINIARRAY"]].sh_size = val
        elif tag == _DT_INIT_ARRAY:
            val -= bias
            _dyn_wval(o, val)
            sh[S["INITARRAY"]].sh_name = _sn(".init_array")
            sh[S["INITARRAY"]].sh_type = 14
            sh[S["INITARRAY"]].sh_flags = _SHF_WRITE | _SHF_ALLOC
            sh[S["INITARRAY"]].sh_addr = sh[S["INITARRAY"]].sh_offset = val
            sh[S["INITARRAY"]].sh_addralign = addr_sz
        elif tag == _DT_INIT_ARRAYSZ:
            sh[S["INITARRAY"]].sh_size = val
        elif tag == _DT_INIT:
            print(f"    .init at 0x{val:X}")
        elif tag == _DT_TEXTREL:
            print("    Warning: DT_TEXTREL (address-dependent)")

    # ── .got / .data sizes ──
    relplt_n = (
        sh[S["RELPLT"]].sh_size // sh[S["RELPLT"]].sh_entsize
        if sh[S["RELPLT"]].sh_entsize
        else 0
    )

    if got_addr:
        got_base = sh[S["GOT"]].sh_addr
        ge = 4 if is32 else 8
        got_end = got_addr + ge * (relplt_n + 3)
        t = got_end & ~0xFFF
        if got_addr < t:
            got_end = t

        if last_load:
            sh[S["DATA"]].sh_name = _sn(".data")
            sh[S["DATA"]].sh_type = _SHT_PROGBITS
            sh[S["DATA"]].sh_flags = _SHF_WRITE | _SHF_ALLOC
            sh[S["DATA"]].sh_addr = sh[S["DATA"]].sh_offset = _paddup(got_end, 0x1000)
            de = last_load.p_vaddr + last_load.p_memsz
            if de > sh[S["DATA"]].sh_addr:
                sh[S["DATA"]].sh_size = de - sh[S["DATA"]].sh_addr
            sh[S["DATA"]].sh_addralign = addr_sz

        if got_end > got_base:
            sh[S["GOT"]].sh_size = got_end - got_base
        else:
            sh[S["GOT"]].sh_addr = sh[S["GOT"]].sh_offset = got_addr
            sh[S["GOT"]].sh_size = got_end - got_addr

    # ── Detect dynsym count ──
    if n_syms == 0 and sh[S["DYNSYM"]].sh_addr and sh[S["DYNSTR"]].sh_addr:
        print("[*] No DT_HASH, detecting dynsym count...")
        so, ss, se = (
            sh[S["DYNSYM"]].sh_addr,
            sh[S["DYNSTR"]].sh_addr,
            sh[S["DYNSTR"]].sh_addr + sh[S["DYNSTR"]].sh_size,
        )
        c = 0
        while so + c * sym_esz + sym_esz <= flen:
            n = _r32(buf, so + c * sym_esz)
            if ss + n < ss or ss + n > se:
                break
            c += 1
        n_syms = c
        print(f"    Detected {n_syms} symbols")

    # ── Fix symbol types ──
    if n_syms and sh[S["DYNSYM"]].sh_addr:
        for i in range(n_syms):
            eo = sh[S["DYNSYM"]].sh_addr + i * sym_esz
            if eo + sym_esz > flen:
                break
            io = eo + (12 if is32 else 4)
            st = buf[io]
            if (st & 0xF) > _STT_FILE:
                bind = st & 0xF0
                sv = _r32(buf, eo + 4) if is32 else _r64(buf, eo + 8)
                nt = _STT_FUNC if sv == 0 else _STT_OBJECT
                if sv:
                    for ph in phdrs:
                        if ph.p_vaddr < sv < ph.p_vaddr + ph.p_memsz:
                            if ph.p_flags & _PF_X:
                                nt = _STT_FUNC
                            break
                buf[io] = bind | nt

    sh[S["DYNSYM"]].sh_size = n_syms * sym_esz

    # ── .plt / .text ──
    pa = 4 if is32 else 16
    pe = 12 if is32 else 16
    sh[S["PLT"]].sh_name = _sn(".plt")
    sh[S["PLT"]].sh_type = _SHT_PROGBITS
    sh[S["PLT"]].sh_flags = _SHF_ALLOC | _SHF_EXECINSTR
    ps = sh[S["RELPLT"]].sh_addr + sh[S["RELPLT"]].sh_size
    sh[S["PLT"]].sh_addr = sh[S["PLT"]].sh_offset = _paddup(ps, pa)
    sh[S["PLT"]].sh_size = _paddup(20 + pe * relplt_n, pa)
    sh[S["PLT"]].sh_addralign = pa

    if sh[S["ARMEXIDX"]].sh_addr:
        sh[S["TEXT"]].sh_name = _sn(".text")
        sh[S["TEXT"]].sh_type = _SHT_PROGBITS
        sh[S["TEXT"]].sh_flags = _SHF_ALLOC | _SHF_EXECINSTR
        sh[S["TEXT"]].sh_addr = sh[S["TEXT"]].sh_offset = (
            sh[S["PLT"]].sh_addr + sh[S["PLT"]].sh_size
        )
        ts = sh[S["ARMEXIDX"]].sh_addr - sh[S["TEXT"]].sh_addr
        if ts > 0:
            sh[S["TEXT"]].sh_size = ts

    sh[S["STRTAB"]].sh_name = _sn(".shstrtab")
    sh[S["STRTAB"]].sh_type = _SHT_STRTAB
    sh[S["STRTAB"]].sh_size = len(_SHSTRTAB_BYTES)
    sh[S["STRTAB"]].sh_addralign = 1

    # ── Fix relocation bias ──
    def _fix_rels(addr, size, esz):
        if not addr or not size or not esz:
            return
        for i in range(size // esz):
            o = addr + i * esz
            if o + esz > flen:
                break
            ro = _ra(buf, o, is32)
            ri = _r32(buf, o + 4) if is32 else _r64(buf, o + 8)
            rt = (ri & 0xFF) if is32 else (ri & 0xFFFFFFFF)
            if rt in (
                _R_ARM_JUMP_SLOT,
                _R_ARM_RELATIVE,
                _R_AARCH64_JUMP_SLOT,
                _R_AARCH64_RELATIVE,
            ):
                if ro > 0:
                    _wa(buf, o, ro - bias, is32)

    _fix_rels(
        sh[S["RELDYN"]].sh_addr, sh[S["RELDYN"]].sh_size, sh[S["RELDYN"]].sh_entsize
    )
    _fix_rels(
        sh[S["RELPLT"]].sh_addr, sh[S["RELPLT"]].sh_size, sh[S["RELPLT"]].sh_entsize
    )

    # ── Fix dynsym bias ──
    if n_syms and sh[S["DYNSYM"]].sh_addr:
        for i in range(n_syms):
            eo = sh[S["DYNSYM"]].sh_addr + i * sym_esz
            if eo + sym_esz > flen:
                break
            vo = eo + (4 if is32 else 8)
            sv = _ra(buf, vo, is32)
            if sv > 0:
                _wa(buf, vo, sv - bias, is32)

    # ── Fix R_*_RELATIVE pointed values ──
    rd = sh[S["RELDYN"]]
    if rd.sh_addr and rd.sh_size and rd.sh_entsize:
        for i in range(rd.sh_size // rd.sh_entsize):
            o = rd.sh_addr + i * rd.sh_entsize
            if o + rd.sh_entsize > flen:
                break
            ro = _ra(buf, o, is32)
            ri = _r32(buf, o + 4) if is32 else _r64(buf, o + 8)
            rt = (ri & 0xFF) if is32 else (ri & 0xFFFFFFFF)
            if rt in (_R_ARM_RELATIVE, _R_AARCH64_RELATIVE) and ro < flen:
                pv = _ra(buf, ro, is32)
                if pv > base_addr:
                    _wa(buf, ro, pv - base_addr, is32)

    # ── Write output ──
    ss = len(_SHSTRTAB_BYTES)
    # Patch ELF header
    if is32:
        _w32(buf, 24, base_addr)  # e_entry
        _w32(buf, 32, flen + ss)  # e_shoff
        struct.pack_into("<HHH", buf, 46, shdr_sz, _SHDRS, _SHDRS - 1)
    else:
        _w64(buf, 24, base_addr)
        _w64(buf, 40, flen + ss)
        struct.pack_into("<HHH", buf, 58, shdr_sz, _SHDRS, _SHDRS - 1)

    sh[S["STRTAB"]].sh_offset = flen

    with open(out_path, "wb") as fw:
        fw.write(buf[:flen])
        fw.write(_SHSTRTAB_BYTES)
        for s in sh:
            fw.write(s.pack(is32))

    print(f"[+] Fixed ELF: {out_path} ({os.path.getsize(out_path):,} bytes)")
    return True


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  MAIN                                                                     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝


def main():
    parser = argparse.ArgumentParser(
        description="memdump — ADB memory dumper + ELF fixer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python memdump.py com.example.app libUE4.so --fix\n"
            "  python memdump.py com.example.app libUE4.so -o out.bin --fix --stop\n"
            "  python memdump.py --fix-only dumped.bin 0x740004D000 fixed.so\n"
        ),
    )
    # Fix-only mode (no ADB needed)
    parser.add_argument(
        "--fix-only",
        nargs=3,
        metavar=("DUMP", "BASE_HEX", "OUTPUT"),
        help="Fix an existing dump without ADB: --fix-only <dump> <base_hex> <output>",
    )
    # Normal mode
    parser.add_argument(
        "package", nargs="?", help="Package name (e.g. com.example.app)"
    )
    parser.add_argument("library", nargs="?", help="Library name (e.g. libUE4.so)")
    parser.add_argument("-o", "--output", default=None, help="Output file path")
    parser.add_argument("--fix", action="store_true", help="Fix ELF headers after dump")
    parser.add_argument(
        "--segments", action="store_true", help="Save each region separately"
    )
    parser.add_argument(
        "--stop", action="store_true", help="SIGSTOP process during dump"
    )
    parser.add_argument(
        "--chunk-mb", type=float, default=2.0, help="Chunk size in MB (default: 2)"
    )

    args = parser.parse_args()

    # ── Fix-only mode ──
    if args.fix_only:
        src, base_hex, out = args.fix_only
        base = int(base_hex, 16)
        print(f"[*] Fix-only mode: {src} → {out} (base=0x{base:X})")
        ok = fix_elf(src, out, base)
        sys.exit(0 if ok else 1)

    # ── Normal mode — need package + library ──
    if not args.package or not args.library:
        parser.print_help()
        sys.exit(1)

    output = args.output
    if output is None:
        output = args.library.replace(".so", "").replace(".", "_") + "_dump.bin"

    chunk_size = int(args.chunk_mb * 1024 * 1024)

    print("=" * 60)
    print("  memdump — ADB Memory Dumper + ELF Fixer")
    print("=" * 60)
    print(f"  Package : {args.package}")
    print(f"  Library : {args.library}")
    print(f"  Output  : {output}")
    print(f"  Fix ELF : {'yes' if args.fix else 'no'}")
    print("=" * 60)

    t0 = time.time()

    try:
        print("\n[*] Checking ADB...")
        devs = adb("devices")
        if "device" not in devs.split("\n", 1)[-1]:
            raise RuntimeError("No device connected.")
        print("[+] Device connected.")

        pid = get_pid(args.package)
        regions = parse_maps(pid, args.library)
        print_regions(regions, args.library)

        region_data = dump_all(pid, regions, chunk_size, stop_process=args.stop)

        if args.segments:
            files = write_segments(regions, region_data, output)
            print(f"\n[+] {len(files)} segment files saved.")
        else:
            write_merged(regions, region_data, output)

        # Auto-fix
        if args.fix and not args.segments:
            base_addr = regions[0][0]
            stem = Path(output).stem
            fix_out = f"{stem}_fixed.so"
            print(f"\n{'─'*60}")
            print(f"[*] Fixing ELF headers (base=0x{base_addr:X})...")
            fix_elf(output, fix_out, base_addr)

        cleanup_device()

        elapsed = time.time() - t0
        total = sum(e - s for s, e, _ in regions)
        speed = total / elapsed / 1024 / 1024 if elapsed > 0 else 0
        print(f"\n{'='*60}")
        print(f"  Done in {elapsed:.0f}s ({speed:.1f} MB/s)")
        print(f"{'='*60}")

    except RuntimeError as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        cleanup_device()
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        cleanup_device()
        sys.exit(130)


if __name__ == "__main__":
    main()
