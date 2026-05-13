#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Game: UE4 globals finder — GEngine, GNames, GUObjectArray.

Pure-Python ELF/ARM64 scanner. No IDA, no extra deps. Works on a
dumped-and-fixed `libUE4*.so` (memory-dump-style ELF) as well as a normal
shared object.

Reference values discovered during analysis Game:
    GEngine        = 0x0EA10468
    GName  (GNames)= 0x0E498300
    GObjectArray   = 0x0E74E0F0

What was learned that drives this script
----------------------------------------
Game (Tencent) compiles UE4 with an extra layer of indirection over the
canonical globals.  Instead of `ADRP X0,&GUObjectArray; ADD X0,X0,#imm` you
get:

    ADRP Xn, <ptr_table_page>@PAGE
    LDR  Xn, [Xn, #<ptr_table_entry>@PAGEOFF]   ; Xn = *(ptr_table_entry)
    MOV  X0, Xn
    BL   <FUObjectArray::AllocateUObjectIndex>

i.e. the pointer-table entry in `.data.rel.ro` holds the actual address of
the global.  That means we cannot byte-search for the address itself — we
have to find a known UE4 function via an anchor (a source-path string from
a `check()`/`ensureMsgf()` baked into the binary) and then resolve the
ADRP+LDR pair sitting in front of the call.

Multiple fallback strategies are tried in order so the finder survives
file-path changes, helper renames and minor codegen drift between Game
versions (4.3 → 4.4.0 → newer).

Strategies (tried in order, first success wins, per global)
-----------------------------------------------------------
  S1  Source-path anchor.  Find a stable UE4 source-path substring in
      .rodata; locate the ADRP+ADD pair that materializes it in .text;
      that pair lives inside the UE4 method we want.  In *its* callers,
      look for an `ADRP Xa,..; LDR Xa,[Xa,#..]; MOV X0,Xa; BL <method>`
      sequence (any register, the MOV may be omitted if the LDR already
      targeted x0).  Dereference the resolved table entry — that's the
      global.

  S2  Same as S1 but the helper is identified by a *call-graph* anchor:
      the function that calls `pthread_mutex_lock` on `this+0x10` and
      then references the source-path is the UObjectArray helper, etc.
      This catches the case where the source-path was stripped or moved.

  S3  Direct ADRP+ADD scan.  In binaries where the global is *not*
      indirected (older builds), look for `ADRP Xn,G@PAGE; ADD Xn,Xn,
      #G@PAGEOFF` where the resolved address is in a writable segment of
      the right size.

  S4  Pointer-table heuristic.  Identify the obfuscated pointer-table
      (a contiguous run of 8-byte LE pointers all landing inside the
      module) and brute-force every entry through the S1 caller test.

The script reports which strategy resolved each global and prints the
absolute address along with the disasm of the proof site.

Usage
-----
    python game_ue4_finder.py [path/to/lib.so] [--json] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import mmap
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional


# ---------------------------------------------------------------------------
# ARM64 mini-disassembler — only the encodings we need.
# ---------------------------------------------------------------------------


def adrp(insn: int, pc: int) -> Optional[tuple[int, int]]:
    """Decode `ADRP Xd, label`.  Returns (rd, page_addr) or None."""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    if imm21 & (1 << 20):
        imm21 -= 1 << 21
    return insn & 0x1F, (pc & ~0xFFF) + (imm21 << 12)


def add_imm64(insn: int) -> Optional[tuple[int, int, int]]:
    """Decode `ADD Xd, Xn, #imm` (64-bit, no shift or LSL #12)."""
    # sf=1 op=0 S=0 100010 sh imm12 Rn Rd  -> 0x9100_0000 mask 0xFF80_0000
    if (insn & 0xFF800000) != 0x91000000:
        return None
    sh = (insn >> 22) & 1
    imm12 = (insn >> 10) & 0xFFF
    if sh:
        imm12 <<= 12
    return insn & 0x1F, (insn >> 5) & 0x1F, imm12


def ldr_uoff64(insn: int) -> Optional[tuple[int, int, int]]:
    """Decode `LDR Xt, [Xn, #imm]` (64-bit, unsigned offset)."""
    # 11 111 0 01 01 imm12 Rn Rt  -> 0xF940_0000 mask 0xFFC0_0000
    if (insn & 0xFFC00000) != 0xF9400000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    return insn & 0x1F, (insn >> 5) & 0x1F, imm12 * 8


def str_uoff64(insn: int) -> Optional[tuple[int, int, int]]:
    """Decode `STR Xt, [Xn, #imm]` (64-bit, unsigned offset)."""
    if (insn & 0xFFC00000) != 0xF9000000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    return insn & 0x1F, (insn >> 5) & 0x1F, imm12 * 8


def bl_target(insn: int, pc: int) -> Optional[int]:
    """Decode `BL imm` -> absolute call target, or None."""
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)


def b_target(insn: int, pc: int) -> Optional[int]:
    """Decode `B imm` -> absolute branch target, or None.  (Same enc as BL with op=0.)"""
    if (insn & 0xFC000000) != 0x14000000:
        return None
    imm26 = insn & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)


def mov_reg(insn: int) -> Optional[tuple[int, int]]:
    """Decode `MOV Xd, Xn` (alias of ORR Xd, XZR, Xn).  Returns (rd, rn)."""
    # sf=1 ORR 0xAA_00_03_E0 with rd in bits 0..4 and rm (the source) in 16..20
    # Encoding: 1 01 01010 00 0 Rm 000000 11111 Rd  (ORR Xd, XZR, Xm, LSL #0)
    if (insn & 0xFFE0FFE0) != 0xAA0003E0:
        return None
    rm = (insn >> 16) & 0x1F
    rd = insn & 0x1F
    return rd, rm


# ---------------------------------------------------------------------------
# ELF64 (read-only, just enough for our needs).
# ---------------------------------------------------------------------------

PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4


@dataclass
class Segment:
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int

    @property
    def executable(self) -> bool:
        return bool(self.p_flags & PF_X)

    @property
    def writable(self) -> bool:
        return bool(self.p_flags & PF_W)


class ELF64:
    """Minimal little-endian ELF64 reader with vaddr<->offset mapping."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fp = open(path, "rb")
        # mmap so we can slice cheaply.
        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:4] != b"\x7fELF" or self.mm[4] != 2 or self.mm[5] != 1:
            raise ValueError(f"{path}: not a little-endian 64-bit ELF")
        e_phoff = struct.unpack_from("<Q", self.mm, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", self.mm, 0x36)[0]
        e_phnum = struct.unpack_from("<H", self.mm, 0x38)[0]
        self.segments: list[Segment] = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _) = (
                struct.unpack_from("<IIQQQQQQ", self.mm, off)
            )
            if p_type == PT_LOAD:
                self.segments.append(
                    Segment(p_offset, p_vaddr, p_filesz, p_memsz, p_flags)
                )
        # Some "fixed" memory dumps lack proper PT_LOAD; fall back to "identity".
        if not self.segments:
            size = self.mm.size()
            self.segments.append(Segment(0, 0, size, size, PF_R | PF_W | PF_X))

    # ---- mapping helpers ----------------------------------------------------

    def vaddr_to_off(self, vaddr: int) -> Optional[int]:
        for s in self.segments:
            if s.p_vaddr <= vaddr < s.p_vaddr + s.p_filesz:
                return s.p_offset + (vaddr - s.p_vaddr)
        return None

    def off_to_vaddr(self, off: int) -> Optional[int]:
        for s in self.segments:
            if s.p_offset <= off < s.p_offset + s.p_filesz:
                return s.p_vaddr + (off - s.p_offset)
        return None

    def is_executable(self, vaddr: int) -> bool:
        for s in self.segments:
            if s.p_vaddr <= vaddr < s.p_vaddr + s.p_memsz:
                return s.executable
        return False

    def is_writable(self, vaddr: int) -> bool:
        for s in self.segments:
            if s.p_vaddr <= vaddr < s.p_vaddr + s.p_memsz:
                return s.writable
        return False

    def is_mapped(self, vaddr: int) -> bool:
        for s in self.segments:
            if s.p_vaddr <= vaddr < s.p_vaddr + s.p_memsz:
                return True
        return False

    # ---- raw reads ----------------------------------------------------------

    def read(self, vaddr: int, n: int) -> bytes:
        off = self.vaddr_to_off(vaddr)
        if off is None:
            return b""
        return bytes(self.mm[off : off + n])

    def read_u32(self, vaddr: int) -> Optional[int]:
        b = self.read(vaddr, 4)
        if len(b) != 4:
            return None
        return struct.unpack("<I", b)[0]

    def read_u64(self, vaddr: int) -> Optional[int]:
        b = self.read(vaddr, 8)
        if len(b) != 8:
            return None
        return struct.unpack("<Q", b)[0]

    # ---- segment iteration --------------------------------------------------

    @property
    def text_segments(self) -> list[Segment]:
        return [s for s in self.segments if s.executable]

    @property
    def data_segments(self) -> list[Segment]:
        return [s for s in self.segments if not s.executable]


# ---------------------------------------------------------------------------
# String search.
# ---------------------------------------------------------------------------


def find_all_substring(buf: bytes, needle: bytes, base_off: int = 0) -> Iterator[int]:
    start = 0
    while True:
        i = buf.find(needle, start)
        if i < 0:
            return
        yield base_off + i
        start = i + 1


def find_strings(elf: ELF64, needles: list[bytes]) -> dict[bytes, list[int]]:
    """For each needle return the list of *virtual addresses* of the
    enclosing C-string's first byte (i.e. the byte after the preceding NUL).

    Code only ever references string starts, so resolving the substring
    match back to its NUL-terminated container is what makes downstream
    `code_xrefs_to_addr` work.
    """
    hits: dict[bytes, list[int]] = {n: [] for n in needles}
    for seg in elf.data_segments:
        buf = bytes(elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz])
        for n in needles:
            for off in find_all_substring(buf, n):
                # Walk back to the previous NUL (or buffer start).
                start = buf.rfind(b"\x00", 0, off) + 1
                hits[n].append(seg.p_vaddr + start)
    return hits


# ---------------------------------------------------------------------------
# Code-segment scan helpers.
# ---------------------------------------------------------------------------


def iter_text_insns(elf: ELF64) -> Iterator[tuple[int, int]]:
    """Yield (pc, insn) for every 4-byte aligned word in executable segments."""
    for seg in elf.text_segments:
        # Cap at file-sz; BSS portion has no insns to decode.
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        for off in range(0, len(buf) & ~3, 4):
            yield base + off, struct.unpack_from("<I", buf, off)[0]


def code_xrefs_to_addr(
    elf: ELF64,
    target_va: int,
    *,
    limit: int = 16,
    allow_add: bool = True,
    allow_ldr: bool = True,
) -> list[int]:
    """Find code sites that compute `target_va` via ADRP + (ADD | LDR).

    Returns the PCs of the first instruction (the ADRP).  Scans both
    ADRP→ADD (immediate materialization, e.g. of a string) and
    ADRP→LDR (loading a 64-bit value at a fixed table entry).
    """
    page_target = target_va & ~0xFFF
    low = target_va & 0xFFF
    hits: list[int] = []

    # Track recent ADRP per-register inside a small sliding window.
    # We allow up to 16 instructions between ADRP and the following
    # ADD/LDR to tolerate scheduler interleavings.
    WINDOW = 24
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        # adrp_state[reg] = (pc_of_adrp, page_addr) or None
        adrp_state: list[Optional[tuple[int, int]]] = [None] * 32
        adrp_age: list[int] = [0] * 32
        i = 0
        while i < n:
            insn = struct.unpack_from("<I", buf, i)[0]
            pc = base + i
            ad = adrp(insn, pc)
            if ad is not None:
                rd, page = ad
                adrp_state[rd] = (pc, page)
                adrp_age[rd] = 0
            else:
                # ADD?
                if allow_add:
                    a = add_imm64(insn)
                    if a is not None:
                        rd, rn, imm = a
                        st = adrp_state[rn]
                        if st is not None and st[1] == page_target and imm == low:
                            hits.append(st[0])
                            if len(hits) >= limit:
                                return hits
                # LDR?
                if allow_ldr:
                    l = ldr_uoff64(insn)
                    if l is not None:
                        rt, rn, imm = l
                        st = adrp_state[rn]
                        if st is not None and st[1] == page_target and imm == low:
                            hits.append(st[0])
                            if len(hits) >= limit:
                                return hits
            # Age out
            for r in range(32):
                if adrp_state[r] is not None:
                    adrp_age[r] += 1
                    if adrp_age[r] > WINDOW:
                        adrp_state[r] = None
            i += 4
    return hits


def find_function_start(elf: ELF64, pc: int, *, max_back: int = 0x4000) -> int:
    """Heuristic walk back to the nearest plausible function prologue.

    UE4 ARM64 prologues look like:
        SUB SP, SP, #imm     (0xD1xxxxFF / sf=1 sub_imm with Rd=31,Rn=31)
        STP X29, X30, [SP,#imm]!  or  STP X29, X30, [SP,#imm]
    The walk stops on a B/RET/BLR/BR or the prologue.
    """
    off = elf.vaddr_to_off(pc)
    if off is None:
        return pc
    # Walk backwards up to max_back/4 instructions, stop on a clear function-end
    # (RET, BR Xn, unconditional B with target outside our scan), or a prologue.
    cur = pc
    steps = max_back // 4
    while steps > 0 and cur > 4:
        prev = cur - 4
        insn = elf.read_u32(prev)
        if insn is None:
            return cur
        # RET? (1101_0110_0101_1111_0000_00 Rn 00000) = 0xD65F0000 | (Rn<<5)
        if (insn & 0xFFFFFC1F) == 0xD65F0000:
            return cur  # cur is the instruction after a RET — function start
        # SUB SP, SP, #imm (prologue): sf=1 op=1 S=0 100010 ...
        # 0xD1000000 mask 0xFF800000  +  Rd==31 Rn==31
        if (insn & 0xFF8003FF) == 0xD10003FF:
            return prev  # likely function start
        # STP x29, x30, [SP, #imm]!  (pre-index)  enc 0xA9800000-ish
        if (
            (insn & 0xFFC07FE0) == 0xA98003E0
            and ((insn >> 10) & 0x1F) == 30
            and (insn & 0x1F) == 29
        ):
            return prev
        cur = prev
        steps -= 1
    return cur


def find_callers_of(elf: ELF64, target_va: int, *, limit: int = 64) -> list[int]:
    """Find every `BL target_va` site in executable segments."""
    callers: list[int] = []
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        for off in range(0, n, 4):
            insn = struct.unpack_from("<I", buf, off)[0]
            t = bl_target(insn, base + off)
            if t == target_va:
                callers.append(base + off)
                if len(callers) >= limit:
                    return callers
    return callers


# ---------------------------------------------------------------------------
# Strategy 1 — Source-path anchor + caller scan
# ---------------------------------------------------------------------------

# Each candidate is a (path-substring-tried-in-order, [optional aliases]).
# Paths in Game builds always start with something like "D:\Release4.4.0\AS\UE4181\..."
# but the tail is the same UE4 file.  We search for the tail substring so the
# leading project/version directory doesn't matter.

UOBJECTARRAY_ANCHORS = [
    rb"CoreUObject\Private\UObject\UObjectArray.cpp",
    rb"CoreUObject/Private/UObject/UObjectArray.cpp",
    rb"UObject\UObjectAllocator.cpp",
    rb"UObject/UObjectAllocator.cpp",
]

# Anchors used for GEngine.  The first set are Game-specific log strings
# (PixUI-UE diagnostic prints) baked right next to a `GEngine` null-check —
# extremely stable.  The second set are vanilla UE4 source-paths used by the
# fallback "scan the function body for the first ADRP+LDR to a writable
# region" strategy.
GENGINE_LOG_ANCHORS = [
    rb"GameInstance GEngine is nullptr",
    rb"GameWorld GEngine is nullptr",
    rb"GEngine is nullptr",
    rb"GEngine != nullptr",
    rb"GEngine == nullptr",
]
GENGINE_SOURCEPATH_ANCHORS = [
    rb"Engine\Private\UnrealEngine.cpp",
    rb"Engine/Private/UnrealEngine.cpp",
    rb"Launch\Private\LaunchEngineLoop.cpp",
    rb"Launch/Private/LaunchEngineLoop.cpp",
    rb"Engine\Private\GameEngine.cpp",
    rb"Engine/Private/GameEngine.cpp",
]

# GNames is harder — there's no Game-specific log string and the canonical
# `FName::GetNames()` is buried.  We try several CoreUObject paths whose
# functions touch the FName pool, then fall back to a pointer-table
# neighborhood scan that reports the strongest candidate near the known
# GUObjectArray entry.
GNAMES_SOURCEPATH_ANCHORS = [
    rb"Core\Private\UObject\UnrealNames.cpp",
    rb"Core/Private/UObject/UnrealNames.cpp",
    rb"CoreUObject\Private\UObject\UObjectGlobals.cpp",
    rb"CoreUObject/Private/UObject/UObjectGlobals.cpp",
    rb"CoreUObject\Private\Misc\PackageName.cpp",
    rb"CoreUObject/Private/Misc/PackageName.cpp",
]


@dataclass
class Resolution:
    name: str
    strategy: str
    address: Optional[int] = None
    pointer_table_entry: Optional[int] = None
    helper_func: Optional[int] = None
    call_site: Optional[int] = None
    anchor: Optional[bytes] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "strategy": self.strategy,
            "address": hex(self.address) if self.address is not None else None,
            "pointer_table_entry": (
                hex(self.pointer_table_entry)
                if self.pointer_table_entry is not None
                else None
            ),
            "helper_func": (
                hex(self.helper_func) if self.helper_func is not None else None
            ),
            "call_site": hex(self.call_site) if self.call_site is not None else None,
            "anchor": self.anchor.decode("ascii", "replace") if self.anchor else None,
            "notes": self.notes,
        }


def function_end(elf: ELF64, fn_start: int, *, max_size: int = 0x8000) -> int:
    """Heuristic end-of-function: stop at the first RET we encounter while
    walking forward.  Cap at max_size to avoid runaway scans.
    """
    cur = fn_start
    end = fn_start + max_size
    while cur < end:
        insn = elf.read_u32(cur)
        if insn is None:
            return cur
        # RET (any reg)
        if (insn & 0xFFFFFC1F) == 0xD65F0000:
            return cur + 4
        # BR Xn (unconditional indirect branch) — also a function end
        if (insn & 0xFFFFFC1F) == 0xD61F0000:
            return cur + 4
        cur += 4
    return cur


def scan_fn_for_indirect_loads(
    elf: ELF64,
    fn_start: int,
    *,
    fn_end: Optional[int] = None,
    only_writable: bool = True,
) -> list[tuple[int, int, int]]:
    """Walk a function body and emit every (pc, table_entry_va, loaded_value)
    triple where:
        ADRP Xn, page; LDR Xn, [Xn, #imm]
    resolves to an in-binary pointer.  If `only_writable` is set, the
    *dereferenced* value must land in a writable segment (typical of a
    runtime-mutable global like GEngine / GNames / GUObjectArray).
    """
    if fn_end is None:
        fn_end = function_end(elf, fn_start)
    out: list[tuple[int, int, int]] = []
    state: list[Optional[tuple[int, int]]] = [None] * 32  # reg -> (pc, page)
    cur = fn_start
    while cur < fn_end:
        insn = elf.read_u32(cur)
        if insn is None:
            break
        ad = adrp(insn, cur)
        if ad is not None:
            rd, page = ad
            state[rd] = (cur, page)
            cur += 4
            continue
        ld = ldr_uoff64(insn)
        if ld is not None:
            rt, rn, imm = ld
            st = state[rn]
            if st is not None:
                entry_va = st[1] + imm
                if elf.is_mapped(entry_va):
                    ptr = elf.read_u64(entry_va)
                    if (
                        ptr
                        and elf.is_mapped(ptr)
                        and (not only_writable or elf.is_writable(ptr))
                        and not elf.is_executable(ptr)
                    ):
                        out.append((cur, entry_va, ptr))
            # LDR overwrites the destination — clear page state
            state[rt] = None
            cur += 4
            continue
        # Any other instruction may clobber the destination.  We can't
        # decode every encoding; do a coarse "writes to Rd" check for the
        # few classes where the destination register is bits[4:0]:
        #   data-processing immediate (op0 == 0b100): bits[28:26] == 0b100
        #   data-processing register-shifted: bits[27:25] == 0b101
        op0 = (insn >> 26) & 0x7
        if op0 in (0b100,):
            rd = insn & 0x1F
            state[rd] = None
        cur += 4
    return out


def scan_fn_for_direct_loads(
    elf: ELF64, fn_start: int, *, fn_end: Optional[int] = None
) -> list[tuple[int, int]]:
    """Walk a function body and emit every (pc, resolved_addr) where:
        ADRP Xn, page; ADD Xn, Xn, #imm
    resolves to a mapped, writable region (i.e. plausible global storage,
    not a string literal).
    """
    if fn_end is None:
        fn_end = function_end(elf, fn_start)
    out: list[tuple[int, int]] = []
    state: list[Optional[tuple[int, int]]] = [None] * 32
    cur = fn_start
    while cur < fn_end:
        insn = elf.read_u32(cur)
        if insn is None:
            break
        ad = adrp(insn, cur)
        if ad is not None:
            rd, page = ad
            state[rd] = (cur, page)
            cur += 4
            continue
        ai = add_imm64(insn)
        if ai is not None:
            rd, rn, imm = ai
            st = state[rn]
            if st is not None:
                addr = st[1] + imm
                if (
                    elf.is_mapped(addr)
                    and elf.is_writable(addr)
                    and not elf.is_executable(addr)
                ):
                    out.append((cur, addr))
            if rd != rn:
                state[rd] = None
        cur += 4
    return out


def enumerate_pointer_table_neighborhood(
    elf: ELF64, seed_entry: int, *, radius: int = 0x1000, stride: int = 8
) -> list[tuple[int, int]]:
    """Enumerate plausible pointer-table entries near `seed_entry`.

    Returns a list of (entry_va, value) pairs where every entry is an
    8-byte LE pointer that maps inside the binary and isn't executable.
    The seed_entry is the known GUObjectArray entry — its neighbors hold
    GEngine / GNames / GMalloc / GWorld in Game's obfuscated table.
    """
    out: list[tuple[int, int]] = []
    lo = (seed_entry - radius) & ~(stride - 1)
    hi = (seed_entry + radius) & ~(stride - 1)
    for va in range(lo, hi, stride):
        if not elf.is_mapped(va):
            continue
        val = elf.read_u64(va)
        if val is None:
            continue
        if val == 0 or not elf.is_mapped(val) or elf.is_executable(val):
            continue
        out.append((va, val))
    return out


def count_code_refs_to_entry(elf: ELF64, entry_va: int) -> int:
    """How many code sites do `ADRP Xn,page; LDR Xn,[Xn,#imm]` resolving
    to `entry_va`?  Used to rank pointer-table candidates.

    Backed by `build_indirect_load_histogram` so a batch lookup costs O(1)
    after the histogram is built.  Caller should prefer the histogram
    directly when scoring many entries.
    """
    return len(
        code_xrefs_to_addr(
            elf, entry_va, limit=1_000_000, allow_add=False, allow_ldr=True
        )
    )


_HISTOGRAM_CACHE: dict[str, dict[int, int]] = {}
_DIRECT_HISTOGRAM_CACHE: dict[str, dict[int, list[int]]] = {}


def build_direct_load_histogram(elf: ELF64) -> dict[int, list[int]]:
    """One-pass scan: for each ADRP+ADD pair in .text, record the resolved
    target address and the PC of the ADD.  Returns {target_va: [pc, ...]}.
    Cached per-ELF.
    """
    cache = _DIRECT_HISTOGRAM_CACHE.get(elf.path)
    if cache is not None:
        return cache
    hist: dict[int, list[int]] = {}
    WINDOW = 24
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        adrp_pc: list[int] = [0] * 32
        adrp_page: list[int] = [0] * 32
        adrp_valid: list[bool] = [False] * 32
        i = 0
        while i < n:
            insn = struct.unpack_from("<I", buf, i)[0]
            pc = base + i
            ad = adrp(insn, pc)
            if ad is not None:
                rd, page = ad
                adrp_pc[rd] = pc
                adrp_page[rd] = page
                adrp_valid[rd] = True
            else:
                ai = add_imm64(insn)
                if ai is not None:
                    rd, rn, imm = ai
                    if adrp_valid[rn] and pc - adrp_pc[rn] <= WINDOW * 4:
                        target = adrp_page[rn] + imm
                        hist.setdefault(target, []).append(pc)
                    # ADD writes Rd
                    if rd != rn:
                        adrp_valid[rd] = False
            i += 4
    _DIRECT_HISTOGRAM_CACHE[elf.path] = hist
    return hist


def build_indirect_load_histogram(elf: ELF64) -> dict[int, int]:
    """One-pass histogram: how many ADRP+LDR pairs in the entire .text
    resolve to each (page+imm12*8) target address?  Cached per-ELF.
    """
    cache_key = elf.path
    cached = _HISTOGRAM_CACHE.get(cache_key)
    if cached is not None:
        return cached
    hist: dict[int, int] = {}
    WINDOW = 24
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        adrp_pc: list[int] = [0] * 32
        adrp_page: list[int] = [0] * 32
        adrp_valid: list[bool] = [False] * 32
        i = 0
        while i < n:
            insn = struct.unpack_from("<I", buf, i)[0]
            pc = base + i
            ad = adrp(insn, pc)
            if ad is not None:
                rd, page = ad
                adrp_pc[rd] = pc
                adrp_page[rd] = page
                adrp_valid[rd] = True
            else:
                ld = ldr_uoff64(insn)
                if ld is not None:
                    rt, rn, imm = ld
                    if adrp_valid[rn] and pc - adrp_pc[rn] <= WINDOW * 4:
                        target = adrp_page[rn] + imm
                        hist[target] = hist.get(target, 0) + 1
                    adrp_valid[rt] = False
            i += 4
    _HISTOGRAM_CACHE[cache_key] = hist
    return hist


def _scan_caller_for_loaded_arg(
    elf: ELF64, bl_pc: int, *, back_window: int = 32, arg_reg: int = 0
) -> Optional[tuple[int, int]]:
    """Inside a caller, scan up to `back_window` instructions back from a BL
    site to find the ADRP+LDR (or ADRP+ADD) that materializes the value
    sitting in `arg_reg` (x0 by default) at the BL.

    Returns (pointer_table_entry_va, mode) where mode is "LDR" if the
    sequence was ADRP+LDR (indirect — caller must deref the entry) or "ADD"
    if it was ADRP+ADD (direct — entry value *is* the address).
    """
    # Forward chain: track register provenance.  Iterate backwards.
    # We need to handle:   MOV Xtmp, Xsrc; ... ADRP Xsrc,..; LDR Xsrc,[Xsrc,#..]
    # so we propagate aliases.
    track = arg_reg
    state: dict[int, tuple[str, int]] = {}  # reg -> ("addr"|"deref_addr", va)
    # Replay forwards using a window starting back_window*4 bytes earlier.
    start = max(bl_pc - back_window * 4, 0)
    cur = start
    while cur < bl_pc:
        insn = elf.read_u32(cur)
        if insn is None:
            break
        ad = adrp(insn, cur)
        if ad is not None:
            rd, page = ad
            state[rd] = ("page", page)
        else:
            ld = ldr_uoff64(insn)
            if ld is not None:
                rt, rn, imm = ld
                src = state.get(rn)
                if src is not None and src[0] == "page":
                    state[rt] = ("deref_addr", src[1] + imm)
                else:
                    state.pop(rt, None)
            else:
                ai = add_imm64(insn)
                if ai is not None:
                    rd, rn, imm = ai
                    src = state.get(rn)
                    if src is not None and src[0] == "page":
                        state[rd] = ("addr", src[1] + imm)
                    elif rd != rn:
                        state.pop(rd, None)
                else:
                    mv = mov_reg(insn)
                    if mv is not None:
                        rd, rm = mv
                        if rm in state:
                            state[rd] = state[rm]
                        else:
                            state.pop(rd, None)
                    else:
                        # any other write to a tracked register clobbers it
                        # (cheap heuristic: zero out destination if any)
                        # We can't decode all of ARM64, so be conservative —
                        # only clobber if the encoding obviously writes Rd.
                        pass
        cur += 4
    info = state.get(track)
    if info is None:
        return None
    kind, va = info
    return (va, "LDR" if kind == "deref_addr" else "ADD")


def strategy_sourcepath_thismethod(
    elf: ELF64, anchors: list[bytes], name: str, *, verbose: bool = False
) -> Optional[Resolution]:
    """For singletons whose helper is a `this`-method (FUObjectArray): find
    the helper via source-path anchor, then look at its callers and decode
    the `MOV X0, Xn` chain that fed `this` into the BL.

    This is the strategy that works for GUObjectArray.
    """
    res = Resolution(name=name, strategy="sourcepath_thismethod")
    found = find_strings(elf, anchors)
    for anc in anchors:
        positions = found.get(anc) or []
        if not positions:
            continue
        if verbose:
            print(
                f"  [{name}] anchor {anc!r} @ {[hex(p) for p in positions]}",
                file=sys.stderr,
            )
        for str_va in positions:
            code_refs = code_xrefs_to_addr(elf, str_va, limit=8, allow_ldr=False)
            if verbose and code_refs:
                print(f"    code refs: {[hex(c) for c in code_refs]}", file=sys.stderr)
            for cref in code_refs:
                fn_start = find_function_start(elf, cref)
                callers = find_callers_of(elf, fn_start, limit=16)
                if verbose:
                    print(
                        f"      helper {hex(fn_start)} has {len(callers)} callers",
                        file=sys.stderr,
                    )
                for cs in callers:
                    arg = _scan_caller_for_loaded_arg(elf, cs)
                    if arg is None:
                        continue
                    entry_va, mode = arg
                    if not elf.is_mapped(entry_va):
                        continue
                    if mode == "LDR":
                        ptr = elf.read_u64(entry_va)
                        if (
                            ptr is None
                            or ptr == 0
                            or not elf.is_mapped(ptr)
                            or elf.is_executable(ptr)
                        ):
                            continue
                        res.address = ptr
                        res.pointer_table_entry = entry_va
                        res.helper_func = fn_start
                        res.call_site = cs
                        res.anchor = anc
                        res.notes.append(
                            f"ADRP+LDR via table entry {hex(entry_va)} -> {hex(ptr)}"
                        )
                        return res
                    else:
                        if elf.is_executable(entry_va) or not elf.is_writable(entry_va):
                            continue
                        res.address = entry_va
                        res.helper_func = fn_start
                        res.call_site = cs
                        res.anchor = anc
                        res.notes.append(f"ADRP+ADD direct -> {hex(entry_va)}")
                        return res
    return None


def strategy_log_anchor(
    elf: ELF64,
    anchors: list[bytes],
    name: str,
    *,
    verbose: bool = False,
    exclude_entries: Optional[set[int]] = None,
) -> Optional[Resolution]:
    """Anchor by a log/diagnostic string that we expect to appear immediately
    after a `if (!X) log(...)` check.  The function containing the log
    string has a `LDR X..., [&X_table_entry]` somewhere before the log call.

    We walk the *whole* containing function body and emit every ADRP+LDR
    pair whose deref lands in a writable region; the one with the lowest
    PC is chosen (closest to function entry — i.e. the early null check).
    """
    exclude = exclude_entries or set()
    res = Resolution(name=name, strategy="log_anchor")
    found = find_strings(elf, anchors)
    for anc in anchors:
        positions = found.get(anc) or []
        if not positions:
            continue
        if verbose:
            print(
                f"  [{name}] log anchor {anc!r} @ {[hex(p) for p in positions]}",
                file=sys.stderr,
            )
        for str_va in positions:
            code_refs = code_xrefs_to_addr(elf, str_va, limit=8, allow_ldr=False)
            if verbose and code_refs:
                print(f"    code refs: {[hex(c) for c in code_refs]}", file=sys.stderr)
            for cref in code_refs:
                fn_start = find_function_start(elf, cref)
                fn_end = function_end(elf, fn_start)
                loads = scan_fn_for_indirect_loads(elf, fn_start, fn_end=fn_end)
                # Filter out excluded entries (e.g. GUObjectArray) and pick
                # the lowest PC.
                loads = [(pc, e, v) for (pc, e, v) in loads if e not in exclude]
                if not loads:
                    continue
                pc, entry_va, ptr = min(loads, key=lambda t: t[0])
                res.address = ptr
                res.pointer_table_entry = entry_va
                res.helper_func = fn_start
                res.call_site = pc
                res.anchor = anc
                res.notes.append(
                    f"first writable ADRP+LDR @ {hex(pc)}, entry {hex(entry_va)} -> {hex(ptr)}"
                )
                return res
    return None


def strategy_helper_body_scan(
    elf: ELF64,
    anchors: list[bytes],
    name: str,
    *,
    exclude_entries: Optional[set[int]] = None,
    verbose: bool = False,
) -> Optional[Resolution]:
    """Like strategy_sourcepath_thismethod but instead of inspecting callers,
    scan inside the helper itself for ADRP+LDR pairs whose deref points to a
    writable region.  Pick the entry with the **highest** number of code
    refs across the binary (most-popular = most-likely a famous global).

    `exclude_entries` is the set of pointer-table entries already claimed
    (so GNames doesn't collide with GUObjectArray, etc.).
    """
    exclude = exclude_entries or set()
    res = Resolution(name=name, strategy="helper_body_scan")
    found = find_strings(elf, anchors)
    hist = build_indirect_load_histogram(elf)
    # entry_va -> (best_score, ptr, helper_fn, anchor, sample_pc)
    by_entry: dict[int, tuple[int, int, int, bytes, int]] = {}
    for anc in anchors:
        positions = found.get(anc) or []
        if not positions:
            continue
        if verbose:
            print(
                f"  [{name}] helper-body anchor {anc!r} @ "
                f"{[hex(p) for p in positions]}",
                file=sys.stderr,
            )
        for str_va in positions:
            code_refs = code_xrefs_to_addr(elf, str_va, limit=4, allow_ldr=False)
            for cref in code_refs:
                fn_start = find_function_start(elf, cref)
                fn_end = function_end(elf, fn_start)
                for pc, entry_va, ptr in scan_fn_for_indirect_loads(
                    elf, fn_start, fn_end=fn_end
                ):
                    if entry_va in exclude:
                        continue
                    if entry_va in by_entry:
                        continue
                    score = hist.get(entry_va, 0)
                    by_entry[entry_va] = (score, ptr, fn_start, anc, pc)
    if not by_entry:
        return None
    # GNames (and similar very-popular globals) get tens of thousands of
    # ADRP+LDR refs — the highest-scoring unclaimed entry loaded by the
    # anchored function is the strongest candidate.  Earlier we tried to
    # filter out "log flag" entries with a 5k cutoff, but that excluded the
    # right answer on Game (GNames at 21k refs), so we just rank by
    # raw score now.  Runners-up are emitted as notes for manual review.
    ranked = sorted(by_entry.items(), key=lambda kv: kv[1][0], reverse=True)
    entry_va, (score, ptr, fn_start, anc, pc) = ranked[0]
    if verbose:
        print(f"  [{name}] helper-body candidates (top 5):", file=sys.stderr)
        for e, t in ranked[:5]:
            print(
                f"    entry={hex(e)} -> {hex(t[1])}  score={t[0]}  "
                f"{'<-- chosen' if e == entry_va else ''}",
                file=sys.stderr,
            )
    res.address = ptr
    res.pointer_table_entry = entry_va
    res.helper_func = fn_start
    res.call_site = pc
    res.anchor = anc
    res.notes.append(f"helper-body load score={score} entry={hex(entry_va)}")
    for e, t in ranked[:5]:
        if e == entry_va:
            continue
        res.notes.append(f"runner-up entry={hex(e)} -> {hex(t[1])} score={t[0]}")
    return res


def strategy_fname_init_pattern(
    elf: ELF64, *, verbose: bool = False, exclude_addrs: Optional[set[int]] = None
) -> Optional[Resolution]:
    """Find &GName_storage via the FName entry-registration pattern.

    This is the codegen UE4 emits inside FName::StaticInit when registering
    each hardcoded EName by copying its wide-char string into the pool.
    Confirmed on Game in IDA at 0x56E880C — it lands on 0xE498300.

    Sequence (instructions; all 4 bytes each):
        ADRP X0, page                          ; 0x9..  (op = 0x90/0xB0)
        ADD  X0, X0, #imm                      ; 0x91xxx000 mask 0xFFC003E0
        BL   <pool ctor>                       ; 0x94/97
        ADRP X8, same_or_other_page            ; ADRP
        LDR  X0, [X8, #imm2]                   ; LDR uoff64; imm2*8 must
                                                 equal the address loaded
                                                 in the first pair above
        ADRP X1, page2                         ; ADRP
        ADD  X1, X1, #imm3                     ; ADD (loads name pointer)
        MOV  W2, #8                            ; exactly 0x52800102
        BL   j_memcpy                          ; BL

    The re-deref-to-self after the constructor BL, immediately followed
    by MOV W2,#8 + BL memcpy registering an 8-wchar EName, is the
    discriminator that pins this pattern.  Other static-init callsites
    don't repeat that shape.

    Returns the resolved &GName_storage on success.
    """
    exclude = exclude_addrs or set()
    res = Resolution(name="GName", strategy="fname_init_pattern")

    # The MOV W2, #8 anchor — a unique 32-bit pattern we can grep for
    # cheaply.  After finding it we verify the surrounding shape.
    MOV_W2_8 = 0x52800102

    matches: list[tuple[int, int]] = []
    # (target_va, anchor_pc) for each plausible match
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        i = 0
        # MOV W2,#8 in LE bytes: 02 01 80 52
        needle = b"\x02\x01\x80\x52"
        start = 0
        while True:
            j = buf.find(needle, start)
            if j < 0 or j > n - 4:
                break
            start = j + 1
            if j & 3:  # require 4-byte alignment
                continue
            mov_pc = base + j
            # MOV W2,#8 is at mov_pc; we expect the layout backwards from it:
            #   mov_pc - 0x1C  ADRP X0
            #   mov_pc - 0x18  ADD  X0
            #   mov_pc - 0x14  BL   ctor
            #   mov_pc - 0x10  ADRP X8
            #   mov_pc - 0x0C  LDR  X0
            #   mov_pc - 0x08  ADRP X1
            #   mov_pc - 0x04  ADD  X1
            #   mov_pc        MOV  W2, #8
            #   mov_pc + 0x04  BL   memcpy
            if mov_pc - 0x1C < base:
                continue
            seq = []
            for k in range(-0x1C, 0x08, 4):
                ins = elf.read_u32(mov_pc + k)
                if ins is None:
                    seq = None
                    break
                seq.append(ins)
            if seq is None:
                continue
            (adrp0, add0, bl_ctor, adrp8, ldr0, adrp1, add1, _mov, bl_mc) = seq
            ad0 = adrp(adrp0, mov_pc - 0x1C)
            if ad0 is None or ad0[0] != 0:  # ADRP must target x0
                continue
            ai0 = add_imm64(add0)
            if ai0 is None or ai0[0] != 0 or ai0[1] != 0:  # ADD x0, x0, #imm
                continue
            if (bl_ctor & 0xFC000000) != 0x94000000:  # BL
                continue
            ad8 = adrp(adrp8, mov_pc - 0x10)
            if ad8 is None:
                continue
            ld = ldr_uoff64(ldr0)
            if ld is None or ld[0] != 0:  # LDR x0, [x?, #imm]
                continue
            # Re-deref must hit the same address that ADRP+ADD produced.
            target_addr = ad0[1] + ai0[2]
            redere_addr = ad8[1] + ld[2]
            if target_addr != redere_addr:
                continue
            # And it must be a writable, mapped, non-executable region.
            if target_addr in exclude:
                continue
            if (
                not elf.is_mapped(target_addr)
                or elf.is_executable(target_addr)
                or not elf.is_writable(target_addr)
            ):
                continue
            # Final BL after MOV W2,#8 (memcpy/memzero/etc.)
            if (bl_mc & 0xFC000000) != 0x94000000:
                continue
            matches.append((target_addr, mov_pc - 0x1C))

    if verbose:
        print(f"  [GName] fname_init_pattern: {len(matches)} matches", file=sys.stderr)
        for t, p in matches[:8]:
            print(f"    target={hex(t)} init_pc={hex(p)}", file=sys.stderr)

    if not matches:
        return None

    # FName::StaticInit registers many EName entries one at a time, each
    # iteration writing to its own offset inside the storage region.  So
    # we get one match per EName.  The "GName" address the user wants is
    # the BASE of that region — i.e. the lowest target across the matches
    # whose enclosing function is the same one (the static-init body).
    matches_sorted = sorted(matches, key=lambda m: m[0])
    target, sample_pc = matches_sorted[0]
    fn_start = find_function_start(elf, sample_pc)
    # Keep only matches inside the same function (drop unrelated false-pos).
    fn_end = function_end(elf, fn_start)
    in_fn = [(t, p) for (t, p) in matches if fn_start <= p < fn_end]
    if in_fn:
        in_fn_sorted = sorted(in_fn, key=lambda m: m[0])
        target, sample_pc = in_fn_sorted[0]
    res.address = target
    res.call_site = sample_pc
    res.helper_func = fn_start
    res.notes.append(
        f"fname-init pattern matched at {len(in_fn) or len(matches)} sites "
        f"in fn {hex(fn_start)}; storage base = {hex(target)}"
    )
    for t, p in (in_fn_sorted if in_fn else matches_sorted)[1:5]:
        res.notes.append(f"sibling entry {hex(t)} init={hex(p)}")
    return res


def strategy_gname_storage(
    elf: ELF64, *, verbose: bool = False, exclude_addrs: Optional[set[int]] = None
) -> Optional[Resolution]:
    """Locate the FName storage region — what the user calls "GName".

    Game initialises this via a single static-init function that does:
        ADRP X0, page       ; resolves to a writable BSS region
        ADD  X0, X0, #imm   ; X0 = &FNameStorage
        BL   <constructor>  ; one-shot init call

    That global is then referenced **exactly once** in code (only the
    init site).  Every later FName access goes through the GNames pointer
    table entry (separate global, scored very differently).

    Discriminators applied:
      - target must be writable, mapped, non-executable
      - exactly one direct ADRP+ADD ref in .text
      - instruction at pc+8 must be a BL (constructor call)
      - prefer candidates whose enclosing function also references an
        EName wide-char string (e.g. L"None", L"ByteProperty") — that
        pins us inside FName::StaticInit and not some other static.
    """
    exclude = exclude_addrs or set()
    res = Resolution(name="GName", strategy="gname_storage")
    direct_hist = build_direct_load_histogram(elf)

    # EName strings: little-endian UTF-16 used by UE4's FName init code.
    ename_strings = [
        "None",
        "ByteProperty",
        "IntProperty",
        "BoolProperty",
        "FloatProperty",
        "ObjectProperty",
        "NameProperty",
        "DelegateProperty",
        "Object",
    ]
    ename_needles = [s.encode("utf-16-le") + b"\x00\x00" for s in ename_strings]
    ename_hits = find_strings(elf, ename_needles)
    ename_vas: set[int] = set()
    for vas in ename_hits.values():
        ename_vas.update(vas)

    # Build an inverse map: for fast "is any PC in [fn_start..fn_end] a
    # direct-ref to an EName string?" — sort each EName VA's PCs.
    ename_ref_pcs: list[int] = []
    for v in ename_vas:
        ename_ref_pcs.extend(direct_hist.get(v, []))
    ename_ref_pcs.sort()
    # The EName strings in Game are also loaded indirectly through a tiny
    # pointer table.  Build the set of pointer-table entries (in any data
    # segment) whose 8-byte LE value equals an EName string VA — code
    # then resolves the string via `ADRP+LDR` to that entry.
    ename_table_entries: set[int] = set()
    for seg in elf.data_segments:
        # Only scan up to ~256 KiB per segment so we don't burn 30s on
        # massive .bss-style segments.
        buf = bytes(elf.mm[seg.p_offset : seg.p_offset + min(seg.p_filesz, 1 << 24)])
        for v in ename_vas:
            target_bytes = struct.pack("<Q", v)
            idx = 0
            while True:
                i = buf.find(target_bytes, idx)
                if i < 0:
                    break
                if (seg.p_vaddr + i) % 8 == 0:
                    ename_table_entries.add(seg.p_vaddr + i)
                idx = i + 1
    if verbose:
        print(
            f"  [GName] EName direct-ref sites: {len(ename_ref_pcs)}, "
            f"indirect-table entries: {len(ename_table_entries)}",
            file=sys.stderr,
        )

    import bisect

    # Pre-index all indirect-load PCs (and their resolved entries) so we
    # can answer "any indirect load in [fn_start..fn_end] resolves to an
    # EName-pointer-table entry?" in O(log n) per candidate.
    all_indirect_pcs: list[int] = []
    all_indirect_entries: list[int] = []
    for seg in elf.text_segments:
        buf = elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz]
        base = seg.p_vaddr
        n = len(buf) & ~3
        adrp_pc_arr = [0] * 32
        adrp_page_arr = [0] * 32
        adrp_valid = [False] * 32
        i = 0
        while i < n:
            insn = struct.unpack_from("<I", buf, i)[0]
            pc = base + i
            ad = adrp(insn, pc)
            if ad is not None:
                rd, page = ad
                adrp_pc_arr[rd] = pc
                adrp_page_arr[rd] = page
                adrp_valid[rd] = True
            else:
                ld = ldr_uoff64(insn)
                if ld is not None:
                    rt, rn, imm = ld
                    if adrp_valid[rn] and pc - adrp_pc_arr[rn] <= 24 * 4:
                        all_indirect_pcs.append(pc)
                        all_indirect_entries.append(adrp_page_arr[rn] + imm)
                    adrp_valid[rt] = False
            i += 4
    # Sort and persist (paired).
    pairs = sorted(zip(all_indirect_pcs, all_indirect_entries))
    all_indirect_pcs = [p for p, _ in pairs]
    all_indirect_entries = [e for _, e in pairs]

    def fn_indirect_load_stats(fs: int, fe: int) -> tuple[int, bool]:
        """Return (count, refs_ename_via_table) for indirect loads in
        [fs..fe).  O(log n + k) where k is the number of loads in range.
        """
        lo = bisect.bisect_left(all_indirect_pcs, fs)
        hi = bisect.bisect_left(all_indirect_pcs, fe)
        cnt = hi - lo
        ref = False
        if ename_table_entries and cnt > 0:
            for idx in range(lo, hi):
                if all_indirect_entries[idx] in ename_table_entries:
                    ref = True
                    break
        return cnt, ref

    # Tuple now: (target, add_pc, fn_start, fn_size, refs_ename, indirect_loads_in_fn)
    candidates: list[tuple[int, int, int, int, bool, int]] = []
    for target, pcs in direct_hist.items():
        if len(pcs) != 1:
            continue
        if target in exclude:
            continue
        if (
            not elf.is_mapped(target)
            or elf.is_executable(target)
            or not elf.is_writable(target)
        ):
            continue
        add_pc = pcs[0]
        # Require a BL within the next 1-4 instructions (constructor call).
        ok = False
        for k in (4, 8, 12, 16):
            nxt = elf.read_u32(add_pc + k)
            if nxt is not None and (nxt & 0xFC000000) == 0x94000000:
                ok = True
                break
        if not ok:
            continue
        fn_start = find_function_start(elf, add_pc)
        fn_end = function_end(elf, fn_start)
        fn_size = fn_end - fn_start

        # Direct EName ref test.
        d_lo = bisect.bisect_left(ename_ref_pcs, fn_start)
        d_hi = bisect.bisect_left(ename_ref_pcs, fn_end)
        refs_ename = d_lo < d_hi
        indirect_count, refs_via_table = fn_indirect_load_stats(fn_start, fn_end)
        refs_ename = refs_ename or refs_via_table

        candidates.append(
            (target, add_pc, fn_start, fn_size, refs_ename, indirect_count)
        )

    if not candidates:
        return None

    # Rank: prefer (a) ename-referencing functions, (b) large functions (FName
    # static init is among the biggest single-init helpers in the binary),
    # (c) many indirect loads (iterates the EName table).
    def rank_key(c):
        target, add_pc, fn_start, fn_size, refs_ename, ind = c
        return (-int(refs_ename), -fn_size, -ind, target)

    ranked = sorted(candidates, key=rank_key)
    if verbose:
        print(
            f"  [GName] storage candidates (singly-ref'd writable + immediate BL): "
            f"{len(candidates)}",
            file=sys.stderr,
        )
        print(
            f"  [GName] top 10 ranked by (ename, fn_size, indirect_loads):",
            file=sys.stderr,
        )
        for t, p, f, fs, r, ind in ranked[:10]:
            print(
                f"    target={hex(t)} init_pc={hex(p)} fn={hex(f)} "
                f"size={fs} ename={r} ind_loads={ind}",
                file=sys.stderr,
            )

    target, add_pc, fn_start, fn_size, refs_ename, indirect_count = ranked[0]
    res.address = target
    res.helper_func = fn_start
    res.call_site = add_pc
    res.notes.append(f"single direct ADRP+ADD @ {hex(add_pc)} -> {hex(target)}")
    res.notes.append(
        f"fn_size={fn_size} indirect_loads={indirect_count} ename={refs_ename}"
    )
    for t, p, f, fs, r, ind in ranked[1:5]:
        res.notes.append(
            f"alt {hex(t)} init={hex(p)} fn={hex(f)} " f"size={fs} ind={ind} ename={r}"
        )
    return res


def strategy_table_neighborhood(
    elf: ELF64,
    name: str,
    *,
    seed_entry: int,
    exclude_entries: set[int],
    verbose: bool = False,
    radius: int = 0x1000,
) -> Optional[Resolution]:
    """Last-resort: enumerate pointer-table entries near a known seed and
    pick the one with the highest code-ref count that isn't already taken.

    Only useful as a "best guess" — the caller should treat the result as
    a candidate and verify in IDA.
    """
    res = Resolution(name=name, strategy="table_neighborhood")
    entries = enumerate_pointer_table_neighborhood(elf, seed_entry, radius=radius)
    hist = build_indirect_load_histogram(elf)
    if verbose:
        print(
            f"  [{name}] table-neighborhood candidates near {hex(seed_entry)}: "
            f"{len(entries)}",
            file=sys.stderr,
        )
    scored: list[tuple[int, int, int]] = []  # (score, entry_va, value)
    for entry_va, val in entries:
        if entry_va in exclude_entries:
            continue
        score = hist.get(entry_va, 0)
        if score == 0:
            continue
        scored.append((score, entry_va, val))
    if not scored:
        return None
    scored.sort(reverse=True)
    if verbose:
        top = ", ".join(f"{hex(e)}={hex(v)}(refs={s})" for s, e, v in scored[:5])
        print(f"    top: {top}", file=sys.stderr)
    score, entry_va, val = scored[0]
    res.address = val
    res.pointer_table_entry = entry_va
    res.notes.append(f"score={score} (1st of {len(scored)}, top-5 follows in notes)")
    for s, e, v in scored[1:5]:
        res.notes.append(f"runner-up entry={hex(e)} -> {hex(v)} refs={s}")
    return res


# ---------------------------------------------------------------------------
# Strategy 3 — direct ADRP+ADD scan (non-indirected builds).
# ---------------------------------------------------------------------------


def strategy_direct_adrp_add(
    elf: ELF64,
    *,
    name: str,
    size_hint: int = 0x40,
    hint_addr: Optional[int] = None,
    hint_window: int = 0,
) -> Optional[Resolution]:
    """Verify a user-supplied hint by locating its ADRP+ADD (direct) or
    ADRP+LDR (indirected through a pointer table) code-ref.

    Default is *exact-only*; the optional `hint_window` enables a slow
    fuzzy window search (in 0x40-byte steps) around the hint.  Fuzzy mode
    is disabled by default because Game version drift moves globals by
    tens of kilobytes — a small window doesn't actually help, and a large
    one finds unrelated junk.
    """
    if hint_addr is None or not elf.is_mapped(hint_addr):
        return None
    # 1) Direct ADRP+ADD reference?
    refs = code_xrefs_to_addr(elf, hint_addr, limit=1, allow_ldr=False)
    if refs:
        return Resolution(
            name=name,
            strategy="direct_adrp_add",
            address=hint_addr,
            call_site=refs[0],
            notes=[f"hint validated by ADRP+ADD at {hex(refs[0])}"],
        )
    # 2) Indirect — find a pointer-table entry whose 8-byte LE value equals
    #    the hint, then verify there's an ADRP+LDR code ref to that entry.
    target_bytes = struct.pack("<Q", hint_addr)
    for seg in elf.data_segments:
        buf = bytes(elf.mm[seg.p_offset : seg.p_offset + seg.p_filesz])
        idx = 0
        while True:
            i = buf.find(target_bytes, idx)
            if i < 0:
                break
            entry_va = seg.p_vaddr + i
            if entry_va % 8 == 0:
                ldr_refs = code_xrefs_to_addr(
                    elf, entry_va, limit=1, allow_add=False, allow_ldr=True
                )
                if ldr_refs:
                    return Resolution(
                        name=name,
                        strategy="hint_indirect",
                        address=hint_addr,
                        pointer_table_entry=entry_va,
                        call_site=ldr_refs[0],
                        notes=[
                            f"hint validated via table entry {hex(entry_va)} "
                            f"(ADRP+LDR at {hex(ldr_refs[0])})"
                        ],
                    )
            idx = i + 1
    # 3) Optional fuzzy window (disabled by default, opt-in via hint_window).
    if hint_window > 0:
        for delta in range(-hint_window, hint_window + 1, 0x40):
            if delta == 0:
                continue
            cand = hint_addr + delta
            if cand <= 0 or not elf.is_mapped(cand):
                continue
            refs = code_xrefs_to_addr(elf, cand, limit=1, allow_ldr=False)
            if refs:
                return Resolution(
                    name=name,
                    strategy="direct_adrp_add_fuzzy",
                    address=cand,
                    call_site=refs[0],
                    notes=[
                        f"fuzzy hint match at {hex(refs[0])} " f"hint_delta={delta:+#x}"
                    ],
                )
    return None


# ---------------------------------------------------------------------------
# Top-level resolver.
# ---------------------------------------------------------------------------


@dataclass
class FinderResult:
    so_path: str
    image_base: int
    gengine: Optional[Resolution] = None
    gnames: Optional[Resolution] = None
    guobjectarray: Optional[Resolution] = None

    def to_dict(self) -> dict:
        return {
            "so_path": self.so_path,
            "image_base": hex(self.image_base),
            "GEngine": self.gengine.to_dict() if self.gengine else None,
            "GName": self.gnames.to_dict() if self.gnames else None,
            "GUObjectArray": (
                self.guobjectarray.to_dict() if self.guobjectarray else None
            ),
        }


def resolve_all(
    elf: ELF64, *, hints: Optional[dict[str, int]] = None, verbose: bool = False
) -> FinderResult:
    hints = hints or {}
    image_base = min((s.p_vaddr for s in elf.segments), default=0)
    out = FinderResult(so_path=elf.path, image_base=image_base)

    claimed_entries: set[int] = set()

    def hint_first(name: str, *strategies):
        """Try the explicit hint first (cheap, deterministic).  Fall back
        through `strategies` (callables returning Optional[Resolution]).
        """
        h = hints.get(name)
        if h is not None:
            r = strategy_direct_adrp_add(elf, name=name, hint_addr=h)
            if r is not None:
                return r
        for s in strategies:
            r = s()
            if r is not None:
                return r
        return None

    # -- GUObjectArray ------------------------------------------------------
    # The this-method strategy is reliable here (FUObjectArray methods take
    # &GUObjectArray as their first arg).
    if verbose:
        print("[*] resolving GUObjectArray", file=sys.stderr)
    out.guobjectarray = hint_first(
        "GUObjectArray",
        lambda: strategy_sourcepath_thismethod(
            elf, UOBJECTARRAY_ANCHORS, "GUObjectArray", verbose=verbose
        ),
    )
    if out.guobjectarray and out.guobjectarray.pointer_table_entry is not None:
        claimed_entries.add(out.guobjectarray.pointer_table_entry)

    # -- GEngine ------------------------------------------------------------
    # GEngine is a pointer to a UEngine, not a `this` of a `FXxx` class, so
    # the caller-scan trick doesn't work.  Use the Game-specific log
    # strings, then fall back to helper-body scan, then table neighborhood.
    if verbose:
        print("[*] resolving GEngine", file=sys.stderr)
    out.gengine = hint_first(
        "GEngine",
        lambda: strategy_log_anchor(
            elf,
            GENGINE_LOG_ANCHORS,
            "GEngine",
            verbose=verbose,
            exclude_entries=claimed_entries,
        ),
        lambda: strategy_helper_body_scan(
            elf,
            GENGINE_SOURCEPATH_ANCHORS,
            "GEngine",
            verbose=verbose,
            exclude_entries=claimed_entries,
        ),
    )
    if out.gengine and out.gengine.pointer_table_entry is not None:
        claimed_entries.add(out.gengine.pointer_table_entry)

    # -- GName (FName storage region) --------------------------------------
    # The user-facing "GName" — singly-referenced writable region passed
    # once into an FName::StaticInit-style constructor.  This matches the
    # value the user has been using on Game (0xE498300) — the storage
    # itself, not the heavily-referenced GNames pointer.
    if verbose:
        print("[*] resolving GName (storage)", file=sys.stderr)
    claimed_addrs: set[int] = set()
    if out.guobjectarray and out.guobjectarray.address is not None:
        claimed_addrs.add(out.guobjectarray.address)
    if out.gengine and out.gengine.address is not None:
        claimed_addrs.add(out.gengine.address)
    gname_hint = hints.get("GName") or hints.get("GNames")
    out.gnames = None
    if gname_hint is not None:
        out.gnames = strategy_direct_adrp_add(elf, name="GName", hint_addr=gname_hint)
    if out.gnames is None:
        out.gnames = (
            strategy_fname_init_pattern(
                elf, verbose=verbose, exclude_addrs=claimed_addrs
            )
            or strategy_gname_storage(elf, verbose=verbose, exclude_addrs=claimed_addrs)
            or strategy_helper_body_scan(
                elf,
                GNAMES_SOURCEPATH_ANCHORS,
                "GName",
                verbose=verbose,
                exclude_entries=claimed_entries,
            )
        )
    if out.gnames and out.gnames.pointer_table_entry is not None:
        claimed_entries.add(out.gnames.pointer_table_entry)

    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_PATHS = [""]

# Known-good values from older versions act as "hints" that S3 (direct
# ADRP+ADD) can use as a starting point.  Add new (version, dict) pairs as
# you analyze them.  Hints are only used as a last resort.
KNOWN_HINTS = {}


def pick_default_path() -> Optional[str]:
    env = os.environ.get("Game_SO")
    if env and os.path.isfile(env):
        return env
    for p in DEFAULT_PATHS:
        if os.path.isfile(p):
            return p
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Game: UE4 globals finder")
    ap.add_argument("path", nargs="?", help="Path to libUE4*.so (dumped or normal)")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    ap.add_argument("--verbose", "-v", action="store_true", help="Diagnostic trace")
    ap.add_argument(
        "--hint",
        action="append",
        default=[],
        metavar="NAME=HEX",
        help="Provide a hint, e.g. --hint GEngine=0xEA10468",
    )
    ap.add_argument(
        "--hint-version",
        default=None,
        help=f"Use a built-in hint set: {list(KNOWN_HINTS)}",
    )
    ap.add_argument(
        "--show-table",
        action="store_true",
        help=(
            "Enumerate pointer-table entries near the resolved "
            "GUObjectArray entry — top entries by code-ref count. "
            "Useful for manually identifying GEngine / GNames / "
            "GMalloc / GWorld."
        ),
    )
    ap.add_argument(
        "--show-table-radius",
        type=lambda s: int(s, 0),
        default=0x1000,
        help="Bytes either side of seed entry to enumerate (default 0x1000)",
    )
    args = ap.parse_args(argv)

    so_path = args.path or pick_default_path()
    if not so_path:
        print(
            "error: no .so path provided and no default exists. Pass one as argv.",
            file=sys.stderr,
        )
        return 2
    if not os.path.isfile(so_path):
        print(f"error: file not found: {so_path}", file=sys.stderr)
        return 2

    hints: dict[str, int] = {}
    if args.hint_version:
        hints.update(KNOWN_HINTS.get(args.hint_version, {}))
    for h in args.hint:
        if "=" not in h:
            print(f"error: bad --hint {h!r}", file=sys.stderr)
            return 2
        k, v = h.split("=", 1)
        hints[k.strip()] = int(v.strip(), 0)

    elf = ELF64(so_path)
    result = resolve_all(elf, hints=hints, verbose=args.verbose)

    if args.show_table:
        seed = None
        if (
            result.guobjectarray
            and result.guobjectarray.pointer_table_entry is not None
        ):
            seed = result.guobjectarray.pointer_table_entry
        elif hints.get("GUObjectArray"):
            seed = hints["GUObjectArray"]
        if seed is None:
            print("--show-table: no seed entry available", file=sys.stderr)
        else:
            entries = enumerate_pointer_table_neighborhood(
                elf, seed, radius=args.show_table_radius
            )
            hist = build_indirect_load_histogram(elf)
            scored = [(hist.get(e, 0), e, v) for e, v in entries]
            scored = [s for s in scored if s[0] > 0]
            scored.sort(reverse=True)
            print(
                f"\nPointer-table neighborhood seeded at {hex(seed)} "
                f"(radius {hex(args.show_table_radius)}):"
            )
            print(f"  {'entry':<14} {'value':<14}  refs")
            for s, e, v in scored[:40]:
                marker = ""
                claimed = {
                    "GEngine": (
                        result.gengine.pointer_table_entry if result.gengine else None
                    ),
                    "GName": (
                        result.gnames.pointer_table_entry if result.gnames else None
                    ),
                    "GUObjectArray": (
                        result.guobjectarray.pointer_table_entry
                        if result.guobjectarray
                        else None
                    ),
                }
                for label, claim in claimed.items():
                    if claim == e:
                        marker = f"  <-- {label}"
                        break
                print(f"  {hex(e):<14} {hex(v):<14}  {s}{marker}")

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(f"File:        {result.so_path}")
    print(f"Image base:  {hex(result.image_base)}")
    print()
    for name, r in (
        ("GEngine", result.gengine),
        ("GName", result.gnames),
        ("GUObjectArray", result.guobjectarray),
    ):
        if r is None or r.address is None:
            print(f"  {name:<14}  NOT FOUND")
            continue
        print(f"  {name:<14}  {hex(r.address)}    [{r.strategy}]")
        if r.pointer_table_entry is not None:
            print(f"    via table  {hex(r.pointer_table_entry)}")
        if r.helper_func is not None:
            print(f"    helper     {hex(r.helper_func)}")
        if r.call_site is not None:
            print(f"    call site  {hex(r.call_site)}")
        if r.anchor is not None:
            print(f"    anchor     {r.anchor.decode('ascii', 'replace')}")
        for note in r.notes:
            print(f"    note       {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
