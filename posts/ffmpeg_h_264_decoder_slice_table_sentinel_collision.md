---
title: "BinCodeQL Analysis of FFmpeg H.264 Decoder slice_table Sentinel Collision Bug"
date: 2026-04-21
---

# FFmpeg H.264 Decoder — slice_table Sentinel Collision & Alloc-Size Signed-Overflow Review

## Metadata

- **binary:** `/media/sanjay/f574986f-8197-4e72-a69d-87ddf200a6a9/sanjay/tools/ffmpeg-8.0.1/ffmpeg_g.bndb`
- **timestamp:** 2026-04-21T06:25:59Z
- **status:** inconclusive
- **finding_count:** 3
- **hypothesis_count:** 4

## Findings

### [MEDIUM]

#### **sentinel_collision_risk** `ff_h264_alloc_tables / ff_h264_decode_mb_cabac` @ 0xb956f6
**Evidence:**
- SentinelMemset.csv: `call_addr=12146422` (0xb956f6), callee='memset', fill_val='4294967295' (0xFFFFFFFF)
- Uint16AllocSite.csv: 5 alloc sites with elem_width=2 including 0xb955b0 (slice_table_base), 0xb955cd (cbp_table)
- MLIL-SSA `0xb956c3: rsi_1#1 = 0xffffffff` (fill arg to memset over slice_table_base)
- MLIL-SSA `0xb9571b: h->slice_table = &h->slice_table_base[sx.q((mb_stride*2).d)+1]` (uint16_t pointer)
- decompile `ff_h264_decode_mb_cabac 0x125bd84: h_1->slice_table[rax_7] = (sl_2->slice_num).w` — .w truncation to 16-bit
- decompile `ff_h264_decode_mb_cabac 0x125c645: h_1->slice_table[mb_xy] = (sl_2->slice_num).w` (skipped MB path)
- decompile `ff_h264_decode_mb_cabac 0x125ce42: rax_122.b = zx.d(h_1->slice_table[rdx_79]) == sl_2->slice_num` (sentinel read-back equality test)
- GuardOnStore16Var.csv: only 1 guard on any 16-bit store variable — a ne-0 check, NOT an upper bound on slice_num
- CabacStore16.csv: 33 narrow 16-bit stores in ff_h264_decode_mb_cabac with no upper-bound guard

**Reasoning:** ff_h264_alloc_tables initializes slice_table_base with memset(base, 0xFFFFFFFF, size), filling each uint16_t slot with the sentinel value 0xFFFF. Per-macroblock, ff_h264_decode_mb_cabac writes `h->slice_table[mb_xy] = (sl_2->slice_num).w` — storing the current slice number as a 16-bit value. The slice_table is used for neighborhood queries: a read-back `slice_table[neighbor_mb] == slice_num` is used to determine if a neighbor MB belongs to the same slice. If a bitstream contains >= 65535 slices (a pathological but spec-legal value), slice_num wraps to 0xFFFF on the 16-bit store. This collides with the sentinel, causing the equality check to return true for uninitialized (sentinel) entries, which would incorrectly classify out-of-bounds MBs as being in the same slice — potentially leading to incorrect CABAC context initialization indexing. No upper-bound guard on slice_num before truncation was found by Datalog. This class of bug (H.264 slice_table sentinel collision with 16-bit counter) was the root cause of CVE-2018-9841 in earlier FFmpeg versions.
*

#### **signed_integer_overflow_alloc_size** `ff_h264_alloc_tables` @ 0xb9556a
**Evidence:**
- MLIL-SSA `0xb95564: rbp_1#2 = rbp#1 * mb_stride_1#1`  (int32 multiply: nb_slice_ctx * mb_stride)
- MLIL-SSA `0xb95567: rbp_2#3 = rbp_1#2 << 4`             (int32 left-shift by 4, i.e. *16)
- MLIL-SSA `0xb9556a: nmemb_1#4 = sx.q(rbp_2#3)`         (sign-extend int32 result to int64)
- MLIL-SSA `0xb95570: av_calloc(nmemb_1#4, 1)`            (used directly as allocation size)
- LShlInAlloc.csv: `ff_h264_alloc_tables, addr=12146023` (0xb95567), dst=rbp_2#3, op=lsl, operand=4
- MulInAlloc.csv:  `ff_h264_alloc_tables, addr=12146020` (0xb95564), dst=rbp_1#2, op=mul, operand=mb_stride_1
- MulSxToAlloc.csv/LShiftSxToAlloc.csv: no direct match (operand chain was not directly sx'd in one step — BN decomposes it across two arith ops before sx.q)

**Reasoning:** In ff_h264_alloc_tables, the allocation size for intra4x4_pred_mode is computed as: `nmemb_1 = sx.q((nb_slice_ctx * mb_stride) << 4)`. Both the multiply and left-shift operate on 32-bit signed integers before the sign-extension to 64-bit. For large dimensions (e.g. `nb_slice_ctx=256, mb_stride=8192` for a 4K-wide frame → 256*8192*16 = 33,554,432 which is within int32 range; but with mb_stride approaching H.264 spec max: mb_stride can be up to 128+1=129 for 4096-wide, times up to 256 thread contexts times 16 = 530,841,600, still within int32 positive range). The overflow would require very large `nb_slice_ctx` AND `mb_stride` simultaneously. The check in ff_h264_decode_seq_parameter_set constrains mb_width to 1024 MBs (16384 pixels) but nb_slice_ctx is bounded by thread count. This remains plausible-unverified as exploitation requires specific thread-count + resolution combinations.
**Confidence:** plausible-unverified

### [LOW]

#### **narrow_store_without_upper_bound_guard** `ff_h264_decode_mb_cavlc` @ 0x1105a50
**Evidence:**
- CavlcStore16.csv: 20 narrow 16-bit stores in `ff_h264_decode_mb_cavlc` with variable widths 2-8
- GuardOnStore16Var.csv: only ne-0 guard on rdi_42#171 at 0x10f1b4e, NOT an upper-bound
- NarrowStore16WithWidth.csv row: `ff_h264_decode_mb_cavlc`, addr=17851639, val_var=rax_89#627, val_width=8 (8-bit stored to 16-bit slot — no overflow risk from this one)
- NarrowStore16WithWidth.csv row: `ff_h264_decode_mb_cavlc`, addr=17851001, val_var=rbx_8#135, val_width=4 (4-bit to 16-bit slot)

**Reasoning:** Multiple narrow stores in CAVLC decoding involve values smaller than 16-bit (4-bit, 8-bit) — these are benign truncations. The slice_num store pattern is the same as CABAC. The lack of upper-bound guards is structural.
**Confidence:** plausible-unverified

## Hypotheses considered
```tsv
| # | Hypothesis | Verdict | Facts checked | MCP checked | Note |
|---|---|---|---|---|---|
| 1 | slice_table sentinel collision: slice_num >= 0xFFFF causes false neighbor match | plausible-unverified | SentinelMemset.csv: 0xb956f6 memset with 0xFFFFFFFF confirmed, Uint16AllocSite.csv: 5 uint16_t alloc sites including slice_table_base at 0xb955b0, MLIL-SSA 0xb956c3: rsi_1#1 = 0xffffffff, CabacStore16.csv: 33 stores, NarrowStore16WithWidth — all width=2 (already 16-bit vars), GuardOnStore16Var.csv: only 1 guard = ne-0, NO upper bound on slice_num before write, decompile_function(ff_h264_decode_mb_cabac) 0x125bd84: slice_table write confirmed, decompile_function(ff_h264_decode_mb_cabac) 0x125ce42: sentinel equality check confirmed | decompile_function(ff_h264_alloc_tables) — confirmed uint16_t alloc + memset(0xFFFFFFFF), decompile_function(ff_h264_decode_mb_cabac) — confirmed slice_table[mb_xy]=(slice_num).w write and slice_table[neighbor]==slice_num read-back | Structural sentinel-collision shape present; exploitation requires bitstream with >=65535 slices. No guard refutes this. NOT confirmed exploitable in this build without dynamic tracing. |
| 2 | signed int32 overflow in (nb_slice_ctx * mb_stride << 4) before sx.q alloc-size | plausible-unverified | MulInAlloc.csv: 0xb95564 mul nb_slice_ctx*mb_stride (int32), LShlInAlloc.csv: 0xb95567 lsl *16 (int32), MLIL-SSA 0xb9556a: sx.q(rbp_2#3) then passed to av_calloc, LShiftSxToAlloc.csv: no match (multi-step chain not captured by single-step rule) | get_il(ff_h264_alloc_tables, mlil, ssa=True) — confirmed full arithmetic chain, decompile_function(ff_h264_alloc_tables) — nmemb_1 = sx.q((nb_slice_ctx*mb_stride)<<4) | Overflow requires nb_slice_ctx * mb_stride * 16 > INT32_MAX. mb_stride max ~1025, nb_slice_ctx bounded by thread count (typically <= 64). Max plausible: 64*1025*16 = 1,049,600 — far from INT32_MAX (2.1B). Likely safe in practice without extremely high thread counts. |
| 3 | rax_329/r9_64 motion vector stores are NOT sentinel-collision candidates | refuted | Rax329Arith.csv: rax_329#250 = rax_328#249.w + rbp_10 — MV delta accumulation (int16 add), R9_64Arith.csv: r9_64#49 = r8_46#65 + r9_63#48.r9w — MV component add, decompile_function(ff_h264_decode_mb_cabac) 0x125e9f5: r9_64 = rax_327.w + var_e0.w — motion vector X, decompile_function(ff_h264_decode_mb_cabac) 0x125e9f8: rax_329 = rax_328.w + rbp_10 — motion vector Y | decompile_function(ff_h264_decode_mb_cabac) — confirmed rax_329/r9_64 are mv_cache stores, not slice_table | These are motion vector components stored to mv_cache[]. The stores to mv_cache are expected int16 operations. The 33 CabacStore16 entries are mostly mv_cache stores, not slice_table writes. |
| 4 | cbp_table store of var_130_1.w — could be wide value narrowed | plausible-unverified | CabacStore16.csv: addr=19252805, var=rdx_47#57, width=2, decompile_function 0x125c29d: cbp_table_1[rax_7] = var_130_1.w — CBP truncated to 16-bit, No guard found on var_130_1 before the 16-bit store | decompile_function(ff_h264_decode_mb_cabac) | var_130_1 is the coded block pattern, max value 0x30 for 4:2:0. Cannot overflow 16-bit. Safe. |
```
## Notes

## Analysis Summary

### Methodology
Full batch fact extraction of 12 H.264 core functions (97K facts). Custom Datalog queries for: sentinel-init detection (`CallArgConst` on `memset`), uint16_t alloc sites (`AllocSite` with `elem_width=2`), narrow 16-bit stores with no upper-bound guards, arithmetic chain before `sx.q` alloc sizes.

### Key Findings

#### Finding 1: slice_table Sentinel Collision Shape (Medium, Plausible-Unverified)

**The classic H.264 slice_table bug pattern is structurally present in this binary.**

Data flow:
```
ff_h264_alloc_tables:
  0xb955b0: slice_table_base = av_calloc(mb_stride+nmemb, 2)  // uint16_t[]
  0xb956f6: memset(slice_table_base, 0xFFFFFFFF, size)         // every uint16_t = 0xFFFF sentinel
  0xb9571b: h->slice_table = &slice_table_base[mb_stride*2+1] // offset past guard row

ff_h264_decode_mb_cabac:
  0x125bd84: h->slice_table[mb_xy] = (sl->slice_num).w        // WRITE: truncate slice_num to uint16_t
  0x125c645: h->slice_table[mb_xy] = (sl->slice_num).w        // WRITE: skipped MB path
  0x125ce42: slice_table[neighbor_mb] == sl->slice_num         // READ-BACK equality check
  0x125befc: slice_table[neighbor_mb] == sl->slice_num         // READ-BACK in MBAFF path
```

The invariant is: `slice_num` must never equal `0xFFFF` (the sentinel). If a bitstream encodes ≥65535 slices, `(slice_num).w == 0xFFFF` collides with the sentinel, causing uninitialized neighbor MBs to appear "in the same slice". This would corrupt CABAC context initialization (`cabac_state[(zx.q(rax_122.b) & ...)  + ...]`) with out-of-bounds MB type reads.

**Datalog evidence:** 0 upper-bound guards found on the slice_num variable in any version across the 33 CABAC 16-bit store sites (GuardOnStore16Var.csv shows only 1 ne-0 guard, unrelated to slice_num). This was the shape of CVE-2018-9841. Whether this specific build includes a fix at a higher level (e.g., in `h264_slice_header_init` capping slice group count) requires further tracing — `inconclusive`.

#### Finding 2: Signed Int32 Overflow in nmemb Computation (Low Risk)

```
ff_h264_alloc_tables:
  0xb95564: rbp_1 = nb_slice_ctx * mb_stride    // int32 multiply
  0xb95567: rbp_2 = rbp_1 << 4                  // int32 shift-by-16
  0xb9556a: nmemb_1 = sx.q(rbp_2)               // sign-extend THEN alloc
  0xb95570: av_calloc(nmemb_1, 1)
```

The overflow requires `nb_slice_ctx * mb_stride * 16 > 2^31`. With typical thread bounds (≤64 threads) and H.264 max width (~1025 mb_stride), max is ~1M — safe. Only exploitable with abnormally large thread pool configs.

#### Finding 3: Motion Vector Stores Are Benign (Refuted)

The 33 `CabacStore16` entries are dominated by `mv_cache` stores (motion vectors), which are expected int16_t operations. The `rax_329/r9_64` variables are motion vector delta additions — not overflow candidates.

### What Would Confirm Finding 1

To confirm the sentinel collision:
1. Verify whether `ff_h264_decode_seq_parameter_set` or `h264_slice_header_init` enforces `slice_num < 0xFFFF` at the bitstream parse level.
2. Trace the source of `slice_num` — it increments per-slice in `h264_slice_header_init`. If the NAL parser allows >65534 slices before a reset, the condition can be reached.
3. Craft a bitstream with `num_slice_groups_minus1 = 65534` and verify runtime behavior.
