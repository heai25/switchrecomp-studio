# SwitchRecomp / Kirikae fix log

Reference for every change made to this SwitchRecomp install and its local Kirikae copy
(`kirikae-src`, commit 726c4a1 plus patches). Originals of every changed file are in
`backup\2026-11-09\` (`*.orig`). Rebuild the tool with `build-patched.bat` (close
"SwitchRecomp App" first or only the app exe fails to update), then `switchrecomp refine <game>`
so each game picks up the runtime changes.

> **2026-11-10 (OoT session):** fixes 31-36 were made directly in this master tree and copied to
> E:\switchrecomp-studio\kirikae-src and switchrecomp-coverage\kirikae-src (all three match). Files touched:
> rt/src/{sched,threads,horizon}.rs, rt/src/services/{nx2,nvdrv}.rs, rt/src/services/am/applet.rs
> (backups `*.before-*` next to each). Pull from here before syncing so they are not overwritten.

## Status of the games (2026-11-09)

| Game | Folder | State |
|---|---|---|
| Super Mario RPG | `games\sm-rpg` | Renders fully, plays (field + battles). ~58-60 fps in Bowser's Keep (was black screen, then ~35 fps). Built with `--fast-regs`. |
| Super Mario 3D World + Bowser's Fury | `games\sm-3d` | Renders fully, 60 fps on title / world map / 1-1 (100-690 fps headroom), 0 interpreted code after refine. Rebuilt with the native LD1/ST1 codegen, no regression. |
| Super Mario Odyssey | `games\0100000000010000` | Plays at 60 fps in menus; 3D levels show white ground / dark Mario (open, see test\ODYSSEY-LIGHTING-NOTES.md). |
| Switch 2 Welcome Tour | `games\s2-welcome-tour-1` | Boots into nnMain; blocked by a damaged romfs.bin (re-dump) and by Kirikae having no Switch 2 GPU backend. |
| `games\0100bc0018138000` | | Broken duplicate build (Odyssey title id); safe to delete. |
| Tears of the Kingdom | | Dump folder is empty; re-dump needed. |

## Shader translator (crates/maxwell/src/translate.rs)

1. **Condition codes**: added T (0xf), CSM_* (0x18-0x1d, false like yuzu), RLE (0x1e: S|Z),
   RGT (0x1f: !S & !Z). Shaders using them were being dropped.
2. **S2R system values**: added the remaining ones (virt cfg/id, PM0-7, ordering ticket,
   prim type, invocation id, wscale, clock, global timer -> 0; INVOCATION_INFO -> 0x00ff0000
   in vertex shaders).
3. **VOTE.VTG** is a hint with no result: now a no-op instead of "unsupported".
4. **Bindless TEX (TEX.B)**: handle taken from the first B register; AOFFI at bit 36, LOD
   mode at bits 37-39. Uses `sample_slot()` so the texture comes from the tracked constant buffer.
5. **Bindless handle tracking** (`handle_source`): follows `mov` from a constant buffer, register
   copies (`mov Rd, Rs`) and `LOP.OR` of two constant-buffer words (NVN puts the texture index and
   the sampler index in separate words). The second word is packed into the handle as
   `handle | (word2 + 1) << 16`. TMML bindless uses the same tracker.
6. **TLD** (texel fetch with integer coordinates) implemented, bound and bindless
   (`fetch_slot()`); arrays, LOD (bit 55), AOFFI (bit 35). Multisample and cube report unsupported.

Effect: Super Mario RPG went from 0 of ~1900 draws per 10 s to every draw rendered.

## Runtime (crates/rt)

7. **gpu/vulkan/textures.rs**: reads the packed second handle word and ORs it in (pairs with 5).
8. **lse.rs (new)**: ARMv8.1 LSE atomics run as host atomics: CAS/CASA/CASL/CASAL (B/H/W/X),
   CASP family, SWP, LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN, LDAPR.
   `abi.rs` exports `kirikae_atomic`; `interp.rs` executes `Stmt::Atomic`;
   `cpu.rs` exposes `host_ptr()` and `cas128_ptr()`.
9. **horizon.rs svcGetInfo**: id 33 = page size (0x1000; Switch 2 nn::ro / nn::os VammManager);
   ids 27, 29-32, 34-40 answer 0 with a one-time warning.
10. **horizon.rs svcMapPhysicalMemory**: a 0-byte request at a page-aligned address succeeds.
11. **services/am/applet.rs**: appletOE command 10 (Switch 2 OpenApplicationProxy) handled like 0.
12. **input.rs**: `KIRIKAE_INPUT_LIVE=<file>`: buttons written in the file (e.g. `A+LUP`) are
    held while they stay there. Lets a script or tool play the game.
13. **gpu/mod.rs + gpu/threed.rs**: `KIRIKAE_WATCH_SHADER=<va,...>` (+ `KIRIKAE_WATCH_FROM`,
    `KIRIKAE_WATCH_COUNT`) traces only the draws that use the listed shaders.
14. **services/vi.rs frame limiter**: wakes 0.5 ms before the vblank and finishes the wait with a
    short spin (Windows sleeps overshoot). `KIRIKAE_PACE_LOG=1` logs limiter decisions.
15. **host1x/mod.rs**: NVDEC/H.264 decoding now runs on the worker thread by default (outside the
    guest lock). Super Mario RPG's movies: ~30 fps (dips to 15) -> ~47 fps.
    `KIRIKAE_NVDEC_SYNC=1` restores inline decoding.

## Lifter and code generator (crates/a64, crates/recomp)

16. **Pointer authentication (ARMv8.3)**, a64/src/lift.rs `pointer_auth()`: RETAA/RETAB -> RET,
    BRAA/BRAB/BRAAZ/BRABZ -> BR, BLRAA/BLRAB/BLRAAZ/BLRABZ -> BLR, PACIA..AUTDZB/XPACI/XPACD -> no-op,
    PACGA, LDRAA/LDRAB -> 64-bit load with scaled S:imm9 and optional pre-index writeback.
    (Hint-space PACIASP/AUTIASP were already no-ops.)
17. **LSE decode**, a64: `is_lse()` lifts LSE words to the new `Stmt::Atomic(word)` (ir.rs).
    recomp/src/clif.rs calls `kirikae_atomic` as a sync point; rust_backend.rs emits
    `kirikae_rt::lse::exec`.
18. **Native LD1/ST1**, recomp/src/clif.rs `ld1st1()`: NEON LD1/ST1 (multiple structures,
    1-4 registers, 64/128-bit, no offset / post-index immediate / post-index register) are compiled
    to plain loads/stores through the register cache instead of calling the SIMD interpreter.
    Super Mario RPG's hottest instructions; gameplay ~35 -> ~59 fps (main thread 21 -> 14 ms,
    job threads 21 -> 8 ms per frame).

## Switch 2 (Ampere / SM86) groundwork — see SWITCH2-PLAN.md

19. **Ampere engine classes**, rt/src/gpu/mod.rs `normalize_class()`: binding a Turing/Ampere
    class (xx97 3D, xxC0 compute, xxB5 copy) maps it onto the Maxwell engine and sets the
    global `AMPERE` flag (logged once: "Ampere GPU classes detected"). Maxwell games never set it.
20. **Per-stage program addresses**, rt/src/gpu/threed.rs `program_address()`: on Ampere each
    pipeline stage carries a full 40-bit address (SET_PIPELINE_PROGRAM_ADDRESS_A/B, regs
    PIPELINE+5/+6) instead of PROGRAM_REGION + offset. Used by draw.rs, trace, watch and
    shader dumps.
21. **Ampere semaphores**: host SEM_EXECUTE (method 0x1b; release, reductions, 64-bit payloads,
    timestamps) and 3D/compute REPORT_SEMAPHORE_EXECUTE (method 0x5a -> `report_ampere`).
22. **SM70+ decoder/disassembler**, crates/maxwell/src/sm70.rs (+ `examples/sm70dis.rs`):
    128-bit instruction fields, ~180 opcodes from Mesa NAK, ALU operand forms, cbuf/uniform
    operands, branch targets, scheduling bits. 4 unit tests. Decode only — no translation yet.
    Regression check after 19-22: Super Mario 3D World still 59.8 fps, 0 interpreted.

23. **Welcome Tour RomFS rebuilt**: the dumped romfs.bin was corrupt (its tables are shifted by
    half a byte; 2002-4281 from nn::fs::MountRom). The extracted `romfs\` folder is intact
    (748 files), so romfs.bin was rebuilt from it with the new
    `crates/loader/examples/mkromfs.rs` (`cargo run --release -p kirikae-loader --example mkromfs
    -- <folder> <out.bin>`); every file checked against the folder. Old file kept as
    `romfs.bin.damaged`.
24. **RomFS size taken from the file**, rt/src/process.rs: a loose romfs.bin's size was baked
    into package.bin at build time, so a rebuilt image looked truncated (MountRom bounds check
    failed). The runtime now uses the file's current length and logs when it differs.
    Welcome Tour now mounts its RomFS and stops next at nn::gsv::BootWithRemoteMemory
    (nn::am::GetGraphicsSupervisor returns no handle) — the Switch 2 graphics service.

25. **Switch 2 graphics services**, rt/src/services/nx2.rs (new): `ISelfController` 2000
    (GetGraphicsSupervisor) returns a raw TIPC session to **gsv**, which hands out syncpt (202,
    shared syncpoint pages via 204 + a 500 us mirror thread), gpu (497: id events, graphics
    device 41, VA ranges 201-203, memory jobs 101/102/211-215 with GPU VA == CPU VA), vi2 (305),
    gpu time (1121) and nvsrv (1402 = the nvdrv protocol). Unknown commands are logged once
    with their data words and answered with zeroes. Independent implementation; the Fritchii
    NX2_NOTES.md were the map.
26. **Ampere GPU characteristics**, services/nvdrv.rs: a 0xd0-byte request gets chip GA10F
    (0x17E, SM 8.8, Ampere classes, TSG/subcontext flags, interface versions, 64 VEIDs);
    VSMS_MAPPING (0x13) fills every pair; GET_ENGINE_INFO (0x1f); nvhost-as 0x0b syncpoint shim.
    Also fixed the Switch 1 characteristics layout (flags is a u64 at 0x50; everything after it
    was 4 bytes early).
27. **svc 0x80** SetGpuMemoryAttribute (horizon.rs): argument checks, success.
28. **KIRIKAE_HANG_DUMP=<s>** (interp.rs): every <s> seconds (4 times) each interpreting thread
    prints its pc, x0-x7 and a short backtrace.
29. **ZBIC NSOs** (Switch 2, SDK 22+, NSO flag bit 7), new crates/zbic + loader/src/nso.rs:
    Zstandard with "ZBIC" magic and BIC-coded FSE count headers (fse/bic.rs; the interval tree
    is generated, not tabled). Based on ruzstd 0.8.3 (MIT). Ocarina of Time (0400486024DEC000)
    used to fail with "bad LZ4 match offset"; all 3 segments of its main now match the SHA-256
    in the NSO header. `crates/loader/examples/nsodump.rs` writes a decompressed image.
30. **DT_RELR relocations + stale romfs.bin check** merged in from the E:\switchrecomp-studio
    copy (loader/dynamic.rs, package.rs).

31. **TLS+0x110 = thread handle** (rt/src/sched.rs `spawn`): SDK 22+ critical sections
    (`nn::os::detail::InternalCriticalSection::IsLockedByCurrentThread`, sdk+0x168fe0 in OoT) compare
    the lock word (& 0xbfffffff) with the u32 at tpidrro_el0+0x110, which Horizon fills, not the SDK.
    Left at 0, every unlocked mutex looked owned by the caller: Ocarina of Time aborted in
    pthread_mutex_lock during __nnmusl_init_dso. Now every thread gets its handle there (NX2navi does
    the same; MacNativeGames stores the thread ID because its ArbitrateLock is keyed by ID).
32. **am/IApplicationProxy 40 and 60** (services/am/applet.rs): Switch 2 sub-interface getters. 40 is a
    generic Stub; 60 is the new IGraphicsScalingParametersFunctions (`nn::am::GetGraphicsScalingParametersFunctions`):
    cmd 10 = graphics scale code read by nn::oe::GetCurrentGraphicsScale (10/20/30 = scale 0/1/2,
    anything else aborts; we answer 20 docked, 10 handheld), cmd 1050 =
    SetGraphicsScaleChangedNotificationEnabled. Without an object OoT hit a null deref at the start of nnMain.
    After 31-32, OoT (v0, built from F:\oot-decrypted) boots through gsv/syncpt/gpu/vi2, creates the graphics
    device, binds class 0xc797 and keeps running (60 s headless test, no crash).

33. **nx2 vi2 session** (services/nx2.rs): 212 GetLayerBufferBits returns the ready slots (0x7fff);
    OoT's main thread polled it once a second forever on the zero reply. 31/32 native events fire on a
    60 Hz thread ("kirikae-nx2-vsync"); 261 binds a slot to vsync, odd 263..271 to change notifications
    (fire once), even 262..272 unbind. 103 refresh rate (60), 104 HDR status (SDR, 400 nits), 105 paper
    white (203), 106 max resolution mode (4 docked / 2 handheld), 228 cancel and 229 present return the
    slots; 229 counts as a frame in KIRIKAE_STATS. 229 does not draw yet (needs gsv native images, below).
34. **/dev/nvhost-tsg-gpu** (services/nvdrv.rs `Device::Tsg`): 'T' ioctls 0x01-0x0f succeed (0x0b
    BIND_CHANNEL_EX, 0x08 u32 in/out); nvhost-gpu 0x1f/0x20 (Switch 2 NvRm channel setup) succeed with the
    arguments echoed. Behaviour as before, but explicit and no longer reported as missing.
35. **Six cores** (sched.rs CORES = 6, threads.rs CORE_MASK 0x3f, CreateThread/SetThreadCoreMask accept
    0-5): Switch 2 npdm ThreadInfo gives cores 0-5 and OoT pins threads to cores 4/5 (it aborted with
    0xe201 InvalidCoreId). svcGetInfo 0 (core mask) still reports 0b1111.
36. **Switch 2 memory budget** (horizon.rs `total_memory`): titles 04xxxxxxxxxxxxxx report 8.5 GiB
    (NX2_TOTAL_MEMORY) for GetInfo 6/21 and svcMapPhysicalMemory. OoT's nninitStartup makes its heap
    (total - used) & ~2 MiB - 0xB0A00000; with 3.2 GiB that went negative (null allocations, then a 0xca01
    SetHeapSize abort while it was over 6 GiB). Its heap is now about 5.7 GiB and fits the 6 GiB region.
    After 33-36 OoT runs 3+ minutes with ~8 threads loading from RomFS and no crash, but stays at 4 GPU
    submits and 0 frames: next is executing NVN 2 command streams (SWITCH2-PLAN.md) and gsv native
    images (111/423/429/430/435 still zeroed). Seen once, timing dependent: steady_clock::now failing
    (nn::time::GetStandardSteadyClockCurrentTimespec read while g_SharedMemoryClient+0x48 was 0).
37. **audout 5.1 downmix** (services/audio/out.rs): a 6-channel audio out (Super Mario RPG's
    FMOD output) only played front left/right; centre, LFE and both rear channels were
    dropped. Now mixed down (centre/rears x0.707, LFE x0.251). `KIRIKAE_TRACE_AUDIO=1` prints
    each channel's RMS every 5 s. (SMRPG's rears carry ambience and positional effects.)
38. **Real Opus decoding in hwopus** (services/hwopus.rs + vendored crates/opus-decoder,
    pure Rust, MIT/Apache): decoders used to output silence. Single and multistream (mapping
    read from the parameter buffer, Ex form too), reset flag honoured, bad packets give
    silence and a decoder reset. SMRPG only queries work-buffer sizes (its middleware decodes
    in software), so this is for other games.

Kirikae trees: C:\...\switchrecomp\kirikae-src is the master; it is mirrored to
E:\switchrecomp-studio\kirikae-src and C:\...\switchrecomp-coverage\kirikae-src (backups of
their previous files in backup\2026-11-10-sync). E:\switchrecomp-studio's tool/app were
rebuilt from it (old exes kept as *.before-zbic).

## Tools added (switchrecomp folder)

- `Log Window.bat` / `log-window.ps1`: live colour-coded log (newest test run, or `-Path`).
- `test\run.ps1`: run a game N seconds with stats; `DUMP_EVERY` (0 = no screenshots),
  `INPUT_FILE` (KIRIKAE_INPUT script), `LOG_WINDOW=1`, `DUMP_SHADERS=1`.
- `test\live.ps1` + `test\press.sh`: live-controller sessions (`-Refine` rebuilds first).
- `test\play.ps1`, `test\watch.ps1`, `test\skipset.ps1`, `test\smo-exp.ps1`: experiments.
- `test\dis.py`: Maxwell shader disassembler/inspector (uses the opcode table).
- `examples\sm70dis.rs` (kirikae-src/crates/maxwell): `cargo run -p kirikae-maxwell --example sm70dis -- <shader.bin> [hdr=0x80]`.
- `test\hillscore.py`: brightness score used for the Odyssey bisection.

## Things learned (avoid repeating)

- Kirikae's screenshot dump (`KIRIKAE_FRAME_DUMP`) reads back and encodes a PNG on the game
  thread: every dump costs ~55 ms. Measure frame rate with `DUMP_EVERY=0` or a large value.
- A shader with any unsupported instruction is dropped entirely (draw.rs), so a single missing op
  can blank a whole scene. `KIRIKAE_DRAW_PARTIAL=1` draws anyway, for diagnosis.
- If `build-patched.bat` says "Finished" but switchrecomp.exe's date doesn't change, run
  `cargo build --release --offline --bin switchrecomp` (with the linker env from the .bat) and copy
  `%LOCALAPPDATA%\srt-tool\release\switchrecomp.exe` by hand.
- Reverted: a spin-finish for guest `svcSleepThread` (the 55 fps it targeted came from screenshots).
