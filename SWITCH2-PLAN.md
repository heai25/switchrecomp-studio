# Native Switch 2 support in Kirikae / SwitchRecomp

Goal: recompile Switch 2 games (Welcome Tour first) the same way Switch 1 games are done —
native CPU code, the GPU emulated on Vulkan.

## What is different on Switch 2

| Area | Switch 1 | Switch 2 | Status |
|---|---|---|---|
| CPU | Cortex-A57, ARMv8.0 | Cortex-A78C, ARMv8.2+ (PAC, LSE atomics, LDAPR) | **Done** (FIXES 15-17) |
| OS / services | Horizon | Horizon (new GetInfo ids, appletOE cmds) | Partly done (FIXES 13-14) |
| GPU engine classes | B197 / B1C0 / B0B5 / B06F | C797 / C7C0 / C7B5 / C76F | **Done** (FIXES 19) |
| 3D methods | Maxwell | 647 of 663 identical offsets; per-stage 40-bit program addresses; new semaphores | **Done** (FIXES 20-21) |
| Shader ISA | Maxwell SM53, 64-bit + sched words | SM86, 128-bit instructions, uniform registers (UR0-63), BSSY/BSYNC | Decoder **done** (FIXES 22); translation **todo** |
| Shader header | SPH v3, 0x50 bytes | SPH v4, 0x80 bytes | todo (check sph.rs) |
| Compute launch | Maxwell QMD | Ampere QMD v3 (layout in mesa `nak/qmd.rs`) | todo |
| Textures (TIC/TSC) | Maxwell headers | same 32-byte format family; verify block-linear/ASTC fields | verify |
| Macro engine (MME) | MME v1 | Turing+ adds MME DMA; check the macro ISA | verify |
| GPU driver interface | nvdrv (nvhost-gpu, nvmap...) | **gsv "Graphics Supervisor"**: session from nn::am::GetGraphicsSupervisor, then nn::gsv::BootWithRemoteMemory (process handle + remote memory) | **todo — current blocker** |
| Video | NVDEC (host1x) | NVDEC newer class | todo when a game needs it |

## Shader translation: chosen approach

The Maxwell translator (translate.rs, ~4000 lines) works directly on Maxwell bit fields and already
handles the hard parts: IO attributes, bindless textures through cbuf handles, control-flow
structurisation, half/double ops. Two ways to reuse it:

1. **Transcoder (fast path, first):** turn each SM70 instruction into the equivalent Maxwell
   instruction word(s), then run the existing translator unchanged.
   - Maxwell already has IADD3, LOP3, SHF, LEA, PRMT, IMAD, FFMA, FSETP/ISETP, TEX/TLD, IPA, ALD/AST.
   - Branch targets: rewrite 16-byte SM70 offsets to the Maxwell 8-byte layout (plus a sched word per 3).
   - BSSY/BSYNC/BREAK -> SSY/SYNC/PBK/BRK.
   - Uniform registers UR0-63 -> a reserved GPR range the shader doesn't use (the header gives the
     register count; Ampere shaders rarely use more than ~128).
   - TEX with a cbuf reference (0xb60) maps straight onto the existing bindless-handle path.
2. **Native SM70 frontend (later, if the transcoder hits a wall):** an SM70 decoder feeding the
   translator's emit helpers directly.

## Next steps, in order
1. ~~Good Welcome Tour RomFS~~ done (FIXES 23-24). Boot now reaches nn::gsv::BootWithRemoteMemory.
1b. Reverse-engineer and emulate the gsv service (the Switch 2 replacement for nvdrv): find which am
   command is GetGraphicsSupervisor, then the gsv command set used by nn::gpu / nn::gsv in sdk.
   The runtime will log "Ampere GPU classes detected" once the GPU channel binds C797.
2. Capture its shaders (`DUMP_SHADERS=1`) and run `sm70dis` on them to list the opcodes actually used.
3. Write the transcoder for that opcode set; add SPH v4 parsing.
4. Ampere QMD for compute dispatches.
5. Play-test, refine, log fixes in FIXES.md.
