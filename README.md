# switchrecomp
 # this fork is still a work in progress
Turns your own Nintendo Switch game dumps into native Windows executables. It is a front end over
[Kirikae](https://github.com/Cor3Duo/kirikae) (MIT/Apache-2.0), a Rust static recompiler: the game's
AArch64 code is lifted to an IR, compiled with Cranelift into a native `.exe`, and linked with
Kirikae's runtime (Horizon kernel and services, Maxwell GPU on Vulkan, audio, video, input).
No emulator runs.

switchrecomp adds: input detection with clear fixes, a game library, one-command
build / play / refine, coverage summaries, a menu, drag-and-drop, and a `doctor` check.

## Setup (once)

1. Install Rust: https://rustup.rs (rustc 1.88 or newer).
2. Install Visual Studio Build Tools with **Desktop development with C++**.
3. A GPU driver with **Vulkan 1.3**.
4. Double-click `setup.bat`. It builds `switchrecomp.exe` here and runs `switchrecomp doctor`.

## What to feed it

Kirikae never decrypts anything, and neither does switchrecomp. Accepted:

| Input | Works directly |
|---|---|
| Folder with `exefs/` (+ `romfs/`), e.g. from nxdumptool on your console | yes |
| NSP whose NCAs are not encrypted | yes |
| Single `.nso` / homebrew `.nro` | yes |
| Retail (encrypted) NSP, NSZ, XCI | no: dump ExeFS/RomFS from your own console or decrypt with your own console's keys first |

`switchrecomp inspect <dump>` tells you which one you have and what to do about it.
Base games only; updates and DLC are not supported by Kirikae yet.

## Use

```
switchrecomp                         menu
switchrecomp inspect game.nsp        title, title ID, modules, lifter coverage
switchrecomp build game.nsp          -> games\<name>\<name>.exe
switchrecomp play <name> [--stats]   run it (keyboard or XInput pad)
switchrecomp refine <name>           rebuild using the play profile
switchrecomp coverage <name>         what the game used that the runtime lacks
switchrecomp extract game.nsp out    write out\exefs and out\romfs
switchrecomp list                    your built games
```

Or drag an NSP or dump folder onto `switchrecomp.exe`.

### The build-play-refine loop

Static analysis can't find every function (jump tables, vtables). Code it missed runs in
Kirikae's interpreter, and the game writes those addresses to `<name>.profile` every 10 s.
`switchrecomp refine <name>` rebuilds with them compiled natively. One play session is
usually enough. `build --fresh` ignores the profile.

## Where things go

- `games\<name>\` - the executable, its `<name>-build` Cargo project, profile and coverage report
- `library.json` - your built games
- `%LOCALAPPDATA%\srt` - Cargo build cache for games (short path on purpose; set `CARGO_TARGET_DIR` to move it)
- `%APPDATA%\kirikae\saves\<title id>` - saves

## Controls (Kirikae defaults)

Left stick WASD/arrows, right stick IJKL, A/B/X/Y = Z or Space/X/C/V, L/R/ZL/ZR = E/U/Q/O,
+/- = Enter/Backspace, D-pad TFGH. First XInput gamepad works too.

## Updating Kirikae

`Cargo.toml` pins Kirikae to commit `726c4a1`. Change `rev` to a newer commit (or `branch = "main"`)
and rerun `setup.bat`.

## Legal

Only use games dumped from your own console. Do not share the executables you build: they
contain the game's code. Not affiliated with Nintendo.
