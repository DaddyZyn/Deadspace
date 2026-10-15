# deadspace

x64 PE alignment cave scanner and zero-alloc detour engine.
Finds compiler alignment padding and slack space in `.text` (verified against `.pdata` exception tables) to place trampolines and bridges. No unbacked `PAGE_EXECUTE_READWRITE` pages, no `VirtualAlloc` private memory allocations for EDR memory scanners to flag.

## build

Requires MSVC with C++20 support.

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## usage

### cli tool
```cmd
# scan for verified alignment caves in target PE
deadspace.exe target.exe --min 14

# generate static 2-stage patch (cave bridge + relocated original trampoline)
deadspace.exe target.exe --target 0x14001000 --dest 0x7FFF80000000 --patch-out target_patched.exe
```

### in-process detours
```cpp
#include <deadspace/runtime.hpp>
#include <deadspace/bridge.hpp>

// reflective self-scan or target module scan
auto img = ds::image::load_memory(GetModuleHandleA(nullptr));
auto caves = ds::cave_scanner::find_caves(*img, { .min_size = 28 });

ds::cave_allocator alloc(caves);
auto cave = alloc.allocate(target_fn_va, 28);

auto hook = ds::bridge::synthesize_two_stage(
    target_fn_va,
    cave->va,
    (uintptr_t)&my_detour_handler,
    target_fn_ptr,
    16
);

// atomic CAS commit across prologue
auto active = ds::runtime::install_in_process_hook(*hook);

// call original function via relocated trampoline
using fn_t = int(*)(int, int);
auto orig = reinterpret_cast<fn_t>(hook->trampoline_va);
int res = orig(10, 20);

// rollback: atomic CAS restores prologue, cave bytes wiped, flushes icache
ds::runtime::uninstall_in_process_hook(*active);
```

## details

- **.pdata validation**: MSVC puts switch tables and floating point constants straight into `.text`. Cave runs (`0xCC`, `0x90`, multi-byte NOPs, `0x00`) are checked against runtime exception tables `[BeginAddress, EndAddress)` with binary search so we never stomp switch jump targets.
- **rel8 branch widening**: short jumps (`70..7F` jcc, `EB` jmp) stolen from the prologue get rewritten to 32-bit displacements (`0F 8x` and `E9`) in the trampoline with relocated branch targets.
- **rip-relative fixups**: `[rip + disp32]` memory operands get displacement recalculation based on cave VA vs target VA.
- **2-byte hotpatch short-jump**: if standard 5-byte padding (`0xCC`/`0x90`) exists before the function, drops an `E9 <disp32>` in padding and an `EB F9` (`jmp short -7`) at entry, stealing only 2 bytes.
- **multi-hook sub-allocator**: carves 16-byte aligned slices from caves with remaining capacity tracking so multiple detours share padding.
- **atomic CAS commit**: patches function entry with `_InterlockedCompareExchange64` to prevent instruction tearing. Transactional unhook restores original bytes and section CRC32 1:1.
