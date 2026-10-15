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

## internals

- **.pdata false-positive filtering**: compilers routinely emit switch jump tables and vector constants directly into `.text`. Candidate cave runs (`0xCC`, `0x90`, multi-byte NOPs, `0x00`) are verified against runtime function bounds `[BeginAddress, EndAddress)` via $O(\log N)$ binary search.
- **rel8 branch widening**: short conditional branches (`70..7F`) and unconditional jumps (`EB`) inside stolen prologues are widened into 32-bit displacements (`0F 8x` and `E9`) inside the relocated trampoline, recalculating branch targets relative to the cave VA.
- **rip-relative displacement recalculation**: fixes `[rip + disp32]` operands so relocated instructions still reference their original variables and data tables.
- **2-byte hotpatch short-jump**: detects standard MSVC 5-byte padding preceding function entries (`hook_va - 5`), placing an `E9 <disp32>` jump in the padding and `EB F9` (`jmp short -7`) at function head—stealing only 2 bytes instead of 5+.
- **multi-hook sub-allocator**: dynamically carves 16-byte aligned slices out of larger alignment caves, tracking remaining capacity so multiple hooks pack into the same cave without stomping each other.
- **atomic CAS commit & rollback**: patches prologue entry using `_InterlockedCompareExchange64` to prevent instruction tearing across threads, and transactional unhooking restores original bytes and section CRC32 baseline 100%.
