#include "image.hpp"
#include "scan.hpp"
#include "rel.hpp"
#include "disasm.hpp"
#include "bridge.hpp"
#include "runtime.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cassert>
#include <cstring>
#include <vector>
#include <numeric>

// crc32 table helper for observing memory delta
static uint32_t crc32_byte(uint32_t crc, uint8_t byte) {
    crc ^= byte;
    for (int j = 0; j < 8; ++j) {
        crc = (crc >> 1) ^ (0xEDB88320 & ~((crc & 1) - 1));
    }
    return crc;
}

static uint32_t calculate_crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc = crc32_byte(crc, data[i]);
    }
    return ~crc;
}

// global state for rip-relative tracking
static volatile uint64_t g_telemetry_state = 0xCAFEBABE1337C0DEULL;
static bool g_add_detour_hit = false;
static bool g_crypto_detour_hit = false;

// function pointer prototypes for trampolines
using fn_dummy_add = int(__fastcall*)(int, int);
using fn_dummy_crypto = uint64_t(__fastcall*)(const char*, size_t);

static fn_dummy_add o_dummy_add = nullptr;
static fn_dummy_crypto o_dummy_crypto = nullptr;

// dummy target functions with distinct prologue structures
[[msvc::noinline]] int __fastcall dummy_add(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    return x * 3 + y * 7 + 42;
}

[[msvc::noinline]] uint64_t __fastcall dummy_crypto(const char* data, size_t len) {
    // rip-relative read of global state
    uint64_t hash = g_telemetry_state;
    for (size_t i = 0; i < len; ++i) {
        hash = (hash ^ static_cast<uint8_t>(data[i])) * 1099511628211ULL;
    }
    return hash;
}

// synthetic alignment caves in .text to guarantee 128-byte capacity outside .pdata
#pragma section(".text$pad1", read, execute)
__declspec(allocate(".text$pad1")) const uint8_t g_code_cave_block_1[128] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};

#pragma section(".text$pad2", read, execute)
__declspec(allocate(".text$pad2")) const uint8_t g_code_cave_block_2[128] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

// detour handlers
int __fastcall detour_add(int a, int b) {
    g_add_detour_hit = true;
    std::cout << "  [DETOUR] detour_add intercepted (" << a << ", " << b << ")\n";
    std::cout << "  [DETOUR] calling original function via relocated trampoline ...\n";
    int orig_result = o_dummy_add(a, b);
    return orig_result + 1000;
}

uint64_t __fastcall detour_crypto(const char* data, size_t len) {
    g_crypto_detour_hit = true;
    std::cout << "  [DETOUR] detour_crypto intercepted (len=" << len << ")\n";
    std::cout << "  [DETOUR] calling original function via relocated trampoline ...\n";
    uint64_t orig_result = o_dummy_crypto(data, len);
    return orig_result ^ 0xAA55AA55AA55AA55ULL;
}

static std::string hex32(uint32_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << v;
    return ss.str();
}

static std::string hex64(uintptr_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << v;
    return ss.str();
}

int main() {
    std::cout << "deadspace in-process verification (x64)\n\n";

    // anchor synthetic caves so linker /OPT:REF retains them
    volatile const uint8_t* p1 = g_code_cave_block_1;
    volatile const uint8_t* p2 = g_code_cave_block_2;
    (void)p1; (void)p2;

    // baseline execution
    std::cout << "[*] running baseline pre-hook invocations ...\n";
    int base_add = dummy_add(5, 10);
    uint64_t base_crypto = dummy_crypto("deadspace", 9);
    std::cout << "    dummy_add(5, 10)       = " << base_add << " (expected 127)\n";
    std::cout << "    dummy_crypto('deadspace') = 0x" << std::hex << base_crypto << std::dec << "\n\n";

    // load in-memory image
    std::cout << "[*] loading in-memory image via GetModuleHandleA(nullptr) ...\n";
    auto img_opt = ds::image::load_memory(GetModuleHandleA(nullptr));
    if (!img_opt) {
        std::cerr << "[-] failed to load current module in memory.\n";
        return 1;
    }

    const auto& img = *img_opt;
    std::cout << "[+] self image mapped at base: " << hex64(img.base()) << "\n";
    std::cout << "    total sections: " << img.sections().size() << "\n";
    std::cout << "    .pdata entries: " << img.functions().size() << " verified functions\n\n";

    // find .text section and compute baseline crc32
    auto text_sec = img.find_section(".text");
    if (!text_sec) {
        std::cerr << "[-] .text section not found in self image.\n";
        return 1;
    }

    auto text_span = img.get_section_bytes(*text_sec);
    uint32_t baseline_crc = calculate_crc32(text_span.data(), text_span.size());
    std::cout << "[*] .text initial checksum (CRC32): " << hex32(baseline_crc)
              << " (" << text_span.size() << " bytes)\n\n";

    // scan for verified inter-function caves
    ds::scan_options opts;
    opts.min_size = 14;
    opts.type = ds::cave_type::any;
    opts.executable_only = true;
    opts.check_pdata = true;

    auto caves = ds::cave_scanner::find_caves(img, opts);
    std::cout << "[*] scanning for verified alignment caves outside .pdata functions ...\n";
    std::cout << "[+] found " << caves.size() << " suitable alignment cave(s) with >= 14 bytes\n\n";

    if (caves.empty()) {
        std::cerr << "[-] no alignment caves discovered in executable sections.\n";
        return 1;
    }

    for (size_t i = 0; i < (caves.size() < 5 ? caves.size() : 5); ++i) {
        const auto& c = caves[i];
        std::cout << "    cave #" << i << ": " << c.section_name << " RVA " << hex32(c.rva)
                  << " (" << hex64(c.va) << ", " << c.size << " bytes, "
                  << ds::cave_scanner::type_name(c.type) << ")\n";
    }
    std::cout << "\n";

    // hook 1: dummy_add
    const uintptr_t fn_add_va = reinterpret_cast<uintptr_t>(&dummy_add);
    const uint32_t fn_add_rva = img.va_to_rva(fn_add_va);

    std::cout << "[*] configuring hook 1: dummy_add (VA: " << hex64(fn_add_va) << ", RVA: " << hex32(fn_add_rva) << ")\n";

    // decode prologue instructions
    auto add_prologue = ds::disasm::decode_prologue(reinterpret_cast<const uint8_t*>(fn_add_va), 32, 5);
    size_t add_stolen = 0;
    for (const auto& insn : add_prologue) add_stolen += insn.length;
    std::cout << "    prologue decoded: " << add_prologue.size() << " insn(s), " << add_stolen << " bytes total\n";

    // cave capacity needed: bridge (14) + trampoline (add_stolen + 5)
    const size_t add_cap_needed = 14 + add_stolen + 5;
    auto reachable_caves = ds::rel::filter_reachable(caves, fn_add_va, add_cap_needed);
    if (reachable_caves.empty()) {
        std::cerr << "[-] no reachable cave for dummy_add.\n";
        return 1;
    }

    const auto& cave_add = reachable_caves.front().target_cave;
    std::cout << "    selected cave: RVA " << hex32(cave_add.rva) << " (capacity: " << cave_add.size << " bytes)\n";

    auto hook_add = ds::bridge::synthesize_two_stage(
        fn_add_va,
        cave_add.va,
        reinterpret_cast<uintptr_t>(&detour_add),
        reinterpret_cast<const uint8_t*>(fn_add_va),
        32,
        ds::bridge_type::abs64_indirect
    );

    if (!hook_add) {
        std::cerr << "[-] synthesis failed for dummy_add.\n";
        return 1;
    }

    o_dummy_add = reinterpret_cast<fn_dummy_add>(hook_add->trampoline_va);
    std::cout << "    trampoline synthesized at VA: " << hex64(hook_add->trampoline_va) << "\n";
    std::cout << "    hook site patch: " << ds::bridge::hex_dump(hook_add->hook_site_patch) << "\n";

    // commit full cave payload (bridge + original trampoline)
    std::vector<uint8_t> cave_add_payload = hook_add->cave_bridge_payload;
    cave_add_payload.insert(cave_add_payload.end(), hook_add->original_trampoline.begin(), hook_add->original_trampoline.end());

    bool add_installed = ds::runtime::install_in_process_hook(
        fn_add_va,
        cave_add.va,
        hook_add->hook_site_patch,
        cave_add_payload
    ).has_value();

    if (!add_installed) {
        std::cerr << "[-] install_in_process_hook failed for dummy_add.\n";
        return 1;
    }
    std::cout << "[+] hook 1 installed atomically via CAS\n\n";

    // execute hooked dummy_add
    std::cout << "[*] executing hooked dummy_add(5, 10) ...\n";
    int hooked_add = dummy_add(5, 10);
    std::cout << "    returned: " << hooked_add << " (expected " << (base_add + 1000) << ")\n";
    assert(g_add_detour_hit && "detour_add was not reached!");
    assert(hooked_add == base_add + 1000 && "hooked calculation result mismatch!");
    std::cout << "[PASS] hook 1 verified cleanly (detour hit + original trampoline executed without crash)\n\n";

    // hook 2: dummy_crypto (RIP-relative handling)
    const uintptr_t fn_crypto_va = reinterpret_cast<uintptr_t>(&dummy_crypto);
    const uint32_t fn_crypto_rva = img.va_to_rva(fn_crypto_va);

    std::cout << "[*] configuring hook 2: dummy_crypto (VA: " << hex64(fn_crypto_va) << ", RVA: " << hex32(fn_crypto_rva) << ")\n";

    auto crypto_prologue = ds::disasm::decode_prologue(reinterpret_cast<const uint8_t*>(fn_crypto_va), 32, 5);
    size_t crypto_stolen = 0;
    for (const auto& insn : crypto_prologue) crypto_stolen += insn.length;
    std::cout << "    prologue decoded: " << crypto_prologue.size() << " insn(s), " << crypto_stolen << " bytes total\n";

    const size_t crypto_cap_needed = 12 + crypto_stolen + 5; // using CET-safe reg_indirect (12 bytes)
    // filter out cave used by add
    std::vector<ds::cave> remaining_caves;
    for (const auto& c : caves) {
        if (c.rva != cave_add.rva) remaining_caves.push_back(c);
    }

    auto reachable_crypto = ds::rel::filter_reachable(remaining_caves, fn_crypto_va, crypto_cap_needed);
    if (reachable_crypto.empty()) {
        std::cerr << "[-] no reachable cave for dummy_crypto.\n";
        return 1;
    }

    const auto& cave_crypto = reachable_crypto.front().target_cave;
    std::cout << "    selected cave: RVA " << hex32(cave_crypto.rva) << " (capacity: " << cave_crypto.size << " bytes)\n";

    auto hook_crypto = ds::bridge::synthesize_two_stage(
        fn_crypto_va,
        cave_crypto.va,
        reinterpret_cast<uintptr_t>(&detour_crypto),
        reinterpret_cast<const uint8_t*>(fn_crypto_va),
        32,
        ds::bridge_type::reg_indirect
    );

    if (!hook_crypto) {
        std::cerr << "[-] synthesis failed for dummy_crypto.\n";
        return 1;
    }

    o_dummy_crypto = reinterpret_cast<fn_dummy_crypto>(hook_crypto->trampoline_va);
    std::cout << "    trampoline synthesized at VA: " << hex64(hook_crypto->trampoline_va) << "\n";

    std::vector<uint8_t> cave_crypto_payload = hook_crypto->cave_bridge_payload;
    cave_crypto_payload.insert(cave_crypto_payload.end(), hook_crypto->original_trampoline.begin(), hook_crypto->original_trampoline.end());

    bool crypto_installed = ds::runtime::install_in_process_hook(
        fn_crypto_va,
        cave_crypto.va,
        hook_crypto->hook_site_patch,
        cave_crypto_payload
    ).has_value();

    if (!crypto_installed) {
        std::cerr << "[-] install_in_process_hook failed for dummy_crypto.\n";
        return 1;
    }
    std::cout << "[+] hook 2 installed atomically via CAS\n\n";

    // execute hooked dummy_crypto
    std::cout << "[*] executing hooked dummy_crypto('deadspace', 9) ...\n";
    uint64_t hooked_crypto = dummy_crypto("deadspace", 9);
    std::cout << "    returned: 0x" << std::hex << hooked_crypto << " (expected 0x" << (base_crypto ^ 0xAA55AA55AA55AA55ULL) << ")" << std::dec << "\n";
    assert(g_crypto_detour_hit && "detour_crypto was not reached!");
    assert(hooked_crypto == (base_crypto ^ 0xAA55AA55AA55AA55ULL) && "hooked crypto result mismatch!");
    std::cout << "[PASS] hook 2 verified cleanly (detour hit + RIP-relative relocated instructions executed)\n\n";

    // observe CRC32 change on .text
    uint32_t post_hook_crc = calculate_crc32(text_span.data(), text_span.size());
    std::cout << "[*] .text post-hook checksum (CRC32): " << hex32(post_hook_crc)
              << " (delta from baseline: " << hex32(baseline_crc ^ post_hook_crc) << ")\n\n";

    std::cout << "[+] live test complete:\n"
              << "    dummy_add:    intercepted (stolen=" << add_stolen << ", tramp=" << hex32(img.va_to_rva(hook_add->trampoline_va)) << ")\n"
              << "    dummy_crypto: intercepted (stolen=" << crypto_stolen << ", tramp=" << hex32(img.va_to_rva(hook_crypto->trampoline_va)) << ")\n";

    return 0;
}
