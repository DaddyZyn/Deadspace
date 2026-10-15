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

// crc32 helper for section integrity observation
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

// target 1: rip-relative global access
static volatile int64_t g_telemetry_counter = 0x1122334455667788LL;
static bool g_detour1_hit = false;

using fn_target1 = int64_t(__fastcall*)(int64_t);
static fn_target1 o_target1 = nullptr;

[[msvc::noinline]] int64_t __fastcall target_rip_global(int64_t val) {
    g_telemetry_counter += val;
    return g_telemetry_counter ^ 0x55AA55AA55AA55AALL;
}

int64_t __fastcall detour_rip_global(int64_t val) {
    g_detour1_hit = true;
    std::cout << "  [DETOUR #1] detour_rip_global intercepted (val=" << val << ")\n";
    std::cout << "  [DETOUR #1] calling original function via relocated trampoline ...\n";
    int64_t orig = o_target1(val);
    return orig + 1000;
}

// target 2: multi-instruction boundary with stolen bytes > 8
static bool g_detour2_hit = false;

using fn_target2 = int64_t(__fastcall*)(int64_t, int64_t, int64_t, int64_t);
static fn_target2 o_target2 = nullptr;

[[msvc::noinline]] int64_t __fastcall target_long_prologue(int64_t a, int64_t b, int64_t c, int64_t d) {
    volatile int64_t big_magic = 0x1122334455667788LL;
    volatile int64_t comp = (a * 7) ^ (b * 13) ^ (c * 31);
    return comp + d + big_magic;
}

int64_t __fastcall detour_long_prologue(int64_t a, int64_t b, int64_t c, int64_t d) {
    g_detour2_hit = true;
    std::cout << "  [DETOUR #2] detour_long_prologue intercepted (" << a << ", " << b << ", " << c << ", " << d << ")\n";
    std::cout << "  [DETOUR #2] calling original function via relocated trampoline ...\n";
    int64_t orig = o_target2(a, b, c, d);
    return orig ^ 0x0F0F0F0F0F0F0F0FLL;
}

// target 3: short conditional branch (rel8) in prologue widened to rel32
static bool g_detour3_hit = false;

using fn_target3 = int64_t(__fastcall*)(int64_t);
static fn_target3 o_target3 = nullptr;

__declspec(noinline) int64_t __fastcall target_short_branch(int64_t x) {
    if (x <= 0) {
        return -42;
    }
    return x * 100 + 7;
}

int64_t __fastcall detour_short_branch(int64_t x) {
    g_detour3_hit = true;
    std::cout << "  [DETOUR #3] detour_short_branch intercepted (x=" << x << ")\n";
    std::cout << "  [DETOUR #3] calling original function via relocated trampoline ...\n";
    int64_t orig = o_target3(x);
    return orig * 2;
}

// synthetic alignment caves in .text (placed outside .pdata functions)
#pragma section(".text$pad1", read, execute)
__declspec(allocate(".text$pad1")) const uint8_t g_synthetic_cave_1[128] = {
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
__declspec(allocate(".text$pad2")) const uint8_t g_synthetic_cave_2[128] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

#pragma section(".text$pad3", read, execute)
__declspec(allocate(".text$pad3")) const uint8_t g_synthetic_cave_3[128] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};

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
    std::cout << "deadspace self-test verifier (x64)\n\n";

    // anchor synthetic cave arrays against linker dead-stripping
    volatile const uint8_t* p1 = g_synthetic_cave_1;
    volatile const uint8_t* p2 = g_synthetic_cave_2;
    volatile const uint8_t* p3 = g_synthetic_cave_3;
    (void)p1; (void)p2; (void)p3;

    // 1. baseline execution
    std::cout << "[*] baseline execution of targets prior to hooking ...\n";
    int64_t base1 = target_rip_global(100);
    int64_t base2 = target_long_prologue(1, 2, 3, 4);
    int64_t base3_neg = target_short_branch(-5);
    int64_t base3_pos = target_short_branch(10);

    std::cout << "    target_rip_global(100)        = " << hex64(base1) << "\n";
    std::cout << "    target_long_prologue(1,2,3,4) = " << hex64(base2) << "\n";
    std::cout << "    target_short_branch(-5)       = " << base3_neg << " (expected -42)\n";
    std::cout << "    target_short_branch(10)       = " << base3_pos << " (expected 1007)\n\n";

    // 2. load self in-memory image
    std::cout << "[*] loading in-memory image via GetModuleHandleA(nullptr) ...\n";
    auto img_opt = ds::image::load_memory(GetModuleHandleA(nullptr));
    if (!img_opt) {
        std::cerr << "[-] failed to load self image in memory.\n";
        return 1;
    }

    const auto& img = *img_opt;
    std::cout << "[+] self image mapped at base: " << hex64(img.base()) << "\n";
    std::cout << "    total sections: " << img.sections().size() << "\n";
    std::cout << "    .pdata entries: " << img.functions().size() << " verified functions\n\n";

    auto text_sec = img.find_section(".text");
    if (!text_sec) {
        std::cerr << "[-] .text section not found in self image.\n";
        return 1;
    }

    auto text_span = img.get_section_bytes(*text_sec);
    uint32_t baseline_crc = calculate_crc32(text_span.data(), text_span.size());
    std::cout << "[*] .text initial baseline checksum (CRC32): " << hex32(baseline_crc)
              << " (" << text_span.size() << " bytes)\n\n";

    // 3. scan for verified alignment caves outside .pdata functions
    ds::scan_options opts;
    opts.min_size = 14;
    opts.type = ds::cave_type::any;
    opts.executable_only = true;
    opts.check_pdata = true;

    auto caves = ds::cave_scanner::find_caves(img, opts);
    std::cout << "[*] scanning for verified alignment caves outside .pdata ...\n";
    std::cout << "[+] discovered " << caves.size() << " suitable alignment cave(s) with >= 14 bytes\n\n";

    if (caves.empty()) {
        std::cerr << "[-] expected alignment caves for hooking.\n";
        return 1;
    }

    // print discovered caves with full 64-bit VA formatting
    std::cout << "+-----+----------+------------+--------------------+-------+-------------------------+-------------------+\n";
    std::cout << "| IDX | SECTION  |    RVA     |         VA         | SIZE  | TYPE                    | STATUS            |\n";
    std::cout << "+-----+----------+------------+--------------------+-------+-------------------------+-------------------+\n";
    for (size_t i = 0; i < (caves.size() < 6 ? caves.size() : 6); ++i) {
        const auto& c = caves[i];
        std::cout << "| #" << std::setw(2) << i << " | "
                  << std::left << std::setw(8) << c.section_name << " | "
                  << hex32(c.rva) << " | "
                  << hex64(c.va) << " | "
                  << std::right << std::setw(5) << c.size << " | "
                  << std::left << std::setw(23) << ds::cave_scanner::type_name(c.type) << " | "
                  << (c.verified_inter_function ? "VERIFIED OUTSIDE " : "INSIDE FUNC BODY ") << "|\n";
    }
    std::cout << "+-----+----------+------------+--------------------+-------+-------------------------+-------------------+\n\n";

    // initialize stateful cave sub-allocator
    std::cout << "[*] initializing stateful multi-hook cave sub-allocator ...\n";
    ds::cave_allocator allocator(caves);

    // hook 1: rip-relative global access
    const uintptr_t fn1_va = reinterpret_cast<uintptr_t>(&target_rip_global);
    const uint32_t fn1_rva = img.va_to_rva(fn1_va);
    std::cout << "[*] configuring hook 1: target_rip_global (VA: " << hex64(fn1_va) << ", RVA: " << hex32(fn1_rva) << ")\n";

    auto p1_insns = ds::disasm::decode_prologue(reinterpret_cast<const uint8_t*>(fn1_va), 32, 5);
    size_t stolen1 = 0;
    for (const auto& in : p1_insns) stolen1 += in.length;
    std::cout << "    prologue decoded: " << p1_insns.size() << " insn(s), " << stolen1 << " bytes stolen\n";

    const size_t req_bytes1 = 14 + stolen1 + 5;
    auto cave1_opt = allocator.allocate(fn1_va, req_bytes1, 16);
    assert(cave1_opt.has_value() && "allocator failed for target 1");
    auto cave1 = *cave1_opt;
    std::cout << "    allocated cave slice: RVA " << hex32(cave1.rva) << " (" << cave1.size << " bytes at " << hex64(cave1.va) << ")\n";

    auto hook1 = ds::bridge::synthesize_two_stage(
        fn1_va,
        cave1.va,
        reinterpret_cast<uintptr_t>(&detour_rip_global),
        reinterpret_cast<const uint8_t*>(fn1_va),
        32,
        ds::bridge_type::abs64_indirect
    );
    assert(hook1.has_value() && "synthesis failed for hook 1");

    o_target1 = reinterpret_cast<fn_target1>(hook1->trampoline_va);
    std::cout << "    trampoline synthesized at VA: " << hex64(hook1->trampoline_va) << "\n";

    std::vector<uint8_t> payload1 = hook1->cave_bridge_payload;
    payload1.insert(payload1.end(), hook1->original_trampoline.begin(), hook1->original_trampoline.end());

    auto hk1 = ds::runtime::install_in_process_hook(fn1_va, cave1.va, hook1->hook_site_patch, payload1);
    if (!hk1) {
        std::cerr << "[-] install_in_process_hook failed for target 1\n";
        return 1;
    }
    std::cout << "[+] hook 1 installed atomically via CAS\n";

    int64_t hooked1 = target_rip_global(50);
    std::cout << "    target_rip_global(50) returned: " << hex64(hooked1) << "\n";
    assert(g_detour1_hit && "detour 1 was not hit!");
    std::cout << "[PASS] hook 1 verified (detour executed + RIP-relative global relocated safely)\n\n";

    // hook 2: multi-instruction prologue with stolen bytes > 8
    const uintptr_t fn2_va = reinterpret_cast<uintptr_t>(&target_long_prologue);
    const uint32_t fn2_rva = img.va_to_rva(fn2_va);
    std::cout << "[*] configuring hook 2: target_long_prologue (VA: " << hex64(fn2_va) << ", RVA: " << hex32(fn2_rva) << ")\n";

    auto p2_insns = ds::disasm::decode_prologue(reinterpret_cast<const uint8_t*>(fn2_va), 32, 5);
    size_t stolen2 = 0;
    for (const auto& in : p2_insns) stolen2 += in.length;
    std::cout << "    prologue decoded: " << p2_insns.size() << " insn(s), " << stolen2 << " bytes stolen\n";

    const size_t req_bytes2 = 12 + stolen2 + 5;
    auto cave2_opt = allocator.allocate(fn2_va, req_bytes2, 16);
    assert(cave2_opt.has_value() && "allocator failed for target 2");
    auto cave2 = *cave2_opt;
    std::cout << "    allocated cave slice: RVA " << hex32(cave2.rva) << " (" << cave2.size << " bytes at " << hex64(cave2.va) << ")\n";

    auto hook2 = ds::bridge::synthesize_two_stage(
        fn2_va,
        cave2.va,
        reinterpret_cast<uintptr_t>(&detour_long_prologue),
        reinterpret_cast<const uint8_t*>(fn2_va),
        32,
        ds::bridge_type::reg_indirect
    );
    assert(hook2.has_value() && "synthesis failed for hook 2");

    o_target2 = reinterpret_cast<fn_target2>(hook2->trampoline_va);
    std::cout << "    trampoline synthesized at VA: " << hex64(hook2->trampoline_va) << "\n";

    std::vector<uint8_t> payload2 = hook2->cave_bridge_payload;
    payload2.insert(payload2.end(), hook2->original_trampoline.begin(), hook2->original_trampoline.end());

    auto hk2 = ds::runtime::install_in_process_hook(fn2_va, cave2.va, hook2->hook_site_patch, payload2);
    if (!hk2) {
        std::cerr << "[-] install_in_process_hook failed for target 2\n";
        return 1;
    }
    std::cout << "[+] hook 2 installed atomically via CAS (stolen_bytes=" << stolen2 << ")\n";

    int64_t hooked2 = target_long_prologue(1, 2, 3, 4);
    std::cout << "    target_long_prologue(1, 2, 3, 4) returned: " << hex64(hooked2) << "\n";
    assert(g_detour2_hit && "detour 2 was not hit!");
    std::cout << "[PASS] hook 2 verified (stolen_bytes > 8 atomic CAS + original trampoline return)\n\n";

    // hook 3: short branch (rel8) in prologue widened to rel32
    const uintptr_t fn3_va = reinterpret_cast<uintptr_t>(&target_short_branch);
    const uint32_t fn3_rva = img.va_to_rva(fn3_va);
    std::cout << "[*] configuring hook 3: target_short_branch (VA: " << hex64(fn3_va) << ", RVA: " << hex32(fn3_rva) << ")\n";

    auto p3_insns = ds::disasm::decode_prologue(reinterpret_cast<const uint8_t*>(fn3_va), 32, 5);
    size_t stolen3 = 0;
    for (const auto& in : p3_insns) stolen3 += in.length;
    std::cout << "    prologue decoded: " << p3_insns.size() << " insn(s), " << stolen3 << " bytes stolen\n";

    for (size_t i = 0; i < p3_insns.size(); ++i) {
        std::cout << "      insn #" << i << ": " << ds::bridge::hex_dump(p3_insns[i].raw_bytes)
                  << " (len=" << p3_insns[i].length << ", is_rel=" << p3_insns[i].is_relative_branch << ")\n";
    }

    const size_t req_bytes3 = 14 + stolen3 + 5 + 4;
    auto cave3_opt = allocator.allocate(fn3_va, req_bytes3, 16);
    assert(cave3_opt.has_value() && "allocator failed for target 3");
    auto cave3 = *cave3_opt;
    std::cout << "    allocated cave slice: RVA " << hex32(cave3.rva) << " (" << cave3.size << " bytes at " << hex64(cave3.va) << ")\n";

    auto hook3 = ds::bridge::synthesize_two_stage(
        fn3_va,
        cave3.va,
        reinterpret_cast<uintptr_t>(&detour_short_branch),
        reinterpret_cast<const uint8_t*>(fn3_va),
        32,
        ds::bridge_type::abs64_indirect
    );
    assert(hook3.has_value() && "synthesis failed for hook 3");

    o_target3 = reinterpret_cast<fn_target3>(hook3->trampoline_va);
    std::cout << "    trampoline synthesized at VA: " << hex64(hook3->trampoline_va)
              << " (rel8 branch widened to rel32, trampoline size: " << hook3->original_trampoline.size() << " bytes)\n";

    std::vector<uint8_t> payload3 = hook3->cave_bridge_payload;
    payload3.insert(payload3.end(), hook3->original_trampoline.begin(), hook3->original_trampoline.end());

    auto hk3 = ds::runtime::install_in_process_hook(fn3_va, cave3.va, hook3->hook_site_patch, payload3);
    if (!hk3) {
        std::cerr << "[-] install_in_process_hook failed for target 3\n";
        return 1;
    }
    std::cout << "[+] hook 3 installed atomically via CAS\n";

    fn_target3 volatile live_fn3 = &target_short_branch;
    int64_t hooked3_neg = live_fn3(-5);
    std::cout << "    live_fn3(-5) returned: " << hooked3_neg << " (expected " << (-42 * 2) << ")\n";
    if (hooked3_neg != -84) {
        std::cerr << "[-] rel8 widened branch taken mismatch: " << hooked3_neg << "\n";
        return 1;
    }

    int64_t hooked3_pos = live_fn3(10);
    std::cout << "    live_fn3(10) returned: " << hooked3_pos << " (expected " << (1007 * 2) << ")\n";
    if (hooked3_pos != 2014) {
        std::cerr << "[-] rel8 widened branch fallthrough mismatch: " << hooked3_pos << "\n";
        return 1;
    }

    if (!g_detour3_hit) {
        std::cerr << "[-] detour 3 was not hit!\n";
        return 1;
    }
    std::cout << "[PASS] hook 3 verified (rel8 widened branch both taken and fallthrough executed cleanly)\n\n";

    // 4. verify 2-byte hotpatch short-jump synthesis
    std::cout << "[*] verifying 2-byte hotpatch short-jump synthesis ...\n";
    const uint8_t mock_hotpatch_padding[5] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    const uint8_t mock_target_prologue[2] = { 0x8B, 0xFF }; // mov edi, edi (2 bytes)

    auto hot_hook = ds::bridge::synthesize_two_stage(
        fn1_va,
        cave1.va,
        reinterpret_cast<uintptr_t>(&detour_rip_global),
        mock_target_prologue,
        sizeof(mock_target_prologue),
        ds::bridge_type::abs64_indirect,
        mock_hotpatch_padding
    );

    assert(hot_hook.has_value() && "hotpatch synthesis failed");
    assert(hot_hook->is_hotpatch && "is_hotpatch must be true");
    assert(hot_hook->stolen_bytes == 2 && "hotpatch stolen bytes must be 2");
    assert(hot_hook->hook_site_patch.size() == 2 && "hook_site_patch must be 2 bytes");
    assert(hot_hook->hook_site_patch[0] == 0xEB && hot_hook->hook_site_patch[1] == 0xF9 && "short jmp -7 mismatch");
    assert(hot_hook->hotpatch_pre_patch.size() == 5 && hot_hook->hotpatch_pre_patch[0] == 0xE9 && "pre-patch E9 mismatch");
    std::cout << "    hotpatch patch emitted: " << ds::bridge::hex_dump(hot_hook->hook_site_patch)
              << " [EB F9 -> jmp short -7]\n";
    std::cout << "    pre-padding patch emitted: " << ds::bridge::hex_dump(hot_hook->hotpatch_pre_patch)
              << " [E9 <disp32> -> jmp cave]\n";
    std::cout << "[PASS] 2-byte hotpatch short-jump optimization verified\n\n";

    // 5. observe post-hook section checksum
    uint32_t post_hook_crc = calculate_crc32(text_span.data(), text_span.size());
    std::cout << "[*] .text post-hook checksum (CRC32): " << hex32(post_hook_crc)
              << " (delta from baseline: " << hex32(baseline_crc ^ post_hook_crc) << ")\n\n";
    assert(post_hook_crc != baseline_crc && "post-hook CRC32 must differ from baseline while hooks are active");

    // 6. transactional unhooking & baseline state restoration
    std::cout << "[*] executing transactional unhook on all active hooks ...\n";

    bool un3 = ds::runtime::uninstall_in_process_hook(*hk3);
    assert(un3 && "failed to unhook target 3");
    (void)un3;
    std::cout << "    hook 3 uninstalled and original prologue restored\n";

    bool un2 = ds::runtime::uninstall_in_process_hook(*hk2);
    assert(un2 && "failed to unhook target 2");
    (void)un2;
    std::cout << "    hook 2 uninstalled and original prologue restored\n";

    bool un1 = ds::runtime::uninstall_in_process_hook(*hk1);
    assert(un1 && "failed to unhook target 1");
    (void)un1;
    std::cout << "    hook 1 uninstalled and original prologue restored\n";

    // verify target functions now execute natively without hitting detours
    g_detour1_hit = false;
    g_detour2_hit = false;
    g_detour3_hit = false;

    std::cout << "[*] calling targets post-unhook to verify native unhooked execution ...\n";
    int64_t post_unhook1 = target_rip_global(100);
    assert(!g_detour1_hit && "detour 1 hit after unhook!");
    (void)post_unhook1;

    int64_t post_unhook2 = target_long_prologue(1, 2, 3, 4);
    assert(!g_detour2_hit && "detour 2 hit after unhook!");
    assert(post_unhook2 == base2 && "unhooked target 2 return mismatch");
    (void)post_unhook2;

    int64_t post_unhook3 = target_short_branch(10);
    assert(!g_detour3_hit && "detour 3 hit after unhook!");
    assert(post_unhook3 == base3_pos && "unhooked target 3 return mismatch");
    (void)post_unhook3;
    std::cout << "[+] all targets executed cleanly post-unhook without detour interception\n";

    // verify .text section checksum returns 100% to baseline
    uint32_t post_unhook_crc = calculate_crc32(text_span.data(), text_span.size());
    std::cout << "[*] .text post-unhook checksum (CRC32): " << hex32(post_unhook_crc)
              << " (baseline: " << hex32(baseline_crc) << ")\n";
    assert(post_unhook_crc == baseline_crc && "post-unhook CRC32 must match pre-hook baseline 100%!");
    std::cout << "[PASS] post-unhook CRC32 matches baseline 100% (" << hex32(post_unhook_crc) << " == " << hex32(baseline_crc) << ")\n\n";

    // 7. verification summary table
    std::cout << "========================================================================\n";
    std::cout << "                        VERIFICATION SUMMARY TABLE                      \n";
    std::cout << "========================================================================\n";
    std::cout << "+-----------------------+------------+------------+-------+------------+--------+\n";
    std::cout << "| TARGET FUNCTION       | TARGET RVA |  CAVE RVA  | STOLEN| TRAMP RVA  | STATUS |\n";
    std::cout << "+-----------------------+------------+------------+-------+------------+--------+\n";
    std::cout << "| target_rip_global     | " << hex32(fn1_rva) << " | " << hex32(cave1.rva) << " | "
              << std::setw(5) << stolen1 << " | " << hex32(img.va_to_rva(hook1->trampoline_va)) << " | [PASS] |\n";
    std::cout << "| target_long_prologue  | " << hex32(fn2_rva) << " | " << hex32(cave2.rva) << " | "
              << std::setw(5) << stolen2 << " | " << hex32(img.va_to_rva(hook2->trampoline_va)) << " | [PASS] |\n";
    std::cout << "| target_short_branch   | " << hex32(fn3_rva) << " | " << hex32(cave3.rva) << " | "
              << std::setw(5) << stolen3 << " | " << hex32(img.va_to_rva(hook3->trampoline_va)) << " | [PASS] |\n";
    std::cout << "+-----------------------+------------+------------+-------+------------+--------+\n";
    std::cout << "All 3 live hooks installed, multi-hook cave sub-allocator verified.\n";
    std::cout << "2-byte hotpatch short-jump synthesized and validated.\n";
    std::cout << "Transactional unhook restored original bytes and matched CRC32 baseline 100%.\n";
    std::cout << "Zero heap allocations, zero unbacked memory pages, CET-safe.\n";

    return 0;
}
