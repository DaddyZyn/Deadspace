#include "image.hpp"
#include "scan.hpp"
#include "rel.hpp"
#include "disasm.hpp"
#include "bridge.hpp"
#include "runtime.hpp"

#include <iostream>
#include <cassert>
#include <cstring>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " (" << #cond << ") at line " << __LINE__ << "\n"; \
            return 1; \
        } \
    } while (0)

int test_rel_math() {
    std::cout << "[*] running test_rel_math ...\n";

    uintptr_t from = 0x140001000;
    uintptr_t to   = 0x140002000;
    auto res = ds::rel::calc(from, to, 5);
    TEST_ASSERT(res.in_range, "small forward jump should fit rel32");
    TEST_ASSERT(res.disp32 == 0xFFB, "disp32 forward calculation mismatch");

    from = 0x140002000;
    to   = 0x140001000;
    res = ds::rel::calc(from, to, 5);
    TEST_ASSERT(res.in_range, "small backward jump should fit rel32");
    TEST_ASSERT(res.disp32 == -0x1005, "disp32 backward calculation mismatch");

    from = 0x140000000;
    to   = 0x140000000 + 0x80000005ULL;
    res = ds::rel::calc(from, to, 5);
    TEST_ASSERT(!res.in_range, "delta > 2GB must not be in range");

    std::cout << "[+] test_rel_math passed!\n";
    return 0;
}

int test_bridge_synthesis() {
    std::cout << "[*] running test_bridge_synthesis ...\n";

    // 1. payload size assertions
    TEST_ASSERT(ds::bridge::payload_size(ds::bridge_type::rel32_jmp) == 5, "rel32 jmp payload size mismatch");
    TEST_ASSERT(ds::bridge::payload_size(ds::bridge_type::abs64_indirect) == 14, "abs64 jmp payload size mismatch");
    TEST_ASSERT(ds::bridge::payload_size(ds::bridge_type::reg_indirect) == 12, "reg_indirect payload size mismatch");
    TEST_ASSERT(ds::bridge::payload_size(ds::bridge_type::stack_pivot) == 16, "stack pivot payload size mismatch");

    // 2. rel32 jmp
    int32_t disp = 0x12345678;
    auto rel_jmp = ds::bridge::emit_rel32_jmp(disp);
    TEST_ASSERT(rel_jmp.size() == 5, "rel32 jmp must be 5 bytes");
    TEST_ASSERT(rel_jmp[0] == 0xE9, "opcode must be 0xE9");
    int32_t decoded_disp = 0;
    std::memcpy(&decoded_disp, &rel_jmp[1], sizeof(int32_t));
    TEST_ASSERT(decoded_disp == disp, "rel32 disp roundtrip mismatch");

    // 3. abs64 indirect jmp
    uintptr_t dest = 0x7FFF112233445566ULL;
    auto abs_jmp = ds::bridge::emit_abs64_jmp(dest);
    TEST_ASSERT(abs_jmp.size() == 14, "abs64 jmp must be 14 bytes");
    TEST_ASSERT(abs_jmp[0] == 0xFF && abs_jmp[1] == 0x25, "abs64 opcode must be FF 25");
    uintptr_t decoded_dest = 0;
    std::memcpy(&decoded_dest, &abs_jmp[6], sizeof(uintptr_t));
    TEST_ASSERT(decoded_dest == dest, "abs64 destination roundtrip mismatch");

    // 4. CET-safe reg_indirect (mov rax, imm64; jmp rax)
    auto reg_ind = ds::bridge::emit_reg_indirect(dest);
    TEST_ASSERT(reg_ind.size() == 12, "reg_indirect must be 12 bytes");
    TEST_ASSERT(reg_ind[0] == 0x48 && reg_ind[1] == 0xB8, "reg_indirect must start with 48 B8");
    TEST_ASSERT(reg_ind[10] == 0xFF && reg_ind[11] == 0xE0, "reg_indirect must end with FF E0");
    uintptr_t decoded_reg_dest = 0;
    std::memcpy(&decoded_reg_dest, &reg_ind[2], sizeof(uintptr_t));
    TEST_ASSERT(decoded_reg_dest == dest, "reg_indirect destination roundtrip mismatch");

    std::cout << "[+] test_bridge_synthesis passed!\n";
    return 0;
}

int test_insn_decoder_and_prologue() {
    std::cout << "[*] running test_insn_decoder_and_prologue ...\n";

    // 48 89 5C 24 08 -> mov [rsp+8], rbx (5 bytes)
    const uint8_t mov_rsp[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
    auto d1 = ds::disasm::decode(mov_rsp, sizeof(mov_rsp));
    TEST_ASSERT(d1.length == 5, "mov [rsp+8], rbx length mismatch");

    // 48 83 EC 20 -> sub rsp, 0x20 (4 bytes)
    const uint8_t sub_rsp[] = { 0x48, 0x83, 0xEC, 0x20 };
    auto d2 = ds::disasm::decode(sub_rsp, sizeof(sub_rsp));
    TEST_ASSERT(d2.length == 4, "sub rsp, 20h length mismatch");

    // 48 8D 05 12 34 56 00 -> lea rax, [rip + 0x00563412] (7 bytes)
    const uint8_t lea_rip[] = { 0x48, 0x8D, 0x05, 0x12, 0x34, 0x56, 0x00 };
    auto d3 = ds::disasm::decode(lea_rip, sizeof(lea_rip));
    TEST_ASSERT(d3.length == 7, "lea rax, [rip + disp32] length mismatch");
    TEST_ASSERT(d3.is_rip_relative, "must be flagged as rip-relative");
    TEST_ASSERT(d3.disp_offset == 3, "disp_offset must be 3");
    TEST_ASSERT(d3.disp32 == 0x00563412, "disp32 must match");

    // combined prologue: sub rsp, 20h (4 bytes) + mov [rsp+8], rbx (5 bytes) = 9 bytes total
    const uint8_t full_prologue[] = {
        0x48, 0x83, 0xEC, 0x20,        // 4 bytes
        0x48, 0x89, 0x5C, 0x24, 0x08  // 5 bytes
    };
    size_t stolen = ds::disasm::measure_prologue(full_prologue, sizeof(full_prologue), 5);
    TEST_ASSERT(stolen == 9, "prologue boundary measurement must steal whole instructions >= 5 (expected 9)");

    // test two-stage synthesis with prologue relocation and original trampoline
    uintptr_t hook_va = 0x140001000;
    uintptr_t cave_va = 0x140002000;
    uintptr_t dest_va = 0x7FFF88990000;

    auto hook = ds::bridge::synthesize_two_stage(
        hook_va,
        cave_va,
        dest_va,
        full_prologue,
        sizeof(full_prologue),
        ds::bridge_type::abs64_indirect
    );

    TEST_ASSERT(hook.has_value(), "two-stage synthesis must succeed");
    TEST_ASSERT(hook->stolen_bytes == 9, "hook must have recorded 9 stolen bytes");
    TEST_ASSERT(hook->hook_site_patch.size() == 9, "hook patch must be 9 bytes");
    TEST_ASSERT(hook->hook_site_patch[0] == 0xE9, "hook patch must start with E9");
    for (size_t i = 5; i < 9; ++i) {
        TEST_ASSERT(hook->hook_site_patch[i] == 0x90, "trailing patch bytes must be NOPs");
    }

    // trampoline must have 9 bytes stolen instructions + 5 bytes relative resume jump = 14 bytes
    TEST_ASSERT(hook->original_trampoline.size() == 14, "original trampoline size mismatch");
    TEST_ASSERT(hook->total_cave_capacity_needed == 14 + 14, "total cave capacity mismatch (14 bridge + 14 trampoline = 28)");

    std::cout << "[+] test_insn_decoder_and_prologue passed!\n";
    return 0;
}

int test_multibyte_nops() {
    std::cout << "[*] running test_multibyte_nops ...\n";

    const uint8_t nop1[] = { 0x90 };
    TEST_ASSERT(ds::cave_scanner::match_nop_sequence(nop1, sizeof(nop1)) == 1, "1-byte NOP mismatch");

    const uint8_t nop2[] = { 0x66, 0x90 };
    TEST_ASSERT(ds::cave_scanner::match_nop_sequence(nop2, sizeof(nop2)) == 2, "2-byte NOP mismatch");

    const uint8_t nop3[] = { 0x0F, 0x1F, 0x00 };
    TEST_ASSERT(ds::cave_scanner::match_nop_sequence(nop3, sizeof(nop3)) == 3, "3-byte NOP mismatch");

    const uint8_t nop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    TEST_ASSERT(ds::cave_scanner::match_nop_sequence(nop5, sizeof(nop5)) == 5, "5-byte NOP mismatch");

    const uint8_t nop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
    TEST_ASSERT(ds::cave_scanner::match_nop_sequence(nop8, sizeof(nop8)) == 8, "8-byte NOP mismatch");

    std::cout << "[+] test_multibyte_nops passed!\n";
    return 0;
}

int test_binary_parsing_and_scanning(const std::string& dll_path) {
    std::cout << "[*] running test_binary_parsing_and_scanning against: " << dll_path << " ...\n";

    auto img = ds::image::load_file(dll_path);
    TEST_ASSERT(img.has_value(), "failed to load test dll");
    TEST_ASSERT(img->valid(), "image must be valid");
    TEST_ASSERT(!img->sections().empty(), "image must have sections");
    TEST_ASSERT(!img->functions().empty(), ".pdata functions must be parsed");

    auto exp_alpha = img->find_export("target_function_alpha");
    TEST_ASSERT(exp_alpha.has_value(), "target_function_alpha export must exist");
    TEST_ASSERT(!exp_alpha->is_forwarded, "target_function_alpha must not be forwarded");

    // test is_inside_function boundary logic
    const auto& fn0 = img->functions().front();
    TEST_ASSERT(img->is_inside_function(fn0.begin_rva, fn0.end_rva - fn0.begin_rva), "exact function range must be inside function");

    // scan caves with .pdata filtering enabled
    ds::scan_options opts;
    opts.min_size = 5;
    opts.executable_only = true;
    opts.check_pdata = true;
    opts.clamp_disk_sections = true;

    auto caves = ds::cave_scanner::find_caves(*img, opts);
    std::cout << "[+] discovered " << caves.size() << " verified caves outside functions\n";

    for (const auto& c : caves) {
        TEST_ASSERT(c.verified_inter_function, "caves must be verified inter-function space");
        TEST_ASSERT(!img->is_inside_function(c.rva, c.size), "cave must not overlap any .pdata function");
    }

    // test Mode A: static disk patch
    const std::string patched_path = "test_target_patched.dll";
    if (!caves.empty()) {
        auto best = caves.front();
        std::vector<uint8_t> hook_patch = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        std::vector<uint8_t> cave_payload = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };

        bool patch_ok = ds::runtime::patch_disk_file(dll_path, patched_path, exp_alpha->rva, best.rva, hook_patch, cave_payload);
        TEST_ASSERT(patch_ok, "Mode A static disk patching must succeed");

        auto patched_img = ds::image::load_file(patched_path);
        TEST_ASSERT(patched_img.has_value(), "patched image must be loadable");
        DeleteFileA(patched_path.c_str());
    }

    std::cout << "[+] test_binary_parsing_and_scanning passed!\n";
    return 0;
}

int main(int argc, char* argv[]) {
    std::cout << "========== [ DEADSPACE UNIT TEST SUITE ] ==========\n";

    if (test_rel_math() != 0) return 1;
    if (test_bridge_synthesis() != 0) return 1;
    if (test_insn_decoder_and_prologue() != 0) return 1;
    if (test_multibyte_nops() != 0) return 1;

    if (argc > 1) {
        if (test_binary_parsing_and_scanning(argv[1]) != 0) return 1;
    }

    std::cout << "\n[SUCCESS] ALL ADVANCED DEADSPACE TESTS PASSED WITH ZERO FAILURES!\n";
    return 0;
}
