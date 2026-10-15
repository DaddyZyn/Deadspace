#pragma once

#include "disasm.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <span>

namespace ds {

enum class bridge_type {
    rel32_jmp,       // 5 bytes:  e9 <disp32>
    abs64_indirect,  // 14 bytes: ff 25 00 00 00 00 <imm64> (cet safe)
    reg_indirect,    // 12 bytes: mov rax, imm64; jmp rax (cet safe)
    stack_pivot      // 16 bytes: push rax; mov rax, imm64; xchg [rsp], rax; ret (legacy)
};

struct two_stage_hook {
    uintptr_t hook_va = 0;
    uintptr_t cave_va = 0;
    uintptr_t target_va = 0;
    int32_t disp32_to_cave = 0;

    // 2-byte hotpatch support
    bool is_hotpatch = false;
    uintptr_t hotpatch_pre_va = 0;
    std::vector<uint8_t> hotpatch_pre_patch; // e9 <disp32> at hook_va - 5

    size_t stolen_bytes = 5;
    std::vector<uint8_t> hook_site_patch;      // >=5 bytes (or 2 bytes if hotpatched)
    std::vector<uint8_t> cave_bridge_payload;  // bridge jump inside cave to handler
    std::vector<uint8_t> original_trampoline;  // relocated prologue + resume jump
    uintptr_t trampoline_va = 0;              // callable trampoline entry
    size_t total_cave_capacity_needed = 0;     // bridge size + trampoline size
};

struct bridge {
    static constexpr size_t rel32_jmp_size = 5;
    static constexpr size_t abs64_jmp_size = 14;
    static constexpr size_t reg_indirect_size = 12;
    static constexpr size_t stack_pivot_size = 16;

    static size_t payload_size(bridge_type type);

    static std::vector<uint8_t> emit_rel32_jmp(int32_t disp32);
    static std::vector<uint8_t> emit_abs64_jmp(uintptr_t target_va);
    static std::vector<uint8_t> emit_reg_indirect(uintptr_t target_va);
    static std::vector<uint8_t> emit_stack_pivot(uintptr_t target_va);

    // build complete 2-stage hook with prologue relocation and callable trampoline
    static std::optional<two_stage_hook> synthesize_two_stage(
        uintptr_t hook_site_va,
        uintptr_t cave_va,
        uintptr_t destination_va,
        const uint8_t* original_code_ptr = nullptr,
        size_t available_code_len = 0,
        bridge_type cave_bridge = bridge_type::abs64_indirect,
        const uint8_t* pre_code_ptr = nullptr
    );

    static std::string hex_dump(std::span<const uint8_t> data);
};

} // namespace ds
