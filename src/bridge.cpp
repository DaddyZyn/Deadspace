#include "bridge.hpp"
#include "rel.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace ds {

size_t bridge::payload_size(bridge_type type) {
    switch (type) {
        case bridge_type::rel32_jmp:      return kRel32JmpSize;
        case bridge_type::abs64_indirect: return kAbs64JmpSize;
        case bridge_type::reg_indirect:   return kRegIndirectSize;
        case bridge_type::stack_pivot:    return kStackPivotSize;
        default:                          return kAbs64JmpSize;
    }
}

std::vector<uint8_t> bridge::emit_rel32_jmp(int32_t disp32) {
    std::vector<uint8_t> bytes(5);
    bytes[0] = 0xE9;
    std::memcpy(&bytes[1], &disp32, sizeof(int32_t));
    return bytes;
}

std::vector<uint8_t> bridge::emit_abs64_jmp(uintptr_t target_va) {
    // ff 25 00 00 00 00 = jmp qword ptr [rip + 0]
    std::vector<uint8_t> bytes = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    bytes.resize(14);
    std::memcpy(&bytes[6], &target_va, sizeof(uintptr_t));
    return bytes;
}

std::vector<uint8_t> bridge::emit_reg_indirect(uintptr_t target_va) {
    // 48 b8 [target_va]    mov rax, target_va
    // ff e0                jmp rax
    std::vector<uint8_t> bytes = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };
    std::memcpy(&bytes[2], &target_va, sizeof(uintptr_t));
    return bytes;
}

std::vector<uint8_t> bridge::emit_stack_pivot(uintptr_t target_va) {
    // 50                   push rax
    // 48 b8 [target_va]    mov  rax, target_va
    // 48 87 04 24          xchg [rsp], rax
    // c3                   ret
    std::vector<uint8_t> bytes = {
        0x50,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x87, 0x04, 0x24,
        0xC3
    };
    std::memcpy(&bytes[3], &target_va, sizeof(uintptr_t));
    return bytes;
}

std::optional<two_stage_hook> bridge::synthesize_two_stage(
    uintptr_t hook_site_va,
    uintptr_t cave_va,
    uintptr_t destination_va,
    const uint8_t* original_code_ptr,
    size_t available_code_len,
    bridge_type cave_bridge,
    const uint8_t* pre_code_ptr
) {
    const auto res = rel::calc(hook_site_va, cave_va, kRel32JmpSize);
    if (!res.in_range) {
        return std::nullopt;
    }

    two_stage_hook hook;
    hook.hook_va = hook_site_va;
    hook.cave_va = cave_va;
    hook.target_va = destination_va;
    hook.disp32_to_cave = res.disp32;

    // bridge payload inside cave jumping to handler
    if (cave_bridge == bridge_type::abs64_indirect) {
        hook.cave_bridge_payload = emit_abs64_jmp(destination_va);
    } else if (cave_bridge == bridge_type::reg_indirect) {
        hook.cave_bridge_payload = emit_reg_indirect(destination_va);
    } else if (cave_bridge == bridge_type::stack_pivot) {
        hook.cave_bridge_payload = emit_stack_pivot(destination_va);
    } else {
        const auto c2t = rel::calc(cave_va, destination_va, kRel32JmpSize);
        if (!c2t.in_range) return std::nullopt;
        hook.cave_bridge_payload = emit_rel32_jmp(c2t.disp32);
    }

    // check 5-byte cc/90 padding right before hook site (hook_va - 5)
    bool has_hotpatch_padding = false;
    if (pre_code_ptr) {
        has_hotpatch_padding = true;
        for (size_t i = 0; i < 5; ++i) {
            if (pre_code_ptr[i] != 0xCC && pre_code_ptr[i] != 0x90) {
                has_hotpatch_padding = false;
                break;
            }
        }
    }

    const size_t min_hook_bytes = (has_hotpatch_padding) ? 2 : kRel32JmpSize;

    // decode stolen prologue instructions
    const bool can_build_trampoline = (original_code_ptr != nullptr && available_code_len >= min_hook_bytes);
    size_t stolen_bytes = min_hook_bytes;
    std::vector<decoded_instruction> prologue_insns;

    if (can_build_trampoline) {
        prologue_insns = disasm::decode_prologue(original_code_ptr, available_code_len, min_hook_bytes);
        size_t total_len = 0;
        for (const auto& insn : prologue_insns) {
            total_len += insn.length;
        }
        if (total_len >= min_hook_bytes) {
            stolen_bytes = total_len;
        }
    }
    hook.stolen_bytes = stolen_bytes;

    // construct hook site patch (and pre-patch if hotpatching)
    if (has_hotpatch_padding && stolen_bytes < 5) {
        // 2-byte hotpatch: 5-byte relative jump in padding at hook_site_va - 5
        const int64_t pre_disp64 = static_cast<int64_t>(cave_va) - static_cast<int64_t>(hook_site_va);
        if (pre_disp64 < INT32_MIN || pre_disp64 > INT32_MAX) {
            return std::nullopt;
        }
        hook.is_hotpatch = true;
        hook.hotpatch_pre_va = hook_site_va - 5;
        hook.hotpatch_pre_patch.resize(5);
        hook.hotpatch_pre_patch[0] = 0xE9;
        const int32_t pre_disp32 = static_cast<int32_t>(pre_disp64);
        std::memcpy(&hook.hotpatch_pre_patch[1], &pre_disp32, sizeof(int32_t));

        // 2-byte backward jump at hook_site_va: eb f9 (jmp short -7) + nops
        hook.hook_site_patch.resize(stolen_bytes, 0x90);
        hook.hook_site_patch[0] = 0xEB;
        hook.hook_site_patch[1] = 0xF9;
    } else {
        hook.is_hotpatch = false;
        hook.hook_site_patch.resize(stolen_bytes, 0x90);
        hook.hook_site_patch[0] = 0xE9;
        std::memcpy(&hook.hook_site_patch[1], &res.disp32, sizeof(int32_t));
    }

    // bridge-only fallback when original_code_ptr is null
    if (!can_build_trampoline) {
        hook.original_trampoline.clear();
        hook.trampoline_va = 0;
        hook.total_cave_capacity_needed = hook.cave_bridge_payload.size();
        return hook;
    }

    // synthesize trampoline inside the cave
    const uintptr_t tramp_va = cave_va + hook.cave_bridge_payload.size();
    hook.trampoline_va = tramp_va;

    std::vector<uint8_t> tramp;
    size_t offset_in_orig = 0;

    for (const auto& insn : prologue_insns) {
        const uintptr_t orig_insn_va = hook_site_va + offset_in_orig;
        const uintptr_t reloc_insn_va = tramp_va + tramp.size();

        // reject branches backward into the stolen prologue bytes
        if (insn.is_relative_branch) {
            const uintptr_t op_target = (orig_insn_va + insn.length) + insn.disp32;
            if (op_target >= hook_site_va && op_target <= orig_insn_va) {
                return std::nullopt;
            }
        }

        std::vector<uint8_t> insn_copy = insn.raw_bytes;

        // widen rel8 branches unconditionally
        if (insn.is_relative_branch && insn.disp_size == 1 && insn.disp_offset < insn.length) {
            const uintptr_t op_target = (orig_insn_va + insn.length) + insn.disp32;
            const uint8_t op_byte = insn.raw_bytes[insn.disp_offset - 1];

            if (op_byte == 0xEB) {
                // widen 0xEB <rel8> (2 bytes) to 0xE9 <rel32> (5 bytes)
                const int64_t new_disp64 = static_cast<int64_t>(op_target) - static_cast<int64_t>(reloc_insn_va + 5);
                if (new_disp64 < INT32_MIN || new_disp64 > INT32_MAX) {
                    return std::nullopt;
                }
                insn_copy.resize(5);
                insn_copy[0] = 0xE9;
                const int32_t new_disp32 = static_cast<int32_t>(new_disp64);
                std::memcpy(&insn_copy[1], &new_disp32, sizeof(int32_t));
            } else if ((op_byte & 0xF0) == 0x70) {
                // widen 0x70-0x7F <rel8> (2 bytes) to 0x0F 0x80-0x8F <rel32> (6 bytes)
                const int64_t new_disp64 = static_cast<int64_t>(op_target) - static_cast<int64_t>(reloc_insn_va + 6);
                if (new_disp64 < INT32_MIN || new_disp64 > INT32_MAX) {
                    return std::nullopt;
                }
                const uint8_t cc = op_byte & 0x0F;
                insn_copy.resize(6);
                insn_copy[0] = 0x0F;
                insn_copy[1] = static_cast<uint8_t>(0x80 + cc);
                const int32_t new_disp32 = static_cast<int32_t>(new_disp64);
                std::memcpy(&insn_copy[2], &new_disp32, sizeof(int32_t));
            } else {
                return std::nullopt;
            }
        } else if ((insn.is_rip_relative || insn.is_relative_branch) && insn.disp_size == 4 && insn.disp_offset + 4 <= insn.length) {
            const uintptr_t op_target = (orig_insn_va + insn.length) + insn.disp32;
            const int64_t new_disp64 = static_cast<int64_t>(op_target) - static_cast<int64_t>(reloc_insn_va + insn.length);

            // fail fast on 32-bit displacement overflow
            if (new_disp64 < INT32_MIN || new_disp64 > INT32_MAX) {
                return std::nullopt;
            }

            const int32_t new_disp32 = static_cast<int32_t>(new_disp64);
            std::memcpy(&insn_copy[insn.disp_offset], &new_disp32, sizeof(int32_t));
        }

        tramp.insert(tramp.end(), insn_copy.begin(), insn_copy.end());
        offset_in_orig += insn.length;
    }

    // append resume jump back to hook_site_va + stolen_bytes
    const uintptr_t resume_target_va = hook_site_va + stolen_bytes;
    const uintptr_t resume_jump_src_va = tramp_va + tramp.size();
    const auto resume_rel = rel::calc(resume_jump_src_va, resume_target_va, kRel32JmpSize);

    if (resume_rel.in_range) {
        // 5-byte relative jump back to remainder of original function
        const auto back_jmp = emit_rel32_jmp(resume_rel.disp32);
        tramp.insert(tramp.end(), back_jmp.begin(), back_jmp.end());
    } else {
        // 14-byte absolute indirect jump if over 2gb
        const auto back_jmp = emit_abs64_jmp(resume_target_va);
        tramp.insert(tramp.end(), back_jmp.begin(), back_jmp.end());
    }

    hook.original_trampoline = std::move(tramp);
    hook.total_cave_capacity_needed = hook.cave_bridge_payload.size() + hook.original_trampoline.size();

    return hook;
}

std::string bridge::hex_dump(std::span<const uint8_t> data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

} // namespace ds
