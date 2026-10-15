#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

namespace ds {

struct decoded_instruction {
    size_t length = 0;
    bool has_modrm = false;
    bool is_rip_relative = false;        // [rip + disp32] (mod == 0, rm == 5)
    bool is_relative_branch = false;     // e8, e9, 0f 8x, eb, 7x
    size_t disp_offset = 0;              // byte offset of displacement in insn
    size_t disp_size = 0;                // 1 for rel8, 4 for rel32/rip
    int32_t disp32 = 0;                  // sign-extended displacement
    std::vector<uint8_t> raw_bytes;
};

struct disasm {
    // minimal length decoder for x64 function prologues
    static inline decoded_instruction decode(const uint8_t* p, size_t max_len) {
        if (!p || max_len == 0) return {};

        size_t idx = 0;
        bool prefix_66 = false;
        bool prefix_67 = false;
        bool rex_w = false;

        // legacy prefix soup: 0x66 operand size, 0x67 addr size, locks, segments
        while (idx < max_len) {
            const uint8_t b = p[idx];
            if (b == 0x66) { prefix_66 = true; ++idx; }
            else if (b == 0x67) { prefix_67 = true; ++idx; }
            else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                     b == 0x2E || b == 0x36 || b == 0x3E ||
                     b == 0x26 || b == 0x64 || b == 0x65) {
                ++idx;
            } else {
                break;
            }
        }

        if (idx >= max_len) return { max_len };

        // rex prefix: 0x40..0x4f (rex.w flag = 64-bit operand width)
        if ((p[idx] & 0xF0) == 0x40) {
            if (p[idx] & 0x08) rex_w = true;
            ++idx;
        }

        if (idx >= max_len) return { max_len };

        uint8_t op = p[idx++];
        bool is_two_byte = false;

        // 2-byte escape
        if (op == 0x0F) {
            if (idx >= max_len) return { max_len };
            is_two_byte = true;
            op = p[idx++];
            if (op == 0x38 || op == 0x3A) {
                if (idx >= max_len) return { max_len };
                ++idx;
            }
        }

        decoded_instruction insn;
        bool has_modrm = false;
        size_t imm_size = 0;

        if (!is_two_byte) {
            switch (op) {
                case 0x50: case 0x51: case 0x52: case 0x53:
                case 0x54: case 0x55: case 0x56: case 0x57:
                case 0x58: case 0x59: case 0x5A: case 0x5B:
                case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                case 0x90: case 0xC3: case 0xCC:
                    break;

                // standard reg/mem ALU ops & movs
                case 0x88: case 0x89: case 0x8A: case 0x8B:
                case 0x8D: case 0x85: case 0x84: case 0x31:
                case 0x33: case 0x29: case 0x2B: case 0x01:
                case 0x03: case 0x39: case 0x3B:
                    has_modrm = true;
                    break;

                // imm arithmetic (80, 81, 83)
                case 0x80: case 0x82: case 0x83:
                    has_modrm = true;
                    imm_size = 1;
                    break;
                case 0x81:
                    has_modrm = true;
                    imm_size = prefix_66 ? 2 : 4;
                    break;

                case 0xC6:
                    has_modrm = true;
                    imm_size = 1;
                    break;
                case 0xC7:
                    has_modrm = true;
                    imm_size = prefix_66 ? 2 : 4;
                    break;

                case 0xB0: case 0xB1: case 0xB2: case 0xB3:
                case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                    imm_size = 1;
                    break;
                case 0xB8: case 0xB9: case 0xBA: case 0xBB:
                case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                    imm_size = rex_w ? 8 : (prefix_66 ? 2 : 4);
                    break;

                // short relative branches (rel8) - need widening if stolen into trampoline
                case 0xEB: case 0x70: case 0x71: case 0x72: case 0x73:
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
                case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D:
                case 0x7E: case 0x7F:
                    insn.is_relative_branch = true;
                    insn.disp_offset = idx;
                    insn.disp_size = 1;
                    imm_size = 1;
                    break;

                // near relative branches (rel32)
                case 0xE9: case 0xE8:
                    insn.is_relative_branch = true;
                    insn.disp_offset = idx;
                    insn.disp_size = 4;
                    imm_size = 4;
                    break;

                case 0x68:
                    imm_size = 4;
                    break;
                case 0x6A:
                    imm_size = 1;
                    break;

                // group 3 & 5 (test r/m, imm / call / jmp)
                case 0xFF:
                case 0xF7: case 0xF6:
                    has_modrm = true;
                    if (op == 0xF6) {
                        // test r/m8, imm8 has imm8 when reg field is 0 or 1
                        if (idx < max_len && ((p[idx] >> 3) & 7) <= 1) imm_size = 1;
                    } else if (op == 0xF7) {
                        if (idx < max_len && ((p[idx] >> 3) & 7) <= 1) imm_size = prefix_66 ? 2 : 4;
                    }
                    break;

                default:
                    if ((op >= 0x00 && op <= 0x3F) || (op >= 0x84 && op <= 0x8F)) {
                        has_modrm = true;
                    }
                    break;
            }
        } else {
            // 0x0F escape opcodes
            switch (op) {
                case 0x1F:
                case 0x28: case 0x29: case 0x10: case 0x11:
                case 0x57: case 0x6E: case 0x7E:
                case 0xB6: case 0xB7: case 0xBE: case 0xBF:
                case 0xAF:
                    has_modrm = true;
                    break;
                case 0x80: case 0x81: case 0x82: case 0x83:
                case 0x84: case 0x85: case 0x86: case 0x87:
                case 0x88: case 0x89: case 0x8A: case 0x8B:
                case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                    insn.is_relative_branch = true;
                    insn.disp_offset = idx;
                    insn.disp_size = 4;
                    imm_size = 4;
                    break;
                case 0xBA:
                    has_modrm = true;
                    imm_size = 1;
                    break;
                default:
                    has_modrm = true;
                    break;
            }
        }

        // modrm / sib parsing
        if (has_modrm && idx < max_len) {
            insn.has_modrm = true;
            const uint8_t modrm = p[idx++];
            const uint8_t mod = (modrm >> 6) & 3;
            const uint8_t rm = modrm & 7;

            bool has_sib = false;
            uint8_t sib = 0;

            if (mod != 3 && rm == 4) {
                if (idx < max_len) {
                    has_sib = true;
                    sib = p[idx++];
                }
            }

            if (mod == 0 && rm == 5) {
                // mod=0 rm=5 is [rip + disp32] in 64-bit mode
                insn.is_rip_relative = true;
                insn.disp_offset = idx;
                insn.disp_size = 4;
                idx += 4;
            } else if (mod == 0 && has_sib && (sib & 7) == 5) {
                insn.disp_offset = idx;
                insn.disp_size = 4;
                idx += 4;
            } else if (mod == 1) {
                insn.disp_offset = idx;
                insn.disp_size = 1;
                idx += 1;
            } else if (mod == 2) {
                insn.disp_offset = idx;
                insn.disp_size = prefix_67 ? 2 : 4;
                idx += insn.disp_size;
            }
        }

        idx += imm_size;
        insn.length = (idx <= max_len) ? idx : max_len;

        // extract displacement bits (sign-extend rel8 to 32-bit)
        if (insn.disp_size == 4 && insn.disp_offset + 4 <= insn.length) {
            std::memcpy(&insn.disp32, p + insn.disp_offset, sizeof(int32_t));
        } else if (insn.disp_size == 1 && insn.disp_offset + 1 <= insn.length) {
            const int8_t d8 = static_cast<int8_t>(p[insn.disp_offset]);
            insn.disp32 = d8;
        }

        insn.raw_bytes.assign(p, p + insn.length);
        return insn;
    }

    // decode whole instructions covering at least min_bytes
    static inline std::vector<decoded_instruction> decode_prologue(const uint8_t* code, size_t max_len, size_t min_bytes = 5) {
        std::vector<decoded_instruction> out;
        if (!code || max_len < min_bytes) return out;

        size_t accumulated = 0;
        while (accumulated < min_bytes && accumulated < max_len) {
            auto insn = decode(code + accumulated, max_len - accumulated);
            if (insn.length == 0) break;
            accumulated += insn.length;
            out.push_back(std::move(insn));
        }
        return out;
    }

    // measure stolen bytes without keeping instruction structures
    static inline size_t measure_prologue(const uint8_t* code, size_t max_len, size_t min_bytes = 5) {
        if (!code || max_len < min_bytes) return min_bytes;

        size_t accumulated = 0;
        while (accumulated < min_bytes && accumulated < max_len) {
            auto insn = decode(code + accumulated, max_len - accumulated);
            if (insn.length == 0) {
                accumulated += 1;
            } else {
                accumulated += insn.length;
            }
        }
        return accumulated;
    }
};

} // namespace ds
