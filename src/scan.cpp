#include "scan.hpp"
#include "rel.hpp"
#include <algorithm>
#include <cstring>
#include <cmath>

namespace ds {

const char* cave_scanner::type_name(cave_type t) {
    switch (t) {
        case cave_type::int3_padding:  return "INT3 (0xCC)";
        case cave_type::nop_padding:   return "NOP  (0x90)";
        case cave_type::null_padding:  return "NULL (0x00)";
        case cave_type::multibyte_nop: return "MULTI-NOP (0F 1F / 66 90)";
        default:                       return "MIXED/UNKNOWN";
    }
}

size_t cave_scanner::match_nop_sequence(const uint8_t* p, size_t remaining) {
    if (remaining == 0) return 0;

    // standard 1-byte nop
    if (p[0] == 0x90) return 1;

    // 2-byte: 66 90
    if (remaining >= 2 && p[0] == 0x66 && p[1] == 0x90) return 2;

    // 3-byte: 0F 1F 00
    if (remaining >= 3 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x00) return 3;

    // 4-byte: 0F 1F 40 00
    if (remaining >= 4 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x40 && p[3] == 0x00) return 4;

    // 5-byte: 0F 1F 44 00 00
    if (remaining >= 5 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x44 && p[3] == 0x00 && p[4] == 0x00) return 5;

    // 6-byte: 66 0F 1F 44 00 00
    if (remaining >= 6 && p[0] == 0x66 && p[1] == 0x0F && p[2] == 0x1F && p[3] == 0x44 && p[4] == 0x00 && p[5] == 0x00) return 6;

    // 7-byte: 0F 1F 80 00 00 00 00
    if (remaining >= 7 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x80 &&
        p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x00 && p[6] == 0x00) return 7;

    // 8-byte: 0F 1F 84 00 00 00 00 00
    if (remaining >= 8 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x84 &&
        p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x00 && p[6] == 0x00 && p[7] == 0x00) return 8;

    // 9-byte: 66 0F 1F 84 00 00 00 00 00
    if (remaining >= 9 && p[0] == 0x66 && p[1] == 0x0F && p[2] == 0x1F && p[3] == 0x84 &&
        p[4] == 0x00 && p[5] == 0x00 && p[6] == 0x00 && p[7] == 0x00 && p[8] == 0x00) return 9;

    return 0;
}

std::vector<cave> cave_scanner::find_caves(const image& img, const scan_options& opt) {
    std::vector<cave> results;
    if (!img.valid()) return results;

    for (const auto& sec : img.sections()) {
        if (opt.executable_only && !sec.is_executable) continue;

        // clamp disk executable scans to avoid reading unmapped trailing junk
        auto bytes = img.get_section_bytes(sec, opt.clamp_disk_sections);
        if (bytes.empty()) continue;

        size_t i = 0;
        const size_t total = bytes.size();

        while (i < total) {
            // handle multi-byte nops if caller asked for nops or any
            if (opt.scan_multibyte_nops && (opt.type == cave_type::any || opt.type == cave_type::nop_padding || opt.type == cave_type::multibyte_nop)) {
                size_t nop_len = match_nop_sequence(bytes.data() + i, total - i);
                if (nop_len > 1 || (nop_len == 1 && (i + 1 < total && match_nop_sequence(bytes.data() + i + 1, total - (i + 1)) > 1))) {
                    const size_t start = i;
                    bool has_multibyte = false;

                    while (i < total) {
                        size_t cur_nop = match_nop_sequence(bytes.data() + i, total - i);
                        if (cur_nop == 0) break;
                        if (cur_nop > 1) has_multibyte = true;
                        i += cur_nop;
                    }

                    const size_t run_len = i - start;
                    if (run_len >= opt.min_size) {
                        cave c;
                        c.rva = sec.rva + static_cast<uint32_t>(start);
                        c.raw_offset = sec.raw_offset + static_cast<uint32_t>(start);
                        c.va = img.rva_to_va(c.rva);
                        c.size = run_len;
                        c.type = has_multibyte ? cave_type::multibyte_nop : cave_type::nop_padding;
                        c.section_name = sec.name;

                        const bool inside_func = img.is_inside_function(c.rva, c.size);
                        if (opt.check_pdata && inside_func) {
                            continue; // drop constants inside functions
                        }

                        c.verified_inter_function = !inside_func;
                        results.push_back(c);
                    }
                    continue;
                }
            }

            const uint8_t b = bytes[i];
            bool match = false;
            cave_type ct = cave_type::any;

            if (opt.type == cave_type::any) {
                if (b == 0xCC) { match = true; ct = cave_type::int3_padding; }
                else if (b == 0x90) { match = true; ct = cave_type::nop_padding; }
                else if (b == 0x00) { match = true; ct = cave_type::null_padding; }
            } else {
                if (b == static_cast<uint8_t>(opt.type)) {
                    match = true;
                    ct = opt.type;
                }
            }

            if (!match) {
                ++i;
                continue;
            }

            const size_t start = i;
            const uint8_t target_byte = b;

            // 64-bit word splat optimization without strict-aliasing ub
            const uint64_t splat = 0x0101010101010101ULL * target_byte;
            while (i + 8 <= total) {
                uint64_t chunk = 0;
                std::memcpy(&chunk, bytes.data() + i, sizeof(uint64_t));
                if (chunk != splat) break;
                i += 8;
            }

            while (i < total && bytes[i] == target_byte) {
                ++i;
            }

            const size_t run_len = i - start;
            if (run_len >= opt.min_size) {
                cave c;
                c.rva = sec.rva + static_cast<uint32_t>(start);
                c.raw_offset = sec.raw_offset + static_cast<uint32_t>(start);
                c.va = img.rva_to_va(c.rva);
                c.size = run_len;
                c.type = ct;
                c.section_name = sec.name;

                const bool inside_func = img.is_inside_function(c.rva, c.size);
                const bool is_slack = (c.rva >= sec.rva + sec.virtual_size);
                const bool at_func_end = img.is_at_function_end(c.rva);

                bool verified = !inside_func;
                if (sec.is_executable && ct == cave_type::null_padding) {
                    // null padding in .text must sit at function end or in virtual slack
                    if (!at_func_end && !is_slack) {
                        verified = false;
                    }
                }

                // drop anything that overlaps .pdata
                if (opt.check_pdata) {
                    if (inside_func) continue;
                    if (sec.is_executable && ct == cave_type::null_padding && !verified) {
                        continue;
                    }
                }

                c.verified_inter_function = verified;
                results.push_back(c);
            }
        }
    }

    return results;
}

std::optional<cave> cave_allocator::allocate(uintptr_t target_va, size_t required_bytes, size_t alignment) {
    if (required_bytes == 0 || caves_.empty()) return std::nullopt;
    if (alignment == 0) alignment = 1;

    // find candidate cave with enough space within +/- 2GB rel32 range
    size_t best_idx = static_cast<size_t>(-1);
    uint64_t best_dist = UINT64_MAX;

    for (size_t i = 0; i < caves_.size(); ++i) {
        const auto& c = caves_[i];
        if (c.size < required_bytes) continue;

        const auto res = rel::calc(target_va, c.va, 5);
        if (res.in_range) {
            const uint64_t dist = static_cast<uint64_t>(std::abs(res.delta));
            if (dist < best_dist) {
                best_dist = dist;
                best_idx = i;
            }
        }
    }

    if (best_idx == static_cast<size_t>(-1)) {
        return std::nullopt;
    }

    auto& c = caves_[best_idx];

    cave allocated_cave;
    allocated_cave.rva = c.rva;
    allocated_cave.raw_offset = c.raw_offset;
    allocated_cave.va = c.va;
    allocated_cave.size = required_bytes;
    allocated_cave.type = c.type;
    allocated_cave.section_name = c.section_name;
    allocated_cave.verified_inter_function = c.verified_inter_function;

    // advance cave metadata with 16-byte alignment to keep icache happy
    const size_t aligned_consumed = (required_bytes + (alignment - 1)) & ~(alignment - 1);
    if (c.size > aligned_consumed) {
        c.rva += static_cast<uint32_t>(aligned_consumed);
        c.raw_offset += static_cast<uint32_t>(aligned_consumed);
        c.va += aligned_consumed;
        c.size -= aligned_consumed;
    } else {
        // cave is fully drained
        caves_.erase(caves_.begin() + best_idx);
    }

    return allocated_cave;
}

} // namespace ds
