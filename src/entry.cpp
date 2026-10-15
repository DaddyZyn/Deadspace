#include "image.hpp"
#include "scan.hpp"
#include "rel.hpp"
#include "disasm.hpp"
#include "bridge.hpp"
#include "runtime.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>

static std::string hex32(uint32_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << val;
    return ss.str();
}

static std::string hex64(uintptr_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << val;
    return ss.str();
}

void print_banner() {
    std::cout << "deadspace x64 in-image cave detour engine\n\n";
}

void print_usage(const char* bin) {
    std::cout << "usage: " << bin << " <binary_path> [options]\n\n"
              << "mode options:\n"
              << "  --patch-out <path> Mode A: write static patched binary to disk\n\n"
              << "scan & hook options:\n"
              << "  --min <n>          minimum cave byte size (default: 5)\n"
              << "  --type <t>         cave byte: int3 | nop | null | any (default: any)\n"
              << "  --all-sections     scan all sections (default: executable only)\n"
              << "  --no-pdata         disable .pdata exception directory filtering\n"
              << "  --target <rva|sym> hook target function RVA (hex) or exported symbol name\n"
              << "  --dest <va>        hook handler destination address (hex, e.g. 0x7FFF12340000)\n"
              << "  --reg-indirect     use CET-safe register indirect (mov rax, imm64; jmp rax - 12 bytes)\n"
              << "  --pivot            [LEGACY] use stack pivot (push/mov/xchg/ret - CET unsafe)\n"
              << "  --exports          dump export directory symbols\n"
              << "  --help             show this help menu\n\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string bin_path;
    std::string patch_out_path;

    ds::scan_options opts;
    opts.min_size = 5;
    opts.type = ds::cave_type::any;
    opts.executable_only = true;
    opts.check_pdata = true;
    opts.scan_multibyte_nops = true;
    opts.clamp_disk_sections = true;

    std::string target_spec;
    uintptr_t dest_va = 0;
    bool dump_exports = false;
    ds::bridge_type b_type = ds::bridge_type::abs64_indirect;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--patch-out" && i + 1 < argc) {
            patch_out_path = argv[++i];
        } else if (arg == "--min" && i + 1 < argc) {
            opts.min_size = std::stoull(argv[++i]);
        } else if (arg == "--type" && i + 1 < argc) {
            std::string t = argv[++i];
            if (t == "int3" || t == "cc") opts.type = ds::cave_type::int3_padding;
            else if (t == "nop" || t == "90") opts.type = ds::cave_type::nop_padding;
            else if (t == "null" || t == "00") opts.type = ds::cave_type::null_padding;
            else opts.type = ds::cave_type::any;
        } else if (arg == "--all-sections") {
            opts.executable_only = false;
        } else if (arg == "--no-pdata") {
            opts.check_pdata = false;
        } else if (arg == "--target" && i + 1 < argc) {
            target_spec = argv[++i];
        } else if (arg == "--dest" && i + 1 < argc) {
            dest_va = std::stoull(argv[++i], nullptr, 16);
        } else if (arg == "--reg-indirect") {
            b_type = ds::bridge_type::reg_indirect;
        } else if (arg == "--pivot") {
            std::cout << "[!] warning: stack pivot triggers CET shadow stack faults on Win11. prefer --reg-indirect.\n";
            b_type = ds::bridge_type::stack_pivot;
        } else if (arg == "--exports") {
            dump_exports = true;
        } else if (arg[0] != '-' && bin_path.empty()) {
            bin_path = arg;
        }
    }

    if (bin_path.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "[*] parsing disk image: " << bin_path << " ...\n";
    auto img_opt = ds::image::load_file(bin_path);

    if (!img_opt) {
        std::cerr << "[-] failed to load and parse PE image. ensure path is valid and binary is x64 PE32+.\n";
        return 1;
    }

    const auto& img = *img_opt;
    std::cout << "[+] valid x64 PE image loaded\n"
              << "    image base:    " << hex64(img.base()) << "\n"
              << "    sections:      " << img.sections().size() << "\n"
              << "    exports:       " << img.exports().size() << "\n"
              << "    .pdata funcs:  " << img.functions().size() << "\n\n";

    if (dump_exports) {
        std::cout << "--- [ export directory ] ---\n";
        for (const auto& exp : img.exports()) {
            std::cout << "  [ord " << std::setw(4) << exp.ordinal << "] "
                      << "RVA: " << hex32(exp.rva)
                      << " | " << exp.name;
            if (exp.is_forwarded) {
                std::cout << "  -> [FORWARDED: " << exp.forwarder_name << "]";
            }
            std::cout << "\n";
        }
        std::cout << "\n";
    }

    std::cout << "--- [ sections ] ---\n";
    for (const auto& sec : img.sections()) {
        std::cout << "  " << std::left << std::setw(10) << sec.name << std::right
                  << " RVA: " << hex32(sec.rva)
                  << " | virt_sz: " << hex32(sec.virtual_size)
                  << " | raw_sz: " << hex32(sec.raw_size)
                  << " | " << (sec.is_executable ? "EXEC " : "     ")
                  << (sec.is_writable ? "WRITE" : "     ") << "\n";
    }
    std::cout << "\n";

    std::cout << "[*] scanning for alignment caves (min_size: " << opts.min_size
              << ", type: " << ds::cave_scanner::type_name(opts.type)
              << ", pdata_filter: " << (opts.check_pdata ? "ENABLED" : "DISABLED") << ") ...\n";

    const auto caves = ds::cave_scanner::find_caves(img, opts);
    std::cout << "[+] discovered " << caves.size() << " verified alignment cave(s)\n\n";

    if (caves.empty()) {
        std::cout << "[-] no caves matched the given criteria.\n";
        return 0;
    }

    const size_t print_limit = (caves.size() < 20) ? caves.size() : 20;
    std::cout << "--- [ cave list (showing " << print_limit << " of " << caves.size() << ") ] ---\n";
    for (size_t i = 0; i < print_limit; ++i) {
        const auto& c = caves[i];
        std::cout << "  #" << std::setw(3) << i
                  << " [" << std::left << std::setw(8) << c.section_name << std::right << "] "
                  << "RVA: " << hex32(c.rva)
                  << " (RAW: " << hex32(c.raw_offset) << ")"
                  << " | size: " << std::setw(5) << c.size << " bytes"
                  << " | " << ds::cave_scanner::type_name(c.type)
                  << " | " << (c.verified_inter_function ? "[VERIFIED INTER-FUNCTION]" : "[INTRA-SECTION]") << "\n";
    }
    std::cout << "\n";

    if (!target_spec.empty()) {
        uint32_t target_rva = 0;
        std::string resolved_name;

        auto exp_sym = img.find_export(target_spec);
        if (exp_sym) {
            if (exp_sym->is_forwarded) {
                std::cerr << "[-] error: export '" << target_spec << "' is forwarded to '"
                          << exp_sym->forwarder_name << "'. cannot hook .rdata forwarder string directly.\n";
                return 1;
            }
            target_rva = exp_sym->rva;
            resolved_name = exp_sym->name;
        } else {
            try {
                target_rva = static_cast<uint32_t>(std::stoull(target_spec, nullptr, 16));
                resolved_name = "RVA_" + hex32(target_rva);
            } catch (...) {
                std::cerr << "[-] could not parse target as RVA or export name: " << target_spec << "\n";
                return 1;
            }
        }

        const uintptr_t target_va = img.rva_to_va(target_rva);
        std::cout << "[*] hook target: " << resolved_name
                  << " (RVA: " << hex32(target_rva)
                  << ", VA: " << hex64(target_va) << ")\n";

        // pull prologue bytes from target section
        const uint8_t* orig_code_ptr = nullptr;
        size_t orig_code_len = 0;
        auto target_sec = img.find_section_by_rva(target_rva);
        if (target_sec) {
            auto sec_bytes = img.get_section_bytes(*target_sec);
            const size_t offset_in_sec = target_rva - target_sec->rva;
            if (offset_in_sec < sec_bytes.size()) {
                orig_code_ptr = sec_bytes.data() + offset_in_sec;
                orig_code_len = sec_bytes.size() - offset_in_sec;
            }
        }

        // measure stolen bytes
        size_t stolen_bytes = 5;
        std::vector<ds::decoded_instruction> prologue_insns;
        if (orig_code_ptr && orig_code_len >= 5) {
            prologue_insns = ds::disasm::decode_prologue(orig_code_ptr, orig_code_len, 5);
            size_t total_len = 0;
            for (const auto& insn : prologue_insns) total_len += insn.length;
            if (total_len >= 5) stolen_bytes = total_len;
        }

        std::cout << "[*] decoded prologue at target (" << prologue_insns.size()
                  << " instructions, " << stolen_bytes << " total bytes to steal):\n";
        size_t cur_off = 0;
        size_t widened_growth = 0;

        for (size_t idx = 0; idx < prologue_insns.size(); ++idx) {
            const auto& insn = prologue_insns[idx];
            std::cout << "    insn #" << idx << ": " << ds::bridge::hex_dump(insn.raw_bytes)
                      << " (" << insn.length << " bytes)";
            if (insn.is_rip_relative) {
                std::cout << " [RIP-RELATIVE disp32: " << hex32(static_cast<uint32_t>(insn.disp32)) << "]";
            } else if (insn.is_relative_branch) {
                if (insn.disp_size == 1) {
                    const uintptr_t op_target = (target_va + cur_off + insn.length) + insn.disp32;
                    if (op_target < target_va || op_target >= target_va + stolen_bytes) {
                        const uint8_t op_byte = insn.raw_bytes[insn.disp_offset - 1];
                        if (op_byte == 0xEB) {
                            widened_growth += 3; // 2 to 5 bytes
                            std::cout << " [REL8 BRANCH -> WIDENS TO REL32 (+3 bytes)]";
                        } else if ((op_byte & 0xF0) == 0x70) {
                            widened_growth += 4; // 2 to 6 bytes
                            std::cout << " [REL8 JCC -> WIDENS TO REL32 (+4 bytes)]";
                        }
                    }
                } else {
                    std::cout << " [REL-BRANCH disp32: " << hex32(static_cast<uint32_t>(insn.disp32)) << "]";
                }
            }
            std::cout << "\n";
            cur_off += insn.length;
        }
        std::cout << "\n";

        // dynamic cave capacity: bridge + relocated prologue (accounting for widened rel8) + resume jump
        const size_t bridge_size = ds::bridge::payload_size(b_type);
        const size_t relocated_prologue_size = stolen_bytes + widened_growth;
        const size_t resume_jump_size = 5; // e9 rel32
        const size_t full_cave_size = bridge_size + relocated_prologue_size + resume_jump_size;

        std::cout << "[*] required cave capacity for bridge + trampoline: " << full_cave_size
                  << " bytes (bridge: " << bridge_size
                  << ", relocated prologue: " << relocated_prologue_size
                  << ", resume jump: " << resume_jump_size << ")\n";

        bool include_trampoline = true;
        auto reachable = ds::rel::filter_reachable(caves, target_va, full_cave_size);
        if (reachable.empty()) {
            std::cout << "[!] no single cave fits both bridge + trampoline (" << full_cave_size
                      << " bytes). checking bridge-only capacity (" << bridge_size << " bytes)...\n";
            reachable = ds::rel::filter_reachable(caves, target_va, bridge_size);
            include_trampoline = false;
        }

        if (reachable.empty()) {
            std::cerr << "[-] zero caves with >= " << bridge_size << " bytes capacity within +/- 2GB range of target.\n";
            return 1;
        }

        std::cout << "[+] discovered " << reachable.size() << " reachable cave(s) for hook target:\n";
        for (size_t i = 0; i < (reachable.size() < 5 ? reachable.size() : 5); ++i) {
            const auto& rc = reachable[i];
            std::cout << "    #" << i << " RVA: " << hex32(rc.target_cave.rva)
                      << " | capacity: " << rc.target_cave.size << " bytes"
                      << " | delta: " << (rc.disp32 >= 0 ? "+" : "") << rc.disp32 << " bytes"
                      << " | distance: " << rc.distance << " bytes\n";
        }
        std::cout << "\n";

        const auto& best = reachable.front();
        std::cout << "[*] selecting optimal cave at RVA " << hex32(best.target_cave.rva)
                  << " (distance: " << best.distance << " bytes)\n";

        if (dest_va != 0) {
            std::cout << "[*] synthesizing 2-stage hook -> destination: " << hex64(dest_va) << " ...\n";

            auto hook = ds::bridge::synthesize_two_stage(
                target_va,
                best.target_cave.va,
                dest_va,
                include_trampoline ? orig_code_ptr : nullptr,
                include_trampoline ? orig_code_len : 0,
                b_type
            );

            if (!hook) {
                std::cerr << "[-] hook synthesis failed! displacement out of range.\n";
                return 1;
            }

            std::cout << "\n[+] hook synthesized:\n"
                      << "    target:      " << hex64(hook->hook_va) << " (RVA: " << hex32(target_rva) << ")\n"
                      << "    cave:        " << hex64(hook->cave_va) << " (RVA: " << hex32(best.target_cave.rva) << ")\n"
                      << "    handler:     " << hex64(hook->target_va) << "\n"
                      << "    disp32:      " << (hook->disp32_to_cave >= 0 ? "+" : "") << hex32(static_cast<uint32_t>(hook->disp32_to_cave)) << "\n"
                      << "    stolen:      " << hook->stolen_bytes << " bytes\n"
                      << "    cave slice:  " << hook->total_cave_capacity_needed << " / " << best.target_cave.size << " bytes\n\n";

            std::cout << "patches:\n"
                      << "  hook site:   " << ds::bridge::hex_dump(hook->hook_site_patch) << "  [jmp rel32 cave]\n"
                      << "  cave bridge: " << ds::bridge::hex_dump(hook->cave_bridge_payload) << "  [jmp handler]\n";

            if (!hook->original_trampoline.empty()) {
                std::cout << "  trampoline:  " << ds::bridge::hex_dump(hook->original_trampoline)
                          << "  (VA: " << hex64(hook->trampoline_va) << ", resume: " << hex64(target_va + hook->stolen_bytes) << ")\n";
            }
            std::cout << "\n";

            // mode a: static disk patching
            if (!patch_out_path.empty()) {
                std::cout << "[*] Mode A: writing static patched PE to: " << patch_out_path << " ...\n";
                std::vector<uint8_t> full_cave_payload = hook->cave_bridge_payload;
                full_cave_payload.insert(full_cave_payload.end(), hook->original_trampoline.begin(), hook->original_trampoline.end());

                if (ds::runtime::patch_disk_file(bin_path, patch_out_path, target_rva, best.target_cave.rva, hook->hook_site_patch, full_cave_payload)) {
                    std::cout << "[+] static disk patch applied successfully!\n";
                } else {
                    std::cerr << "[-] failed to write static patched binary to disk.\n";
                }
            }
        }
    }

    return 0;
}
