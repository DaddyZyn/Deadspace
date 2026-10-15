#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "image.hpp"
#include "bridge.hpp"
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace ds {

struct active_hook {
    uintptr_t hook_va = 0;
    uintptr_t cave_va = 0;
    std::vector<uint8_t> original_prologue;
    std::vector<uint8_t> original_cave_bytes;

    bool is_hotpatch = false;
    uintptr_t hotpatch_pre_va = 0;
    std::vector<uint8_t> original_pre_bytes;
};

struct runtime {
    // mode a: write static patches directly to a cloned pe file on disk
    static bool patch_disk_file(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        uint32_t hook_rva,
        uint32_t cave_rva,
        const std::vector<uint8_t>& hook_patch,
        const std::vector<uint8_t>& cave_payload
    );

    // mode b: write cave payload and atomically commit jump via cas
    static std::optional<active_hook> install_in_process_hook(
        uintptr_t hook_va,
        uintptr_t cave_va,
        const std::vector<uint8_t>& hook_patch,
        const std::vector<uint8_t>& cave_payload
    );

    static std::optional<active_hook> install_in_process_hook(
        const two_stage_hook& hook
    );

    // transactional unhook: restores original bytes via cas and flushes icache
    static bool uninstall_in_process_hook(const active_hook& hk);
};

} // namespace ds
