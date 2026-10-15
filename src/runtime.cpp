#include "runtime.hpp"
#include <fstream>
#include <cstring>
#include <intrin.h>
#include <algorithm>

namespace ds {

bool runtime::patch_disk_file(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    uint32_t hook_rva,
    uint32_t cave_rva,
    const std::vector<uint8_t>& hook_patch,
    const std::vector<uint8_t>& cave_payload
) {
    auto img_opt = image::load_file(input_pe_path);
    if (!img_opt) return false;

    auto& img = *img_opt;
    const uint32_t hook_raw = img.rva_to_file_offset(hook_rva);
    const uint32_t cave_raw = img.rva_to_file_offset(cave_rva);

    if (hook_raw == 0 || cave_raw == 0) return false;

    auto& buf = img.buffer_mut();
    if (hook_raw + hook_patch.size() > buf.size()) return false;
    if (cave_raw + cave_payload.size() > buf.size()) return false;

    // write payload into alignment cave
    std::memcpy(buf.data() + cave_raw, cave_payload.data(), cave_payload.size());

    // write hook patch at target function entry
    std::memcpy(buf.data() + hook_raw, hook_patch.data(), hook_patch.size());

    // write cloned binary to disk
    std::ofstream out(output_pe_path, std::ios::binary);
    if (!out.is_open()) return false;

    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return out.good();
}

std::optional<active_hook> runtime::install_in_process_hook(
    uintptr_t hook_va,
    uintptr_t cave_va,
    const std::vector<uint8_t>& hook_patch,
    const std::vector<uint8_t>& cave_payload
) {
    if (!hook_va || !cave_va || hook_patch.empty() || cave_payload.empty()) return std::nullopt;
    if (hook_patch.size() < 2) return std::nullopt;

    active_hook hk;
    hk.hook_va = hook_va;
    hk.cave_va = cave_va;

    // backup original cave bytes before writing
    hk.original_cave_bytes.resize(cave_payload.size());
    std::memcpy(hk.original_cave_bytes.data(), reinterpret_cast<const void*>(cave_va), cave_payload.size());

    // backup original prologue before patching
    hk.original_prologue.resize(hook_patch.size());
    std::memcpy(hk.original_prologue.data(), reinterpret_cast<const void*>(hook_va), hook_patch.size());

    // write cave payload into module alignment padding
    DWORD old_cave_prot = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(cave_va), cave_payload.size(), PAGE_EXECUTE_READWRITE, &old_cave_prot)) {
        return std::nullopt;
    }

    std::memcpy(reinterpret_cast<void*>(cave_va), cave_payload.data(), cave_payload.size());
    VirtualProtect(reinterpret_cast<LPVOID>(cave_va), cave_payload.size(), old_cave_prot, &old_cave_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(cave_va), cave_payload.size());

    // atomically commit hook site via cas across first 8 bytes
    const size_t total_protect_len = (std::max)(hook_patch.size(), static_cast<size_t>(8));
    DWORD old_hook_prot = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(hook_va), total_protect_len, PAGE_EXECUTE_READWRITE, &old_hook_prot)) {
        return std::nullopt;
    }

    volatile auto* target_ptr = reinterpret_cast<volatile LONG64*>(hook_va);
    LONG64 current_val = *target_ptr;

    while (true) {
        LONG64 desired_val = current_val;
        const size_t first_chunk = (std::min)(hook_patch.size(), static_cast<size_t>(8));
        std::memcpy(&desired_val, hook_patch.data(), first_chunk);

        const LONG64 prev_val = _InterlockedCompareExchange64(target_ptr, desired_val, current_val);
        if (prev_val == current_val) {
            break;
        }
        current_val = prev_val;
    }

    // fill trailing stolen bytes beyond 8 with nops (already unreachable)
    if (hook_patch.size() > 8) {
        std::memcpy(
            reinterpret_cast<void*>(hook_va + 8),
            hook_patch.data() + 8,
            hook_patch.size() - 8
        );
    }

    VirtualProtect(reinterpret_cast<LPVOID>(hook_va), total_protect_len, old_hook_prot, &old_hook_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hook_va), total_protect_len);
    return hk;
}

std::optional<active_hook> runtime::install_in_process_hook(const two_stage_hook& hook) {
    std::vector<uint8_t> cave_payload = hook.cave_bridge_payload;
    if (!hook.original_trampoline.empty()) {
        cave_payload.insert(cave_payload.end(), hook.original_trampoline.begin(), hook.original_trampoline.end());
    }

    if (hook.is_hotpatch && hook.hotpatch_pre_va != 0 && !hook.hotpatch_pre_patch.empty()) {
        active_hook hk;
        hk.hook_va = hook.hook_va;
        hk.cave_va = hook.cave_va;
        hk.is_hotpatch = true;
        hk.hotpatch_pre_va = hook.hotpatch_pre_va;

        // backup pre-padding bytes at hotpatch_pre_va
        hk.original_pre_bytes.resize(hook.hotpatch_pre_patch.size());
        std::memcpy(hk.original_pre_bytes.data(), reinterpret_cast<const void*>(hook.hotpatch_pre_va), hook.hotpatch_pre_patch.size());

        // backup original prologue at hook_va
        hk.original_prologue.resize(hook.hook_site_patch.size());
        std::memcpy(hk.original_prologue.data(), reinterpret_cast<const void*>(hook.hook_va), hook.hook_site_patch.size());

        // backup original cave bytes
        hk.original_cave_bytes.resize(cave_payload.size());
        std::memcpy(hk.original_cave_bytes.data(), reinterpret_cast<const void*>(hook.cave_va), cave_payload.size());

        // write cave payload
        DWORD old_prot = 0;
        if (!VirtualProtect(reinterpret_cast<LPVOID>(hook.cave_va), cave_payload.size(), PAGE_EXECUTE_READWRITE, &old_prot)) {
            return std::nullopt;
        }
        std::memcpy(reinterpret_cast<void*>(hook.cave_va), cave_payload.data(), cave_payload.size());
        VirtualProtect(reinterpret_cast<LPVOID>(hook.cave_va), cave_payload.size(), old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hook.cave_va), cave_payload.size());

        // write 5-byte relative jump in pre-padding
        if (!VirtualProtect(reinterpret_cast<LPVOID>(hook.hotpatch_pre_va), hook.hotpatch_pre_patch.size(), PAGE_EXECUTE_READWRITE, &old_prot)) {
            return std::nullopt;
        }
        std::memcpy(reinterpret_cast<void*>(hook.hotpatch_pre_va), hook.hotpatch_pre_patch.data(), hook.hotpatch_pre_patch.size());
        VirtualProtect(reinterpret_cast<LPVOID>(hook.hotpatch_pre_va), hook.hotpatch_pre_patch.size(), old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hook.hotpatch_pre_va), hook.hotpatch_pre_patch.size());

        // atomically commit 2-byte short jump at hook_va
        const size_t total_protect_len = (std::max)(hook.hook_site_patch.size(), static_cast<size_t>(8));
        if (!VirtualProtect(reinterpret_cast<LPVOID>(hook.hook_va), total_protect_len, PAGE_EXECUTE_READWRITE, &old_prot)) {
            return std::nullopt;
        }

        volatile auto* target_ptr = reinterpret_cast<volatile LONG64*>(hook.hook_va);
        LONG64 current_val = *target_ptr;

        while (true) {
            LONG64 desired_val = current_val;
            const size_t first_chunk = (std::min)(hook.hook_site_patch.size(), static_cast<size_t>(8));
            std::memcpy(&desired_val, hook.hook_site_patch.data(), first_chunk);

            const LONG64 prev_val = _InterlockedCompareExchange64(target_ptr, desired_val, current_val);
            if (prev_val == current_val) {
                break;
            }
            current_val = prev_val;
        }

        if (hook.hook_site_patch.size() > 8) {
            std::memcpy(
                reinterpret_cast<void*>(hook.hook_va + 8),
                hook.hook_site_patch.data() + 8,
                hook.hook_site_patch.size() - 8
            );
        }

        VirtualProtect(reinterpret_cast<LPVOID>(hook.hook_va), total_protect_len, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hook.hook_va), total_protect_len);
        return hk;
    }

    return install_in_process_hook(hook.hook_va, hook.cave_va, hook.hook_site_patch, cave_payload);
}

bool runtime::uninstall_in_process_hook(const active_hook& hk) {
    if (!hk.hook_va || !hk.cave_va || hk.original_prologue.empty() || hk.original_cave_bytes.empty()) {
        return false;
    }

    // atomically restore original prologue at hook_va
    const size_t total_protect_len = (std::max)(hk.original_prologue.size(), static_cast<size_t>(8));
    DWORD old_hook_prot = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(hk.hook_va), total_protect_len, PAGE_EXECUTE_READWRITE, &old_hook_prot)) {
        return false;
    }

    volatile auto* target_ptr = reinterpret_cast<volatile LONG64*>(hk.hook_va);
    LONG64 current_val = *target_ptr;

    while (true) {
        LONG64 desired_val = current_val;
        const size_t first_chunk = (std::min)(hk.original_prologue.size(), static_cast<size_t>(8));
        std::memcpy(&desired_val, hk.original_prologue.data(), first_chunk);

        const LONG64 prev_val = _InterlockedCompareExchange64(target_ptr, desired_val, current_val);
        if (prev_val == current_val) {
            break;
        }
        current_val = prev_val;
    }

    if (hk.original_prologue.size() > 8) {
        std::memcpy(
            reinterpret_cast<void*>(hk.hook_va + 8),
            hk.original_prologue.data() + 8,
            hk.original_prologue.size() - 8
        );
    }

    VirtualProtect(reinterpret_cast<LPVOID>(hk.hook_va), total_protect_len, old_hook_prot, &old_hook_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hk.hook_va), total_protect_len);

    // restore pre-padding bytes if hotpatched
    if (hk.is_hotpatch && hk.hotpatch_pre_va != 0 && !hk.original_pre_bytes.empty()) {
        DWORD old_pre_prot = 0;
        if (VirtualProtect(reinterpret_cast<LPVOID>(hk.hotpatch_pre_va), hk.original_pre_bytes.size(), PAGE_EXECUTE_READWRITE, &old_pre_prot)) {
            std::memcpy(reinterpret_cast<void*>(hk.hotpatch_pre_va), hk.original_pre_bytes.data(), hk.original_pre_bytes.size());
            VirtualProtect(reinterpret_cast<LPVOID>(hk.hotpatch_pre_va), hk.original_pre_bytes.size(), old_pre_prot, &old_pre_prot);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hk.hotpatch_pre_va), hk.original_pre_bytes.size());
        }
    }

    // restore original cave padding bytes
    DWORD old_cave_prot = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(hk.cave_va), hk.original_cave_bytes.size(), PAGE_EXECUTE_READWRITE, &old_cave_prot)) {
        return false;
    }

    std::memcpy(reinterpret_cast<void*>(hk.cave_va), hk.original_cave_bytes.data(), hk.original_cave_bytes.size());
    VirtualProtect(reinterpret_cast<LPVOID>(hk.cave_va), hk.original_cave_bytes.size(), old_cave_prot, &old_cave_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(hk.cave_va), hk.original_cave_bytes.size());

    return true;
}

} // namespace ds
