#pragma once

#include "image.hpp"
#include <cstdint>
#include <vector>
#include <string>

namespace ds {

enum class cave_type : uint8_t {
    int3_padding   = 0xCC,
    nop_padding    = 0x90,
    null_padding   = 0x00,
    multibyte_nop  = 0x1F,
    any            = 0xFF
};

struct cave {
    uint32_t rva = 0;
    uint32_t raw_offset = 0;
    uintptr_t va = 0;
    size_t size = 0;
    cave_type type = cave_type::any;
    std::string section_name;
    bool verified_inter_function = false;
};

struct scan_options {
    size_t min_size = 5;
    cave_type type = cave_type::any;
    bool executable_only = true;
    bool check_pdata = true;           // filter false-positives against .pdata functions
    bool scan_multibyte_nops = true;   // handle 2-9 byte x64 nop patterns
    bool clamp_disk_sections = true;   // clamp raw_size to virtual_size on disk
};

struct cave_scanner {
    static std::vector<cave> find_caves(const image& img, const scan_options& opt = {});
    static const char* type_name(cave_type t);
    static size_t match_nop_sequence(const uint8_t* p, size_t remaining);
};

// tracks and carves slices out of candidate caves
class cave_allocator {
public:
    cave_allocator() = default;
    explicit cave_allocator(std::vector<cave> caves) : caves_(std::move(caves)) {}

    // carve a slice out of the closest cave within +/- 2GB of target_va
    std::optional<cave> allocate(uintptr_t target_va, size_t required_bytes, size_t alignment = 16);

    [[nodiscard]] const std::vector<cave>& available_caves() const { return caves_; }

private:
    std::vector<cave> caves_;
};

} // namespace ds
