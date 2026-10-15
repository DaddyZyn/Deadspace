#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <span>

namespace ds {

struct section_info {
    std::string name;
    uint32_t rva;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
    bool is_executable;
    bool is_writable;
};

struct export_symbol {
    std::string name;
    uint32_t rva;
    uint16_t ordinal;
    bool is_forwarded = false;
    std::string forwarder_name;
};

struct function_range {
    uint32_t begin_rva;
    uint32_t end_rva;
    uint32_t unwind_rva;
};

class image {
public:
    image() = default;
    ~image() = default;

    image(const image&) = default;
    image& operator=(const image&) = default;
    image(image&&) noexcept = default;
    image& operator=(image&&) noexcept = default;

    static std::optional<image> load_file(const std::string& path);
    static std::optional<image> load_memory(HMODULE mod);
    static std::optional<image> load_buffer(std::vector<uint8_t> buffer, uintptr_t base_address = 0, bool is_memory_layout = false);

    [[nodiscard]] bool valid() const { return valid_; }
    [[nodiscard]] uintptr_t base() const { return base_address_; }
    [[nodiscard]] bool is_in_memory() const { return from_memory_; }
    [[nodiscard]] size_t size() const { return total_size_; }
    [[nodiscard]] const std::vector<section_info>& sections() const { return sections_; }
    [[nodiscard]] const std::vector<export_symbol>& exports() const { return exports_; }
    [[nodiscard]] const std::vector<function_range>& functions() const { return functions_; }

    [[nodiscard]] const uint8_t* raw_view() const {
        return from_memory_ ? mem_ptr_ : disk_buffer_.data();
    }

    [[nodiscard]] uint8_t* raw_view_mut() {
        return from_memory_ ? const_cast<uint8_t*>(mem_ptr_) : disk_buffer_.data();
    }

    const IMAGE_DOS_HEADER* dos() const {
        const auto* ptr = raw_view();
        return ptr ? reinterpret_cast<const IMAGE_DOS_HEADER*>(ptr) : nullptr;
    }

    const IMAGE_NT_HEADERS64* nt() const {
        const auto* d = dos();
        const auto* ptr = raw_view();
        if (!d || !ptr || d->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        return reinterpret_cast<const IMAGE_NT_HEADERS64*>(ptr + d->e_lfanew);
    }

    uint32_t rva_to_file_offset(uint32_t rva) const;
    uintptr_t rva_to_va(uint32_t rva) const;
    uint32_t va_to_rva(uintptr_t va) const;

    std::span<const uint8_t> get_section_bytes(const section_info& sec, bool clamp_to_min = false) const;
    std::span<uint8_t> get_section_bytes_mut(const section_info& sec);

    std::optional<export_symbol> find_export(const std::string& name) const;
    std::optional<section_info> find_section_by_rva(uint32_t rva) const;
    std::optional<section_info> find_section(const std::string& name) const;

    // checks if range intersects any .pdata function bounds
    bool is_inside_function(uint32_t rva, size_t size) const;

    // checks if rva is a verified function boundary or preceded by int3 padding
    bool is_at_function_end(uint32_t rva) const;

    [[nodiscard]] const std::vector<uint8_t>& buffer() const { return disk_buffer_; }
    [[nodiscard]] std::vector<uint8_t>& buffer_mut() { return disk_buffer_; }

private:
    bool parse();

    bool valid_ = false;
    bool from_memory_ = false;
    uintptr_t base_address_ = 0;
    std::vector<uint8_t> disk_buffer_;
    const uint8_t* mem_ptr_ = nullptr;
    size_t total_size_ = 0;

    std::vector<section_info> sections_;
    std::vector<export_symbol> exports_;
    std::vector<function_range> functions_;
    std::vector<uint32_t> end_rvas_;
};

} // namespace ds
