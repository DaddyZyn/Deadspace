#include "image.hpp"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace ds {

std::optional<image> image::load_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    const auto sz = static_cast<size_t>(file.tellg());
    if (sz < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

    file.seekg(0, std::ios::beg);
    image img;
    img.disk_buffer_.resize(sz);
    file.read(reinterpret_cast<char*>(img.disk_buffer_.data()), sz);

    img.from_memory_ = false;
    img.mem_ptr_ = nullptr;
    img.total_size_ = sz;
    img.base_address_ = 0;

    if (!img.parse()) return std::nullopt;
    return img;
}

std::optional<image> image::load_memory(HMODULE mod) {
    if (!mod) return std::nullopt;

    image img;
    img.from_memory_ = true;
    img.mem_ptr_ = reinterpret_cast<const uint8_t*>(mod);
    img.base_address_ = reinterpret_cast<uintptr_t>(mod);

    const auto* dos = img.dos();
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

    const auto* nt = img.nt();
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

    img.total_size_ = nt->OptionalHeader.SizeOfImage;
    if (!img.parse()) return std::nullopt;
    return img;
}

std::optional<image> image::load_buffer(std::vector<uint8_t> buffer, uintptr_t base_address, bool is_memory_layout) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

    image img;
    img.disk_buffer_ = std::move(buffer);
    img.from_memory_ = is_memory_layout;
    img.mem_ptr_ = nullptr;
    img.total_size_ = img.disk_buffer_.size();
    img.base_address_ = base_address;

    if (!img.parse()) return std::nullopt;
    return img;
}

bool image::parse() {
    const uint8_t* view = raw_view();
    if (!view || total_size_ < sizeof(IMAGE_DOS_HEADER)) return false;

    // dos header sanity check
    const auto* dos_hdr = this->dos();
    if (!dos_hdr || dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

    if (dos_hdr->e_lfanew < 0 || static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > total_size_) {
        return false;
    }

    // nt signature check
    const auto* nt_hdr = this->nt();
    if (!nt_hdr || nt_hdr->Signature != IMAGE_NT_SIGNATURE) return false;

    // drop 32-bit binaries, we only care about x64
    if (nt_hdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    if (!from_memory_) {
        base_address_ = nt_hdr->OptionalHeader.ImageBase;
    }

    const uint16_t num_secs = nt_hdr->FileHeader.NumberOfSections;
    const size_t sec_table_offset = static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(DWORD) +
                                   sizeof(IMAGE_FILE_HEADER) + nt_hdr->FileHeader.SizeOfOptionalHeader;

    if (sec_table_offset + num_secs * sizeof(IMAGE_SECTION_HEADER) > total_size_) {
        return false;
    }

    const auto* sec_hdr = reinterpret_cast<const IMAGE_SECTION_HEADER*>(view + sec_table_offset);

    sections_.clear();
    sections_.reserve(num_secs);

    for (uint16_t i = 0; i < num_secs; ++i) {
        const auto& s = sec_hdr[i];
        char name_buf[9] = {};
        std::memcpy(name_buf, s.Name, 8);

        section_info info;
        info.name = name_buf;
        info.rva = s.VirtualAddress;
        info.virtual_size = s.Misc.VirtualSize;
        info.raw_offset = s.PointerToRawData;
        info.raw_size = s.SizeOfRawData;
        info.characteristics = s.Characteristics;
        info.is_executable = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        info.is_writable = (s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        sections_.push_back(info);
    }

    // index .pdata exception directory for function bounds
    functions_.clear();
    const auto& exc_dir = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc_dir.VirtualAddress && exc_dir.Size) {
        const uint32_t exc_off = from_memory_ ? exc_dir.VirtualAddress : rva_to_file_offset(exc_dir.VirtualAddress);
        if (exc_off != 0 && exc_off + exc_dir.Size <= total_size_) {
            const size_t num_entries = exc_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
            const auto* entries = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(view + exc_off);
            functions_.reserve(num_entries);

            for (size_t i = 0; i < num_entries; ++i) {
                if (entries[i].BeginAddress < entries[i].EndAddress) {
                    function_range fr;
                    fr.begin_rva = entries[i].BeginAddress;
                    fr.end_rva = entries[i].EndAddress;
                    fr.unwind_rva = entries[i].UnwindInfoAddress;
                    functions_.push_back(fr);
                }
            }

            // sort by begin_rva for binary search
            std::sort(functions_.begin(), functions_.end(), [](const auto& a, const auto& b) {
                return a.begin_rva < b.begin_rva;
            });

            end_rvas_.clear();
            end_rvas_.reserve(functions_.size());
            for (const auto& fn : functions_) {
                end_rvas_.push_back(fn.end_rva);
            }
            std::sort(end_rvas_.begin(), end_rvas_.end());
            end_rvas_.erase(std::unique(end_rvas_.begin(), end_rvas_.end()), end_rvas_.end());
        }
    }

    // parse exports and flag forwarder strings
    exports_.clear();
    const auto& exp_dir = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress && exp_dir.Size) {
        const uint32_t exp_offset = from_memory_ ? exp_dir.VirtualAddress : rva_to_file_offset(exp_dir.VirtualAddress);
        if (exp_offset != 0 && exp_offset + sizeof(IMAGE_EXPORT_DIRECTORY) <= total_size_) {
            const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(view + exp_offset);

            constexpr uint32_t kMaxExportCount = 0x00FFFFFF;
            if (exp->NumberOfNames <= kMaxExportCount && exp->NumberOfFunctions <= kMaxExportCount &&
                exp->NumberOfNames > 0 && exp->NumberOfFunctions > 0) {

                const uint32_t names_off = from_memory_ ? exp->AddressOfNames : rva_to_file_offset(exp->AddressOfNames);
                const uint32_t ords_off  = from_memory_ ? exp->AddressOfNameOrdinals : rva_to_file_offset(exp->AddressOfNameOrdinals);
                const uint32_t funcs_off = from_memory_ ? exp->AddressOfFunctions : rva_to_file_offset(exp->AddressOfFunctions);

                const size_t names_bytes = static_cast<size_t>(exp->NumberOfNames) * sizeof(uint32_t);
                const size_t ords_bytes  = static_cast<size_t>(exp->NumberOfNames) * sizeof(uint16_t);
                const size_t funcs_bytes = static_cast<size_t>(exp->NumberOfFunctions) * sizeof(uint32_t);

                if (names_off && ords_off && funcs_off &&
                    names_off + names_bytes <= total_size_ &&
                    ords_off  + ords_bytes  <= total_size_ &&
                    funcs_off + funcs_bytes <= total_size_) {

                    const auto* names = reinterpret_cast<const uint32_t*>(view + names_off);
                    const auto* ords  = reinterpret_cast<const uint16_t*>(view + ords_off);
                    const auto* funcs = reinterpret_cast<const uint32_t*>(view + funcs_off);

                    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                        const uint32_t name_off = from_memory_ ? names[i] : rva_to_file_offset(names[i]);
                        if (!name_off || name_off >= total_size_) continue;

                        const size_t max_name_len = total_size_ - name_off;
                        const size_t str_len = strnlen(reinterpret_cast<const char*>(view + name_off), max_name_len);
                        if (str_len == max_name_len) continue;

                        const uint16_t ord = ords[i];
                        if (ord >= exp->NumberOfFunctions) continue;
                        const uint32_t fn_rva = funcs[ord];

                        export_symbol sym;
                        sym.name = std::string(reinterpret_cast<const char*>(view + name_off), str_len);
                        sym.rva = fn_rva;
                        sym.ordinal = static_cast<uint16_t>(exp->Base + ord);

                        // don't attempt to hook forwarded export strings in .rdata
                        if (fn_rva >= exp_dir.VirtualAddress && fn_rva < exp_dir.VirtualAddress + exp_dir.Size) {
                            sym.is_forwarded = true;
                            const uint32_t fwd_off = from_memory_ ? fn_rva : rva_to_file_offset(fn_rva);
                            if (fwd_off && fwd_off < total_size_) {
                                const size_t max_fwd_len = total_size_ - fwd_off;
                                const size_t fwd_len = strnlen(reinterpret_cast<const char*>(view + fwd_off), max_fwd_len);
                                if (fwd_len < max_fwd_len) {
                                    sym.forwarder_name = std::string(reinterpret_cast<const char*>(view + fwd_off), fwd_len);
                                }
                            }
                        }

                        exports_.push_back(sym);
                    }
                }
            }
        }
    }

    valid_ = true;
    return true;
}

uint32_t image::rva_to_file_offset(uint32_t rva) const {
    if (from_memory_) return rva;

    for (const auto& sec : sections_) {
        const uint32_t extent = (sec.raw_size > sec.virtual_size) ? sec.raw_size : sec.virtual_size;
        if (rva >= sec.rva && rva < sec.rva + extent) {
            const uint32_t diff = rva - sec.rva;
            if (diff < sec.raw_size) {
                return sec.raw_offset + diff;
            }
        }
    }
    return 0;
}

uintptr_t image::rva_to_va(uint32_t rva) const {
    return base_address_ + rva;
}

uint32_t image::va_to_rva(uintptr_t va) const {
    return static_cast<uint32_t>(va - base_address_);
}

std::span<const uint8_t> image::get_section_bytes(const section_info& sec, bool clamp_to_min) const {
    const uint8_t* view = raw_view();
    if (!view) return {};

    if (from_memory_) {
        // in memory: grab mapped virtual page tail up to 4KB page boundary
        size_t len = sec.virtual_size;
        if (sec.virtual_size > 0) {
            size_t page_aligned = (sec.virtual_size + 0xFFF) & ~static_cast<size_t>(0xFFF);
            uint32_t next_rva = static_cast<uint32_t>(total_size_);
            for (const auto& other : sections_) {
                if (other.rva > sec.rva && other.rva < next_rva) {
                    next_rva = other.rva;
                }
            }
            if (sec.rva + page_aligned > next_rva) {
                page_aligned = next_rva - sec.rva;
            }
            if (sec.rva + page_aligned <= total_size_) {
                len = page_aligned;
            }
        }
        if (sec.rva + len <= total_size_) {
            return { view + sec.rva, len };
        }
        return {};
    }

    size_t len = sec.raw_size;
    if (clamp_to_min && sec.virtual_size > 0 && sec.virtual_size < sec.raw_size) {
        len = sec.virtual_size;
    }

    if (sec.raw_offset + len <= total_size_) {
        return { view + sec.raw_offset, len };
    }
    return {};
}

std::span<uint8_t> image::get_section_bytes_mut(const section_info& sec) {
    uint8_t* view = raw_view_mut();
    if (!view) return {};

    if (from_memory_) {
        size_t len = sec.virtual_size;
        if (sec.virtual_size > 0) {
            size_t page_aligned = (sec.virtual_size + 0xFFF) & ~static_cast<size_t>(0xFFF);
            uint32_t next_rva = static_cast<uint32_t>(total_size_);
            for (const auto& other : sections_) {
                if (other.rva > sec.rva && other.rva < next_rva) {
                    next_rva = other.rva;
                }
            }
            if (sec.rva + page_aligned > next_rva) {
                page_aligned = next_rva - sec.rva;
            }
            if (sec.rva + page_aligned <= total_size_) {
                len = page_aligned;
            }
        }
        if (sec.rva + len <= total_size_) {
            return { view + sec.rva, len };
        }
        return {};
    }

    if (sec.raw_offset + sec.raw_size <= total_size_) {
        return { view + sec.raw_offset, sec.raw_size };
    }
    return {};
}

std::optional<export_symbol> image::find_export(const std::string& name) const {
    for (const auto& exp : exports_) {
        if (exp.name == name) return exp;
    }
    return std::nullopt;
}

std::optional<section_info> image::find_section_by_rva(uint32_t rva) const {
    for (const auto& sec : sections_) {
        if (rva >= sec.rva && rva < sec.rva + sec.virtual_size) {
            return sec;
        }
    }
    return std::nullopt;
}

std::optional<section_info> image::find_section(const std::string& name) const {
    for (const auto& sec : sections_) {
        if (sec.name == name) return sec;
    }
    return std::nullopt;
}

bool image::is_inside_function(uint32_t rva, size_t size) const {
    if (functions_.empty() || size == 0) return false;

    const uint32_t target_end = rva + static_cast<uint32_t>(size);

    auto it = std::lower_bound(functions_.begin(), functions_.end(), rva, [](const function_range& fn, uint32_t start) {
        return fn.end_rva <= start;
    });

    while (it != functions_.end() && it->begin_rva < target_end) {
        if ((std::max)(rva, it->begin_rva) < (std::min)(target_end, it->end_rva)) {
            return true;
        }
        ++it;
    }

    return false;
}

bool image::is_at_function_end(uint32_t rva) const {
    if (rva == 0) return false;

    // match against .pdata function end bounds via binary search
    if (!end_rvas_.empty()) {
        auto it = std::lower_bound(end_rvas_.begin(), end_rvas_.end(), rva);
        if (it != end_rvas_.end() && *it == rva) {
            return true;
        }
    }

    // fallback: check for preceding 0xCC 0xCC int3 padding
    if (rva >= 2) {
        const uint8_t* view = raw_view();
        if (view) {
            const uint32_t off1 = from_memory_ ? (rva - 1) : rva_to_file_offset(rva - 1);
            const uint32_t off2 = from_memory_ ? (rva - 2) : rva_to_file_offset(rva - 2);
            if (off1 < total_size_ && off2 < total_size_) {
                if (from_memory_ || (off1 != 0 && off2 != 0)) {
                    if (view[off1] == 0xCC && view[off2] == 0xCC) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

} // namespace ds
