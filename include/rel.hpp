#pragma once

#include "scan.hpp"
#include <cstdint>
#include <optional>
#include <vector>
#include <algorithm>
#include <cmath>

namespace ds {

struct rel32_result {
    int64_t delta;
    int32_t disp32;
    bool in_range;
};

struct reachable_cave {
    cave target_cave;
    int64_t distance;
    int32_t disp32;
};

struct rel {
    // 5-byte rel32 jump: e9 <disp32>
    static constexpr size_t kRel32JmpSize = 5;

    // delta = target - (source + insn_len)
    static inline rel32_result calc(uintptr_t from, uintptr_t to, size_t insn_len = kRel32JmpSize) {
        const int64_t delta = static_cast<int64_t>(to) - static_cast<int64_t>(from + insn_len);
        const bool fits = (delta >= INT32_MIN && delta <= INT32_MAX);
        return { delta, static_cast<int32_t>(delta), fits };
    }

    // find caves reachable within +/- 2gb
    static inline std::vector<reachable_cave> filter_reachable(
        const std::vector<cave>& caves,
        uintptr_t hook_site_va,
        size_t required_capacity = kRel32JmpSize
    ) {
        std::vector<reachable_cave> out;
        out.reserve(caves.size());

        for (const auto& c : caves) {
            if (c.size < required_capacity) continue;

            const auto res = calc(hook_site_va, c.va);
            if (res.in_range) {
                out.push_back({ c, std::abs(res.delta), res.disp32 });
            }
        }

        // sort closest first for cache locality
        std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
            return a.distance < b.distance;
        });

        return out;
    }
};

} // namespace ds
