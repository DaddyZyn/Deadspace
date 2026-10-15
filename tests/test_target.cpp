#include <windows.h>
#include <cstdint>

extern "C" {

__declspec(dllexport) uint64_t target_function_alpha(uint64_t a, uint64_t b) {
    return (a * 6364136223846793005ULL) ^ (b + 0xDEADBEEF);
}

__declspec(dllexport) uint64_t target_function_beta(const char* str) {
    if (!str) return 0;
    uint64_t hash = 14695981039346656037ULL;
    while (*str) {
        hash ^= static_cast<uint8_t>(*str++);
        hash *= 1099511628211ULL;
    }
    return hash;
}

__declspec(dllexport) void target_function_gamma(int* arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) {
        arr[i] = arr[i] * 3 + 7;
    }
}

}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
