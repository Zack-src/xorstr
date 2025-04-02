#ifndef XORSTR_HPP
#define XORSTR_HPP

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#if defined(_MSC_VER)
#include <windows.h>
#include <intrin.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM)
#include <arm_neon.h>
#endif

#ifndef __COUNTER__
#define __COUNTER__ __LINE__
#endif

#if defined(_MSC_VER)
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#endif

void secure_memzero(void* ptr, std::size_t len) {
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(ptr);
    while(len--) *p++ = 0;
#endif
}

bool lock_memory(void* ptr, std::size_t len) {
#if defined(_MSC_VER)
    return VirtualLock(ptr, len) != 0;
#else
    return mlock(ptr, len) == 0;
#endif
}

bool unlock_memory(void* ptr, std::size_t len) {
#if defined(_MSC_VER)
    return VirtualUnlock(ptr, len) != 0;
#else
    return munlock(ptr, len) == 0;
#endif
}

constexpr std::size_t ct_strlen(const char* str) {
    std::size_t len = 0;
    while(str[len] != '\0') { ++len; }
    return len;
}

XORSTR_FORCEINLINE constexpr uint32_t key4(uint32_t seed) noexcept {
    uint32_t value = seed;
    for (char c : __TIME__)
        value = static_cast<uint32_t>((value ^ c) * 16777619ull);
    for (char c : __DATE__)
        value = static_cast<uint32_t>((value ^ c) * 16777619ull);
    return value;
}

XORSTR_FORCEINLINE constexpr uint64_t key8(std::size_t S) noexcept {
    constexpr uint32_t initial = 2166136261u;
    const uint32_t first_part  = key4(initial + static_cast<uint32_t>(S));
    const uint32_t second_part = key4(first_part);
    return (static_cast<uint64_t>(first_part) << 32) | second_part;
}

#define GENERATE_KEY(cnt) (key8(cnt))

template <std::size_t N>
constexpr uint32_t compute_checksum(const std::array<char, N>& arr) {
    uint32_t sum = 0;
    for (std::size_t i = 0; i < N; ++i) {
        sum += static_cast<uint8_t>(arr[i]);
    }
    return sum;
}

template<int Alg>
struct Obfuscator;

template<>
struct Obfuscator<0> {
    static XORSTR_FORCEINLINE constexpr char encrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        return static_cast<char>((static_cast<uint8_t>(c) ^ k) + (pos & 0xFF));
    }
    static XORSTR_FORCEINLINE constexpr char decrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        return static_cast<char>((static_cast<uint8_t>(c) - (pos & 0xFF)) ^ k);
    }
};

template<>
struct Obfuscator<1> {
    static XORSTR_FORCEINLINE constexpr uint8_t rotate_left(uint8_t x, unsigned int n) {
        return static_cast<uint8_t>((x << n) | (x >> (8 - n)));
    }
    static XORSTR_FORCEINLINE constexpr uint8_t rotate_right(uint8_t x, unsigned int n) {
        return static_cast<uint8_t>((x >> n) | (x << (8 - n)));
    }
    static XORSTR_FORCEINLINE constexpr char encrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k   = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t add = static_cast<uint8_t>(pos & 0x0F);
        uint8_t val = static_cast<uint8_t>(c) + k + add;
        uint8_t rot = static_cast<uint8_t>((pos % 5) + 1);
        return static_cast<char>(rotate_left(val, rot));
    }
    static XORSTR_FORCEINLINE constexpr char decrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t rot = static_cast<uint8_t>((pos % 5) + 1);
        uint8_t val = rotate_right(static_cast<uint8_t>(c), rot);
        uint8_t k   = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t add = static_cast<uint8_t>(pos & 0x0F);
        return static_cast<char>(val - k - add);
    }
};

template<>
struct Obfuscator<2> {
    static XORSTR_FORCEINLINE constexpr char encrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k   = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t val = static_cast<uint8_t>(c) + static_cast<uint8_t>(pos & 0xFF);
        return static_cast<char>((val * 13 + 7) ^ k);
    }
    static XORSTR_FORCEINLINE constexpr char decrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k   = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t val = static_cast<uint8_t>(c) ^ k;
        return static_cast<char>(((val - 7) * 197) - (pos & 0xFF));
    }
};

template<>
struct Obfuscator<3> {
    static XORSTR_FORCEINLINE constexpr uint8_t modinv(uint8_t a) {
        for (uint16_t i = 1; i < 256; ++i) {
            if ((a * i) % 256 == 1)
                return static_cast<uint8_t>(i);
        }
        return 1;
    }
    static XORSTR_FORCEINLINE constexpr char encrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t factor = static_cast<uint8_t>((pos % 127) | 1);
        uint8_t x = static_cast<uint8_t>(c) ^ k;
        return static_cast<char>((x * factor) % 256);
    }
    static XORSTR_FORCEINLINE constexpr char decrypt_char(char c, std::size_t pos, uint64_t key) {
        uint8_t k = static_cast<uint8_t>((key >> ((pos % 8) * 8)) & 0xFF);
        uint8_t factor = static_cast<uint8_t>((pos % 127) | 1);
        uint8_t inv = modinv(factor);
        uint8_t x = (static_cast<uint8_t>(c) * inv) % 256;
        return static_cast<char>(x ^ k);
    }
};

template<std::size_t N, int Alg, uint64_t Key>
struct ObscuredString {
    alignas(32) std::array<char, N> encrypted{};
    mutable std::string decryptedCache;
    mutable bool decryptedInitialized = false;
    uint32_t checksum = 0;

    constexpr ObscuredString(const char (&str)[N])
        : encrypted([](const char (&s)[N], uint64_t key) constexpr {
        std::array<char, N> arr{};
        for (std::size_t i = 0; i < N; ++i)
            arr[i] = Obfuscator<Alg>::encrypt_char(s[i], i, key);
        return arr;
            }(str, Key)), checksum(compute_checksum(encrypted))
    {}

    void decrypt(char* output) const {
        if (compute_checksum(encrypted) != checksum) {
            throw std::runtime_error("Data integrity check failed!");
        }
#if defined(__SSE2__)
        if constexpr (N >= 16 && Alg == 1) {
            __m128i keyVec = _mm_set1_epi8(static_cast<char>(Key & 0xFF));
            __m128i block  = _mm_load_si128(reinterpret_cast<const __m128i*>(encrypted.data()));
            __m128i dec    = _mm_xor_si128(block, keyVec);
            _mm_store_si128(reinterpret_cast<__m128i*>(output), dec);
            for (std::size_t i = 16; i < N; ++i)
                output[i] = Obfuscator<Alg>::decrypt_char(encrypted[i], i, Key);
            goto lock_and_finish;
        }
#elif defined(__ARM_NEON)
        if constexpr (N >= 16 && Alg == 1) {
            uint8x16_t keyVec = vdupq_n_u8(static_cast<uint8_t>(Key & 0xFF));
            uint8x16_t block  = vld1q_u8(reinterpret_cast<const uint8_t*>(encrypted.data()));
            uint8x16_t dec    = veorq_u8(block, keyVec);
            vst1q_u8(reinterpret_cast<uint8_t*>(output), dec);
            for (std::size_t i = 16; i < N; ++i)
                output[i] = Obfuscator<Alg>::decrypt_char(encrypted[i], i, Key);
            goto lock_and_finish;
        }
#endif
        for (std::size_t i = 0; i < N; ++i)
            output[i] = Obfuscator<Alg>::decrypt_char(encrypted[i], i, Key);
    
    lock_and_finish:
        lock_memory(output, N);
    }

    std::string get() const {
        if (!decryptedInitialized) {
            decryptedCache.resize(N);
            decrypt(&decryptedCache[0]);
            decryptedInitialized = true;
        }
        return decryptedCache;
    }

    template<typename Func>
    void use(Func&& func) const {
        char buffer[N];
        decrypt(buffer);
        func(buffer);
        secure_memzero(buffer, N);
        unlock_memory(buffer, N);
    }
};

#define XORSTR_INTERNAL(str, cnt) \
    ObscuredString<sizeof(str), (GENERATE_KEY(cnt) % 4), GENERATE_KEY(cnt)>(str)

#define XORSTR(str) XORSTR_INTERNAL(str, __COUNTER__)

#endif // XORSTR_HPP
