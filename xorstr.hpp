#ifndef XORSTR_HPP
#define XORSTR_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(_MSC_VER)
    #define FORCE_INLINE __forceinline
    #include <windows.h>
#else
    #if defined(__GNUC__) || defined(__clang__)
        #define FORCE_INLINE inline __attribute__((always_inline))
    #else
        #define FORCE_INLINE inline
    #endif
    #include <sys/mman.h>
#endif

#if defined(__SSE2__)
    #include <emmintrin.h>
#endif

#ifndef ENCRYPT_SALT
    #define ENCRYPT_SALT 0xDEADBEEF
#endif

#ifndef UNIQUE_KEY
    #define UNIQUE_KEY __COUNTER__
#endif

namespace CompileTimeEncryption {

    constexpr uint32_t prng(uint32_t seed) {
        return seed * 1664525u + 1013904223u;
    }

    constexpr uint32_t ct_hash(const char* s) {
        uint32_t hash = 2166136261u;
        while (*s) {
            hash = (hash ^ static_cast<uint32_t>(*s)) * 16777619u;
            ++s;
        }
        return hash;
    }

    FORCE_INLINE void secureClear(void* buf, size_t len) {
#if defined(_MSC_VER)
        SecureZeroMemory(buf, len);
#elif defined(__STDC_LIB_EXT1__)
        memset_s(buf, len, 0, len);
#else
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(buf);
        while (len--) {
            *p++ = 0;
        }
#endif
    }

    FORCE_INLINE void lockMemory(void* buf, size_t len) {
#if defined(_MSC_VER)
        VirtualLock(buf, len);
#elif defined(__unix__) || defined(__APPLE__)
        mlock(buf, len);
#endif
    }

    FORCE_INLINE void unlockMemory(void* buf, size_t len) {
#if defined(_MSC_VER)
        VirtualUnlock(buf, len);
#elif defined(__unix__) || defined(__APPLE__)
        munlock(buf, len);
#endif
    }

    FORCE_INLINE bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len) {
#if defined(__SSE2__)
        size_t i = 0;
        __m128i diff = _mm_setzero_si128();
        for (; i + 15 < len; i += 16) {
            __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i));
            __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
            __m128i vxor = _mm_xor_si128(va, vb);
            diff = _mm_or_si128(diff, vxor);
        }
        int d = _mm_movemask_epi8(diff);
        for (; i < len; ++i) {
            d |= a[i] ^ b[i];
        }
        return d == 0;
#else
        volatile uint8_t d = 0;
        for (size_t i = 0; i < len; ++i)
            d |= a[i] ^ b[i];
        return d == 0;
#endif
    }

    template <std::size_t N>
    class EncryptedString {
    private:
        static constexpr uint32_t k = ct_hash(__DATE__) ^ ct_hash(__TIME__) ^ ENCRYPT_SALT ^ UNIQUE_KEY;
        static constexpr uint8_t k_byte = static_cast<uint8_t>(k & 0xFF);
        static constexpr uint16_t k_mask = static_cast<uint16_t>(k & 0xFFFF);

        static constexpr std::size_t pad_before = (prng(k) % 5) + 1;
        static constexpr std::size_t pad_after  = (prng(k + 1u) % 5) + 1;

        static constexpr std::size_t encrypted_core_length = (N - 1) * 2;
        static constexpr std::size_t total_size = 4 + pad_before + encrypted_core_length + pad_after;

        std::array<uint8_t, total_size> data;
        static constexpr uint16_t offset = 0xABCD;

        static consteval std::array<uint8_t, total_size> encrypt(const char (&str)[N]) {
            std::array<uint8_t, total_size> out = {};
            uint16_t obf_length = static_cast<uint16_t>((N - 1)) ^ k_mask;
            out[0] = static_cast<uint8_t>(obf_length & 0xFF);
            out[1] = static_cast<uint8_t>((obf_length >> 8) & 0xFF);
            out[2] = static_cast<uint8_t>(pad_before);
            out[3] = static_cast<uint8_t>(pad_after);
            std::size_t index = 4;

            {
                uint32_t seed = k;
                for (std::size_t i = 0; i < pad_before; i++) {
                    seed = prng(seed);
                    out[index++] = static_cast<uint8_t>(seed & 0xFF);
                }
            }

            for (std::size_t i = 0; i < N - 1; i++) {
                uint16_t val = static_cast<uint16_t>(str[i]);
                bool variant_flag = (((k >> (i % 3)) & 1u) != 0);
                uint16_t enc;
                if (variant_flag) {
                    enc = (val ^ k_byte) + offset + static_cast<uint16_t>(i) + 13;
                } else {
                    enc = (val ^ k_byte) + offset + static_cast<uint16_t>(i);
                }
                out[index++] = static_cast<uint8_t>(enc & 0xFF);
                out[index++] = static_cast<uint8_t>((enc >> 8) & 0xFF);
            }

            {
                uint32_t seed = k + 1u;
                for (std::size_t i = 0; i < pad_after; i++) {
                    seed = prng(seed);
                    out[index++] = static_cast<uint8_t>(seed & 0xFF);
                }
            }
            return out;
        }

        std::array<uint8_t, total_size> runtime_encrypt(const std::string & s) const {
            std::array<uint8_t, total_size> out = {};
            out[0] = data[0];
            out[1] = data[1];
            out[2] = static_cast<uint8_t>(pad_before);
            out[3] = static_cast<uint8_t>(pad_after);
            std::size_t index = 4;

            {
                uint32_t seed = k;
                for (std::size_t i = 0; i < pad_before; i++) {
                    seed = prng(seed);
                    out[index++] = static_cast<uint8_t>(seed & 0xFF);
                }
            }

            for (std::size_t i = 0; i < s.size(); i++) {
                uint16_t val = static_cast<uint16_t>(s[i]);
                bool variant_flag = (((k >> (i % 3)) & 1u) != 0);
                uint16_t enc;
                if (variant_flag) {
                    enc = (val ^ k_byte) + offset + static_cast<uint16_t>(i) + 13;
                } else {
                    enc = (val ^ k_byte) + offset + static_cast<uint16_t>(i);
                }
                out[index++] = static_cast<uint8_t>(enc & 0xFF);
                out[index++] = static_cast<uint8_t>((enc >> 8) & 0xFF);
            }

            {
                uint32_t seed = k + 1u;
                for (std::size_t i = 0; i < pad_after; i++) {
                    seed = prng(seed);
                    out[index++] = static_cast<uint8_t>(seed & 0xFF);
                }
            }
            return out;
        }

    public:
        consteval EncryptedString(const char (&str)[N])
            : data(encrypt(str))
        {}

        std::string get() const {
            uint16_t obf_length = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
            uint16_t plain_length = obf_length ^ k_mask;
            std::string result;
            result.resize(plain_length);
            std::size_t index = 4 + pad_before;
            for (std::size_t i = 0; i < plain_length; i++) {
                uint16_t enc = static_cast<uint16_t>(data[index]) | (static_cast<uint16_t>(data[index + 1]) << 8);
                index += 2;
                bool variant_flag = (((k >> (i % 3)) & 1u) != 0);
                uint16_t val;
                if (variant_flag) {
                    val = (enc - offset - static_cast<uint16_t>(i) - 13) ^ k_byte;
                } else {
                    val = (enc - offset - static_cast<uint16_t>(i)) ^ k_byte;
                }
                result[i] = static_cast<char>(val & 0xFF);
            }
            return result;
        }

        bool compare(const std::string & s) const {
            auto encrypted_input = runtime_encrypt(s);
            bool equal = constantTimeCompare(data.data(), encrypted_input.data(), total_size);
            secureClear(encrypted_input.data(), total_size);
            return equal;
        }
    };

} // namespace CompileTimeEncryption

#define XORSTR(str) ([]() consteval { return CompileTimeEncryption::EncryptedString<sizeof(str)>(str); }())


#endif // XORSTR_HPP
