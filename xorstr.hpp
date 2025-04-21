#ifndef XORSTR_HPP
#define XORSTR_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_MSC_VER)
    #define FORCE_INLINE __forceinline
    #include <intrin.h>
    #include <windows.h>
#else
    #if defined(__GNUC__) || defined(__clang__)
        #define FORCE_INLINE inline __attribute__((always_inline))
        #if defined(__x86_64__) || defined(__i386__)
            #include <x86intrin.h>
        #endif
    #else
        #define FORCE_INLINE inline
    #endif
        #include <sys/mman.h>
        #include <unistd.h>
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

namespace StrEncryption {

    constexpr uint32_t prng(uint32_t seed) {
        return seed * 1664525u + 1013904223u;
    }

    constexpr uint32_t c_hash(const char* s) {
        uint32_t hash = 2166136261u;
        while (*s) {
            hash = (hash ^ static_cast<uint32_t>(*s)) * 16777619u;
            ++s;
        }
        return hash;
    }

    FORCE_INLINE void secure_memzero(void* buf, size_t len) {
#if defined(_MSC_VER)
        SecureZeroMemory(buf, len);
#elif defined(__STDC_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ >= 1)
        memset_s(buf, len, 0, len);
#else
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(buf);
        while (len--) {
            *p++ = 0;
        }
#endif
    }

    FORCE_INLINE bool lock_mem(void* buf, size_t len) {
#if defined(_MSC_VER)
        return VirtualLock(buf, len) != 0;
#elif defined(__unix__) || defined(__APPLE__)
        return mlock(buf, len) == 0;
#else
        (void)buf; (void)len; return false;
#endif
    }

    FORCE_INLINE bool unlock_mem(void* buf, size_t len) {
#if defined(_MSC_VER)
        return VirtualUnlock(buf, len) != 0;
#elif defined(__unix__) || defined(__APPLE__)
        return munlock(buf, len) == 0;
#else
        (void)buf; (void)len; return false;
#endif
    }

    FORCE_INLINE bool ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
#if defined(__SSE2__)
        size_t i = 0;
        __m128i diff = _mm_setzero_si128();
        for (; i + 15 < len; i += 16) {
            __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i));
            __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
            diff = _mm_or_si128(diff, _mm_xor_si128(va, vb));
        }
        int d = _mm_movemask_epi8(diff);
        for (; i < len; ++i) d |= a[i] ^ b[i];
        return d == 0;
#else
        volatile uint8_t diff_accumulator = 0;
        for (size_t i = 0; i < len; ++i) diff_accumulator |= a[i] ^ b[i];
        return diff_accumulator == 0;
#endif
    }


    namespace Sha256 {
        // Constantes SHA-256
        constexpr std::array<uint32_t, 64> K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        constexpr uint32_t rotr(uint32_t n, unsigned int c) {
            return (n >> c) | (n << (32 - c));
        }
        constexpr uint32_t shr(uint32_t n, unsigned int c) {
            return n >> c;
        }
        constexpr uint32_t Sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
        constexpr uint32_t Sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
        constexpr uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
        constexpr uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }
        constexpr uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
        constexpr uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

        struct Context {
            uint64_t len = 0;
            std::array<uint32_t, 8> h = { // Valeurs de hachage initiales H(0)
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };
            std::array<uint8_t, 64> buffer{}; // Buffer de 512 bits (64 bytes)
            size_t buffer_len = 0;

            constexpr void process_block() {
                std::array<uint32_t, 64> w{};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] =
                        (static_cast<uint32_t>(buffer[i * 4 + 0]) << 24) |
                        (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
                        (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8)  |
                        (static_cast<uint32_t>(buffer[i * 4 + 3]) << 0);
                }
                
                for (size_t i = 16; i < 64; ++i) {
                    w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
                }
                
                uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], h_ = h[7];
                
                for (size_t i = 0; i < 64; ++i) {
                    uint32_t T1 = h_ + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
                    uint32_t T2 = Sigma0(a) + Maj(a, b, c);
                    h_ = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
                }
                
                h[0] += a; h[1] += b; h[2] += c; h[3] += d;
                h[4] += e; h[5] += f; h[6] += g; h[7] += h_;
                buffer_len = 0;
            }

            constexpr void update(const uint8_t* data, size_t length) {
                for (size_t i = 0; i < length; ++i) {
                    buffer[buffer_len++] = data[i];
                    if (buffer_len == 64) {
                        process_block();
                    }
                }
                len += length * 8;
            }

            constexpr std::array<uint8_t, 32> final() {
                buffer[buffer_len++] = 0x80;
                if (buffer_len > 56) {
                    while(buffer_len < 64) buffer[buffer_len++] = 0;
                    process_block();
                }
                while(buffer_len < 56) buffer[buffer_len++] = 0;

                for (int i = 7; i >= 0; --i) {
                    buffer[56 + i] = static_cast<uint8_t>((len >> ((7 - i) * 8)) & 0xFF);
                }
                process_block();

                std::array<uint8_t, 32> digest{};
                for (size_t i = 0; i < 8; ++i) {
                    digest[i * 4 + 0] = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
                    digest[i * 4 + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
                    digest[i * 4 + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
                    digest[i * 4 + 3] = static_cast<uint8_t>((h[i] >> 0) & 0xFF);
                }
                return digest;
            }
        };

        constexpr std::array<uint8_t, 32> calculate(const uint8_t* data, size_t length) {
            Context ctx;
            ctx.update(data, length);
            return ctx.final();
        }

        inline std::array<uint8_t, 32> calculate(const std::string& s) {
            return calculate(reinterpret_cast<const uint8_t*>(s.data()), s.length());
        }

        inline std::array<uint8_t, 32> calculate(const char* s) {
            return calculate(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
        }
    }

    namespace HmacSha256 {
        constexpr size_t BLOCK_SIZE = 64;
        constexpr size_t HASH_SIZE = 32;

        constexpr std::array<uint8_t, HASH_SIZE> calculate(
            const uint8_t* key, size_t key_len,
            const uint8_t* data, size_t data_len)
        {
            std::array<uint8_t, BLOCK_SIZE> k_padded{};
            std::array<uint8_t, BLOCK_SIZE> opad_key{};
            std::array<uint8_t, BLOCK_SIZE> ipad_key{};

            if (key_len > BLOCK_SIZE) {
                std::array<uint8_t, HASH_SIZE> key_hash = Sha256::calculate(key, key_len);
                for(size_t i=0; i < HASH_SIZE; ++i) k_padded[i] = key_hash[i];
            } else {
                for(size_t i=0; i < key_len; ++i) k_padded[i] = key[i];
            }

            for (size_t i = 0; i < BLOCK_SIZE; ++i) {
                opad_key[i] = k_padded[i] ^ 0x5c;
                ipad_key[i] = k_padded[i] ^ 0x36;
            }

            Sha256::Context inner_ctx;
            inner_ctx.update(ipad_key.data(), BLOCK_SIZE);
            inner_ctx.update(data, data_len);
            std::array<uint8_t, HASH_SIZE> inner_hash = inner_ctx.final();

            Sha256::Context outer_ctx;
            outer_ctx.update(opad_key.data(), BLOCK_SIZE);
            outer_ctx.update(inner_hash.data(), HASH_SIZE);
            std::array<uint8_t, HASH_SIZE> final_hmac = outer_ctx.final();

            for(size_t i=0; i<BLOCK_SIZE; ++i) { k_padded[i] = 0; opad_key[i] = 0; ipad_key[i] = 0; }
            return final_hmac;
        }

        constexpr std::array<uint8_t, HASH_SIZE> calculate(
            uint32_t key,
            const uint8_t* data, size_t data_len)
        {
            std::array<uint8_t, 4> key_bytes = {
                static_cast<uint8_t>((key >> 24) & 0xFF), static_cast<uint8_t>((key >> 16) & 0xFF),
                static_cast<uint8_t>((key >> 8) & 0xFF), static_cast<uint8_t>(key & 0xFF)
            };
            return calculate(key_bytes.data(), key_bytes.size(), data, data_len);
        }

        inline std::array<uint8_t, HASH_SIZE> calculate(uint32_t key, const std::string& s) {
            return calculate(key, reinterpret_cast<const uint8_t*>(s.data()), s.length());
        }

        inline std::array<uint8_t, HASH_SIZE> calculate(uint32_t key, const char* s) {
            return calculate(key, reinterpret_cast<const uint8_t*>(s), std::strlen(s));
        }

    }

    template <std::size_t N>
    class EncryptedString {
    private:

        static constexpr uint32_t k = c_hash(__DATE__) ^ c_hash(__TIME__) ^ ENCRYPT_SALT ^ UNIQUE_KEY;
        static constexpr uint8_t k_byte = static_cast<uint8_t>(k & 0xFF);
        static constexpr uint16_t k_mask = static_cast<uint16_t>(k & 0xFFFF);
        static constexpr uint16_t offset = 0xABCD;
        static constexpr std::size_t pad_before = (prng(k) % 5) + 1;
        static constexpr std::size_t pad_after  = (prng(k + 1u) % 5) + 1;
        static constexpr std::size_t plain_length = N - 1;
        static constexpr std::size_t encrypted_core_length = plain_length * 2;
        static constexpr std::size_t encrypted_data_size = 4 + pad_before + encrypted_core_length + pad_after;
        static constexpr size_t HASH_SIZE = HmacSha256::HASH_SIZE;

        std::array<uint8_t, encrypted_data_size> encrypted_data;
        std::array<uint8_t, HASH_SIZE> stored_hmac;

        static consteval std::array<uint8_t, encrypted_data_size> encrypt(const char (&str)[N]) {
            std::array<uint8_t, encrypted_data_size> out = {};
            std::size_t index = 0;
            
            uint16_t obf_length = static_cast<uint16_t>(plain_length) ^ k_mask;
            out[index++] = static_cast<uint8_t>(obf_length & 0xFF);
            out[index++] = static_cast<uint8_t>((obf_length >> 8) & 0xFF);
            out[index++] = static_cast<uint8_t>(pad_before);
            out[index++] = static_cast<uint8_t>(pad_after);
            
            uint32_t seed1 = k; for (std::size_t i = 0; i < pad_before; i++) { seed1=prng(seed1); out[index++] = static_cast<uint8_t>(seed1 & 0xFF); }
            
            for (std::size_t i = 0; i < plain_length; i++) {
                uint16_t val = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
                bool variant_flag = (((k >> (i % 3)) & 1u) != 0);
                uint16_t enc = (variant_flag) ? ((val ^ k_byte) + offset + static_cast<uint16_t>(i) + 13)
                    : ((val ^ k_byte) + offset + static_cast<uint16_t>(i));
                out[index++] = static_cast<uint8_t>(enc & 0xFF); out[index++] = static_cast<uint8_t>((enc >> 8) & 0xFF);
            }
            
            uint32_t seed2 = k + 1u; for (std::size_t i = 0; i < pad_after; i++) { seed2=prng(seed2); out[index++] = static_cast<uint8_t>(seed2 & 0xFF); }
            if (index != encrypted_data_size) throw std::runtime_error("Encrypt size mismatch");
            
            return out;
        }

        static consteval std::array<uint8_t, HASH_SIZE> compute_hmac(const char (&str)[N]) {
            std::array<uint8_t, N - 1> str_bytes{};
            for (size_t i = 0; i < N - 1; ++i) {
                str_bytes[i] = static_cast<uint8_t>(str[i]);
            }

            return HmacSha256::calculate(k, str_bytes.data(), N - 1);
        }

        FORCE_INLINE char decrypt_char_at(std::size_t i) const {
            std::size_t data_index = 4 + pad_before + (i * 2);
            if (data_index + 1 >= encrypted_data_size) throw std::out_of_range("Decrypt index out of bounds");
            uint16_t enc = static_cast<uint16_t>(encrypted_data[data_index]) | (static_cast<uint16_t>(encrypted_data[data_index + 1]) << 8);
            bool variant_flag = (((k >> (i % 3)) & 1u) != 0);
            uint16_t val = (variant_flag) ? ((enc - offset - static_cast<uint16_t>(i) - 13) ^ k_byte)
                : ((enc - offset - static_cast<uint16_t>(i)) ^ k_byte);
            return static_cast<char>(val & 0xFF);
        }

    public:
        consteval EncryptedString(const char (&str)[N])
            : encrypted_data(encrypt(str)), stored_hmac(compute_hmac(str))
        {}

        std::string get() const {
            uint16_t obf_length = static_cast<uint16_t>(encrypted_data[0]) | (static_cast<uint16_t>(encrypted_data[1]) << 8);
            uint16_t current_plain_length = obf_length ^ k_mask;
            if (current_plain_length != plain_length) throw std::runtime_error("Length mismatch in get()");

            std::vector<char> temp_buffer(current_plain_length);
            bool locked = lock_mem(temp_buffer.data(), current_plain_length);
            try {
                for (std::size_t i = 0; i < current_plain_length; i++) {
                    temp_buffer[i] = decrypt_char_at(i);
                }
            } catch(...) {
                secure_memzero(temp_buffer.data(), current_plain_length);
                if (locked) unlock_mem(temp_buffer.data(), current_plain_length);
                throw;
            }

            std::string result(temp_buffer.data(), current_plain_length);
            secure_memzero(temp_buffer.data(), current_plain_length);
            if (locked) unlock_mem(temp_buffer.data(), current_plain_length);
            return result;
        }

        bool compare(const std::string & s) const {
            std::array<uint8_t, HASH_SIZE> input_hmac = HmacSha256::calculate(k, s);
            bool result = ct_compare(input_hmac.data(), stored_hmac.data(), HASH_SIZE);
            secure_memzero(input_hmac.data(), HASH_SIZE);
            return result;
        }

        bool compare(const char* s) const {
            if (!s) return false;
            std::array<uint8_t, HASH_SIZE> input_hmac = HmacSha256::calculate(k, s);
            bool result = ct_compare(input_hmac.data(), stored_hmac.data(), HASH_SIZE);
            secure_memzero(input_hmac.data(), HASH_SIZE);
            return result;
        }

        bool operator==(const std::string& other) const { return compare(other); }
        bool operator==(const char* other) const { return compare(other); }
        bool operator!=(const std::string& other) const { return !compare(other); }
        bool operator!=(const char* other) const { return !compare(other); }

    };

} // namespace StrEncryption

  // --- Macro utilisateur ---
#define XORSTR(str) ([]() consteval { return StrEncryption::EncryptedString<sizeof(str)>(str); }())

#endif // XORSTR_HPP
