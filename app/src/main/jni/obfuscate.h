#include <cstddef>
#include <string>

#ifndef AY_OBFUSCATE_DEFAULT_KEY
#define AY_OBFUSCATE_DEFAULT_KEY ay::generate_key(__LINE__)
#endif

namespace ay
{
    using size_type = unsigned long long;
    using key_type = unsigned long long;

    template <std::size_t... Is>
    struct index_sequence {};

    template <std::size_t N, std::size_t... Is>
    struct make_index_sequence : make_index_sequence<N - 1, N - 1, Is...> {};

    template <std::size_t... Is>
    struct make_index_sequence<0, Is...> {
        using type = index_sequence<Is...>;
    };

    constexpr key_type generate_key_step5(key_type key)
    {
        return (key ^ (key >> 33)) | 0x0101010101010101ull;
    }

    constexpr key_type generate_key_step4(key_type key)
    {
        return generate_key_step5(key * 0xc4ceb9fe1a85ec53);
    }

    constexpr key_type generate_key_step3(key_type key)
    {
        return generate_key_step4(key ^ (key >> 33));
    }

    constexpr key_type generate_key_step2(key_type key)
    {
        return generate_key_step3(key * 0xff51afd7ed558ccd);
    }

    constexpr key_type generate_key(key_type seed)
    {
        return generate_key_step2(seed ^ (seed >> 33));
    }

    inline void cipher(char* data, size_type size, key_type key)
    {
        for (size_type i = 0; i < size; i++)
        {
            data[i] ^= static_cast<char>(key >> ((i % 8) * 8));
        }
    }

    constexpr char encrypt_char(char c, size_type i, key_type key)
    {
        return c ^ static_cast<char>(key >> ((i % 8) * 8));
    }

    template <size_type N, key_type KEY>
    class obfuscator
    {
    public:
        template <std::size_t... Is>
        constexpr obfuscator(const char* data, index_sequence<Is...>)
            : m_data{ encrypt_char(data[Is], Is, KEY)... }
        {}

        constexpr const char* data() const
        {
            return &m_data[0];
        }

        constexpr size_type size() const
        {
            return N;
        }

        constexpr key_type key() const
        {
            return KEY;
        }

    private:
        char m_data[N];
    };

    template <size_type N, key_type KEY>
    class obfuscated_data
    {
    public:
        obfuscated_data(const obfuscator<N, KEY>& obfuscator)
        {
            for (size_type i = 0; i < N; i++)
            {
                m_data[i] = obfuscator.data()[i];
            }
        }

        ~obfuscated_data()
        {
            for (size_type i = 0; i < N; i++)
            {
                m_data[i] = 0;
            }
        }

        operator char*()
        {
            decrypt();
            return m_data;
        }

        operator std::string()
        {
            decrypt();
            return m_data;
        }

        void decrypt()
        {
            if (m_encrypted)
            {
                cipher(m_data, N, KEY);
                m_encrypted = false;
            }
        }

        void encrypt()
        {
            if (!m_encrypted)
            {
                cipher(m_data, N, KEY);
                m_encrypted = true;
            }
        }

        bool is_encrypted() const
        {
            return m_encrypted;
        }

    private:
        char m_data[N];
        bool m_encrypted{ true };
    };

    template <size_type N, key_type KEY = AY_OBFUSCATE_DEFAULT_KEY>
    constexpr obfuscator<N, KEY> make_obfuscator(const char(&data)[N])
    {
        return obfuscator<N, KEY>(data, typename make_index_sequence<N>::type{});
    }
}

#define OBFUSCATE(data) OBFUSCATE_KEY(data, AY_OBFUSCATE_DEFAULT_KEY)

#define OBFUSCATE_KEY(data, key) \
    []() -> ay::obfuscated_data<sizeof(data)/sizeof(data[0]), key>& { \
        static_assert(sizeof(decltype(key)) == sizeof(ay::key_type), "key must be a 64 bit unsigned integer"); \
        static_assert((key) >= (1ull << 56), "key must span all 8 bytes"); \
        constexpr auto n = sizeof(data)/sizeof(data[0]); \
        constexpr auto obfuscator = ay::make_obfuscator<n, key>(data); \
        static auto obfuscated_data = ay::obfuscated_data<n, key>(obfuscator); \
        return obfuscated_data; \
    }()

