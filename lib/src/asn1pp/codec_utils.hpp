/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_CODEC_UTILS_HPP_
#define __ASN1PP_CODEC_UTILS_HPP_

#include <cctype>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <asn1pp/asn1_errors.hpp>

namespace asn1pp::detail
{

    inline std::string
    error_text (const char* prefix, const std::string& message)
    {
        return std::string (prefix) + message;
    }

    inline void
    append_base128 (std::vector < uint8_t >& out, uint64_t value)
    {
        uint8_t octets[10];
        size_t count = 0;
        do
        {
            octets[count++] = static_cast < uint8_t > (value & 0x7Fu);
            value >>= 7;
        } while (value != 0);
        while (count != 0)
        {
            uint8_t octet = octets[--count];
            if (count != 0)
            {
                octet |= 0x80u;
            }
            out.push_back (octet);
        }
    }

    inline uint64_t
    read_base128 (std::span < const uint8_t > bytes, size_t& pos)
    {
        uint64_t value = 0;
        bool first = true;
        while (true)
        {
            if (pos >= bytes.size ())
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::TRUNCATED_INPUT, pos, "Truncated base-128 value");
            }
            uint8_t octet = bytes[pos++];
            if (first && octet == 0x80u)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::NON_CANONICAL_DER, pos - 1, "Non-minimal base-128 value");
            }
            first = false;
            if (value > (std::numeric_limits < uint64_t >::max () >> 7))
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, pos - 1, "Base-128 value overflows uint64_t");
            }
            value = (value << 7) | (octet & 0x7Fu);
            if ((octet & 0x80u) == 0)
            {
                return value;
            }
        }
    }

    inline bool
    leap (int year)
    {
        return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    }

    inline int
    month_days (int year, int month)
    {
        static constexpr int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        return month == 2 ? days[1] + (leap (year) ? 1 : 0) : (month >= 1 && month <= 12 ? days[month - 1] : 0);
    }

    inline int
    number (std::string_view value, size_t pos, size_t count)
    {
        int result = 0;
        for (size_t i = 0; i < count; ++i)
        {
            unsigned char c = value[pos + i];
            if (!std::isdigit (c))
            {
                return -1;
            }
            result = result * 10 + c - '0';
        }
        return result;
    }

} // asn1pp::detail

#endif // __ASN1PP_CODEC_UTILS_HPP_
