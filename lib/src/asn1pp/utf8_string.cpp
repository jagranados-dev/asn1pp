/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/utf8_string.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    UTF8_String::validate (std::string_view s)
    {
        size_t i = 0;
        while (i < s.size ())
        {
            uint8_t c = static_cast < uint8_t > (s[i++]);
            uint32_t cp;
            size_t n;
            if (c < 0x80)
            {
                continue;
            }
            if (c >= 0xC2 && c <= 0xDF)
            {
                cp = c & 0x1F;
                n = 1;
            }
            else if (c >= 0xE0 && c <= 0xEF)
            {
                cp = c & 0x0F;
                n = 2;
            }
            else if (c >= 0xF0 && c <= 0xF4)
            {
                cp = c & 7;
                n = 3;
            }
            else
            {
                throw ASN1_InvalidArgument ("Invalid UTF-8 leading octet");
            }
            if (n > s.size () - i)
            {
                throw ASN1_InvalidArgument ("Truncated UTF-8 sequence");
            }
            for (size_t j = 0; j < n; ++j)
            {
                uint8_t d = static_cast < uint8_t > (s[i++]);
                if ((d & 0xC0u) != 0x80u)
                {
                    throw ASN1_InvalidArgument ("Invalid UTF-8 continuation octet");
                }
                cp = (cp << 6) | (d & 0x3Fu);
            }
            if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            {
                throw ASN1_InvalidArgument ("Invalid UTF-8 scalar value");
            }
        }
    }

    UTF8_String::UTF8_String (std::string_view v)
    {
        assign (v);
    }

    const std::string&
    UTF8_String::value () const noexcept
    {
        return _value;
    }

    void
    UTF8_String::assign (std::string_view v)
    {
        validate (v);
        _value = v;
    }

    void
    UTF8_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value);
    }
    
    void
    UTF8_String::decode_from (BER_Decoder& from)
    {
        std::string v;
        from.decode (v);
        assign (v);
    }

    bool
    UTF8_String::operator== (const UTF8_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const UTF8_String& value)
    {
        stream << value._value;
        return stream;
    }

} // asn1pp
