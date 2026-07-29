/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/character_strings.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    namespace
    {

        void
        stream_hex (std::ostream& stream, std::span < const uint8_t > value)
        {
            static constexpr char digits[] = "0123456789ABCDEF";
            for (uint8_t octet : value)
            {
                stream << digits[octet >> 4] << digits[octet & 0x0Fu];
            }
        }

    } // namespace

    Teletex_String::Teletex_String (std::span < const uint8_t > value)
    {
        assign (value);
    }

    const std::vector < uint8_t >&
    Teletex_String::value () const noexcept
    {
        return _value;
    }

    void
    Teletex_String::assign (std::span < const uint8_t > value)
    {
        _value.assign (value.begin (), value.end ());
    }

    void
    Teletex_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, ASN1_Type::TELETEX_STRING);
    }

    void
    Teletex_String::decode_from (BER_Decoder& from)
    {
        from.decode_string_bytes (_value, ASN1_Type::TELETEX_STRING);
    }

    bool
    Teletex_String::operator== (const Teletex_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Teletex_String& value)
    {
        stream_hex (stream, value._value);
        return stream;
    }

    BMP_String::BMP_String (std::span < const uint8_t > value)
    {
        assign (value);
    }

    const std::vector < uint8_t >&
    BMP_String::value () const noexcept
    {
        return _value;
    }

    void
    BMP_String::validate (std::span < const uint8_t > value)
    {
        if (value.size () % 2 != 0)
        {
            throw ASN1_InvalidArgument ("BMPString must contain complete two-octet code units");
        }
        for (size_t offset = 0; offset < value.size (); offset += 2)
        {
            const uint16_t code = static_cast < uint16_t > ((value[offset] << 8) | value[offset + 1]);
            if (code >= 0xD800u && code <= 0xDFFFu)
            {
                throw ASN1_InvalidArgument ("BMPString cannot contain surrogate code points");
            }
        }
    }

    void
    BMP_String::assign (std::span < const uint8_t > value)
    {
        validate (value);
        _value.assign (value.begin (), value.end ());
    }

    void
    BMP_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, ASN1_Type::BMP_STRING);
    }

    void
    BMP_String::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > value;
        from.decode_string_bytes (value, ASN1_Type::BMP_STRING);
        assign (value);
    }

    bool
    BMP_String::operator== (const BMP_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const BMP_String& value)
    {
        stream_hex (stream, value._value);
        return stream;
    }

    Universal_String::Universal_String (std::span < const uint8_t > value)
    {
        assign (value);
    }

    const std::vector < uint8_t >&
    Universal_String::value () const noexcept
    {
        return _value;
    }

    void
    Universal_String::validate (std::span < const uint8_t > value)
    {
        if (value.size () % 4 != 0)
        {
            throw ASN1_InvalidArgument ("UniversalString must contain complete four-octet code units");
        }
        for (size_t offset = 0; offset < value.size (); offset += 4)
        {
            const uint32_t code = (static_cast < uint32_t > (value[offset]) << 24) |
                                  (static_cast < uint32_t > (value[offset + 1]) << 16) |
                                  (static_cast < uint32_t > (value[offset + 2]) << 8) | value[offset + 3];
            if (code > 0x10FFFFu || (code >= 0xD800u && code <= 0xDFFFu))
            {
                throw ASN1_InvalidArgument ("UniversalString contains an invalid Unicode scalar value");
            }
        }
    }

    void
    Universal_String::assign (std::span < const uint8_t > value)
    {
        validate (value);
        _value.assign (value.begin (), value.end ());
    }

    void
    Universal_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, ASN1_Type::UNIVERSAL_STRING);
    }

    void
    Universal_String::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > value;
        from.decode_string_bytes (value, ASN1_Type::UNIVERSAL_STRING);
        assign (value);
    }

    bool
    Universal_String::operator== (const Universal_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Universal_String& value)
    {
        stream_hex (stream, value._value);
        return stream;
    }

} // asn1pp
