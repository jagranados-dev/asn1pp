/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/octet_string.hpp>

#include <ostream>

#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    Octet_String::Octet_String (std::span < const uint8_t > v)
    {
        assign (v);
    }

    const std::vector < uint8_t >&
    Octet_String::value () const noexcept
    {
        return _value;
    }

    void
    Octet_String::assign (std::span < const uint8_t > v)
    {
        _value.assign (v.begin (), v.end ());
    }

    void
    Octet_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value);
    }

    void
    Octet_String::decode_from (BER_Decoder& from)
    {
        from.decode_string_bytes (_value);
    }
    
    bool
    Octet_String::operator== (const Octet_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Octet_String& value)
    {
        static constexpr char digits[] = "0123456789ABCDEF";
        for (uint8_t octet : value._value)
        {
            stream << digits[octet >> 4] << digits[octet & 0x0Fu];
        }
        return stream;
    }

} // asn1pp
