/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/bit_string.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    Bit_String::Bit_String () : _unused_bits (0)
    {}

    Bit_String::Bit_String (std::span < const uint8_t > b, uint8_t u)
    {
        assign (b, u);
    }

    const std::vector < uint8_t >&
    Bit_String::bytes () const noexcept
    {
        return _bytes;
    }

    uint8_t
    Bit_String::unused_bits () const noexcept
    {
        return _unused_bits;
    }

    size_t
    Bit_String::bit_count () const noexcept
    {
        return _bytes.size () * 8 - _unused_bits;
    }

    void
    Bit_String::validate () const
    {
        if (_unused_bits > 7 || (_bytes.empty () && _unused_bits) ||
            (!_bytes.empty () && _unused_bits && (_bytes.back () & ((1u << _unused_bits) - 1u))))
        {
            throw ASN1_InvalidArgument ("Invalid BIT STRING unused bits");
        }
    }

    void
    Bit_String::assign (std::span < const uint8_t > b, uint8_t u)
    {
        _bytes.assign (b.begin (), b.end ());
        _unused_bits = u;
        validate ();
    }

    void
    Bit_String::encode_into (DER_Encoder& to) const
    {
        validate ();
        std::vector < uint8_t > v{_unused_bits};
        v.insert (v.end (), _bytes.begin (), _bytes.end ());
        to.encode (v, ASN1_Type::BIT_STRING);
    }

    void
    Bit_String::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > value;
        uint8_t unused_bits = 0;
        from.decode_bit_string (value, unused_bits);
        assign (value, unused_bits);
    }
    
    bool
    Bit_String::operator== (const Bit_String& other) const noexcept
    {
        return _bytes == other._bytes && _unused_bits == other._unused_bits;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Bit_String& value)
    {
        stream << '\'';
        for (size_t index = 0; index < value.bit_count (); ++index)
        {
            stream << ((value._bytes[index / 8] & (0x80u >> (index % 8))) ? '1' : '0');
        }
        stream << "'B";
        return stream;
    }

} // asn1pp
