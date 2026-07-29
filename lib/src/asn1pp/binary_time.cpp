/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/binary_time.hpp>

#include <ostream>
#include <string>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    Binary_Time::Binary_Time (uint64_t seconds)
    {
        assign (std::to_string (seconds));
    }

    Binary_Time::Binary_Time (std::string_view seconds)
    {
        assign (seconds);
    }

    const Big_Int&
    Binary_Time::value () const noexcept
    {
        return _value;
    }

    void
    Binary_Time::validate (const Big_Int& value)
    {
        if (value.negative ())
        {
            throw ASN1_InvalidArgument ("BinaryTime cannot be negative");
        }
    }

    void
    Binary_Time::assign (std::string_view seconds)
    {
        Big_Int value (seconds);
        validate (value);
        _value = std::move (value);
    }

    void
    Binary_Time::encode_into (DER_Encoder& to) const
    {
        validate (_value);
        to.encode (_value);
    }

    void
    Binary_Time::decode_from (BER_Decoder& from)
    {
        Big_Int value;
        from.decode (value);
        validate (value);
        _value = std::move (value);
    }

    bool
    Binary_Time::operator== (const Binary_Time& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Binary_Time& value)
    {
        return stream << value._value.to_decimal ();
    }

} // asn1pp
