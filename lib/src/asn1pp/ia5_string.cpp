/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/ia5_string.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    IA5_String::validate (std::string_view v)
    {
        for (unsigned char c : v)
        {
            if (c > 0x7F)
            {
                throw ASN1_InvalidArgument ("IA5String contains a non-ASCII octet");
            }
        }
    }

    IA5_String::IA5_String (std::string_view v)
    {
        assign (v);
    }

    const std::string&
    IA5_String::value () const noexcept
    {
        return _value;
    }

    void
    IA5_String::assign (std::string_view v)
    {
        validate (v);
        _value = v;
    }

    void
    IA5_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, ASN1_Type::IA5_STRING);
    }
    
    void
    IA5_String::decode_from (BER_Decoder& from)
    {
        std::string v;
        from.decode (v, ASN1_Type::IA5_STRING);
        assign (v);
    }

    bool
    IA5_String::operator== (const IA5_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const IA5_String& value)
    {
        stream << value._value;
        return stream;
    }

} // asn1pp
