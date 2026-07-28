/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/printable_string.hpp>

#include <ostream>

#include <cctype>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    void
    Printable_String::validate (std::string_view v)
    {
        static const std::string allowed = " '()+,-./:=?";
        for (unsigned char c : v)
        {
            if (!std::isalnum (c) && allowed.find (c) == std::string::npos)
            {
                throw ASN1_InvalidArgument ("PrintableString contains a forbidden character");
            }
        }
    }

    Printable_String::Printable_String (std::string_view v)
    {
        assign (v);
    }

    const std::string&
    Printable_String::value () const noexcept
    {
        return _value;
    }

    void
    Printable_String::assign (std::string_view v)
    {
        validate (v);
        _value = v;
    }

    void
    Printable_String::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, ASN1_Type::PRINTABLE_STRING);
    }

    void
    Printable_String::decode_from (BER_Decoder& from)
    {
        std::string v;
        from.decode (v, ASN1_Type::PRINTABLE_STRING);
        assign (v);
    }
    
    bool
    Printable_String::operator== (const Printable_String& other) const noexcept
    {
        return _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Printable_String& value)
    {
        stream << value._value;
        return stream;
    }

} // asn1pp
