/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/asn1_time.hpp>

#include <ostream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

#include "codec_utils.hpp"

namespace asn1pp
{

    using detail::month_days;
    using detail::number;

    ASN1_Time::ASN1_Time () : _type (ASN1_TimeType::UTC), _value ("700101000000Z")
    {}

    ASN1_Time::ASN1_Time (ASN1_TimeType t, std::string_view v)
    {
        assign (t, v);
    }

    ASN1_TimeType
    ASN1_Time::type () const noexcept
    {
        return _type;
    }

    const std::string&
    ASN1_Time::value () const noexcept
    {
        return _value;
    }

    void
    ASN1_Time::validate (ASN1_TimeType t, std::string_view v)
    {
        size_t yd = t == ASN1_TimeType::UTC ? 2 : 4;
        if (v.size () != yd + 11 || v.back () != 'Z')
        {
            throw ASN1_InvalidArgument ("Time must use canonical DER form with seconds and Z");
        }
        int y = number (v, 0, yd);
        if (y < 0)
        {
            throw ASN1_InvalidArgument ("Invalid year");
        }
        if (t == ASN1_TimeType::UTC)
        {
            y += y >= 50 ? 1900 : 2000;
        }
        int m = number (v, yd, 2), d = number (v, yd + 2, 2), h = number (v, yd + 4, 2), n = number (v, yd + 6, 2),
            s = number (v, yd + 8, 2);
        if (m < 1 || m > 12 || d < 1 || d > month_days (y, m) || h < 0 || h > 23 || n < 0 || n > 59 || s < 0 || s > 59)
        {
            throw ASN1_InvalidArgument ("Invalid calendar time");
        }
    }

    void
    ASN1_Time::assign (ASN1_TimeType t, std::string_view v)
    {
        validate (t, v);
        _type = t;
        _value = v;
    }

    void
    ASN1_Time::encode_into (DER_Encoder& to) const
    {
        to.encode (_value, _type == ASN1_TimeType::UTC ? ASN1_Type::UTC_TIME : ASN1_Type::GENERALIZED_TIME);
    }

    void
    ASN1_Time::decode_from (BER_Decoder& from)
    {
        auto h = from.peek_next_header ();
        if (!h || h->tag.tag_class != ASN1_TagClass::UNIVERSAL)
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TAG_MISMATCH, 0, "Expected time");
        }
        ASN1_TimeType t;
        ASN1_Type tag;
        if (h->tag.number == 23)
        {
            t = ASN1_TimeType::UTC;
            tag = ASN1_Type::UTC_TIME;
        }
        else if (h->tag.number == 24)
        {
            t = ASN1_TimeType::GENERALIZED;
            tag = ASN1_Type::GENERALIZED_TIME;
        }
        else
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::TAG_MISMATCH, 0, "Expected UTCTime or GeneralizedTime");
        }
        std::string v;
        from.decode (v, tag);
        assign (t, v);
    }
    
    bool
    ASN1_Time::operator== (const ASN1_Time& other) const noexcept
    {
        return _type == other._type && _value == other._value;
    }

    std::ostream&
    operator<< (std::ostream& stream, const ASN1_Time& value)
    {
        stream << value._value;
        return stream;
    }

} // asn1pp
