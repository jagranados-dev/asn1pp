/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/oid.hpp>

#include <ostream>

#include <cctype>
#include <limits>
#include <sstream>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

#include "codec_utils.hpp"

namespace asn1pp
{

    using detail::append_base128;
    using detail::read_base128;

    OID::OID (std::vector < uint64_t > v)
    {
        assign (std::move (v));
    }

    OID::OID (std::string_view v)
    {
        assign (v);
    }

    const std::vector < uint64_t >&
    OID::arcs () const noexcept
    {
        return _arcs;
    }

    void
    OID::validate (const std::vector < uint64_t >& a)
    {
        if (a.size () < 2 || a[0] > 2 || (a[0] < 2 && a[1] > 39))
        {
            throw ASN1_InvalidArgument ("Invalid OID root arcs");
        }
    }

    void
    OID::assign (std::vector < uint64_t > a)
    {
        validate (a);
        _arcs = std::move (a);
    }

    void
    OID::assign (std::string_view s)
    {
        std::vector < uint64_t > a;
        size_t start = 0;
        while (start < s.size ())
        {
            size_t end = s.find ('.', start);
            if (end == std::string_view::npos)
            {
                end = s.size ();
            }
            if (end == start)
            {
                throw ASN1_InvalidArgument ("Empty OID arc");
            }
            uint64_t n = 0;
            for (size_t i = start; i < end; ++i)
            {
                if (!std::isdigit (static_cast < unsigned char > (s[i])))
                {
                    throw ASN1_InvalidArgument ("Invalid OID arc");
                }
                unsigned d = s[i] - '0';
                if (n > (UINT64_MAX - d) / 10)
                {
                    throw ASN1_InvalidArgument ("OID arc overflow");
                }
                n = n * 10 + d;
            }
            a.push_back (n);
            start = end + 1;
        }
        assign (std::move (a));
    }

    std::string
    OID::to_string () const
    {
        std::ostringstream out;
        for (size_t i = 0; i < _arcs.size (); ++i)
        {
            if (i)
            {
                out << '.';
            }
            out << _arcs[i];
        }
        return out.str ();
    }

    void
    OID::encode_into (DER_Encoder& to) const
    {
        validate (_arcs);
        if (_arcs[0] == 2 && _arcs[1] > UINT64_MAX - 80)
        {
            throw ASN1_EncodingError (ASN1_ErrorCode::INVALID_VALUE, "OID first subidentifier overflow");
        }
        std::vector < uint8_t > v;
        append_base128 (v, _arcs[0] * 40 + _arcs[1]);
        for (size_t i = 2; i < _arcs.size (); ++i)
        {
            append_base128 (v, _arcs[i]);
        }
        to.encode (v, ASN1_Type::OBJECT_ID);
    }

    void
    OID::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > v;
        from.decode (v, ASN1_Type::OBJECT_ID);
        if (v.empty ())
        {
            throw ASN1_DecodingError (ASN1_ErrorCode::INVALID_VALUE, 0, "OID cannot be empty");
        }
        size_t pos = 0;
        uint64_t first = read_base128 (v, pos);
        std::vector < uint64_t > a;
        if (first < 40)
        {
            a = {0, first};
        }
        else if (first < 80)
        {
            a = {1, first - 40};
        }
        else
        {
            a = {2, first - 80};
        }
        while (pos < v.size ())
        {
            if (a.size () >= 4096)
            {
                throw ASN1_DecodingError (ASN1_ErrorCode::LIMIT_EXCEEDED, pos, "OID has too many arcs");
            }
            a.push_back (read_base128 (v, pos));
        }
        _arcs = std::move (a);
    }
    
    bool
    OID::operator== (const OID& other) const noexcept
    {
        return _arcs == other._arcs;
    }

    std::ostream&
    operator<< (std::ostream& stream, const OID& value)
    {
        stream << value.to_string ();
        return stream;
    }

} // asn1pp
