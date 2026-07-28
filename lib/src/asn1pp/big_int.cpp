/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/big_int.hpp>

#include <ostream>

#include <algorithm>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    std::vector < uint8_t >
    Big_Int::canonicalize (std::span < const uint8_t > v)
    {
        if (v.empty ())
        {
            throw ASN1_InvalidArgument ("Big_Int cannot be empty");
        }
        size_t i = 0;
        while (i + 1 < v.size () &&
               ((v[i] == 0 && (v[i + 1] & 0x80u) == 0) || (v[i] == 0xFFu && (v[i + 1] & 0x80u) != 0)))
        {
            ++i;
        }
        return {v.begin () + i, v.end ()};
    }

    Big_Int::Big_Int () : _bytes{0}
    {}

    Big_Int::Big_Int (int64_t v)
    {
        uint64_t bits = static_cast < uint64_t > (v);
        uint8_t b[8];
        for (size_t i = 0; i < 8; ++i)
        {
            b[7 - i] = bits & 0xFFu;
            bits >>= 8;
        }
        _bytes = canonicalize (b);
    }

    Big_Int::Big_Int (std::string_view v)
    {
        set_decimal (v);
    }

    const std::vector < uint8_t >&
    Big_Int::bytes () const noexcept
    {
        return _bytes;
    }

    bool
    Big_Int::negative () const noexcept
    {
        return _bytes[0] & 0x80u;
    }

    void
    Big_Int::set_bytes (std::span < const uint8_t > v)
    {
        _bytes = canonicalize (v);
    }

    void
    Big_Int::set_decimal (std::string_view s)
    {
        bool neg = !s.empty () && s.front () == '-';
        if (neg)
        {
            s.remove_prefix (1);
        }
        if (s.empty ())
        {
            throw ASN1_InvalidArgument ("Invalid decimal integer");
        }
        std::vector < uint8_t > mag (1, 0);
        for (char c : s)
        {
            if (c < '0' || c > '9')
            {
                throw ASN1_InvalidArgument ("Invalid decimal integer");
            }
            unsigned carry = c - '0';
            for (auto i = mag.rbegin (); i != mag.rend (); ++i)
            {
                unsigned x = *i * 10u + carry;
                *i = x & 0xFFu;
                carry = x >> 8;
            }
            if (carry)
            {
                mag.insert (mag.begin (), (uint8_t) carry);
            }
        }
        while (mag.size () > 1 && mag[0] == 0)
        {
            mag.erase (mag.begin ());
        }
        if (mag.size () == 1 && mag[0] == 0)
        {
            _bytes = {0};
            return;
        }
        if (!neg)
        {
            if (mag[0] & 0x80u)
            {
                mag.insert (mag.begin (), 0);
            }
            _bytes = std::move (mag);
            return;
        }
        for (auto& b : mag)
        {
            b = ~b;
        }
        unsigned carry = 1;
        for (auto i = mag.rbegin (); i != mag.rend () && carry; ++i)
        {
            unsigned x = *i + carry;
            *i = x & 0xFFu;
            carry = x >> 8;
        }
        if ((mag[0] & 0x80u) == 0)
        {
            mag.insert (mag.begin (), 0xFFu);
        }
        _bytes = canonicalize (mag);
    }

    std::string
    Big_Int::to_decimal () const
    {
        bool neg = negative ();
        auto mag = _bytes;
        if (neg)
        {
            for (auto& b : mag)
            {
                b = ~b;
            }
            unsigned c = 1;
            for (auto i = mag.rbegin (); i != mag.rend () && c; ++i)
            {
                unsigned x = *i + c;
                *i = x & 0xFFu;
                c = x >> 8;
            }
        }
        while (mag.size () > 1 && mag[0] == 0)
        {
            mag.erase (mag.begin ());
        }
        std::string out;
        while (!(mag.size () == 1 && mag[0] == 0))
        {
            unsigned r = 0;
            for (auto& b : mag)
            {
                unsigned x = (r << 8) | b;
                b = static_cast < uint8_t > ( x / 10 );
                r = x % 10;
            }
            out.push_back ('0' + (uint8_t) r);
            while (mag.size () > 1 && mag[0] == 0)
            {
                mag.erase (mag.begin ());
            }
        }
        if (out.empty ())
        {
            out = "0";
        }
        else
        {
            std::reverse (out.begin (), out.end ());
        }
        if (neg)
        {
            out.insert (out.begin (), '-');
        }
        return out;
    }

    void
    Big_Int::encode_into (DER_Encoder& to) const
    {
        to.encode (_bytes, ASN1_Type::INTEGER);
    }

    void
    Big_Int::decode_from (BER_Decoder& from)
    {
        std::vector < uint8_t > b;
        from.decode (b, ASN1_Type::INTEGER);
        _bytes = canonicalize (b);
    }
    
    bool
    Big_Int::operator== (const Big_Int& other) const noexcept
    {
        return _bytes == other._bytes;
    }

    std::ostream&
    operator<< (std::ostream& stream, const Big_Int& value)
    {
        stream << value.to_decimal ();
        return stream;
    }

} // asn1pp
