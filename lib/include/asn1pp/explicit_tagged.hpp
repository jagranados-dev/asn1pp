/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_EXPLICIT_TAGGED_HPP_
#define __ASN1PP_EXPLICIT_TAGGED_HPP_

#include <ostream>
#include <utility>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    /** @brief ASN.1 value wrapped by an explicit constructed identifier. */
    template < typename T, ASN1_Tag Tag >
    class Explicit_Tagged : public ASN1_Object
    {
        static_assert (Tag.constructed, "An EXPLICIT tag must use constructed form");

    public:
        static constexpr ASN1_Tag effective_tag = Tag;

        Explicit_Tagged () = default;
        explicit Explicit_Tagged (const T& value) : _value (value) {}
        explicit Explicit_Tagged (T&& value) : _value (std::move (value)) {}

        [[nodiscard]] const T& value () const noexcept { return _value; }
        [[nodiscard]] T& value () noexcept { return _value; }

        void assign (const T& value) { _value = value; }
        void assign (T&& value) { _value = std::move (value); }

        void encode_into (DER_Encoder& to) const override
        {
            to.encode_constructed (Tag, false, [&] (DER_Encoder& child)
            {
                child.encode (_value);
            });
        }

        void decode_from (BER_Decoder& from) override
        {
            T result;
            from.decode_constructed (Tag, [&] (BER_Decoder& child)
            {
                child.decode (result);
            });
            _value = std::move (result);
        }

        bool operator== (const Explicit_Tagged& other) const
        {
            return _value == other._value;
        }

        friend std::ostream& operator<< (std::ostream& stream, const Explicit_Tagged& value)
        {
            return stream << value._value;
        }

    private:
        T _value;
    };

} // asn1pp

#endif // __ASN1PP_EXPLICIT_TAGGED_HPP_
