/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef __ASN1PP_IMPLICIT_TAGGED_HPP_
#define __ASN1PP_IMPLICIT_TAGGED_HPP_

#include <ostream>
#include <utility>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    /**
     * @brief ASN.1 value whose natural identifier is replaced by an implicit tag.
     * @tparam T Wrapped ASN.1 object type.
     * @tparam EffectiveTag Identifier emitted on the wire.
     * @tparam NaturalTag Original identifier expected by the wrapped object.
     */
    template < typename T, ASN1_Tag EffectiveTag, ASN1_Tag NaturalTag >
    class Implicit_Tagged : public ASN1_Object
    {
        static_assert (EffectiveTag.constructed == NaturalTag.constructed,
                       "IMPLICIT tagging must preserve primitive or constructed form");

    public:
        static constexpr ASN1_Tag effective_tag = EffectiveTag;
        static constexpr ASN1_Tag natural_tag = NaturalTag;

        Implicit_Tagged () = default;
        explicit Implicit_Tagged (const T& value) : _value (value) {}
        explicit Implicit_Tagged (T&& value) : _value (std::move (value)) {}

        [[nodiscard]] const T& value () const noexcept { return _value; }
        [[nodiscard]] T& value () noexcept { return _value; }

        void assign (const T& value) { _value = value; }
        void assign (T&& value) { _value = std::move (value); }

        void encode_into (DER_Encoder& to) const override
        {
            to.encode_implicit (_value, EffectiveTag, NaturalTag);
        }

        void decode_from (BER_Decoder& from) override
        {
            T result;
            from.decode_implicit (result, EffectiveTag, NaturalTag);
            _value = std::move (result);
        }

        bool operator== (const Implicit_Tagged& other) const
        {
            return _value == other._value;
        }

        friend std::ostream& operator<< (std::ostream& stream, const Implicit_Tagged& value)
        {
            return stream << value._value;
        }

    private:
        T _value;
    };

} // asn1pp

#endif // __ASN1PP_IMPLICIT_TAGGED_HPP_
