/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_CONSTRAINTS_HPP
#define ASN1PP_CONSTRAINTS_HPP

#include <cstddef>
#include <span>

#include <asn1pp/asn1_errors.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/octet_string.hpp>

namespace asn1pp
{

    /**
     * @brief OCTET STRING that enforces a compile-time ASN.1 SIZE constraint.
     * @tparam Minimum Minimum permitted number of octets.
     * @tparam Maximum Maximum permitted number of octets.
     */
    template < size_t Minimum, size_t Maximum >
    class Sized_Octet_String : public Octet_String
    {
        static_assert (Minimum <= Maximum, "Invalid ASN.1 SIZE constraint");

    public:
        /** @brief Creates an empty value when permitted by the constraint. */
        Sized_Octet_String () = default;

        /** @brief Creates and validates a constrained OCTET STRING. */
        explicit Sized_Octet_String (std::span < const uint8_t > value) : Octet_String (value)
        {
            validate_size (value.size ());
        }

        /** @brief Replaces and validates the constrained OCTET STRING. */
        void assign (std::span < const uint8_t > value)
        {
            validate_size (value.size ());
            Octet_String::assign (value);
        }

        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override
        {
            validate_size (value ().size ());
            Octet_String::encode_into (to);
        }

        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override
        {
            Octet_String result;
            from.decode (result);
            validate_size (result.value ().size ());
            Octet_String::assign (result.value ());
        }

    private:
        static void validate_size (size_t size)
        {
            if (size < Minimum || size > Maximum)
            {
                throw ASN1_InvalidArgument ("OCTET STRING violates its ASN.1 SIZE constraint");
            }
        }
    };

} // asn1pp

#endif // ASN1PP_CONSTRAINTS_HPP
