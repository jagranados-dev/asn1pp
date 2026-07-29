/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_ENUMERATED_HPP
#define ASN1PP_ENUMERATED_HPP

#include <cstdint>
#include <ostream>
#include <type_traits>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>

namespace asn1pp
{

    /**
     * @brief Type-safe ASN.1 ENUMERATED value.
     * @tparam Enum C++ enumeration used by the application schema.
     *
     * Unknown numeric values are preserved by value. Applications that use a
     * closed enumeration can validate the value after decoding.
     */
    template < typename Enum >
    class Enumerated : public ASN1_Object
    {
        static_assert (std::is_enum_v < Enum >, "Enumerated requires a C++ enumeration type");
        static_assert (sizeof (std::underlying_type_t < Enum >) <= sizeof (int64_t),
                       "Enumerated supports enumeration storage up to 64 bits");

    public:
        /** @brief Creates an ENUMERATED value initialized to zero. */
        Enumerated () = default;

        /** @brief Creates an ENUMERATED value from a C++ enumeration. */
        explicit Enumerated (Enum value) : _value (static_cast < int64_t > (value))
        {}

        /** @brief Creates an ENUMERATED value from its numeric representation. */
        explicit Enumerated (int64_t value) : _value (value)
        {}

        /** @brief Returns the numeric ENUMERATED value. */
        [[nodiscard]] int64_t numeric_value () const noexcept
        {
            return _value;
        }

        /** @brief Returns the value converted to the application enumeration. */
        [[nodiscard]] Enum value () const noexcept
        {
            return static_cast < Enum > (_value);
        }

        /** @brief Assigns an application enumeration value. */
        void assign (Enum value) noexcept
        {
            _value = static_cast < int64_t > (value);
        }

        /** @brief Assigns a numeric value, including an unknown extension value. */
        void assign_numeric (int64_t value) noexcept
        {
            _value = value;
        }

        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override
        {
            to.encode (_value, ASN1_Type::ENUMERATED);
        }

        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override
        {
            int64_t value = 0;
            from.decode (value, ASN1_Type::ENUMERATED);
            _value = value;
        }

        /** @brief Compares two ENUMERATED values by their numeric value. */
        bool operator== (const Enumerated& other) const noexcept
        {
            return _value == other._value;
        }

        /** @brief Writes the numeric value to a stream. */
        friend std::ostream& operator<< (std::ostream& stream, const Enumerated& value)
        {
            return stream << value._value;
        }

    private:
        int64_t _value = 0;
    };

} // asn1pp

#endif // ASN1PP_ENUMERATED_HPP
