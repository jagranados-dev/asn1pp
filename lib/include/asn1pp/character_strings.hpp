/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_CHARACTER_STRINGS_HPP
#define ASN1PP_CHARACTER_STRINGS_HPP

#include <cstdint>
#include <ostream>
#include <span>
#include <vector>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp
{

    /** @brief ASN.1 TeletexString value preserving its encoded octets. */
    class Teletex_String : public ASN1_Object
    {
    public:
        /** @brief Creates an empty TeletexString. */
        Teletex_String () = default;
        /** @brief Creates a TeletexString from encoded T.61 octets. */
        explicit Teletex_String (std::span < const uint8_t > value);
        /** @brief Returns the encoded T.61 octets. */
        [[nodiscard]] const std::vector < uint8_t >& value () const noexcept;
        /** @brief Replaces the encoded T.61 octets. */
        void assign (std::span < const uint8_t > value);
        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares encoded character values. */
        bool operator== (const Teletex_String& other) const noexcept;
        /** @brief Writes the encoded value in hexadecimal notation. */
        friend std::ostream& operator<< (std::ostream& stream, const Teletex_String& value);

    private:
        std::vector < uint8_t > _value;
    };

    /** @brief ASN.1 BMPString value encoded as big-endian UCS-2 code units. */
    class BMP_String : public ASN1_Object
    {
    public:
        /** @brief Creates an empty BMPString. */
        BMP_String () = default;
        /** @brief Creates a BMPString from big-endian UCS-2 octets. */
        explicit BMP_String (std::span < const uint8_t > value);
        /** @brief Returns the big-endian UCS-2 octets. */
        [[nodiscard]] const std::vector < uint8_t >& value () const noexcept;
        /** @brief Replaces and validates the big-endian UCS-2 octets. */
        void assign (std::span < const uint8_t > value);
        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares encoded character values. */
        bool operator== (const BMP_String& other) const noexcept;
        /** @brief Writes the encoded value in hexadecimal notation. */
        friend std::ostream& operator<< (std::ostream& stream, const BMP_String& value);

    private:
        static void validate (std::span < const uint8_t > value);
        std::vector < uint8_t > _value;
    };

    /** @brief ASN.1 UniversalString value encoded as big-endian UCS-4 scalar values. */
    class Universal_String : public ASN1_Object
    {
    public:
        /** @brief Creates an empty UniversalString. */
        Universal_String () = default;
        /** @brief Creates a UniversalString from big-endian UCS-4 octets. */
        explicit Universal_String (std::span < const uint8_t > value);
        /** @brief Returns the big-endian UCS-4 octets. */
        [[nodiscard]] const std::vector < uint8_t >& value () const noexcept;
        /** @brief Replaces and validates the big-endian UCS-4 octets. */
        void assign (std::span < const uint8_t > value);
        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares encoded character values. */
        bool operator== (const Universal_String& other) const noexcept;
        /** @brief Writes the encoded value in hexadecimal notation. */
        friend std::ostream& operator<< (std::ostream& stream, const Universal_String& value);

    private:
        static void validate (std::span < const uint8_t > value);
        std::vector < uint8_t > _value;
    };

} // asn1pp

#endif // ASN1PP_CHARACTER_STRINGS_HPP
