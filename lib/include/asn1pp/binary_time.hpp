/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_BINARY_TIME_HPP
#define ASN1PP_BINARY_TIME_HPP

#include <ostream>
#include <string_view>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/big_int.hpp>

namespace asn1pp
{

    /**
     * @brief RFC 6019 BinaryTime represented by a non-negative ASN.1 INTEGER.
     */
    class Binary_Time : public ASN1_Object
    {
    public:
        /** @brief Creates the Unix epoch value. */
        Binary_Time () = default;
        /** @brief Creates a BinaryTime value from unsigned seconds. */
        explicit Binary_Time (uint64_t seconds);
        /** @brief Creates a BinaryTime value from unsigned decimal seconds. */
        explicit Binary_Time (std::string_view seconds);
        /** @brief Returns the arbitrary-precision INTEGER representation. */
        [[nodiscard]] const Big_Int& value () const noexcept;
        /** @brief Assigns unsigned decimal seconds. */
        void assign (std::string_view seconds);
        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares two BinaryTime values. */
        bool operator== (const Binary_Time& other) const noexcept;
        /** @brief Writes the decimal number of seconds. */
        friend std::ostream& operator<< (std::ostream& stream, const Binary_Time& value);

    private:
        static void validate (const Big_Int& value);
        Big_Int _value;
    };

} // asn1pp

#endif // ASN1PP_BINARY_TIME_HPP
