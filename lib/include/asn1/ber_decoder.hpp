#ifndef __ASN1_BER_DECODER_HPP_
#define __ASN1_BER_DECODER_HPP_

#include <vector>
#include <string>
#include <span>

#include <asn1/asn1_types.hpp>

namespace asn1
{
    /**
     * @brief BER/DER Decoder providing sequential TLV parsing and bounds checking.
     */
    class BER_Decoder
    {
    public:
        /**
         * @brief Constructs a decoder over a read-only memory span.
         */
        explicit BER_Decoder(std::span<const uint8_t> data);
        explicit BER_Decoder(const std::vector<uint8_t> &data);

        ~BER_Decoder() = default;

        /**
         * @brief Checks if there are more items to decode within the current scope.
         */
        [[nodiscard]] bool more_items () const;

        /**
         * @brief Decodes a boolean value.
         */
        BER_Decoder& decode ( bool& out );

        /**
         * @brief Decodes an unsigned integer.
         */
        BER_Decoder& decode ( uint64_t &out );

        /**
         * @brief Decodes a signed integer.
         */
        BER_Decoder& decode ( int64_t& out );

        /**
         * @brief Decodes a byte vector (e.g., OCTET STRING or BIT STRING).
         */
        BER_Decoder& decode ( std::vector < uint8_t >& out,
                              ASN1_Type type_tag   = ASN1_Type::OCTET_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL );

        /**
         * @brief Decodes a string (e.g., UTF8String, PrintableString).
         */
        BER_Decoder& decode ( std::string& out,
                              ASN1_Type  type_tag = ASN1_Type::UTF8_STRING,
                              ASN1_Class class_tag = ASN1_Class::UNIVERSAL);

        /**
         * @brief Decodes and verifies an ASN.1 NULL object.
         */
        BER_Decoder& decode_null ();

        /**
         * @brief Opens a SEQUENCE scope.
         */
        BER_Decoder& start_sequence ();

        /**
         * @brief Opens a SET scope.
         */
        BER_Decoder& start_set ();

        /**
         * @brief Closes the current constructed scope (SEQUENCE/SET) and verifies all bytes were consumed.
         */
        BER_Decoder& end_cons ();

        /**
         * @brief Reads the next TLV object without type enforcement.
         */
        BER_Object_Header get_next_object ();
    private:
        BER_Object_Header get_next_header ();
        std::vector < uint8_t > get_next_value ( ASN1_Type expected_type, ASN1_Class expected_class );
        void start_cons ( ASN1_Type expected_type );

        std::span < const uint8_t > _data;
        size_t _offset;
        std::vector < size_t > _limits;
    };
} // asn1

#endif // __ASN1_BER_DECODER_HPP_