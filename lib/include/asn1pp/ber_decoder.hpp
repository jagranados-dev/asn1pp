/*********************************************************************************
 * MIT License
 *
 * Copyright (c) 2026 Jose Alberto Granados
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *********************************************************************************/

#ifndef __ASN1PP_BER_DECODER_HPP_
#define __ASN1PP_BER_DECODER_HPP_

#include <span>
#include <string>

#include <asn1pp/asn1_types.hpp>

namespace asn1pp
{

    /**
     * @brief BER/DER object header definition.
     */
    struct BER_ObjectHeader
    {
        ASN1_Type type_tag;
        uint8_t class_tag;
        size_t length;
        size_t header_size;
    };

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
        BER_ObjectHeader get_next_object ();
    private:
        BER_ObjectHeader get_next_header ();
        std::vector < uint8_t > get_next_value ( ASN1_Type expected_type, ASN1_Class expected_class );
        void start_cons ( ASN1_Type expected_type );
    private:
        size_t _offset;
        std::vector < size_t > _limits;
        std::span < const uint8_t > _data;
    };

} // asn1pp

#endif // __ASN1PP_BER_DECODER_HPP_