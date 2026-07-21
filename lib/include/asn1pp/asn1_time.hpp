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

#ifndef __ASN1PP_ASN1_TIME_HPP_
#define __ASN1PP_ASN1_TIME_HPP_

#include <chrono>
#include <string>
#include <string_view>
#include <iosfwd>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/asn1_types.hpp>

namespace asn1pp 
{

    /**
     * @brief Represents an ASN.1 Time object (UTCTime or GeneralizedTime).
     * 
     * Encapsulates a C++20 chrono system_clock time point and handles its DER
     * encoding and BER decoding according to ITU-T X.690 and RFC 5280 rules.
     * Automatically selects UTCTime for years 1950-2049 and GeneralizedTime otherwise.
     */
    class ASN1_Time final : public ASN1_Object {
    public:
        /**
         * @brief Constructs an uninitialized ASN1_Time (epoch time with UTC_TIME tag).
         */
        ASN1_Time () = default;

        /**
         * @brief Constructs an ASN1_Time from a chrono system_clock time point.
         * @param time The C++20 time point.
         * @param tag The ASN.1 tag to use (defaults to EOC for automatic selection based on year).
         */
        explicit ASN1_Time ( std::chrono::system_clock::time_point time, ASN1_Type tag = ASN1_Type::EOC );

        /**
         * @brief Constructs an ASN1_Time by parsing an ASN.1 DER date string.
         * @param time_str Formatted string (e.g., "260721173202Z" or "20260721173202Z").
         * @param tag The ASN.1 tag (defaults to EOC for automatic format detection).
         */
        explicit ASN1_Time ( std::string_view time_str, ASN1_Type tag = ASN1_Type::EOC );

        ~ASN1_Time() override = default;

        // Copy and move semantics
        ASN1_Time ( const ASN1_Time& ) = default;
        ASN1_Time& operator= ( const ASN1_Time& ) = default;
        ASN1_Time ( ASN1_Time&& ) noexcept = default;
        ASN1_Time& operator= ( ASN1_Time&& ) noexcept = default;

        /**
         * @brief Serializes this time object into a DER encoder stream.
         * @param to The target DER encoder.
         */
        void encode_into ( DER_Encoder& to ) const override;

        /**
         * @brief Deserializes a time object from a BER decoder stream.
         * @param from The source BER decoder.
         */
        void decode_from ( BER_Decoder& from ) override;

        /**
         * @brief Returns the underlying C++20 system_clock time point.
         */
        [[nodiscard]] std::chrono::system_clock::time_point get_time_point () const noexcept;

        /**
         * @brief Returns the ASN.1 tag associated with this timestamp (UTC_TIME or GENERALIZED_TIME).
         */
        [[nodiscard]] ASN1_Type get_tag () const noexcept;

        /**
         * @brief Formats the date as an ISO-8601 readable string (e.g., "2026-07-21T17:32:02Z").
         */
        [[nodiscard]] std::string to_string () const;

        /**
         * @brief Formats the date as the exact DER ASN.1 string representation.
         */
        [[nodiscard]] std::string to_asn1_string () const;

        // Relational operators for chronological comparison
        [[nodiscard]] bool operator== ( const ASN1_Time& other ) const noexcept;
        [[nodiscard]] bool operator!= ( const ASN1_Time& other ) const noexcept;
        [[nodiscard]] bool operator< ( const ASN1_Time& other ) const noexcept;
        [[nodiscard]] bool operator<= ( const ASN1_Time& other ) const noexcept;
        [[nodiscard]] bool operator> ( const ASN1_Time& other ) const noexcept;
        [[nodiscard]] bool operator>= ( const ASN1_Time& other ) const noexcept;
    private:
        std::chrono::system_clock::time_point _time_point;
        ASN1_Type _tag = ASN1_Type::UTC_TIME;
    };

    /**
     * @brief Stream insertion operator for printing ASN1_Time instances.
     */
    std::ostream& operator<< ( std::ostream& os, const ASN1_Time& time );

} // asn1pp

#endif // __ASN1PP_ASN1_TIME_HPP_