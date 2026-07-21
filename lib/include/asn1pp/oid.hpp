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

#ifndef __ASN1PP_OID_HPP_
#define __ASN1PP_OID_HPP_

#include <string>
#include <string_view>
#include <initializer_list>

#include <asn1pp/asn1_object.hpp>

namespace asn1pp 
{

    /**
     * @brief Represents an ASN.1 Object Identifier (OID).
     * 
     * Encapsulates an OID as a sequence of integer components (arcs) and handles its
     * base-128 DER encoding and BER decoding according to ITU-T X.690 specifications.
     */
    class OID final : public ASN1_Object
    {
    public:
        /**
         * @brief Constructs an empty OID.
         */
        OID () = default;

        /**
         * @brief Constructs an OID from a dotted-decimal string representation.
         * @param str The OID string (e.g., "1.2.840.113549.1.1.1").
         */
        explicit OID ( std::string_view str );

        /**
         * @brief Constructs an OID from a vector of integer arcs.
         * @param components The sequence of OID arcs.
         */
        explicit OID ( std::vector < uint32_t > components );

        /**
         * @brief Constructs an OID from an initializer list of integer arcs.
         * @param components The sequence of OID arcs.
         */
        OID ( std::initializer_list < uint32_t > components );

        ~OID() override = default;

        // Copy and move semantics
        OID ( const OID& ) = default;
        OID& operator= ( const OID& ) = default;
        OID ( OID&& ) noexcept = default;
        OID& operator= ( OID&& ) noexcept = default;

        /**
         * @brief Serializes this OID into a DER encoder stream.
         * @param to The target DER encoder.
         */
        void encode_into ( DER_Encoder& to ) const override;

        /**
         * @brief Deserializes an OID from a BER decoder stream.
         * @param from The source BER decoder.
         */
        void decode_from ( BER_Decoder& from ) override;

        /**
         * @brief Formats the OID as a dotted-decimal string.
         * @return Formatted string (e.g., "2.5.4.3").
         */
        [[nodiscard]] std::string to_string () const;

        /**
         * @brief Returns the read-only vector of OID component arcs.
         */
        [[nodiscard]] const std::vector < uint32_t >& get_components() const noexcept;

        /**
         * @brief Checks whether the OID is empty (contains no arcs).
         */
        [[nodiscard]] bool empty () const noexcept;

        /**
         * @brief Clears all component arcs from this OID.
         */
        void clear () noexcept;

        /**
         * @brief Appends a new arc to the OID.
         * @param new_component The integer arc to append.
         * @return Reference to this OID instance.
         */
        OID& operator+= ( uint32_t new_component );

        /**
         * @brief Produces a new OID with an additional appended arc.
         * @param new_component The integer arc to append.
         * @return A newly constructed OID containing the combined arcs.
         */
        [[nodiscard]] OID operator+ ( uint32_t new_component ) const;

        // Relational operators for ordering and equality checks
        [[nodiscard]] bool operator== ( const OID& other ) const noexcept;
        [[nodiscard]] bool operator!= ( const OID& other ) const noexcept;
        [[nodiscard]] bool operator< ( const OID& other ) const noexcept;
    private:
        std::vector < uint32_t > _components;
    };

    /**
     * @brief Stream insertion operator for printing OID instances.
     */
    std::ostream& operator<< ( std::ostream& os, const OID& oid );

} // asnpp

#endif // __ASN1PP_OID_HPP_