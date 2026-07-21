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

#ifndef __ASN1PP_ASN1_OBJECT_HPP_
#define __ASN1PP_ASN1_OBJECT_HPP_

#include <cstdint>
#include <vector>

namespace asn1pp
{

    class DER_Encoder;
    class BER_Decoder;

    /**
     * @brief Universal ASN.1 Object
     */
    class ASN1_Object
    {
    public:
        ASN1_Object () = default;
        ASN1_Object ( const ASN1_Object& ) = default;
        ASN1_Object& operator= ( const ASN1_Object& ) = default;
        ASN1_Object ( ASN1_Object&& ) = default;
        virtual ~ASN1_Object () = default;

        /**
         * @brief Encode whatever this object is into to
         * @param to the DER_Encoder that will be written to
         */
        virtual void encode_into ( DER_Encoder& to ) const = 0;

        /**
         * @brief Decode whatever this object is from from
         * @param from the BER_Decoder that will be read from
         */
        virtual void decode_from ( BER_Decoder& from ) = 0;

        /**
         * @brief Return the encoding of this object. 
         * 
         * This is a convenience method when just one object needs 
         * to be serialized. Use DER_Encoder for complicated encodings.
         */
        std::vector < uint8_t > BER_encode () const;

        ASN1_Object& operator= ( ASN1_Object&& ) = default;
    };

} // asn1pp

#endif // __ASN1PP_ASN1_OBJECT_HPP_