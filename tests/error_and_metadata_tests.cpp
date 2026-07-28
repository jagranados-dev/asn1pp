
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

#include <asn1pp/asn1pp.hpp>
#include <catch2/catch_test_macros.hpp>

TEST_CASE ( "ASN1_Error preserves its code, offset, and diagnostic", "[errors]" )
{
    const asn1pp::ASN1_DecodingError error (
        asn1pp::ASN1_ErrorCode::TRUNCATED_INPUT,
        17,
        "Truncated value"
    );

    REQUIRE ( error.code () == asn1pp::ASN1_ErrorCode::TRUNCATED_INPUT );
    REQUIRE ( error.offset () == 17 );
    REQUIRE ( std::string ( error.what () ).find ( "Truncated value" ) != std::string::npos );
}

TEST_CASE ( "ASN1_Tag compares complete identifier metadata", "[metadata]" )
{
    const asn1pp::ASN1_Tag first { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, true, 201 };
    const asn1pp::ASN1_Tag equal { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, true, 201 };
    const asn1pp::ASN1_Tag different { asn1pp::ASN1_TagClass::CONTEXT_SPECIFIC, false, 201 };

    REQUIRE ( first == equal );
    REQUIRE_FALSE ( first == different );
}

TEST_CASE ( "Default resource limits are finite and internally consistent", "[limits]" )
{
    const asn1pp::BER_DecoderLimits decoder_limits;
    const asn1pp::DER_EncoderLimits encoder_limits;

    REQUIRE ( decoder_limits.max_input_size >= decoder_limits.max_element_size );
    REQUIRE ( decoder_limits.max_depth > 0 );
    REQUIRE ( decoder_limits.max_items > 0 );
    REQUIRE ( decoder_limits.max_tag_octets > 0 );
    REQUIRE ( decoder_limits.max_length_octets > 0 );
    REQUIRE ( encoder_limits.max_output_size > 0 );
    REQUIRE ( encoder_limits.max_depth > 0 );
}
