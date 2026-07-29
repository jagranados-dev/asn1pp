/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_DIRECTORY_STRING_HPP
#define ASN1PP_DIRECTORY_STRING_HPP

#include <asn1pp/character_strings.hpp>
#include <asn1pp/choice_alternative.hpp>
#include <asn1pp/choice_of.hpp>
#include <asn1pp/printable_string.hpp>
#include <asn1pp/utf8_string.hpp>

namespace asn1pp
{

    /**
     * @brief X.500 DirectoryString CHOICE used by PKIX names.
     *
     * The type accepts the five alternatives required for interoperable PKIX
     * processing, including legacy TeletexString and BMPString values.
     */
    using Directory_String = Choice_Of <
        Choice_Alternative < Teletex_String, {ASN1_TagClass::UNIVERSAL, false, 20}, "teletexString" >,
        Choice_Alternative < Printable_String, {ASN1_TagClass::UNIVERSAL, false, 19}, "printableString" >,
        Choice_Alternative < Universal_String, {ASN1_TagClass::UNIVERSAL, false, 28}, "universalString" >,
        Choice_Alternative < UTF8_String, {ASN1_TagClass::UNIVERSAL, false, 12}, "utf8String" >,
        Choice_Alternative < BMP_String, {ASN1_TagClass::UNIVERSAL, false, 30}, "bmpString" > >;

} // asn1pp

#endif // ASN1PP_DIRECTORY_STRING_HPP
