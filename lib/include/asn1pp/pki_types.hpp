/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_PKI_TYPES_HPP
#define ASN1PP_PKI_TYPES_HPP

#include <cstdint>
#include <optional>
#include <vector>

#include <asn1pp/asn1_any.hpp>
#include <asn1pp/asn1_object.hpp>
#include <asn1pp/octet_string.hpp>
#include <asn1pp/oid.hpp>

namespace asn1pp
{

    /** @brief X.509 AlgorithmIdentifier with preserved BER parameters. */
    class Algorithm_Identifier : public ASN1_Object
    {
    public:
        OID algorithm;
        std::optional < ASN1_Any > parameters;

        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares the algorithm and exact parameter encoding. */
        bool operator== (const Algorithm_Identifier& other) const;
    };

    /** @brief X.501 Attribute with preserved BER SET OF values. */
    class Attribute : public ASN1_Object
    {
    public:
        OID type;
        std::vector < ASN1_Any > values;

        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares the attribute type and values. */
        bool operator== (const Attribute& other) const;
    };

    /** @brief X.509 Extension containing one DER value inside an OCTET STRING. */
    class Extension : public ASN1_Object
    {
    public:
        OID extn_id;
        bool critical = false;
        Octet_String extn_value;

        /** @brief Assigns the DER encoding of the extension syntax. */
        void set_der_value (const ASN1_Object& value);
        /** @brief Returns the validated DER value stored in extnValue. */
        [[nodiscard]] ASN1_Any der_value () const;
        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares all extension fields. */
        bool operator== (const Extension& other) const;
    };

    /** @brief CMS ContentInfo preserving an optional BER open value. */
    class Content_Info : public ASN1_Object
    {
    public:
        OID content_type;
        std::optional < ASN1_Any > content;

        /** @copydoc ASN1_Object::encode_into */
        void encode_into (DER_Encoder& to) const override;
        /** @copydoc ASN1_Object::decode_from */
        void decode_from (BER_Decoder& from) override;
        /** @brief Compares the content type and exact open-value encoding. */
        bool operator== (const Content_Info& other) const;
    };

} // asn1pp

#endif // ASN1PP_PKI_TYPES_HPP
