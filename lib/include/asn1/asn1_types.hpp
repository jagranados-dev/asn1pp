#ifndef __ASN1_TYPES_HPP_
#define __ASN1_TYPES_HPP_

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace asn1
{
    /**
     * @brief Universal ASN.1 Type Tags (ITU-T X.680)
     */
    enum class ASN1_Type : uint8_t
    {
        EOC              = 0x00,
        BOOLEAN          = 0x01,
        INTEGER          = 0x02,
        BIT_STRING       = 0x03,
        OCTET_STRING     = 0x04,
        NULL_TAG         = 0x05,
        OBJECT_ID        = 0x06,
        ENUMERATED       = 0x0A,
        UTF8_STRING      = 0x0C,
        SEQUENCE         = 0x10,
        SET              = 0x11,
        PRINTABLE_STRING = 0x13,
        IA5_STRING       = 0x16,
        UTC_TIME         = 0x17,
        GENERALIZED_TIME = 0x18
    };

    /**
     * @brief ASN.1 Tag Classes and Construction Flags
     */
    enum class ASN1_Class : uint8_t
    {
        UNIVERSAL        = 0x00,
        APPLICATION      = 0x40,
        CONTEXT_SPECIFIC = 0x80,
        PRIVATE          = 0xC0,
        CONSTRUCTED      = 0x20,
        EXPLICIT         = 0xA0 // CONTEXT_SPECIFIC | CONSTRUCTED
    };

    inline constexpr uint8_t operator| ( ASN1_Class lhs, ASN1_Class rhs ) noexcept
    {
        return static_cast < uint8_t > ( static_cast < uint8_t > ( lhs ) | static_cast < uint8_t > ( rhs ) );
    }

    inline constexpr uint8_t operator| ( ASN1_Class lhs, uint8_t rhs ) noexcept
    {
        return static_cast < uint8_t > ( static_cast < uint8_t > ( lhs ) | rhs );
    }

    inline constexpr uint8_t operator| ( uint8_t lhs, ASN1_Class rhs ) noexcept
    {
        return static_cast < uint8_t > ( lhs | static_cast < uint8_t > ( rhs ) );
    }

    class ASN1_Encoding_Error : public std::runtime_error
    {
    public:
        explicit ASN1_Encoding_Error(const std::string& msg)
            : std::runtime_error ( "ASN.1 Encoding Error: " + msg )
        {}
    };

    class ASN1_Decoding_Error : public std::runtime_error
    {
    public:
        explicit ASN1_Decoding_Error ( const std::string& msg )
            : std::runtime_error ( "ASN.1 Decoding Error: " + msg )
        {}
    };

    struct BER_Object_Header
    {
        ASN1_Type type_tag;
        uint8_t class_tag;
        size_t length;
        size_t header_size;
    };

} // asn1

#endif // __ASN1_TYPES_HPP_