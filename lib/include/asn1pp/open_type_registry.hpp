/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#ifndef ASN1PP_OPEN_TYPE_REGISTRY_HPP
#define ASN1PP_OPEN_TYPE_REGISTRY_HPP

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <asn1pp/asn1_object.hpp>
#include <asn1pp/oid.hpp>

namespace asn1pp
{

    /**
     * @brief Maps an object identifier to an ASN.1 open-type factory.
     *
     * Registries are intended for algorithm parameters, attributes,
     * extensions, CMS content types, and other table-constrained open types.
     */
    class Open_Type_Registry
    {
    public:
        /** @brief Factory that creates an empty concrete ASN.1 object. */
        using Factory = std::function < std::unique_ptr < ASN1_Object > () >;

        /** @brief Creates an empty registry. */
        Open_Type_Registry () = default;

        /**
         * @brief Registers or replaces the factory associated with an OID.
         * @param oid Object identifier that determines the open type.
         * @param factory Factory for the associated concrete object.
         */
        void register_type (const OID& oid, Factory factory);

        /** @brief Removes the factory associated with an OID. */
        void unregister_type (const OID& oid);

        /** @brief Returns true when an OID has a registered concrete type. */
        [[nodiscard]] bool contains (const OID& oid) const;

        /**
         * @brief Creates an empty concrete object for an OID.
         * @return Concrete object, or a null pointer when the OID is unknown.
         */
        [[nodiscard]] std::unique_ptr < ASN1_Object > create (const OID& oid) const;

    private:
        std::unordered_map < std::string, Factory > _factories;
    };

} // asn1pp

#endif // ASN1PP_OPEN_TYPE_REGISTRY_HPP
