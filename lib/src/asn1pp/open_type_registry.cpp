/*********************************************************************************
 * MIT License
 * Copyright (c) 2026 Jose Alberto Granados
 *********************************************************************************/

#include <asn1pp/open_type_registry.hpp>

#include <utility>

#include <asn1pp/asn1_errors.hpp>

namespace asn1pp
{

    void
    Open_Type_Registry::register_type (const OID& oid, Factory factory)
    {
        if (!factory)
        {
            throw ASN1_InvalidArgument ("Open-type factory cannot be empty");
        }
        _factories[oid.to_string ()] = std::move (factory);
    }

    void
    Open_Type_Registry::unregister_type (const OID& oid)
    {
        _factories.erase (oid.to_string ());
    }

    bool
    Open_Type_Registry::contains (const OID& oid) const
    {
        return _factories.contains (oid.to_string ());
    }

    std::unique_ptr < ASN1_Object >
    Open_Type_Registry::create (const OID& oid) const
    {
        const auto found = _factories.find (oid.to_string ());
        return found == _factories.end () ? nullptr : found->second ();
    }

} // asn1pp
