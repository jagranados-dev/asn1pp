#include <iostream>
#include <cassert>

#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/oid.hpp>

using namespace asn1pp;

int
main ( int, char** )
{
    try
    {
        OID rsa_oid ( "1.2.840.113549.1.1.1" );
        OID sha256_with_rsa = rsa_oid + 11u;
        
        std::cout << "OID RSA: " << rsa_oid << "\n";
        std::cout << "OID SHA256 with RSA: " << sha256_with_rsa << "\n";

        // 2. Codificación: Pasamos el objeto OID directamente al encoder
        DER_Encoder encoder;
        encoder.start_sequence ()
               .encode ( rsa_oid )
               .encode ( sha256_with_rsa )
               .end_cons ();

        std::vector < uint8_t > der_stream = encoder.get_contents ();

        // 3. Decodificación: Desacoplada mediante polimorfismo en ASN1_Object
        OID decoded_oid_1;
        OID decoded_oid_2;

        BER_Decoder decoder ( der_stream );
        decoder.start_sequence ()
               .decode ( decoded_oid_1 )
               .decode ( decoded_oid_2 )
               .end_cons ();

        std::cout << "Decoded OID 1: " << decoded_oid_1 << "\n";
        std::cout << "Decoded OID 2: " << decoded_oid_2 << "\n";

        // Verificación
        assert ( decoded_oid_1 == rsa_oid );
        assert ( decoded_oid_2 == sha256_with_rsa );
        assert ( !decoder.more_items () );

        std::cout << "\nSUCCESS: All OIDs structures encoded and decoded perfectly!\n";
    }
    catch ( const std::exception& ex )
    {
        std::cerr << "FATAL ERROR: " << ex.what () << "\n";

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}