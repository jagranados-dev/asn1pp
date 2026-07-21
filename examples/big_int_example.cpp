#include <iostream>
#include <cassert>
#include <asn1pp/der_encoder.hpp>
#include <asn1pp/ber_decoder.hpp>
#include <asn1pp/big_int.hpp>

using namespace asn1pp;

int main ()
{
    std::cout << "--- Testing Big_Int standalone serialization ---\n";

    Big_Int small_num ( 65537ULL );
    std::cout << "Small Big_Int: " << small_num << " | uint64: " << small_num.to_uint64 () << "\n";
    assert ( small_num.to_uint64 () == 65537ULL );

    Big_Int rsa_modulus_chunk ( "0xFFEEDDCCBBAA99887766554433221100" );
    std::cout << "Large Big_Int (MSB set): " << rsa_modulus_chunk << "\n";

    DER_Encoder encoder;
    encoder.start_sequence ()
           .encode ( small_num )
           .encode ( rsa_modulus_chunk )
           .end_cons ();

    std::vector < uint8_t > der_stream = encoder.get_contents ();
    std::cout << "Encoded sequence size: " << der_stream.size () << " bytes\n";

    Big_Int decoded_small;
    Big_Int decoded_large;

    BER_Decoder decoder ( der_stream );
    decoder.start_sequence ()
           .decode ( decoded_small )
           .decode ( decoded_large )
           .end_cons ();

    std::cout << "Decoded Small : " << decoded_small << "\n";
    std::cout << "Decoded Large : " << decoded_large << "\n";

    assert ( decoded_small == small_num );
    assert ( decoded_large == rsa_modulus_chunk );
    assert ( decoded_small < decoded_large );
    assert ( !decoder.more_items () );

    std::cout << "SUCCESS: Big_Int encoded, decoded, and DER sign-padded flawlessly!\n";

    return EXIT_SUCCESS;
}