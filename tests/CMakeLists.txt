##################################################################################
# MIT License
# Copyright (c) 2026 Jose Alberto Granados
##################################################################################

include(FetchContent)

find_package(Catch2 3.15.2 QUIET)

if(NOT Catch2_FOUND)
    FetchContent_Declare(
        catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.15.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(catch2)
endif()

set(ASN1PP_TEST_SOURCES
    ber_der_decoder_tests.cpp
    container_tests.cpp
    der_encoder_tests.cpp
    error_and_metadata_tests.cpp
    tagging_and_choice_tests.cpp
    value_object_tests.cpp
)

add_executable(asn1pp_tests ${ASN1PP_TEST_SOURCES})
target_link_libraries(asn1pp_tests PRIVATE Catch2::Catch2WithMain asn1pp::static)
target_compile_features(asn1pp_tests PRIVATE cxx_std_20)

include(Catch)
catch_discover_tests(asn1pp_tests)
