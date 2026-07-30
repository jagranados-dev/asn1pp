##################################################################################
# MIT License
# Copyright (c) 2026 Jose Alberto Granados
##################################################################################

set(ASN1PP_EXAMPLES
    basic_example
    advanced_example
)

foreach(example IN LISTS ASN1PP_EXAMPLES)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} PRIVATE asn1pp::static)
    target_compile_features(${example} PRIVATE cxx_std_20)
endforeach()
