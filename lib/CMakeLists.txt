##################################################################################
# MIT License
# Copyright (c) 2026 Jose Alberto Granados
##################################################################################

set(ASN1PP_SOURCES
    src/asn1pp/asn1_any.cpp
    src/asn1pp/asn1_errors.cpp
    src/asn1pp/asn1_object.cpp
    src/asn1pp/asn1_time.cpp
    src/asn1pp/ber_decoder.cpp
    src/asn1pp/big_int.cpp
    src/asn1pp/bit_string.cpp
    src/asn1pp/der_decoder.cpp
    src/asn1pp/der_encoder.cpp
    src/asn1pp/ia5_string.cpp
    src/asn1pp/octet_string.cpp
    src/asn1pp/oid.cpp
    src/asn1pp/printable_string.cpp
    src/asn1pp/utf8_string.cpp
)

add_library(asn1pp_static STATIC ${ASN1PP_SOURCES})
add_library(asn1pp::static ALIAS asn1pp_static)
add_library(asn1pp::asn1 ALIAS asn1pp_static)

set_target_properties(asn1pp_static PROPERTIES
    OUTPUT_NAME asn1pp
    EXPORT_NAME static
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

target_compile_features(asn1pp_static PUBLIC cxx_std_20)
target_include_directories(asn1pp_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asn1pp
)

function(ASN1PP_configure_target target)
    if(ASN1PP_ENABLE_WARNINGS)
        if(MSVC)
            target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${ASN1PP_WARNINGS_AS_ERRORS}>:/WX>)
        else()
            target_compile_options(${target} PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                $<$<BOOL:${ASN1PP_WARNINGS_AS_ERRORS}>:-Werror>
            )
        endif()
    endif()

    if(ASN1PP_ENABLE_SANITIZERS)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        else()
            message(WARNING "ASN1PP_ENABLE_SANITIZERS is supported only by GCC and Clang")
        endif()
    endif()
endfunction()

ASN1PP_configure_target(asn1pp_static)

if(ASN1PP_BUILD_SHARED)
    add_library(asn1pp_shared SHARED ${ASN1PP_SOURCES})
    add_library(asn1pp::shared ALIAS asn1pp_shared)

    set_target_properties(asn1pp_shared PROPERTIES
        OUTPUT_NAME asn1pp
        EXPORT_NAME shared
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        CXX_EXTENSIONS OFF
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )

    target_compile_features(asn1pp_shared PUBLIC cxx_std_20)
    target_include_directories(asn1pp_shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/asn1pp
    )

    ASN1PP_configure_target(asn1pp_shared)
endif()

if(ASN1PP_INSTALL)
    install(
        TARGETS asn1pp_static
        EXPORT asn1ppTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    if(TARGET asn1pp_shared)
        install(
            TARGETS asn1pp_shared
            EXPORT asn1ppTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )
    endif()

    install(
        DIRECTORY include/asn1
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.hpp"
    )
endif()
