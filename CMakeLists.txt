##################################################################################
# MIT License
# Copyright (c) 2026 Jose Alberto Granados
##################################################################################

cmake_minimum_required(VERSION 3.20)

project(asn1pp
    VERSION 1.1.1
    DESCRIPTION "C++20 ASN.1 BER decoder and DER codec library"
    HOMEPAGE_URL "https://github.com/jagranados-dev/asn1pp"
    LANGUAGES CXX
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(PROJECT_IS_TOP_LEVEL)
    set(ASN1PP_DEFAULT_DEVELOPER_OPTIONS ON)
else()
    set(ASN1PP_DEFAULT_DEVELOPER_OPTIONS OFF)
endif()

option(ASN1PP_BUILD_DOCS            "Build Doxygen API documentation"                           OFF)
option(ASN1PP_BUILD_TESTS           "Build Catch2 unit and functional tests"                    ${ASN1PP_DEFAULT_DEVELOPER_OPTIONS})
option(ASN1PP_BUILD_EXAMPLES        "Build example executables"                                 ${ASN1PP_DEFAULT_DEVELOPER_OPTIONS})
option(ASN1PP_BUILD_SHARED          "Build the shared library target"                           OFF)
option(ASN1PP_ENABLE_WARNINGS       "Enable strict compiler warnings for project targets"       ${ASN1PP_DEFAULT_DEVELOPER_OPTIONS})
option(ASN1PP_WARNINGS_AS_ERRORS    "Treat project warnings as errors"                          OFF)
option(ASN1PP_ENABLE_SANITIZERS     "Enable AddressSanitizer and UndefinedBehaviorSanitizer"    OFF)
option(ASN1PP_INSTALL               "Generate install and CMake package rules"                  OFF)

add_subdirectory(lib)

if(ASN1PP_BUILD_TESTS)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()

if(ASN1PP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(ASN1PP_BUILD_DOCS)
    add_subdirectory(doc)
endif()

if(ASN1PP_INSTALL)
    set(ASN1PP_INSTALL_CMAKEDIR 
        "${CMAKE_INSTALL_LIBDIR}/cmake/asn1pp"
    )

    configure_package_config_file(
        cmake/asn1ppConfig.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/asn1ppConfig.cmake"
        INSTALL_DESTINATION "${ASN1PP_INSTALL_CMAKEDIR}"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/asn1ppConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(
        EXPORT asn1ppTargets
        FILE asn1ppTargets.cmake
        NAMESPACE asn1pp::
        DESTINATION "${ASN1PP_INSTALL_CMAKEDIR}"
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/asn1ppConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/asn1ppConfigVersion.cmake"
        DESTINATION "${ASN1PP_INSTALL_CMAKEDIR}"
    )

    install(
        FILES
            README.md
            LICENSE
        DESTINATION "${CMAKE_INSTALL_DOCDIR}"
    )
endif()
