##################################################################################
# MIT License
#
# Copyright (c) 2025 Jose Alberto Granados
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##################################################################################

# File directories
file(GLOB_RECURSE LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE LIB_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)

# Static library output
add_library(STATIC_LIB STATIC ${LIB_SOURCES} ${LIB_HEADERS})
target_include_directories(STATIC_LIB
   PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
)
# Link with dependencies
# target_link_libraries(STATIC_LIB
#     PUBLIC
#       Example::lib
# )
set_target_properties(STATIC_LIB PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

# Shared library output
if (BUILD_SHARED_LIBS)
   add_library(SHARED_LIB SHARED ${LIB_SOURCES} ${LIB_HEADERS})
   target_include_directories(SHARED_LIB
      PUBLIC
         ${CMAKE_CURRENT_SOURCE_DIR}/include
   )
   # Link with dependencies
   # target_link_libraries(SHARED_LIB
   #    PUBLIC
   #       Example::lib
   # )
   set_target_properties(SHARED_LIB PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
endif()
