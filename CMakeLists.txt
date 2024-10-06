cmake_minimum_required(VERSION 3.15)

project(TheCruZMMap)

find_package(MSPDBX REQUIRED)

add_compile_options(/MT$<$<CONFIG:Debug>:d> /GR- /INCREMENTAL:NO)
add_link_options(/INCREMENTAL:NO /OPT:REF /OPT:ICF)

set(IS_DEBUG_BUILD FALSE)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
set(IS_DEBUG_BUILD TRUE)
endif()
option(ENABLE_LOGGING "Enable Logging" ${IS_DEBUG_BUILD})

set(SRC_ROOT "Manual Map Injector")

include(CBuildKit)

add_library_ns(thecruz manualmap STATIC ${SRC_ROOT}/injector.cpp)
target_include_dir_iface(thecruz-manualmap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_ROOT} include)
target_link_libraries(thecruz-manualmap mspdbx::mspdbx)
install_target_and_headers(thecruz manualmap)

if(NOT ENABLE_LOGGING)
    target_compile_definitions(thecruz-manualmap PUBLIC DISABLE_OUTPUT)
endif()

add_executable(injector ${SRC_ROOT}/main.cpp)
target_link_libraries(injector thecruz::manualmap)
target_compile_definitions(injector PRIVATE -DUNICODE -D_UNICODE)

install(FILES 
    ${SRC_ROOT}/injector.h
    DESTINATION include/TheCruZ)

configure_file(TheCruZMMapConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/TheCruZMMapConfig.cmake
    @ONLY)

# Realize Installation of Configuration cmake file
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/TheCruZMMapConfig.cmake
    DESTINATION lib/cmake/TheCruZ)