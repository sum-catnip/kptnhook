cmake_minimum_required(VERSION 3.23.0)
project(kptnhook VERSION 0.1.0)

#include(CTest)
#enable_testing()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/deps/findwdk/cmake")
find_package(WDK REQUIRED)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/shellcode/shellcode32.asm)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/shellcode/shellcode64.asm)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/shellcode/structs.asm)

exec_program(powershell "${CMAKE_CURRENT_LIST_DIR}"
             ARGS -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_LIST_DIR}\\compile-shellcode.ps1 ${CMAKE_CURRENT_LIST_DIR}\\src\\shellcode\\shellcode32.asm
             OUTPUT_VARIABLE SHELLCODE_BYTES32)

message("compiled 32bit shellcode: ${SHELLCODE_BYTES32}")

exec_program(powershell "${CMAKE_CURRENT_LIST_DIR}"
             ARGS -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_LIST_DIR}\\compile-shellcode.ps1 ${CMAKE_CURRENT_LIST_DIR}\\src\\shellcode\\shellcode64.asm
             OUTPUT_VARIABLE SHELLCODE_BYTES64)

message("compiled 64bit shellcode: ${SHELLCODE_BYTES64}")

wdk_add_driver(kptnhook src/main.cpp)

target_compile_definitions(kptnhook PUBLIC ARR_SHELLCODE32=${SHELLCODE_BYTES32})
target_compile_definitions(kptnhook PUBLIC ARR_SHELLCODE64=${SHELLCODE_BYTES64})
add_custom_command(TARGET kptnhook POST_BUILD
    COMMAND ${WDK_ROOT}/bin/${WDK_VERSION}/x64/signtool.exe sign /v /n kptnhook $<TARGET_FILE:kptnhook>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "signing kernel driver"
)

add_subdirectory(src)
add_subdirectory(include/kptnhook)
#add_subdirectory(deps)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

message(${WDK_ROOT}/bin/${WDK_VERSION}/x64/signtool.exe )