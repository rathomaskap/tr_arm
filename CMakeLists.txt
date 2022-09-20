cmake_minimum_required(VERSION 3.0.0)
project(tr_arm2 VERSION 0.1.0)

include(CTest)
enable_testing()

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJ_IS_BIG_ENDIAN=0")
set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJ_IS_BIG_ENDIAN=0")

include_directories(${linuxIncPath} 
" /home/rainer/work/buildroot-2018.08.2/output/build/linux-4.17.19/arch/arm/include/asm/vc_include "
" /home/rainer/git/json/include " ) 


add_executable(tr_arm2 alt_pjsua_aud.c ioctl_netif.c myconfig.c stateless_proxy.c)

target_link_libraries(tr_arm2 pthread ssl crypto rt m pj pjmedia-codec pjmedia pjsip pjsip-ua pjsip-simple pjsua2 pjmedia-audiodev pjsua pjlib-util pjnath config)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

set(CMAKE_VERBOSE_MAKEFILE ON)

add_custom_command(TARGET tr_arm2 POST_BUILD
    COMMAND scp tr_arm2 root@10.1.1.50:/root )
