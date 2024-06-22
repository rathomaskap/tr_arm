cmake_minimum_required(VERSION 3.0.0)
project(tr_arm3 VERSION 0.1.0)

include(CTest)
enable_testing()

link_directories( /home/rainer/git/socket.io-arm )

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJ_IS_BIG_ENDIAN=0")
set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJ_IS_BIG_ENDIAN=0")

include_directories(${linuxIncPath} 

" /home/rainer/git/json/include " 
"/home/rainer/buildroot/buildroot-2022.02.7/output/build/linux-5.15.70/arch/arm/include/asm/vc_include" 
" /home/rainer/git/json/include/nlohmann "
" /home/rainer/git/json/include "
" /home/rainer/git/socket.io-arm/src"
) 


add_executable(tr_arm3 alt_pjsua_aud.c ioctl_netif.c pvmain.cpp delayline.cpp ipconfiguration.cpp sessionParam.cpp)

target_link_libraries(tr_arm3 pthread ssl crypto rt m pj pjmedia-codec pjmedia pjsip pjsip-ua pjsip-simple pjsua2 pjmedia-audiodev pjsua pjlib-util pjnath config -lsioclient)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

set(CMAKE_VERBOSE_MAKEFILE ON)

add_custom_command(TARGET tr_arm3 POST_BUILD
    COMMAND ssh root@cv1 /root/scripts/killall.sh
    COMMAND scp tr_arm3 root@192.168.1.201:/root )
