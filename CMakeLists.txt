cmake_minimum_required(VERSION 3.17)
project(SI_T1)

set(CMAKE_CXX_STANDARD 20)

include_directories(src)
include_directories(src/obj)
include_directories(src/obj/crypto)
include_directories(src/obj/comm)
include_directories(src/obj/thread)

set(
        COMMON_SOURCES
        src/obj/defs.h
        src/obj/types.h
)

set(
        CRYPTO_SOURCES
        src/obj/crypto/Key.cpp
        src/obj/crypto/Key.h
        src/obj/crypto/CryptoObject.cpp
        src/obj/crypto/CryptoObject.h
        src/obj/crypto/CryptoBlock.cpp
        src/obj/crypto/CryptoBlock.h
        src/obj/crypto/CryptoManager.cpp
        src/obj/crypto/CryptoManager.h
)

set(
        CLIENT_SOURCES
        src/obj/comm/Socket.cpp
        src/obj/comm/Socket.h
        src/obj/comm/ClientSocket.cpp
        src/obj/comm/ClientSocket.h
        src/obj/comm/ServerSocket.cpp
        src/obj/comm/ServerSocket.h
)

set(
        SERVER_SOURCES
        src/obj/comm/Socket.cpp
        src/obj/comm/Socket.h
        src/obj/comm/ServerSocket.cpp
        src/obj/comm/ServerSocket.h
        src/obj/ServerThread.cpp
        src/obj/ServerThread.h
        src/obj/Server.cpp
        src/obj/KeyManager.cpp
        src/obj/KeyManager.h
        src/obj/thread/Semaphore.cpp
        src/obj/thread/Semaphore.h
)

set (STATIC_LIBS

        -lpthread
        -lcrypto
        -lssl

)


add_executable(CryptoManagerTest src/main.cpp ${COMMON_SOURCES} ${CRYPTO_SOURCES} src/obj/KeyManager.cpp )
target_link_libraries(CryptoManagerTest ${STATIC_LIBS})

add_executable(NodeA ${COMMON_SOURCES} ${CRYPTO_SOURCES} ${CLIENT_SOURCES} src/obj/NodeA.cpp)
add_executable(NodeB ${COMMON_SOURCES} ${CRYPTO_SOURCES} ${CLIENT_SOURCES} src/obj/NodeB.cpp)
add_executable(NodeKM ${COMMON_SOURCES} ${CRYPTO_SOURCES} ${SERVER_SOURCES})

target_link_libraries( NodeA ${STATIC_LIBS} )
target_link_libraries( NodeB ${STATIC_LIBS} )
target_link_libraries( NodeKM ${STATIC_LIBS} )