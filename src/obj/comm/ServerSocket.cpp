//
// Created by loghin on 01.11.2020.
//

#include "ServerSocket.h"

#include <sys/socket.h>
#include <netinet/in.h>

ServerSocket::ServerSocket( uint16 port, uint32 queueSize ) noexcept (false) : Socket() {
    Socket::debug() << "Creating Server Socket ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    sockaddr_in serverInfo {};
    serverInfo.sin_port = htons ( port );
    serverInfo.sin_addr.s_addr = htonl ( INADDR_ANY );
    serverInfo.sin_family = AF_INET;

    int sock_opt_option = 1;
    if ( -1 == setsockopt ( this->_descriptor, SOL_SOCKET, SO_REUSEADDR, & sock_opt_option, sizeof ( int ) ) )
        throw SetSocketOptionException();

    if ( -1 == bind( this->_descriptor, reinterpret_cast< sockaddr * > ( & serverInfo ), static_cast < socklen_t > ( sizeof ( sockaddr_in ) ) ) )
        throw BindException();

    if ( -1 == listen( this->_descriptor, queueSize ))
        throw ListenException();
}

Socket ServerSocket::accept() noexcept {
    Socket::debug () << "Waiting for client ( 0x" << reinterpret_cast < std::size_t >( this ) << " )\n";

    sockaddr_in clientDummyAddr {};
    socklen_t dummyAddrLen = sizeof(clientDummyAddr);
    return Socket ( ::accept ( this->_descriptor, reinterpret_cast < sockaddr * > ( & clientDummyAddr ), & dummyAddrLen ) );
}