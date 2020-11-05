//
// Created by loghin on 01.11.2020.
//

#include "ClientSocket.h"

#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>

static constexpr bool isDigit ( char c ) noexcept {
    return c >= '0' && c <= '9';
}

static bool isNumeric ( const char * str ) noexcept {
    for ( int i = 0, length = std::strlen(str); i < length; i++ )
        if ( ! isDigit( str[i] ) )
            return false;
    return true;
}

static bool isValidIP ( const char * IP ) noexcept {
    char temporaryBuffer [ 32 ];
    std::strcpy ( temporaryBuffer, IP );

    int segmentIndex = 1;

    char * pSegment = std::strtok ( temporaryBuffer, "." );
    while ( pSegment != nullptr ) {
        if ( segmentIndex > 4 )
            return false;

        if ( ! isNumeric( pSegment ) || std::strlen(pSegment) > 3 )
            return false;

        segmentIndex ++;
        pSegment = strtok ( nullptr, "." );
    }

    return true;
}

ClientSocket::ClientSocket(const std::string & IP, uint16 port) noexcept : Socket () {
    Socket::debug() << "Creating Client Socket ( 0x" << reinterpret_cast<std::size_t>(this) << " )\n";

    if ( ! IP.empty() )
        this->connect( IP, port );
}

ClientSocket::ClientSocket(const char * pIP, uint16 port) noexcept : Socket () {
    Socket::debug() << "Creating Client Socket ( 0x" << reinterpret_cast<std::size_t>(this) << " )\n";
    if ( pIP != nullptr )
        this->connect( pIP, port );
}

ClientSocket & ClientSocket::connect(const std::string & IP, uint16 port) noexcept {
    return this->connect( IP.c_str(), port );
}

ClientSocket & ClientSocket::connect(const char * pIP, uint16 port) noexcept {
    if ( ! isValidIP( pIP ) ) {
        Socket::debug() << "Cannot connect to '" << pIP << ":" << static_cast < std::size_t > (port) << "' (0x " << reinterpret_cast<std::size_t>(this) << " ). Invalid address\n";
        return * this;
    }

    if ( this->isConnected() && this->_connectedIP != pIP )
        this->close();

    Socket::debug() << "Connecting to '" << pIP << ":" << static_cast < std::size_t > (port) << "' ( 0x" << reinterpret_cast<std::size_t>(this) << " )\n";

    sockaddr_in serverAddress {};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons( port );
    serverAddress.sin_addr.s_addr = inet_addr( pIP );

    if ( -1 == ::connect ( this->_descriptor, reinterpret_cast < sockaddr * > ( & serverAddress ), sizeof ( sockaddr_in ) ) ) {
        Socket::debug() << "Cannot connect to '" << pIP << ":" << static_cast < std::size_t > (port) << "' ( 0x" << reinterpret_cast<std::size_t>(this) << " ). Connect Failed\n";
        return *this;
    }

    this->_connectedIP = pIP;
    this->_port = port;

    return * this;
}

ClientSocket::~ClientSocket() noexcept = default;