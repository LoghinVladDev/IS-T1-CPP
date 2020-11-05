
//
// Created by loghin on 01.11.2020.
//

#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "Socket.h"

Socket::SocketDebug Socket::SocketDebug::_instance;

#include <iomanip>
#include <ctime>

std::string getTimeAsString(  ) noexcept {
    auto time = std::time ( nullptr );
    std::ostringstream oss;
    oss << ( std::put_time ( std::localtime ( & time ), "%d/%m/%Y %H:%M:%S" ) );
    return oss.str();
}

void Socket::SocketDebug::setDebugOutputBuffer( std::ostream & buffer ) noexcept {
    this->_debugBuffer->flush();
    this->_debugBuffer = & buffer;
}

const Socket::SocketDebug & Socket::SocketDebug::operator<<(const std::string &str) const noexcept {
    if ( this->_debugToggle ) {
        (*this->_debugBuffer) << str;
    }

    return * this;
}

const Socket::SocketDebug & Socket::SocketDebug::operator << ( const char * pStr ) const noexcept {
    if ( this->_debugToggle ) {
        (*this->_debugBuffer) << pStr;
    }

    return * this;
}

const Socket::SocketDebug & Socket::SocketDebug::operator << ( char c ) const noexcept {
    if ( this->_debugToggle ) {
        (*this->_debugBuffer) << c;
     }

    return * this;
}

const Socket::SocketDebug & Socket::SocketDebug::operator << ( std::size_t size ) const noexcept {
    if ( this->_debugToggle ) {
        (*this->_debugBuffer) << size;
    }

    return * this;
}

const Socket::SocketDebug & Socket::SocketDebug::operator << ( int val ) const noexcept {
    if ( this->_debugToggle ) {
        (*this->_debugBuffer) << val;
    }

    return * this;
}

const Socket::SocketDebug & Socket::SocketDebug::getInstance () noexcept {
    return ( Socket::SocketDebug::_instance << "\t[ SOCKET DEBUG ] " << getTimeAsString() << " " );
}

Socket::Socket( Socket::ExceptionFlags exceptionFlags ) noexcept :
        _descriptor( Socket::CLOSED_DESCRIPTOR ),
        _exceptionFlags( exceptionFlags ) {
    Socket::debug() << "Created Socket ( 0x" << reinterpret_cast < std::size_t > ( this ) << " )\n";
    this->open();
}

Socket::~Socket() noexcept {
    Socket::debug() << "Destroying socket ( 0x" << reinterpret_cast < std::size_t > ( this ) << " )\n";
//    this->close();
}

Socket & Socket::open() noexcept {
    if ( this->isClosed() ) {
        Socket::debug() << "Opening socket ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";
        this->_descriptor = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);
    }
    return * this;
}

Socket & Socket::close() noexcept {
    if ( this->isOpen() ) {
        Socket::debug() << "Closing socket ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";
        ::close(this->_descriptor);
    }
    return * this;
}


#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

Socket & Socket::operator >> ( std::string & inputBuffer ) noexcept (false) {

    #define TREAT_READ_EXCEPTIONS(_readResult, _normalResult)                                           \
        if ( (_readResult) == Socket::SOCKET_ERROR ) {                                                  \
            this->close();                                                                              \
            if ( this->_exceptionFlags & Socket::eError )                                               \
                throw Socket::ErrorException();                                                         \
            return * this;                                                                              \
        }                                                                                               \
        if ( (_readResult) == Socket::SOCKET_DISCONNECT ) {                                             \
            this->close();                                                                              \
            if ( this->_exceptionFlags & Socket::eDisconnect )                                          \
                throw Socket::DisconnectException ();                                                   \
            return * this;                                                                              \
        }                                                                                               \
        if ( ( this->_exceptionFlags & Socket::eBadByteBuffering ) && (_readResult) != (_normalResult) )\
            throw Socket::BadByteBufferingException();

    if ( ( this->_exceptionFlags & Socket::eClosed ) && this->isClosed() )
        throw Socket::ClosedException();

    Socket::debug() << "Waiting on string length read ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    int messageLength = 0;
    int bytesRead = read ( this->_descriptor, & messageLength, sizeof ( int ) );
    TREAT_READ_EXCEPTIONS( bytesRead, sizeof(int) )

    Socket::debug() << "Read string length : '" << messageLength << "' ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    if ( ( this->_exceptionFlags & Socket::eClosed ) && this->isClosed() )
        throw Socket::ClosedException();

    Socket::debug() << "Waiting on string read ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    inputBuffer.resize ( messageLength + 1 );
    bytesRead = read ( this->_descriptor, inputBuffer.data(), messageLength );
    TREAT_READ_EXCEPTIONS( bytesRead, messageLength )

    Socket::debug() << "Read String '" << crypto128::CryptoManager::getPrintableCipherText( inputBuffer ) << "' ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    inputBuffer = this->decrypt ( inputBuffer );

    Socket::debug() << "Decrypted String '" << inputBuffer << "' ( 0x" << reinterpret_cast< std::size_t >( this ) << " )\n";


    return * this;
    #undef TREAT_READ_EXCEPTIONS
}

Socket & Socket::operator << ( const std::string & outputBuffer ) noexcept (false) {

    #define TREAT_WRITE_EXCEPTIONS(_writeResult, _normalResult)                                         \
        if ( (_writeResult ) == Socket::SOCKET_ERROR ) {                                                \
            this->close();                                                                              \
            if ( this->_exceptionFlags & Socket::eError )                                               \
                throw Socket::ErrorException();                                                         \
            return * this;                                                                              \
        }                                                                                               \
        if ( (this->_exceptionFlags & Socket::eBadByteBuffering) && (_writeResult) != (_normalResult) ) \
            throw Socket::BadByteBufferingException();

    if ( ( this->_exceptionFlags & Socket::eClosed ) && this->isClosed() )
        throw Socket::ClosedException();

    Socket::debug() << "Encrypting '" << outputBuffer << "' (0x" << reinterpret_cast< std::size_t >( this ) << " )\n";
    auto encryptedMessage = this->encrypt ( outputBuffer );

    int messageLength = static_cast < int > (encryptedMessage.length() + 1);
    int bytesWritten = write ( this->_descriptor, & messageLength, sizeof (int) );
    TREAT_WRITE_EXCEPTIONS( bytesWritten, sizeof ( int ) )

    if ( ( this->_exceptionFlags & Socket::eClosed ) && this->isClosed() )
        throw Socket::ClosedException();

    Socket::debug() << "Written string length '" << messageLength << "' (0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    bytesWritten = write( this->_descriptor, encryptedMessage.c_str(), messageLength );
    TREAT_WRITE_EXCEPTIONS( bytesWritten, messageLength )

    Socket::debug() << "Written string '" << crypto128::CryptoManager::getPrintableCipherText( encryptedMessage ) << "' (0x" << reinterpret_cast< std::size_t >( this ) << " )\n";

    return * this;
    #undef TREAT_WRITE_EXCEPTIONS
}

#pragma clang diagnostic pop

std::string Socket::decrypt(const std::string & cipherText) const noexcept {
    if ( ! this->_encryptionDetails._isEncrypted )
        return cipherText;

    switch ( this->_encryptionDetails._encryptionMode ) {
        case crypto128::CryptoManager::EncryptMode::ECB :
            return crypto128::CryptoManager::decryptECB (
                    cipherText,
                    this->_encryptionDetails._encryptionKey
            );
        case crypto128::CryptoManager::EncryptMode::CBC :
            return crypto128::CryptoManager::decryptCBC (
                    cipherText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
        case crypto128::CryptoManager::EncryptMode::CFB :
            return crypto128::CryptoManager::decryptCFB (
                    cipherText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
        case crypto128::CryptoManager::EncryptMode::OFB :
            return crypto128::CryptoManager::decryptOFB (
                    cipherText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
    }

    return cipherText;
}

std::string Socket::encrypt ( const std::string & plainText ) const noexcept {
    if ( ! this->_encryptionDetails._isEncrypted )
        return plainText;

    switch ( this->_encryptionDetails._encryptionMode ) {
        case crypto128::CryptoManager::EncryptMode::ECB :
            return crypto128::CryptoManager::encryptECB (
                    plainText,
                    this->_encryptionDetails._encryptionKey
            );
        case crypto128::CryptoManager::EncryptMode::CBC :
            return crypto128::CryptoManager::encryptCBC (
                    plainText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
        case crypto128::CryptoManager::EncryptMode::CFB :
            return crypto128::CryptoManager::encryptCFB (
                    plainText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
        case crypto128::CryptoManager::EncryptMode::OFB :
            return crypto128::CryptoManager::encryptOFB (
                    plainText,
                    this->_encryptionDetails._encryptionKey,
                    this->_encryptionDetails._encryptionIV
            );
    }

    return plainText;
}