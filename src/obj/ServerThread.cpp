//
// Created by loghin on 04.11.2020.
//

#include "ServerThread.h"
#include <KeyManager.h>

crypto128::CryptoManager::EncryptMode getEncrpytionModeFromString ( std::string & string ) noexcept {
    auto toLower = [](std::string & s) -> std::string & { for( char & c : s ) c = static_cast < char > (std::tolower(c)); return s; };
    if ( toLower ( string ) == "ecb" ) return crypto128::CryptoManager::ECB;
    if ( toLower ( string ) == "cbc" ) return crypto128::CryptoManager::CBC;
    if ( toLower ( string ) == "cfb" ) return crypto128::CryptoManager::CFB;
    if ( toLower ( string ) == "ofb" ) return crypto128::CryptoManager::OFB;

    return crypto::CryptoManager<crypto::BITS_128>::ECB;
}

std::string getEncryptionModeString ( crypto128::CryptoManager::EncryptMode mode ) noexcept {
    switch ( mode ) {
        case crypto::CryptoManager<crypto::BITS_128>::ECB : return "ecb";
        case crypto::CryptoManager<crypto::BITS_128>::CBC : return "cbc";
        case crypto::CryptoManager<crypto::BITS_128>::CFB : return "cfb";
        case crypto::CryptoManager<crypto::BITS_128>::OFB : return "ofb";
    }
    return "";
}

void ServerThread::run() noexcept {
    this->_socket.setExceptionFlags( Socket::eDisconnect | Socket::eBadByteBuffering | Socket::eError | Socket::eClosed ); // NOLINT(hicpp-signed-bitwise)
    KeyManager::getInstance().loadKeys("../resources/keys.dat");

    try {
        this->_socket.enableEncryption(crypto128::CryptoManager::ECB, KeyManager::getInstance().getK3(), crypto128::IV());

        std::cout << "Thread " << (this->_associatedNode == NODE_B ? "B" : "A") <<  " Started\n";

        this->_semaphore.getTo().notify();

        std::string preferredEncryptionMode;

        this->_socket >> preferredEncryptionMode;

        this->_encryptMode = getEncrpytionModeFromString( preferredEncryptionMode );
        std::cout << "Assigned " << this->_encryptMode << '\n';

        this->_semaphore.getTo().notify();

        this->_semaphore.getFrom().wait();

        std::cout << "Server Assigned : " << this->_encryptMode << '\n';

        if ( this->_encryptMode == crypto::CryptoManager<crypto::BITS_128>::ECB ) {
            this->_socket << getEncryptionModeString( this->_encryptMode );
            this->_socket << reinterpret_cast < const char * > ( KeyManager::getInstance().getK1().data() );
        } else if ( this->_encryptMode == crypto::CryptoManager<crypto::BITS_128>::CFB ) {
            this->_socket << getEncryptionModeString( this->_encryptMode );
            this->_socket << reinterpret_cast < const char * > ( KeyManager::getInstance().getK2().data() );
            this->_socket << reinterpret_cast < const char * > ( crypto128::IV::getRandom().data() );
        }

        this->_semaphore.getTo().notify();

        this->_socket.close();

    } catch ( Socket::Exception const & exception ) {
        std::cerr << "Server : " <<  exception.what() << "\n";
    }
}