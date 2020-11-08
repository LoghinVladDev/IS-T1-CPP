//
// Created by loghin on 04.11.2020.
//

#include "ServerThread.h"
#include <KeyManager.h>

auto removeSpaces = [](std::string & s) -> std::string & { while ( s.ends_with(' ') ) s.pop_back(); return s; };
crypto128::CryptoManager::EncryptMode getEncrpytionModeFromString ( std::string & string ) noexcept {
    auto toLower = [](std::string & s) -> std::string & { for( char & c : s ) c = static_cast < char > (std::tolower(c)); return s; };
    if ( removeSpaces ( toLower ( string ) ) == "ecb" ) return crypto128::CryptoManager::ECB;
    if ( removeSpaces ( toLower ( string ) ) == "cbc" ) return crypto128::CryptoManager::CBC;
    if ( removeSpaces ( toLower ( string ) ) == "cfb" ) return crypto128::CryptoManager::CFB;
    if ( removeSpaces ( toLower ( string ) ) == "ofb" ) return crypto128::CryptoManager::OFB;

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

        crypto128::Key assignedKey;
        crypto128::IV  assignedIV;

        if ( this->_encryptMode == crypto::CryptoManager<crypto::BITS_128>::ECB ) {
            this->_socket << getEncryptionModeString( this->_encryptMode );
            assignedKey = KeyManager::getInstance().getK1();
            this->_socket << reinterpret_cast < const char * > ( assignedKey.data() );
        } else if ( this->_encryptMode == crypto::CryptoManager<crypto::BITS_128>::CFB ) {
            this->_socket << getEncryptionModeString( this->_encryptMode );
            assignedKey = KeyManager::getInstance().getK2();
//            assignedIV  = crypto128::IV::getRandom();
            assignedIV  = KeyManager::getInstance().getIV();
            this->_socket << reinterpret_cast < const char * > ( assignedKey.data() );
            this->_socket << reinterpret_cast < const char * > ( assignedIV.data() );
        }

        this->_semaphore.getTo().notify();

        std::string confirmationMessage;

        std::cout << "SWITCH ENCRIPTION : \n" << this->_encryptMode << '\n'
            << assignedKey.toHexString() << '\n' << assignedIV.toHexString();

        this->_socket.enableEncryption( this->_encryptMode, assignedKey, assignedIV );

        this->_socket >> confirmationMessage;

        std::cout << confirmationMessage << '\n';

        if ( removeSpaces(confirmationMessage) != Socket::CONFIRMATION_MESSAGE ) {
            this->_socket.close();
            return;
        }

//        std::cout << "Message received successfully\n";


        this->_semaphore.getTo().notify();


        this->_socket << "ready";

        std::string msg;
        this->_socket >> msg;

        try {
            this->_semaphore.getTo().notify();
            while (removeSpaces(msg) != "done") {

                this->_semaphore.getFrom().wait();
                this->_socket << "continue";
                this->_semaphore.getTo().notify();

            }
        } catch ( Socket::Exception const & e ) {
            std::cout << e.what() << '\n';
        }

        this->_socket.close();

    } catch ( Socket::Exception const & exception ) {
        std::cerr << "Server : " <<  exception.what() << "\n";
    }
}