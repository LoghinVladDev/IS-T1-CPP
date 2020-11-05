//
// Created by loghin on 04.11.2020.
//

#include <iostream>
#include <Socket.h>
#include <defs.h>

class Client {
private:
    ClientSocket    _socket;
    std::ostream &  _logChannel  {std::clog};
    bool            _enableDebug {false};

public:
    Client () noexcept = delete;
    explicit Client ( const char * pIP, uint16 port, bool enableDebug = false, std::ostream & debugChannel = std::clog ) noexcept :
            _socket( pIP, port ),
            _logChannel ( debugChannel ),
            _enableDebug ( enableDebug ){
    }

    int run () noexcept (false);
};


int main () {

    try {
        return Client( LOCALHOST, PORT, true ).run();
    } catch ( std::exception const & exception ) {
        std::cerr << "Exception caught in application base runtime : " << exception.what() << '\n';
    }

    return 1;
}


bool isValidEncryptMode ( std::string & string ) noexcept {
    auto toLower = [](std::string & s) -> std::string & { for( char & c : s ) c = static_cast < char > (std::tolower(c)); return s; };
    if ( toLower ( string ) == "ecb" ) return true;
    if ( toLower ( string ) == "cbc" ) return true;
    if ( toLower ( string ) == "cfb" ) return true;
    if ( toLower ( string ) == "ofb" ) return true;

    return false;
}

#include <fstream>

int Client::run () noexcept (false) {
    try {
        std::ifstream keysFile;
        keysFile.open ( "../resources/keys.dat" );
        std::string keyString;
        keysFile >> keyString >> keyString >> keyString;
        auto key = crypto128::Key::getFromHex(keyString.c_str());
        auto iv = crypto128::IV();
        this->_socket.enableEncryption( crypto128::CryptoManager::ECB, key, iv );
        if ( this->_enableDebug )
            ClientSocket::enableDebug( this->_logChannel );


        std::string encryptionMode;

        while ( true ) {
            std::cout << "Input desired encryption mode (ECB/CFB) : ";
            std::cin >> encryptionMode;
            if ( isValidEncryptMode( encryptionMode ) ) {
                this->_socket << encryptionMode;
                break;
            }
            std::cout << "Invalid mode. Try again\n";
        }

        std::string ivString;

        this->_socket >> encryptionMode >> keyString;
        if ( encryptionMode != "ecb" )
            this->_socket >> ivString;

        crypto128::Key receivedKey( keyString.c_str() );
        crypto128::IV receivedIV( ivString.c_str() );

        std::cout << encryptionMode << '\n' << receivedKey.toHexString() << '\n' << receivedIV.toHexString() << '\n';

        this->_socket.close();

    } catch ( Socket::Exception const & exception ) {
        std::cerr << "Exception caught in client runtime : " << exception.what() << '\n';
    }

    return 0;
}