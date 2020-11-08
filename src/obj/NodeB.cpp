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


#include <fstream>

int main () {

    try {
        std::ofstream logFile ( "../logs/nodeBLog.txt" );
        return Client( LOCALHOST, PORT, true, logFile ).run();
        logFile.close();
    } catch ( std::exception const & exception ) {
        std::cerr << "Exception caught in application base runtime : " << exception.what() << '\n';
    }

    return 1;
}


auto toLower = [](std::string & s) -> std::string & { for( char & c : s ) c = static_cast < char > (std::tolower(c)); return s; };
auto removeSpaces = [](std::string & s) -> std::string & { while ( s.ends_with(' ') ) s.pop_back(); return s; };

bool isValidEncryptMode ( std::string & string ) noexcept {
    if ( toLower ( string ) == "ecb" ) return true;
    if ( toLower ( string ) == "cbc" ) return true;
    if ( toLower ( string ) == "cfb" ) return true;
    if ( toLower ( string ) == "ofb" ) return true;

    return false;
}

crypto128::CryptoManager::EncryptMode getEncryptionMode ( std::string & string ) noexcept {
    if ( removeSpaces ( toLower ( string ) ) == "ecb" ) return crypto128::CryptoManager::ECB;
    if ( removeSpaces ( toLower ( string ) ) == "cbc" ) return crypto128::CryptoManager::CBC;
    if ( removeSpaces ( toLower ( string ) ) == "cfb" ) return crypto128::CryptoManager::CFB;
    if ( removeSpaces ( toLower ( string ) ) == "ofb" ) return crypto128::CryptoManager::OFB;

    return crypto::CryptoManager<crypto::BITS_128>::ECB;
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
        if ( removeSpaces(encryptionMode)  != "ecb" )
            this->_socket >> ivString;

        crypto128::Key receivedKey( keyString.c_str() );
        crypto128::IV receivedIV( ivString.c_str() );

//        std::cout << encryptionMode << '\n' << receivedKey.toHexString() << '\n' << receivedIV.toHexString() << '\n';

//        std::cout << "SWITCH ENCRIPTION : \n" << getEncryptionMode ( encryptionMode )  << '\n'
//                  << receivedKey.toHexString() << '\n' << receivedIV.toHexString();

        this->_socket.enableEncryption( getEncryptionMode( encryptionMode ), receivedKey, receivedIV );
        this->_socket << "NODE_READY";


        std::string startConfirm;

        this->_socket >> startConfirm;

        if ( removeSpaces(startConfirm) != "ready" )
            exit(0);



        Socket nodeSocket;
        ClientSocket toNode ( "127.0.0.1", 6999 );
        if ( ! toNode.isConnected() ) {
            ServerSocket channel ( 6999 );
            Socket fromNode = channel.accept();
            nodeSocket = Socket(fromNode);
        } else {
            nodeSocket = Socket(toNode);
        }

        nodeSocket.enableEncryption( getEncryptionMode( encryptionMode ), receivedKey, receivedIV );

        std::string aInfo;

        nodeSocket >> aInfo;

        std::string confirm;
        while ( removeSpaces ( aInfo ) != "<EOF>" ) {
            std::cout << aInfo;
            this->_socket << "8_blocks";
            this->_socket >> confirm;
            nodeSocket >> aInfo;
        }

        this->_socket << "done";

        this->_socket.close();


    } catch ( Socket::Exception const & exception ) {
        std::cerr << "Exception caught in client runtime : " << exception.what() << '\n';
    }

    return 0;
}
