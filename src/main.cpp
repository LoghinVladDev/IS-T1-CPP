#include <iostream>
#include <Key.h>

#include <CryptoBlock.h>
#include <CryptoObject.h>
#include <CryptoManager.h>

using namespace crypto128;
#include <fstream>
#include <KeyManager.h>
void f() {
    std::ifstream file ("../src/test.txt");
    std::string line;

//    crypto128::Key receivedKey = crypto128::Key::getRandom();
//    crypto128::Key receivedIV = crypto128::Key::getRandom();

    KeyManager::getInstance().loadKeys( "../resources/keys.dat" );

    auto receivedKey = KeyManager::getInstance().getK2();
    auto receivedIV = KeyManager::getInstance().getIV();

    line.resize ( 16 * 8 + 1 );

    while ( file.read ( line.data(), 16 * 8 ) ) {
        if ( line.empty() )
            continue;

        std::cout << "{ len : " << line.length() << ", text = '" << line << "'}\n";
        auto enc = crypto128::CryptoManager ::encryptCFB( line.c_str(), 16 * 8, receivedKey, receivedIV );

        std::cout << "{ len : " << enc.length() << ", text = '" << enc << "'}\n";

        auto dec = crypto128::CryptoManager ::decryptCFB( enc.c_str(), 16 * 8, receivedKey, receivedIV );
        std::cout << "{ len : " << dec.length() << ", text = '" << dec << "'}\n\n\n";

//        std::cout << "<LINE>" << line << "<END OF LINE>" <<  '\n';
//        std::cout << "<CTEXT>" << crypto128::CryptoManager::encryptCFB ( line.c_str(), receivedKey, receivedIV ) << "<END OF CTEXT>" << '\n';
//        std::cout << "<DCTEXT>" << crypto128::CryptoManager::decryptCFB(crypto128::CryptoManager::encryptCFB ( line.c_str(), 16 * 8, receivedKey, receivedIV ).c_str(), 16 * 8, receivedKey, receivedIV ) << "<END OF DCTEXT>" << '\n';
//        nodeSocket << line;
//        this->_socket << "8_blocks";
//        this->_socket >> confirm;
//            nodeSocket >> confirm;
    }

    exit(0);
}

int main () {
    f();

    auto key = Key::getFromHex("0123456789abcdef1");
    auto iv = IV::getFromHex("01234");

    auto plainText = "CryptoText-ul meu cel micuts si sigur nu incape pe un block";

    std::cout << "Data : \n";
    std::cout << "KEY : " << key.toHexString() << '\n';
    std::cout << "IV  : " << iv.toHexString() << '\n';

    std::cout << "\n--------General Encryption--------\n";
    auto encryptedText = CryptoManager :: encrypt< CryptoManager::CBC >( plainText, key, iv );
    auto decryptedText = CryptoManager :: decrypt< CryptoManager::CBC >( encryptedText, key, iv );

    std::cout << "Original Text : " << plainText << '\n';
    std::cout << "Encrypted Text : " << CryptoManager::getPrintableCipherText ( encryptedText ) << '\n';
    std::cout << "Decrypted Text : " << decryptedText << '\n';

    std::cout << "\n--------ECB--------\n";
    encryptedText = CryptoManager :: encryptECB (plainText , key );
    decryptedText = CryptoManager :: decryptECB (encryptedText, key );

    std::cout << "Original Text : " << plainText << '\n';
    std::cout << "Encrypted Text : " << CryptoManager::getPrintableCipherText ( encryptedText ) << '\n';
    std::cout << "Decrypted Text : " << decryptedText << '\n';

    std::cout << "\n--------CBC--------\n";

    encryptedText = CryptoManager :: encryptCBC (plainText , key, iv );
    decryptedText = CryptoManager :: decryptCBC (encryptedText, key, iv );

    std::cout << "Original Text : " << plainText << '\n';
    std::cout << "Encrypted Text : " << CryptoManager::getPrintableCipherText ( encryptedText ) << '\n';
    std::cout << "Decrypted Text : " << decryptedText << '\n';

    std::cout << "\n--------CFB--------\n";

    encryptedText = CryptoManager :: encryptCFB (plainText , key, iv );
    decryptedText = CryptoManager :: decryptCFB (encryptedText, key, iv );

    std::cout << "Original Text : " << plainText << '\n';
    std::cout << "Encrypted Text : " << CryptoManager::getPrintableCipherText ( encryptedText ) << '\n';
    std::cout << "Decrypted Text : " << decryptedText << '\n';

    std::cout << "\n--------OFB--------\n";

    encryptedText = CryptoManager :: encryptOFB (plainText , key, iv );
    decryptedText = CryptoManager :: decryptOFB (encryptedText, key, iv );

    std::cout << "Original Text : " << plainText << '\n';
    std::cout << "Encrypted Text : " << CryptoManager::getPrintableCipherText ( encryptedText ) << '\n';
    std::cout << "Decrypted Text : " << decryptedText << '\n';
    return 0;
}