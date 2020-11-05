#include <iostream>
#include <Key.h>

#include <CryptoBlock.h>
#include <CryptoObject.h>
#include <CryptoManager.h>

using namespace crypto128;

int main () {
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