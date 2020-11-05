//
// Created by loghin on 01.11.2020.
//

#include "CryptoObject.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void handleEvpErrors ( ) {
    ERR_print_errors_fp( stderr );
    abort();
}

static std::size_t _encrypt (const byte * pPlaintext, std::size_t plainTextLength, const byte * pKey, const byte * pIV , byte * pCipherTextBuffer ) noexcept { // NOLINT(bugprone-reserved-identifier)
    EVP_CIPHER_CTX * cipherObject = nullptr;
    std::size_t cipherTextLength = 0;

    if ( ( cipherObject = EVP_CIPHER_CTX_new() ) == nullptr )
        handleEvpErrors();

    if ( EVP_EncryptInit_ex( cipherObject, EVP_aes_128_ecb() , nullptr, pKey, pIV ) != 1 )
        handleEvpErrors();

    EVP_CIPHER_CTX_set_padding( cipherObject, 0 );

    int length = 0;

    if ( EVP_EncryptUpdate( cipherObject, pCipherTextBuffer, & length, pPlaintext, plainTextLength ) != 1)
        handleEvpErrors();

    cipherTextLength += length;

    EVP_CIPHER_CTX_free( cipherObject );

    return cipherTextLength;
}

static std::size_t _decrypt ( const byte * pCipherText, std::size_t cipherTextLength, const byte * pKey, const byte * pIV, byte * pPlainTextBuffer ) noexcept { // NOLINT(bugprone-reserved-identifier)
    EVP_CIPHER_CTX * cipherObject = nullptr;

    std::size_t plainTextLength = 0;

    if ( ( cipherObject = EVP_CIPHER_CTX_new() ) == nullptr )
        handleEvpErrors();

    if ( EVP_DecryptInit_ex( cipherObject, EVP_aes_128_ecb() , nullptr, pKey, pIV ) != 1 )
        handleEvpErrors();

    EVP_CIPHER_CTX_set_padding( cipherObject, 0 );

    int length = 0;

    if ( EVP_DecryptUpdate( cipherObject, pPlainTextBuffer, & length, pCipherText, cipherTextLength ) != 1)
        handleEvpErrors();

    plainTextLength += length;

    EVP_CIPHER_CTX_free( cipherObject );

    return plainTextLength;
}

crypto::FunctionPtrCrypto crypto::getEncryptFunction () noexcept {
    return _encrypt;
}

crypto::FunctionPtrCrypto crypto::getDecryptFunction () noexcept {
    return _decrypt;
}