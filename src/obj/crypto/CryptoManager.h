//
// Created by loghin on 02.11.2020.
//

#ifndef SI_T1_CRYPTOMANAGER_H
#define SI_T1_CRYPTOMANAGER_H

#include <CryptoObject.h>

namespace crypto {

    template<BlockSize size>
    class CryptoManager {
    public:
        typedef enum {
            ECB,
            CBC,
            CFB,
            OFB
        } EncryptMode;

        CryptoManager() noexcept = delete;

        static std::string getPrintableCipherText(const std::string &str) noexcept {
            std::string newString = str;
            std::transform(newString.cbegin(), newString.cend(), newString.begin(), [](char c) -> char {if (c < 32 || c > 126) return '.';return c;});
            return newString;
        }

        template <EncryptMode mode>
        static std::string encrypt(const char *, const Key<size> &, const IV <size> &) noexcept;
        template <EncryptMode mode>
        static std::string encrypt(const std::string & plainText, const Key<size>& key, const IV<size>& iv) noexcept {
            return encrypt<mode>( plainText.c_str(), key, iv );
        }

        template <EncryptMode mode>
        static std::string decrypt(const char *, const Key<size> &, const IV <size> &) noexcept;

        template <EncryptMode mode>
        static std::string decrypt(const std::string & plainText, const Key<size>& key, const IV<size>& iv) noexcept {
            return decrypt<mode>( plainText.c_str(), key, iv );
        }

        static std::string encryptECB(const char *, const Key<size> & ) noexcept;
        static std::string encryptCBC(const char *, const Key<size> &, const IV<size> &) noexcept;
        static std::string encryptCFB(const char *, const Key<size> &, const IV<size> &) noexcept;
        static std::string encryptOFB(const char *, const Key<size> &, const IV<size> &) noexcept;

        static std::string encryptECB(const std::string & plainText, const Key<size> & key) noexcept {
            return CryptoManager::encryptECB( plainText.c_str(), key );
        }
        static std::string encryptCBC(const std::string & plainText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::encryptCBC( plainText.c_str(), key, iv );
        }
        static std::string encryptCFB(const std::string & plainText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::encryptCBC( plainText.c_str(), key, iv );
        }
        static std::string encryptOFB(const std::string & plainText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::encryptCBC( plainText.c_str(), key, iv );
        }

        static std::string decryptECB(const char *, const Key<size> & ) noexcept;
        static std::string decryptCBC(const char *, const Key<size> &, const IV<size> &) noexcept;
        static std::string decryptCFB(const char *, const Key<size> &, const IV<size> &) noexcept;
        static std::string decryptOFB(const char *, const Key<size> &, const IV<size> &) noexcept;

        static std::string decryptECB(const std::string & cipherText, const Key<size> & key ) noexcept {
            return CryptoManager::decryptECB( cipherText.c_str(), key );
        }
        static std::string decryptCBC(const std::string & cipherText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::decryptCBC( cipherText.c_str(), key, iv );
        }
        static std::string decryptCFB(const std::string & cipherText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::decryptCFB( cipherText.c_str(), key, iv );
        }
        static std::string decryptOFB(const std::string & cipherText, const Key<size> & key, const IV<size> & iv) noexcept {
            return CryptoManager::decryptOFB( cipherText.c_str(), key, iv );
        }
    };

}




#include <sstream>
template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::encryptECB(const char * pPlainText, const Key<size> & key) noexcept {
    Encryptor < size > encryptor;
    std::stringstream cipherText;

    encryptor.setKey(key);

    for ( const auto & block : CryptoBlock < size > :: split ( pPlainText ) ) {
        encryptor.setInput( block ).run();
        cipherText << encryptor.getOutput().data();
    }

    return cipherText.str();
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::encryptCBC(const char * pPlainText, const Key<size> & key, const IV<size> & iv) noexcept {
    Encryptor < size > encryptor;
    std::stringstream cipherText;

    encryptor.setKey(key).setIV(iv);

    for ( const auto & block : CryptoBlock < size > :: split ( pPlainText ) ) {
        encryptor.setInput( encryptor.getIV() ^ block ).run().setIV( encryptor.getOutput() );
        cipherText << encryptor.getOutput().data();
    }

    return cipherText.str();
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::encryptCFB(const char * pPlainText, const Key<size> & key, const IV<size> & iv) noexcept {
    Encryptor < size > encryptor;
    std::stringstream cipherText;

    encryptor.setKey(key).setIV(iv);

    for ( const auto & block : CryptoBlock < size > :: split ( pPlainText ) ) {
        encryptor.setInput( encryptor.getIV() ).run();
        IV < size > nextIV ( block ^ encryptor.getOutput() );
        encryptor.setIV ( nextIV );
        cipherText << nextIV.data();
    }

    return cipherText.str();
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::encryptOFB(const char * pPlainText, const Key<size> & key, const IV<size> & iv) noexcept {
    Encryptor < size > encryptor;
    std::stringstream cipherText;

    encryptor.setKey(key).setIV(iv);

    for ( const auto & block : CryptoBlock < size > :: split ( pPlainText ) ) {
        encryptor.setInput( encryptor.getIV() ).run().setIV( encryptor.getOutput() );
        cipherText << ( block ^ encryptor.getOutput() ).data();
    }

    return cipherText.str();
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::decryptECB(const char * pCipherText, const Key<size> & key) noexcept {
    Decryptor < size > decryptor;
    std::stringstream plainText;

    decryptor.setKey(key);

    for ( const auto & block : CryptoBlock < size > :: split ( pCipherText ) ) {
        decryptor.setInput(block).run();
        plainText << decryptor.getOutput().data();
    }

    return plainText.str().substr(0, plainText.str().find(' '));
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::decryptCBC(const char * pCipherText, const Key<size> & key, const IV<size> & iv) noexcept {
    Decryptor < size > decryptor;
    std::stringstream plainText;

    decryptor.setKey(key).setIV(iv);

    for ( const auto & block : CryptoBlock < size > :: split ( pCipherText ) ) {
        IV < size > currentIV = decryptor.getIV();
        decryptor.setInput(block).run().setIV( decryptor.getInput() );
        plainText << ( currentIV ^ decryptor.getOutput() ).data();
    }

    return plainText.str().substr(0, plainText.str().find(' '));
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::decryptCFB(const char * pCipherText, const Key<size> & key, const IV<size> & iv) noexcept {
    Encryptor < size > decryptor;
    std::stringstream plainText;

    decryptor.setKey(key).setIV(iv);

    for ( const auto & block : CryptoBlock < size > :: split ( pCipherText ) ) {
        decryptor.setInput( decryptor.getIV() ).run().setIV ( block );
        plainText << ( decryptor.getOutput() ^ block ).data();
    }

    return plainText.str().substr(0, plainText.str().find(' '));
}

template <crypto::BlockSize size>
std::string crypto::CryptoManager<size>::decryptOFB(const char * pCipherText, const Key<size> & key, const IV<size> & iv) noexcept {
    return encryptOFB( pCipherText, key, iv );
}

template<crypto::BlockSize size>
template<typename crypto::CryptoManager<size>::EncryptMode mode>
std::string crypto::CryptoManager<size>::encrypt(const char * pPlainText, const crypto::Key<size> & key, const crypto::IV<size> & iv) noexcept {
    switch ( mode ) {
        case ECB: return encryptECB ( pPlainText, key );
        case CBC: return encryptCBC ( pPlainText, key, iv );
        case CFB: return encryptCFB ( pPlainText, key, iv );
        case OFB: return encryptOFB ( pPlainText, key, iv );
    }
}

template<crypto::BlockSize size>
template<typename crypto::CryptoManager<size>::EncryptMode mode>
std::string crypto::CryptoManager<size>::decrypt(const char * pCipherText, const crypto::Key<size> & key, const crypto::IV<size> & iv) noexcept {
    switch ( mode ) {
        case ECB: return decryptECB ( pCipherText, key );
        case CBC: return decryptCBC ( pCipherText, key, iv );
        case CFB: return decryptCFB ( pCipherText, key, iv );
        case OFB: return decryptOFB ( pCipherText, key, iv );
    }
}

#define __NAMESPACE_GEN( _name, _size )                                                     \
namespace _name ## _size {                                                                  \
    using CryptoBlock = ::crypto::CryptoBlock < ::crypto::BlockSize::BITS_ ## _size >;      \
    using CryptoManager = ::crypto::CryptoManager < ::crypto::BlockSize::BITS_ ## _size >;  \
    using CryptoObject = ::crypto::CryptoObject < ::crypto::BlockSize::BITS_ ## _size >;    \
    using Key = ::crypto::Key < ::crypto::KeySize::BITS_ ## _size >;                        \
    using IV = ::crypto::IV < ::crypto::IVSize::BITS_ ## _size >;                           \
    using Encryptor = ::crypto::Encryptor < ::crypto::BlockSize :: BITS_ ## _size >;        \
    using Decryptor = ::crypto::Decryptor < ::crypto::BlockSize :: BITS_ ## _size >;        \
}

__NAMESPACE_GEN(crypto, 64)
__NAMESPACE_GEN(crypto, 128)
__NAMESPACE_GEN(crypto, 256)
__NAMESPACE_GEN(crypto, 512)

#undef __NAMESPACE_GEN

#endif //SI_T1_CRYPTOMANAGER_H
