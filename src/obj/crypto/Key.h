//
// Created by loghin on 29.10.2020.
//

#ifndef SI_T1_KEY_H
#define SI_T1_KEY_H

#include <types.h>
#include <defs.h>
#include <array>
#include <string>
#include <exception>
#include <cstring>
#include <CryptoBlock.h>

namespace crypto {

    using IVSize = BlockSize;
    using KeySize = BlockSize;

    template<KeySize size>
    class Key : public CryptoBlock<size> {
    public:
        Key() noexcept: CryptoBlock<size>(static_cast < byte > ( 0x00u )) {}
        Key(const Key<size> &key) noexcept: CryptoBlock<size>(key) {}
        Key(const Key<size> &&key) noexcept: CryptoBlock<size>(key) {}

        explicit Key(const CryptoBlock <size> &block) noexcept: CryptoBlock<size>(block) {}
        explicit Key(const CryptoBlock <size> &&block) noexcept: CryptoBlock<size>(block) {}

        explicit Key(const char *pData) noexcept: CryptoBlock<size>(pData, '\0') {}

        explicit Key(const byte *pByteData, std::size_t byteDataSize) noexcept:
            CryptoBlock<size>(pByteData,byteDataSize,static_cast < byte > ( 0xFF )) {

        }

        static Key getFromHex(const char *) noexcept;
        static Key getRandom () noexcept;

        Key<size> &operator=(const Key<size> &key) noexcept {
            this->setData(key);
            return *this;
        }

    private:
        static constexpr byte getHexDigitValue(char hexDigit) noexcept {
            if (hexDigit >= '0' && hexDigit <= '9')
                return hexDigit - '0';
            if (hexDigit >= 'A' && hexDigit <= 'F')
                return hexDigit - 'A' + 10u;
            if (hexDigit >= 'a' && hexDigit <= 'f')
                return hexDigit - 'a' + 10u;
            return 0;
        }
    };

    template<KeySize size>
    using IV = Key<size>;
}

template <crypto::KeySize size>
crypto::Key<size> crypto::Key<size>::getRandom() noexcept {
    srand(time(nullptr));
    Key <size> key;
    for ( auto i = 0; i < static_cast < std::size_t > ( size ); i++ ) {
        key[i] = rand()%256;
    }

    return key;
}

template < crypto::KeySize size >
crypto::Key<size> crypto::Key<size>::getFromHex(const char *pHexData) noexcept {
    auto byteSize = static_cast < std::size_t > ( size );
    byte buffer [ byteSize + 1 ];

    auto originalLength = static_cast < std::size_t > ( std::strlen ( pHexData ) );
    auto len = originalLength / 2;

    for ( std::size_t i = 0, length = std::min ( len, byteSize ); i < length; i++ ) {
        buffer [ i ] =
                ( static_cast < byte > ( ( getHexDigitValue( pHexData [ 2 * i ] ) << 4u ) ) & 0xF0u ) +
                ( ( 2 * i + 1 < originalLength ) ? ( ( getHexDigitValue( pHexData [ 2 * i + 1 ] ) ) & 0x0Fu ) : 0 );
    }

    if ( len < static_cast < uint32 > ( byteSize ) && originalLength % 2 == 1 )
        buffer[ len ++ ] = static_cast < byte > ( static_cast < byte > ( getHexDigitValue( pHexData [ originalLength - 1 ] ) << 4u ) & 0xF0u );

    for (; len < static_cast < uint32 > ( byteSize ); len++ )
        buffer [ len ] = 0x00u;

    return Key ( buffer, byteSize );
}



#endif //SI_T1_KEY_H
