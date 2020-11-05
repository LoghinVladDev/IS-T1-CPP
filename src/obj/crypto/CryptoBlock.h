//
// Created by loghin on 02.11.2020.
//

#ifndef SI_T1_CRYPTOBLOCK_H
#define SI_T1_CRYPTOBLOCK_H

#include <types.h>
#include <cstring>
#include <algorithm>
#include <string>
#include <list>

namespace crypto {

    typedef enum : byte {
        BITS_64 = 8,
        BITS_128 = 16,
        BITS_256 = 32,
        BITS_512 = 64
    } BlockSize;

    template<BlockSize byteSize>
    class CryptoBlock {
    private:
        byte _data[byteSize + 1];
        byte _padData{' '};

    public:
        explicit CryptoBlock(byte padData = ' ') noexcept: _padData(padData) {// NOLINT(cppcoreguidelines-pro-type-member-init)
            std::memset(this->_data, this->_padData, static_cast < std::size_t > ( byteSize ));
            this->_data[static_cast < std::size_t > ( byteSize )] = '\0';
        }

        CryptoBlock(CryptoBlock<byteSize> const &&block) noexcept { // NOLINT(cppcoreguidelines-pro-type-member-init)
            std::memcpy(this->_data, block._data, static_cast < std::size_t > ( byteSize ) + 1);
        }

        CryptoBlock(CryptoBlock<byteSize> const &block) noexcept { // NOLINT(cppcoreguidelines-pro-type-member-init)
            std::memcpy(this->_data, block._data, static_cast < std::size_t > ( byteSize ) + 1);
        }

        explicit CryptoBlock(const byte *pData, std::size_t dataSize,byte padData = ' ') noexcept { // NOLINT(cppcoreguidelines-pro-type-member-init)
            std::memcpy(this->_data, pData, std::min(dataSize, static_cast < std::size_t > ( byteSize )));

            if (dataSize < static_cast < std::size_t > ( byteSize ))
                std::memset(this->_data + dataSize, padData, static_cast < std::size_t > ( byteSize ) - dataSize);
            this->_data[static_cast < std::size_t > ( byteSize )] = 0;
        }

        explicit CryptoBlock(const char *pData,byte padData = ' ') noexcept { // NOLINT(cppcoreguidelines-pro-type-member-init)
            auto dataSize = static_cast < std::size_t > ( std::strlen(pData));
            std::memcpy(this->_data, pData, std::min(dataSize, static_cast < std::size_t > ( byteSize )));

            if (dataSize < static_cast < std::size_t > ( byteSize ))
                std::memset(this->_data + dataSize, padData, static_cast < std::size_t > ( byteSize ) - dataSize);

            this->_data[static_cast < std::size_t > ( byteSize )] = 0;
        }

        CryptoBlock<byteSize> &setPadData(byte padData) noexcept {
            this->_padData = padData;
            return *this;
        }

        [[nodiscard]] const byte *data() const noexcept {
            return this->_data;
        }

        CryptoBlock<byteSize> &operator=(const CryptoBlock<byteSize> &block) noexcept {
            if (this == &block)
                return *this;

            std::memcpy(this->_data, block._data, static_cast < std::size_t > ( byteSize ) + 1);
            return *this;
        }

        CryptoBlock<byteSize> &setData(const CryptoBlock<byteSize> &block) noexcept {
            return (*this = block);
        }

        CryptoBlock<byteSize> &setData(const byte *pData, std::size_t dataSize, byte padData = ' ') noexcept {
            std::memcpy(this->_data, pData, std::min(dataSize, static_cast < std::size_t > ( byteSize )));

            if (dataSize < static_cast < std::size_t > ( byteSize ))
                std::memset(this->_data + dataSize, padData, static_cast < std::size_t > ( byteSize ) - dataSize);
            this->_data[static_cast < std::size_t > ( byteSize )] = 0;
            return *this;
        }

        friend CryptoBlock<byteSize>
        operator ^ (const CryptoBlock<byteSize> &a, const CryptoBlock<byteSize> &b) noexcept {
            CryptoBlock<byteSize> result;

            for (std::size_t i = 0; i < static_cast < std::size_t > ( byteSize ); i++)
                result[i] = a[i] ^ b[i];
            return result;
        }

        [[nodiscard]] std::string toString() const noexcept {
            return static_cast < std::basic_string<char> > ( *this );
        }

        explicit operator std::basic_string<char>() const noexcept {
            return std::basic_string<char>("{ size = ").append(
                    std::to_string(static_cast < std::size_t > ( byteSize ))).append(", data = '").append(
                    reinterpret_cast < const char * > (this->_data)).append("'}");
        }

        friend std::ostream &operator<<(std::ostream &buffer, const CryptoBlock<byteSize> &object) noexcept {
            return buffer << static_cast < std::string > ( object );
        }

        byte operator[](int index) const noexcept {
            if (index < 0)
                index += ((0 - index) / static_cast < int > ( byteSize ) + 1) * static_cast < int > ( byteSize );

            return this->_data[index % static_cast < std::size_t > ( byteSize )];
        }

        byte &operator[](int index) noexcept {
            if (index < 0)
                index += ((0 - index) / static_cast < int > ( byteSize ) + 1) * static_cast < int > ( byteSize );

            return this->_data[index % static_cast < std::size_t > ( byteSize )];
        }

        [[nodiscard]] std::string toHexString() const noexcept;

        static std::list<CryptoBlock<byteSize> > split(const char *) noexcept;
    };

}

#include <iomanip>
#include <sstream>

template<crypto::BlockSize size>
std::string crypto::CryptoBlock<size>::toHexString() const noexcept {
    std::stringstream stream;

    stream << "{ block = ";
    for (std::size_t i = 0; i < static_cast < std::size_t > ( size ); i++)
        stream << std::hex << std::setfill('0') << std::setw(2) << static_cast < uint32 > ( this->data()[i] )
               << ' ';
    stream << " }";
    return stream.str();
}

template<crypto::BlockSize byteSize>
std::list<crypto::CryptoBlock<byteSize> > crypto::CryptoBlock<byteSize>::split(const char *pText) noexcept {
    std::size_t length = strlen(pText);
    std::list<CryptoBlock<byteSize> > list;

    for (std::size_t i = 0, count = length / static_cast < std::size_t > ( byteSize ); i < count; i++) {
        list.emplace_back(pText + i * static_cast < std::size_t > ( byteSize ));
    }

    if (length % static_cast < std::size_t > ( byteSize ) != 0)
        list.emplace_back(pText + length - length % 16);

    return list;
}

#endif //SI_T1_CRYPTOBLOCK_H
