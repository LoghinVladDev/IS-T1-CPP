//
// Created by loghin on 01.11.2020.
//

#ifndef SI_T1_CRYPTOOBJECT_H
#define SI_T1_CRYPTOOBJECT_H

#include <CryptoBlock.h>
#include <Key.h>

namespace crypto {

    template<BlockSize size>
    class CryptoObject {
    protected:

        Key<size> _key;
        IV<size> _iv;
        CryptoBlock<size> _input;
        CryptoBlock<size> _output;

    public:
        CryptoObject() noexcept = default;

        CryptoObject &setKey(const CryptoBlock<size> &block) noexcept {
            this->_key.setData(block);
            return *this;
        }

        CryptoObject &setIV(const CryptoBlock<size> &block) noexcept {
            this->_iv.setData(block);
            return *this;
        }

        CryptoObject &setInput(const CryptoBlock<size> &input) noexcept {
            this->_input = input;
            return *this;
        }

        const Key<size> &getKey() const noexcept { return this->_key; }
        const IV<size> &getIV() const noexcept { return this->_iv; }
        const CryptoBlock<size> &getInput() const noexcept { return this->_input; }
        const CryptoBlock<size> &getOutput() const noexcept { return this->_output; }

        explicit virtual operator std::basic_string<char>() const noexcept {
            return std::string("{ input = ").append(this->_input.toString()).append(", output = ")
                    .append(this->_output.toString()).append(", key = ").append(this->_key.toHexString())
                    .append(", iv = ").append(this->_iv.toHexString()).append(" }");
        }

        [[nodiscard]] std::string toString() const noexcept { return static_cast < std::basic_string<char> > ( *this ); }

        friend std::ostream &operator<<(std::ostream &buffer, const CryptoObject<size> &object) noexcept { return buffer << static_cast < std::string > ( object ); }

        virtual CryptoObject &run() noexcept = 0;
    };

    typedef std::size_t ( *FunctionPtrCrypto )(const byte *, std::size_t, const byte *, const byte *, byte *) noexcept;

    FunctionPtrCrypto getEncryptFunction() noexcept;
    FunctionPtrCrypto getDecryptFunction() noexcept;

    template<BlockSize size>
    class Encryptor : public CryptoObject<size> {
    public:
        Encryptor() noexcept = default;

        Encryptor &run() noexcept {

            byte cipherTextBuffer[static_cast < std::size_t > ( size )];
            memset(cipherTextBuffer, 0, sizeof(cipherTextBuffer));

            std::size_t cipherTextLength = getEncryptFunction()(
                    this->_input.data(),
                    static_cast < std::size_t > ( size ),
                    this->_key.data(),
                    this->_iv.data(),
                    cipherTextBuffer
            );

            this->_output.setData(cipherTextBuffer, cipherTextLength);

            return *this;
        }

        explicit operator std::string() const noexcept {
            return std::string("{ Encryptor = ").append(CryptoObject<size>::operator std::basic_string<char>()).append(
                    " }");
        }
    };

    template<BlockSize size>
    class Decryptor : public CryptoObject<size> {
    public:
        Decryptor() noexcept = default;

        Decryptor &run() noexcept {

            byte plainTextBuffer[static_cast < std::size_t > ( size ) + 1];
            memset(plainTextBuffer, 0, sizeof(plainTextBuffer));

            std::size_t plainTextLength = getDecryptFunction()(
                    this->_input.data(),
                    static_cast < std::size_t > ( size ),
                    this->_key.data(),
                    this->_iv.data(),
                    plainTextBuffer
            );

            plainTextBuffer[static_cast < std::size_t > ( size )] = 0;
            this->_output.setData(plainTextBuffer, plainTextLength);

            return *this;
        }

        explicit operator std::string() const noexcept {
            return std::string("{ Decryptor = ").append(CryptoObject<size>::operator std::basic_string<char>()).append(
                    " }");
        }
    };

}


#endif //SI_T1_CRYPTOOBJECT_H
