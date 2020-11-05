//
// Created by loghin on 01.11.2020.
//

#ifndef SI_T1_SOCKET_H
#define SI_T1_SOCKET_H

#include <exception>
#include <string>
#include <types.h>
#include <iostream>
#include <CryptoManager.h>

class Socket {
private:
    constexpr static int SOCKET_DISCONNECT = 0;
    constexpr static int SOCKET_ERROR = -1;

    class SocketDebug {
        friend class Socket;
    private:
        bool            _debugToggle     {false};
        std::ostream *  _debugBuffer     { & std::clog};

        SocketDebug () noexcept = default;

        static SocketDebug _instance;

    public:
        static const SocketDebug & getInstance () noexcept;// { return SocketDebug::_instance; }

        const SocketDebug & operator << ( const std::string & str ) const noexcept;
        const SocketDebug & operator << ( const char * ) const noexcept;
        const SocketDebug & operator << ( char ) const noexcept;
        const SocketDebug & operator << ( std::size_t ) const noexcept;
        const SocketDebug & operator << ( int ) const noexcept;

        void setDebugOutputBuffer ( std::ostream & ) noexcept;

        void initDebug () const noexcept {
            (*this->_debugBuffer) << "[ SOCKET ] init debug : \n";
        }

        SocketDebug & enableDebug ( ) noexcept {
            if ( ! this->_debugToggle) {
                this->initDebug ();
            }

            this->_debugToggle = true;
            return * this;
        }

        SocketDebug & disableDebug () noexcept {
            this->_debugToggle = false;
            this->_debugBuffer->clear();

            return * this;
        }
    };

    struct {
        bool                                    _isEncrypted{false};
        crypto128::CryptoManager::EncryptMode   _encryptionMode{crypto128::CryptoManager::EncryptMode::ECB};
        crypto128::Key                          _encryptionKey;
        crypto128::IV                           _encryptionIV;
    } _encryptionDetails;

    [[nodiscard]] std::string encrypt ( const std::string & ) const noexcept;
    [[nodiscard]] std::string decrypt ( const std::string & ) const noexcept;

protected:
    constexpr static int CLOSED_DESCRIPTOR = -1;

    int _descriptor     { Socket::CLOSED_DESCRIPTOR };
    int _exceptionFlags { Socket::noExcept };

    [[nodiscard]] constexpr bool isOpen () const noexcept { return this->_descriptor != CLOSED_DESCRIPTOR; }
    [[nodiscard]] constexpr bool isClosed () const noexcept { return this->_descriptor == CLOSED_DESCRIPTOR; }

public:
    class Exception : public std::exception { };

    class DisconnectException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "Socket end disconnected";
        }
    };

    class ErrorException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "Socket read/write error";
        }
    };

    class BadByteBufferingException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "When reading or writing, could not read/write all requested bytes";
        }
    };

    class ClosedException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "Socket closed. First open the socket, then read/write from it.";
        }
    };

    typedef byte ExceptionFlags;
    typedef byte ExceptionFlagBits;

    constexpr static ExceptionFlags    noExcept = 0x00;
    constexpr static ExceptionFlagBits eDisconnect = 0x01;
    constexpr static ExceptionFlagBits eError = 0x02;
    constexpr static ExceptionFlagBits eBadByteBuffering = 0x04;
    constexpr static ExceptionFlagBits eClosed = 0x08;


public:
    Socket ( const Socket & obj ) noexcept :
            _descriptor(obj._descriptor),
            _exceptionFlags(obj._exceptionFlags){
        Socket::debug() << "Copied Socket ( 0x" << reinterpret_cast < std::size_t > ( this ) << " )\n";
    }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    Socket ( const Socket && obj ) noexcept :
            _descriptor(obj._descriptor),
            _exceptionFlags(obj._exceptionFlags){
        Socket::debug() << "Copied Socket ( 0x" << reinterpret_cast < std::size_t > ( this ) << " )\n";
    }
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    explicit Socket ( int descriptor, Socket::ExceptionFlags exceptionFlags = Socket::eError ) noexcept :
            _descriptor ( descriptor ),
            _exceptionFlags ( exceptionFlags ){
        Socket::debug() << "Copied Socket by Params ( 0x" << reinterpret_cast < std::size_t > ( this ) << " )\n";
    }
#pragma clang diagnostic pop

    static void enableDebug ( std::ostream & outputBuffer = std::clog ) noexcept {
        Socket::SocketDebug::_instance.setDebugOutputBuffer( outputBuffer );
        Socket::SocketDebug::_instance.enableDebug();
    }

    static void disableDebug () noexcept {
        Socket::SocketDebug::_instance.disableDebug();
    }

    static const SocketDebug & debug() noexcept {
        Socket::SocketDebug::_instance._debugBuffer->flush();
        return Socket::SocketDebug::getInstance();
    }

    explicit Socket ( Socket::ExceptionFlags = Socket::eError ) noexcept;

    ~Socket (  ) noexcept;

    Socket & open (  ) noexcept;
    Socket & close (  ) noexcept;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    Socket & setExceptionFlags ( Socket::ExceptionFlags flags ) noexcept {
        this->_exceptionFlags = flags;
        return * this;
    }
#pragma clang diagnostic pop

    Socket & enableExceptions ( Socket::ExceptionFlags flags ) noexcept {
        this->_exceptionFlags |= flags; // NOLINT(hicpp-signed-bitwise)
        return * this;
    }

    Socket & disableExceptions ( Socket::ExceptionFlags flags ) noexcept {
        this->_exceptionFlags &= ~flags; // NOLINT(hicpp-signed-bitwise)
        return * this;
    }

    Socket & operator >> ( std::string & ) noexcept (false);
    Socket & operator << ( const std::string & ) noexcept (false);

    Socket & operator = ( const Socket & obj ) noexcept {
        if ( this == & obj )
            return * this;

        this->_descriptor           = obj._descriptor;
        this->_exceptionFlags       = obj._exceptionFlags;
        this->_encryptionDetails    = obj._encryptionDetails;
        return * this;
    }

    Socket & enableEncryption (
            crypto128::CryptoManager::EncryptMode mode,
            const crypto128::Key & key,
            const crypto128::IV & iv
    ) noexcept {
        this->_encryptionDetails = {
                ._isEncrypted       = true,
                ._encryptionMode    = mode,
                ._encryptionKey     = key,
                ._encryptionIV      = iv
        };

        return * this;
    }

    Socket & disableEncryption (  ) noexcept {
        this->_encryptionDetails = {
                ._isEncrypted       = false,
                ._encryptionMode    = crypto128::CryptoManager::EncryptMode::ECB,
                ._encryptionKey     = crypto128::Key(),
                ._encryptionIV      = crypto128::IV()
        };

        return * this;
    }
};


#endif //SI_T1_SOCKET_H

#include <ServerSocket.h>
#include <ClientSocket.h>