//
// Created by loghin on 01.11.2020.
//

#ifndef SI_T1_SERVERSOCKET_H
#define SI_T1_SERVERSOCKET_H

#include <Socket.h>
class ServerSocket : public Socket {
public:

    constexpr static uint32 DEFAULT_QUEUE_SIZE = 2048u;

    class BindException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "Fail on Bind";
        }
    };

    class SetSocketOptionException : public Socket::Exception {
    public:
        [[nodiscard]] const char * what() const noexcept override {
            return "Fail on SetSockOpt";
        }
    };

    class ListenException : public Socket::Exception {
        [[nodiscard]] const char * what() const noexcept override {
            return "Fail on listen";
        }
    };

    ServerSocket () noexcept = delete;
    explicit ServerSocket ( uint16, uint32 = ServerSocket::DEFAULT_QUEUE_SIZE ) noexcept (false);
    ~ServerSocket() noexcept = default;

    Socket accept () noexcept;
};


#endif //SI_T1_SERVERSOCKET_H
