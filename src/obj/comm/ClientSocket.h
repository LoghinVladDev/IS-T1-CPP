//
// Created by loghin on 01.11.2020.
//

#ifndef SI_T1_CLIENTSOCKET_H
#define SI_T1_CLIENTSOCKET_H

#include <Socket.h>
class ClientSocket : public Socket {
private:
    std::string _connectedIP    { std::string() };
    uint16 _port                { 0 };

public:
    ClientSocket (  ) noexcept = default;

    explicit ClientSocket ( const char *, uint16 ) noexcept;
    explicit ClientSocket ( const std::string &, uint16 ) noexcept;

    ClientSocket & connect ( const char *, uint16 ) noexcept;
    ClientSocket & connect ( const std::string &, uint16 ) noexcept;

    ClientSocket & disconnect () noexcept {
        this->_port = 0;
        this->_connectedIP.clear();
        this->close().open();
        return *this;
    }

    [[nodiscard]] constexpr bool isConnected () const noexcept {
        return this->isOpen() && ! this->_connectedIP.empty();
    }

    ~ClientSocket() noexcept;
};


#endif //SI_T1_CLIENTSOCKET_H
