//
// Created by loghin on 04.11.2020.
//

#ifndef SI_T1_SERVERTHREAD_H
#define SI_T1_SERVERTHREAD_H

#include <Socket.h>

#include <utility>
#include <Semaphore.h>

class ServerThread {
public:
    typedef enum {
        NODE_A,
        NODE_B
    } Node;
private:
    Socket      _socket;
    Node        _associatedNode;
    BinarySemaphore & _semaphore;

    crypto128::CryptoManager::EncryptMode _encryptMode { crypto128::CryptoManager::ECB };
    crypto128::Key _key;
    crypto128::IV _iv;

public:
    ServerThread() noexcept = delete;
    explicit ServerThread ( Socket socket, Node associatedNode, BinarySemaphore & semaphore ) noexcept : // NOLINT(performance-unnecessary-value-param)
        _socket(std::move(socket)), // NOLINT(performance-move-const-arg)
        _associatedNode(associatedNode),
        _semaphore ( semaphore ){

    }

    [[nodiscard]] crypto128::CryptoManager::EncryptMode getEncryptMode () const noexcept {
        return this->_encryptMode;
    }

    void setEncryptionMode ( crypto128::CryptoManager::EncryptMode mode ) noexcept {
        this->_encryptMode = mode;
    }

    void run() noexcept;

    static void startThread ( ServerThread * pServerThread ) noexcept {
        pServerThread->run();

        delete pServerThread;
    }
};


#endif //SI_T1_SERVERTHREAD_H
