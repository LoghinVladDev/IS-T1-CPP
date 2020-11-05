//
// Created by loghin on 04.11.2020.
//


#include <iostream>
#include <Socket.h>
#include <vector>
#include <thread>
#include <defs.h>
#include <pthread.h>
#include <ServerThread.h>
#include <Semaphore.h>
#include <KeyManager.h>

class Server {
private:
//    std::vector < std::thread > _threads;
    std::thread                 _threadNodeA;
    std::thread                 _threadNodeB;
    ServerSocket                _serverSocket;
    std::ostream &              _logChannel;
    bool                        _enableDebug;

    BinarySemaphore             _nodeASync {BinarySemaphore(0, 0)};
    BinarySemaphore             _nodeBSync {BinarySemaphore(0, 0)};

public:
    Server() noexcept = delete;
    explicit Server ( uint16 port, bool enableDebug = false, std::ostream & logChannel = std::clog ) noexcept :
        _serverSocket ( ServerSocket ( port ) ),
        _logChannel(logChannel),
        _enableDebug(enableDebug){

    }

    ~Server () noexcept {
//        pthread_cancel ( this->_threadNodeA.native_handle() );
//        pthread_cancel ( this->_threadNodeB.native_handle() );
        _serverSocket.close();
//        exit(0);
    }

    int run() noexcept(false);


//    static void controlThread ( Server * instanceControlled ) noexcept {
//        std::string command;
//
//        while ( true ) {
//            std::cout << "Input Server Admin Command : ";
//            std::cin >> command;
//
//            if ( command == "quit" ) {
//                instanceControlled->~Server();
//                return;
//            }
//        }
//    }


};

int main () {
    try {
        return Server ( PORT, true ).run();
    } catch ( std::exception const & exception ) {
        std::cerr << "Exception caught in application base runtime : " << exception.what() << '\n';
    }

    return 1;
}

int Server::run() noexcept(false) {
//    std::thread controlThread ( Server::controlThread, this );

    if ( this->_enableDebug )
        Socket::enableDebug( _logChannel );

    try {
        auto nodeA = new ServerThread ( this->_serverSocket.accept(), ServerThread::NODE_A, this->_nodeASync );
        this->_threadNodeA = std::thread ( ServerThread::startThread, nodeA );

        auto nodeB = new ServerThread ( this->_serverSocket.accept(), ServerThread::NODE_B, this->_nodeBSync );

        this->_threadNodeB = std::thread ( ServerThread::startThread, nodeB );

        this->_nodeASync.getTo().wait();
        this->_nodeBSync.getTo().wait();

        std::cout << "Threads Started\n";

        this->_nodeASync.getTo().wait();
        this->_nodeBSync.getTo().wait();

        std::cout << "Mode A : " << nodeA->getEncryptMode() << " ...Mode B : " << nodeB->getEncryptMode() << '\n';

        srand(time(nullptr));

        if (    nodeA->getEncryptMode() != nodeB->getEncryptMode() ||
                (   nodeA->getEncryptMode() == nodeB->getEncryptMode() &&
                    (   nodeA->getEncryptMode() == crypto::CryptoManager<crypto::BITS_128>::CBC ||
                        nodeA->getEncryptMode() == crypto::CryptoManager<crypto::BITS_128>::OFB
                    )
                )
            )
        {
            int modeNumber = rand()%2;
            crypto128::CryptoManager::EncryptMode encryptMode;
            if ( modeNumber == 0 ) {
                encryptMode = crypto128::CryptoManager::ECB;
            } else {
                encryptMode = crypto128::CryptoManager::CFB;
            }

            nodeA->setEncryptionMode( encryptMode );
            nodeB->setEncryptionMode( encryptMode );
        }

        this->_nodeASync.getFrom().notify();
        this->_nodeBSync.getFrom().notify();

        this->_nodeASync.getTo().wait();
        this->_nodeBSync.getTo().wait();

        std::cout << "Mode/Key/IV sent\n";

        this->_threadNodeA.join();
        this->_threadNodeB.join();
//        controlThread.join();

    } catch ( Socket::Exception const & exception ) {
        std::cerr << "Exception Caught on Server runtime : " << exception.what() << '\n';
    }

    return 0;
}
