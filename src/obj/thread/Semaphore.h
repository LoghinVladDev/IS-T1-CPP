//
// Created by loghin on 05.11.2020.
//

#ifndef SI_T1_SEMAPHORE_H
#define SI_T1_SEMAPHORE_H

#include <mutex>
#include <condition_variable>

class Semaphore {
private:
    int                     _count;
    std::mutex              _lock;
    std::condition_variable _conditionVariable;
public:
    explicit Semaphore ( int count = 0 ) noexcept : _count ( count ) { }

    inline void notify () {
        std::unique_lock < std::mutex > lock ( this->_lock );
        this->_count++;
        this->_conditionVariable.notify_one();
    }

    inline void wait () {
        std::unique_lock < std::mutex > lock ( this->_lock );
        while ( this->_count == 0 ) {
            this->_conditionVariable.wait ( lock );
        }

        this->_count--;
    }
};

class BinarySemaphore {
private:
    Semaphore _from {Semaphore(0)};
    Semaphore _to   {Semaphore(0)};
public:
    BinarySemaphore ( int _countFrom, int _countTo ) noexcept :
        _from ( Semaphore(_countFrom) ),
        _to ( Semaphore(_countTo) ) {

    }

    BinarySemaphore() noexcept = default;

    Semaphore & getFrom () noexcept {
        return this->_from;
    }

    Semaphore & getTo () noexcept {
        return this->_to;
    }
};


#endif //SI_T1_SEMAPHORE_H
