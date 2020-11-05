//
// Created by loghin on 04.11.2020.
//

#include "KeyManager.h"

KeyManager KeyManager::_instance;

crypto128::Key KeyManager::_dummyKey1 = crypto128::Key::getFromHex( "102132435465768798a9bacbdcedfef1" );
crypto128::Key KeyManager::_dummyKey2 = crypto128::Key::getFromHex( "00112233445566778899aabbccddeeff" );
crypto128::Key KeyManager::_dummyKey3 = crypto128::Key::getFromHex( "eeffccddaabb88996677445522330011" );

KeyManager & KeyManager::getInstance() noexcept {
    return KeyManager::_instance;
}

const crypto128::Key & KeyManager::getK1() noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key1AtomicGuard );
    return this->_k1;
}

const crypto128::Key & KeyManager::getK2() noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key2AtomicGuard );
    return this->_k2;
}

const crypto128::Key & KeyManager::getK3() noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key3AtomicGuard );
    return this->_k3;
}

KeyManager & KeyManager::setK1(const crypto128::Key & key) noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key1AtomicGuard );
    this->_k1 = key;
    return * this;
}

KeyManager & KeyManager::setK2(const crypto128::Key & key) noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key2AtomicGuard );
    this->_k2 = key;
    return * this;
}

KeyManager & KeyManager::setK3(const crypto128::Key & key) noexcept {
    const std::lock_guard < std::mutex > keyAtomicLock ( this->_key3AtomicGuard );
    this->_k3 = key;
    return * this;
}

#include <fstream>
#include <iostream>

KeyManager & KeyManager::loadKeys ( const char * pFilePath ) noexcept {
    try {
        std::ifstream keysFile;
        keysFile.open(pFilePath);

        std::string key1String;
        std::string key2String;
        std::string key3String;

        keysFile >> key1String >> key2String >> key3String;

        this->setK1( crypto128::Key::getFromHex( key1String.c_str() ) );
        this->setK2( crypto128::Key::getFromHex( key2String.c_str() ) );
        this->setK3( crypto128::Key::getFromHex( key3String.c_str() ) );

        keysFile.close();
    } catch ( std::exception const & exception ) {
        std::cerr << exception.what() << " upon reading keys from file\n";
    }

    return * this;
}


