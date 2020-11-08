//
// Created by loghin on 04.11.2020.
//

#ifndef SI_T1_KEYMANAGER_H
#define SI_T1_KEYMANAGER_H

#include <CryptoManager.h>
#include <mutex>

class KeyManager {

private:
    static KeyManager _instance;

    static crypto128::Key _dummyKey1;
    static crypto128::Key _dummyKey2;
    static crypto128::Key _dummyKey3;

    std::mutex _key1AtomicGuard;
    std::mutex _key2AtomicGuard;
    std::mutex _key3AtomicGuard;

    crypto128::Key _k1 { KeyManager::_dummyKey1 };
    crypto128::Key _k2 { KeyManager::_dummyKey2 };
    crypto128::Key _k3 { KeyManager::_dummyKey3 };

    crypto128::Key _iv { crypto128::IV::getRandom() };

    KeyManager() noexcept = default;

public:
    static KeyManager & getInstance () noexcept;

    const crypto128::Key & getK1() noexcept;
    const crypto128::Key & getK2() noexcept;
    const crypto128::Key & getK3() noexcept;

    const crypto128::IV & getIV () noexcept;

    KeyManager & setK1 ( const crypto128::Key & ) noexcept;
    KeyManager & setK2 ( const crypto128::Key & ) noexcept;
    KeyManager & setK3 ( const crypto128::Key & ) noexcept;

    KeyManager & loadKeys ( const char * ) noexcept;
};


#endif //SI_T1_KEYMANAGER_H
