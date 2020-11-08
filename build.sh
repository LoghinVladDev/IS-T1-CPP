mkdir build
g++-10 src/obj/NodeA.cpp src/obj/crypto/*.cpp src/obj/comm/*.cpp -I ./src/ -I ./src/obj/crypto/ -I ./src/obj/comm/ -I ./src/obj/thread/ -I ./src/obj/ -std=c++20 -lcrypto -lssl -lpthread
g++-10 src/obj/NodeB.cpp src/obj/crypto/*.cpp src/obj/comm/*.cpp -I ./src/ -I ./src/obj/crypto/ -I ./src/obj/comm/ -I ./src/obj/thread/ -I ./src/obj/ -std=c++20 -lcrypto -lssl -lpthread
g++-10 src/obj/Server.cpp src/obj/crypto/*.cpp src/obj/comm/*.cpp src/obj/thread/*.cpp src/obj/ServerThread.cpp src/obj/KeyManager.cpp -I ./src/ -I ./src/obj/crypto/ -I ./src/obj/comm/ -I ./src/obj/thread/ -I ./src/obj/ -std=c++20 -lcrypto -lssl -lpthread
