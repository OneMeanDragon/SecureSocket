#include "SecureSocket.h"

SecureSocket mySecure;

#define SERVER_ADDRESS "connect-bot.classic.blizzard.com"
#define SEC_ADDRESS "*.classic.blizzard.com"

int CALLBACK WinMain(HINSTANCE currentinstance, HINSTANCE previousinstance, LPSTR BS1, int BS2) {

	mySecure.Connect(SERVER_ADDRESS, SEC_ADDRESS, (UINT16)443);

	while (true) {} //(only here for debug output reading)

	WSACleanup();
	return 0;
}
