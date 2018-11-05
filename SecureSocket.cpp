#include "SecureSocket.h"

DWORD SecureSocket::SocketProcess(LPVOID param) { //(WorkerThread)
	SecureSocket *mSocket = reinterpret_cast<SecureSocket*>(param);
	DWORD EventID;

	while (mSocket->m_connected != FALSE)
	{
		//EventID = WaitForSingleObject(mSocket->events[0], INFINITE);
		//mSocket->SocketAPCProcess(param, EventID);
	}

	return 0;
}

void SecureSocket::SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials)
{
	schannelcredentials.dwVersion = SCHANNEL_CRED_VERSION;
	schannelcredentials.grbitEnabledProtocols = protocol;
	schannelcredentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	schannelcredentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
}

void SecureSocket::Connect(std::string serv, std::string sec_serv, UINT16 serv_port)
{
	//are we trying to connect an already open socket?
	if (this->mySocket != INVALID_SOCKET) { 
		//clean up secure bits...
		//
		//clean up old socket
		closesocket(this->mySocket); 
		this->m_connected = FALSE; 
		this->mySocket = INVALID_SOCKET; 
	}

	ServerAddress = serv;
	ServerSecAddress = sec_serv;
	port = serv_port;

	int iResult = getaddrinfo(this->ServerAddress.c_str(), std::to_string(this->port).c_str(), &hints, &result);
	if (iResult != 0) { 
		//this->Error("getaddrinfo failed.", true); //TODO: Event
		return; 
	}
	ptr = result;
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		//this->AttemptingConnectionTo(ptr); //TODO: Event

		this->mySocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (this->mySocket == INVALID_SOCKET) {
			continue;
		}
		iResult = connect(this->mySocket, ptr->ai_addr, (int)(ptr->ai_addrlen));
		if (iResult != SOCKET_ERROR)
		{
			break; //break the for loop were connected
		}
		else {
			closesocket(this->mySocket);
			this->mySocket = INVALID_SOCKET;
		}
	}
	freeaddrinfo(result);

	if (this->mySocket == INVALID_SOCKET)
	{
		//connection failed
		//this->Error("Server connection Failed!", true); //TODO: Event
	}
	else {
		//we connected
		this->m_connected = true;
		time(&this->m_connecteddate);
		//Connected(); //TODO: Event
	}
}
