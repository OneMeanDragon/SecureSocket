#include "SecureSocket.h"

DWORD SecureSocket::SocketProcess(LPVOID param) { //(WorkerThread)
	SecureSocket *mSocket = reinterpret_cast<SecureSocket*>(param);
	DWORD EventID;

	while (mSocket->SckDat.m_connected != FALSE)
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
	if (this->SckDat.mySocket != INVALID_SOCKET) {
		//clean up secure bits...
		//
		//clean up old socket
		closesocket(this->SckDat.mySocket);
		this->SckDat.m_connected = FALSE;
		this->SckDat.mySocket = INVALID_SOCKET;
		//Re initalize the secure bits
		//

		//Or just return a message saying were already connected, force them to disconnect.
		//this->Error("We are already connected, try disconnecting first.", false); //TODO: Event
		//return;
	}

	ServerAddress = serv;
	ServerSecAddress = sec_serv;
	port = serv_port;

	int iResult = getaddrinfo(this->ServerAddress.c_str(), std::to_string(this->port).c_str(), &SckDat.hints, &SckDat.result);
	if (iResult != 0) { 
		//this->Error("getaddrinfo failed.", true); //TODO: Event
		return; 
	}
	SckDat.ptr = SckDat.result;
	for (SckDat.ptr = SckDat.result; SckDat.ptr != NULL; SckDat.ptr = SckDat.ptr->ai_next)
	{
		//this->AttemptingConnectionTo(ptr); //TODO: Event

		this->SckDat.mySocket = socket(SckDat.ptr->ai_family, SckDat.ptr->ai_socktype, SckDat.ptr->ai_protocol);
		if (this->SckDat.mySocket == INVALID_SOCKET) {
			continue;
		}
		iResult = connect(this->SckDat.mySocket, SckDat.ptr->ai_addr, (int)(SckDat.ptr->ai_addrlen));
		if (iResult != SOCKET_ERROR)
		{
			break; //break the for loop were connected
		}
		else {
			closesocket(this->SckDat.mySocket);
			this->SckDat.mySocket = INVALID_SOCKET;
		}
	}
	freeaddrinfo(SckDat.result);

	if (this->SckDat.mySocket == INVALID_SOCKET)
	{
		//connection failed
		//this->Error("Server connection Failed!", true); //TODO: Event
	}
	else {
		//we connected
		this->SckDat.m_connected = true;
		time(&this->m_connecteddate);
		//Connected(); //TODO: Event
	}
	PerformHandshake();
}

void SecureSocket::PerformHandshake(void)
{
	SChanDat.OutBuffers[0].pvBuffer = 0;
	SChanDat.OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	SChanDat.OutBuffers[0].cbBuffer = 0;

	SChanDat.OutBuffer.cBuffers = 1;
	SChanDat.OutBuffer.pBuffers = SChanDat.OutBuffers;
	SChanDat.OutBuffer.ulVersion = SECBUFFER_VERSION;

	SECURITY_STATUS scRet = SChanDat.schannel->InitializeSecurityContextA(
		&SChanDat.m_cc,
		0,
		(SEC_CHAR *)ServerSecAddress.c_str(),
		SChanDat.sspiflags,
		0,
		SECURITY_NATIVE_DREP,
		0,
		0,
		&SChanDat.contexthandle,
		&SChanDat.OutBuffer,
		&SChanDat.sspioutflags,
		0
	);
	if (scRet != SEC_I_CONTINUE_NEEDED)
		MessageBox(0, "Error Initializing Security Context", "Message", MB_TASKMODAL | MB_OK);
	else
		MessageBox(0, "Security Context Initialized", "Message", MB_TASKMODAL | MB_OK);


	MessageBox(0, "Done", "Message", MB_TASKMODAL | MB_OK);

}
