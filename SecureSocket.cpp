#include "SecureSocket.h"

DWORD SecureSocket::SocketProcess(LPVOID param) { //(WorkerThread)
	SecureSocket *mSocket = reinterpret_cast<SecureSocket*>(param);
	DWORD EventID;

	while (mSocket->SckDat.m_connected != FALSE)
	{
		EventID = WaitForSingleObject(mSocket->SckDat.events[0], INFINITE);
		mSocket->SocketAPCProcess(param, EventID);
	}

	return 0;
}

BOOL getSysVersionInfo(OSVERSIONINFOEX &osInfo)
{
	NTSTATUS(WINAPI *RtlGetVersion)(LPOSVERSIONINFOEX);

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		return TRUE;
	}
	return FALSE;
}

bool SecureSocket::LoadSecurityModule(void)
{
	INIT_SECURITY_INTERFACE pInitSecurityInterface;
	//  QUERY_CREDENTIALS_ATTRIBUTES_FN pQueryCredentialsAttributes;
	OSVERSIONINFOEX VerInfo;
	char lpszDLL[MAX_PATH];
	if (!getSysVersionInfo(VerInfo))
	{
		this->ErrorMessage("Could not retrieve OS Version info. ", true);
		return false;
	}

	//  Find out which security DLL to use, depending on
	//  whether we are on Win2K, NT or Win9x
	//VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	//if (!GetVersionEx(&VerInfo)) return FALSE; <----------- Depreciated


	if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT && VerInfo.dwMajorVersion == 4)
	{
		strcpy_s(lpszDLL, NT4_DLL_NAME); // NT4_DLL_NAME TEXT("Security.dll")
	}
	else if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
		VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		strcpy_s(lpszDLL, DLL_NAME); // DLL_NAME TEXT("Secur32.dll")
	}
	else
	{
		this->ErrorMessage("System not recognized. ", true);
		return FALSE;
	}


	//  Load Security DLL
	this->mod_security = LoadLibrary(lpszDLL);
	if (this->mod_security == NULL) {
		this->ErrorMessage("Error Loading Security Module. ", true);
		return FALSE;
	}

	pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(this->mod_security, "InitSecurityInterfaceA");
	if (pInitSecurityInterface == NULL) { 
		this->ErrorMessage("Error reading InitSecurityInterface entry point. ", true);
		return FALSE;
	}

	SChanDat.schannel = pInitSecurityInterface(); // call InitSecurityInterfaceA(void);
	if (SChanDat.schannel == NULL) { 
		this->ErrorMessage("Error reading security interface. ", true); 
		return FALSE; 
	}

	return TRUE; // and PSecurityFunctionTable
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
		//closesocket(this->SckDat.mySocket);
		//this->SckDat.m_connected = FALSE;
		//this->SckDat.mySocket = INVALID_SOCKET;
		//Re initalize the secure bits
		//

		//Or just return a message saying were already connected, force them to disconnect.
		this->ErrorMessage("We are already connected, try disconnecting first. ", false);
		return;
	}

	ServerAddress = serv;
	ServerSecAddress = sec_serv;
	port = serv_port;

	int iResult = getaddrinfo(this->ServerAddress.c_str(), std::to_string(this->port).c_str(), &SckDat.hints, &SckDat.result);
	if (iResult != 0) { 
		this->ErrorMessage("getaddrinfo failed. ", true);
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
		this->ErrorMessage("Server connection Failed! ", true);
		return; //We simply couldent connect the socket, criticalerror out and return.
	}
	else {
		//we connected
		this->SckDat.m_connected = true;
		time(&this->m_connecteddate);
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
	if (scRet != SEC_I_CONTINUE_NEEDED) {
		this->ErrorMessage("Error Initializing Security Context. ", true);
		return;
	} else {
		this->InfoMessage("Security Context Initialized. ");
	}

	//need to do the handshake loop before this
	this->InfoMessage("Starting up WorkerThread. ");
	this->StartSocketThread();
}

void SecureSocket::StartSocketThread(void)
{
	this->SckDat.events[0] = CreateEvent(0, 0, 0, 0);
	WSAResetEvent(this->SckDat.events[0]);
	WSAEventSelect(this->SckDat.mySocket, this->SckDat.events[0], 0);
	WSAEventSelect(this->SckDat.mySocket, this->SckDat.events[0], FD_READ | FD_CLOSE);

	//clean the worker
	if (this->SckDat.WorkerThread != NULL) {
		CloseHandle(this->SckDat.WorkerThread);
		this->SckDat.WorkerThread = CreateThread(NULL, 0, SocketProcess, (LPVOID)this, CREATE_SUSPENDED, NULL);
	}

	ResumeThread(SckDat.WorkerThread); //	###TODO### FixMe --^

	//raise connected event
	//this->Connected(); //TODO: Event
}

void CALLBACK SecureSocket::SocketAPCProcess(LPVOID param, const DWORD dwEventID)
{
	OutputDebugString("EVENTS: INVISABLE\r\n");
	SecureSocket *refSocket = reinterpret_cast<SecureSocket*>(param);

	//process by events
	if (!IsBadReadPtr((VOID*)refSocket, sizeof(refSocket))) {

		//refSocket->CriticalSection.enter();

		switch (dwEventID)
		{
		case WAIT_TIMEOUT: {
			break;
		}
		case WAIT_FAILED: {
			refSocket->ErrorMessage("(WaitForSingleObject)", false);
			refSocket->ErrorMessage("Error WAIT_FAILED.", false);
			break;
		}
		case WAIT_ABANDONED: {
			refSocket->ErrorMessage("(WaitForSingleObject)", false);
			refSocket->ErrorMessage("Error WAIT_ABANDONED.", false);
			break;
		}
		case WAIT_OBJECT_0: {
			char *buffer = new char[8192];
			ZeroMemory(buffer, 8192);
			int buflen = 0;
			int recvlen = recv(refSocket->SckDat.mySocket, buffer + buflen, 8192 - buflen, 0);
			if (!recvlen || recvlen == SOCKET_ERROR) {
				char tmpErrorData[256] = "";
				int errorcodevalue = WSAGetLastError();
				if (recvlen == 0) {
					sprintf_s(tmpErrorData, "Server closing socket (%ld)", errorcodevalue); //keeps returning 0 when server disconnects me.
					refSocket->ErrorMessage(std::string(tmpErrorData), false);
					//I want to be sure only 0 = server disconnects..
				}
				else {
					if (!refSocket->SckDat.m_connected) { return; }// 0;	} //we already disconnected somewhere.
					sprintf_s(tmpErrorData, "SOCKET_ERROR: %ld", errorcodevalue); //keeps returning 0 when server disconnects me.
					refSocket->ErrorMessage(std::string(tmpErrorData), false);
				}
				refSocket->DisconnectMessage();
				return;// 1;// SOCKET_ERROR;
			}
			//Build data arrival..
			refSocket->DataArrivalMessage(buffer, recvlen); //this needs to be decrypted before sending it to the iface.
			delete[] buffer; //clear and free our buffer.
			break;
		}
		}
		//process events delete the struct
		//refSocket->CriticalSection.leave();
		return;
	}
}






//////////////////////////////////////
//		Events						//
//////////////////////////////////////
void SecureSocket::ErrorMessage(std::string error_message, bool crit_error)
{
	//Call Error event.
	if (!IsBadReadPtr((VOID*)_events.Error, sizeof(_events.Error))) {
		_events.Error(error_message);
	}
	else {
		OutputDebugString(error_message.c_str());
	}
	if (crit_error) { this->DisconnectMessage(); } //Disconnect after the message.
}
void SecureSocket::InfoMessage(std::string info_message)
{
	//Call Info event.
	if (!IsBadReadPtr((VOID*)_events.Info, sizeof(_events.Info))) {
		_events.Info(info_message);
	}
	else {
		OutputDebugString(info_message.c_str());
	}
}
void SecureSocket::DisconnectMessage(void)
{
	//if (this->are_we_connected) { CloseHandle(g_hThread); g_hThread = NULL; }
	shutdown(this->SckDat.mySocket, SD_BOTH);
	closesocket(this->SckDat.mySocket);
	this->SckDat.mySocket = INVALID_SOCKET;
	//WSACleanup();
	this->SckDat.m_connected = false;
	//reset the state
	this->SckDat.m_STATE = 0x00000000;
	//reset connected time
	this->m_connecteddate = 0;
	//Reset the data counters
	this->SckDat.m_bytesout = 0;
	this->SckDat.m_bytesin = 0;

	//Call disconnect event.
	if (!IsBadReadPtr((VOID*)_events.Disconnected, sizeof(_events.Disconnected))) {
		_events.Disconnected(this->ServerAddress, this->port);
	}
	else {
		OutputDebugString("Disconnected.");
	}

}
void SecureSocket::DataArrivalMessage(char *buffer, int Length)
{
	this->SckDat.m_bytesin += Length;

	if (!IsBadReadPtr((VOID*)_events.DataArrival, sizeof(_events.DataArrival))) {
		_events.DataArrival(buffer, Length);
	}
	else {
		OutputDebugString(std::string(buffer).c_str()); //should hex dump this message
	}
}
