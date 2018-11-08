#include "SecureSocket.h"
#include "sha1.h"
#include "base64.h"

#define SHA_BUF_LEN 20
std::string ClientSecKey = "";
void CreateClientSecKey()
{
	DWORD mTick = GetTickCount();
	std::string rndK = std::to_string(mTick);
	unsigned char shabuf[SHA_BUF_LEN];
	SHA_1((unsigned const char *)rndK.c_str(), rndK.length(), shabuf);
	ClientSecKey = base64_encode(shabuf, SHA_BUF_LEN);
}


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

	//  Find out which security DLL to use, depending on
	//  whether we are on Win2K, NT or Win9x
	//VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	//if (!GetVersionEx(&VerInfo)) return FALSE; <----------- Depreciated
	if (!getSysVersionInfo(VerInfo))
	{
		this->ErrorMessage("Could not retrieve OS Version info. ", true);
		return false;
	}


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

void SecureSocket::UnloadSecurityLibrary(void)
{
	FreeLibrary(this->mod_security);
	this->mod_security = NULL;
}

void SecureSocket::SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials)
{
	schannelcredentials.dwVersion = SCHANNEL_CRED_VERSION;
	schannelcredentials.grbitEnabledProtocols = protocol;
	schannelcredentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	schannelcredentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
}

void SecureSocket::testsend()
{
	CreateClientSecKey();
	SecPkgContext_StreamSizes Sizes;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
	SECURITY_STATUS                        scRet;            // unsigned long BufferType;  // Type of the buffer (below)        
	char *pbIoBuffer; // void    SEC_FAR * pvBuffer;   // Pointer to the buffer
	DWORD                                            cbIoBufferLength, cbData;


	// Read stream encryption properties.
	scRet = SChanDat.schannel->QueryContextAttributes(&SChanDat.contexthandle, SECPKG_ATTR_STREAM_SIZES, &Sizes);
	if (scRet != SEC_E_OK)
	{
		this->ErrorMessage("Error **** reading SECPKG_ATTR_STREAM_SIZES (ts).", false);
		return;// scRet;
	}


	// Create a buffer.
	cbIoBufferLength = Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
	pbIoBuffer = (char *)LocalAlloc(LMEM_FIXED, cbIoBufferLength);
	if (pbIoBuffer == NULL) { 
		this->ErrorMessage("Error **** reading Out of memory (ts).", false);
		return;// SEC_E_INTERNAL_ERROR;
	}

	std::string httpRequest = "GET /v1/rpc/chat HTTP/1.1\r\n"; // /v1/rpc/chat
	std::string headers;
	headers = "Host: connect-bot.classic.blizzard.com\r\n";
	headers += "User-Agent: VisualStudio2017 (Windows NT 10.0; Win64; x64; rv:62.0)\r\n";
	headers += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*; q = 0.8\r\n";
	headers += "Accept-Language: en-US, en; q = 0.5\r\n";
	headers += "Accept-Encoding: gzip, deflate, br\r\n";
	headers += "Sec-WebSocket-Version: 13\r\n";
	headers += "Origin: null\r\n";
	headers += "Sec-WebSocket-Protocol: json\r\n";
	headers += "Sec-WebSocket-Extensions: permessage-deflate\r\n";
	headers += "Sec-WebSocket-Key: " + ClientSecKey + "\r\n";
	headers += "Cookie: optimizelyEndUserId = oeu1526472067711r0.22869007145801235; _ga = GA1.2.189589478.1526472082\r\n";
	headers += "DNT: 1\r\n";
	headers += "Connection: keep-alive, Upgrade\r\n";
	headers += "Pragma: no-cache\r\n";
	headers += "Cache-Control: no-cache\r\n";
	headers += "Upgrade: WebSocket\r\n";
	headers += "\r\n"; //end of header
	httpRequest += headers;

	sprintf_s((char *)pbIoBuffer+Sizes.cbHeader, (size_t)((cbIoBufferLength - Sizes.cbHeader) - httpRequest.length()), "%s", (const char *)httpRequest.c_str()); // message begins after the header
	cbData = EncryptSend(SckDat.mySocket, &SChanDat.contexthandle, (char *)pbIoBuffer, 0, Sizes);
}

void SecureSocket::Connect(std::string serv, std::string sec_serv, UINT16 serv_port)
{
	//are we trying to connect an already open socket?
	if (this->SckDat.mySocket != INVALID_SOCKET) {
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

	if (!PerformHandshake(SckDat.mySocket, &SChanDat.m_cc, (SEC_CHAR *)ServerSecAddress.c_str(), &SChanDat.contexthandle, &SChanDat.ExtraData)) { return; }
	//need to do the handshake loop before this
	this->InfoMessage("Starting up WorkerThread. ");
	this->StartSocketThread();

	//Send text message.
	testsend();
}

bool SecureSocket::PerformHandshake(SOCKET Socket, PCredHandle phCreds, SEC_CHAR *pszServerSecName, CtxtHandle *phContext, SecBuffer *pExtraData)
{
	SecBufferDesc	OutBuffer;
	SecBuffer		OutBuffers[1];
	TimeStamp       tsExpiry;
	DWORD           dwSSPIOutFlags;

	OutBuffers[0].pvBuffer = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	SECURITY_STATUS scRet = SChanDat.schannel->InitializeSecurityContextA(
		phCreds,
		NULL,
		pszServerSecName,
		SSPI_FLAGS,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		phContext,
		&OutBuffer,
		&dwSSPIOutFlags,
		&tsExpiry
	);

	if (scRet != SEC_I_CONTINUE_NEEDED) {
		this->ErrorMessage("Error Initializing Security Context. ", true);
		return false;
	} else {
		this->InfoMessage("Security Context Initialized. ");
	}

	DWORD cbData;
	// Send response to server if there is one. (say hello)
	if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
	{
		cbData = send(Socket, (const char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			SChanDat.schannel->FreeContextBuffer(OutBuffers[0].pvBuffer);
			SChanDat.schannel->DeleteSecurityContext(phContext);
			this->ErrorMessage("Error sending data to server. ", true);
			return false;
		}
		//printf("%d bytes of handshake data sent\n", cbData);
		//if (_DEBUG) { 
		//	PrintHexDump(cbData, SChanDat.OutBuffers[0].pvBuffer); 
		//	printf("\n"); 
		//}
		SChanDat.schannel->FreeContextBuffer(OutBuffers[0].pvBuffer); // Free output buffer.
		OutBuffers[0].pvBuffer = NULL;
	}
	//HandShakeLoop
	if (ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData)) { return false; }
	return true;
}

bool SecureSocket::ClientHandshakeLoop(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext, BOOL inital_read, SecBuffer *pExtraData)
{
	SecBufferDesc   InBuffer;
	SecBuffer       InBuffers[2];
	SecBufferDesc   OutBuffer;
	SecBuffer       OutBuffers[1];
	DWORD           dwSSPIOutFlags;
	TimeStamp       tsExpiry;
	SECURITY_STATUS scRet;
	DWORD           cbData;

	char			*IoBuffer;
	DWORD           cbIoBuffer;
	BOOL            fDoRead;

	//
	// Allocate data buffer.
	//

	IoBuffer = (char *)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
	if (IoBuffer == NULL)
	{
		this->ErrorMessage("Error **** Out of memory. ", true);
		return false; // SEC_E_INTERNAL_ERROR;
	}
	cbIoBuffer = 0;

	fDoRead = inital_read;
	// 
	// Loop until the handshake is finished or an error occurs.
	//

	scRet = SEC_I_CONTINUE_NEEDED;

	while (scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_INCOMPLETE_MESSAGE || scRet == SEC_I_INCOMPLETE_CREDENTIALS)
	{

		//
		// Read data from server.
		//

		if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			if (fDoRead)
			{
				cbData = recv(Socket, IoBuffer + cbIoBuffer, IO_BUFFER_SIZE - cbIoBuffer, 0);
				if (cbData == SOCKET_ERROR)
				{
					this->ErrorMessage("Error **** reading data from server. ", false);
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}
				else if (cbData == 0)
				{
					this->ErrorMessage("Error **** Server unexpectedly disconnected. ", false);
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}

				//printf("%d bytes of handshake data received\n", cbData);
				//if (fVerbose)
				//{
				//	PrintHexDump(cbData, IoBuffer + cbIoBuffer);
				//	printf("\n");
				//}

				cbIoBuffer += cbData;
			}
			else
			{
				fDoRead = TRUE;
			}
		}


		//
		// Set up the input buffers. Buffer 0 is used to pass in data
		// received from the server. Schannel will consume some or all
		// of this. Leftover data (if any) will be placed in buffer 1 and
		// given a buffer type of SECBUFFER_EXTRA.
		//

		InBuffers[0].pvBuffer = IoBuffer;
		InBuffers[0].cbBuffer = cbIoBuffer;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer = NULL;
		InBuffers[1].cbBuffer = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;

		InBuffer.cBuffers = 2;
		InBuffer.pBuffers = InBuffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;

		//
		// Set up the output buffers. These are initialized to NULL
		// so as to make it less likely we'll attempt to free random
		// garbage later.
		//

		OutBuffers[0].pvBuffer = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;

		OutBuffer.cBuffers = 1;
		OutBuffer.pBuffers = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		//
		// Call InitializeSecurityContext.
		//

		scRet = SChanDat.schannel->InitializeSecurityContextA(phCreds,
			phContext,
			NULL,
			SSPI_FLAGS,
			0,
			SECURITY_NATIVE_DREP,
			&InBuffer,
			0,
			NULL,
			&OutBuffer,
			&dwSSPIOutFlags,
			&tsExpiry);

		//
		// If InitializeSecurityContext was successful (or if the error was 
		// one of the special extended ones), send the contends of the output
		// buffer to the server.
		//

		if (scRet == SEC_E_OK ||
			scRet == SEC_I_CONTINUE_NEEDED ||
			FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
		{
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
			{
				cbData = send(Socket, (const char *)OutBuffers[0].pvBuffer,	OutBuffers[0].cbBuffer,	0);
				if (cbData == SOCKET_ERROR || cbData == 0)
				{
					SChanDat.schannel->FreeContextBuffer(OutBuffers[0].pvBuffer);
					SChanDat.schannel->DeleteSecurityContext(phContext);
					this->ErrorMessage("Error **** sending data to server. ", true);
					return SEC_E_INTERNAL_ERROR;
				}

				//printf("%d bytes of handshake data sent\n", cbData);
				//if (fVerbose)
				//{
				//	PrintHexDump(cbData, OutBuffers[0].pvBuffer);
				//	printf("\n");
				//}

				// Free output buffer.
				SChanDat.schannel->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = NULL;
			}
		}


		//
		// If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
		// then we need to read more data from the server and try again.
		//

		if (scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			continue;
		}


		//
		// If InitializeSecurityContext returned SEC_E_OK, then the 
		// handshake completed successfully.
		//

		if (scRet == SEC_E_OK)
		{
			//
			// If the "extra" buffer contains data, this is encrypted application
			// protocol layer stuff. It needs to be saved. The application layer
			// will later decrypt it with DecryptMessage.
			//

			printf("Handshake was successful\n");

			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);
				if (pExtraData->pvBuffer == NULL)
				{
					this->ErrorMessage("Error **** Out of memory. ", true);
					return SEC_E_INTERNAL_ERROR;
				}

				MoveMemory(pExtraData->pvBuffer,
					IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
					InBuffers[1].cbBuffer);

				pExtraData->cbBuffer = InBuffers[1].cbBuffer;
				pExtraData->BufferType = SECBUFFER_TOKEN;

				printf("%d bytes of app data was bundled with handshake data\n",
					pExtraData->cbBuffer);
			}
			else
			{
				pExtraData->pvBuffer = NULL;
				pExtraData->cbBuffer = 0;
				pExtraData->BufferType = SECBUFFER_EMPTY;
			}

			//
			// Bail out to quit
			//

			break;
		}


		//
		// Check for fatal error.
		//

		if (FAILED(scRet))
		{
			this->ErrorMessage("Error **** InitializeSecurityContext (2). ", false);
			break;
		}


		//
		// If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
		// then the server just requested client authentication. 
		//

		if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			//
			// Busted. The server has requested client authentication and
			// the credential we supplied didn't contain a client certificate.
			//

			// 
			// This function will read the list of trusted certificate
			// authorities ("issuers") that was received from the server
			// and attempt to find a suitable client certificate that
			// was issued by one of these. If this function is successful, 
			// then we will connect using the new certificate. Otherwise,
			// we will attempt to connect anonymously (using our current
			// credentials).
			//

			//GetNewClientCredentials(phCreds, phContext);

			// Go around again.
			fDoRead = FALSE;
			scRet = SEC_I_CONTINUE_NEEDED;
			continue;
		}


		//
		// Copy any leftover data from the "extra" buffer, and go around
		// again.
		//

		if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(IoBuffer,
				IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
				InBuffers[1].cbBuffer);

			cbIoBuffer = InBuffers[1].cbBuffer;
		}
		else
		{
			cbIoBuffer = 0;
		}
	}

	// Delete the security context in the case of a fatal error.
	if (FAILED(scRet))
	{
		SChanDat.schannel->DeleteSecurityContext(phContext);
	}

	LocalFree(IoBuffer);

	return scRet;
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
			char *pbIoBuffer;
			DWORD cbIoBufferLength;
			SecPkgContext_StreamSizes Sizes;
			SECURITY_STATUS scRet = refSocket->SChanDat.schannel->QueryContextAttributes(&refSocket->SChanDat.contexthandle, SECPKG_ATTR_STREAM_SIZES, &Sizes);
			if (scRet != SEC_E_OK)
			{
				refSocket->SckDat.m_connected = false;
				refSocket->ErrorMessage("Error **** reading SECPKG_ATTR_STREAM_SIZES", true);
				return;
			}
			cbIoBufferLength = Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
			pbIoBuffer = (char *)LocalAlloc(LMEM_FIXED, cbIoBufferLength);

			if (ReadDecrypt(refSocket->SckDat.mySocket, &refSocket->SChanDat.m_cc, &refSocket->SChanDat.contexthandle, pbIoBuffer, cbIoBufferLength) != SEC_E_OK) {
				refSocket->SckDat.m_connected = false; 
			}
			LocalFree(pbIoBuffer);
			break;
		}
		}
		//process events delete the struct
		//refSocket->CriticalSection.leave();
		return;
	}
}

SECURITY_STATUS SecureSocket::ReadDecrypt(SOCKET Socket, PCredHandle phCreds, CtxtHandle * phContext, char * pbIoBuffer, DWORD    cbIoBufferLength)

// calls recv() - blocking socket read
// http://msdn.microsoft.com/en-us/library/ms740121(VS.85).aspx

// The encrypted message is decrypted in place, overwriting the original contents of its buffer.
// http://msdn.microsoft.com/en-us/library/aa375211(VS.85).aspx

{
	SecBuffer				ExtraBuffer;
	SecBuffer				*pDataBuffer, *pExtraBuffer;

	SECURITY_STATUS			scRet;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
	SecBufferDesc			Message;        // unsigned long BufferType;  // Type of the buffer (below)
	SecBuffer				Buffers[4];    // void    SEC_FAR * pvBuffer;   // Pointer to the buffer

	DWORD					cbIoBuffer, cbData, length;
	char *					buff;
	int						i;



	// Read data from server until done.
	cbIoBuffer = 0;
	scRet = 0;
	while (TRUE) // Read some data.
	{
		if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE) // get the data
		{
			cbData = recv(Socket, pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);
			if (cbData == SOCKET_ERROR)
			{
				this->ErrorMessage("Error **** reading data from server.", false);
				scRet = SEC_E_INTERNAL_ERROR;
				break;
			}
			else if (cbData == 0) // Server disconnected.
			{
				if (cbIoBuffer)
				{
					this->ErrorMessage("Error **** Server unexpectedly disconnected.", false);
					scRet = SEC_E_INTERNAL_ERROR;
					return scRet;
				}
				else
					break; // All Done
			}
			else // success
			{
				//printf("%d bytes of (encrypted) application data received\n", cbData);
				//if (fVerbose) { 
				//	PrintHexDump(cbData, pbIoBuffer + cbIoBuffer); 
				//	printf("\n"); 
				//}
				cbIoBuffer += cbData;
			}
		}


		// Decrypt the received data.
		Buffers[0].pvBuffer = pbIoBuffer;
		Buffers[0].cbBuffer = cbIoBuffer;
		Buffers[0].BufferType = SECBUFFER_DATA;  // Initial Type of the buffer 1
		Buffers[1].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 2
		Buffers[2].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 3
		Buffers[3].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 4

		Message.ulVersion = SECBUFFER_VERSION;    // Version number
		Message.cBuffers = 4;                                    // Number of buffers - must contain four SecBuffer structures.
		Message.pBuffers = Buffers;                        // Pointer to array of buffers
		scRet = SChanDat.schannel->DecryptMessage(phContext, &Message, 0, NULL);
		if (scRet == SEC_I_CONTEXT_EXPIRED) break; // Server signalled end of session
//      if( scRet == SEC_E_INCOMPLETE_MESSAGE - Input buffer has partial encrypted record, read more
		if (scRet != SEC_E_OK &&
			scRet != SEC_I_RENEGOTIATE &&
			scRet != SEC_I_CONTEXT_EXPIRED)
		{
			//DisplaySECError((DWORD)scRet);
			this->ErrorMessage("Error **** DecryptMessage.", false);
			return scRet;
		}



		// Locate data and (optional) extra buffers.
		pDataBuffer = NULL;
		pExtraBuffer = NULL;
		for (i = 1; i < 4; i++)
		{
			if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA) pDataBuffer = &Buffers[i];
			if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) pExtraBuffer = &Buffers[i];
		}


		// Display the decrypted data.
		if (pDataBuffer)
		{
			length = pDataBuffer->cbBuffer;
			if (length) // check if last two chars are CR LF
			{
				buff = (char *)pDataBuffer->pvBuffer; // printf( "n-2= %d, n-1= %d \n", buff[length-2], buff[length-1] );
				//printf("Decrypted data: %d bytes", length); 
				//PrintText(length, buff);
				this->DataArrivalMessage(buff, length);
				//if (fVerbose) { 
				//	PrintHexDump(length, buff); 
				//	printf("\n"); 
				//}
				if (buff[length - 2] == 13 && buff[length - 1] == 10) break; // printf("Found CRLF\n");
			}
		}



		// Move any "extra" data to the input buffer.
		if (pExtraBuffer)
		{
			MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
			cbIoBuffer = pExtraBuffer->cbBuffer; // printf("cbIoBuffer= %d  \n", cbIoBuffer);
		}
		else
			cbIoBuffer = 0;


		// The server wants to perform another handshake sequence.
		if (scRet == SEC_I_RENEGOTIATE)
		{
			printf("Server requested renegotiate!\n");
			scRet = ClientHandshakeLoop(Socket, phCreds, phContext, FALSE, &ExtraBuffer);
			if (scRet != SEC_E_OK) return scRet;

			if (ExtraBuffer.pvBuffer) // Move any "extra" data to the input buffer.
			{
				MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
				cbIoBuffer = ExtraBuffer.cbBuffer;
			}
		}
	} // Loop till CRLF is found at the end of the data

	return SEC_E_OK;
}

DWORD SecureSocket::EncryptSend(SOCKET Socket, CtxtHandle * phContext, char * pbIoBuffer, DWORD bufLength, SecPkgContext_StreamSizes Sizes)
// http://msdn.microsoft.com/en-us/library/aa375378(VS.85).aspx
// The encrypted message is encrypted in place, overwriting the original contents of its buffer.
{
	SECURITY_STATUS		scRet;				// unsigned long cbBuffer;		// Size of the buffer, in bytes
	SecBufferDesc		Message;			// unsigned long BufferType;	// Type of the buffer (below)
	SecBuffer			Buffers[4];			// void    SEC_FAR * pvBuffer;	// Pointer to the buffer
	DWORD				cbMessage, cbData;
	char *				pbMessage;


	pbMessage = pbIoBuffer + Sizes.cbHeader; // Offset by "header size"
	cbMessage = (DWORD)strlen(pbMessage); //........ fix me
	//printf("Sending %d bytes of plaintext:", cbMessage); 
	//PrintText(cbMessage, pbMessage);
	//if (fVerbose) { 
	//	PrintHexDump(cbMessage, pbMessage); 
	//	printf("\n"); 
	//}


	// Encrypt the HTTP request.
	Buffers[0].pvBuffer = pbIoBuffer;                                // Pointer to buffer 1
	Buffers[0].cbBuffer = Sizes.cbHeader;                        // length of header
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;    // Type of the buffer

	Buffers[1].pvBuffer = pbMessage;                                // Pointer to buffer 2
	Buffers[1].cbBuffer = cbMessage;                                // length of the message
	Buffers[1].BufferType = SECBUFFER_DATA;                        // Type of the buffer

	Buffers[2].pvBuffer = pbMessage + cbMessage;        // Pointer to buffer 3
	Buffers[2].cbBuffer = Sizes.cbTrailer;                    // length of the trailor
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;    // Type of the buffer

	Buffers[3].pvBuffer = SECBUFFER_EMPTY;                    // Pointer to buffer 4
	Buffers[3].cbBuffer = SECBUFFER_EMPTY;                    // length of buffer 4
	Buffers[3].BufferType = SECBUFFER_EMPTY;                    // Type of the buffer 4


	Message.ulVersion = SECBUFFER_VERSION;    // Version number
	Message.cBuffers = 4;                                    // Number of buffers - must contain four SecBuffer structures.
	Message.pBuffers = Buffers;                        // Pointer to array of buffers
	scRet = SChanDat.schannel->EncryptMessage(phContext, 0, &Message, 0); // must contain four SecBuffer structures.
	if (FAILED(scRet)) { printf("**** Error 0x%x returned by EncryptMessage\n", scRet); return scRet; }


	// Send the encrypted data to the server.                                            len                                                                         flags
	cbData = send(Socket, pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);

	//printf("%d bytes of encrypted data sent\n", cbData);
	//if (fVerbose) { PrintHexDump(cbData, pbIoBuffer); printf("\n"); }

	return cbData; // send( Socket, pbIoBuffer,    Sizes.cbHeader + strlen(pbMessage) + Sizes.cbTrailer,  0 );

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
		std::string debugoutstring = "\r\nDebug:\r\n" + error_message + "\r\n";
		OutputDebugString(debugoutstring.c_str());
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
		std::string debugoutstring = "\r\nDebug:\r\n" + info_message + "\r\n";
		OutputDebugString(debugoutstring.c_str());
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
		std::string debugoutstring = "\r\nDebug:\r\n";
		debugoutstring += "Disconnected.";
		debugoutstring += "\r\n";
		OutputDebugString(debugoutstring.c_str());
	}
}
void SecureSocket::DataArrivalMessage(char *buffer, int Length)
{
	this->SckDat.m_bytesin += Length;

	if (!IsBadReadPtr((VOID*)_events.DataArrival, sizeof(_events.DataArrival))) {
		_events.DataArrival(buffer, Length);
	}
	else {
		std::string debugoutstring = "\r\nDebug:\r\n" + std::string(buffer) + "\r\n";
		OutputDebugString(debugoutstring.c_str()); //Should hex dump this line
	}
}
