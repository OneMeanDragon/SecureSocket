#pragma once
#pragma comment(lib, "ws2_32.lib")

#include <WinSock2.h>
#include <Windows.h>
#include <winuser.h>
#include <ws2tcpip.h>
#define SECURITY_WIN32
#define IO_BUFFER_SIZE  0x10000
#define DLL_NAME TEXT("Secur32.dll")
#define NT4_DLL_NAME TEXT("Security.dll")
#include <SChannel.h>
#include <security.h>

#include <chrono>
#include <string>

struct SChannelData {
	UINT32 m_protocol = SP_PROT_TLS1;
	SCHANNEL_CRED m_scc;
	CredHandle m_cc;
	DWORD sspiflags = (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM);
	DWORD sspioutflags;
	SecBuffer OutBuffers[1];
	SecBufferDesc OutBuffer;
	CtxtHandle contexthandle;
	PSecurityFunctionTable schannel;
};

struct SocketDat {
	WSADATA versioninfo;
	SOCKET mySocket = INVALID_SOCKET;
	BOOL m_connected = FALSE;
	struct addrinfo *result, *ptr, hints;
	HANDLE events[2];
	UINT64 m_bytesout, m_bytesin = 0;
	HANDLE WorkerThread;
	UINT32 m_STATE;
};

class SecureSocket
{
private: 
	std::string ServerAddress = "";
	std::string ServerSecAddress = "";
	UINT16 port = 0;

	time_t m_connecteddate = NULL;

	//SChannel Infos
	HMODULE mod_security = NULL;
	SChannelData SChanDat;

	void SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials);

public: 
	//Socket Infos
	SocketDat SckDat; //Public for the thread

	static DWORD WINAPI SocketProcess(LPVOID param);
	void CALLBACK SocketAPCProcess(LPVOID param, const DWORD dwEventID);

	//Events
	void ErrorMessage(std::string error_message, bool crit_error);
	void InfoMessage(std::string info_message);
	void DataArrivalMessage(char *buffer, int Length);
	void DisconnectMessage(void);

	typedef void(*_Disconnected)(std::string from_address, u_short on_port);
	typedef void(*_DataArrival)(char *buffer, int length);
	typedef void(*_Error)(std::string message);
	typedef void(*_Connecting)(std::string host_address, u_short port);
	typedef void(*_InfoMessage)(std::string message);
	typedef void(*_Connected)(std::string host_address, u_short port);
	typedef void(*_SecureSocketFinalized)(void);
	struct _FunctionPointers {
		_Connected Connected;
		_Disconnected Disconnected;
		_DataArrival DataArrival;
		_Error Error;
		_Connecting Connecting;
		_InfoMessage Info;
		_SecureSocketFinalized SecuredSocket;
	} _events;
	
	SecureSocket()
	{
		WSAStartup(0x0202, &SckDat.versioninfo);
		// Load Security DLL
		mod_security = LoadLibrary("Secur32.dll");
		// Initialize Schannel
		if (!LoadSecurityModule()) { return; }

		// Setup Schannel Credentials
		ZeroMemory(&SChanDat.m_scc, sizeof(SChanDat.m_scc));
		SetupSchannelCredentials(SChanDat.m_protocol, SChanDat.m_scc);
		// Get Client Credentials handle
		SECURITY_STATUS securitystatus = SChanDat.schannel->AcquireCredentialsHandleA(
			0,
			(SEC_CHAR *)UNISP_NAME_A,
			SECPKG_CRED_OUTBOUND,
			0,
			&SChanDat.m_scc,
			0,
			0,
			&SChanDat.m_cc,
			0
		);
		if (securitystatus != SEC_E_OK) {
			this->ErrorMessage("Failed to get credenetials. ", true);
			return;
		} else {
			this->InfoMessage("Got client credenetials. "); 
		}
		//DataArrival worker
		SckDat.WorkerThread = CreateThread(NULL, 0, SocketProcess, (LPVOID)this, CREATE_SUSPENDED, NULL);
	}
	~SecureSocket()
	{
		//unload the socket thread
		SckDat.m_connected = false;
		ResumeThread(SckDat.WorkerThread);
		WaitForSingleObject(SckDat.WorkerThread, INFINITE);
		CloseHandle(SckDat.WorkerThread);
		//free the library
		FreeLibrary(mod_security);
		mod_security = NULL;
	}
	
	BOOL LoadSecurityModule(void);
	void Connect(std::string serv, std::string sec_serv, UINT16 serv_port);
	void PerformHandshake(void);
	void StartSocketThread(void);

	//EncryptSend
	//Recieve
	//DecryptRecieve
};
