#pragma once
#pragma comment(lib, "ws2_32.lib")

#include <WinSock2.h>
#include <Windows.h>
#include <winuser.h>
#include <ws2tcpip.h>
#define SECURITY_WIN32
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
};

class SecureSocket
{
private: 
	std::string ServerAddress = "";
	std::string ServerSecAddress = "";
	UINT16 port = 0;

	time_t m_connecteddate = NULL;

	//Socket Infos
	SocketDat SckDat;

	//SChannel Infos
	HMODULE mod_security = NULL;
	SChannelData SChanDat;

	void SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials);

public: 
	static DWORD WINAPI SocketProcess(LPVOID param);

	
	SecureSocket()
	{
		WSAStartup(0x0202, &SckDat.versioninfo);
		// Load Security DLL
		mod_security = LoadLibrary("Secur32.dll");
		// Initialize Schannel
		INIT_SECURITY_INTERFACE initsecurtyinterfacefunction = (INIT_SECURITY_INTERFACE)GetProcAddress(mod_security, "InitSecurityInterfaceA");
		SChanDat.schannel = initsecurtyinterfacefunction();
		if (!SChanDat.schannel) {
			MessageBox(0, "Failed to initialize schannel", "Message", MB_TASKMODAL | MB_OK);
			//clean up?
		} else {
			MessageBox(0, "initialized schannel", "Message", MB_TASKMODAL | MB_OK);
		}
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
		if (securitystatus != SEC_E_OK)
			MessageBox(0, "Failed to get credenetials", "Message", MB_TASKMODAL | MB_OK);
		else
			MessageBox(0, "Got client credenetials", "Message", MB_TASKMODAL | MB_OK);
	}
	~SecureSocket()
	{
		//free the library
		FreeLibrary(mod_security);
		mod_security = NULL;
	}
	
	void Connect(std::string serv, std::string sec_serv, UINT16 serv_port);
	void PerformHandshake(void);

	//EncryptSend
	//Recieve
	//DecryptRecieve
};
