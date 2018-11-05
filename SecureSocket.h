#pragma once
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")
#define SECURITY_WIN32
#include <SChannel.h>
#include <security.h>


#include <string>

class SecureSocket
{
private: 
	std::string ServerAddress = "";
	std::string ServerSecAddress = "";
	UINT16 port = 0;

	SOCKET mySocket = INVALID_SOCKET;

	WSADATA versioninfo;
	HMODULE securitydllmodule = NULL;

	UINT32 m_protocol = SP_PROT_TLS1;
	SCHANNEL_CRED m_scc;
	CredHandle m_cc;

	void SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials);

public: 

  SecureSocket();
  ~SecureSocket();
  
  };
