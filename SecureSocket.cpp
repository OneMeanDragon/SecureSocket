#include "SecureSocket.h"

void SecureSocket::SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials)
{
	schannelcredentials.dwVersion = SCHANNEL_CRED_VERSION;
	schannelcredentials.grbitEnabledProtocols = protocol;
	schannelcredentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	schannelcredentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
}

SecureSocket::SecureSocket()
{
	WSAStartup(0x0202, &versioninfo);
	// Load Security DLL
	securitydllmodule = LoadLibrary("Secur32.dll");
	// Initialize Schannel
	INIT_SECURITY_INTERFACE initsecurtyinterfacefunction = (INIT_SECURITY_INTERFACE)GetProcAddress(securitydllmodule, "InitSecurityInterfaceA");
	PSecurityFunctionTable schannel = initsecurtyinterfacefunction();
	if (!schannel) {
		MessageBox(0, "Failed to initialize schannel", "Message", MB_TASKMODAL | MB_OK);
		//clean up?
	} else {
		MessageBox(0, "initialized schannel", "Message", MB_TASKMODAL | MB_OK);
	}
	// Setup Schannel Credentials
	ZeroMemory(&m_scc, sizeof(m_scc));
	SetupSchannelCredentials(m_protocol, m_scc);
	// Get Client Credentials handle
	SECURITY_STATUS securitystatus = schannel->AcquireCredentialsHandleA(
		0,
		(SEC_CHAR *)UNISP_NAME_A,
		SECPKG_CRED_OUTBOUND,
		0,
		&m_scc,
		0,
		0,
		&m_cc,
		0
		);
	
	if (securitystatus != SEC_E_OK)
		MessageBox(0, "Failed to get credenetials", "Message", MB_TASKMODAL | MB_OK);
	else
		MessageBox(0, "Got client credenetials", "Message", MB_TASKMODAL | MB_OK);
}

SecureSocket::~SecureSocket()
{
	//free the library
	FreeLibrary(securitydllmodule);
	securitydllmodule = NULL;
}
	
