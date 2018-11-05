#include "SecureSocket.h"

void SecureSocket::SetupSchannelCredentials(UINT32 protocol, SCHANNEL_CRED &schannelcredentials)
{
	schannelcredentials.dwVersion = SCHANNEL_CRED_VERSION;
	schannelcredentials.grbitEnabledProtocols = protocol;
	schannelcredentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	schannelcredentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
}

