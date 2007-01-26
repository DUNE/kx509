/*
 * Copyright  ©  2007
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * permission is granted to use, copy, create derivative works 
 * and redistribute this software and such derivative works 
 * for any purpose, so long as the name of the university of 
 * michigan is not used in any advertising or publicity 
 * pertaining to the use or distribution of this software 
 * without specific, written prior authorization.  if the 
 * above copyright notice or any other identification of the 
 * university of michigan is included in any copy of any 
 * portion of this software, then the disclaimer below must 
 * also be included.
 *
 * this software is provided as is, without representation 
 * from the university of michigan as to its fitness for any 
 * purpose, and without warranty by the university of 
 * michigan of any kind, either express or implied, including 
 * without limitation the implied warranties of 
 * merchantability and fitness for a particular purpose. the 
 * regents of the university of michigan shall not be liable 
 * for any damages, including special, indirect, incidental, or 
 * consequential damages, with respect to any claim arising 
 * out of or in connection with the use of the software, even 
 * if it has been or is hereafter advised of the possibility of 
 * such damages.
 */

// msk5.c

#ifdef USE_MSK5

#define UNICODE
#define _UNICODE

#include <windows.h>
#undef FAR



#include <stdio.h>      
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#define SECURITY_WIN32
#include <security.h> 
#include <ntsecapi.h>

#include "debug.h"
#include "dialog_u_pw.h"

//#define USE_KRB5

#include <memory.h>

#define __WINCRYPT_H__		// PREVENT windows.h from including wincrypt.h
							// since wincrypt.h and openssl namepsaces collide
							//  ex. X509_NAME is #define'd and typedef'd ...
#include <winsock.h>		// Must be included before <windows.h> !!!
#include <windows.h>
#include <openssl/pem.h>


#include <stdlib.h>
#include <openssl/x509v3.h>

#include <krb5.h>
#include <com_err.h>

#include "msg.h"
#include "udp_nb.h"
#include "kx509.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include "kx509_asn.h"
#include <openssl/rand.h>


#define	K4_CA_PRINC		"cert"
#define	K4_CA_INST		"x509"

#define	K5_CA_PRINC		"kca_service"

#define KRBCHK_PORT     (u_short)9878
#define	DEFBITS	512 /* first get MS stuff working, then do 1024 */

void fill_in_octet_string(
	ASN1_OCTET_STRING *osp,
	char *st,
	int len);

RSA *client_genkey(int keybits);




#define SEC_SUCCESS(Status) ((Status) >= 0) 

typedef struct _Auth_Pkg_Rtns {
	BOOL	(*get_userid_and_realm)();
	BOOL	(*get_authent_and_sesskey)();
	BOOL	(*test_authent_to_ksvr)();
} AUTH_RTNS;

BOOL	MSK5_get_userid_and_realm();
BOOL	MSK5_get_authent_and_sesskey();
BOOL	MSK5_test_authent_to_ksvr();

extern void MSK5_Generate_Authenticator();
extern BOOL 	bPwdPrompt;
extern HINSTANCE myhInstance;
extern HWND      myhMainWindow;



/* We only use one cred handle for the user. Will make it static
 * external for now. 
 */
CredHandle cred_handle = {0,0};

#define AddErrTxt(n, t) { n, #n, t }

typedef struct _errtxt {
        int		rc;
        char	*sym;
		char	*txt;
} ERRTXT ;

ERRTXT	ErrTxt[] = {
	AddErrTxt(ERROR_NO_TRUST_LSA_SECRET,			"The workstation does not have a trust secret"),
	AddErrTxt(ERROR_NO_TRUST_SAM_ACCOUNT,			"The security database on the server does not have a computer account for this workstation trust relationship"),
	AddErrTxt(ERROR_TRUSTED_DOMAIN_FAILURE,			"The trust relationship between the primary domain and the trusted domain failed"),
	AddErrTxt(ERROR_TRUSTED_RELATIONSHIP_FAILURE,	"The trust relationship between this workstation and the primary domain failed"),
	AddErrTxt(ERROR_TRUST_FAILURE,					"The network logon failed"),
	{-1, 0, 0}
};



#define MAX_MSG_SIZE 256

VOID 
ShowLastError(
	LPSTR			szCodeName, 
	NTSTATUS		dwCodeValue 
)
{
	static WCHAR	szMsgBuf[MAX_MSG_SIZE];
	NTSTATUS		dwWinError = LsaNtStatusToWinError(dwCodeValue);

	if (dwWinError == 0) 
		return;

	if (!FormatMessage (
				FORMAT_MESSAGE_FROM_SYSTEM,
				NULL,
				dwWinError,
				MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
				szMsgBuf,
				MAX_MSG_SIZE,
				NULL))
		wcscpy(szMsgBuf,L"Unknown error");

#if 0 /// 2002.0410 BILLDO -- AVOID PRINTF (USE GUI) /////////////////////////////////////////////////
	printf("    %s %x = %0d (0x%x = %0d): %S",
				szCodeName, dwCodeValue, dwCodeValue, 
				dwWinError, dwWinError, szMsgBuf);
#endif /// 2002.0410 BILLDO -- AVOID PRINTF (USE GUI) /////////////////////////////////////////////////
	MessageBox(myhMainWindow, szMsgBuf,TEXT("Kx509 Error"),MB_OK | MB_ICONWARNING);

}


VOID 
ShowNTError( 
	LPSTR		szAPI, 
	LPSTR		szCodeName, 
	NTSTATUS	dwCodeValue 
) 
{     
    printf("Error calling function %s.\n", szAPI);
   // 
    // Convert the NTSTATUS to Winerror. Then call ShowLastError().     
    // 
   ShowLastError(szCodeName, dwCodeValue);
} 


VOID
InitUnicodeString(
	PUNICODE_STRING DestinationString,
    PCWSTR SourceString OPTIONAL
    )
{
    ULONG Length;

    DestinationString->Buffer = (PWSTR)SourceString;
    if (SourceString != NULL) {
        Length = wcslen( SourceString ) * sizeof( WCHAR );
        DestinationString->Length = (USHORT)Length;
        DestinationString->MaximumLength = (USHORT)(Length + sizeof(UNICODE_NULL));
        }
    else {
        DestinationString->MaximumLength = 0;
        DestinationString->Length = 0;
        }
}


time_t FileTimeToUnixTime(LARGE_INTEGER *ltime)
{
	FILETIME filetime,localfiletime;
	SYSTEMTIME systime;
	struct tm utime;
	filetime.dwLowDateTime=ltime->LowPart;
	filetime.dwHighDateTime=ltime->HighPart;
	FileTimeToLocalFileTime(&filetime,&localfiletime);
	FileTimeToSystemTime(&localfiletime,&systime);
	utime.tm_sec=systime.wSecond;
	utime.tm_min=systime.wMinute;
	utime.tm_hour=systime.wHour;
	utime.tm_mday=systime.wDay;
	utime.tm_mon=systime.wMonth-1;
	utime.tm_year=systime.wYear-1900;
	utime.tm_isdst=-1;
	return(mktime(&utime));
}


#if 0 ///////////////////////////
extern BOOL WINAPI UnicodeToANSI(
	LPTSTR	lpInputString, 
	LPSTR	lpszOutputString, 
	int		nOutStringLen);
#else
BOOL WINAPI UnicodeToANSI(
	LPTSTR	lpInputString, 
	LPSTR	lpszOutputString, 
	int		nOutStringLen)
{         
	CPINFO	CodePageInfo;


	GetCPInfo(CP_ACP, &CodePageInfo);

	if (CodePageInfo.MaxCharSize > 1)
		// Only supporting non-Unicode strings
		return FALSE; 
	else if (((LPBYTE) lpInputString)[1] == '\0')
		{
		// Looks like unicode, better translate it
		WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) lpInputString, -1,
		 lpszOutputString, nOutStringLen, NULL, NULL);
		}
	else
		strcpy(lpszOutputString, (LPSTR) lpInputString);

	return TRUE;
}  // UnicodeToANSI
#endif ////////////////////////////////

VOID WINAPI ANSIToUnicode(
	LPSTR	lpInputString, 
	LPTSTR	lpszOutputString, 
	int		nOutStringLen
)
{         
	CPINFO	CodePageInfo;


	lstrcpy(lpszOutputString, (LPTSTR) lpInputString);

	GetCPInfo(CP_ACP, &CodePageInfo);

	if (CodePageInfo.MaxCharSize > 1)
		// It must already be a Unicode string
		return;
	else if (((LPBYTE) lpInputString)[1] != '\0')
	{
		// Looks like ANSI, better translate it
		MultiByteToWideChar(CP_ACP, 0, (LPCSTR) lpInputString, -1,
		(LPWSTR) lpszOutputString, nOutStringLen);
	}
}  // ANSIToUnicode


VOID WINAPI MSBufLenToANSIStr(
	WCHAR	*buf,
	int		len,
	char	*str
)
{
	WCHAR	tmp[512];

	wcsncpy(tmp, buf, len);
	tmp[len] = 0;
	UnicodeToANSI(tmp, str, 256);
}


BOOL 
PackageConnectLookup(
    HANDLE		*pLogonHandle, 
    ULONG		*pPackageId
)
{
    LSA_STRING	Name;
    NTSTATUS	Status;


    Status = LsaConnectUntrusted(
                pLogonHandle
                );

    if (!SEC_SUCCESS(Status))
    {
        ShowNTError("LsaConnectUntrusted", "Status", Status);
        return FALSE;
    }

    Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
    Name.Length = strlen(Name.Buffer);
    Name.MaximumLength = Name.Length + 1;

    Status = LsaLookupAuthenticationPackage(
                *pLogonHandle,
                &Name,
                pPackageId
                );

    if (!SEC_SUCCESS(Status))
    {
        ShowNTError("LsaLookupAuthenticationPackage", "Status", Status);
		LsaDeregisterLogonProcess(*pLogonHandle);
        return FALSE;
    }

    return TRUE;

}

#if 0
/* DEE Not used we use SSPI QueryAttributes  
 */   

BOOL
GetMSTGT(
	HANDLE							LogonHandle,
	ULONG							PackageId,
	char							*user,
	char							*realm
)
{
    NTSTATUS						Status;
    ULONG							ResponseSize;
    NTSTATUS						SubStatus;
    KERB_QUERY_TKT_CACHE_REQUEST	CacheRequest;
	PKERB_RETRIEVE_TKT_RESPONSE		TicketEntry = NULL;


    CacheRequest.MessageType		= KerbRetrieveTicketMessage;
    CacheRequest.LogonId.LowPart	= 0;	
    CacheRequest.LogonId.HighPart	= 0;


    Status = LsaCallAuthenticationPackage(
                LogonHandle,
                PackageId,
                &CacheRequest,	sizeof(CacheRequest),
                &TicketEntry,	&ResponseSize,
                &SubStatus
                );

 
	if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
    {
        ShowNTError("LsaCallAuthenticationPackage", "Status", Status);
		ShowLastError("SubStatus", SubStatus);
		return(FALSE);
    }

	MSBufLenToANSIStr(TicketEntry->Ticket.ClientName->Names[0].Buffer,
					  TicketEntry->Ticket.ClientName->Names[0].Length/sizeof(WCHAR),
					  user);

	MSBufLenToANSIStr(TicketEntry->Ticket.TargetDomainName.Buffer,
					  TicketEntry->Ticket.TargetDomainName.Length/sizeof(WCHAR),
					  realm);

	TicketEntry = (PKERB_RETRIEVE_TKT_RESPONSE)LsaFreeReturnBuffer(TicketEntry), NULL;

	return(TRUE);
}

#endif /* DEE */

SECURITY_STATUS
GetMSSvcTkt(
	HANDLE							LogonHandle,
	ULONG							PackageId,
	char							*ca_princ,
	char							*ca_inst,
	char							*ca_realm,
	DWORD							*pdwStartTime,
	DWORD							*pdwEndTime,
	BYTE							*pubAuthent,
	DWORD							*pdwAuthentLen,
	BYTE							*pubSessKey,
	DWORD							*pdwSessKeyLen
)
{
    NTSTATUS						Status			= 0;
    ULONG							ResponseSize	= 0;
    NTSTATUS						SubStatus		= 0;
	WORD							cbTicketRequest	= 0;
    KERB_RETRIEVE_TKT_REQUEST		*pTicketRequest = NULL;
	KERB_RETRIEVE_TKT_RESPONSE		*pTicketResponse= NULL;
	WCHAR							Server[256];
    KERB_EXTERNAL_TICKET			*pTicket		= NULL;
    UNICODE_STRING					Target			= {0}; 
    UNICODE_STRING					Target2			= {0};


	if (pdwAuthentLen) *pdwAuthentLen	= 0;
	if (pdwSessKeyLen) *pdwSessKeyLen	= 0;

	// translate narrow principal, instance and realm
	//		  to wide Server principal (SPN)

	swprintf(Server, L"%S/%S@%S", ca_princ, ca_inst, ca_realm);

	// then translate that to a Unicode string

    InitUnicodeString( &Target2, Server);

	// Do a stack-based malloc of the TicketRequest buffer (zero-init'd)

	cbTicketRequest = Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST);
    pTicketRequest = (KERB_RETRIEVE_TKT_REQUEST *)
						LocalAlloc(LMEM_ZEROINIT, cbTicketRequest);


	// Setup TicketRequest (force non-cached response)

    pTicketRequest->MessageType				 = KerbRetrieveEncodedTicketMessage ;
    pTicketRequest->LogonId.LowPart			 = 0;
    pTicketRequest->LogonId.HighPart		 = 0;
	// FORCE SVC TKT TO BE PLACED IN MS CRED CACHE
	pTicketRequest->CacheOptions			 = KERB_RETRIEVE_TICKET_AS_KERB_CRED
							|KERB_RETRIEVE_TICKET_USE_CREDHANDLE; 
					/*		|KERB_RETRIEVE_TICKET_USE_CACHE_ONLY; */
    pTicketRequest->TargetName.Buffer		 = (LPWSTR) (pTicketRequest + 1); // skip to end...
    pTicketRequest->TargetName.Length		 = Target2.Length;
    pTicketRequest->TargetName.MaximumLength = Target2.MaximumLength;
	pTicketRequest->CredentialsHandle.dwLower  = cred_handle.dwLower;
	pTicketRequest->CredentialsHandle.dwUpper  = cred_handle.dwUpper;


    CopyMemory(pTicketRequest->TargetName.Buffer, Target2.Buffer, Target2.Length);

	/* Moved so the SSPI will get the ticket, and the
	 * authenticator. We will then get the same ticket
	 * so the session key matches the authentictor.
	 */
	if (pubAuthent) {
		MSK5_Generate_Authenticator(Server, pubAuthent, pdwAuthentLen);
	}



	// Ask LSA for Kerberos Service Ticket

	 Status = LsaCallAuthenticationPackage(
                LogonHandle,
                PackageId,
                pTicketRequest,
                cbTicketRequest,
                (PVOID *) &pTicketResponse,
                &ResponseSize,
                &SubStatus
                );


	if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
    {
//        ShowNTError("LsaCallAuthenticationPackage", "Status", Status);
//		ShowLastError("SubStatus", SubStatus);
//		return(FALSE);
		if (Status)	return Status;
		return(SubStatus);
    }

	pTicket = &(pTicketResponse->Ticket);

	if (pdwEndTime) {
		*pdwEndTime = FileTimeToUnixTime(&(pTicket->EndTime));
	}

	if (pdwStartTime) {
		*pdwStartTime = FileTimeToUnixTime(&(pTicket->StartTime));
	}

	if (pubSessKey) {
		*pdwSessKeyLen	= pTicket->SessionKey.Length;
		memcpy(pubSessKey, pTicket->SessionKey.Value, *pdwSessKeyLen);
	}

	pTicketResponse = (KERB_RETRIEVE_TKT_RESPONSE *)LsaFreeReturnBuffer(pTicketResponse), NULL;


	return(0);
}



BOOL
MSK5_get_userid_and_realm(
	char					*user,
	char					*realm
)
{
	BOOL					rc = FALSE;
#if 0
	HANDLE					LogonHandle=NULL;
	ULONG					PackageId;
	

	if(PackageConnectLookup(&LogonHandle, &PackageId))
	{
		if (GetMSTGT(LogonHandle, PackageId,user, realm))
		{
			rc = TRUE;
		}
		LsaDeregisterLogonProcess(LogonHandle);
	}
#else
	SECURITY_STATUS maj_status;

    SecPkgCredentials_Names CredName = {NULL}; /* must cleanup */
	PWCHAR pwuser = NULL;   /* points into CredName */
    PWCHAR pwrealm = NULL;  /* points into CredName */

	maj_status = QueryCredentialsAttributes(&cred_handle,
                                    SECPKG_CRED_ATTR_NAMES,
                                    &CredName);
    if (maj_status != SEC_E_OK) {
		ShowNTError("QueryCredentialsAttributes","Status", maj_status);
        goto cleanup;
    }

    /* break the principal into user and realm */
    /* and return as client user and cell. No instance for now */
    pwuser = CredName.sUserName;
    pwrealm = wcschr(CredName.sUserName,L'@');
 
    if (pwrealm) {
        *pwrealm = 0;
        pwrealm++;
    }

	/* user and realm are based in but not the lengths. 
	 * based on looking a tthe code it loks like the lengths are
	 * 256 and 50 
	 * This needs to be fixed 
	 */
    WideCharToMultiByte(CP_ACP, 0, pwuser, lstrlen(pwuser)*sizeof(WCHAR),
            user, 256 , NULL, NULL);

    WideCharToMultiByte(CP_ACP, 0, pwrealm, lstrlen(pwrealm)*sizeof(WCHAR),
            realm, 50, NULL, NULL);

	rc = TRUE;

cleanup:
	if (CredName.sUserName) {
        FreeContextBuffer(CredName.sUserName);
    }
#endif

	return rc;
}


BOOL
MSK5_get_authent_and_sesskey(
	char					*ca_princ,
	char					*ca_inst,
	char					*ca_realm,
	BYTE					*pubAuthent,
	DWORD					*pdwAuthentLen,
	BYTE					*pubSessKey,
	DWORD					*pdwSessKeyLen
)
{
	HANDLE					LogonHandle	= NULL;
	ULONG					PackageId	= 0;
	BOOL					rc			= FALSE;
	DWORD					EndTime		= 0;

    
	if(PackageConnectLookup(&LogonHandle, &PackageId))
	{
		if (GetMSSvcTkt(LogonHandle, PackageId,
						ca_princ, ca_inst, ca_realm,
						NULL, &EndTime, 
						pubAuthent, pdwAuthentLen, 
						pubSessKey, pdwSessKeyLen) == 0)
		{
			rc = TRUE;
		}
		LsaDeregisterLogonProcess(LogonHandle);
	}

	return rc;
}





BOOL
MSK5_test_authent_to_ksvr(
	char	*ca_princ,
	char	*ca_inst,
	char	*ca_realm,
	BYTE	*pubAuthent,
	DWORD	*pdwAuthentLen,
	BYTE	*pubSessKey,
	DWORD	*pdwSessKeyLen
)
{
	int				sock;
	struct hostent	*ca_hostent;
	struct sockaddr_in ca_addr;
	struct sockaddr_in sockaddr;
	int				rc=0;
	int				i;
	int				arg=1;

	char			*ca_hostname = "zingara.citi.umich.edu";	// 2002.0406 BILLDO -- HARD-CODED
	unsigned char	version_2_0_string[4] = {0,0,2,0};
	unsigned int	len=0;

	KX_MSG			pkt_to_send;
	KX509_REQUEST	*request = 0;
	RSA				*rsa=NULL;
#define ENTROPY_NEEDED 20  /* require 160 bits = 20 bytes of randomness */
	char			entropy_pool[ENTROPY_NEEDED];
	unsigned int	entropy_still_needed = ENTROPY_NEEDED;
	unsigned char	buffer[1024];
	unsigned char	*pubkey_ptr=NULL;
	unsigned char	*tmp_ptr=NULL;
	int				pubkey_len=0;
	int				keybits=DEFBITS;	/* Number of bits in the public key / private key */
	WORD			wVersionRequested;
	WSADATA			wsaData;
	int				err;



	/* GET SOCKET */


	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 )
		return FALSE;
 
	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
			HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		WSACleanup( );
		return FALSE;
	}
 
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return FALSE;

	memset(&sockaddr, 0, sizeof(struct sockaddr_in));
	if (ioctlsocket(sock, FIONBIO, &arg) < 0)
		return FALSE;

	/*
	 * THIS COULD BE **BETTER** -- Starting with Openssl-0.9.6, the
	 * RAND functions insist that ENTROPY_NEEDED (20) bytes of seed
	 * material be provided before they will work at all.  As a really
	 * cheesy work-around, the code below simply copies the 8-byte
	 * kerberos session-key a couple times to generate 24-bytes of
	 * entropy...
	 */

	memcpy(entropy_pool, pubSessKey, *pdwSessKeyLen); /* assume need > 1 key */
	entropy_still_needed -= *pdwSessKeyLen;
	while (entropy_still_needed > 0)
	{
		if (entropy_still_needed < *pdwSessKeyLen)
		{
			memcpy(&entropy_pool[ENTROPY_NEEDED-entropy_still_needed],
				pubSessKey, entropy_still_needed);
			entropy_still_needed = 0;
		}
		else
		{
			memcpy(&entropy_pool[ENTROPY_NEEDED-entropy_still_needed],
				pubSessKey, *pdwSessKeyLen);
			entropy_still_needed -= *pdwSessKeyLen;
		}
	}

	/* GENERATE PUBLIC KEY PAIR  */

	RAND_seed(entropy_pool, ENTROPY_NEEDED);

	rsa=client_genkey(keybits); 

	memset(buffer, 0, sizeof(buffer));	/* BILLDO 2001.0330 -- something causes 1st try_ca failures to make later try_ca's fail... */
	pubkey_ptr	= buffer;
	tmp_ptr		= pubkey_ptr;
	pubkey_len	= i2d_RSAPublicKey (rsa, &tmp_ptr);


	/* REQUEST := AUTHENT + PUBKEY + CHKSUM */

	request = KX509_REQUEST_new();
	fill_in_octet_string(request->authenticator,
		pubAuthent, *pdwAuthentLen);
	fill_in_octet_string(request->pkey, pubkey_ptr, pubkey_len);
	KX509_REQUEST_compute_checksum(version_2_0_string, request,
		request->hash, pubSessKey, *pdwSessKeyLen);

	/* CONVERT REQUEST STRUCTURE TO WIRE-VERSION MSG */

	len = i2d_KX509_REQUEST(request, 0) + 4;	// desired len: REQ + 2_0 str
	if (len > MAX_UDP_PAYLOAD_LEN)
		return FALSE;

	if (MSG_ALLOC(&pkt_to_send, len))			// malloc desired len
		return FALSE;

	memcpy(pkt_to_send.m_data, version_2_0_string, 4);	// start with vers str
	tmp_ptr = pkt_to_send.m_data+4;
	i2d_KX509_REQUEST(request, &tmp_ptr);				// finish with req
	pkt_to_send.m_curlen = tmp_ptr - pkt_to_send.m_data;

	/* DETERMINE IP ADDRESS OF KCA SERVER */

	if (!(ca_hostent = gethostbyname(ca_hostname)))
		return FALSE;

	memset(&ca_addr, 0, sizeof(ca_addr));
	ca_addr.sin_family	= AF_INET;
	ca_addr.sin_port	= htons(KRBCHK_PORT);
	ca_addr.sin_addr.s_addr	= *(int *)(ca_hostent->h_addr_list[0]);

	/* "CONNECT" TO IT (ICMP RESPONSE INDICATES HOST ISN'T LISTENING ON THAT PORT) */

	rc = connect(sock, (struct sockaddr *)&ca_addr, sizeof(struct sockaddr));
	if (rc < 0)
		return FALSE;

	/* SOMETHINGS LISTENING -- SEND PACKET */

	i = send(sock, &pkt_to_send.m_data[0], pkt_to_send.m_curlen, 0);

	return(TRUE);
}







AUTH_RTNS MSK5_Package[] = {
	&MSK5_get_userid_and_realm,
	&MSK5_get_authent_and_sesskey,
	&MSK5_test_authent_to_ksvr
};

BOOL
MSK5_acquire_cred_handle()
{
	SECURITY_STATUS maj_stat;
	SEC_WINNT_AUTH_IDENTITY_EXA AuthIdentity; /* no cleanup */
	HANDLE					LogonHandle	= NULL;
	ULONG					PackageId	= 0;
	char user_at_realm[256];
	char password[256];
	char * realm;
	int prompting = 0;

	dialog_u_pw_params dupwp = {0, 
				"KX509 Prompter",
				"User@Realm",
				 user_at_realm, sizeof(user_at_realm),
				 "Password",
				 password, sizeof(password)};

log_printf("MSK5_acquire_cred_handle bPwdPrompt %d cred_handle %d %d\n",
                         bPwdPrompt, cred_handle.dwLower, cred_handle.dwUpper);

	memset(user_at_realm, 0, sizeof(user_at_realm));
	memset(password, 0, sizeof(password));


 /* DEE stop gap to get to work with MS W2K AD as KDC
  * we need a small ticket without a PAC. 
  * The SEC_WINNT_AUTH_IDENTITY_ONLY sents PA-DATA for no PAC.
  * MIT KDC does not understand this. So only use with W2K
  */    

	memset(&AuthIdentity, 0, sizeof(AuthIdentity));
	AuthIdentity.Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
	AuthIdentity.Length = sizeof(AuthIdentity);
	AuthIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI 
						   | SEC_WINNT_AUTH_IDENTITY_ONLY ;

	if (bPwdPrompt == TRUE) {
		bPwdPrompt = FALSE;
		prompting = 1;
tryagain:
		read_user_password_dialog(myhInstance,
							 0 /* since our window is not shown, put on top. myhMainWindow*/,
							 &dupwp);

		if (dupwp.rc && user_at_realm[0] && password[0]) {
			prompting = 2;
			AuthIdentity.User = user_at_realm;
			realm = strchr(user_at_realm,'@');
			if (realm) {
				AuthIdentity.UserLength = realm - user_at_realm;
					realm++;
			} else {
				AuthIdentity.UserLength = strlen(AuthIdentity.User);
			}
			if (realm) {
				CharUpperBuffA(realm, strlen(realm));
			} else {
				realm = "ANL.GOV"; /* DEE really gross, assume at ANL.GOV */
			}
			AuthIdentity.Domain = realm;
			AuthIdentity.DomainLength = strlen(AuthIdentity.Domain);

			AuthIdentity.Password = password;
			AuthIdentity.PasswordLength = strlen(AuthIdentity.Password);
		} else {
			prompting = 1;
		}
 
	}

	maj_stat = AcquireCredentialsHandle(
                                      NULL,                       // no principal name
                                      L"Kerberos",                 // package name
                                      SECPKG_CRED_OUTBOUND,
                                      NULL,                       // no logon id
                                      &AuthIdentity,
                                      NULL,                       // no get key fn
                                      NULL,                       // noget key arg
                                      &cred_handle,
                                      NULL
                                      );
   if (maj_stat != SEC_E_OK)
   {
	   /* DEE AcquireCredHandle may return OK, when used with the IDENTITY_ONLY
	    * It does not get a TGT at this time!
	    * This looks like a bug, to me.
		* When MS gets no PAC fix for AD, I think it might work.
		*/
	log_printf("acquire failed prompting=%d\n",prompting);
	   if (prompting > 0) {
		   ShowNTError("AcquireCrednetialPackage","Status", maj_stat);
		   		   if (prompting > 1) goto tryagain;
//      display_status("acquiring credentials",maj_stat,0);
	   }
      return FALSE;
   }

   if (prompting >1) {
	   /* since AcquireCredHandle may not actually try and get a TGT, we will
	    * have to do it here, to test if the user@realm and password are valid.
		* This is really gross of MS!
		*/

		if(PackageConnectLookup(&LogonHandle, &PackageId))
		{
			maj_stat = GetMSSvcTkt(LogonHandle, PackageId,
							"krbtgt", realm , realm,
							NULL, NULL,
							NULL, 0, 
							NULL, 0);
			LsaDeregisterLogonProcess(LogonHandle);
			if (maj_stat) {
				ShowNTError("GetMSSvcTkt","Status",maj_stat);
				goto tryagain;
			}
	}
   }
   return TRUE;
}
#endif // USE_MSK5
