/*
 * Copyright  ©  2000
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

#include <afx.h>

#include <tchar.h>
#include <stdio.h>

#ifdef UNICODE 
#define USTR	L 
#else 
#define	USTR 
#endif // UNICODE 
 
#define	MY_STORE	USTR"My" 

#include <winsock.h>         // Must be included before <windows.h> !!! 
#include <windows.h>
#include <wincrypt.h>

extern "C" void log_printf(char *, ...);
extern "C" void HandleError(char *);



// defeat Microsoft name-mangling of C++ routine so it can be called from .c files
extern "C" long certLife(char *);


void 
get_cert_time_left(
	char				*realm,
	CTimeSpan			*ptimeLeft
)
{
	HCERTSTORE			hStoreHandle		= NULL;
	PCCERT_CONTEXT		pCertContext		= NULL;      
	PCCERT_CONTEXT		prev_pCertContext	= NULL;      
	DWORD				dwCertEncodingType	= X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwAddDisposition	= CERT_STORE_ADD_REPLACE_EXISTING;
	DWORD				dwFindFlags			= 0;
# define				OID_KCA_AUTHREALM	"1.3.6.1.4.1.250.42.1"
	DWORD				dwFindType			= CERT_FIND_ANY;
	CERT_INFO			*pCertInfo			= NULL;
	PCERT_EXTENSION		pCertExt			= NULL;
	CRYPT_OBJID_BLOB	*p					= NULL;
	int					i					= 0;
	char				tmpRealm[250]		= { 0 };
	CTime				startTime			= 0;
	CTime				endTime				= 0;



	memset(ptimeLeft, 0, sizeof(*ptimeLeft));

	if (!realm || !strlen(realm))
		return;

	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("get_cert_time_left: Strange.  Unable to access your place in the Registry for certificates");
		goto EXIT_RTN;
	}


	// Find first MY store cert issued by our Certificate Authority

	while ((pCertContext = CertFindCertificateInStore(
						hStoreHandle,					// in
						dwCertEncodingType,				// in
						dwFindFlags,					// in
						dwFindType,						// in
						NULL,							// in
						prev_pCertContext				// in
						)))
	{
		if (pCertInfo = pCertContext->pCertInfo)
			for (i = pCertInfo->cExtension; i; i--)
			{
				pCertExt = &pCertInfo->rgExtension[i-1];
				if (!strcmp(pCertExt->pszObjId, OID_KCA_AUTHREALM))
				{
					log_printf("get_cert_time_left: Found KCA_AUTHREALM Extension\n");

					p = &pCertExt->Value;
					memcpy(tmpRealm, &p->pbData[2], p->cbData-2);
					tmpRealm[p->cbData-2] ='\0';
					log_printf("get_cert_time_left:    value is: '%s'\n", tmpRealm);

					/* only match if realm of current TGT matches AuthRealm of this cert */
					if (realm && !strcmp(realm, tmpRealm))
					{
						// It matches, determine remaining certificate's remaining minutes
						startTime	= CTime::GetCurrentTime();
						endTime		= pCertContext->pCertInfo->NotAfter;
						*ptimeLeft	= endTime - startTime;

						goto EXIT_RTN;
					}
				}
			}

		prev_pCertContext = pCertContext;
	}

EXIT_RTN:
	if ((prev_pCertContext != pCertContext) && pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
		pCertContext = NULL;
	}

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	if(hStoreHandle &&!CertCloseStore(
							hStoreHandle,
#ifdef DEBUG
							CERT_CLOSE_STORE_CHECK_FLAG
#else // !DEBUG
							CERT_CLOSE_STORE_FORCE_FLAG
#endif // ! DEBUG
			))
	{
		log_printf("get_cert_time_left: The store was closed, but certificates still in use.\n");
	}
} // get_cert_time_left


long certLife(char *realm)
{
	CTimeSpan		timeLeft	= 0;
	long			lifeLeft	= 0;


	get_cert_time_left(realm, &timeLeft);
	lifeLeft = timeLeft.GetTotalMinutes();

	return lifeLeft;
}

