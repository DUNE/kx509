/*
 * Copyright  ©  2000,2007
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
#include "debug.h" 

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void clean_cert_store(char *realm)
{
	HCERTSTORE			hStoreHandle		= 0;
	PCCERT_CONTEXT		pCertContext		= NULL;      
	PCCERT_CONTEXT		prev_pCertContext	= NULL;      
	DWORD				dwCertEncodingType	= X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwAddDisposition	= CERT_STORE_ADD_REPLACE_EXISTING;
	DWORD				dwFindFlags			= 0;
# define			OID_KCA_AUTHREALM	"1.3.6.1.4.1.250.42.1"
	DWORD				dwFindType			= CERT_FIND_ANY;
	CERT_INFO			*pCertInfo			= NULL;
	PCERT_EXTENSION		pCertExt			= NULL;
	CRYPT_OBJID_BLOB	*p					= NULL;
	int					i					= 0;
	char				tmpRealm[250]		= { 0 };


	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("Strange.  Unable to access your place in the Registry for certificates");
		goto EXIT_RTN;
	}


	// Find and Delete all MY store certs issued by our Certificate Authority

LOOP:
		if ((pCertContext = CertFindCertificateInStore(
						hStoreHandle,					// in
						dwCertEncodingType,				// in
						dwFindFlags,					// in
						dwFindType,					// in
						NULL,						// in
						prev_pCertContext			// in
						)))
		{
			if (pCertInfo = pCertContext->pCertInfo)
				for (i = pCertInfo->cExtension; i; i--)
				{
					pCertExt = &pCertInfo->rgExtension[i-1];
					if (!strcmp(pCertExt->pszObjId, OID_KCA_AUTHREALM))
					{
						log_printf("Found KCA_AUTHREALM Extension\n");
						p = &pCertExt->Value;
						memcpy(tmpRealm, &p->pbData[2], p->cbData-2);
						tmpRealm[p->cbData-2] ='\0';
						log_printf("   value is: '%s'\n", tmpRealm);

						/* only delete if realm of current TGT matches AuthRealm of this cert */
						if (!strcmp(realm, tmpRealm))
						{
							if (CertDeleteCertificateFromStore(pCertContext))
								log_printf("Successfully deleted previously obtained certificate for realm %s\n", realm);
							else
							{
								msg_printf("Unable to delete previous certificates for realm %s, error 0x%08x -- %s",
									realm, GetLastError(), GetLastErrorText());
							}

							/* since this cert's pointer is now deleted, */
							/*	we should ask again using prev_pCertContext */
							/*DEE but prev_pCertContext was freed, so set it to null and start over */
							prev_pCertContext = NULL;
							goto LOOP;
						}
					}
				}

			/* this cert unaffected, so find cert following it */

/* DEE - CertFindCertificateInStore will free the prev_pCertContext so don't do it here */
//			if (prev_pCertContext)
//				prev_pCertContext = (PCCERT_CONTEXT)CertFreeCertificateContext(prev_pCertContext), NULL;

			prev_pCertContext = pCertContext;
			goto LOOP;
		}

EXIT_RTN:
/* DEE - CertFindCertificateInStore will free the prev_pCertContext so don't do it here */
//	if (prev_pCertContext)
//		prev_pCertContext = (PCCERT_CONTEXT)CertFreeCertificateContext(prev_pCertContext), NULL;

	if ((prev_pCertContext != pCertContext) && pCertContext)
		pCertContext = (PCCERT_CONTEXT)CertFreeCertificateContext(pCertContext), NULL;

	if(hStoreHandle && !CertCloseStore(
			hStoreHandle,
#ifdef DEBUG
			CERT_CLOSE_STORE_CHECK_FLAG
#else // !DEBUG
			CERT_CLOSE_STORE_FORCE_FLAG
#endif // ! DEBUG
			))
	{
		log_printf("The store was closed, but certificates still in use.\n");
	}

} // clean_cert_store


int store_cert(BYTE *cert, DWORD len)
{
	HCERTSTORE          hStoreHandle		= 0;
	PCCERT_CONTEXT      pCertContext		= NULL;      
	CRYPT_KEY_PROV_INFO NewProvInfo			= { 0 };
	DWORD               dwPropId			= 0; 
	DWORD               dwFlags				= CERT_STORE_NO_CRYPT_RELEASE_FLAG;
	DWORD				dwCertEncodingType	= X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwErr				= 0;
	DWORD				dwFindFlags			= 0;
	DWORD				dwAddDisposition	= CERT_STORE_ADD_NEW;
	int					rc					= 0;


	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("The MY system store did not open.");
		goto EXIT_RTN;
	}


	//--------------------------------------------------------------------
	// Add caller-provided certificate to the MY store.

	if (!(rc = CertAddEncodedCertificateToStore(
			hStoreHandle,
			dwCertEncodingType,
			cert,
			len,
			dwAddDisposition,
			&pCertContext)))			// returned pointer to CERT_CONTEXT
	{
		dwErr = GetLastError();
		if (dwErr == CRYPT_E_EXISTS)
		{
			log_printf("CertAddEncodedCertificateToStore returned CRYPT_E_EXISTS\n");
			msg_printf("Couldn't add your Certificate to Registry (CRYPT_E_EXISTS)");
		}
		else if ((dwErr & CRYPT_E_OSS_ERROR) == CRYPT_E_OSS_ERROR)
		{
			log_printf("CertAddEncodedCertificateToStore returned CRYPT_E_OSS_ERROR"
						" with GetLastError() returning 0x%08x -- %s\n", dwErr, GetLastErrorText());
			msg_printf("Couldn't add your Certificate to Registry (CRYPT_E_OSS_ERROR) -- %s", GetLastErrorText());
		}
		else
		{
			log_printf("CertAddEncodedCertificateToStore failed with 0x%08x -- %s\n", dwErr, GetLastErrorText());
			msg_printf("Couldn't add your Certificate to Registry (0x%08x -- %s)",dwErr, GetLastErrorText());
		}

		return 0;
	}

	//--------------------------------------------------------------------
	// Initialize the CRYPT_KEY_PROV_INFO data structure.
	// Note: pwszContainerName and pwszProvName can be set to NULL 
	// to use the default container and provider.

//	memset(&NewProvInfo, 0, sizeof(NewProvInfo));

	NewProvInfo.pwszContainerName	= NULL;
	NewProvInfo.pwszProvName		= MS_DEF_PROV_W;
	NewProvInfo.dwProvType			= PROV_RSA_FULL;
	NewProvInfo.dwFlags				= 0;
	NewProvInfo.cProvParam			= 0;
	NewProvInfo.rgProvParam			= NULL;
	NewProvInfo.dwKeySpec			= AT_KEYEXCHANGE;	//	AT_SIGNATURE; // 

	//--------------------------------------------------------------------
	// Set the property.

	dwPropId = CERT_KEY_PROV_INFO_PROP_ID; 
	if(!CertSetCertificateContextProperty(
			pCertContext,	// A pointer to the certificate
							// where the property will be set.
			 dwPropId,      // An identifier of the property to be 
							// set. In this case,
							// CERT_KEY_PROV_INFO_PROP_ID is to be set to
							// provide a pointer with the certificate to
							// its associated private key container.
			dwFlags,		// The flag used in this case is   
							// CERT_STORE_NO_CRYPT_RELEASE_FLAG,
							// indicating that the cryptographic 
							// context acquired should not
							// be released when the function finishes.
			&NewProvInfo))	// A pointer to a data structure that holds
							// information on the private key container to
							// be associated with this certificate.
     {
          HandleError("Set property failed.");
     }

	//--------------------------------------------------------------------
	// Clean up.

	pCertContext = (PCCERT_CONTEXT)CertFreeCertificateContext(pCertContext), NULL;

EXIT_RTN:
	if(hStoreHandle && !CertCloseStore(
			hStoreHandle,
#ifdef DEBUG
			CERT_CLOSE_STORE_CHECK_FLAG
#else // !DEBUG
			CERT_CLOSE_STORE_FORCE_FLAG
#endif // ! DEBUG
			))
	{
		log_printf("The store was closed, but certificates still in use.\n");
	}

	return 1; 
}  // End store_cert
