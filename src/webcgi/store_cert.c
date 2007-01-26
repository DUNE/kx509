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
#include "krbchk_ie.h"
#include <winsock.h>         // Must be included before <windows.h> !!! 
#include <windows.h>

#define OUR_CERTIFICATE_AUTHORITY	L"US, Michigan, Ann Arbor, University of Michigan, TEST -- CITI Client CA v1"
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void HandleError(char *s);

void clean_cert_store()
{
	HCERTSTORE          hStoreHandle;
	PCCERT_CONTEXT      pCertContext=NULL;      
	DWORD				dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwAddDisposition = CERT_STORE_ADD_REPLACE_EXISTING;
	DWORD				dwFindFlags = 0;
	DWORD				dwFindType = CERT_FIND_ISSUER_STR;
	int					rc;
	FILE				*log_file = NULL;
	WCHAR				vFindPara[] = OUR_CERTIFICATE_AUTHORITY;


	log_file = stdout;

	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("The MY system store did not open.");
	}


	// Find and Delete all MY store certs issued by our Certificate Authority

LOOP:
		if ((pCertContext = CertFindCertificateInStore(
						hStoreHandle,					// in
						dwCertEncodingType,				// in
						dwFindFlags,					// in
						dwFindType,						// in
						&vFindPara,						// in
						NULL							// in
						)))
		{
			if (CertDeleteCertificateFromStore(pCertContext))
				fprintf(log_file, "deleted cert\n");
			else
			{
				rc = GetLastError();
				fprintf(log_file, "FAILED         TO       DELETE        CERT    DUE    TO   0x%lX\n", rc);
			}

			goto LOOP;
		}
} // clean_cert_store


int store_cert(BYTE *cert, DWORD len)
{
	HCERTSTORE          hStoreHandle;
	PCCERT_CONTEXT      pCertContext=NULL;      
	CRYPT_KEY_PROV_INFO NewProvInfo;
	DWORD               dwPropId; 
	DWORD               dwFlags =  CERT_STORE_NO_CRYPT_RELEASE_FLAG;
	DWORD				dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwAddDisposition = CERT_STORE_ADD_REPLACE_EXISTING;
	DWORD				dwErr;
	DWORD				dwFindFlags = 0;
	DWORD				dwFindType = CERT_FIND_ISSUER_STR;
	WCHAR				vFindPara[] = OUR_CERTIFICATE_AUTHORITY;
	FILE				*log_file = NULL;
	int					rc;


	log_file = stdout;

	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("The MY system store did not open.");
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
			fprintf(log_file, "CertAddEncodedCertificateToStore returned CRYPT_E_EXISTS\n");
		}
		else if ((dwErr & CRYPT_E_OSS_ERROR) == CRYPT_E_OSS_ERROR)
		{
			fprintf(log_file, "CertAddEncodedCertificateToStore returned CRYPT_E_OSS_ERROR"
						" with GetLastError() returning %0d\n", dwErr);
		}
		else
		{
			fprintf(log_file, "CertAddEncodedCertificateToStore failed with %08X\n", dwErr);
		}

		return 0;
	}

	//--------------------------------------------------------------------
	// Initialize the CRYPT_KEY_PROV_INFO data structure.
	// Note: pwszContainerName and pwszProvName can be set to NULL 
	// to use the default container and provider.

	NewProvInfo.pwszContainerName = NULL;
	NewProvInfo.pwszProvName = MS_DEF_PROV_W;
	NewProvInfo.dwProvType = PROV_RSA_FULL;
	NewProvInfo.dwFlags = 0;
	NewProvInfo.cProvParam = 0;
	NewProvInfo.rgProvParam = NULL;
	NewProvInfo.dwKeySpec = AT_KEYEXCHANGE;	//	AT_SIGNATURE; // 

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
          HandleError("Set property failed.\n ");
     }

	//--------------------------------------------------------------------
	// Clean up.

	CertFreeCertificateContext(pCertContext);
	if(!CertCloseStore(
			hStoreHandle,
			CERT_CLOSE_STORE_CHECK_FLAG))
	{
		fprintf(log_file, "The store was closed, but certificates still in use.\n");
	}

	fclose(log_file);

	return 1; 
}  // End store_cert
