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
#include <wincrypt.h>

#include "debug.h" 

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


/*----------------------------------------------------------------------*/
/* This routine gets the Common Name attribute from a CERT_INFO		*/
/* structure.  It returns TRUE if successful, or FALSE otherwise.	*/
/*----------------------------------------------------------------------*/

BOOL getCommonNameFromCertContext
(
	PCCERT_CONTEXT	pCertContext, 
	char			**ppName, 
	int				*pNamelen
)
{
	DWORD			cbDecoded	= 0;		/* Length of decoded output */
	BYTE			*pbDecoded	= NULL;		/* Decoded output of subject name */
	PCERT_NAME_INFO pNameInfo	= NULL;		/* Ptr to NAME_INFO structure */
	DWORD			i			= 0;
	BOOL			retval		= FALSE;	/* Be a pessimist */
	

	if (!pCertContext || !ppName || !pNamelen)
	{
		log_printf("getCommonNameFromCertContext: missing param (0x%08x 0x%08x 0x%08x)\n",
			pCertContext, ppName, pNamelen);
		goto EXIT_GET;
	}
	
	/* First get the length needed for the decoded output */
	if (!CryptDecodeObject(
		MY_ENCODING_TYPE,	/* Encoding type */
		((LPCSTR) 7),		/* (X509_NAME) this definition from */
					/* wincrypt.h conflicts with a */
					/* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			    /* Flags */
		NULL,			/* Just getting req'd length */
		&cbDecoded))		/* where to return the length */
	{
		log_printf("getCommonNameFromCertContext: error (0x%08x) "
			"getting length of decoded subject name\n", GetLastError());
		goto EXIT_GET;
	}
	
	/* Allocate the space for the decoded Subject data */
	if ( (pbDecoded = (BYTE*)malloc(cbDecoded)) == NULL )
	{
		log_printf("getCommonNameFromCertContext: Could not obtain %d bytes "
			"for decoded subject.\n", cbDecoded);
		goto EXIT_GET;
	}
	
	/* Now, get the decoded subject output */
	if (!CryptDecodeObject(
		MY_ENCODING_TYPE,	/* Encoding type */
		((LPCSTR) 7),		/* (X509_NAME) this definition from */
					/* wincrypt.h conflicts with a */
					/* definition in OpenSSL ... */
		pCertContext->pCertInfo->Subject.pbData,	/* The thing to be decoded */
		pCertContext->pCertInfo->Subject.cbData,	/* Length of thing to be decoded */
		0,			/* Flags */
		pbDecoded,		/* Return the decoded subject info */
		&cbDecoded))		/* and it's length */
	{
		log_printf("getCommonNameFromCertContext: error (0x%08x) decoding subject name\n",
			GetLastError());
		goto EXIT_GET;
	}
	
	pNameInfo = (PCERT_NAME_INFO)pbDecoded;
	
	/* Loop through all the RDN elements, looking for the Common Name */
	for (i = 0; i < pNameInfo->cRDN; i++)
	{
		log_printf("getCommonNameFromCertContext: RDN %d\tOID '%s'\tString '%s'\n",
			i, pNameInfo->rgRDN[i].rgRDNAttr->pszObjId,
			pNameInfo->rgRDN[i].rgRDNAttr->Value.pbData);
		if (!strcmp(pNameInfo->rgRDN[i].rgRDNAttr->pszObjId, szOID_COMMON_NAME))
		{
			log_printf("getCommonNameFromCertContext: Found Common Name at index %d\n",
				i);
			break;
		}
	}
	
	/* If we found the right RDN, get it's value into a string */
	if (i < pNameInfo->cRDN)
	{
		memcpy(*ppName, pNameInfo->rgRDN[i].rgRDNAttr->Value.pbData, pNameInfo->rgRDN[i].rgRDNAttr->Value.cbData);
		(*ppName)[pNameInfo->rgRDN[i].rgRDNAttr->Value.cbData] = '\0';
		retval = TRUE; /* SUCCESS */
	}
	else
	{
		log_printf("getCommonNameFromCertContext: Could not locate Common Name RDN value!\n");
	}
	
EXIT_GET:
	if (pbDecoded)
	{
		free(pbDecoded);
		pbDecoded = NULL;
	}
	
	return retval;
}


char *get_cert_subj(char *realm)
{
	HCERTSTORE			hStoreHandle;
	PCCERT_CONTEXT		pCertContext=NULL;      
	PCCERT_CONTEXT		prev_pCertContext=NULL;      
	DWORD				dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD				dwAddDisposition = CERT_STORE_ADD_REPLACE_EXISTING;
	DWORD				dwFindFlags = 0;
# define				OID_KCA_AUTHREALM	"1.3.6.1.4.1.250.42.1"
	DWORD				dwFindType = CERT_FIND_ANY;
	CERT_INFO			*pCertInfo = NULL;
	PCERT_EXTENSION		pCertExt = NULL;
	CRYPT_OBJID_BLOB	*p = NULL;
	int					i = 0;
	char				tmpRealm[250];
	char				tmpUserID[250];
	char				*pUserID = &tmpUserID[0];
	int					cbUserID = 0;
	char				*pbSubj = NULL;


	if (!realm || !strlen(realm))
		return pbSubj;

	//--------------------------------------------------------------------
	// Open a store as the source of the certificates to be deleted and added

	if(!(hStoreHandle = CertOpenSystemStore(
			0,
			MY_STORE)))
	{
		HandleError("get_cert_subj: Strange.  Unable to access your place in the Registry for certificates");
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
					log_printf("get_cert_subj: Found KCA_AUTHREALM Extension\n");

					p = &pCertExt->Value;
					memcpy(tmpRealm, &p->pbData[2], p->cbData-2);
					tmpRealm[p->cbData-2] ='\0';
					log_printf("get_cert_subj:    value is: '%s'\n", tmpRealm);

					/* only match if realm of current TGT matches AuthRealm of this cert */
					if (!strcmp(realm, tmpRealm))
					{
						/* get UserID from Cert */
						if (getCommonNameFromCertContext(pCertContext, &pUserID, &cbUserID))
						{
							/* Allocate the space for the decoded Subject data */
							if ( (pbSubj = (BYTE*)malloc(256)) == NULL )
							{
								log_printf("get_cert_subj: Could not obtain %d bytes "
									"for decoded subject.\n", 256);
								goto EXIT_RTN;
							}

							sprintf(pbSubj, "%s@%s", tmpUserID, tmpRealm);
							goto EXIT_RTN;
						}
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

	if(!CertCloseStore(
			hStoreHandle,
#ifdef DEBUG
			CERT_CLOSE_STORE_CHECK_FLAG
#else // !DEBUG
			CERT_CLOSE_STORE_FORCE_FLAG
#endif // ! DEBUG
			))
	{
		log_printf("get_cert_subj: The store was closed, but certificates still in use.\n");
	}

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	return pbSubj;
} // get_cert_subj
