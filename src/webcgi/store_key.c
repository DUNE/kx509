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

//------------------------------------------------------------------------------------
//
// OVERVIEW:
//
// store_key is called, provided with "p" -- a pointer to a
//     CryptoAPI PRIVKEYBLOB (see rsa_to_keyblob.cc)
//
// store_key's raison d'etre is to:
//
//   Import the provided PRIVKEYBLOB into the "default" Key Container,
//      creating this container if it doesn't already exist.
//
//------------------------------------------------------------------------------------

#include <stdio.h>
#include "krbchk_ie.h"
#include <windows.h>
#include <wincrypt.h>

void HandleError(char *s);

int store_key(BYTE *p, DWORD cbPk)
{
	HCRYPTPROV				hCryptProv;
	HCRYPTKEY				hKey;


	//----------------------------------------
	// ACQUIRE CRYPT CONTEXT
	if(!CryptAcquireContext(
		&hCryptProv,				// Handle to the CSP
		NULL,						// ContainerName
		MS_DEF_PROV,				// Provider name   
		PROV_RSA_FULL,				// Provider type
		0))							// Flag values  (?? CRYPT_SILENT ??)
	{ 
		printf("initial CryptAcquireContext returned 0x%8X\n.",GetLastError());

		//--------------------------------------------------------------------
		// NO PRE-EXISTING CONTAINER.  Create a new default key container. 
	   if(!CryptAcquireContext(
			&hCryptProv, 
			NULL,					// ContainerName
			MS_DEF_PROV,			// Provider name 
			PROV_RSA_FULL,			// Provider type
			CRYPT_NEWKEYSET)) 
		{
			HandleError("Could not create a new key container.\n");
		}
	}

	// NOW IMPORT CALLER'S RSA KEY INTO THAT CONTAINER'S SIGNATURE KEY
	//   (the PRIVKEYBLOB specifies that it's a "SIGNATURE" key)
	
	printf("About to ImportKey of Blob length of %0d\n", cbPk);
	if(!CryptImportKey(
			hCryptProv, 
			p,
			cbPk,
			0,
			CRYPT_EXPORTABLE,
			&hKey))
	{
		printf("CryptImportKey failed GetLastError() returns %0d\n", GetLastError());
	}
	if (!CryptReleaseContext(hCryptProv, 0))
	{
		printf("CryptReleaseContext failed with GetLastError() = %0d\n", GetLastError());
		exit(0);
	}
	return 1;
}
