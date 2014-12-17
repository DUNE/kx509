/*
 * Copyright  ©  2000,2002,2007
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
#include <windows.h>
#include <wincrypt.h>
#include "debug.h" 

int store_key(BYTE *p, DWORD cbPk)
{
	HCRYPTPROV				hCryptProv	= 0;
	HCRYPTKEY				hKey		= 0;
	int					retval		= 0;


	//----------------------------------------
	// ACQUIRE CRYPT CONTEXT
	if(!CryptAcquireContext(
		&hCryptProv,				// Handle to the CSP
		NULL,					// ContainerName
		MS_DEF_PROV,				// Provider name   
		PROV_RSA_FULL,				// Provider type (RSA_FULL requires "high encryption" (a.k.a. 128-bit))
		0))					// Flag values  (?? CRYPT_SILENT ??)
	{ 
		log_printf("initial CryptAcquireContext returned 0x%8X -- %s\n",GetLastError(), GetLastErrorText());

		//--------------------------------------------------------------------
		// NO PRE-EXISTING CONTAINER.  Create a new default key container. 
	   if(!CryptAcquireContext(
			&hCryptProv, 
			NULL,				// ContainerName
			MS_DEF_PROV,			// Provider name 
			PROV_RSA_FULL,			// Provider type (RSA_FULL requires "high encryption" (a.k.a. 128-bit))
			CRYPT_NEWKEYSET)) 
		{
		    // NTE_EXISTS (0x8009000f) could mean that this machine doesn't have "high encryption" installed
		    //    Windows XP automatically has "high encryption"
		    //    IE 5.5 and higher also automatically installs "high encryption"
		    //       (*EXCEPT* on Windows 2000, in which case you have to install the "Windows 2000 High Encryption pack":
		    //            http://www.microsoft.com/windows/ie/downloads/recommended/128bit/default.asp)

		   // HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates\My\Certificates

			log_printf("second CryptAcquireContext returned 0x%8X -- %s\n",GetLastError(), GetLastErrorText());
			HandleError("Cannot create Registry container for your private key.\n");
			goto error_return;
		}
	}

	// NOW IMPORT CALLER'S RSA KEY INTO THAT CONTAINER'S SIGNATURE KEY
	//   (the PRIVKEYBLOB specifies that it's a "SIGNATURE" key)
	
	log_printf("About to ImportKey of Blob length of %0d\n", cbPk);
	if(!CryptImportKey(
			hCryptProv, 
			p,
			cbPk,
			0,
			CRYPT_EXPORTABLE,
			&hKey))
	{
		log_printf("CryptImportKey failed GetLastError() returns 0x%08x -- %s\n", GetLastError(), GetLastErrorText());
		HandleError("Cannot import your private key.\n");
		goto error_return;
	}

	// Success
	retval = 1;
error_return:
	if (hCryptProv && !CryptReleaseContext(hCryptProv, 0))
	{
		log_printf("CryptReleaseContext failed with GetLastError() = 0x%08x -- %s\n", GetLastError(), GetLastErrorText());
		retval = 0;
	}
	return retval;
}
