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
#define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                             // since wincrypt.h and openssl namepsaces collide
                             //  ex. X509_NAME is #define'd and typedef'd ...

#include <windows.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "debug.h" 

#ifdef WIN32
extern	BOOL 	bSilent;
#endif /* WIN32 */

/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */

#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define	Malloc		OPENSSL_malloc
# define	Realloc		OPENSSL_realloc
# define	Free(addr)	OPENSSL_free(addr)
#endif

typedef unsigned int ALG_ID;

/*#if 0*/
typedef struct _PUBLICKEYSTRUC {
        BYTE    bType;
        BYTE    bVersion;
        WORD    reserved;
        ALG_ID  aiKeyAlg;
} PUBLICKEYSTRUC;

typedef struct _RSAPUBKEY {
        DWORD   magic;                  // Has to be "RSA1" or "RSA2"
        DWORD   bitlen;                 // # of bits in modulus
        DWORD   pubexp;                 // public exponent
                                        // Modulus data follows
} RSAPUBKEY;
/*#endif*/

typedef struct _PRIVKEYBLOB {
	PUBLICKEYSTRUC	blobheader;
	RSAPUBKEY		rsapubkey;
	DWORD			beginning[1];
//	BYTE			modulus[KEYBITS/8];			// "n"
//	BYTE			prime1[KEYBITS/16];			// "p"
//	BYTE			prime2[KEYBITS/16];			// "q"
//	BYTE			exponent1[KEYBITS/16];		// "dmp1"
//	BYTE			exponent2[KEYBITS/16];		// "dmq1"
//	BYTE			coefficient[KEYBITS/16];	// "iqmp"
//	BYTE			privateExponent[KEYBITS/8];	// "d"
} PRIVKEYBLOB;

void hexdump(void *pin, char *label, int len)
{
	BYTE *p = (BYTE *)pin;
	int	i;


	log_printf("%s (%0d bytes):", label, len<<2);
	for (i=0; i<len*BN_BYTES; i++)
	{
		if ((i & 0x7) == 0)
			log_printf("\n    ");
		log_printf("%#04X, ", p[i]);
	}
	log_printf("\n\n");
}

LPVOID GetLastErrorText()
{
	DWORD dwFmtMsgFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		                  FORMAT_MESSAGE_FROM_SYSTEM |
						  FORMAT_MESSAGE_IGNORE_INSERTS;
	LPVOID lpMsgBuf;

	FormatMessage(dwFmtMsgFlags,
		      NULL,
			  GetLastError(),
			  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			  (LPTSTR) &lpMsgBuf,
			  0,
			  NULL);

	return lpMsgBuf;
}

void HandleError(char *s)
{
	DWORD dwFmtMsgFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		                  FORMAT_MESSAGE_FROM_SYSTEM |
						  FORMAT_MESSAGE_IGNORE_INSERTS;
	LPVOID lpMsgBuf;
	char msg[1024];
	DWORD dwLastError = GetLastError();


	if (bSilent)
		return;

	FormatMessage(dwFmtMsgFlags,
		          NULL,
				  dwLastError,
				  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				  (LPTSTR) &lpMsgBuf,
				  0,
				  NULL);
	sprintf(msg, "%s\nError code 0x%08x -- %s", s, dwLastError, lpMsgBuf);
	MessageBox(0, msg, "KX509: Error!", MB_OK|MB_ICONERROR);
}

#define MAX_UNIQNAME_LEN	8

int rsa_to_keyblob(int keybits, RSA *key, BYTE	**ppk, DWORD *pcbPk)
{
	PRIVKEYBLOB	*pk					= NULL;
	RSAPUBKEY	*pPub				= NULL;
	DWORD		*p					= NULL;
	DWORD		*key_n				= NULL;
	DWORD		*key_p				= NULL;
	DWORD		*key_q				= NULL;
	DWORD		*key_dmp1			= NULL;
	DWORD		*key_dmq1			= NULL;
	DWORD		*key_iqmp			= NULL;
	DWORD		*key_d				= NULL;

	DWORD		cbPubKeyStruc		= sizeof(PUBLICKEYSTRUC);

	DWORD		dwContainerNameLen	= MAX_UNIQNAME_LEN+1;
	DWORD		l					= 0;
	extern int 	debugPrint;


	// setup PUBLICKEYSTRUC (aka BLOBHEADER) first

	*pcbPk = 0;
	if (!key)
	{
		return 0;
	}


	l = sizeof(PRIVKEYBLOB)-1 + BN_BYTES *
								( key->n->top
								+ key->p->top
								+ key->q->top
								+ key->dmp1->top
								+ key->dmq1->top
								+ key->iqmp->top
								+ key->d->top
								);
	*ppk = (BYTE *)Malloc(l);
	pk = (PRIVKEYBLOB *)*ppk;


	if (!pk)
	{
		return 0;
	}

	*pcbPk = l;
	pk->blobheader.bType=		0x07;				// PRIVATEKEYBLOB
	pk->blobheader.bVersion=	0x02;				// CUR_BLOB_VERSION
	pk->blobheader.reserved=	0x0000;				// 0x0000
//    pk->blobheader.aiKeyAlg=	0x00002400;			// CALG_RSA_SIGN
	pk->blobheader.aiKeyAlg=	0x0000A400;			// CALG_RSA_KEYX

	log_printf("pk->blobheader.bType=%#04X\n",		pk->blobheader.bType);
	log_printf("pk->blobheader.bVersion=%#04X\n",	pk->blobheader.bVersion);
	log_printf("pk->blobheader.reserved=%#06X\n",	pk->blobheader.reserved);
	log_printf("pk->blobheader.aiKeyAlg=%#010X\n",	pk->blobheader.aiKeyAlg);
	log_printf("\n");

	// setup RSAPUBKEY next

	pPub = &pk->rsapubkey;
	memcpy(&pPub->magic, "RSA2", 4);	// "RSA2" means PRIVKEYBLOB
	pPub->bitlen=keybits;
	pPub->pubexp=RSA_F4;

	log_printf("pk->rsapubkey.magic=%0ld ('%s')\n",		pPub->magic, &pPub->magic);
	log_printf("pk->rsapubkey.bitlen=%0ld (%#010lX)\n", pPub->bitlen, pPub->bitlen);
	log_printf("pk->rsapubkey.pubexp=%0ld (%#010lX)\n", pPub->pubexp, pPub->pubexp);
	log_printf("\n");

	// and finally, the KEY-INFO itself (n, p, q, dmp1, dmpq1, iqmp, & d)

	key_n	= p  = &pk->beginning[0]; memcpy(p,	key->n->d,	  BN_BYTES * key->n->top);
	key_p	= p += key->n->top;		  memcpy(p,	key->p->d,	  BN_BYTES * key->p->top);
	key_q	= p += key->p->top;		  memcpy(p,	key->q->d,	  BN_BYTES * key->q->top);
	key_dmp1= p += key->q->top;		  memcpy(p,	key->dmp1->d, BN_BYTES * key->dmp1->top);
	key_dmq1= p += key->dmp1->top;	  memcpy(p,	key->dmq1->d, BN_BYTES * key->dmq1->top);
	key_iqmp= p += key->dmq1->top;	  memcpy(p,	key->iqmp->d, BN_BYTES * key->iqmp->top);
	key_d	= p += key->iqmp->top;	  memcpy(p,	key->d->d,	  BN_BYTES * key->d->top);

	if (debugPrint)
	{
		hexdump((BYTE *)key_n,		"pk->modulus",			key->n->top);
		hexdump((BYTE *)key_p,		"pk->prime1",			key->p->top);
		hexdump((BYTE *)key_q,		"pk->prime2",			key->q->top);
		hexdump((BYTE *)key_dmp1,	"pk->exponent1",		key->dmp1->top);
		hexdump((BYTE *)key_dmq1,	"pk->exponent2",		key->dmq1->top);
		hexdump((BYTE *)key_iqmp,	"pk->coefficient",		key->iqmp->top);
		hexdump((BYTE *)key_d,		"pk->privateExponent",	key->d->top);
	}

	return 1;
}
