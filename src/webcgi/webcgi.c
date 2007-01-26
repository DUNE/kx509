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

#include <stdio.h> 
#include <errno.h> 
#include <string.h> 
#include <fcntl.h> 
#include <sys/types.h> 
#ifdef WIN32
#define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                             // since wincrypt.h and openssl namepsaces collide
                             //  ex. X509_NAME is #define'd and typedef'd ...

#include <windows.h> 
#include <kerb95.h>
#else
typedef unsigned char BYTE;
typedef unsigned long DWORD; 
#endif /* WIN32 */
#include "rand.h" 
#include "x509v3.h" 
#include "pem.h" 
#ifndef WIN32
#define DES_DEFS
#include <krb.h>
#endif /* !WIN32 */
#include "store_tkt.h"
 
int getcert(RSA *rsa, char *buffer, DWORD *buflen, char **realm); 
#ifdef WIN32
void clean_cert_store(); 
int store_key(BYTE *b, DWORD cbPk); 
int store_cert(BYTE *cert, DWORD len); 
void display_cert_and_key(); 
int rsa_to_keyblob(int keybits, RSA *key, BYTE	**ppk, DWORD *pcbPk); 
#endif /* WIN32 */
 
 
#define MAX_UNIQNAME_LEN	8 
 
#define	BUF_LEN	2048 
#define	DEFBITS	512 /* first get MS stuff working, then do 1024 */
 
BIO *bio_err=NULL; 
 
 
 
/* 
 * load "random" seed based on contents of 
 *	supplied colon-separated <list> of filenames 
 */ 
 
static void gr_load_rand(char *name) 
{ 
	char file[256]; 
	int last=0; 
	char *p; 
 
	for (; name && !last; name=p+1) 
	{ 
		/* move p to "end" of current filename */ 
		for (p=name; ((*p != '\0') && (*p != ':')); p++) 
			; 
 
		/* copy current filename to "file" and null terminate */ 
		strncpy(file, name, p-name); 
		file[p-name] = '\0'; 
 
		/* shouldn't happen, but all-done if null-length filename */ 
		if (!strlen(file)) 
			break; 
 
		/* add contents of <file> to entropy of RAND functions */ 
		(void)RAND_load_file( file, 1024L*1024L ); 
 
		last = (*p == '\0'); 
	} 
 
	return; 
} 
 
 
RSA *client_genkey(int keybits) 
{ 
	RSA *rsa=NULL; 
	EVP_CIPHER *enc=NULL; 
	EVP_MD *digest=EVP_md5(); 
	char *inrand=NULL; 
	char *outfile=NULL; 
	char *crtfile=NULL; 
	DWORD f4=RSA_F4; 
 
 
	/* assign constants to needed filenames ... for now */ 
 
	inrand		= "/var/adm/messages"; 
	outfile		= "/tmp/t.key"; 
 
	/* SET-UP HOUSE */ 
 
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); 
	SSLeay_add_all_algorithms(); 
 
	if ((bio_err=BIO_new(BIO_s_file())) != NULL) 
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT); 
 
	gr_load_rand(inrand); 
 
	/* GENERATE KEY-PAIR */ 
 
	rsa=RSA_generate_key(keybits,f4,NULL,NULL); 
		 
	return rsa; 
} 
 
int main(int argc, char **argv) 
{ 
	RSA		*rsa=NULL; 
	BYTE		*pk; 
	DWORD		cbPk=0; 
	BIO		*out=NULL; 
	DWORD 		i=BUF_LEN; 
	char		buffer[BUF_LEN]; 
	char		*realm;
	BYTE		*p = (BYTE *)(&buffer[0]); 
	X509		*cert=NULL; 
	int		keybits=DEFBITS; 
 
 
	/* CLEAN OUT OLD CERTS  */
 
#ifdef WIN32
	clean_cert_store(); 
#endif /* WIN32 */
 
	/* GENERATE PUBLIC KEY PAIR  */
 
	rsa=client_genkey(keybits); 
 
	/* USE K4 AUTHENT + RSA PUB-KEY TO GET CERT FROM CA SERVER  */
	 
	if (!getcert(rsa, buffer, &i, &realm)) 
	{ 
		fprintf (stderr, "Failed to get cert from CA: %0d\n", i); 
		goto THE_END; 
	} 
 
	/* GOT PEM-ENCODED CERT, WANT DER-ENCODED (ASN)  */
 
	out = BIO_new(BIO_s_mem()); 
	if (!out) 
	{ 
		fprintf (stderr, "Failed reading certificate: %0d\n", i); 
		goto THE_END; 
	} 
 
	BIO_write(out, buffer, i); 
	PEM_read_bio_X509(out, &cert, NULL, NULL); 
 
	i = i2d_X509(cert, &p); 
 
	fprintf (stderr, "translated to %0d bytes of DER-encoded cert from CA server\n", i); 
 
#ifdef WIN32
	/* SINCE GOT CERT, PUT KEY-PAIR and CERT INTO "MY" KEY-STORE & CERT-STORE  */
 
	if (!rsa_to_keyblob(DEFBITS, rsa, &pk, &cbPk)) 
	{ 
		fprintf (stderr, "rsa_to_keyblob failed\n"); 
		goto THE_END; 
	} 
 
	if (!store_key(pk, cbPk)) 
	{ 
		fprintf (stderr, "store_key failed\n"); 
		goto THE_END; 
	} 
 
	store_cert((BYTE *)buffer, i); 
#else
	/* SINCE GOT CERT, MUNGE KEY-PAIR and CERT INTO K4 TKT FILE AS MOCK TICKET */

	if (!store_tkt(rsa, (BYTE *)buffer, i, realm))
	{ 
		fprintf (stderr, "store_tkt failed\n"); 
		goto THE_END; 
	} 
#endif /* WIN32 */
 
 
THE_END: 
	i=i; 
} 
