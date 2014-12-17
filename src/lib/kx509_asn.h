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

/*
 *	kx509 ASN.1 send/receive structures.
 *
 * these hold the parsed packet contents.
 */

typedef struct kx509_request {
	ASN1_OCTET_STRING *authenticator;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *pkey;
	ASN1_PRINTABLESTRING *client_version;
} KX509_REQUEST;

typedef struct kx509_response {
	int status;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *certificate;
	ASN1_PRINTABLESTRING *error_message;
} KX509_RESPONSE;

/* these are bogus error codes.  Yuck. */
#define ASN1_F_D2I_KX509_REQUEST 900
#define ASN1_F_D2I_KX509_RESPONSE 901
#define ASN1_F_D2I_KX509_REQUEST_NEW 902
#define ASN1_F_D2I_KX509_RESPONSE_NEW 903

/* routines to allocate, free, and parse, a la openssl */
KX509_REQUEST * KX509_REQUEST_new(void);

void KX509_REQUEST_free(KX509_REQUEST *);
KX509_RESPONSE *KX509_RESPONSE_new(void);
void KX509_RESPONSE_free(KX509_RESPONSE *);
int i2d_KX509_REQUEST(KX509_REQUEST *, unsigned char **);
int i2d_KX509_RESPONSE(KX509_RESPONSE *, unsigned char **);
KX509_REQUEST *d2i_KX509_REQUEST(KX509_REQUEST **,unsigned char **, long);
KX509_RESPONSE *d2i_KX509_RESPONSE(KX509_RESPONSE **,unsigned char **, long);

/* routines to compute key'd hash values based on a supplied session key */
int KX509_REQUEST_compute_checksum(unsigned char[], KX509_REQUEST *,ASN1_OCTET_STRING *,char *key, int);
int KX509_RESPONSE_compute_checksum(unsigned char[], KX509_RESPONSE *, ASN1_OCTET_STRING *, char *, int);

/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */
#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define        Malloc          OPENSSL_malloc
# define        Realloc         OPENSSL_realloc
# ifdef Free
#  undef	Free
# endif /* Free */
# define        Free(addr)      OPENSSL_free(addr)
#endif

