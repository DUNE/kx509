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

#include <stdio.h>
#if 0
#include "cryptlib.h"
#else
#include "openssl/crypto.h"
#endif
#include "openssl/err.h"
#include "openssl/asn1_mac.h"
#include "kx509_asn.h"
#include "openssl/hmac.h"
#if SSLEAY_VERSION_NUMBER < 0x00900000
#define ASN1_VISIBLESTRING ASN1_STRING 
#define ASN1_VISIBLESTRING_new()	(ASN1_VISIBLESTRING *)ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define i2d_ASN1_VISIBLESTRING(a,pp) i2d_ASN1_bytes((ASN1_STRING *)(a),(pp),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define d2i_ASN1_VISIBLESTRING(a,pp,l)	d2i_ASN1_bytes((ASN1_STRING **)(a),(pp),(l),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define ASN1_VISIBLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING*)(a))
#endif

int
KX509_REQUEST_compute_checksum(unsigned char vs[4],
			       KX509_REQUEST *a,
			       ASN1_OCTET_STRING *o,
			       char *key,
			       int klen)
{
	HMAC_CTX hctx[1];
	EVP_MD *md;
	char *digest;
	int dlen;
	int result = 0;

	md = EVP_sha1();
	HMAC_Init(hctx, key, klen, md);
	dlen = HMAC_size(hctx);
	if (o->length != dlen)
	{
		if (!(digest = Malloc(dlen)))
		{
			result = -1;
		}
		Free(o->data);
		o->data = (unsigned char *)digest;
		o->length = dlen;
	} else digest = (char *)o->data;
	/*
	 * Note: The following was changed from "sizeof vs" to "4"
	 * to fix 64-bit clients where "vs" is a pointer and
	 * "sizeof vs" is not 4.  Thanks to Ken McInnis.
	 */
	HMAC_Update(hctx, vs, 4);
	HMAC_Update(hctx, a->pkey->data, a->pkey->length);
	HMAC_Final(hctx, (unsigned char *)digest, 0);
#ifdef darwin
	HMAC_CTX_cleanup(hctx);
#else /* darwin */
	HMAC_cleanup(hctx);
#endif /* darwin */
	return result;
}

int
KX509_RESPONSE_compute_checksum(unsigned char vs[4],
				KX509_RESPONSE *a,
				ASN1_OCTET_STRING *o,
				char *key,
				int klen)
{
	HMAC_CTX hctx[1];
	EVP_MD *md;
	char *digest;
	int dlen;
	int result = 0;
	char status_bytes[8];
	unsigned int temp;
	char *sp;

	md = EVP_sha1();
	HMAC_Init(hctx, key, klen, md);
	dlen = HMAC_size(hctx);
	if (o->length != dlen)
	{
		if (!(digest = Malloc(dlen)))
		{
			result = -1;
		}
		Free(o->data);
		o->data = (unsigned char *)digest;
		o->length = dlen;
	} else digest = (char *)o->data;
	/*
	 * Note: The following was changed from "sizeof vs" to "4"
	 * to fix 64-bit clients where "vs" is a pointer and
	 * "sizeof vs" is not 4.  Thanks to Ken McInnis.
	 */
	HMAC_Update(hctx, vs, 4);
	if (temp = a->status)
	{
		sp = status_bytes+sizeof status_bytes;
		do {
			*--sp = (char)temp;
			temp >>= 8;
		} while (temp);
		HMAC_Update(hctx, (unsigned char *)sp, (status_bytes+sizeof status_bytes)-sp);
	}
	if (a->certificate)
		HMAC_Update(hctx, a->certificate->data, a->certificate->length);
	if (a->error_message)
		HMAC_Update(hctx, a->error_message->data, a->error_message->length);
	HMAC_Final(hctx, (unsigned char *)digest, 0);
#ifdef darwin
	HMAC_CTX_cleanup(hctx);
#else /* darwin */
	HMAC_cleanup(hctx);
#endif /* darwin */
	return result;
}
