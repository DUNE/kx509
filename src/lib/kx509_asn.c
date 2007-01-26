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
 *	kx509_asn.h
 *
 * Routines to parse ASN.1 data contained in "version 2.0" packets.
 * Note that version 2.0 packets also have a 4 byte header {0,0,2,0},
 * which is not handled by these routines.
 *
 * The corresponding ASN.1 grammar to what is handled here is:
 *
 *	-- kx509
 *	KX509 DEFINITIONS ::=
 *	BEGIN
 *
 *	Kx509Request ::= SEQUENCE {
 *		authenticator OCTET STRING,
 *		pk-hash OCTET STRING,
 *		pk-key OCTET STRING,
 *		client-version VisibleString OPTIONAL
 *	}
 *
 *	Kx509Response ::= SEQUENCE {
 *		error-code[0]	INTEGER DEFAULT 0,
 *		hash[1]		OCTET STRING OPTIONAL,
 *		certificate[2]	OCTET STRING OPTIONAL,
 *		e-text[3]	VisibleString OPTIONAL
 *	}
 *	END
 *
 * It is expected that in general, the response will either
 * contain one of these 3 cases:
 *	certificate, hash		OK
 *	error-code, e-text, hash	most errors
 *	error-code, e-text		some low-level errors
 * we don't impose this in the grammar because it adds
 * to the complexity and limits flexiblity.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#if 0
#include "cryptlib.h"
#else
#include <openssl/crypto.h>
#endif
#include <openssl/err.h>
#include "openssl/asn1_mac.h"
#include "kx509_asn.h"
#if defined(WIN32)
#include <string.h>
#endif

#if SSLEAY_VERSION_NUMBER < 0x00900000
#define ASN1_VISIBLESTRING ASN1_STRING 
#define ASN1_VISIBLESTRING_new()	(ASN1_VISIBLESTRING *)ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define i2d_ASN1_VISIBLESTRING(a,pp) i2d_ASN1_bytes((ASN1_STRING *)(a),(pp),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define d2i_ASN1_VISIBLESTRING(a,pp,l)	d2i_ASN1_bytes((ASN1_STRING **)(a),(pp),(l),V_ASN1_VISIBLESTRING,V_ASN1_UNIVERSAL)
#define ASN1_VISIBLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING*)(a))
#endif

/*
 *	Allocate a new request with null strings.
 */

KX509_REQUEST *
KX509_REQUEST_new()
{
	KX509_REQUEST * ret;
#if SSLEAY_VERSION_NUMBER >= 0x00900000
	ASN1_CTX c;
#endif
	M_ASN1_New_Malloc(ret,KX509_REQUEST);
	ret->authenticator = ASN1_OCTET_STRING_new();
	ret->hash = ASN1_OCTET_STRING_new();
	ret->pkey = ASN1_OCTET_STRING_new();
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	ret->client_version = 0;
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */
	return ret;
	M_ASN1_New_Error(ASN1_F_D2I_KX509_REQUEST_NEW);
}

/* free a request */

void KX509_REQUEST_free(KX509_REQUEST *a)
{
	if (!a) return;
	ASN1_OCTET_STRING_free(a->authenticator);
	ASN1_OCTET_STRING_free(a->hash);
	ASN1_OCTET_STRING_free(a->pkey);
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	ASN1_VISIBLESTRING_free(a->client_version);
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */
	Free((char*)a);
}

/*
 *	Allocate a new response with no strings.
 */
KX509_RESPONSE *
KX509_RESPONSE_new()
{
	KX509_RESPONSE * ret;
#if SSLEAY_VERSION_NUMBER >= 0x00900000
	ASN1_CTX c;
#endif
	M_ASN1_New_Malloc(ret,KX509_RESPONSE);
	memset((char*)ret, 0, sizeof *ret);
	return ret;
	M_ASN1_New_Error(ASN1_F_D2I_KX509_RESPONSE_NEW);
}

/*	free a response and any strings */

void KX509_RESPONSE_free(KX509_RESPONSE *a)
{
	if (!a) return;
	ASN1_OCTET_STRING_free(a->hash);
	ASN1_OCTET_STRING_free(a->certificate);
	ASN1_VISIBLESTRING_free(a->error_message);
	Free((char*)a);
}

/*
 *	encode a kx509 request into wire format.
 *
 *	if "pp" is non-null, it will be updated to point
 *	to the end of the wire data.  If it is null,
 *	nothing is actually stored.  This routine
 *	always returns the count of what was or would
 *	have been stored.
 */

i2d_KX509_REQUEST(KX509_REQUEST *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	M_ASN1_I2D_len(a->authenticator, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(a->hash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(a->pkey, i2d_ASN1_OCTET_STRING);
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	M_ASN1_I2D_len_IMP_opt(a->client_version, i2d_ASN1_VISIBLESTRING);
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(a->authenticator, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(a->hash, i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(a->pkey, i2d_ASN1_OCTET_STRING);
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	M_ASN1_I2D_put_IMP_opt(a->client_version, i2d_ASN1_VISIBLESTRING, 0);
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */

	M_ASN1_I2D_finish();
}

/*
 *	encode a kx509 response into wire format.
 *
 *	if "pp" is non-null, it will be updated to point
 *	to the end of the wire data stored by this routine.
 *	If it is null, nothing is actually stored.  This routine
 *	always returns the count of what was or would
 *	have been stored.
 */

i2d_KX509_RESPONSE(KX509_RESPONSE *a, unsigned char **pp)
{
	ASN1_INTEGER *bs = 0;
	int v0,v1,v2,v3;
	M_ASN1_I2D_vars(a);

	if (a->status)
	{
		bs = ASN1_INTEGER_new();
		if (!bs) return 0;
		ASN1_INTEGER_set(bs, a->status);
	}
	M_ASN1_I2D_len_EXP_opt(bs, i2d_ASN1_INTEGER, 0, v0);
	M_ASN1_I2D_len_EXP_opt(a->hash, i2d_ASN1_OCTET_STRING, 1, v1);
	M_ASN1_I2D_len_EXP_opt(a->certificate, i2d_ASN1_OCTET_STRING, 2, v2);
	M_ASN1_I2D_len_EXP_opt(a->error_message, i2d_ASN1_VISIBLESTRING, 3, v3);

	r=ASN1_object_size(1, ret, V_ASN1_SEQUENCE);
	if (pp == NULL)
	{
		ASN1_INTEGER_free(bs);
		return(r);
	}
	p= *pp;
	ASN1_put_object(&p, 1, ret, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

	M_ASN1_I2D_put_EXP_opt(bs, i2d_ASN1_INTEGER, 0, v0);
	ASN1_INTEGER_free(bs);
	M_ASN1_I2D_put_EXP_opt(a->hash, i2d_ASN1_OCTET_STRING, 1, v1);
	M_ASN1_I2D_put_EXP_opt(a->certificate, i2d_ASN1_OCTET_STRING, 2, v2);
	M_ASN1_I2D_put_EXP_opt(a->error_message, i2d_ASN1_VISIBLESTRING, 3, v3);

	M_ASN1_I2D_finish();
}

/*
 *	decode a kx509 request
 *
 *	at most "length" bytes will be decoded, and pp will
 *	be updated to point to the end.  If "a" is non-null,
 *	the data will be stored in that structure, otherwise,
 *	a new structure will be allocated.  The structure
 *	will be returned if no parse errors are encountered,
 *	otherwise, NULL is returned.
 */

KX509_REQUEST *
d2i_KX509_REQUEST(KX509_REQUEST **a, unsigned char **pp, long length)
{
#ifdef KX509_ASN1_DEBUG
#define err Request_err
char *Request_what;
#endif
	M_ASN1_D2I_vars(a, KX509_REQUEST *, KX509_REQUEST_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->authenticator, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_get(ret->hash, d2i_ASN1_OCTET_STRING);
	M_ASN1_D2I_get(ret->pkey, d2i_ASN1_OCTET_STRING);
#ifdef KX509_ASN1_DEBUG
Request_what="#13";
#endif
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	M_ASN1_D2I_get_IMP_opt(ret->client_version,
		d2i_ASN1_VISIBLESTRING,
		0,
		V_ASN1_VISIBLESTRING);
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */
#ifdef KX509_ASN1_DEBUG
#undef err
#endif
	goto Done;

Done:
	M_ASN1_D2I_Finish(a, KX509_REQUEST_free, ASN1_F_D2I_KX509_REQUEST);
#ifdef KX509_ASN1_DEBUG
Request_err:
	fprintf(stderr,"Error =%d; %s\n", c.error, Request_what);
bin_dump(c.q, c.p-c.q);
	goto err;
#endif
}

/*
 *	decode a kx509 response
 *
 *	at most "length" bytes will be decoded, and pp will
 *	be updated to point to the end.  If "a" is non-null,
 *	the data will be stored in that structure, otherwise,
 *	a new structure will be allocated.  The structure
 *	will be returned if no parse errors are encountered,
 *	otherwise, NULL is returned.
 */

KX509_RESPONSE *
d2i_KX509_RESPONSE(KX509_RESPONSE **a, unsigned char **pp, long length)
{
#ifdef KX509_ASN1_DEBUG
#define err Response_err
char *Response_what;
#endif
	ASN1_INTEGER *bs;
	M_ASN1_D2I_vars(a, KX509_RESPONSE *, KX509_RESPONSE_new);
#ifdef KX509_ASN1_DEBUG
Response_what="#1";
#endif

#ifdef KX509_ASN1_DEBUG
Response_what="#2";
#endif
	M_ASN1_D2I_Init();
#ifdef KX509_ASN1_DEBUG
Response_what="#3";
#endif
	M_ASN1_D2I_start_sequence();
#ifdef KX509_ASN1_DEBUG
Response_what="#4";
#endif
	bs = ASN1_INTEGER_new();
#ifdef KX509_ASN1_DEBUG
Response_what="#5";
#endif
	if (!c.slen) goto Done;
	M_ASN1_D2I_get_EXP_opt(bs, d2i_ASN1_INTEGER, 0);
#ifdef KX509_ASN1_DEBUG
Response_what="#10";
#endif
	ret->status = ASN1_INTEGER_get(bs);
	ASN1_INTEGER_free(bs);
	if (!c.slen) goto Done;
#ifdef KX509_ASN1_DEBUG
Response_what="#11";
#endif
	M_ASN1_D2I_get_EXP_opt(ret->hash, d2i_ASN1_OCTET_STRING, 1);
	if (!c.slen) goto Done;
#ifdef KX509_ASN1_DEBUG
Response_what="#12";
#endif
	M_ASN1_D2I_get_EXP_opt(ret->certificate, d2i_ASN1_OCTET_STRING, 2);
	if (!c.slen) goto Done;
#ifdef KX509_ASN1_DEBUG
Response_what="#13";
#endif
	M_ASN1_D2I_get_EXP_opt(ret->error_message, d2i_ASN1_VISIBLESTRING, 3);
#ifdef KX509_ASN1_DEBUG
#undef err
#endif
Done:
	M_ASN1_D2I_Finish(a, KX509_RESPONSE_free, ASN1_F_D2I_KX509_RESPONSE);
#ifdef KX509_ASN1_DEBUG
Response_err:
	fprintf(stderr,"Error =%d; %s\n", c.error, Response_what);
bin_dump(c.q, c.p-c.q);
	goto err;
#endif
}
