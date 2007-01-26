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

#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include "kca_ext.h"
#include "kx509.h"

#ifdef X2001_0408
# include "server.h"
#else
extern int debug_mask;
# define DF(x)  (debug_mask & (1L<<((x-'@'&31))))
#endif

/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */

#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define	Malloc		malloc
# define	Realloc		realloc
# define	Free(addr)	free(addr)
#endif

#ifndef TRUE
#define TRUE  1
#endif

#if 0
#define	SN_KCA				"kca"
#define	LN_KCA				"Kerberized Certificate Authority"
#define	OBJ_KCA				"1.3.6.1.4.1.250.42"
#endif

#define	SN_KCA_ClientVersion		"kx509ClientVersion"
#define	LN_KCA_ClientVersion		"KX509 client version"
#define	OBJ_KCA_ClientVersion		"1.3.6.1.4.1.250.42.2"

#define	SN_KCA_ServerVersion		"kx509ServerVersion"
#define	LN_KCA_ServerVersion		"KX509 Server version"
#define	OBJ_KCA_ServerVersion		"1.3.6.1.4.1.250.42.3"

#define ASN1_F_KCA_VERSION_NEW	0
#define ERR_R_MALLOC_FAILURE		1
#define ERR_R_NESTED_ASN1_ERROR		2

#if 0
static STACK_OF(CONF_VALUE)
    *i2v_DLA3_QUERYURL
    (
	X509V3_EXT_METHOD	*method,
	DLA3_QUERYURL		*dlf,
	STACK_OF(CONF_VALUE)	*extlist
    );

static DLA3_QUERYURL
    *v2i_DLA3_QUERYURL
    (
	X509V3_EXT_METHOD	*method,
	X509V3_CTX		*ctx,
	STACK_OF(CONF_VALUE)	*values
    );
#endif /* 0 */


void KCA_VERSION_free(KCA_VERSION *a)
{
	if (a == NULL) return;
	ASN1_OCTET_STRING_free (a->Version);
	Free ((char *)a);
}

int i2d_KCA_VERSION(KCA_VERSION *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	r = M_ASN1_I2D_len (a->Version, i2d_ASN1_OCTET_STRING);

#if 0
	M_ASN1_I2D_seq_total();
#endif

	if (pp)
	{
		p = *pp;
		M_ASN1_I2D_put (a->Version, i2d_ASN1_OCTET_STRING);
		M_ASN1_I2D_finish();
	}
	else
		return(r);
}

KCA_VERSION *KCA_VERSION_new(void)
{
	KCA_VERSION *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, KCA_VERSION);
	ret->Version = NULL;
	return (ret);
#if 0
	M_ASN1_New_Error(ASN1_F_KCA_VERSION_NEW);
#else
err2:
	return(NULL);
#endif
}

KCA_VERSION *d2i_KCA_VERSION(KCA_VERSION **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,KCA_VERSION *,KCA_VERSION_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->Version, d2i_ASN1_OCTET_STRING);
#if 0
	M_ASN1_D2I_Finish(a, KCA_VERSION_free, ASN1_F_D2I_KCA_VERSION);
#else
	if (!asn1_Finish(&c))
		goto err;
	*pp = c.p;
	if (a != NULL)
		(*a)=ret;
	return(ret);
err:
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		KCA_VERSION_free(ret);
	return(NULL);
#endif
}

static STACK_OF(CONF_VALUE) *i2v_KCA_VERSION(X509V3_EXT_METHOD *method,
	     KCA_VERSION *kca, STACK_OF(CONF_VALUE) *extlist)
{
#ifndef HOPEFULLY_NOT_NEEDED
	dprintf (DF('d'), "i2v_KCA_VERSION entered\n");
#else
	X509V3_add_value("Version", kca->Version, &extlist);
#endif
	return extlist;
}

static KCA_VERSION *v2i_KCA_VERSION(X509V3_EXT_METHOD *method,
	     X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values)
{
#ifndef HOPEFULLY_NOT_NEEDED
	dprintf(DF('d'), "v2i_KCA_VERSION entered\n");
#else
	KCA_VERSION *kca=NULL;
	CONF_VALUE *val;
	int i;
	if(!(dlf = KCA_VERSION_new())) {
		X509V3err(X509V3_F_V2I_KCA_VERSION, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(values); i++) {
		val = sk_CONF_VALUE_value(values, i);
		if(!strcmp(val->name, "Version")) {
			if(!X509V3_get_value(val, &kca->Version)) goto err;
		} else {
			X509V3err(X509V3_F_V2I_KCA_VERSION, X509V3_R_INVALID_NAME);
			X509V3_conf_err(val);
			goto err;
		}
	}
	return kca;
	err:
	KCA_VERSION_free(kca);
#endif
	return NULL;
}

X509V3_EXT_METHOD v3_kca_clientVersion = {
	0 /* NID_CLIR_KCA_Version */, 0,
	(X509V3_EXT_NEW)KCA_VERSION_new,
	(X509V3_EXT_FREE)KCA_VERSION_free,
	(X509V3_EXT_D2I)d2i_KCA_VERSION,
	(X509V3_EXT_I2D)i2d_KCA_VERSION,
	NULL, NULL,
	(X509V3_EXT_I2V)i2v_KCA_VERSION,
	(X509V3_EXT_V2I)v2i_KCA_VERSION,
	NULL,NULL,
	NULL
};

int
KCA_add_client_version()
{
	int nid=0;
	int i;
	char *failed;
	X509V3_EXT_METHOD v3_kca_clientVersion;

	dprintf (DF('d'), "KCA_add_client_version entered\n");

	failed = 0;
#if 0
	if (!OBJ_create(OBJ_KCA, SN_KCA, LN_KCA))
		failed = "OBJ_create OBJ_KCA";
	else
#endif
	if (!(nid = OBJ_create(OBJ_KCA_ClientVersion, SN_KCA_ClientVersion, LN_KCA_ClientVersion)))
		failed = "OBJ_create OBJ_KCA_ClientVersion";

	if (failed)
		elcprintf ("KCA_add_client_version failed doing %s\n", failed);
	else
	{
		v3_kca_clientVersion.ext_nid = nid;
		X509V3_EXT_add(&v3_kca_clientVersion);
	}

	dprintf (DF('d'), "KCA_add_client_version completes\n");

	return nid;
}

X509V3_EXT_METHOD v3_kca_serverVersion = {
	0 /* NID_CLIR_KCA_Version */, 0,
	(X509V3_EXT_NEW)KCA_VERSION_new,
	(X509V3_EXT_FREE)KCA_VERSION_free,
	(X509V3_EXT_D2I)d2i_KCA_VERSION,
	(X509V3_EXT_I2D)i2d_KCA_VERSION,
	NULL, NULL,
	(X509V3_EXT_I2V)i2v_KCA_VERSION,
	(X509V3_EXT_V2I)v2i_KCA_VERSION,
	NULL,NULL,
	NULL
};

int
KCA_add_server_version()
{
	int nid=0;
	int i;
	char *failed;

	dprintf (DF('d'), "KCA_add_server_version entered\n");

	failed = 0;
#if 0
	if (!OBJ_create(OBJ_KCA, SN_KCA, LN_KCA))
		failed = "OBJ_create OBJ_KCA";
	else
#endif
	if (!(nid = OBJ_create(OBJ_KCA_ServerVersion,
			SN_KCA_ServerVersion,
			LN_KCA_ServerVersion)))
		failed = "OBJ_create OBJ_KCA_ServerVersion";

	if (failed)
		elcprintf ("KCA_add_server_version failed doing %s\n", failed);
	else
	{
		v3_kca_serverVersion.ext_nid = nid;
		X509V3_EXT_add(&v3_kca_serverVersion);
	}

	dprintf (DF('d'), "KCA_add_server_version completes\n");

	return nid;
}
