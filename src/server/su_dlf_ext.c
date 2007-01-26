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
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include "dla3.h"
#include "kx509.h"
#include "server.h"

#ifndef TRUE
# define TRUE  1
#endif

char *strdup();
/* char *malloc(); */
char *getenv();

#define	SN_CLIR				"clir"
#define	LN_CLIR				"Council on Library and Information Resources"
#define	OBJ_CLIR			"1.2.840.114006"

#define	SN_CLIR_DLA3			"clirDla3"
#define	LN_CLIR_DLA3			"CLIR Digital Library Authentication and Authorization Architecture"
#define	OBJ_CLIR_DLA3			"1.2.840.114006.1000"

#define	SN_CLIR_DLA3_QueryURL		"dla3QueryUrl"
#define	LN_CLIR_DLA3_QueryURL		"CLIR DLA3 Query Url"
#define	OBJ_CLIR_DLA3_QueryURL		"1.2.840.114006.1000.1"


#define ASN1_F_DLA3_QUERYURL_NEW	0
#define ERR_R_MALLOC_FAILURE		1
#define ERR_R_NESTED_ASN1_ERROR		2

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


void DLA3_QUERYURL_free(DLA3_QUERYURL *a)
{
	if (a == NULL) return;
	ASN1_OCTET_STRING_free (a->queryUrl);
	Free ((char *)a);
}

int i2d_DLA3_QUERYURL(DLA3_QUERYURL *a, unsigned char **pp)
{
	M_ASN1_I2D_vars(a);

	r = M_ASN1_I2D_len (a->queryUrl, i2d_ASN1_OCTET_STRING);

#if 0
	M_ASN1_I2D_seq_total();
#endif

	if (pp)
	{
		p = *pp;
		M_ASN1_I2D_put (a->queryUrl, i2d_ASN1_OCTET_STRING);
		M_ASN1_I2D_finish();
	}
	else
		return(r);
}

DLA3_QUERYURL *DLA3_QUERYURL_new(void)
{
	DLA3_QUERYURL *ret=NULL;
	ASN1_CTX c;
	M_ASN1_New_Malloc(ret, DLA3_QUERYURL);
	ret->queryUrl = NULL;
	return (ret);
#if 0
	M_ASN1_New_Error(ASN1_F_DLA3_QUERYURL_NEW);
#else
err2:
	return(NULL);
#endif
}

DLA3_QUERYURL *d2i_DLA3_QUERYURL(DLA3_QUERYURL **a,
	     unsigned char **pp, long length)
{
	M_ASN1_D2I_vars(a,DLA3_QUERYURL *,DLA3_QUERYURL_new);
	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get (ret->queryUrl, d2i_ASN1_OCTET_STRING);
#if 0
	M_ASN1_D2I_Finish(a, DLA3_QUERYURL_free, ASN1_F_D2I_DLA3_QUERYURL);
#else
	if (!asn1_Finish(&c))
		goto err;
	*pp = c.p;
	if (a != NULL)
		(*a)=ret;
	return(ret);
err:
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		DLA3_QUERYURL_free(ret);
	return(NULL);
#endif
}

static STACK_OF(CONF_VALUE) *i2v_DLA3_QUERYURL(X509V3_EXT_METHOD *method,
	     DLA3_QUERYURL *dlf, STACK_OF(CONF_VALUE) *extlist)
{
#ifndef HOPEFULLY_NOT_NEEDED
	dprintf (DF('d'), "i2v_DLA3_QUERYURL entered\n");
#else
	X509V3_add_value("queryUrl", dlf->queryUrl, &extlist);
#endif
	return extlist;
}

static DLA3_QUERYURL *v2i_DLA3_QUERYURL(X509V3_EXT_METHOD *method,
	     X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values)
{
#ifndef HOPEFULLY_NOT_NEEDED
	dprintf(DF('d'), "v2i_DLA3_QUERYURL entered\n");
#else
	DLA3_QUERYURL *dlf=NULL;
	CONF_VALUE *val;
	int i;
	if(!(dlf = DLA3_QUERYURL_new())) {
		X509V3err(X509V3_F_V2I_DLA3_QUERYURL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	for(i = 0; i < sk_CONF_VALUE_num(values); i++) {
		val = sk_CONF_VALUE_value(values, i);
		if(!strcmp(val->name, "queryUrl")) {
			if(!X509V3_get_value(val, &dlf->queryUrl)) goto err;
		} else {
			X509V3err(X509V3_F_V2I_DLA3_QUERYURL, X509V3_R_INVALID_NAME);
			X509V3_conf_err(val);
			goto err;
		}
	}
	return dlf;
	err:
	DLA3_QUERYURL_free(dlf);
#endif
	return NULL;
}


X509V3_EXT_METHOD v3_dla3_queryUrl = {
	0 /* NID_CLIR_DLA3_QueryURL */, 0,
	(X509V3_EXT_NEW)DLA3_QUERYURL_new,
	(X509V3_EXT_FREE)DLA3_QUERYURL_free,
	(X509V3_EXT_D2I)d2i_DLA3_QUERYURL,
	(X509V3_EXT_I2D)i2d_DLA3_QUERYURL,
	NULL, NULL,
	(X509V3_EXT_I2V)i2v_DLA3_QUERYURL,
	(X509V3_EXT_V2I)v2i_DLA3_QUERYURL,
	NULL,NULL,
	NULL
};

int
KCA_add_dlf_extensions()
{
	int nid=0;
	int i;
	char *failed;

	dprintf (DF('d'), "KCA_add_dlf_extensions entered\n");

	failed = 0;
	if (!OBJ_create(OBJ_CLIR, SN_CLIR, LN_CLIR))
		failed = "OBJ_create OBJ_CLIR";
	else if (!OBJ_create(OBJ_CLIR_DLA3, SN_CLIR_DLA3, LN_CLIR_DLA3))
		failed = "OBJ_create OBJ_CLIR_DLA3";
	else if (!(nid = OBJ_create(OBJ_CLIR_DLA3_QueryURL,
				SN_CLIR_DLA3_QueryURL, LN_CLIR_DLA3_QueryURL)))
		failed = "OBJ_create OBJ_CLIR_DLA3_QueryURL";

	if (failed)
		elcprintf ("KCA_add_dlf_extensions failed doing %s\n", failed);
	else
	{
		v3_dla3_queryUrl.ext_nid = nid;
		X509V3_EXT_add(&v3_dla3_queryUrl);
	}

	dprintf (DF('d'), "KCA_add_dlf_extensions completes\n");

	return nid;
}
