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

#if defined(USE_KRB5)

/*
 * store_in_cc.c -- use K5 credentials cache to store RSA key-pair & 1-day X.509 cert
 */

#include <stdio.h> 
#include <errno.h> 
#include <string.h> 
#include <sys/param.h>
#include <fcntl.h> 
#ifndef macintosh
#include <sys/types.h> 
#endif /* !macintosh */
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <krb5.h>
#include "kx509.h"
#include "debug.h" 
#include <sys/timeb.h>
 
#ifdef WIN32
/* Microsoft wisely named these with leading underscores... */
# define tzset _tzset
# define timezone _timezone
# define daylight _daylight
#else /* !WIN32 */
# define Malloc	malloc
# define Free	free
#endif

#define KX509_CC_PRINCIPAL	"kx509"
#define KX509_CC_INSTANCE	"certificate"

/*
 * Convert an ASN.1 UTCTime structure into unix time format
 */
time_t utc2unix(ASN1_UTCTIME *utctime, time_t *unixtime)
{
	char *utcchars;
	int length, temp;
	time_t utime;
	char *current;
	struct tm tms;

	memset(&tms, '\0', sizeof(tms));

	utime = -1;				/* preset with error return */

	/*
	 * XXX Here we are making the assumption that all times are (UTC/ZULU)
	 * XXX and that all times include the seconds value.
	 */
	length = utctime->length;
	if (length != 13)
		goto returntime;

	utcchars = (char *)utctime->data;
	if (utcchars[12] != 'Z')
		goto returntime;

	current = utcchars;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get year value */
	if (temp < 50)									/* UTCTime runs from 1950 - 2049 */
		temp += 100;								/* Must use GeneralizedTime after 2049 */
	tms.tm_year = temp;

	current+=2;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get month value */
	temp--;											/* make it zero based */
	tms.tm_mon = temp;

	current+=2;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get day of the month value */
	tms.tm_mday = temp;

	current+=2;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get hour value */
	tms.tm_hour = temp;

	current+=2;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get minute value */
	tms.tm_min = temp;

	current+=2;
	temp = (current[0]-'0')*10 + (current[1]-'0');	/* get seconds value */
	tms.tm_sec = temp;

	tms.tm_isdst = -1;								/* Forces mktime to check DST */

#if defined(OpenBSD)
	/*
	 * mktime() doesn't seem to work the same on OpenBSD as others (like linux
	 * and Solaris).  It would seem that this should be a call to timelocal(),
	 * but hey, it works...
	 */
	utime = timegm(&tms);
#else
	utime = mktime(&tms);							/* get unix time (GMT) */
	if (utime != -1) {
#ifdef darwin
		utime += tms.tm_gmtoff;
#else
		utime = utime - timezone + tms.tm_isdst*3600;
#endif
	}
#endif

  returntime:

	if (unixtime)
		*unixtime = utime;
	return utime;
}

#if defined(CC_REMOVE_IMPLEMENTED)
/*
 * The krb5_cc_remove_cred() function is defined in the MIT API documentation,
 * however it is not implemented.  So we don't bother trying to call it...
 */
krb5_error_code clear_old_certs(krb5_context k5_context,
								krb5_ccache cc,
								krb5_creds *creds)
{
	if (krb5_cc_remove_cred(k5_context, cc, XXX, creds))
	{
		log_printf("clear_old_certs: unable to initialize K5 context (%d)\n", k5_rc);
		return -1;
	}
	return 0;
}
#endif	/* CC_REMOVE_IMPLEMENTED */

/*
 * Store the given private key (key) and certificate (cert)
 * into the Kerberos 5 credentials cache.  The "lifetime"
 * of the certificate is also given in notBefore, and notAfter.
 */
int store_in_cc(RSA *key,
	BYTE 			*cert,
	DWORD 			cert_length,
	char 			*realm,
	ASN1_UTCTIME 		*notBefore,
	ASN1_UTCTIME 		*notAfter,
#if defined(KX509_LIB)
	char			*tkt_cache_name,
#endif
	char 			**err_msg)
{
	krb5_context		k5_context;
	krb5_ccache		cc;
	krb5_creds		fake_creds;
	DWORD			key_length;
	krb5_error_code		k5_rc		= 0;
	int			retcode		= KX509_STATUS_GOOD;
	BYTE			*ptr 		= NULL;
	BYTE			*memptr 	= NULL;


	/*
	 * Use fake_creds.ticket for private key and
	 * fake_creds.second_ticket for certificate
	 */

	memset(&fake_creds, '\0', sizeof(fake_creds));

	if (k5_rc = krb5_init_context(&k5_context))
	{
		log_printf("store_in_cc: unable to initialize Kerberos 5 context (%d)\n", k5_rc);
		*err_msg = "Error initializing kerberos 5 environment."; 
		return KX509_STATUS_CLNT_FIX;
	}

#if 0	/* DON'T NEED THIS, and it is a private function anyway... */
	if (k5_rc = krb5_set_default_realm(k5_context, realm))
	{
		log_printf("store_in_cc: failed to malloc space for k5 default_realm\n");
		*err_msg = "Try re-authenticating.  "
				"Hopefully temporary client-side problem";
		return KX509_STATUS_CLNT_FIX;
	}
#endif

#if defined(KX509_LIB)
	if (k5_rc = krb5_cc_resolve(k5_context, tkt_cache_name, &cc))
	{
		log_printf("store_in_cc: failed to resolve credential cache (%d)\n", k5_rc);
		*err_msg = "Try re-authenticating.  "
			"Could not resolve your credential cache name.";
		return KX509_STATUS_CLNT_FIX;
	}
#else
	if (k5_rc = krb5_cc_default(k5_context, &cc))
	{
		log_printf("store_in_cc: failed to resolve credential cache (%d)\n", k5_rc);
		*err_msg = "Try re-authenticating.  "
				"Could not resolve your credential cache name.";
		return KX509_STATUS_CLNT_FIX;
	}
#endif

#if defined(HAVE_HEIMDAL)
	if (k5_rc = krb5_make_principal(k5_context, &fake_creds.server,
						    realm,
						    KX509_CC_PRINCIPAL,
						    KX509_CC_INSTANCE,
						    NULL))
#else
	if (k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
							KX509_CC_PRINCIPAL,
							KRB5_NT_UNKNOWN,
							&fake_creds.server))
#endif
	{
		log_printf("store_in_cc: unable to create server principal from sname (%d)\n",
				k5_rc);
		*err_msg = "Internal error with kerberos while creating fake server principal.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}

#if defined(CC_REMOVE_IMPLEMENTED)
	/*
	 * We really want to clear out any old private key/certificate entries
	 * from the credentials cache.  However, the function to do that is
	 * not defined...
	 */
	if (k5_rc = kx509_clear_old_certificates(k5_context, cc, fake_creds))
	{
		log_printf("store_in_cc: couldn't clear out old certificate "
			"from cred cache (%d)\n", k5_rc);
		*err_msg = "Error removing old certificate from your kerberos credentials cache.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}
#endif	/* CC_REMOVE_IMPLEMENTED */

	if (k5_rc = krb5_cc_get_principal(k5_context, cc, &fake_creds.client))
	{
		log_printf("store_in_cc: unable to create client principal from sname (%d)\n",
				k5_rc);
		*err_msg = "Internal error with kerberos while creating fake client principal.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}

	/*
	 * Get the DER-encoded length of the private key.
	 * Allocate storage to hold the private key and certificate.
	 */

	key_length = i2d_RSAPrivateKey(key, NULL);	/* Get DER-encoded len of Private Key */
	if (key_length <= 0)
	{
		log_printf("store_in_cc: unable to determine length of "
			"encoded private key (%d)\n", key_length);
		*err_msg = "Error determining encoded length of private key.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}

	ptr = Malloc(key_length + cert_length);
	if (!ptr)
	{
		log_printf("store_in_cc: error allocating %d bytes for "
			"private key (%d) and certificate (%d)\n", 
			key_length+cert_length, key_length, cert_length);
		*err_msg = "Error allocating storage for private key and certificate.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}

	memptr = ptr;	/* Save a ptr to the allocated area for later when we free it */

	fake_creds.ticket.data = (char *)ptr; 
	fake_creds.ticket.length = i2d_RSAPrivateKey(key, &ptr);

	/* Note that i2d_RSAPrivateKey() updates ptr!!! */
	memcpy(ptr, cert, cert_length);
	fake_creds.second_ticket.data = (char *)ptr;
	fake_creds.second_ticket.length = cert_length;

	/* Set up the ticket lifetime according to the certificate lifetime */
	fake_creds.times.starttime = utc2unix(notBefore, NULL);
	fake_creds.times.endtime = utc2unix(notAfter, NULL);

	/*
	 * Store the fake ticket (containing the private key
	 * and certificate) into the credentials cache.
	 */ 

	if (k5_rc = krb5_cc_store_cred(k5_context, cc, &fake_creds))
	{
		log_printf("store_in_cc: krb5_cc_store_cred returned %0d\n", k5_rc);
		*err_msg = "Try re-authenticating.  "
			"Currently unable to write your Kerberos credentials cache.";
		retcode = KX509_STATUS_CLNT_FIX;
		goto close_and_return;
	}

close_and_return:

	if (memptr)
	{
		Free(memptr);
		memptr = NULL;
	}

	krb5_cc_close(k5_context, cc);	/* ignore return code from close */

	return(retcode);
}

#endif	/* USE_KRB5 */
