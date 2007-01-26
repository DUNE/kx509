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

/* get_realm.c -- gather into one file all code related to determining
 *			the realm of the user's (currently active)
 *			Kerberos tickets, irrespective of the client's
 *			architecture or kerberos implementation
 *
 * CHANGE HISTORY:
 *	2000.1213 -- billdo -- created
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef WIN32
# define __WINCRYPT_H__		// PREVENT windows.h from including wincrypt.h
				// since wincrypt.h and openssl namepsaces collide
				//  ex. X509_NAME is #define'd and typedef'd ...
# include <winsock.h>		// Must be included before <windows.h> !!!
# include <windows.h>
# include <openssl/pem.h>
#endif  /* WIN32 */


#include <stdlib.h>
#include <openssl/x509v3.h>

#ifdef USE_KRB5
/* #ifndef USE_MSK5 */
# include <krb5.h>
# if !defined(HAVE_HEIMDAL) && !defined(WIN32)
# include <et/com_err.h>
# endif
/* #endif /* USE_MSK5 */
#else /* !USE_KRB5 */
# ifndef WIN32
#  ifndef linux
#   define DES_DEFS			/* Prevent collision with K5 DES delarations */
#  endif /* !linux */
#  ifdef macintosh
#   include <KClient.h>
#  else /* !macintosh */
#   include "des-openssl-hack.h"
#   include <krb.h>
#  endif /* macintosh */
# else /* !WIN32 */
#  include "des-openssl-hack.h"
#  include <krb.h>
# endif /* !WIN32 */
#endif /* USE_KRB5 */

#include "kx509.h"
#include "debug.h"

#ifdef WIN32
extern BOOL 	bPwdPrompt; 
BOOL bkx509busy = FALSE;
#endif /* WIN32 */

#ifdef USE_MSK5
extern int MSK5_get_userid_and_realm();
#endif /* USE_MSK5 */

# ifdef WIN32
#  include <loadfuncs-krb5.h>
# else
#ifdef HAVE_HEIMDAL
#define KRB5_CALLCONV_C
#define KRB5_CALLCONV
#endif
   typedef krb5_error_code (KRB5_CALLCONV_C *FP_krb5_cc_default)
		(krb5_context, krb5_ccache *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_cc_get_principal)
		(krb5_context, krb5_ccache, krb5_principal *);
   typedef void (KRB5_CALLCONV *FP_krb5_free_principal)
		(krb5_context, krb5_principal);
   typedef krb5_error_code (KRB5_CALLCONV_C *FP_krb5_cc_close)
		(krb5_context, krb5_ccache cache);
# endif /* WIN32 */
typedef char * (KRB5_CALLCONV *FP_error_message)
		(krb5_error_code);

extern FP_error_message				perror_message;
extern FP_krb5_cc_default			pkrb5_cc_default;
extern FP_krb5_cc_close				pkrb5_cc_close;
extern FP_krb5_cc_get_principal 	pkrb5_cc_get_principal;
extern FP_krb5_free_principal		pkrb5_free_principal;

extern void FixupExceptionalFuncs(
	krb5_ccache	cc
	);

//#include <Pure.h>

#if defined(USE_KRB5)
/*
 *=========================================================================*
 *
 * get_krb5_realm()
 *
 *=========================================================================*
 */
int get_krb5_realm(krb5_context k5_context, char *realm, char **err_msg)
{
	int				rc = 0;
#if !defined(USE_MSK5)
	krb5_ccache		cc = NULL;
	krb5_principal	me = NULL;
	krb5_error_code result;


	*realm = 0;

	if (result = (*pkrb5_cc_default)(k5_context, &cc))
	{
		msg_printf("get_krb5_realm: krb5_cc_default: %s\n", (*perror_message)(result));
		*err_msg = "Try re-authenticating(K5).  "
			"You have no Kerberos tickets";
		if (cc)
			(*pkrb5_cc_close)(k5_context, cc);	/* ignore return code from close */

		rc = KX509_STATUS_CLNT_FIX;
		goto gkr_exit;
	}

	FixupExceptionalFuncs(cc);

	if (result = (*pkrb5_cc_get_principal)(k5_context, cc, &me)
#ifdef WIN32
		&& bkx509busy
#endif
		)
	{
#ifdef WIN32
		if (((result == KRB5_FCC_NOFILE) || (result == 1)) // what does "1" mean!?!
			&& bPwdPrompt)
		{
			PROCESS_INFORMATION		ProcessInfo;
			STARTUPINFO				StartupInfo;
			CHAR					pszLeash[512];
			HANDLE					hLeash			= INVALID_HANDLE_VALUE;

			/* ASSUME THAT LEASH32.EXE IS INSTALLED IN WINDOWS SYSTEM32 DIRECTORY */
			memset(&StartupInfo, 0, sizeof(StartupInfo));
			strcpy(pszLeash, "leash32.exe -kinit");
			result = CreateProcess( NULL, pszLeash, NULL, NULL, FALSE, 0,
									NULL, NULL, &StartupInfo, &ProcessInfo);
			bPwdPrompt = FALSE; /* Only true once (not every second!) */
		}
#endif /* WIN32 */
		/*		msg_printf("get_krb5_realm: krb5_cc_get_principal: %s\n", (*perror_message)(result)); */
		*err_msg = "Try re-authenticating(K5).  "
			"You have no Kerberos tickets";
		rc = KX509_STATUS_CLNT_TMP; /*KX509_STATUS_CLNT_FIX; */
		goto gkr_exit;
	}

#if defined(HAVE_HEIMDAL)
	strcpy(realm, me->realm);
#else
	strcpy(realm, krb5_princ_realm(k5_context, me)->data);
#endif
	
gkr_exit:
	if (me)
		(*pkrb5_free_principal)(k5_context, me);
	me = NULL;

	if (cc)
		(*pkrb5_cc_close)(k5_context, cc);	/* ignore return code from close */
	cc = NULL;

	return rc;
#else /* USE_MSK5 */

	char	user[256];


	*realm = '\0';
	*err_msg = NULL;

	if ((rc = MSK5_get_userid_and_realm( user, realm )) != TRUE)
	{
		*err_msg = "MSK5_get_userid_and_realm failed";
	}

	return !rc;
#endif /* USE_MSK5 */
}

#else	/* USE_KRB5 */

/*
 *=========================================================================*
 *
 * get_krb4_realm()
 *
 *=========================================================================*
 */
int get_krb4_realm(char *realm, char **err_msg)
{
	char	dummy[MAX_K_NAME_SZ+1];

	/* DETERMINE REALM OF USER'S TICKET FILE */
	*realm = 0;

#if defined(macintosh)
	if ((err = KClientGetLocalRealm(realm)) != noErr)
#else
	if (krb_get_tf_fullname(tkt_string(), dummy, dummy, realm))
#endif
	{
		*err_msg = "Have you authenticated to Kerberos?  Your ticket file is invalid.";
		return KX509_STATUS_CLNT_FIX;
	}

	return 0;
}

#endif	/* USE_KRB5 */
