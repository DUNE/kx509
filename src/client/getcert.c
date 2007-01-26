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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifndef WIN32
#ifdef macintosh
#include <Sockets.h>
#include <Kerberos/Kerberos.h>		// Needed on Mac for Kerberos Framework
#else /* !macintosh */
# include <sys/time.h>
# include <sys/socket.h>
# include <netinet/in.h>
#endif /* macintosh */
#endif

#ifdef WIN32
# define WSHELPER
#endif /* WIN32 */

#ifdef WSHELPER
# include <wshelper.h>
#else /* !WSHELPER */
# include <arpa/inet.h>
# include <arpa/nameser.h>
# include <resolv.h>
#endif /* !WSHELPER */

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# ifndef FD_SET
#  include <sys/select.h>
# endif
#endif

#ifndef WIN32
# include <netdb.h>
#endif

#include <memory.h>

#ifdef WIN32
# define __WINCRYPT_H__		// PREVENT windows.h from including wincrypt.h
				// since wincrypt.h and openssl namepsaces collide
				//  ex. X509_NAME is #define'd and typedef'd ...
# include <winsock.h>		// Must be included before <windows.h> !!!
# include <windows.h>
# include <NTSecAPI.h>
# include <openssl/pem.h>
#endif  /* WIN32 */


#include <stdlib.h>
#include <openssl/x509v3.h>

#ifdef USE_KRB5
//  #ifndef USE_MSK5
# include <krb5.h>
# if !defined(HAVE_HEIMDAL) && !defined(WIN32)
# include <et/com_err.h>
# endif
# ifdef WIN32
#  include <loadfuncs-krb5.h>
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_free_default_realm)
		(krb5_context, const char *);
# else
   typedef krb5_error_code (KRB5_CALLCONV_C *FP_krb5_build_principal_ext)
		(krb5_context, krb5_principal *, int, const char *, ...);
   typedef krb5_error_code (KRB5_CALLCONV_C *FP_krb5_cc_close)
		(krb5_context, krb5_ccache cache);
   typedef krb5_error_code (KRB5_CALLCONV_C *FP_krb5_cc_default)
		(krb5_context, krb5_ccache *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_cc_get_principal)
		(krb5_context, krb5_ccache, krb5_principal *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_cc_resolve)
   		(krb5_context, const char *, krb5_ccache *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_cc_retrieve_cred)
		(krb5_context, krb5_ccache, krb5_flags, krb5_creds *, krb5_creds *);
   typedef void (KRB5_CALLCONV *FP_krb5_free_context)
		(krb5_context);
   typedef void (KRB5_CALLCONV *FP_krb5_free_cred_contents)
		(krb5_context, krb5_creds *);
   typedef void (KRB5_CALLCONV *FP_krb5_free_creds)
		(krb5_context, krb5_creds *);
   typedef void (KRB5_CALLCONV *FP_krb5_free_default_realm)
		(krb5_context, char *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_free_host_realm)
		(krb5_context, char * const *);
   typedef void (KRB5_CALLCONV *FP_krb5_free_principal)
		(krb5_context, krb5_principal);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_get_host_realm)
		(krb5_context, const char *, char * * * );
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_init_context)
		(krb5_context *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_mk_req)
		(krb5_context, krb5_auth_context *, const krb5_flags, char *,
		 char *, krb5_data *, krb5_ccache, krb5_data * );
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_get_default_realm)
		(krb5_context *, char * *);
   typedef krb5_error_code (KRB5_CALLCONV *FP_krb5_parse_name)
		(krb5_context *, const char *, krb5_principal *);
# endif /* WIN32 */
typedef char * (KRB5_CALLCONV *FP_error_message)
		(krb5_error_code);

   extern FP_error_message			perror_message;
   extern FP_krb5_build_principal_ext		pkrb5_build_principal_ext;
   extern FP_krb5_cc_close			pkrb5_cc_close;
   extern FP_krb5_cc_default			pkrb5_cc_default;
   extern FP_krb5_cc_get_principal		pkrb5_cc_get_principal;
   extern FP_krb5_cc_resolve			pkrb5_cc_resolve;
   extern FP_krb5_cc_retrieve_cred		pkrb5_cc_retrieve_cred;
   extern FP_krb5_free_context			pkrb5_free_context;
   extern FP_krb5_free_cred_contents		pkrb5_free_cred_contents;
   extern FP_krb5_free_creds			pkrb5_free_creds;
   extern FP_krb5_free_default_realm	pkrb5_free_default_realm;
   extern FP_krb5_free_host_realm		pkrb5_free_host_realm;
   extern FP_krb5_free_principal		pkrb5_free_principal;
   extern FP_krb5_get_default_realm		pkrb5_get_default_realm;
   extern FP_krb5_get_host_realm		pkrb5_get_host_realm;
   extern FP_krb5_init_context			pkrb5_init_context;
   extern FP_krb5_mk_req			pkrb5_mk_req;
   extern FP_krb5_parse_name			pkrb5_parse_name;
//  #endif /* USE_MSK5 */
#else /* !USE_KRB5 */
# ifndef WIN32
#  ifndef linux
#   define DES_DEFS		// Prevent collision with K5 DES delarations
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

#include "msg.h"
#include "udp_nb.h"
#include "kx509.h"
#include "doauth.h"
#include "debug.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include "kx509_asn.h"
#include <openssl/rand.h>

char version_2_0_string[4]={0,0,2,0};

#define	MAX_MSG_LEN	2048
#define RECV_TIMEOUT	5
#define SEND_TIMEOUT	5
#define MAX_KCA_HOSTS	16

#if defined(WIN32) && !defined(USE_KRB5)
/* I don't know if WIN32 defines this or not, but if not, here it is... */
# ifndef MAX_KTXT_LEN
#  define MAX_KTXT_LEN 1250
# endif
# ifndef ANAME_SZ
#  define ANAME_SZ	40
# endif
# ifndef REALM_SZ
#  define REALM_SZ	40
# endif
# ifndef SNAME_SZ
#  define SNAME_SZ	40
# endif
# ifndef INST_SZ
#  define INST_SZ	40
# endif
# ifndef KSUCCESS
#  define KSUCCESS	0
# endif
#endif	/* WIN32 && !USE_KRB5 */

#define	K5_CA_PRINC		"kca_service"

#ifdef DEBUG
void print_response(KX509_RESPONSE *);
void print_request(KX509_REQUEST *);
#endif

extern int	debugPrint;	/* XXX TEMPORARY TAKE THIS OUT */
#ifdef WIN32
extern char	gszHardErrorMsg[];
extern BOOL 	bSilent;
#else /* !WIN32 */
char	*gszHardErrorMsg = "";
#endif /* WIN32 */
extern char		szCertRealm[];

void print_response(KX509_RESPONSE *client_response);
void fill_in_octet_string( ASN1_OCTET_STRING *osp, char *st, int len);

#ifdef WIN32
 void clean_cert_store(char *realm);
# ifdef USE_KRB5
  int get_krb5_realm(krb5_context k5_context, char *realm, char **err_msg);
# else
  int get_krb4_realm(char *realm, char **err_msg);
#endif /* USE_KRB5 */
// int /*PASCAL*/ krb_mk_req(KTEXT,char *,char *,char *,long);
#ifdef USE_MSK5
extern BOOL PackageConnectLookup();
extern NTSTATUS GetMSSvcTkt();
extern BOOL MSK5_get_authent_and_sesskey();
extern BOOL MSK5_acquire_cred_handle();
#endif /* USE_MSK5 */
#endif /* WIN32 */
int get_kca_list(char *base_realm, char ***dns_hostlist);
extern long certLife(char *realm);


#define KRBCHK_PORT     (u_short)9878
#define BUF_LEN		2048


#if defined(USE_KRB5)
#define CA_SERVICE	"kca_service"
#else
#define CA_PRINC	"cert"
#define CA_INST		"x509"
#endif

#if defined(USE_KRB5)
char ca_service[256] = CA_SERVICE;
#else
char ca_princ[ANAME_SZ] = CA_PRINC, ca_inst[INST_SZ] = CA_INST;
#endif

#define	DEFBITS	512 /* first get MS stuff working, then do 1024 */

/* Make "buffer" static since it's sometimes used for returned error messages */
#if defined(USE_KRB5)
static char buffer[2048];
#else
static char buffer[MAX_KTXT_LEN+1];
#endif

#ifdef WIN32
#if defined(USE_KRB5)
krb5_timestamp	staleTGTtime = 0;

extern void FixupExceptionalFuncs();

krb5_timestamp
get_tgt_time
(
	krb5_context		k5_context
)
{
#ifdef USE_MSK5
	krb5_timestamp		tgtTime		= 0;
	HANDLE				LogonHandle	= NULL;
	ULONG				PackageId	= 0;


	if(PackageConnectLookup(&LogonHandle, &PackageId))
	{
		maj_stat = GetMSSvcTkt(LogonHandle, PackageId,
					"krbtgt", realm , realm,
					&tgtTime, NULL,
					NULL, 0, 
					NULL, 0);

		LsaDeregisterLogonProcess(LogonHandle);

		if (maj_stat) 
			tgtTime = 0;
	}

#else /* !USE_MSK5 */

	krb5_ccache		cc	= NULL;
	char			realm[512] = {0};
	krb5_creds		mcred;
	krb5_creds		cred;
	int				cred_in_use = 0;
	krb5_error_code		k5_rc	= 0;
	krb5_timestamp		tgtTime = 0;
	char			princ[512] = {0};


	/* Retrieve TGT for default realm */
	memset(&mcred, 0, sizeof(mcred));
	if (k5_rc = (*pkrb5_cc_default)(k5_context, &cc))
		goto gtt_exit;

	FixupExceptionalFuncs(cc);

	if (k5_rc = (*pkrb5_cc_get_principal)(k5_context, cc,
					  &mcred.client))
		goto gtt_exit;
	strncpy(realm, mcred.client->realm.data, mcred.client->realm.length);
	realm[mcred.client->realm.length] = '\0';
	if (k5_rc = (*pkrb5_parse_name)(k5_context, princ, &mcred.server))
		goto gtt_exit;
	if (k5_rc = (*pkrb5_cc_retrieve_cred)(k5_context, cc, 0,
					 &mcred, &cred))
		goto gtt_exit;

	/* Success.  Now get TGT's start time */
	cred_in_use = 1;
	tgtTime = cred.times.starttime;

gtt_exit:
	if (mcred.client && mcred.client->data)
	{
		(*pkrb5_free_principal)(k5_context, mcred.client);
		mcred.client = NULL;
	}
	if (mcred.server && mcred.server->data)
	{
		(*pkrb5_free_principal)(k5_context, mcred.server);
		mcred.server = NULL;
	}
	if (cred_in_use)
	{
		(*pkrb5_free_cred_contents)(k5_context, &cred);
		cred_in_use = 0;
	}
#endif /* !USE_MSK5 */

	return tgtTime;
}



krb5_timestamp
get_tgt_life
(
	krb5_context		k5_context
)
{
	krb5_ccache		cc	= NULL;
	char			realm[512] = {0};
	krb5_creds		mcred;
	krb5_creds		cred;
	int				cred_in_use = 0;
	krb5_error_code		k5_rc	= 0;
	krb5_timestamp		tgtTime = 0;
	char			princ[512] = {0};


	/* Retrieve TGT for default realm */
	memset(&mcred, 0, sizeof(mcred));
	if (k5_rc = (*pkrb5_cc_default)(k5_context, &cc))
		goto gtl_exit;

	FixupExceptionalFuncs(cc);

	if (k5_rc = (*pkrb5_cc_get_principal)(k5_context, cc,
					  &mcred.client))
		goto gtl_exit;
	strncpy(realm, mcred.client->realm.data, mcred.client->realm.length);
	realm[mcred.client->realm.length] = '\0';
	sprintf(princ, "krbtgt/%s@%s", realm, realm);
	if (k5_rc = (*pkrb5_parse_name)(k5_context, princ, &mcred.server))
		goto gtl_exit;
	if (k5_rc = (*pkrb5_cc_retrieve_cred)(k5_context, cc, 0,
					 &mcred, &cred))
		goto gtl_exit;

	/* Success.  Now get TGT's start time */
	cred_in_use = 1;
	tgtTime = cred.times.endtime;

gtl_exit:
	if (mcred.client && mcred.client->data)
	{
		(*pkrb5_free_principal)(k5_context, mcred.client);
		mcred.client = NULL;
	}
	if (mcred.server && mcred.server->data)
	{
		(*pkrb5_free_principal)(k5_context, mcred.server);
		mcred.server = NULL;
	}
	if (cred_in_use)
	{
		(*pkrb5_free_cred_contents)(k5_context, &cred);
		cred_in_use = 0;
	}
	return tgtTime;
}
#endif	/* USE_KRB5 */
#endif /* WIN32 */

#if defined(USE_KRB5)
/*
 *=========================================================================*
 *
 * get_cert_authent_K5()
 *
 *=========================================================================*
 */
int
get_cert_authent_K5
(
	krb5_context		k5_context,
	char			*ca_hostname,
	krb5_data		*k5_authent,
	char			sess_key_result[],
	int			*sess_len_ptr,
	char			*realm,
#if defined(KX509_LIB)
	char *tkt_cache_name,
#endif
	char			**err_ptr
)
{
	int			rc			= 0;
#ifndef USE_MSK5
	krb5_auth_context	k5_auth_context;
	krb5_ccache		cc			= NULL;
	int			in_use_cc		= 0;
	krb5_principal		me			= NULL;
	int			in_use_me		= 0;
	krb5_creds		mcreds;
	krb5_creds		outcreds;
	int			in_use_outcreds		= 0;
	krb5_error_code		result			= 0;
	char			**realms_of_host	= NULL;


	/* Without this, I get a bus error within krb5_mk_req() in krb5_copy_keyblock() */
	memset(&k5_auth_context,	'\0', sizeof(k5_auth_context));

	/* DETERMINE USER'S PRINCIPAL NAME FROM TICKET FILE */

#if defined(KX509_LIB)
	if (result = (*pkrb5_cc_resolve)(k5_context, tkt_cache_name, &cc))
	{
		msg_printf("get_cert_authent_K5: krb5_cc_resolve: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"You have no Kerberos tickets";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}
#else
	if (result = (*pkrb5_cc_default)(k5_context, &cc))
	{
		msg_printf("get_cert_authent_K5: krb5_cc_default: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"Bad default credentials cache.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}
#endif
	in_use_cc = 1;

	if (result = (*pkrb5_cc_get_principal)(k5_context, cc, &me))
	{
		msg_printf("get_cert_authent_K5: krb5_cc_get_principal: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"You have no Kerberos tickets";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}
	in_use_me = 1;

	/* GENERATE KRB5 AUTHENTICATOR FOR CA SERVER */

	if (result = (*pkrb5_mk_req)(k5_context, &k5_auth_context, AP_OPTS_MUTUAL_REQUIRED,
			ca_service, ca_hostname, 0L, cc, k5_authent))

	{
		if ((result == KRB5KRB_AP_ERR_SKEW)
			|| (result == KRB5KRB_AP_ERR_TKT_NYV))
		{
#ifdef WIN32
			staleTGTtime = get_tgt_time(k5_context);
#endif /* WIN32 */
			*err_ptr = "Bad time zone or time."
				   "  Correct and re-authenticate.";
		}
		else if (result == KRB5KRB_AP_ERR_TKT_EXPIRED)
			*err_ptr = "Your kerberos tickets have expired."
				   "  Correct and re-authenticate.";
		else
			*err_ptr = "Try re-authenticating(K5).  "
				"Can't build needed authenticator.";
		msg_printf("get_cert_authent_K5: krb5_mk_req: %s\n",
			(*perror_message)(result));
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}

#ifdef WIN32
	staleTGTtime = 0; /* since mk_req succeeded, clear any record of staleTGT */
#endif /* WIN32 */

	/* EXTRACT THE SESSION KEY FROM THE RESULTING CREDENTIALS (TICKET) */

	memset(&mcreds, 0, sizeof(mcreds));
	memset(&outcreds, 0, sizeof(outcreds));
	mcreds.client = me;
	if (result = (*pkrb5_get_host_realm)(k5_context, ca_hostname, &realms_of_host))
	{
		msg_printf("get_cert_authent_K5: krb5_get_host_realm: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"Can't determine realm of KCA host.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}

	if (realms_of_host[0] == NULL)
	{
		msg_printf("get_cert_authent_K5: krb5_get_host_realm returned empty list\n");
		*err_ptr = "Check your Kerberos 5 configuration.  "
			"Can't determine realm of KCA host.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}

	if (result = (*pkrb5_build_principal_ext)(k5_context, &mcreds.server,
				strlen(realms_of_host[0]),
				realms_of_host[0],
				strlen(ca_service), ca_service,
				strlen(ca_hostname), ca_hostname,
				0))
	{
		msg_printf("get_cert_authent_K5: krb5_build_principal_ext: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"Can't build new principal.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}


	if (result = (*pkrb5_cc_retrieve_cred)(k5_context, cc, 0, &mcreds, &outcreds))
	{
		msg_printf("get_cert_authent_K5: krb5_cc_retrieve_cred: %s\n",
			(*perror_message)(result));
		*err_ptr = "Try re-authenticating(K5).  "
			"Can't get session key.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}
	in_use_outcreds = 1;

#ifdef WIN32
	/* Ensure that cred has a lifetime greater than 5 minutes */
	{
		long	currTime = time(0);
		long	lifeTime = outcreds.times.endtime - currTime;
		long	lifeMin  = lifeTime/60;

		if (lifeMin <= 5)
		{
			*err_ptr = "Try re-authenticating(K5).  "
				"Credentials are stale/dead.";
			rc = KX509_STATUS_CLNT_TMP;
			goto EXIT_GCAK5;
		}
	}
#endif /* WIN32 */

	/* Verify caller can hold session key, and return it */
#if defined(HAVE_HEIMDAL)
	if (*sess_len_ptr < outcreds.session.keyvalue.length)
#else
	if (*sess_len_ptr < (int)outcreds.keyblock.length)
#endif
	{
		*err_ptr = "Internal error; session key too large.";
		(*pkrb5_free_creds)(k5_context, &outcreds);
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCAK5;
	}
#if defined(HAVE_HEIMDAL)
	*sess_len_ptr = outcreds.session.keyvalue.length;
	memcpy(sess_key_result, outcreds.session.keyvalue.data,
				outcreds.session.keyvalue.length);
#else
	*sess_len_ptr = outcreds.keyblock.length;
	memcpy(sess_key_result, outcreds.keyblock.contents, outcreds.keyblock.length);
#endif

	rc = 0;
	goto EXIT_GCAK5;

EXIT_GCAK5:

#else /* USE_MSK5 */

	/* Place to receive the MS K5 authenticator data */
	static	char	authent_dat[1024];


	k5_authent->data = &authent_dat[0];
	rc = !MSK5_get_authent_and_sesskey(CA_SERVICE, ca_hostname, realm,
						&k5_authent->data[0],
						&k5_authent->length,
						sess_key_result,
						sess_len_ptr);
#endif /* USE_MSK5 */

#ifndef USE_MSK5
	if (in_use_me)
	{
		(*pkrb5_free_principal)(k5_context, me);
		me = NULL;
	}
	if (in_use_outcreds)
		(*pkrb5_free_cred_contents)(k5_context, &outcreds);
	if (in_use_cc)
	{
		(*pkrb5_cc_close)(k5_context, cc);
		cc = NULL;
	}
	if (realms_of_host)
	{
		(*pkrb5_free_host_realm)(k5_context, realms_of_host);
		realms_of_host = NULL;
	}
#endif /* USE_MSK5 */

	return rc;
}

#else	/* !USE_KRB5 */

/*
 *=========================================================================*
 *
 * get_cert_authent()
 *
 *=========================================================================*
 */
int
get_cert_authent(
	KTEXT				authent,
	char				sess_key_result[],
	int					*sess_len,
	char				*realm,
	char				**err_ptr
)
{
#ifdef WIN32
	char				guard_rail_1[2048];	/* BILLDO */
	CREDENTIALS			cr;
	char				guard_rail_2[2048];	/* BILLDO */
#else /* !WIN32 */
	char				dummy[MAX_K_NAME_SZ+1];
#  ifndef macintosh
	CREDENTIALS			cr;
	char				*sess_key				= NULL;
#  endif /* macintosh */
#endif /* WIN32 */

#ifdef macintosh
	KClientSessionInfo	session;
	int					err						= 0;
	static KClientKey	sessionKey;
	int					rc						= 0;
#endif /* macintosh */


#ifdef WIN32
	memset(guard_rail_1, 0, 2048);	/* BILLDO */
	memset(guard_rail_2, 0, 2048);	/* BILLDO */
#endif /* WIN32 */
	memset(&cr,			'\0', sizeof(cr));
	memset(&session,	'\0', sizeof(session));

	if (*sess_len < 8)
	{
		*err_ptr = "Internal error; bad *sess_len";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	*sess_len = 8;

	/* GENERATE KRB4 AUTHENTICATOR FOR CA SERVER */

#if defined(macintosh)
	if ((err = KClientNewSession(&session, 0, 0, 0, 0)) != noErr)
	{
		*err_ptr = "Nope, you needed to pass KClientNewSession something else.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	sprintf(dummy, "%s.%s@%s", ca_princ, ca_inst, realm);
	authent->length = sizeof(authent->dat);
	if ((err = KClientGetTicketForService(&session, dummy, authent,
					(unsigned long *)&authent->length)) != noErr)
	{
		*err_ptr = "Try re-authenticating.  "
			"Can't build authenticator.";
		KClientDisposeSession(&session);
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	if ((err = KClientGetSessionKey(&session, &sessionKey)) != noErr) {
		*err_ptr = "Try re-authenticating.  "
			"Can't get session key.";
		KClientDisposeSession(&session);
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	/* XXX need to get the session key */
	memcpy(sess_key_result, &sessionKey, 8);
	KClientDisposeSession(&session);
#else   /* MIT V4 on Unix or WIN32 */
	if (krb_mk_req(authent, ca_princ, ca_inst, realm, 0L))
	{
		*err_ptr = "Try re-authenticating.  "
			"Can't build authenticator.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	if (krb_get_cred(ca_princ, ca_inst, realm, &cr))
	{
		*err_ptr = "Try re-authenticating.  "
			"Can't get session key.";
		rc = KX509_STATUS_CLNT_FIX;
		goto EXIT_GCA;
	}
	memcpy(sess_key_result, cr.session, 8);
#endif  /* MIT V4 on Unix or WIN32 */

EXIT_GCA:
	return 0;
}

#endif	/* USE_KRB5 */







int
do_kx509_request(
	KX509_REQUEST		*request,
	int			socket,			/* IN Socket to be used to communicate with CA */
	char			*ca_hostname,		/* IN Host name of the the CA to try */
	int			(*verify_recvd_packet)(),/*IN routine to call to verify the CA response */
	void			*arg,		/* IN Arguments passed to verification routine */
	char			**emsg,		/* IN/OUT error string buffer */
	int			*err_num_ptr	/* OUT Error value recipient */
)
{
	int			keybits			= DEFBITS;	/* Number of bits in the public key / private key */
	fd_set			readfds;
	struct hostent		*ca_hostent		= NULL;
	struct sockaddr_in	ca_addr			= { 0 };
	struct timeval		timeout			= { 0 };
	DWORD			i			= 0;
	KX_MSG			pkt_to_send		= { 0 };
	KX_MSG			pkt_recvd		= { 0 };
	char			*pubkey_ptr		= NULL;
	unsigned char		*tmp_ptr		= NULL;
	int			pubkey_len		= 0;
	int			entropy_to_copy		= 0;
	int			len			= 0;
	static int		triedAuthent		= 0;
	int			rc			= 0;
#ifdef macintosh
	OSErr			err			= 0;
#endif /* macintosh */

	len = i2d_KX509_REQUEST(request, 0) + 4;
	log_printf("try_ca: Checking len %d against MAX_UDP_PAYLOAD_LEN %d\n",
			len, MAX_UDP_PAYLOAD_LEN);
	if (len > MAX_UDP_PAYLOAD_LEN)
	{
		log_printf("try_ca: len=%d MAX_UDP_PAYLOAD_LEN=%d\n",
			len, MAX_UDP_PAYLOAD_LEN);
		*emsg = "Weird!  KX509 transmit packet is too large!";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	if (MSG_ALLOC(&pkt_to_send, len))
	{
		log_printf("try_ca: could not allocate %d bytes?\n", len);
		*emsg = "Try again.  Transient client-side problem";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	memcpy(pkt_to_send.m_data, version_2_0_string, 4);
	tmp_ptr = pkt_to_send.m_data+4;
	i2d_KX509_REQUEST     (request, &tmp_ptr);
	pkt_to_send.m_curlen = tmp_ptr - pkt_to_send.m_data;

	/* XXX This won't work on macintosh */
	if (debugPrint) {
#if defined(DEBUG) && !defined(WIN32)
		print_request(request);
#endif
		PEM_write(stderr, "kx509 request", ca_hostname,
			pkt_to_send.m_data+4, pkt_to_send.m_curlen-4);
	}


	/* DETERMINE IP ADDRESS OF KCA SERVER */

	/* According to MSDN, NEVER free ca_hostent (not on Windows at least) */
	if (!(ca_hostent = gethostbyname(ca_hostname)))
	{
#ifdef macintosh
		err = GetMITLibError();
		if (GetErrorLongFormat(err, buffer, sizeof(buffer)) == noErr) {
		    log_printf("try_ca: gethostbyname of CA (%s) failed ('%s')\n",
			ca_hostname, buffer);
		}
#else /* !macintosh */
		log_printf("try_ca: gethostbyname of CA (%s) failed ('%s')\n",
			ca_hostname, strerror(errno));
#endif /* macintosh */
		*emsg = "try_ca: gethostbyname failed";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	memset(&ca_addr, 0, sizeof(ca_addr));
	ca_addr.sin_family	= AF_INET;
	ca_addr.sin_port	= htons(KRBCHK_PORT);
	ca_addr.sin_addr.s_addr	= *(int *)(ca_hostent->h_addr_list[0]);

	/* "CONNECT" TO IT (ICMP RESPONSE INDICATES HOST ISN'T LISTENING ON THAT PORT) */

	log_printf("try_ca: About to connect to KCA at %s:%d\n",
		inet_ntoa(ca_addr.sin_addr), KRBCHK_PORT);
	if (udp_nb_connect(socket, &ca_addr) == -1)
	{
#ifdef macintosh
		err = GetMITLibError();
		if (GetErrorLongFormat(err, buffer, sizeof(buffer)) == noErr) {
		    log_printf("try_ca: udp_nb_connect failed with err %d ('%s')\n",
			err, buffer);
		}
#else /* !macintosh */
		log_printf("try_ca: udp_nb_connect failed with errno %d ('%s')\n",
			errno, strerror(errno));
#endif /* macintosh */
		*emsg = "try_ca: udp_nb_connect failed";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	/* SOMETHINGS LISTENING -- SEND PACKET */

	i = udp_nb_send(socket, &pkt_to_send);
	log_printf("try_ca: sent KX_CLNT_PKT of %0d bytes (rc = %d) \n",
			pkt_to_send.m_curlen, i);

	/* RECV WIRE-VERSION OF KX_SRVR_PKT FROM CA SERVER */

	if (MSG_ALLOC(&pkt_recvd, MAX_KSP_LEN))
	{
		log_printf("try_ca: failed to allocate %d bytes for recv pkt?\n", MAX_KSP_LEN);
		*emsg = "Try again.  Transient client-side problem";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	/* WAIT UP TO "KX509_CLIENT_TIMEOUT" SECONDS FOR RESPONSE */

	FD_ZERO(&readfds);
	FD_SET((WORD)socket, &readfds);
	timeout.tv_sec = KX509_CLIENT_TIMEOUT;
	timeout.tv_usec = 0;
	i = udp_nb_select(&readfds, NULL, NULL, &timeout);
	if (i<0)
	{
#ifdef macintosh
		err = GetMITLibError();
		if (GetErrorLongFormat(err, buffer, sizeof(buffer)) == noErr) {
		    log_printf("try_ca: udp_nb_select failed with code %d, errno %d ('%s')\n",
			i, err, buffer);
		}
#else /* !macintosh */
		log_printf("try_ca: udp_nb_select failed with code %d, errno %d ('%s')\n",
			i, errno, strerror(errno));
#endif /* macintosh */
		*emsg = "Error return waiting for response.";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}
	else if (i==0)
	{
		log_printf("try_ca: timeout during udp_nb_select\n");
		*emsg = "Timed out waiting on KCA";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}

	if (udp_nb_recv(socket, &pkt_recvd) == -1)
	{
#ifdef macintosh
		err = GetMITLibError();
		if (GetErrorLongFormat(err, buffer, sizeof(buffer)) == noErr) {
			log_printf("try_ca: udp_nb_recv failed with err %d ('%s')\n",
				err, buffer);
		}
#else /* !macintosh */
		log_printf("try_ca: udp_nb_recv failed with errno %d ('%s')\n",
			errno, strerror(errno));
#endif /* macintosh */
#ifdef WIN32
		if (WSAGetLastError() == WSAECONNREFUSED)
#elif defined(macintosh)
		if (0)
#else /* !WIN32 && !macintosh */
		if (errno == ECONNREFUSED)
#endif
			*emsg = "Try later.  No KCA's currently available.";
		else
			*emsg = "Strange.  Unexpected error on receive.";
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_DKR;
	}


	*emsg = NULL;
	rc = (*verify_recvd_packet)(&pkt_recvd, arg);

EXIT_RTN_DKR:
	if (pkt_to_send.m_data)
		MSG_FREE(&pkt_to_send);
	if (pkt_recvd.m_data)
		MSG_FREE(&pkt_recvd);

	return(rc);
}
























/*
 *=========================================================================*
 *
 * try_ca()
 *
 * Request a certificate from a particular KCA.
 * If we haven't already generated a key-pair, do that now.
 * If using K5, we need a different authenticator for each
 * CA we contact.  If using K4, then we can use the same one
 * for each CA.  We use the session key to seed the generation
 * of the key-pair.
 *
 *=========================================================================*
 */
int try_ca(
#if defined(USE_KRB5)
	krb5_context		k5_context,
#endif
	int			socket,				/* IN Socket to be used to communicate with CA */
	char			*ca_hostname,		/* IN Host name of the the CA to try */
	char 			*realm,				/* IN Realm name */
	RSA			**rsa,				/* IN/OUT key-pair information */
	X509			**certp,			/* OUT certificate information */
	int			(*verify_recvd_packet)(),/*IN routine to call to verify the CA response */
	void			*arg,				/* IN Arguments passed to verification routine */
	char			sess_key[],			/* IN/OUT session key holder */
	int			*sess_len_ptr,		/* IN/OUT length of session key */
#if defined(KX509_LIB)
	char			*tkt_cache_name,		/* IN credential cache file name */
#endif
	char			**emsg,				/* IN/OUT error string buffer */
	int			*err_num_ptr		/* OUT Error value recipient */
)
{
	int			keybits			= DEFBITS;	/* Number of bits in the public key / private key */
	struct hostent		*ca_hostent		= NULL;
	struct sockaddr_in	ca_addr			= { 0 };
	struct timeval		timeout			= { 0 };
	DWORD			i			= 0;
	KX_MSG			pkt_to_send		= { 0 };
	KX_MSG			pkt_recvd		= { 0 };
	KX509_REQUEST		*request		= NULL;
	char			*pubkey_ptr		= NULL;
	unsigned char		*tmp_ptr		= NULL;
	int			pubkey_len		= 0;
	int			entropy_to_copy		= 0;
	int			len			= 0;
	static int		triedAuthent		= 0;
	int			rc			= 0;
#if defined(USE_KRB5)
	krb5_data		k5_authent		= { 0 };
#else
	static KTEXT_ST		authent			= { 0 };	/* BILLDO 2001.0330 -- make static so that it's preserved across try_ca calls */
#endif

/*
 * require 128 bytes of randomness  N.B. This is a moving target.
 * This is defined in OpenSSL's crypto/rand/rand_lcl.h.  But that
 * is an internal header.  As of OpenSSL 0.9.6 the value was 20 bytes.
 * As of OpenSSL 0.9.7 the value is 32 bytes.
 */
#define ENTROPY_NEEDED 128
	char				entropy_pool[ENTROPY_NEEDED];
	int					entropy_still_needed = ENTROPY_NEEDED;


	memset(&pkt_to_send,	0, sizeof(pkt_to_send));
	memset(&pkt_recvd,	0, sizeof(pkt_recvd));
	*err_num_ptr = 0;

#if defined(USE_KRB5)
	/* For K5, we always generate a new authenticator for the host we are contacting */
	if (rc = get_cert_authent_K5(k5_context, ca_hostname, &k5_authent, sess_key,
#if defined(KX509_LIB)
				sess_len_ptr, realm, tkt_cache_name, emsg))
#else
				sess_len_ptr, realm, emsg))
#endif
	{
		*err_num_ptr = KX509_STATUS_CLNT_TMP;
		rc = KX509_STATUS_CLNT_TMP;
		goto EXIT_RTN_TC;
	}
#endif

	/*
	 * If this is the first host we've tried
	 * {
	 *	If using K4
	 *	{
	 *	  generate authenticator
	 *	}
	 *	generate the key-pair
	 * }
	 */

	if ( NULL == *rsa)
	{
#if !defined(USE_KRB5)
		if (triedAuthent == 0) 
		{
			triedAuthent = 1;
			if (rc = get_cert_authent(&authent, sess_key, sess_len_ptr, realm, emsg))
			{
				*err_num_ptr = KX509_STATUS_CLNT_TMP;
				rc = KX509_STATUS_CLNT_TMP;
				goto EXIT_RTN_TC;
			}
		}
		else
		{
			*err_num_ptr = KX509_STATUS_CLNT_TMP;
			rc = KX509_STATUS_CLNT_TMP;
			goto EXIT_RTN_TC;
		}
#endif
		/*
		 * THIS COULD BE **BETTER** -- Starting with Openssl-0.9.6, the
		 * RAND functions insist that ENTROPY_NEEDED (20) bytes of seed
		 * material be provided before they will work at all.  As a really
		 * cheesy work-around, the code below simply copies the 8-byte
		 * kerberos session-key a couple times to generate 24-bytes of
		 * entropy...
		 */
		
		/*
		 * Note that with 3DES, the session key is 24 bytes.
		 * Don't copy too much!
		 */
		if (*sess_len_ptr > entropy_still_needed)
			entropy_to_copy = entropy_still_needed;
		else
			entropy_to_copy = *sess_len_ptr;

		memcpy(entropy_pool, sess_key, entropy_to_copy);
		entropy_still_needed -= entropy_to_copy;
		while (entropy_still_needed > 0)
		{
			if (entropy_still_needed < *sess_len_ptr)
			{
				memcpy(&entropy_pool[ENTROPY_NEEDED-entropy_still_needed],
					sess_key, entropy_still_needed);
				entropy_still_needed = 0;
			}
			else
			{
				memcpy(&entropy_pool[ENTROPY_NEEDED-entropy_still_needed],
					sess_key, *sess_len_ptr);
				entropy_still_needed -= *sess_len_ptr;
			}
		}

		/* GENERATE PUBLIC KEY PAIR  */

		RAND_seed(entropy_pool, ENTROPY_NEEDED);

		*rsa=client_genkey(keybits); 
		if (*rsa == NULL) {		/* Verify that key generation succeeded.  If not, bail out now! */
			*emsg = "Error generating RSA key pair.";
			*err_num_ptr = KX509_STATUS_CLNT_BAD;
			rc = KX509_STATUS_CLNT_BAD;
			goto EXIT_RTN_TC;
		}
	 
		log_printf("try_ca: sending authentication request (len %d) to KCA\n",
#if defined(USE_KRB5)
			k5_authent.length);
#else
			authent.length);
#endif

	}

	
	/* CONVERT KEY-PAIR INFO AND AUTHENT TO REQUEST */

	memset(buffer, 0, sizeof(buffer));	/* BILLDO 2001.0330 -- something causes 1st try_ca failures to make later try_ca's fail... */
	pubkey_ptr	= buffer;
	tmp_ptr		= (unsigned char *)pubkey_ptr;
	pubkey_len	= i2d_RSAPublicKey (*rsa, (unsigned char **)&tmp_ptr);

	log_printf("try_ca: sending pubkey_len=%d bytes of public key\n", pubkey_len);

	request = KX509_REQUEST_new();
	fill_in_octet_string(request->authenticator,
#if defined(USE_KRB5)
		k5_authent.data, k5_authent.length);
#else
		(char *)authent.dat, authent.length);
#endif
	fill_in_octet_string(request->pkey, pubkey_ptr, pubkey_len);
	KX509_REQUEST_compute_checksum((unsigned char *)version_2_0_string, request,
		request->hash, sess_key, *sess_len_ptr);

	/* CONVERT REQUEST STRUCTURE TO WIRE-VERSION MSG */

	log_printf("try_ca: authent.length is %d, and pubkey_len is %d\n",
#if defined(USE_KRB5)
		k5_authent.length, pubkey_len);
#else
		authent.length, pubkey_len);
#endif

#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	request->client_version = ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING);
	{
		char cv[100] = {0};

		sprintf(cv, "%s %s", KX509_CLIENT_KRB, KX509_CLIENT_VERSION);
		ASN1_STRING_set(request->client_version, cv, -1);
	}
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */
		
	rc = do_kx509_request(request, socket, ca_hostname, verify_recvd_packet,
				arg, emsg, err_num_ptr);
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	if (rc == KX509_STATUS_SRVR_CANT_CLNT_VERS)
	{
		/* Request with client_version failed.  remove and try again */
		ASN1_STRING_free(request->client_version);
		request->client_version = NULL;
		rc = do_kx509_request(request, socket, ca_hostname, 
					verify_recvd_packet, arg, emsg, err_num_ptr);
	}
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */

EXIT_RTN_TC:
	if (request)
		KX509_REQUEST_free(request);

	return(rc);
}


void fill_in_octet_string(
	ASN1_OCTET_STRING *osp,
	char *st,
	int len)
{
	char *c;
	if (osp->data && osp->length)
	{
		Free(osp->data);
		osp->data = NULL;
	}

	if (len <= 0)
		return;

	c = Malloc(len);
	memcpy(c, st, len);
	osp->data = (unsigned char *)c;
	osp->length = len;
}

struct verify_arg {
	KX509_RESPONSE	*response;
	char sess_key[32];
	int sess_len;
	char *emsg;
};


int
verify_recvd_packet(
	KX_MSG				*pkt_recvd,
	void 				*arg
)
{
	unsigned char		*p			= NULL;
#if defined(DEBUG) && !defined(WIN32)
	unsigned char		*op			= NULL;
#endif
	int					length		= 0;
	ASN1_OCTET_STRING	*hash		= NULL;
	int					result		= 0;
	struct verify_arg	*varg		= (struct verify_arg *)arg;


	if (pkt_recvd->m_curlen < 4)
	{
		sprintf(buffer,"verify_recvd_packet: received runt of length %d",
			pkt_recvd->m_curlen);
		varg->emsg = buffer;
		result = KX509_STATUS_CLNT_BAD;
		goto EXIT_VRP;
	}
	if (2[(unsigned char *)pkt_recvd->m_data] != version_2_0_string[2])
	{
		sprintf(buffer,
			"verify_recvd_packet: rec'd version %d.%d does not match %d.*",
			2[(unsigned char *)pkt_recvd->m_data],
			3[(unsigned char *)pkt_recvd->m_data],
			version_2_0_string[2]);
		varg->emsg = buffer;
		result = KX509_STATUS_CLNT_BAD;
		goto EXIT_VRP;
	}
	p = pkt_recvd->m_data+4;
	length = pkt_recvd->m_curlen-4;
#if defined(DEBUG) && !defined(WIN32)
	/* XXX this wont work on macintosh */
	if (debugPrint) 
	{
		PEM_write(stderr, "kx509 response", "", p, length);
		bin_dump((char *)p, length);
	}
	op = p;
#endif
	if (!(varg->response = d2i_KX509_RESPONSE(NULL, &p, length)))
	{
		varg->emsg = "verify_recvd_packet: d2i_X509_RESPONSE failed";
		result = KX509_STATUS_CLNT_BAD;
		goto EXIT_VRP;
	}
#if defined(DEBUG) && !defined(WIN32)
	log_printf ("Decoded %d bytes of %d\n", p-op, length);
	print_response(varg->response);
#endif
	if (!varg->response->hash)
	{
		if (varg->response->error_message)
		{
			int xlen;
			xlen = sizeof buffer-1;
			if (xlen > varg->response->error_message->length)
				xlen=varg->response->error_message->length;
			memcpy(buffer, varg->response->error_message->data, xlen);
			buffer[xlen] = 0;
			varg->emsg = buffer;
			if (!strcmp(buffer, KX509_EMSG_UNABLE_TO_D2I_KX509_REQUEST))
			{
				strcpy(buffer, "CA can't handle client_version in a request");
				varg->response->status = KX509_STATUS_SRVR_CANT_CLNT_VERS;
			}
		}
		result = varg->response->status ?
						varg->response->status : KX509_STATUS_CLNT_BAD;
		goto EXIT_VRP;
	}
	if (!(hash = ASN1_OCTET_STRING_new()))
	{
		varg->emsg = "verify_recvd_packet: out of memory";
		result = KX509_STATUS_CLNT_BAD;
		goto EXIT_VRP;
	}

	KX509_RESPONSE_compute_checksum(
		pkt_recvd->m_data,
		varg->response,
		hash,
		varg->sess_key, 
		varg->sess_len);

	if (hash->length != varg->response->hash->length
		|| memcmp(hash->data, varg->response->hash->data, hash->length))
	{
		varg->emsg = "verify_recvd_packet: generated hash did not compare";
		result = KX509_STATUS_CLNT_BAD;
	}

EXIT_VRP:
	if (hash)
	{
		ASN1_OCTET_STRING_free(hash);
		hash = NULL;
	}

	return result;
}

/*
 *=========================================================================*
 *
 * getcert()
 *
 * Attempt to obtain a certificate
 *
 *=========================================================================*
 */
int getcert(
	RSA		**rsa,
	X509	**certp,
	char	*emsg,
	int		elen,
	char	*realm
#if defined(KX509_LIB)
	, char	*tkt_cache_name
#endif
)
{
#if defined(USE_KRB5)
	krb5_error_code		k5_result		= 0;
#if 1 /* BILLDO 2004.0305 -- Only krb5_init_context once per process */
	static krb5_context	k5_context		= NULL;
#else /* !1 */
	krb5_context		k5_context		= NULL;
#endif
#endif
	char				**dns_hostlist	= NULL;
	char				**kca_hostlist	= NULL;
	char				ca_hostname_to_try[256];
	char				*base_realm		= NULL;
	char				*env_host_list	= NULL;
	int					rc				= 0;
	int					n				= 0;
	struct verify_arg	arg[1]; 
	int					socket			= -1;
	unsigned char		*tmp_ptr		= NULL;
#ifdef macintosh
	OSErr				err				= 0;
#endif /* macintosh */
#ifdef WIN32
	int					minLeft			= 0;
#endif /* WIN32 */


	*certp = 0;
	*emsg = 0;
	memset((char*)arg, 0, sizeof arg);
	arg[0].sess_len = sizeof(arg[0].sess_key);

#if defined(USE_KRB5)
#if !defined(USE_MSK5)
#if 1 /* BILLDO 2004.0305 -- Only krb5_init_context once per process */
	if (!k5_context)
#endif /* 1 */
	/* Check for any early Hard Failures */
	if (strlen(gszHardErrorMsg))
		goto Failed;
	else if ((k5_result = (*pkrb5_init_context)(&k5_context))) 
	{
		msg_printf("getcert: unable to initialize Kerberos 5 context: %s\n",
			(*perror_message)(k5_result));
		arg->emsg = "Verify KRB5 configuration. Init context failed.\n";
		rc = KX509_STATUS_CLNT_BAD;
		goto Failed;
	}
#else /* USE_MSK5 */
	k5_context = NULL;

	/*
	 * we will determin if we have any credentials or get the credentials
	 * usung the SSPI AcquireCredHandle We save the credHandle so all
	 * calls to SSPI or LSA will use this cred handle. This allows us
	 * to run under a different user@realm if needed. Future code
	 * to add this feature. 
	 * But we will tell the W2K KDC that we want tickets without
	 * a PAC to keep them small. 
	 * DEE
	 */

	MSK5_acquire_cred_handle();


#endif /* USE_MSK5 */
#endif /* USE_KRB5 */

	/* Determine the realm */

#if defined(USE_KRB5)
	if (rc = get_krb5_realm(k5_context, realm, &arg->emsg))
#else
	if (rc = get_krb4_realm(realm, &arg->emsg))
#endif
	{
/*		log_printf("getcert: failed to determine kerberos realm information (%d)\n", rc); */
/*		arg->emsg = "Failed to determine kerberos realm information.\n"; */
/*		rc = KX509_STATUS_CLNT_BAD; */
		goto Failed;
	}

#ifdef WIN32
#if defined(USE_KRB5)
	{
		krb5_timestamp		currTGTtime = get_tgt_time(k5_context);
		krb5_timestamp		currTGTlife = get_tgt_life(k5_context);
		krb5_timestamp		currTime = time(0);


		if ((currTGTlife - currTime) < 5*60)
		{
			arg->emsg = "Tickets are dead or soon to be.  Please re-authenticate.";
			rc = KX509_STATUS_CLNT_BAD;
			goto Failed;
		}

		/* Check if current TGT was found to be stale */

		if (staleTGTtime && (staleTGTtime == currTGTtime))
		{
			arg->emsg = "Bad time zone or time.  "
					"  Correct and re-authenticate.";
			rc = KX509_STATUS_CLNT_BAD;
			goto Failed;
		}
	}
#endif /* USE_KRB5 */
#endif /* WIN32 */

	/* CLEAN OUT OLD CERTS  */
 
#ifdef WIN32
	minLeft = certLife(realm);
	if (minLeft <= 0)	
		clean_cert_store(realm);
#endif /* WIN32 */

	/*
	 * We use one of two ways to determine the hostname(s) of the KCA server(s):
	 *
	 *
	 *	1.  if the KCA_HOST_LIST environment variable is defined,
	 *		we simply use the list of hostname(s) defined there
	 *
	 *	2.  otherwise, we *assume* that the KCA servers can be
	 *		reached by resolving the hostname(s) that Kerberos
	 *		expects the KDC to be at for a given base_realm as
	 *		specified in /etc/krb.conf
	 *
	 *		(note: for the "ENGIN.UMICH.EDU" realm,
	 *		       "UMICH.EDU" is used for base_realm)
	 */

	/* DNS SRV records should obviate need for ENGIN->UMICH mapping */
	base_realm = realm;

	/* Use environment variable first, otherwise use list from DNS */

	if ((env_host_list = getenv("KCA_HOST_LIST")) != NULL)
	{
		char *host;
		int hostcount = 0;
		char *hostlist = NULL;
		char **hostarray = NULL;

		/* Make a copy of the environment string */
		if (strlen(env_host_list)) 
			hostlist = malloc(strlen(env_host_list) + 1);
		if (hostlist)
			strcpy(hostlist, env_host_list);
		else
		{
			rc = KX509_STATUS_CLNT_BAD;
			arg->emsg = "Empty KCA_HOST_LIST environment variable or malloc error";
			goto Failed;
		}

		hostarray = calloc(MAX_KCA_HOSTS + 1, sizeof(char *));

		if (hostarray)
		{

			/* Separate the hosts in the list and keep an array of pointers */
			host = strtok(hostlist, " ");
			while (host != NULL && *host != '\0')
			{
				hostarray[hostcount++] = host;
				host = strtok(NULL, " ");
			}
		}
		else
		{
			rc = KX509_STATUS_CLNT_BAD;
			arg->emsg = "Error allocating array for KCA_HOST_LIST";
			goto Failed;
		}

		if (hostcount <= 0)
		{
			rc = KX509_STATUS_CLNT_BAD;
			arg->emsg = "Empty KCA_HOST_LIST environment variable or tokenize error";
			goto Failed;
		}

		kca_hostlist = hostarray;
	} else {
		if (get_kca_list(base_realm, &dns_hostlist))
		{
			rc = KX509_STATUS_CLNT_BAD;
			arg->emsg = "DNS SRV lookup of KCA hostname(s) failed!";
			goto Failed;
		}
		else
			kca_hostlist = dns_hostlist;
	}

	/* CREATE SOCKET TO BIND TO CA SERVER */

	if ((socket=udp_nb_socket(0)) == -1)
	{
#ifdef macintosh
		err = GetMITLibError();
		if (GetErrorLongFormat(err, buffer, sizeof(buffer)) == noErr) {
			log_printf("try_ca: udp_nb_socket failed to obtain a socket ('%s')\n",
				buffer);
		}
#else /* !macintosh */
		log_printf("try_ca: udp_nb_socket failed to obtain a socket ('%s')\n",
			strerror(errno));
#endif /* macintosh */
		arg->emsg = "Failed to create a socket.\n";
		rc = KX509_STATUS_CLNT_TMP;
		goto Failed;
	}

	/* ITERATE THROUGH LIST OF KCA HOSTNAMES */

	for (n=0; kca_hostlist[n]; )
	{
		int e;

		strcpy(ca_hostname_to_try, kca_hostlist[n++]);

		/* Exit the loop as soon as we get a good response */
#if defined(USE_KRB5)
		if (!(rc = try_ca(k5_context, socket, ca_hostname_to_try,
				realm, rsa, certp, verify_recvd_packet,
				(void*)arg, arg->sess_key, &arg->sess_len,
#if defined(KX509_LIB)
				tkt_cache_name,
#endif
				&arg->emsg, &e)))
#else
		if (!(rc = try_ca(socket, ca_hostname_to_try,
				realm, rsa, certp, verify_recvd_packet,
				(void*)arg, arg->sess_key, &arg->sess_len, &arg->emsg, &e)))
#endif
			break;
		else
		{
			log_printf("try_ca to '%s' returned rc %d, ecode %d, emsg '%s'\n",
				ca_hostname_to_try, rc, e, arg->emsg);
		}
	}
	if (!n)
	{
		rc = KX509_STATUS_CLNT_BAD;
		arg->emsg = "Error!  Unable to determine KCA hostname(s)!";
	}
	if (arg->emsg)
		log_printf("%s\n", arg->emsg);


Failed:
	if (socket != -1)
	{
#ifdef WIN32
		(void)closesocket(socket);
#else /* !WIN32 */
		(void)close(socket);
#endif /* !WIN32 */
		socket = -1;
	}

#ifndef USE_MSK5
#if 1 /* BILLDO 2004.0305 -- Only krb5_init_context once per process */
#else /* !1 */
	if (k5_context)
	{
		(*pkrb5_free_context)(k5_context);
		k5_context = NULL;
	}
#endif /* !1 */
#endif /* ! USE_MSK5 */

	if (!dns_hostlist && kca_hostlist)
	{
		free(kca_hostlist);
		kca_hostlist = NULL;
	}
	if (rc)
	{
		if (*rsa)
		{
			RSA_free(*rsa);
			*rsa = NULL;
		}
		if (*certp)
		{
			X509_free(*certp);
			*certp = NULL;
		}
	}

	if (dns_hostlist != NULL)
	{
		Free(dns_hostlist);
		dns_hostlist = NULL;
	}

	if (strlen(gszHardErrorMsg))
	{
		strncpy(emsg, gszHardErrorMsg, elen);
		emsg[elen-1] = '\0';
		rc = KX509_STATUS_CLNT_FIX;
	}
	else if (rc)
	{
		if (!arg->emsg || !*arg->emsg)
			arg->emsg = "Missing error message #1";
		strncpy(emsg, arg->emsg, elen);
		emsg[elen-1] = '\0';
	}
	else if (!arg->response || (rc = arg->response->status))
	{
		if (!arg->response || arg->response->error_message)
		{
			log_printf ("status %d; response had error message; contents were:\n", rc);
#ifdef DEBUG
			if (arg->response)
				bin_dump((char *)arg->response->error_message->data, arg->response->error_message->length);
#endif
		} else {
			log_printf ("status %d; response no longer has error message\n", rc);
		}
		if (!arg->response || !arg->response->error_message
		|| !arg->response->error_message->length)
			strncpy(emsg, "Missing error message #2", elen);
		else {
			if (arg->response->error_message->length > (elen-1))
				arg->response->error_message->length = elen-1;
			memcpy(emsg,
				arg->response->error_message->data,
				arg->response->error_message->length);
			emsg[arg->response->error_message->length] = 0;
		}
	} else if (arg->response->certificate) {
		tmp_ptr = arg->response->certificate->data;
		if (!(*certp = d2i_X509(NULL, &tmp_ptr,
			arg->response->certificate->length)))
		{
			strncpy(emsg, "getcert: d2i_X509 failed", elen);
			rc = KX509_STATUS_CLNT_BAD;
		}
	} else {
		strncpy(emsg, "getcert: missing certificate", elen);
		rc = KX509_STATUS_CLNT_BAD;
	}

	KX509_RESPONSE_free(arg->response);
	arg->response = NULL;

	log_printf("dns_hostlist  = 0x%8X\n", dns_hostlist);
	log_printf("kca_hostlist  = 0x%8X\n", kca_hostlist);
	log_printf("base_realm    = 0x%8X\n", base_realm);
	log_printf("env_host_list = 0x%8X\n", env_host_list);
	log_printf("tmp_ptr       = 0x%8X\n", tmp_ptr);

	return rc;
}

#ifdef DEBUG

/*
 *=========================================================================*
 *
 * print_response()
 *
 *=========================================================================*
 */
void print_response(KX509_RESPONSE *client_response)
{
	log_printf ("response status %d\n", client_response->status);
	if (client_response->certificate)
	{
		log_printf ("response certificate:\n");
		bin_dump((char *)client_response->certificate->data,
			client_response->certificate->length);
	} else log_printf ("no response certificate\n");
		if (client_response->hash)
	{
		log_printf ("response hash:\n");
		bin_dump((char *)client_response->hash->data,
			client_response->hash->length);
	} else log_printf ("no response hash\n");
	if (client_response->error_message)
	{
		log_printf ("response error_message:\n");
		bin_dump((char *)client_response->error_message->data,
			client_response->error_message->length);
	} else log_printf ("no response error_message\n");
	return;
}

/*
 *=========================================================================*
 *
 * print_request()
 *
 *=========================================================================*
 */
void print_request(KX509_REQUEST *server_request)
{
	log_printf ("request Authenticator:\n");
	bin_dump((char *)server_request->authenticator->data,
		server_request->authenticator->length);
	log_printf ("request hash:\n");
	bin_dump((char *)server_request->hash->data,
		server_request->hash->length);
	log_printf ("request pkey:\n");
	bin_dump((char *)server_request->pkey->data,
		server_request->pkey->length);
#ifdef KX509_CLIENT_VERSION_IN_REQUEST
	if (server_request->client_version)
	{
		log_printf ("request client_version:\n");
		bin_dump((char *)server_request->client_version->data,
			server_request->client_version->length);
	}
#endif /* KX509_CLIENT_VERSION_IN_REQUEST */
}

/*
 *=========================================================================*
 *
 * bin_dump()
 *
 *=========================================================================*
 */
bin_dump(char *cp, int s)
{
	char *buffer;
	char c;
	int w;
	int i;
	long o;

	o = 0;
	buffer = cp;
	while (s > 0)
	{
		c = 16;
		if (c > s) c = s;
		log_printf ("%06lx:", o);
		w = 0;
		for (i = 0; i < c/2; ++i)
			w += 5, log_printf (" %4x", ((unsigned short *)buffer)[i]);
		if (c & 1)
			w += 3, log_printf (" %2x", buffer[c-1]);
		while (w < 41)
			++w, log_printf(" ");
		for (i = 0; i < c; ++i)
			if (isprint(buffer[i]))
				log_printf("%c", buffer[i]);
			else
				log_printf(".");
		log_printf("\n");
		o += c;
		buffer += c;
		s -= c;
	}
	log_printf ("%06lx:\n", o);
	return 1;
}
#endif
