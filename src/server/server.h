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

#ifndef _KX509_SERVER_H_
#define _KX509_SERVER_H_ 1

/*
 * server.h
 */

#if defined(USE_KRB5)
#include <sys/param.h>
#include <krb5.h>
#if defined(HAVE_HEIMDAL)
#define KRB5_PVNO	5
#endif
#endif

/*
 * These are just the default values.
 * The "right" way to set all of these is via the configuration file.
 * We'll use billdo's configuration for now...
 */
#define	KRBCHK_PORT	9878
#define NETBUFLEN  	1024 

#define	CA_PRINC	"cert"
#define	CA_INST		"x509"

#if defined(USE_KRB5)
#define KEYTAB		"/var/kca/kca_service.keytab"
#endif
#define	SRVTAB		"/etc/srvtab.keysigner"
#define	SRVTAB_ENGIN	"/etc/srvtab.keysigner.ENGIN"

#if 0
#define SERIAL_NUMBER_FILE	"/var/https-1.3.6/test/ssl/kca_serial"
#else
#define SERIAL_NUMBER_FILE	"/var/https/test/ssl/kca_serial"
#endif
#define DEF_DAYS	1

#define DEFAULT_SERVER_CERTIFICATE "/var/kca/conf/kca.crt"
#define DEFAULT_SERVER_KEYFILE "/var/kca/conf/kca.key"

#define DEFAULT_CONFIG_FILE "/var/kca/kca.cnf"
#define DEFAULT_LOG_FILE "/var/kca/kca.log"

#define DEFAULT_EMAIL_DOMAIN "$AUTHENTICATOR_REALM$"

extern int	kca_port;
extern char	kca_princ[];
extern char	kca_inst[];

#if defined(USE_KRB5)
extern char		*keytab;
extern krb5_context	k5_context;
extern krb5_keytab	k5_keytab;
extern char		keytab_string[MAXPATHLEN];
#endif

extern char	*srvtab;
extern char	*srvtab_engin;
extern char	*serial_number_file;

extern int	single_process;
extern char	*pn;			/* program name */
extern char	*config_file;
/* extern LHASH	*kx509_config; */

struct request {
	int version;

	struct r_v2 {
		KX509_REQUEST	*request;
	} v2;

	int		krb_prot_version;	/* Kerberos protocol version (4, 5, other?) */

#if defined(USE_KRB4)
	/* request */
	KTEXT_ST	authent;
	AUTH_DAT	ad;
#endif
#if defined(USE_KRB5)
	krb5_data	k5_authent;
	krb5_ticket	*k5_ticket;
        char		*k5_client_string;
	krb5_data	*k5_client;
	krb5_auth_context k5_auth_context;
#endif
	int ad_is_valid;
	EVP_PKEY *pubkey;

	/* response */
	X509 *cert;

	/* log data */
	char caller_name[512];	/* "from X.X.X.X portno v1 kname.@R" */

	/* error handling */
	char	*err_msg;
	int	err_code;
	char	err_buf[512];
};

int debug_mask;
#define DF(x)	(debug_mask & (1L<<((x-'@'&31))))

/* prototypes for su_util.c */
char *iptos(long a, char *buf);

#endif	/* _KX509_SERVER_H_ */
