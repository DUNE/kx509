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
#include <errno.h> 
#include <string.h> 
#include <fcntl.h> 

#ifndef macintosh
#include <sys/types.h> 
#endif /* !macintosh */

#ifdef WIN32
#define __WINCRYPT_H__
#include <windows.h> 
#include <kerb95.h>
#endif /* WIN32 */

#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#if defined(USE_KRB5)
# include <krb5.h>
#else
# ifndef WIN32
#  ifndef linux
#   define DES_DEFS
#  endif /* !linux */
#  ifdef macintosh
#   include <KClient.h>
#  else /* !macintosh */
#   include "des-openssl-hack.h"
#   include <krb.h>
#  endif /* macintosh */
# endif /* !WIN32 */
#endif	/* USE_KRB5 */

#include "kx509.h"
#if defined(USE_KRB4)
#include "store_tkt.h"
#endif
#include "debug.h" 

char *oflag;
BIO *ofile;
#if defined(USE_KRB5)
char *progname;
#endif

main(int argc, char **argv)
{
	char *argp;
	int didit;
	char *cp;
	char proxyname[64];

#if defined(WRITE_CERT)
	exit(0);
#endif
#if defined(USE_KRB5)
	progname = argv[0];
#endif
	didit = 0;
	while (--argc > 0) if (*(argp = *++argv) == '-')
	if (argp[1]) while (*++argp) switch(*argp)
	{
	case 'o':
		if (argc < 1) goto Usage;
		--argc;
		oflag = *++argv;
		break;
	case 'p':
		if (!(oflag = getenv("X509_USER_PROXY")))
		{
			sprintf(proxyname,"/tmp/x509up_u%d",getuid());
			oflag = proxyname;
		}
		break;
	case '-':
		break;
	default:
		fprintf (stderr, "Bad char <%c>\n", *argp);
	Usage:
		fprintf (stderr,
			"Usage: kxlist [-o cert+key] [-p] [files]...\n");
		exit(1);
	}
	else ++didit, process("-");
	else ++didit, process(argp);
	if (!didit) process(NULL);
	if (ofile)
	{
		BIO_free(ofile);
		ofile = NULL;
	}
	exit(0);
}

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
		printf ("%06lx:", o);
		w = 0;
		for (i = 0; i < c/2; ++i)
			w += 5, printf (" %4x", ((unsigned short *)buffer)[i]);
		if (c & 1)
			w += 3, printf (" %2x", buffer[c-1]);
		while (w < 41)
			++w, putchar(' ');
		for (i = 0; i < c; ++i)
			if (isprint(buffer[i]))
				putchar(buffer[i]);
			else
				putchar('.');
		putchar('\n');
		o += c;
		buffer += c;
		s -= c;
	}
	printf ("%06lx:\n", o);
	return 1;
}

char *iptos(long a, char *buf)
{
	sprintf(buf, "%d.%d.%d.%d",
		(unsigned char) (a>>24),
		(unsigned char) (a>>16),
		(unsigned char) (a>>8),
		(unsigned char) a);
	return buf;
}
 
int process(char *keyfile)
{
	RSA		*rsa=NULL; 
	BIO		*STDout = BIO_new_fp(stdout,BIO_NOCLOSE);
	X509		*cert=NULL; 
#if defined(USE_KRB4)
	char	pname[ANAME_SZ];
	char	pinst[INST_SZ];
	CREDENTIALS c;
#endif
	char buffer[2048];
	int code;

#if defined(USE_KRB5)
	krb5_context	k5_context;
	krb5_ccache	cc;
	krb5_error_code	k5_rc = 0;
	krb5_creds	match_creds;
	krb5_creds	creds;
	unsigned char * p;
	unsigned int    cert_length;
 	unsigned int    key_length;

#if defined(HAVE_HEIMDAL)
	int             retrieve_flags = 0;
#else
	int             retrieve_flags = (KRB5_TC_MATCH_SRV_NAMEONLY);
#endif
#endif

	if (oflag && !ofile)
	{
		int fd;

		//  Try to ensure a safe location for credentials
		fd = open(oflag, O_CREAT|O_EXCL|O_WRONLY, 0600);
		if (fd < 0) {
			if (errno != EEXIST) {
				perror("open (first attempt)");
				exit(1);
			}

			if (unlink(oflag)) {
				perror("unlink");
				exit(1);
			}

			fd = open(oflag, O_CREAT|O_EXCL|O_WRONLY, 0600);
			if (fd < 0) {
				perror("open (second attempt)");
				exit(1);
			}
		}
		ofile = BIO_new_fd(fd, BIO_CLOSE);
		if (!ofile) {
			perror("BIO_new_fd failed");
			exit(1);
		}
	}
#if defined(USE_KRB5)

#define KX509_CC_PRINCIPAL  "kx509"
#define KX509_CC_INSTANCE   "certificate"

	memset(&match_creds, '\0', sizeof(match_creds));
	if (k5_rc = krb5_init_context(&k5_context))
	{
		com_err(progname, k5_rc, "initializing K5 context");
		return 0;
	}
	if (k5_rc = krb5_cc_default(k5_context, &cc))
	{
		com_err(progname, k5_rc, "while resolving default k5 credentials cache");
		return 0;
	}
	if (k5_rc = krb5_cc_get_principal(k5_context, cc, &match_creds.client))
	{
		com_err(progname, k5_rc, "while retrieving primary principal from credentials cache");
		return 0;
	}
#if defined(HAVE_HEIMDAL)
	if (k5_rc = krb5_make_principal(k5_context, &match_creds.server,
		match_creds.client->realm, KX509_CC_PRINCIPAL,
		KX509_CC_INSTANCE, NULL))
#else
	if (k5_rc = krb5_sname_to_principal(k5_context, KX509_CC_INSTANCE,
		KX509_CC_PRINCIPAL, KRB5_NT_UNKNOWN, &match_creds.server ))
#endif
	{
		com_err(progname, k5_rc, "while creating principal structure for server principal");
		return 0;
	}
	
	if (k5_rc = krb5_cc_retrieve_cred(k5_context, cc, retrieve_flags, &match_creds, &creds))
	{
		com_err(progname, k5_rc, "while finding the credentials containing the private key and certificate in the credentials cache");
		return 0;
	}

	key_length = creds.ticket.length;
	p = (unsigned char *) creds.ticket.data;

	rsa = 0;
	d2i_RSAPrivateKey(&rsa,&p,key_length);
	if (!rsa)
	{
		printf ("service ; can't convert rsa key\n");
		bin_dump( (char*) p, key_length);
	}

	cert_length = creds.second_ticket.length;
	p = (unsigned char *) creds.second_ticket.data;

#else	/* USE_KRB5 */

	if (!keyfile)
		keyfile = getenv("KRBTKFILE");
	if (!keyfile)
		keyfile = TKT_FILE; 
	printf ("Ticket file: %s\n", keyfile);

	if (code = tf_init(keyfile, R_TKT_FIL))
	{
		perror(keyfile);
		return 0;
	}
	if (tf_get_pname(pname))
	{
		fprintf(stderr,"can't read principal's name\n");
		tf_close();
		return 0;
	}
	if (tf_get_pinst(pinst))
	{
		fprintf(stderr,"can't read principal's instance\n");
		tf_close();
		return 0;
	}
	printf ("Ticket owner: %s.%s\n", pname, pinst);
	while (!(code = tf_get_cred(&c)))
	{
		unsigned int key_length, cert_length;
		unsigned char *p;
		key_length = ((MOCK_KTEXT_ST*)&c.ticket_st)->key_length;
		cert_length = ((MOCK_KTEXT_ST*)&c.ticket_st)->cert_length;
		if (key_length + cert_length >= c.ticket_st.length)
		{
			printf ("service %s.%s; %d+%d >%d\n",
				c.service, c.instance,
				key_length, cert_length, c.ticket_st.length);
			continue;
		}
		p = (unsigned char*) ((MOCK_KTEXT_ST*)&c.ticket_st)->data;
		rsa = 0;
		cert = 0;
		d2i_RSAPrivateKey(&rsa,&p,key_length);
		if (!rsa)
		{
			printf ("service %s.%s; can't convert rsa key\n",
				c.service, c.instance);
			bin_dump( ((MOCK_KTEXT_ST*)&c.ticket_st)->data, key_length);
			continue;
		}
		if (p != ((MOCK_KTEXT_ST*)&c.ticket_st)->data+key_length) {
			printf ("service %s.%s; key was supposed to be %d bytes, but is actually only %d bytes\n",
				c.service, c.instance, key_length,
				p- ((unsigned char*)((MOCK_KTEXT_ST*)&c.ticket_st)->data));
			continue;
		}
#endif /* USE_KRB5 */
		d2i_X509(&cert,&p,cert_length);
#if defined(USE_KRB5)
		printf ("Service %s/%s\n", KX509_CC_PRINCIPAL, KX509_CC_INSTANCE);
#else
		printf ("Service %s.%s\n", c.service, c.instance);
#endif
		X509_NAME_oneline(X509_get_issuer_name(cert),buffer, sizeof buffer);
		printf (" issuer= %s\n", buffer);
		X509_NAME_oneline(X509_get_subject_name(cert),buffer, sizeof buffer);
		printf (" subject= %s\n", buffer);
		printf (" serial=");
		i2a_ASN1_INTEGER(STDout,cert->cert_info->serialNumber);
		printf ("\n");
		printf (" hash=%08lx\n", X509_subject_name_hash(cert));
		if (ofile)
		{
			PEM_write_bio_X509(ofile,cert);
			PEM_write_bio_RSAPrivateKey(ofile,rsa,
				NULL,NULL,0,NULL,NULL);
		}
#if !defined(USE_KRB5)
	}
#endif
	if (STDout) 
	{
		BIO_free(STDout);
		STDout = NULL;
	}
	return 1;
}
