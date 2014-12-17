/*
 * Portions of this code:
 *
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

#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <krb5.h>

#include "kx509.h"
#include "debug.h" 
int debugPrint;					/* Defined in debug.c */

char *output_file_flag;			/* Defined in kx509.c */
char *oflag;
BIO *ofile;
#if defined(USE_KRB5)
char *progname;
#endif

int quietPrint;					/* extern defined in kx509.c */

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


krb5_error_code materialize_cert(  
     krb5_context     k5_context,  
     krb5_ccache      cc,
     krb5_creds *     creds)

{
	char *cp;
	char proxyname[64];

	RSA		*rsa=NULL; 
	BIO		*STDout = BIO_new_fp(stdout,BIO_NOCLOSE);
	X509		*cert=NULL; 

	char buffer[2048];
	int code;

	krb5_error_code	k5_rc = 0;
	unsigned char * p;
	unsigned int    cert_length;
 	unsigned int    key_length;

	if (output_file_flag != NULL)
	{
		oflag = output_file_flag;		/* Output file spec from -o option */
	}
	else if (!(oflag = getenv("X509_USER_PROXY")))
	{
		sprintf(proxyname,"/tmp/x509up_u%d",getuid());
		oflag = proxyname;
	}

	if (debugPrint)
	{
		printf( "Output file is %s\n", oflag);
	}

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

#define KX509_CC_PRINCIPAL  "kx509"
#define KX509_CC_INSTANCE   "certificate"

	key_length = creds->ticket.length;
	p = (unsigned char *) creds->ticket.data;

	rsa = 0;
	d2i_RSAPrivateKey(&rsa,&p,key_length);
	if (!rsa)
	{
		printf ("service ; can't convert rsa key\n");
		bin_dump( (char*) p, key_length);
	}

	cert_length = creds->second_ticket.length;
	p = (unsigned char *) creds->second_ticket.data;


	d2i_X509(&cert,&p,cert_length);
	if (!quietPrint)
		{
		printf ("Service %s/%s\n", KX509_CC_PRINCIPAL, KX509_CC_INSTANCE);
		}

	X509_NAME_oneline(X509_get_issuer_name(cert),buffer, sizeof buffer);
	if (!quietPrint)
		{
		printf (" issuer= %s\n", buffer);
		}

	X509_NAME_oneline(X509_get_subject_name(cert),buffer, sizeof buffer);
	if (!quietPrint)
		{
		printf (" subject= %s\n", buffer);
		printf (" serial=");
		}

	if (!quietPrint)
		{
		i2a_ASN1_INTEGER(STDout,cert->cert_info->serialNumber);
		printf ("\n");
		printf (" hash=%08lx\n", X509_subject_name_hash(cert));
		}

	if (ofile)
	{
		PEM_write_bio_X509(ofile,cert);
		PEM_write_bio_RSAPrivateKey(ofile,rsa,NULL,NULL,0,NULL,NULL);
	}
	if (STDout) 
	{
		BIO_free(STDout);
		STDout = NULL;
	}

	if (ofile)
	{
		BIO_free(ofile);
		ofile = NULL;
	}

	return 0;
}
