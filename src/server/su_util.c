/*
 * Copyright  ©  2000,2002,2007
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
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef linux		/* XXX need better logic... */
#include "e_os.h"
#endif
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#if 1
#include "dla3.h"
#endif
#ifdef linux
#define MS_STATIC	/* XXX who defines this? */
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/conf.h>

#if defined(USE_KRB4)
#ifndef DES_DEFS
#define DES_DEFS 1
#endif
#include "../lib/des-openssl-hack.h"
#include <krb.h>
#endif

#include "kx509.h"
#include "kx509_asn.h"
#include "server.h"
#include "kca_ext.h"


#ifndef TRUE
#define TRUE  1
#endif

/* default configuration */
int kca_port = KRBCHK_PORT;
#if defined(USE_KRB4)
char kca_princ[ANAME_SZ] = CA_PRINC, kca_inst[INST_SZ] = CA_INST;
char *srvtab = SRVTAB;
char *srvtab_engin = SRVTAB_ENGIN;
#endif
#if defined(USE_KRB5)
char *keytab = KEYTAB;
#endif
char *CAserial = SERIAL_NUMBER_FILE;
int def_days = DEF_DAYS;
char *CAfile	= 0;
char *CAkeyfile	= 0;
char *config_file = 0;
char *kca_extensions = 0;
char *default_client_version = 0;
char *email_domain = DEFAULT_EMAIL_DOMAIN;
char *logfile_name = DEFAULT_LOG_FILE;
int serial_number_increment = 1;

#if defined(USE_KRB5)
/* Define this global storage here... */
krb5_context k5_context;
char keytab_string[MAXPATHLEN];
krb5_keytab k5_keytab;
#endif

LHASH   *kx509_config;


#define KX509_SECTION "kx509"
#define CA_SECTION "ca"
#define ENV_DEFAULT_CA "default_ca"

/*
 * Signal handling routine.  Sets the flag to indicate
 * that a HUP signal needs processing when appropriate.
 */
volatile int need_hup_processing = 0;
void process_hup(int signum)
{
	need_hup_processing = 1;
	return;
}


/* routine to avoid panics from printing NULL strings */
static char* pstr(char *p)
{
	if (p == NULL)
		return "<NULL>";

	return p;
}


/*
 * set_serial_number -- sets the serial number in a given X509 structure.
 * Reads the current value from a file and sets that within the X509
 * structure.  Increments the number by the proper number and writes
 * the new value back to the file.
 */

static int set_serial_number(X509 *cert)
{
	BIO *io = NULL;
	BIGNUM *serial = NULL;
	ASN1_INTEGER *this_sn = NULL, *next_sn = NULL;
	MS_STATIC char buf2[1024];

	int retval = -1;	/* Assume failure */

	serial = BN_new();
	this_sn = ASN1_INTEGER_new();
	if ((serial == NULL) || (this_sn == NULL))
	{
		elcprintf("next_serial_number: failed to get BIGNUM (0x%08x) "
			  "or ASN1_INTEGER (0x%08x)\n", serial, this_sn);
		goto SETSN_ERROR;
	}

	io = BIO_new(BIO_s_file());
	if (io == NULL)
	{
		elcprintf("next_serial_number: BIO_new error\n");
		goto SETSN_ERROR;
	}
	if (BIO_read_filename(io, CAserial) <= 0)
	{
		elcprintf("next_serial_number: could not read serial number from '%s'\n",
			CAserial);
		goto SETSN_ERROR;
	}
	if (!a2i_ASN1_INTEGER(io, this_sn, buf2, sizeof(buf2)))
	{
		elcprintf("next_serial_number: unable to load serial number from '%s'\n",
			CAserial);
		goto SETSN_ERROR;
	}
	serial=BN_bin2bn(this_sn->data, this_sn->length, serial);
	if (serial == NULL)
	{
		elcprintf("next_serial_number: error converting bin to BIGNUM\n");
		goto SETSN_ERROR;
	}

	if (!BN_add_word(serial, serial_number_increment))
	{
		elcprintf("next_serial_number: error incrementing serial number by %d\n",
			serial_number_increment);
		goto SETSN_ERROR;
	}

	if (!(next_sn = BN_to_ASN1_INTEGER(serial, NULL)))
	{
		elcprintf("next_serial_number: error converting new serial number to ASN1_INTEGER\n");
		goto SETSN_ERROR;
	}

	if (BIO_write_filename(io, CAserial) <= 0)
	{
		elcprintf("next_serial_number: error writing new serial number to '%s'\n",
			CAserial);
		goto SETSN_ERROR;
	}

	i2a_ASN1_INTEGER(io, next_sn);
	BIO_puts(io, "\n");
	BIO_free(io);
	io = NULL;

	if (!X509_set_serialNumber(cert, this_sn)) {
		elcprintf("next_serial_number: error setting serial number in cert\n");
		goto SETSN_ERROR;
	}

	retval = 0;	/* What do you know?  We succeeded! */

    SETSN_ERROR:
	if (serial)
		BN_free(serial);
	if (this_sn)
		ASN1_INTEGER_free(this_sn);
	if (next_sn)
		ASN1_INTEGER_free(next_sn);
	if (io)
		BIO_free(io);
	return retval;
}


/*
 * return RSA Key Pair (EVP_PKEY) loaded from given PEM-encoded file (*.key)
 */

static EVP_PKEY *load_key(char *file)
{
	EVP_PKEY *pkey=NULL;
	BIO *key;

	if ( (key=BIO_new(BIO_s_file()))
			&& (BIO_read_filename(key, file) > 0))
		pkey=PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

	if (key != NULL)
		BIO_free(key);
	return(pkey);
}

/*
 * return X.509 certificate (X509) loaded from given PEM-encoded file (*.crt)
 */

static X509 *load_cert(char *file)
{
	X509 *x=NULL;
	BIO *cert;

	if ( (cert=BIO_new(BIO_s_file()))
			&& (BIO_read_filename(cert, file) > 0))
		x=PEM_read_bio_X509(cert, NULL, NULL, NULL);

	if (cert != NULL)
		BIO_free(cert);
	return(x);
}



/*
 * Ensure acceptable type for supplied NID
 */

static int req_fix_type(int nid, int *type)
{
	if (nid == NID_pkcs9_emailAddress)
		*type=V_ASN1_IA5STRING;
	if ((nid == NID_commonName) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_challengePassword) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;

	if ((nid == NID_pkcs9_unstructuredName) && (*type == V_ASN1_T61STRING))
		return(0);
	if (nid == NID_pkcs9_unstructuredName)
		*type=V_ASN1_IA5STRING;
	return(1);
}

/*
 * add X509_NAME_ENTRY for given NID (with given value) to given DN (X509_NAME)
 */

static int add_DN_object(X509_NAME *n, char *value, int nid)
{
	X509_NAME_ENTRY *ne=NULL;
	BYTE buf[1024];
	int ret=0;
	int j;

	strcpy((char *)buf, value);

	j=ASN1_PRINTABLE_type(buf, -1);
	if (req_fix_type(nid, &j)
			&& (ne=X509_NAME_ENTRY_create_by_NID(
					NULL, nid, j, buf,  strlen((const char *)buf)))
			&& X509_NAME_add_entry(n, ne, X509_NAME_entry_count(n), 0))
		ret=1;

	if (ne != NULL)
		X509_NAME_ENTRY_free(ne);

	return(ret);
}

#if defined(HAVE_DLF_SUPPORT)
/* global for needed once-only semantics. */
int NID_dlf = NID_undef;
#endif	/* HAVE_DLF_SUPPORT */
int NID_kca = NID_undef;
int NID_client_version = NID_undef;
int NID_server_version = NID_undef;


#if defined(USE_KRB4)

/*
 * TAKEN FROM K5 1.2.1 lib/krb4/lifetime.c (since /usr/um/krb5/1.1.1 lacks it)
 *
 * kca_krb_life_to_time - takes a start time and a Kerberos standard
 * lifetime char and returns the corresponding end time.  There are
 * four simple cases to be handled.  The first is a life of 0xff,
 * meaning no expiration, and results in an end time of 0xffffffff.
 * The second is when life is less than the values covered by the
 * table.  In this case, the end time is the start time plus the
 * number of 5 minute intervals specified by life.  The third case
 * returns start plus the MAXTKTLIFETIME if life is greater than
 * TKTLIFEMAXFIXED.  The last case, uses the life value (minus
 * TKTLIFEMINFIXED) as an index into the table to extract the lifetime
 * in seconds, which is added to start to produce the end time.
 */

#define TKTLIFENUMFIXED 64
#define TKTLIFEMINFIXED 0x80
#define TKTLIFEMAXFIXED 0xBF
#define TKTLIFENOEXPIRE 0xFF
#define MAXTKTLIFETIME  (30*24*3600)    /* 30 days */
#ifndef NEVERDATE
#define NEVERDATE ((unsigned long)-1L)
#endif

static int tkt_lifetimes[TKTLIFENUMFIXED] = {
    38400,				/* 10.67 hours, 0.44 days */ 
    41055,				/* 11.40 hours, 0.48 days */ 
    43894,				/* 12.19 hours, 0.51 days */ 
    46929,				/* 13.04 hours, 0.54 days */ 
    50174,				/* 13.94 hours, 0.58 days */ 
    53643,				/* 14.90 hours, 0.62 days */ 
    57352,				/* 15.93 hours, 0.66 days */ 
    61318,				/* 17.03 hours, 0.71 days */ 
    65558,				/* 18.21 hours, 0.76 days */ 
    70091,				/* 19.47 hours, 0.81 days */ 
    74937,				/* 20.82 hours, 0.87 days */ 
    80119,				/* 22.26 hours, 0.93 days */ 
    85658,				/* 23.79 hours, 0.99 days */ 
    91581,				/* 25.44 hours, 1.06 days */ 
    97914,				/* 27.20 hours, 1.13 days */ 
    104684,				/* 29.08 hours, 1.21 days */ 
    111922,				/* 31.09 hours, 1.30 days */ 
    119661,				/* 33.24 hours, 1.38 days */ 
    127935,				/* 35.54 hours, 1.48 days */ 
    136781,				/* 37.99 hours, 1.58 days */ 
    146239,				/* 40.62 hours, 1.69 days */ 
    156350,				/* 43.43 hours, 1.81 days */ 
    167161,				/* 46.43 hours, 1.93 days */ 
    178720,				/* 49.64 hours, 2.07 days */ 
    191077,				/* 53.08 hours, 2.21 days */ 
    204289,				/* 56.75 hours, 2.36 days */ 
    218415,				/* 60.67 hours, 2.53 days */ 
    233517,				/* 64.87 hours, 2.70 days */ 
    249664,				/* 69.35 hours, 2.89 days */ 
    266926,				/* 74.15 hours, 3.09 days */ 
    285383,				/* 79.27 hours, 3.30 days */ 
    305116,				/* 84.75 hours, 3.53 days */ 
    326213,				/* 90.61 hours, 3.78 days */ 
    348769,				/* 96.88 hours, 4.04 days */ 
    372885,				/* 103.58 hours, 4.32 days */ 
    398668,				/* 110.74 hours, 4.61 days */ 
    426234,				/* 118.40 hours, 4.93 days */ 
    455705,				/* 126.58 hours, 5.27 days */ 
    487215,				/* 135.34 hours, 5.64 days */ 
    520904,				/* 144.70 hours, 6.03 days */ 
    556921,				/* 154.70 hours, 6.45 days */ 
    595430,				/* 165.40 hours, 6.89 days */ 
    636601,				/* 176.83 hours, 7.37 days */ 
    680618,				/* 189.06 hours, 7.88 days */ 
    727680,				/* 202.13 hours, 8.42 days */ 
    777995,				/* 216.11 hours, 9.00 days */ 
    831789,				/* 231.05 hours, 9.63 days */ 
    889303,				/* 247.03 hours, 10.29 days */ 
    950794,				/* 264.11 hours, 11.00 days */ 
    1016537,				/* 282.37 hours, 11.77 days */ 
    1086825,				/* 301.90 hours, 12.58 days */ 
    1161973,				/* 322.77 hours, 13.45 days */ 
    1242318,				/* 345.09 hours, 14.38 days */ 
    1328218,				/* 368.95 hours, 15.37 days */ 
    1420057,				/* 394.46 hours, 16.44 days */ 
    1518247,				/* 421.74 hours, 17.57 days */ 
    1623226,				/* 450.90 hours, 18.79 days */ 
    1735464,				/* 482.07 hours, 20.09 days */ 
    1855462,				/* 515.41 hours, 21.48 days */ 
    1983758,				/* 551.04 hours, 22.96 days */ 
    2120925,				/* 589.15 hours, 24.55 days */ 
    2267576,				/* 629.88 hours, 26.25 days */ 
    2424367,				/* 673.44 hours, 28.06 days */ 
    2592000};				/* 720.00 hours, 30.00 days */ 

unsigned long kca_krb_life_to_time(unsigned long start, int life)
{
    life = (unsigned char) life;
    if (life == TKTLIFENOEXPIRE) return NEVERDATE;
    if (life < TKTLIFEMINFIXED) return start + life*5*60;
    if (life > TKTLIFEMAXFIXED) return start + MAXTKTLIFETIME;
    return start + tkt_lifetimes[life - TKTLIFEMINFIXED];
}

#endif	/* USE_KRB4 */

int
do_CA(struct request *r, char *uniqname, char *realm)
{
	RSA *rsa=NULL;
	EVP_CIPHER *enc=NULL;
	EVP_PKEY *CApkey=NULL;
	EVP_MD *digest=EVP_md5();
	ASN1_OCTET_STRING *str;
	X509 *cert;
	X509 *CAcertificate;
	BUF_MEM *mem;

	char fullname[256];
	char emailaddr[256];
	char *inrand=NULL;
	char *outfile=NULL;
	char *crtfile=NULL;
	char *randfile=NULL;
	char *keyfile=NULL;
	char *infile = NULL;

	DWORD f4=RSA_F4;

/*
 * From DEE's comments, it seems that the defines below are
 * backwards bit-order from what they should be: i.e. 0x01 should be 0x80
 * and 0x80 should be 0x01...
 */

#define NS_CERT_TYPE_SSL_CLIENT_AUTH	0x01
#define NS_CERT_TYPE_SSL_SERVER_AUTH	0x02
#define NS_CERT_TYPE_SMIME_CLIENT	0x04
#define NS_CERT_TYPE_OBJECT_SIGN	0x08
#define NS_CERT_TYPE_RESERVED		0x10
#define NS_CERT_TYPE_SSL_CA		0x20
#define NS_CERT_TYPE_SMIME_CA		0x40
#define NS_CERT_TYPE_OBJECT_SIGN_CA	0x80

	BYTE ntype = 0xC0;	/* DEE want ssl client and server */
	BYTE bscrit = 1;	/* basic constraint should be critical */
	BYTE nscrit = 0;	/* netscape constraint is not critical */

	int data_type;
	int nid;
	BYTE *p;
	long l;
	int err_code;
	int n;
	int i;


	dprintf(DF('c'), "do_CA entered\n");

	if (!(CAcertificate = load_cert(CAfile)))
	{
		elcprintf( "*** can't load certificate from file <%s>!\n",
			CAfile);
		r->err_msg = "KCA server-side problem -- unable to load CA certificate";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	if ((CApkey=load_key(CAkeyfile)) == NULL)
	{
		elcprintf( "*** can't load private key from file <%s>!\n",
			CAkeyfile);
		r->err_msg = "KCA server-side problem -- unable to load CA private key";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	if (!X509_check_private_key(CAcertificate, CApkey))
	{
		elcprintf( "*** certificate from file <%s> and key from file <%s> do not match!\n",
			CAfile, CAkeyfile);
		r->err_msg = "KCA server-side problem -- CA private key and certificate do not match";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	err_code = KX509_STATUS_GOOD;

	if ((cert=X509_new()) == NULL)
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to allocate new cert";
		err_code = KX509_STATUS_SRVR_TMP;
		goto end;
	}

	/* Make it a V3 certificate */
	X509_set_version(cert, 2);

	if (set_serial_number(cert) != 0) {
		r->err_msg = "KCA server-side problem -- do_CA error setting serial number";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	X509_set_issuer_name(cert, X509_get_subject_name(CAcertificate));

	/* fill in <subject> with CA name + supplied commonName */
	/*   using issuer's dn as prefix for subject's dn */
	{
		X509_NAME_ENTRY	*dn_sub_ptr = NULL;
#define		MAX_VAL_SIZE	1024
		int		dn_sub = 0;

		while (dn_sub < cert->cert_info->issuer->entries->num)
		{
			dn_sub_ptr = (X509_NAME_ENTRY *)
					cert->cert_info->issuer->
						entries->data[dn_sub];

			nid = OBJ_obj2nid(dn_sub_ptr->object);

			/* Change type of CN portion to OU for subject */
			if (nid == NID_commonName)
				nid = NID_organizationalUnitName;

			if (dn_sub_ptr->value->length > MAX_VAL_SIZE)
			{
				r->err_msg = "KCA server-side problem -- compenent of CA DN is too large";
				err_code = KX509_STATUS_SRVR_BAD;
				goto end;
			}

			if (!add_DN_object(cert->cert_info->subject,
					   (char *)dn_sub_ptr->value->data, nid))
			{
				r->err_msg = "KCA server-side problem -- do_CA unable to set base subject name";
				err_code = KX509_STATUS_SRVR_BAD;
				goto end;
			}

			dn_sub++;
		}
	}
#if defined(HAVE_LDAP_LOOKUP)
	/*
	** use X.500 to translate Uniqname to "fullname"
	*/
	dprintf(DF('c'), "Using X.500 to map uniqname to fullname\n");
	get_cn(uniqname, fullname);
	if (!strlen(fullname))
	{
	    dprintf(DF('c'), "failed to use X.500 to map uniqname to fullname\n");
#if 0
	    r->err_msg = "KCA server-side problem -- do_CA unable to use uniqname to retrieve subject's full name from X.500";
	    err_code = KX509_STATUS_SRVR_TMP;
	    goto end;
#else
	    strcpy(fullname, "X.500 down -- no fullname available");
#endif
	}
#else	/* HAVE_LDAP_LOOKUP */
	strcpy(fullname, uniqname);
#endif	/* HAVE_LDAP_LOOKOP */

#if defined(HAVE_UMID_LOOKUP)
	/*
	** use uniqname server to append UMID (8-digits from ID card) to fullname
	*/
	dprintf(DF('c'), "Using uniqname to map uniqname to UMID\n");
	strcat(fullname, " (");
	get_umid(uniqname, fullname+strlen(fullname));
	if (fullname[strlen(fullname)] == '(')
	{
		elcprintf("failed to use Uniqame server to map uniqname to 8-digit UMID\n");
		r->err_msg = "KCA server-side problem -- do_CA unable to use uniqname to retrieve subject's UMID from ID Card database";
		err_code = KX509_STATUS_SRVR_TMP;
		goto end;
	}
	strcat(fullname, ")");
	dprintf(DF('c'), "mapped uniqname '%s' to fullname '%s'\n",
		uniqname, fullname);
#endif	/* HAVE_UMID_LOOKUP */

	nid=OBJ_txt2nid("commonName");
	if (!add_DN_object(cert->cert_info->subject, fullname, nid))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to complete subject's full name";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	/*
	* DEE - add netscape USERID
	*/
	nid=OBJ_txt2nid("userId");
	if (!add_DN_object(cert->cert_info->subject, uniqname, nid))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add subject's UserID";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}


	/*
	 * 990713 BILLDO -- Oops!  Forgot to add emailAddress to subject's DN
	 */

	nid=OBJ_txt2nid("emailAddress");
	/*
	 * 2002.0327 BILLDO -- Default realm to that of authenticator
	 */
	if (!strcmp(email_domain, DEFAULT_EMAIL_DOMAIN))
		sprintf(emailaddr, "%s@%s", uniqname, realm);
	else
		sprintf(emailaddr, "%s@%s", uniqname, email_domain);
	if (!add_DN_object(cert->cert_info->subject, emailaddr, nid))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add subject's emailAddress";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

#if defined(USE_KRB5)
	if (KRB5_PVNO == r->krb_prot_version)
	{
		/* Use the times in the user's ticket to determine certificate lifetime */
		time_t start, end;
		char sc[30], ec[30];

		/* Use the later of now, or the start time in the user's ticket, for start time */
		start = time(0);
#if defined(HAVE_HEIMDAL)
		if (*(r->k5_ticket->ticket.starttime) > start)
			start = *(r->k5_ticket->ticket.starttime);
#else
		if (r->k5_ticket->enc_part2->times.starttime > start)
			start = r->k5_ticket->enc_part2->times.starttime;
#endif

		/* XXX
		 * XXX The non-K5 code below seems to be using 'def_days' as 'max_days',
		 * which isn't necessarily what we want?  (I don't think so anyway!)
		 * I'm using the endtime in the K5 ticket as the end time for the certificate.
		 */
#if defined(HAVE_HEIMDAL)
		end = r->k5_ticket->ticket.endtime;
#else
		end = r->k5_ticket->enc_part2->times.endtime;
#endif

		start -= 24*60*60;	/* Schiller hack */
		strcpy(sc, ctime(&start));
		strcpy(ec, ctime(&end));
		lcprintf("Cert validity times %ld (%.24s) to %ld (%.24s)\n",
			start, sc, end, ec);

		ASN1_UTCTIME_set(X509_get_notBefore(cert), start);
		ASN1_UTCTIME_set(X509_get_notAfter(cert), end);
	}
#if defined(USE_KRB4)
	else
#endif
#endif	/* USE_KRB5 */
#if defined(USE_KRB4)
	if (4 == r->krb_prot_version)
	{
		time_t t1, t2;
		t1 = time(0);				/* current time */
		if ((int)(t1 - r->ad.time_sec) < 0)	/*  unless issued */
			t1 = r->ad.time_sec;		/*  in the future */
		t2 = kca_krb_life_to_time(r->ad.time_sec, r->ad.life);
		if (def_days && t2 > t1+60*60*24*def_days)
			t2 = t1+60*60*24*def_days;
		t1 -= 24*60*60;	/* Schiller hack */
		ASN1_UTCTIME_set(X509_get_notBefore(cert), t1);
		ASN1_UTCTIME_set(X509_get_notAfter(cert), t2);
		{
			char e1[30], e2[30];
			strcpy(e1, ctime(&t1));
			strcpy(e2, ctime(&t2));
			lcprintf("Cert validity times %ld(%.24s) to %ld(%.24s); life=%d\n",
				t1, e1, t2, e2, r->ad.life);
		}
	}
#endif	/* USE_KRB4 */
	else
	{
		r->err_msg = "KCA server-side problem -- invalid Kerberos version";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	X509_set_pubkey(cert, r->pubkey);

	if (kca_extensions)
	{
		X509V3_CTX ctx;

		if (!cert->cert_info->version)
			if (!((cert->cert_info->version = ASN1_INTEGER_new())))
			{
				r->err_msg = "KCA server-side problem -- do_CA unable to set ci->version";
				err_code = KX509_STATUS_SRVR_BAD;
				goto end;
			}
		ASN1_INTEGER_set(cert->cert_info->version, 2); /* version 3 certificate */

		/* Shouldn't be any, but openssl 0.9.5 apps/ca.c does this */
		if (cert->cert_info->extensions)
			sk_X509_EXTENSION_pop_free(cert->cert_info->extensions,
				X509_EXTENSION_free);

		cert->cert_info->extensions = NULL;

		X509V3_set_ctx(&ctx, CAcertificate, cert, NULL, NULL, 0);
		X509V3_set_conf_lhash(&ctx, kx509_config);

		if(!X509V3_EXT_add_conf(kx509_config, &ctx, kca_extensions, cert))
		{
			r->err_msg = "KCA server-side problem -- do_CA unable to add constraints";
			err_code = KX509_STATUS_SRVR_BAD;
			goto end;
		}
#if 1
/* XXX get rid of this: */
	} else {
		X509_EXTENSION *x;

		ASN1_OCTET_STRING *bcons_ext;
		BASIC_CONSTRAINTS bcons = {0, NULL};
		BYTE *bcons_der;
		int bcons_len;

#if defined(HAVE_DLF_SUPPORT)
		ASN1_OCTET_STRING *dlf_ext;
		DLA3_QUERYURL dlf = {NULL};
		BYTE *dlf_der;
		int dlf_len;
		BYTE dlfcrit = 0;	/* dlf extension is NOT critical */

#endif	/* HAVE_DLF_SUPPORT */

	/* ADD GENERATED ENCODING OF BASIC CONSTRAINTS: CA FLAGS & PATHLEN */

	bcons.ca = 0 ;			/* DEE we are not a CA  */
	bcons.pathlen = ASN1_INTEGER_new();
	ASN1_INTEGER_set(bcons.pathlen, 0L);

	bcons_len = i2d_BASIC_CONSTRAINTS(&bcons, NULL);
	bcons_der = malloc(bcons_len);
	p = bcons_der;
	i2d_BASIC_CONSTRAINTS(&bcons, &p);
	ASN1_INTEGER_free(bcons.pathlen);
	bcons_ext = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(bcons_ext, bcons_der, bcons_len);

       	if (!(x = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints,
						bscrit, bcons_ext)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add basic constraints";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}
       	X509_add_ext(cert, x, -1);

       	X509_EXTENSION_free(x);
	free(bcons_der);
       	ASN1_OCTET_STRING_free(bcons_ext);

	/* ADD GENERATED ENCODING OF NETSCAPE CONSTRAINTS: NTYPE (NS CERT TYPE) */

       	str = NULL;
#ifndef OPENSSL
       	data_type = X509v3_data_type_by_NID(NID_netscape_cert_type);
       	X509v3_pack_string(&str, data_type, &ntype, 1);

       	if (!(x = X509_EXTENSION_create_by_NID(NULL, NID_netscape_cert_type,
						nscrit, str)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add netscape_cert_type extension";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}
#else
{
	ASN1_BIT_STRING	*a = ASN1_BIT_STRING_new();
	int i;

	for (i=0; i<8; i++)
		if (1<<i & ntype)
			ASN1_BIT_STRING_set_bit(a, 7-i, 1);

	x = X509V3_EXT_i2d(NID_netscape_cert_type, nscrit, a);
	ASN1_STRING_free(a);
	if (!x)
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add netscape_cert_type extension";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}
}
#endif /* OPENSSL */
       	X509_add_ext(cert, x, -1);

       	X509_EXTENSION_free(x);

#if defined(HAVE_DLF_SUPPORT)
	/* ADD GENERATED ENCODING OF DLA3 QUERY URL */

	if (!(dlf.queryUrl = ASN1_OCTET_STRING_new())
		|| !ASN1_STRING_set(dlf.queryUrl, CURRENTLY_HARDCODED_QUERY_URL,
						strlen(CURRENTLY_HARDCODED_QUERY_URL)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add DLF Query URL";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	dlf_len = i2d_DLA3_QUERYURL(&dlf, NULL);
	dlf_der = malloc(dlf_len);
	p = dlf_der;
	i2d_DLA3_QUERYURL(&dlf, &p);
	dlf_ext = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(dlf_ext, dlf_der, dlf_len);

       	if (!(x = X509_EXTENSION_create_by_NID(NULL, NID_dlf,
						dlfcrit, dlf_ext)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add DLF Query URL";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}
       	X509_add_ext(cert, x, -1);

       	X509_EXTENSION_free(x);
	free(dlf_der);
       	ASN1_OCTET_STRING_free(dlf_ext);
#endif /* HAVE_DLF_SUPPORT */

#if 1 /* KCA AuthRealm extension */
	/* ADD GENERATED ENCODING OF KCA AuthRealm extension */
	{
	ASN1_OCTET_STRING	*kca_ext = NULL;
	KCA_AUTHREALM		kca;
	int			kca_len = 0;
	BYTE			*kca_der = NULL;
	BYTE			kca_crit = 0;

	if (!(kca.authRealm = ASN1_OCTET_STRING_new())
		|| !ASN1_STRING_set(kca.authRealm, realm, strlen(realm)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add KCA AuthRealm extension";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}

	kca_len = i2d_KCA_AUTHREALM(&kca, NULL);
	kca_der = malloc(kca_len);
	p = kca_der;
	i2d_KCA_AUTHREALM(&kca, &p);
	kca_ext = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(kca_ext, kca_der, kca_len);

       	if (!(x = X509_EXTENSION_create_by_NID(NULL, NID_kca,
						kca_crit, kca_ext)))
	{
		r->err_msg = "KCA server-side problem -- do_CA unable to add KCA AuthRealm extension #2";
		err_code = KX509_STATUS_SRVR_BAD;
		goto end;
	}
       	X509_add_ext(cert, x, -1);

       	X509_EXTENSION_free(x);
	free(kca_der);
	ASN1_OCTET_STRING_free(kca.authRealm);
       	ASN1_OCTET_STRING_free(kca_ext);
	}
#endif /* KCA AuthRealm extension */

#if 1 /* KCA ClientVersion extension */
	/* maybe ADD GENERATED ENCODING OF KCA ClientVersion extension */
	if (default_client_version)
	{
		ASN1_OCTET_STRING	*client_version_ext = NULL;
		KCA_VERSION		kca;
		int			kca_len = 0;
		BYTE			*kca_der = NULL;
		BYTE			kca_crit = 0;
		char *client_version;

		if (r->version == KX509_VERSION_2_0
			&& r->v2.request->client_version)
			client_version = (char *)r->v2.request->client_version->data;
		else
			client_version = default_client_version;
dprintf(1, "Ok, default_client_version is <%s>, client_version is <%s>\n",
default_client_version, client_version);

		if (!(kca.Version = ASN1_OCTET_STRING_new())
			|| !ASN1_STRING_set(kca.Version, client_version,
			strlen(client_version)))
		{
			r->err_msg = "KCA server-side problem -- do_CA unable to add KCA ClientVersion extension";
			err_code = KX509_STATUS_SRVR_BAD;
			goto end;
		}

		kca_len = i2d_KCA_VERSION(&kca, NULL);
		kca_der = malloc(kca_len);
		p = kca_der;
		i2d_KCA_VERSION(&kca, &p);
		client_version_ext = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(client_version_ext, kca_der, kca_len);

		if (!(x = X509_EXTENSION_create_by_NID(NULL, NID_kca,
							kca_crit, client_version_ext)))
		{
			r->err_msg = "KCA server-side problem -- do_CA unable to add KCA ClientVersion extension #2";
			err_code = KX509_STATUS_SRVR_BAD;
			goto end;
		}
		X509_add_ext(cert, x, -1);

		X509_EXTENSION_free(x);
		free(kca_der);
		ASN1_OCTET_STRING_free(kca.Version);
		ASN1_OCTET_STRING_free(client_version_ext);
	}
#endif /* KCA ClientVersion extension */

#endif
	}

	/* OK, WE'VE MODIFIED THE CERTIFICATE SO IT WILL HAVE TO BE RE-SIGNED */
	X509_sign(cert, CApkey, digest);

	/* AND, FINALLY, WRITE OUT THE SIGNED CERTIFICATE */
	r->cert = cert;

	err_code = 0;

end:
	if (CAcertificate) X509_free(CAcertificate);
	if (CApkey) EVP_PKEY_free(CApkey);

	return err_code;
}


int
server_init(fd_set *socket_set, int *socket_set_size, int port)
{
	int	rc;
	int	ls;
#if defined(USE_KRB5)
	krb5_error_code k5_rc;
#endif


	FD_ZERO(socket_set);
	*socket_set_size = 0;

#if defined(USE_KRB5)
	if (k5_rc = krb5_init_context(&k5_context))
	{
		elcprintf("Error initializing krb5 context: %d\n", k5_rc);
		return -1;
	}

	sprintf(keytab_string, "FILE:%.*s", sizeof(keytab_string)-6, keytab);
	keytab_string[MAXPATHLEN-1] = '\0';

	if (k5_rc = krb5_kt_resolve(k5_context, keytab_string, &k5_keytab))
	{
		elcprintf("Error resolving keytab file '%s'\n", keytab_string);
		return -1;
	}

#endif

	/* Create the listener socket */
	lcprintf( "Creating Listener socket %d\n", port);
	if (udp_nb_sockets(socket_set, socket_set_size, port))
	{
		elcprintf("Unable to create socket: %s\n",
				 strerror(errno));
		return -1;
	}

	signal(SIGPIPE, SIG_IGN); /* esp. for X.500, but doesn't hurt */

	/* Catch SIG_HUP and process it when appropriate */
	signal(SIGHUP, process_hup);

	return 0;
}

/*
 * return only when sock has something to read...
 *		(used to be TCP-based, but have switched to UDP-based)
 */

int
server_accept(fd_set *socket_set, int *socket_set_size)
{
	int	rc;



	while (TRUE)
	{
		rc = udp_nb_select(socket_set, NULL, NULL, (void *)-1);
		if (rc >= 0)
			break;

		if ((rc == -1) && (errno != EWOULDBLOCK) && (errno != EAGAIN) )
		{
			/* If interrupted, skip the message but still return */
			if (errno != EINTR)
			{
				elcprintf("Failed waiting for UDP "
					  "packet (udp_nb_select): %s\n",
					  strerror(errno));
			}
			return -1;
		}
	}

	dprintf(DF('u'), "\nUDP packet ready\n");

	return 0;
}

void
process_args(int argc, char **argv)
{
	char *argp;
	int didit;
	char *section;
	int argnum;
#if 0
	STACK *attr;
#endif
	long lineno = -1;

	/* store the program's name */
	if (argp = strrchr(argv[0], '/'))
		pn = argp+1;
	else
		pn = argv[0];

	didit = 0;
	while (--argc > 0) if (*(argp = *++argv) == '-')
	if (argp[1]) while (*++argp) switch(*argp)
	{
	case 'c':
		if (argc < 1) goto Usage;
		--argc;
		if (config_file) goto Usage;
		config_file = *++argv;
		break;
	case 'd':	/* print debugging information */
		if (argp[1])
		{
			set_debug_mask(argp+1);
			while (*argp)
				++argp;
		}
		else if (argc < 1)
		{
			fprintf(stderr,"%s: -d: Missing debug level", pn);
			exit(1);
		}
		else
		{
			set_debug_mask (*++argv);
			--argc;
		}
		break;
	case 'm':	/* Use multiple processes */
		single_process = 0;
		break;
	case '-':
		break;
	default:
		fprintf(stderr,"%s: Bad switch <%c>\n", pn, *argp);
	Usage:
		fprintf(stderr,
			"Usage: kca [-dXXX]"
				" [-c config_file] [-m]\n");
		exit(1);
	}
#if 0
	else ++didit, process("-");
	else ++didit, process(argp);
	if (!didit) process(NULL);
#endif

	if (!config_file)
		config_file = DEFAULT_CONFIG_FILE;

	/* SET-UP HOUSE */

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	SSLeay_add_all_algorithms();
	OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
#ifndef OPENSSL
	X509v3_add_netscape_extensions();
	X509v3_add_standard_extensions();
#else
	X509V3_add_standard_extensions();	/* NOTE: the "v" is now UPPER-case */
	/* OPENSSL folded Netscape extensions into standard via v3_nscert */
#endif /* OPENSSL */
#if defined(HAVE_DLF_SUPPORT)
	if (NID_dlf == NID_undef)
		NID_dlf = KCA_add_dlf_extensions();	XXX I bet this does not work.
#endif	/* HAVE_DLF_SUPPORT */
	if (NID_kca == NID_undef)
		NID_kca = KCA_add_kca_extensions();
	if (NID_client_version == NID_undef)
		NID_client_version = KCA_add_client_version();
	if (NID_server_version == NID_undef)
		NID_server_version = KCA_add_server_version();

	kx509_config = CONF_load(kx509_config, config_file, &lineno);
	if (!kx509_config)
	{
		elcprintf("Error loading <%s> at line %d\n", config_file, lineno);
		/* These aren't defaulted otherwise! */
		CAfile = DEFAULT_SERVER_CERTIFICATE;
		CAkeyfile = DEFAULT_SERVER_KEYFILE;
		return;
	}
	section = CONF_get_string(kx509_config, CA_SECTION, ENV_DEFAULT_CA);
	if (!section)
		section = "CA_default";
	/*
	 * At this time we can determine where the log file should go.  Open it up...
	 */
	if (argp = CONF_get_string(kx509_config, section, "logfile_name"))
		logfile_name = argp;

	OpenLogfiles();

	if (argp = CONF_get_string(kx509_config, KX509_SECTION, "server_port"))
	{
		if (sscanf(argp, "%d", &kca_port) != 1)
		{
			fprintf(stderr,
				"%s: config: Can't convert <%s> to int for server_port\n",
				pn, argp);
			exit(1);
		}
	}
#if defined(USE_KRB4)
	if (argp = CONF_get_string(kx509_config, KX509_SECTION, "krbname"))
	{
		char realm[REALM_SZ];
		if (kname_parse(kca_princ, kca_inst, realm, argp) != KSUCCESS)
		{
			fprintf(stderr,
				"%s: config: Can't convert krbname <%s> to ca_princ.ca_inst\n",
				pn, argp);
			exit(1);
		}
	}
	if (argp = CONF_get_string(kx509_config, KX509_SECTION, "srvtab"))
		srvtab = argp;
	if (argp = CONF_get_string(kx509_config, KX509_SECTION, "srvtab_engin"))
		srvtab_engin = argp;
#endif
#if defined(USE_KRB5)
	if (argp = CONF_get_string(kx509_config, KX509_SECTION, "keytab"))
		keytab = argp;
#endif

	if (argp = CONF_get_string(kx509_config, section, "serial"))
		CAserial = argp;

	if (argp = CONF_get_string(kx509_config, section, "sn_increment"))
	{
		if (sscanf(argp, "%d", &serial_number_increment) != 1)
		{
			fprintf(stderr,
				"%s: config: Can't convert <%s> to int for sn_increment\n",
				pn, argp);
			exit(1);
		}
	}

	if (argp = CONF_get_string(kx509_config, section, "x509_extensions"))
		kca_extensions = argp;
	if (kca_extensions)
	{
		/* check syntax of file */
		X509V3_CTX ctx;
		X509V3_set_ctx_test(&ctx);
		X509V3_set_conf_lhash(&ctx, kx509_config);
		if(!X509V3_EXT_add_conf(kx509_config, &ctx, kca_extensions, NULL))
		{
			fprintf(stderr,
				"%s: config: Error Loading extension section <%s>\n",
				pn, kca_extensions);
			ERR_print_errors_fp(stderr);
			ERR_clear_error();
			{
				STACK_OF(CONF_VALUE) *nval; int i;
				X509_EXTENSION *ext;
				CONF_VALUE *val;
				if (!(nval = CONF_get_section(kx509_config, kca_extensions))) {
					fprintf(stderr, "%s: config: no such section\n", pn);
				} else {
					for (i = 0; i < sk_CONF_VALUE_num(nval); ++i)
					{
						val = sk_CONF_VALUE_value(nval, i);
						if (!(ext =  X509V3_EXT_conf(kx509_config, &ctx, val->name, val->value)))
						{
							fprintf(stderr, "X509V3_EXT_conf failed on %s = %s\n",
								val->name, val->value);
						}
					}
				}
			}
			exit(1);
		}
	}

	if (argp = CONF_get_string(kx509_config, section, "default_client_version"))
		default_client_version = argp;

	if (argp = CONF_get_string(kx509_config, section, "default_days"))
	{
		if (sscanf(argp, "%d", &def_days) != 1)
		{
			fprintf(stderr,
				"%s: config: Can't convert <%s> to int for default_days\n",
				pn, argp);
			exit(1);
		}
	}

	if (argp = CONF_get_string(kx509_config, section, "private_key"))
		CAkeyfile = argp;
	if (argp = CONF_get_string(kx509_config, section, "certificate"))
		CAfile = argp;

	if (argp = CONF_get_string(kx509_config, section, "email_domain"))
		email_domain = argp;

	/* private key & certificate default to each other unless
	 * neither is set, in which case we use billdo's defaults.
	 */
	if (!CAkeyfile)
	{
		if (CAfile)
			CAkeyfile = CAfile;
		else
		{
			CAfile = DEFAULT_SERVER_CERTIFICATE;
			CAkeyfile = DEFAULT_SERVER_KEYFILE;
		}
	} else {
		if (!CAfile)
			CAfile = CAkeyfile;
	}
#if 0
/* the server doesn't need to know any random data */
	if (argp = CONF_get_string(kx509_config, section, "RANDFILE"))
		;
	else if (argp = CONF_get_string(kx509_config, NULL, "RANDFILE"))
		;
	if (argp)
	{
RAND_load_file(randfile, "xxx");
	}
#ifdef WINDOWS
	RAND_screen();
#endif
#endif
#if 0
		attr=CONF_get_section(kx509_config, section);
		if (!attr)
#endif
}

int request_count;

void
server_main(fd_set *socket_set, int *socket_set_size,  int (*server_request)() )
{
	fd_set	readfds;
	int	read_set_size;
	int	sock;
	int	i;
	int	n;				/* Memory debug */


	while (TRUE)
	{
		if (need_hup_processing)
		{
			ReopenLogfiles();
			need_hup_processing = 0;
			/* Re-install the signal handler */
			signal(SIGHUP, process_hup);
		}

		memcpy(&readfds, socket_set, sizeof(fd_set));
		read_set_size = *socket_set_size;

		if (server_accept(&readfds, &read_set_size))
			continue;

		sock=-1;
		for (i=0; i<read_set_size; i++)
			if (FD_ISSET(i, &readfds))
			{
				sock=i;
				break;
			}

		if (sock == -1)
			continue;	/* should NOT happen */

		++request_count;


		if (single_process) {
/*			n = fetchseed(1);		 Memory debug */
			(*server_request)(sock);
/*			mcheck(n);			 Memory debug */
		}
		else
			switch ( fork () )
			{
		    		case -1:
					elcprintf(
						"Failed forking\n%s\n",
			    			strerror(errno));
					exit(1);

		    		case 0: /* We're the child process */
/*					n = fetchseed(1);		 Memory debug */
					(*server_request)(sock);
/*					mcheck(n);			 Memory debug */
					break;

		    		otherwise:
					break;

			} /* end of switch */

	}  /* end of while */
}

log_print_caller(char *tag)
{
	logprintf(tag, "kca %d.%d ", getpid(), request_count);
}

#ifdef DEBUG
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
#endif

char *iptos(long a, char *buf)
{
	sprintf(buf, "%d.%d.%d.%d",
		(unsigned char) (a>>24),
		(unsigned char) (a>>16),
		(unsigned char) (a>>8),
		(unsigned char) a);
	return buf;
}

fill_in_octet_string(ASN1_OCTET_STRING *osp, char *st, int len)
{
	char *c;
	if (osp->data && osp->length) Free(osp->data);
	c = Malloc(len);
	memcpy(c, st, len);
	osp->data = (BYTE *)c;
	osp->length = len;
}
