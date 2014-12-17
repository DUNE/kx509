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

#if defined(USE_KRB4)

/*
 * store_tkt.c -- use K4 ticket file as place to hold RSA key-pair & 1-day X.509 cert
 */

#include <stdio.h> 
#include <errno.h> 
#include <string.h> 
#include <fcntl.h> 

#ifndef macintosh
# include <sys/types.h> 
#endif /* !macintosh */

#include <openssl/rand.h>
#include <openssl/x509v3.h> 
#include <openssl/pem.h> 

#ifndef linux
# define DES_DEFS
#endif /* !linux */

#ifdef macintosh
# include <KClient.h>
# include "tf_util.h"
# include "kx509.h"
# define TKT_FILE "tktfile"
# define R_TKT_FIL 0
# define W_TKT_FIL 1
#else /* !macintosh */
# include "des-openssl-hack.h"
# include <krb.h>
#endif /* macintosh */

#include "kx509.h"
#include "store_tkt.h"
#include "debug.h" 
 
int store_tkt(RSA *key, BYTE *cert, DWORD cert_length, char *realm, char **err_msg)
{
    C_Block		fake_session_key;
    int			lifetime=0;
    int			kvno=1;
    MOCK_KTEXT_ST	munged_ticket;
    BYTE		*der_ptr=&munged_ticket.data[0];
    long		issue_date=time(0);
    DWORD		key_length;
    DWORD		munge_length;
    int			rc;


    key_length = i2d_RSAPrivateKey (key, &der_ptr); 

    munge_length = sizeof(DWORD) + key_length + sizeof(DWORD) + cert_length;
    if (MAX_KTXT_LEN < munge_length)
    {
	log_printf("store_tkt: sizeof(DWORD + key-pair + DWORD + cert) > MAX_KTXT_LEN: %0d\n",
			MAX_KTXT_LEN);
	*err_msg = "Try re-authenticating.  Somehow the combination of your private key and cert is too large.";
	return KX509_STATUS_CLNT_FIX;
    }
    memcpy(der_ptr, cert, cert_length);

    munged_ticket.length	= munge_length;
    munged_ticket.key_length	= key_length;
    munged_ticket.cert_length	= cert_length;
    munged_ticket.mbz		= 0;

    if ((rc = tf_init(TKT_FILE, W_TKT_FIL)) != KSUCCESS)
    {
	log_printf("store_tkt: tf_init returned %0d\n", rc);
#ifdef macintosh
	*err_msg = "Try quitting Netscape.  Unable to get write access to your Kerberos ticket file.";
#else /* !macintosh */
	*err_msg = "Try re-authenticating.  Unable to get write access to your Kerberos ticket file.";
#endif /* macintosh */
	return KX509_STATUS_CLNT_FIX;
    }

    rc = tf_save_cred(  KX509_PRINC, KX509_INST, realm,
			fake_session_key, lifetime, kvno,
			(KTEXT_ST *)&munged_ticket, issue_date);
			
    tf_close();

    if (KSUCCESS != rc)
    {
	log_printf("store_tkt: tf_save_cred returned %0d\n", rc);
	*err_msg = "Try re-authenticating.  Currently unable to write your Kerberos ticket file.";
	return KX509_STATUS_CLNT_FIX;
    }

    return KX509_STATUS_GOOD;
}


#endif	/* USE_KRB4 */
