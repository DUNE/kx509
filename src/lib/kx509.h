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

/*
 * kx509.h -- Defines contents of packets exchanged between clients (kx509, webcgi)
 *		and the server (kca)
 */

#ifndef _INCLUDED_KX509_H
#define _INCLUDED_KX509_H
#include "min_types.h"
#include "buf.h"

#define KX509_VERSION_1		0x0100		/* version 1.0 (obsolete) */
#define KX509_VERSION_2_0	0x0200		/* version 2.0 (current) */

#ifdef WIN32
#  if defined(USE_KRB5)
#    if defined(USE_MSK5)
#      define KX509_CLIENT_KRB	"MSK5"	/* Kerberos package for this release of the Windows KX509 */
#    else /* !USE_MSK5 */
#      define KX509_CLIENT_KRB	"KFWK5"	/* Kerberos package for this release of the Windows KX509 */
#    endif /* !USE_MSK5 */
#  else /* !USE_KRB5 */
#      define KX509_CLIENT_KRB	"KFWK4"	/* Kerberos package for this release of the Windows KX509 */
#  endif /* !USE_KRB5 */
#  define KX509_CLIENT_VERSION	"1.2b1"	/* Version number for this release of the Windows KX509 */
#else /* !WIN32 */
#  define KX509_CLIENT_KRB		"KRB5"	/* Kerberos package for this release of non-Windows KX509 */
#  define KX509_CLIENT_VERSION	"1.0"	/* Version number for this release of non-Windows KX509 */
#endif /* !WIN32 */

/* Modded by Joe - added Jeff A changes */
/*#define	KX509_CLIENT_TIMEOUT	10 */		/* 10 seconds *seems* long enough */

/* #define MAX_UDP_PAYLOAD_LEN	1400 */		/* must fit in UDP payload */

/* #define MAX_AUTHENT_LEN		1250 */		/* mumbly foo made up value == MAX_KTXT_LEN */
/* #define MAX_PUBKEY_LEN		1000 */		/* mumbly foo made up value... */
/* #define	MAX_X509_CERT_LEN	1250 */		/* mumbly foo made up value... */

#define    KX509_CLIENT_TIMEOUT    30        /* was 10 seconds */
#define MAX_UDP_PAYLOAD_LEN    4000        /* must fit in UDP payload */
#define MAX_AUTHENT_LEN        3000        /* mumbly foo made up value == MAX_KTXT_LEN */
#define MAX_PUBKEY_LEN         2048        /* mumbly foo made up value... */
#define MAX_X509_CERT_LEN      3988        /* mumbly foo made up value... */

/*
 * KX509_STATUS_###
 *
 *    Values for ksp_status indicating class of problems encountered
 * while processing the client request.  Rather than indicating the exact
 * problem encountered, the values indicate both the likely source of the
 * problem as well as how transient the problem is.  For values of
 * ksp_status other than KX509_STATUS_GOOD, the ksp_reply field is filled
 * in with text that describes the problem in greater detail.  For the most
 * part, ksp_status is to be used by the client-side program to determine
 * whether it should: 'try again' or 'inform the user and exit'.
 */

#define KX509_STATUS_GOOD	0		/* No problems handling client request */

#define	KX509_STATUS_CLNT_BAD	1		/* Client-side permanent problem */
							/* ex. version incompatible */
#define	KX509_STATUS_CLNT_FIX	2		/* Client-side solvable problem */
							/* ex. re-authenticate */
#define	KX509_STATUS_CLNT_TMP	3		/* Client-side temporary problem */
							/* ex. packet loss */
#define	KX509_STATUS_SRVR_BAD	4		/* Server-side permanent problem */
							/* ex. server broken */
#define	KX509_STATUS_SRVR_TMP	5		/* Server-side temporary problem */
							/* ex. server overloaded */
#define	KX509_STATUS_SRVR_CANT_CLNT_VERS 6	/* Server-side doesn't handle */
							/* existence of client_version */
							/* field in KX509_REQUEST */

#define KX509_EMSG_UNABLE_TO_D2I_KX509_REQUEST "Unable to d2i_KX509_REQUEST"

#ifdef macintosh
#define KSUCCESS 0
#define KFAILURE 255
/* include space for '.' and '@' */
#define MAX_K_NAME_SZ (ANAME_SZ + INST_SZ + REALM_SZ + 2)
#endif /* macintosh */

typedef struct _kx_clnt_pkt {
	WORD	kcp_checksum;
	WORD	kcp_version;
	DWORD	kcp_mutauth;
	WORD	kcp_authent_len;
	WORD	kcp_pubkey_len;
	BUFF	kcp_authent;
	BUFF	kcp_pubkey;
} KX_CLNT_PKT;
#define MAX_KCP_LEN	(4*sizeof(WORD)+MAX_AUTHENT_LEN+MAX_PUBKEY_LEN+sizeof(DWORD))


typedef struct _kx_srvr_pkt {
	WORD	ksp_checksum;
	WORD	ksp_version;
	DWORD	ksp_mutauth;
	WORD	ksp_status;
	WORD	ksp_reply_len;
	BUFF	ksp_reply;
} KX_SRVR_PKT;
#define MAX_KSP_LEN	(4*sizeof(WORD)+MAX_X509_CERT_LEN+sizeof(DWORD))


#define	CERT_DYING	5

#endif	/* _INCLUDED_KX509_H */
