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

#ifdef WIN32 
# include <openssl/des.h>
# define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                              // since wincrypt.h and openssl namepsaces collide
                              //  ex. X509_NAME is #define'd and typedef'd ...

# include <winsock.h>         // Must be included before <windows.h> !!! 
# include <windows.h> 
# include <time.h>
#else
# include <openssl/des.h>
# ifndef linux
#  ifndef DES_DEFS
#   define DES_DEFS		// Prevent collision with K5 DES delarations
#  endif /* DES_DEFS */
# endif /* !linux */
# ifdef macintosh
#  include <Sockets.h>
#  include <KClient.h>
# endif /* macintosh */
#endif /* !WIN32 */

#include "msg.h"

#ifdef HACK_HTONS_NEEDS_NETINET_IN_H
/* the K5 include files do this for us, but K4 does not.
 * we should really always include this, but for now we'll
 * let configure decide...
 */
#include <sys/types.h>	/* required by in.h */
#include <sys/socket.h>	/* required by in.h */
#include <netinet/in.h>	/* the payoff, htons and ntohs are defined here. */
#endif

int msg_place_cksum(KX_MSG *msg)
{
	WORD		cksum = 0;


	return MSG_APPEND(msg, &cksum, sizeof(WORD));
}


int msg_update_cksum(KX_MSG *msg)
{
	WORD		cksum;


	cksum = 0;	/* TEMPORARY !!   REPLACE WITH CODE TO CALCULATE CKSUM */

	cksum = htons(cksum);
	return MSG_APPEND(msg, &cksum, sizeof(WORD));
}


int msg_ck_cksum(KX_MSG *msg)
{
	WORD		cksum;


	if (MSG_PULL(msg, &cksum, sizeof(WORD)))
		return 1;
	cksum = ntohs(cksum);

	return (cksum != 0); /* TEMPORARY !!   REPLACE WITH CODE TO CHECK CKSUM */
}


int msg_add_mutauth(KX_MSG *msg,
		    void *sess_key,
		    WORD mutauth_in)
{
	des_key_schedule	seskey_sched;
	WORD		m_rand;
	BYTE		*p;


	p = &msg->m_data[msg->m_curlen];

#if defined(WIN32) || defined(macintosh)
	srand( (unsigned)time( NULL ) );
	m_rand = htons((WORD)(rand() & 0xFFFF));
#else
	m_rand = htons(random() & 0xFFFF);
#endif
	if (MSG_APPEND(msg, &m_rand, sizeof(WORD)))
		return 1;

	mutauth_in = htons(mutauth_in);
	if (MSG_APPEND(msg, &mutauth_in, sizeof(WORD)))
		return 1;

	if (des_set_key(sess_key, seskey_sched))
		return 1;

	(void)des_pcbc_encrypt((void *)p, (void *)p, sizeof(DWORD), seskey_sched, sess_key, 1);

	return 0;
}


int msg_ck_mutauth(KX_MSG *msg,
		   void *sess_key,
		   WORD mutauth_in)
{
	des_key_schedule	seskey_sched;
	WORD		mutauth_out;
	WORD		m_rand;
	BYTE		*p;


	p = &msg->m_data[msg->m_curlen];

	if (des_set_key(sess_key, seskey_sched))
		return 1;

	(void)des_pcbc_encrypt((void *)p, (void *)p, sizeof(DWORD), seskey_sched, sess_key, 0);

	if (MSG_PULL(msg, &m_rand, sizeof(WORD)))
		return 1;
	m_rand = ntohs(m_rand);

	if (MSG_PULL(msg, &mutauth_out, sizeof(WORD)))
		return 1;
	mutauth_out = ntohs(mutauth_out);

	return (mutauth_in+1 == mutauth_out);
}
