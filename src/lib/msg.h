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
 * msg.h -- Include file for MSG data-type
 */

#ifndef _INCLUDED_MSG_H
#define _INCLUDED_MSG_H

#include "min_types.h"
#include "buf.h"

typedef struct _msg {
	BUFF	m_data;
	WORD	m_maxlen;
	WORD	m_curpos;
	WORD	m_curlen;
} KX_MSG;

int msg_place_cksum(KX_MSG *msg);
int msg_update_cksum(KX_MSG *msg);
int msg_ck_cksum(KX_MSG *msg);
int msg_add_mutauth(KX_MSG *msg, void *sess_key, WORD mutauth_in);
int msg_ck_mutauth(KX_MSG *msg, void *sess_key, WORD mutauth_in);

#define MSG_CLEAR(msg)		(msg)->m_curpos = (msg)->m_curlen=0

#define MSG_ALLOC(msg, m_len)	( ((msg)->m_data = (BUFF)malloc(m_len)) \
					? (msg)->m_maxlen=m_len, MSG_CLEAR(msg) \
					: -1 )

#define MSG_FREE(msg)		free((msg)->m_data)

#define MSG_APPEND(msg, new, new_len)	( (((msg)->m_curlen+new_len) > (msg)->m_maxlen) \
						? -1					\
						: (long)memcpy(&((msg)->m_data[(msg)->m_curlen]),(char *)new,new_len),	\
						  (msg)->m_curlen += new_len,		\
						  0 )

#define MSG_PULL(msg, to, to_cnt)	( (((msg)->m_curpos+to_cnt) > (msg)->m_curlen)	\
						? -1 					\
						: (long)memcpy((char *)to,&((msg)->m_data[(msg)->m_curpos]),to_cnt),	\
						  (msg)->m_curpos += to_cnt,		\
						  0 )

#define MSG_PLACE_CKSUM(msg)		msg_place_cksum(msg)

#define MSG_UPDATE_CKSUM(msg)		msg_update_cksum(msg)

#define MSG_CK_CKSUM(msg)		msg_ck_cksum(msg)

#define MSG_ADD_MUTAUTH(msg, key, in)	msg_add_mutauth(msg, key, in)

#define MSG_CK_MUTAUTH(msg, key, in)	msg_ck_mutauth(msg, key, in)

#endif
