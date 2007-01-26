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

#ifndef WIN32
#ifdef macintosh
# include <Sockets.h>
#else /* !macintosh */
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif /* macintosh */
#else
#include <winsock.h>
#endif
#include "msg.h"

#ifndef WIN32
extern int errno;
#endif

int udp_nb_recv(int s, KX_MSG *msg)
{
	char	*buf = (char *)&(msg->m_data[msg->m_curlen]);
	int	len = msg->m_maxlen - msg->m_curlen;
	int	attempt=0;
	int	cc;

	do
	{
		attempt++;
#ifdef macintosh
		cc = socket_recv(s, buf, len, 0);
#else /* !macintosh */
		cc = recv(s, buf, len, 0);
#endif /* macintosh */
	}
	while
#if !defined(WIN32) && !defined(macintosh)
		/* Supposedly you can get EAGAIN ("Resource temporarily unavailable") */
		/*	so maybe it will become available or give another error...    */
		((cc == -1) && (errno == EAGAIN));
#else
		(cc == -12345);		/* I'm looking for an impossible condition */
#endif

	if (cc > 0)
		msg->m_curlen += cc;

	return cc;
}
