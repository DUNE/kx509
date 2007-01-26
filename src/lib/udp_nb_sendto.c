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

#ifndef WIN32
#ifdef macintosh
# include <Sockets.h>
#else /* !macintosh */
# include <sys/types.h>
# include <sys/socket.h>
#endif /* macintosh */
#endif
#ifndef macintosh
#include <netinet/in.h>
#endif /* !macintosh */
#include "msg.h"

int udp_nb_sendto(int s,
		  KX_MSG *msg,
		  struct sockaddr_in *to)
{
	int	cc;
	int	n = sizeof(struct sockaddr_in);
	char	*buf = (char *)&msg->m_data[0];
	int	len = msg->m_curlen;

#ifdef macintosh
	cc = (int)socket_sendto(s, buf, len, 0, (void *)to, n);
#else /* !macintosh */
	cc = (int)sendto(s, buf, len, 0, (void *)to, n);
#endif /* macintosh */

	return cc;
}
