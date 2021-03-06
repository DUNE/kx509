/*
 * Copyright  �  2000,2007
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
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/file.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif /* macintosh */
# ifdef HAVE_SYS_FILE_H
#  include <sys/file.h>
# endif
# ifdef HAVE_SYS_FCNTL_H
#  include <sys/fcntl.h>
# endif
#else
# include <winsock.h>
typedef	unsigned short	u_short;
#endif

typedef struct  sockaddr_in	SOCK_ADDR;

int udp_nb_bind(int ls, u_short port)
{
	SOCK_ADDR	listener;
	int		arg;


	memset(&listener, 0, sizeof(listener));
	listener.sin_family = AF_INET;
	listener.sin_port   = htons(port);
	listener.sin_addr.s_addr = INADDR_ANY;

#ifdef macintosh
	if (socket_bind(ls, (struct sockaddr *)&listener, sizeof(listener)) < 0)
#else /* !macintosh */
	if (bind(ls, (struct sockaddr *)&listener, sizeof(listener)) < 0)
#endif /* macintosh */
		return -1;

#ifdef WIN32
	arg = 1;
	if (ioctlsocket(ls, FIONBIO, &arg) < 0)
#elif defined(macintosh)
	arg = socket_fcntl(ls, F_GETFL, 0); 
	arg |= O_NONBLOCK;
	if (socket_fcntl(ls, F_SETFL, arg))
#else
	arg = FNDELAY;
	if (fcntl(ls, F_SETFL, arg) == -1)
#endif
		return -1;

	return 0;
}
