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

#ifndef macintosh
#include <sys/types.h>
#endif /* macintosh */
#include <ctype.h>
#include <string.h>

#ifndef WIN32
#ifdef macintosh
# include <Sockets.h>
#else /* !macintosh */
# include <sys/socket.h>
# include <sys/ioctl.h>
# ifdef SOLARIS
#  include <sys/sockio.h>
# endif
# include <sys/socket.h>
# include <sys/errno.h>
  extern int errno;
# include <netdb.h>
# include <net/if.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif /* macintosh */
# ifdef HAVE_SYS_FILE_H
#  include <sys/file.h>
# endif
# ifdef HAVE_SYS_FCNTL_H
#  include <sys/fcntl.h>
# endif
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# endif
#else
# include <winsock.h>
#endif



int
udp_nb_socket(int port)
{
	struct sockaddr_in sockaddr;
	int		arg;
#if !defined(macintosh) && !defined(WIN32)
	int		o;
#endif /* !macintosh */
	int		s	= 0;


#ifdef macintosh
	if ((s = socket(AF_INET, SOCK_DGRAM, PF_INET)) < 0)
#else /* !macintosh */
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
#endif /* macintosh */
	{
		perror("can't make socket");
		goto UNS_err;
	}

#if !defined(macintosh) && !defined(WIN32)
	/*
	 * this could be up to 65536 -- try to allow for a
	 * reasonable backlog.
	 */
	o = 32768;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&o, sizeof(o)) < 0)
		perror("setsockopt so_rcvbuf");
#endif /* macintosh */

	memset(&sockaddr, 0, sizeof(struct sockaddr_in));
	sockaddr.sin_port = htons((short)port);

#ifdef WIN32
	arg=1;
	if (ioctlsocket(s, FIONBIO, &arg) < 0)
#elif defined(macintosh)
	arg = socket_fcntl(s, F_GETFL, 0); 
	arg |= O_NONBLOCK;
	if (socket_fcntl(s, F_SETFL, arg))
#else
	arg=FNDELAY;
	if (fcntl(s, F_SETFL, arg) == -1)
#endif
	{
		perror("setting datagram socket to non-blocking");
		goto UNS_err;
	}

	if (!port)
		goto UNS_exit;

#ifdef macintosh
	if (socket_bind(s, (void *)&sockaddr, sizeof(struct sockaddr_in)) < 0)
#else /* !macintosh */
	if (bind(s, (void *)&sockaddr, sizeof(struct sockaddr_in)) < 0)
#endif
	{
		perror("binding datagram socket");
		goto UNS_err;
	}

	goto UNS_exit;


UNS_err:
#ifdef WIN32
	closesocket((unsigned int)socket);
#else /* !WIN32 */
	close((unsigned int)socket);
#endif /* !WIN32 */
	s = -1;


UNS_exit:
	return s;

}
