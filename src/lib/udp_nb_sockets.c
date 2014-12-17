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

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#endif
#include <ctype.h>
#include <string.h>
#include <sys/ioctl.h>
#ifdef SOLARIS
#include <sys/sockio.h>
#endif

#include <netdb.h>
#ifndef WIN32
#include <sys/errno.h>
extern int errno;
#else
#include <winsock.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif



int
udp_nb_sockets(fd_set *socket_set,
	       int *socket_set_size,
	       int port)
{
	struct ifconf	ifc;
	struct ifreq	iflist[512];
	struct ifreq	*ifrp;
	int		i, size;
	int		arg=FNDELAY;
	int		o;
	int		s;


       	/* Open socket */
        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
               	perror("opening datagram socket");
	       	return -1;
       	}
	ifc.ifc_len = sizeof(iflist);
	ifc.ifc_req = iflist;
	if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
	{
		perror("SIOCGIFCONF failed");
		return -1;
	}
	close(s);
	FD_ZERO(socket_set);
	*socket_set_size = 0;
	for (
		size = ifc.ifc_len, ifrp = iflist;
		size > IFNAMSIZ;
		ifrp = (struct ifreq *) (((char*)ifrp)+i), size -= i
	    )
	{
#ifndef AIX
		i = sizeof(*ifrp);
#else
		i = IFNAMSIZ + ifrp->ifr_addr.sa_len;
#endif
		if (ifrp->ifr_addr.sa_family != AF_INET)
			continue;

		if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		{
			perror("can't make socket");
			return -1;
		}

		/*
		 * this could be up to 65536 -- try to allow for a
		 * reasonable backlog.
		 */
		o = 32768;
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&o, sizeof(o)) < 0)
			perror("setsockopt so_rcvbuf");

		((struct sockaddr_in*)&ifrp->ifr_addr)->sin_port = htons((short)port);

		if (bind(s, &ifrp->ifr_addr, sizeof(struct sockaddr_in)) < 0)
		{
			perror("binding datagram socket");
			return -1;
		}

		if (fcntl(s, F_SETFL, arg) == -1)
		{
			perror("setting datagram socket to non-blocking");
			return -1;
		}

		FD_SET(s, socket_set);
		if (s >= *socket_set_size)
			*socket_set_size = (s+1);
	}

	return 0;
}
