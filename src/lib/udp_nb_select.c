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

#include <stdio.h>	/* home of NULL */
#ifndef WIN32
#ifdef macintosh
#include <Sockets.h>
#else /* macintosh */
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif /* macintosh */
#else
#include <winsock.h>
#endif

#ifndef WIN32
extern int errno;
#endif

int udp_nb_select(fd_set *readfds,
		  fd_set *writefds,
		  fd_set *exceptfds,
		  struct timeval *timeout)
{
	int	nfound;
	int	wait = 0;

	/* setting timeout to -1 means wait forever */
	if (timeout == (void *)-1)
	{
		timeout = NULL;
		wait = 1;
	}

	/* do selects until one of:
	 *
	 *		1.  a packet is ready
	 *		2.  timeout has elapsed (for non-NULL timeout)
	 *		3.  an error occurs (if timeout=-1,
	 *				then would-block type errors are excluded)
	 */

	do {
#ifdef macintosh
		nfound = socket_select(FD_SETSIZE, readfds, writefds, exceptfds, timeout);
#else /* !macintosh */
		nfound = select(FD_SETSIZE, readfds, writefds, exceptfds, timeout);
#endif /* macintosh */
	} while
		 ((nfound == -1)
		 && wait
#if !defined(WIN32) && !defined(macintosh)
		 && ((errno == EWOULDBLOCK) || (errno == EAGAIN)));
#else
		&& 0);		/* On Windows, assume it's not going to fix itself */
				/* On Macintosh, we don't have errno */
#endif

	return nfound;
}
