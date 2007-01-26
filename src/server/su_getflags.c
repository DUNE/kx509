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

#if defined(HAVE_UMID_LOOKUP)

/*
 * su_getflags.c -- retrieve a uniqname's access_flags for a particular lifetime
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#ifdef	AFS_AIX31_ENV
#include <signal.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#if 0	/* XXX I think <afs/param.h> does this already -mdw */
#include <afs/stds.h>
#endif
#ifdef HACK_AIX43_AFS34_TYPEDEF_CLASH
# define int16	transarc_int16
# define u_int16	transarc_u_int16
# define int32	transarc_int32
#endif
#include <afs/param.h>
#ifdef HACK_AIX43_AFS34_TYPEDEF_CLASH
# undef int16
# undef u_int16
# undef int32
#endif
#include <afs/cmd.h>
#include <afs/cellconfig.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include <netinet/in.h>
#include <rx/rxkad.h>
#include <afs/auth.h>
#include <errno.h>

#include "unclient.h"
#include "unerror.h"

/*struct ubik_client *unuclient = 0;*/

long uniqtolifetime(char *loginid, char *group, char *flags)
{
	register long	code;
	lifetimelist	lifetimes;
	struct lifetime *p;
	uniqname	un;
	long		gid;
	int		n;

	*flags = 0;
	un_Initialize((char*)0,AFSCONF_CLIENTNAME,(long)0);

	if (code = MapGroupToId(group, &gid))
		return code;

	bzero((char*)&lifetimes, sizeof lifetimes);
	if (!(code = un_FindEntry("ifs", loginid, &un, &lifetimes)))
		for (n=0; n<lifetimes.lifetimelist_len; n++) {
			p = &lifetimes.lifetimelist_val[n];
			if (p->group == gid) {
				util_GenFlags(p->access_flags, flags);
				break;
			}
		}

	if (lifetimes.lifetimelist_val)
		free((char*) lifetimes.lifetimelist_val);

	return 0;
}

#endif	/* HAVE_UMID_LOOKUP */
