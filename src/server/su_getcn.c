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

#if defined(HAVE_LDAP_LOOKUP)

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <lber.h>
#include <ldap.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/time.h>

#include "ldapconfig.h"

#define LDAP_RESPONSE_TIMEOUT		10	/* wait up to 10 seconds for response */

#define KNOWN_LDAP_HOST_CNT	3
char *ldap_hosts[KNOWN_LDAP_HOST_CNT] = {
	"ragingangels.dir.itd.umich.edu",
	"solarcrisis.dir.itd.umich.edu",
	LDAPHOST
};

int got_alarm;
static jmp_buf x500alarmjb;

void x500watchdog(int i)
{
	++got_alarm;
	if (got_alarm > 8)
		longjmp(x500alarmjb, 1);
}

get_cn(char *uniqname, char *cn)
{
	char	rn[] = "get_cn";

	char    *filtpattern = "uid=";
	char    *attrs[2] = {"cn"};
	int	rc, scope;
	int	ldap_options, timelimit, sizelimit;
	char	*binddn = LDAPSEARCH_BINDDN;
	char	*passwd = NULL;
	char	*base = LDAPSEARCH_BASE;
	int	ldapport = LDAP_PORT;
	auto LDAP	*ld;
	int	i;
	struct sigaction sa[1], osa[1];
	struct itimerval itv[1], oitv[1];
	char what[512];

	*cn = '\0';

	ldap_options = 0;
	sizelimit = 0;
	timelimit = LDAP_RESPONSE_TIMEOUT;
	scope = LDAP_SCOPE_SUBTREE;
	ld = 0;

	if (setjmp(x500alarmjb))
	{
		if (setitimer(ITIMER_REAL, oitv, 0) < 0)
			elcprintf("setitimer #1: %s\n", strerror(errno));
		if (sigaction(SIGALRM, osa, 0) < 0)
			elcprintf("sigaction #1: %s\n", strerror(errno));
elcprintf("%s: ldap_open watchdog! #1\n", rn);
		*cn = 0;
		return;
	}
	memset((char*)sa, 0, sizeof *sa);
	sa->sa_handler = x500watchdog;
	if (sigaction(SIGALRM, sa, osa) < 0)
		elcprintf("sigaction #2: %s\n", strerror(errno));
	memset((char*)itv, 0, sizeof *itv);
	itv->it_value.tv_sec = 3;
	itv->it_value.tv_usec = 0;
	itv->it_interval.tv_sec = 0;
	itv->it_interval.tv_usec = 500000;
	got_alarm = 0;
	if (setitimer(ITIMER_REAL, itv, oitv) < 0)
	{
		int se = errno;
		elcprintf ("itv.value=%d.%06d itv.interval=%d.%06d\n",
itv->it_value.tv_sec,
itv->it_value.tv_usec,
itv->it_interval.tv_sec,
itv->it_interval.tv_usec);
		elcprintf("setitimer #2: %s\n", strerror(se));
	}

	for (i=0; i<KNOWN_LDAP_HOST_CNT; i++)
	{
		if (setjmp(x500alarmjb))
		{
			elcprintf("%s: ldap_open watchdog! #2\n", rn);
			got_alarm = 0;
			continue;
		}
		ld = ldap_open( ldap_hosts[i], ldapport );
		if (! ld )
		{
			elcprintf("%s: failed ldap_open %s\n", rn, ldap_hosts[i]);
			continue;
		}
		if (setjmp(x500alarmjb))
		{
elcprintf("%s: ldap_open watchdog! #3\n", rn);
			got_alarm = 0;
			if (ld)
			{
#if 0
/*
 * Not worth teaching autoconf about this; close_connection
 *  is in os-ip.c, which also references sockets and ldap_debug.
 *  ldap_debug is defined in open.c, which references kerberos.
 *  So, to link this, we'd have to use -lkrb -lnsl -lsocket.
 *  YUCK.
 *
 *  Instead, we'll just do it the "hard" way...
 */
#ifdef HACK_LDAP_CLOSE_CONNECTION
				ldap_close_connection( &ld->ld_sb );
#else
#ifdef HACK_OLD_LDAP_CLOSE_CONNECTION
				close_connection( &ld->ld_sb );
#else
Houston, we have a problem.
#endif
#endif
#else
				close(ld->ld_sb.sb_sd);
#endif
				ldap_ld_free(ld, 0);
			}
			ld = 0;
			continue;
		}

		ld->ld_deref = 0;
		ld->ld_timelimit = timelimit;
		ld->ld_sizelimit = sizelimit;
		ld->ld_options = ldap_options;

		if ( ldap_bind_s( ld, binddn, passwd, LDAP_AUTH_SIMPLE )
				!= LDAP_SUCCESS )
		{
			sprintf(what, "ldap_bind_s %s", ldap_hosts[i]);
			elcldap_perror(ld, what);
		} else {

		rc = dosearch( ld, base, scope, attrs, filtpattern, uniqname, cn );
		}

		ldap_unbind( ld );
		ld = 0;

		if (strlen(cn))
			break;

		elcprintf("%s: failed dosearch %s\n", rn, ldap_hosts[i]);
	}
	got_alarm = 0;
	if (setitimer(ITIMER_REAL, oitv, 0) < 0)
	{
		int se = errno;
		elcprintf ("failed to set, oitv.value=%d.%06d oitv.interval=%d.%06d\n",
oitv->it_value.tv_sec,
oitv->it_value.tv_usec,
oitv->it_interval.tv_sec,
oitv->it_interval.tv_usec);
		elcprintf("setitimer #3: %s\n", strerror(se));
	}
	if (sigaction(SIGALRM, osa, 0) < 0)
		elcprintf("sigaction #3: %s\n", strerror(errno));

	if (!strlen(cn))
		elcprintf("%s: failed on all %d LDAP servers!\n",
			rn, KNOWN_LDAP_HOST_CNT);

	return;
}

/*************
** 
** dosearch -- Start a search and call print_entry to  display 
**             the results.
*************/

int
dosearch( LDAP *ld, char *base, int scope, char **attrs,
	  char *filtpatt, char *uniqname, char *cn )
{
	char		filter[ BUFSIZ ], **val;
	int		rc, matches;
	LDAPMessage	*res, *e;

	/*
	** Construct the search filter composed of filter & uniqname
	*/
	strcpy (filter, filtpatt);
	strcat (filter, uniqname);

	if ( ldap_search( ld, base, scope, filter, attrs, 0 ) == -1 )
	{
		elcldap_perror( ld, "ldap_search" );
		return( ld->ld_errno );
	}

	matches = 0;
	
	while ( (rc = ldap_result( ld, LDAP_RES_ANY, 0, NULL, &res ))
			      == LDAP_RES_SEARCH_ENTRY )
	{
		matches++;
		e = ldap_first_entry( ld, res );
		set_cn( ld, e, uniqname, cn );
		ldap_msgfree( res );
	}
	
	if ( rc == -1 )
	{
		elcldap_perror( ld, "ldap_result" );
		return( rc );
	}
	if (( rc = ldap_result2error( ld, res, 0 )) != LDAP_SUCCESS )
		elcldap_perror( ld, "ldap_search" );

	ldap_msgfree( res );
	return( rc );
}

/*************
** 
** set_cn -- retrieve the search results and set cn to it.
**
*************/

set_cn( LDAP *ld, LDAPMessage *entry, char *uniqname, char *cn )
{
	char		*dn;
	char		**rdn;
	char		*ent;
	int		len;

	dn = ldap_get_dn( ld, entry );
	rdn = ldap_explode_dn (dn, 1);
		
	/* add " 1" to end of commonName if not already suffixed */
	ent = rdn[0];
	len = strlen(ent);
	if (index("0123456789", ent[len-1]))
		strcpy(cn, ent);
	else
		sprintf(cn, "%s 1", ent);
		
	free( dn );

	return;
}

elcldap_perror(LDAP *ld, char *s)
{
	char *es, *ad;
	if (!ld)
	{
		elcprintf("%s failed - error %d\n", s, errno);
		return;
	}
	es = ldap_err2string(ld->ld_errno);
	if (strcmp(es, "Unknown error"))
		es = "";
	if (ld->ld_error && *ld->ld_error)
		ad = ld->ld_error;
	else ad = 0;
	elcprintf("%s failed - error %d%s%s%s%s%s\n", s, ld->ld_errno,
		*es ? " " : "",
		es,
		ad ? " (" : "",
		ad ? ad : "",
		ad ? ")" : "");
}

#endif	/* HAVE_LDAP_LOOKUP */
