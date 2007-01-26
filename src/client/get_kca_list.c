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

/* get_kca_list.c -- gather into one file all code related to determining
 *			the list of kca hostnames to communicate with
 *			irrespective of the client's architecture or
 *			kerberos implementation
 * CHANGE HISTORY:
 *	2000.1213 -- billdo -- created
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifndef WIN32
# ifdef macintosh
#  include <Sockets.h>
# else /* !macintosh */
#  include <sys/time.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
# endif /* macintosh */
#endif

#ifdef WIN32
# define WSHELPER
#endif /* WIN32 */

#ifdef WSHELPER
# include <wshelper.h>
#else /* WSHELPER */
# include <arpa/inet.h>
# include <arpa/nameser.h>
# include <resolv.h>
#endif /* WSHELPER */

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# ifndef FD_SET
#  include <sys/select.h>
# endif
#endif
#ifndef WIN32
# include <netdb.h>
#endif
#include <memory.h>

#include <stdlib.h>

#include "msg.h"
#include "udp_nb.h"
#include "kx509.h"
#include "debug.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include "kx509_asn.h"
#include <openssl/rand.h>



/* "#define" macros that were dropped as-of OpenSSL-0.9.6 -- billdo 2000.1205 */

#if SSLEAY_VERSION_NUMBER > 0x0090600e
# define	Malloc		OPENSSL_malloc
# define	Realloc		OPENSSL_realloc
# define	Free(addr)	OPENSSL_free(addr)
#endif



#ifndef T_SRV
# define T_SRV 33
#endif /* T_SRV */

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)

struct srv_dns_entry {
	struct srv_dns_entry *next;
	int priority;
	int weight;
	unsigned short port;
	char *host;
};


/*
 * Lookup list of KCA's via DNS SRV records and return a string of
 * blank-separated hostnames.
 */
int
get_kca_list(const char *realm,
	     char ***hostname_pp)
{
    char *service = "_kca";
    char *protocol = "_udp";
    int out, j, count;
    union {
        unsigned char bytes[2048];
        HEADER hdr;
    } answer;
    unsigned char *p=NULL;
    char host[MAX_DNS_NAMELEN];
    struct hostent *hp = NULL;
    int type, class;
    int priority, weight, size, len, numanswers, numqueries, rdlen;
    unsigned short port;
    const int hdrsize = sizeof(HEADER);
    struct srv_dns_entry *head = NULL;
    struct srv_dns_entry *srv = NULL, *entry = NULL;
    char **list = NULL;


    out = 0;

    count = 1;

    /*
     * First off, build a query of the form:
     *
     * service.protocol.realm
     *
     * which will most likely be something like:
     *
     * _kca._udp.REALM
     *
     */

    if ( strlen(service) + strlen(protocol) + strlen(realm) + 5 
         > MAX_DNS_NAMELEN )
        goto out;
    sprintf(host, "%s.%s.%s", service, protocol, realm);

    size = res_search(host, C_IN, T_SRV, answer.bytes, sizeof(answer.bytes));

    if (size < hdrsize)
		goto out;

    /*
     * We got an answer!  First off, parse the header and figure out how
     * many answers we got back.
     */

    p = answer.bytes;

    numqueries = ntohs(answer.hdr.qdcount);
    numanswers = ntohs(answer.hdr.ancount);

    p += sizeof(HEADER);

    /*
     * We need to skip over all of the questions, so we have to iterate
     * over every query record.  dn_expand() is able to tell us the size
     * of compress DNS names, so we use it.
     */

#define INCR_CHECK(x,y) x += y; if (x > size + answer.bytes) goto out
#define CHECK(x,y) if (x + y > size + answer.bytes) goto out
#define NTOHSP(x,y) x[0] << 8 | x[1]; x += y

    while (numqueries--) 
	{
		len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
		if (len < 0)
			goto out;
		INCR_CHECK(p, len + 4);
    }

    /*
     * We're now pointing at the answer records.  Only process them if
     * they're actually T_SRV records (they might be CNAME records,
     * for instance).
     *
     * But in a DNS reply, if you get a CNAME you always get the associated
     * "real" RR for that CNAME.  RFC 1034, 3.6.2:
     *
     * CNAME RRs cause special action in DNS software.  When a name server
     * fails to find a desired RR in the resource set associated with the
     * domain name, it checks to see if the resource set consists of a CNAME
     * record with a matching class.  If so, the name server includes the CNAME
     * record in the response and restarts the query at the domain name
     * specified in the data field of the CNAME record.  The one exception to
     * this rule is that queries which match the CNAME type are not restarted.
     *
     * In other words, CNAMEs do not need to be expanded by the client.
     */

    while (numanswers--) 
	{
		/* First is the name; use dn_expand to get the compressed size */
		len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
		if (len < 0)
			goto out;
		INCR_CHECK(p, len);

		/* Next is the query type */
		CHECK(p, 2);
		type = NTOHSP(p,2);

		/* Next is the query class; also skip over 4 byte TTL */
		CHECK(p, 6);
		class = NTOHSP(p,6);

		/* Record data length */

		CHECK(p,2);
		rdlen = NTOHSP(p,2);

		/*
		 * If this is an SRV record, process it.  Record format is:
		 *
		 * Priority
		 * Weight
		 * Port
		 * Server name
		 */

		if (class == C_IN && type == T_SRV) 
		{
			CHECK(p,2);
			priority = NTOHSP(p,2);
			CHECK(p, 2);
			weight = NTOHSP(p,2);
			CHECK(p, 2);
			port = NTOHSP(p,2);
			len = dn_expand(answer.bytes, answer.bytes + size, p, host, sizeof(host));
			if (len < 0)
				goto out;
			INCR_CHECK(p, len);

			/*
			 * We got everything!  Insert it into our list, but make sure
			 * it's in the right order.  Right now we don't do anything
			 * with the weight field
			 */

			srv = (struct srv_dns_entry *) Malloc(sizeof(struct srv_dns_entry));
			if (srv == NULL)
				goto out;
		
			srv->priority = priority;
			srv->weight = weight;
			srv->port = port;

			/* strdup would implicitly use the evil malloc ... */
			srv->host = (char *) Malloc(strlen(host)+1);
			if (srv->host == NULL)
				goto out;
#if 0
			strcpy(srv->host, host);
#else
			{
				char *t, *f;
				f = host;
				t = srv->host;
				while (*f != '\0')
					*t++ = tolower(*f++);
				*t = '\0';

			}
#endif


			if (head == NULL || head->priority > srv->priority) 
			{
				srv->next = head;
				head = srv;
			} 
			else
				/*
				 * This is confusing.  Only insert an entry into this
				 * spot if:
				 * The next person has a higher priority (lower priorities
				 * are preferred).
				 * Or
				 * There is no next entry (we're at the end)
				 */
				for (entry = head; entry != NULL; entry = entry->next)
					if ((entry->next &&
						entry->next->priority > srv->priority) ||
						entry->next == NULL) 
					{
						srv->next = entry->next;
						entry->next = srv;
						break;
					}
		} 
		else
			INCR_CHECK(p, rdlen);
    }
	
    /*
     * Okay!  Now we've got a linked list of entries sorted by
     * priority.  Yank the hostnames out of entry and transfer to hostname_pp
     */

    for (entry = head; entry != NULL; entry = entry->next)
		out++;

    if (out == 0)
		goto out;

    list = Malloc( sizeof(char *) * (out + 1));
    if (list)
    {
		for (j=0, entry = head;  entry != NULL;  j++, entry = entry->next)
		{
			list[j] = entry->host;
			entry->host = NULL;
		}
		list[out] = NULL;
    }

out:
	
    /* free the list of entries */
    for (entry = NULL; head != NULL; )
    {
		entry = head;
		head = entry->next;
		if ( entry->host )
		{
			Free( entry->host );
			entry->host = NULL;
		}
		Free( entry );
		entry = NULL;
    }

    if (list == NULL)
		return ENOMEM;

    if (out == 0)	/* No good servers */
		return -1;

    *hostname_pp = list;
    return 0;
}
