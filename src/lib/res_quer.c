// WIN32 ONLY FILE	--	billdo 2001.0522

/*
 *
 *	@doc RESOLVE
 *
 *  	
 *	@module res_quer.c | Contains the implementation of res_query,
 *	res_search, and res_querydomain
 *
 * WSHelper DNS/Hesiod Library for WINSOCK
 *
 */

/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)res_query.c	5.11 (Berkeley) 3/6/91";
#endif /* LIBC_SCCS and not lint */

#include <windows.h>
#include <winsock.h>

#define __DECLDLL__H
#undef  EXPORT
#undef  EXPORT32
#define EXPORT
#define EXPORT32

#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>


#include "u-compat.h"


#define strcasecmp	stricmp

#if PACKETSZ > 4096
#define MAXPACKET       PACKETSZ
#else
#define MAXPACKET       4096
#endif

#if !defined (_WINDLL) && !defined (_WIN32)
int h_errno;
#endif

#ifdef _DEBUG
#define DEBUG
#endif

#if (defined (_WINDLL) || defined (_WIN32) ) && defined(DEBUG)
/* For debugging output */
char debstr[80];
#endif

#if defined(_WINDOWS) || defined(_WIN32)
#define ERROR_IS(x) (WSAGetLastError() == WSA##x)
#define SET_ERROR(x) WSASetLastError(WSA##x)
#else
#define ERROR_IS(x) (errno == x)
#define SET_ERROR(x) h_errno = x
#endif

/*
 *
 @func EXPORT32 int EXPORT WINAPI | res_query | 
	 Formulate a normal query, send, and await answer.
 Returned answer is placed in supplied buffer "answer".
 Perform preliminary check of answer, returning success only
 if no error is indicated and the answer count is nonzero.
 Return the size of the response on success, -1 on error.
 Error number is left in h_errno.
 Caller must parse answer and determine whether it answers the question.

   @parm char *| name | domain name
   @parm int | qclass | class of query
   @parm int | type | type of query
   @parm u_char * | answer | buffer to put answer in
   @parm int | anslen | size of answer buffer
*
*	
*
*/
EXPORT32 int
#ifdef _WINDLL
EXPORT WINAPI
#endif
res_query(char *name, int qclass, int type, u_char *answer, int anslen)
    /* domain name, class and type of query, buffer to put answer, size of answer buffer */
{
    char buf[MAXPACKET];
    HEADER *hp;
    int n;

    if ((_res.options & RES_INIT) == 0 && res_init() == -1)
        return (-1);
#ifdef DEBUG
    if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined (_WIN32)
        printf("res_query(%s, %d, %d)\n", name, qclass, type);
#else
    {
        wsprintf(debstr, "res_query(%s, %d, %d)\n", name, qclass, type);
        OutputDebugString(debstr);
    }
#endif		
#endif
    n = res_mkquery(QUERY, name, qclass, type, (char *)NULL, 0, NULL,
                    buf, sizeof(buf));

    if (n <= 0) {
#ifdef DEBUG
        if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined (_WIN32)
            printf("res_query: mkquery failed\n");
#else
        {
            wsprintf(debstr, "res_query: mkquery failed\n");
            OutputDebugString(debstr);
        }
#endif
#endif

#if !defined (_WINDLL) && !defined (_WIN32)
        h_errno = NO_RECOVERY;
#else
        WSASetLastError(WSANO_RECOVERY);
#endif
        return (n);
    }
    n = res_send(buf, n, (char *)answer, anslen);
    if (n < 0) {
#ifdef DEBUG
        if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined (_WIN32)
            printf("res_query: send error\n");
#else
        {
            wsprintf(debstr, "res_query: send error\n");
            OutputDebugString(debstr);
        }
#endif    
#endif

#if !defined (_WINDLL) && !defined (_WIN32)
        h_errno = TRY_AGAIN;
#else
        WSASetLastError(WSATRY_AGAIN);
#endif
        return(n);
    }

    hp = (HEADER *) answer;
    if (hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
#ifdef DEBUG
        if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined (_WIN32)
            printf("rcode = %d, ancount=%d\n", hp->rcode,
                   ntohs(hp->ancount));
#else
        {
            wsprintf(debstr, "rcode = %d, ancount=%d\n", hp->rcode,
                     ntohs(hp->ancount));
            OutputDebugString(debstr);
        }
#endif
#endif
        switch (hp->rcode) {
        case NXDOMAIN:
#if !defined (_WINDLL) && !defined (_WIN32)
            h_errno = HOST_NOT_FOUND;
#else
            WSASetLastError(WSAHOST_NOT_FOUND);
#endif
            break;
        case SERVFAIL:
#if !defined (_WINDLL) && !defined (_WIN32)
            h_errno = TRY_AGAIN;
#else
            WSASetLastError(WSATRY_AGAIN);
#endif
            break;
        case NOERROR:
#if !defined (_WINDLL) && !defined (_WIN32)
            h_errno = NO_DATA;
#else
            WSASetLastError(WSANO_DATA);
#endif
            break;
        case FORMERR:
        case NOTIMP:
        case REFUSED:
        default:
#if !defined (_WINDLL) && !defined (_WIN32)
            h_errno = NO_RECOVERY;
#else
            WSASetLastError(WSANO_RECOVERY);
#endif
            break;
        }
        return (-1);
    }
    return(n);
}


/*

  @func EXPORT32 int EXPORT WINAPI | res_search |
  
 Formulate a normal query, send, and retrieve answer in supplied buffer.
 Return the size of the response on success, -1 on error.
 If enabled, implement search rules until answer or unrecoverable failure
 is detected.  Error number is left in h_errno.
 Only useful for queries in the same name hierarchy as the local host
 (not, for example, for host address-to-name lookups in domain in-addr.arpa).

	@parm char *| name | domain name
	@parm int | qclass | class of query
	@parm int | type| type of query
	@parm u_char *| answer | buffer to put answer in
	@parm int | anslen | size of the answer buffer


 */
#ifdef _WINDLL
EXPORT32 int EXPORT WINAPI
#endif
res_search(const char *name, int qclass, int type, u_char *answer, int anslen)
    /* domain name, class and type of query, buffer to put answer, size of answer */
{
    register char *cp, **domain;
    int n, ret, got_nodata = 0;
    char *__hostalias();
	
    if ((_res.options & RES_INIT) == 0 && res_init() == -1)
        return (-1);

#if !defined (_WINDLL) && !defined (_WIN32)
    errno = 0;
    h_errno = HOST_NOT_FOUND;               /* default, if we never query */
#else
    WSASetLastError(WSAHOST_NOT_FOUND);
#endif
    for (cp = (char *)name, n = 0; *cp; cp++)
        if (*cp == '.')
            n++;
    if (n == 0 && (cp = __hostalias(name)))
        return (res_query(cp, qclass, type, answer, anslen));

    /*
     * We do at least one level of search if
     *      - there is no dot and RES_DEFNAME is set, or
     *      - there is at least one dot, there is no trailing dot,
     *        and RES_DNSRCH is set.
     */
    if ((n == 0 && _res.options & RES_DEFNAMES) ||
        (n != 0 && *--cp != '.' && _res.options & RES_DNSRCH))
        for (domain = _res.dnsrch; *domain; domain++) {
            ret = res_querydomain(name, *domain, qclass, type,
                                  answer, anslen);
            if (ret > 0)
                return (ret);
            /*
             * If no server present, give up.
             * If name isn't found in this domain,
             * keep trying higher domains in the search list
             * (if that's enabled).
             * On a NO_DATA error, keep trying, otherwise
             * a wildcard entry of another type could keep us
             * from finding this entry higher in the domain.
             * If we get some other error (negative answer or
             * server failure), then stop searching up,
             * but try the input name below in case it's fully-qualified.
             */
            if (ERROR_IS(ECONNREFUSED)) {
                SET_ERROR(TRY_AGAIN);
                return (-1);
            }
            if (ERROR_IS(NO_DATA))
                got_nodata++;
            if ((!ERROR_IS(HOST_NOT_FOUND) && !ERROR_IS(NO_DATA)) ||
                (_res.options & RES_DNSRCH) == 0)
                break;
        }
    /*
     * If the search/default failed, try the name as fully-qualified,
     * but only if it contained at least one dot (even trailing).
     * This is purely a heuristic; we assume that any reasonable query
     * about a top-level domain (for servers, SOA, etc) will not use
     * res_search.
     */
    if (n && (ret = res_querydomain(name, (char *)NULL, qclass, type,
                                    answer, anslen)) > 0)
        return (ret);
    if (got_nodata)
        SET_ERROR(NO_DATA);
    return (-1);
}


/*

  @func int WINAPI | res_querydomain| 

  Perform a call on res_query on the concatenation of name and domain,
  removing a trailing dot from name if domain is NULL.

  @parm char *| name| name
  @parm char *| domain| domain
  @parm int | qclass | query class
  @parm int | type | query type
  @parm u_char *| answer | buffer for answer
  @parm int | anslen | length of buffer

 */
int
#ifdef _WINDLL
WINAPI
#endif
res_querydomain(const char *name, const char *domain, int qclass, int type, u_char *answer, int anslen)
{
    char nbuf[2*MAXDNAME+2];
    char *longname = nbuf;
    int n;

#ifdef DEBUG
    if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined (_WIN32)
        printf("res_querydomain(%s, %s, %d, %d)\n",
               name, domain, qclass, type);
#else
    {
        wsprintf(debstr, "res_querydomain(%s, %s, %d, %d)\n",
                 name, domain ? domain : "<NULL>", qclass, type); /* il 8/22/95 -- bombed when domain is NULL */
        OutputDebugString(debstr);
	}
#endif
#endif
    if (domain == NULL) {
        /*
         * Check for trailing '.';
         * copy without '.' if present.
         */
        n = strlen(name) - 1;
        if (name[n] == '.' && n < sizeof(nbuf) - 1) {
#if !defined (_WINDLL) && !defined (_WIN32)
            bcopy(name, nbuf, n);
#else
            memcpy(nbuf, name, n);
#endif
            nbuf[n] = '\0';
        } else
            longname = (char *)name;
    } else
#if !defined (_WINDLL) && !defined (_WIN32)
        (void)sprintf(nbuf, "%.*s.%.*s",
                      MAXDNAME, name, MAXDNAME, domain);
#else
    /*
      This has to be done because wsprintf() doesn't understand * as a
      precision specifer - if MAXDNAME should ever change (in arpa/nameser.h)
      then this will need to be better implemented
    */
    (void)wsprintf(nbuf, "%.256s.%.256s",
                   name, domain);
#endif
    return (res_query(longname, qclass, type, answer, anslen));
}

char *
__hostalias(register const char *name)
{
    register char *C1, *C2;
    FILE *fp;
    char *file; 
//  char *getenv(), *strcpy(), *strncpy();  // pbh XXX 11/1/96
    char buf[BUFSIZ];
    static char abuf[MAXDNAME];

    file = getenv("HOSTALIASES");
    if (file == NULL || (fp = fopen(file, "r")) == NULL)
        return (NULL);
    buf[sizeof(buf) - 1] = '\0';
    while (fgets(buf, sizeof(buf), fp)) {
        for (C1 = buf; *C1 && !isspace(*C1); ++C1);
        if (!*C1)
            break;
        *C1 = '\0';
        if (!strcasecmp(buf, name)) {
            while (isspace(*++C1));
            if (!*C1)
                break;
            for (C2 = C1 + 1; *C2 && !isspace(*C2); ++C2);
            abuf[sizeof(abuf) - 1] = *C2 = '\0';
            (void)strncpy(abuf, C1, sizeof(abuf) - 1);
            fclose(fp);
            return (abuf);
        }
    }
    fclose(fp);
    return (NULL);
}
