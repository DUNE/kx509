// WIN32 ONLY FILE	--	billdo 2001.0522

/*
 *	@doc RESOLVE
 *
 *	
 *	@module res_mkqu.c | Contains the implementation of res_mkquery
 *   
 *  
 *
 * WSHelper DNS/Hesiod Library for WINSOCK
 *
*/

/*
 * Copyright (c) 1985 Regents of the University of California.
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
static char sccsid[] = "@(#)res_mkquery.c	6.16 (Berkeley) 3/6/91";
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
#include <string.h>

#include "u-compat.h"

#ifdef _DEBUG
#define DEBUG
#endif

#if (defined(_WINDLL) || defined (_WIN32) ) && defined(DEBUG)
/* For debugging output */
char debstr[80];
#endif



/*
 *
 *  @func EXPORT32 int EXPORT WINAPI | res_mkquery | Form all types of queries.

    @parm         int | op      | opcode of query 
    @parm const char* | dname   | domain name 
    @parm         int | qclass  | class of query
    @parm         int | type    | type of query 
    @parm const char* | data    | resource record data 
    @parm         int | datalen | length of data 
    @parm const struct rrec *| newrr | new rr for modify or append 
    @parm       char* | buf     | buffer to put query 
    @parm         int | buflen  | size of buffer 

 * 
 *  @rdesc Returns the size of the result or -1.
 */
#ifdef _WINDLL
EXPORT32 int EXPORT WINAPI
#endif
res_mkquery(int op,			/* opcode of query */
            const char *dname,		/* domain name */
            int qclass, int type,	/* class and type of query */
            const char *data,		/* resource record data */
            int datalen,		/* length of data */
            const struct rrec *newrr,	/* new rr for modify or append */
            char *buf,			/* buffer to put query */
            int buflen)			/* size of buffer */
{
    register HEADER *hp;
    register char *cp;
    register int n;
    char *dnptrs[10], **dpp, **lastdnptr;

#ifdef _WINDLL
    void __putshort(register u_short, register u_char *);
    void __putlong(register u_long, u_char *);
#endif

#ifdef DEBUG
    if (_res.options & RES_DEBUG)
#if !defined (_WINDLL) && !defined( _WIN32)
        printf("res_mkquery(%d, %s, %d, %d)\n", op, dname, qclass, type);
#else
    {
        wsprintf(debstr, "res_mkquery(%d, %s, %d, %d)\n", op, dname, qclass,
                 type);
        OutputDebugString(debstr);
    }
#endif    
#endif /* DEBUG */
    /*
     * Initialize header fields.
     */
    if ((buf == NULL) || (buflen < sizeof(HEADER)))
        return(-1);
#if !defined (_WINDLL) && !defined( _WIN32)
    bzero(buf, sizeof(HEADER));
#else
    memset(buf, '\0', sizeof(HEADER));
#endif
    hp = (HEADER *) buf;
    hp->id = htons(++_res.id);
    hp->opcode = op;
    hp->pr = (_res.options & RES_PRIMARY) != 0;
    hp->rd = (_res.options & RES_RECURSE) != 0;
    hp->rcode = NOERROR;
    cp = buf + sizeof(HEADER);
    buflen -= sizeof(HEADER);
    dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = NULL;
    lastdnptr = dnptrs + sizeof(dnptrs)/sizeof(dnptrs[0]);
    /*
     * perform opcode specific processing
     */
    switch (op) {
    case QUERY:
        if ((buflen -= QFIXEDSZ) < 0)
            return(-1);
        if ((n = dn_comp((u_char *)dname, (u_char *)cp, buflen,
                         (u_char **)dnptrs, (u_char **)lastdnptr)) < 0)
            return (-1);
        cp += n;
        buflen -= n;
        __putshort((u_short)type, (u_char *)cp);
        cp += sizeof(u_short);
        __putshort((u_short)qclass, (u_char *)cp);
        cp += sizeof(u_short);
        hp->qdcount = htons(1);
        if (op == QUERY || data == NULL)
            break;
        /*
         * Make an additional record for completion domain.
         */
        buflen -= RRFIXEDSZ;
        if ((n = dn_comp((u_char *)data, (u_char *)cp, buflen,
                         (u_char **)dnptrs, (u_char **)lastdnptr)) < 0)
            return (-1);
        cp += n;
        buflen -= n;
        __putshort(T_NULL, (u_char *)cp);
        cp += sizeof(u_short);
        __putshort((u_short)qclass, (u_char *)cp);
        cp += sizeof(u_short);
        __putlong(0, (u_char *)cp);
        cp += sizeof(u_long);
        __putshort(0, (u_char *)cp);
        cp += sizeof(u_short);
        hp->arcount = htons(1);
        break;

    case IQUERY:
        /*
         * Initialize answer section
         */
        if (buflen < 1 + RRFIXEDSZ + datalen)
            return (-1);
        *cp++ = '\0';   /* no domain name */
        __putshort((u_short)type, (u_char *)cp);
        cp += sizeof(u_short);
        __putshort((u_short)qclass, (u_char *)cp);
        cp += sizeof(u_short);
        __putlong(0, (u_char *)cp);
        cp += sizeof(u_long);
        __putshort((u_short)datalen, (u_char *)cp);
        cp += sizeof(u_short);
        if (datalen) {
#if !defined (_WINDLL) && !defined( _WIN32)
            bcopy(data, cp, datalen);
#else
            memcpy(cp, data, datalen);
#endif
            cp += datalen;
        }
        hp->ancount = htons(1);
        break;

#ifdef ALLOW_UPDATES
        /*
	 * For UPDATEM/UPDATEMA, do UPDATED/UPDATEDA followed by UPDATEA
	 * (Record to be modified is followed by its replacement in msg.)
	 */
    case UPDATEM:
    case UPDATEMA:

    case UPDATED:
        /*
         * The res code for UPDATED and UPDATEDA is the same; user
         * calls them differently: specifies data for UPDATED; server
         * ignores data if specified for UPDATEDA.
         */
    case UPDATEDA:
        buflen -= RRFIXEDSZ + datalen;
        if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
            return (-1);
        cp += n;
        __putshort(type, cp);
        cp += sizeof(u_short);
        __putshort(qclass, cp);
        cp += sizeof(u_short);
        __putlong(0, cp);
        cp += sizeof(u_long);
        __putshort(datalen, cp);
        cp += sizeof(u_short);
        if (datalen) {
#if !defined (_WINDLL) && !defined( _WIN32)
            bcopy(data, cp, datalen);
#else
            memcpy(cp, data, datalen);
#endif
            cp += datalen;
        }
        if ( (op == UPDATED) || (op == UPDATEDA) ) {
            hp->ancount = htons(0);
            break;
        }
        /* Else UPDATEM/UPDATEMA, so drop into code for UPDATEA */

    case UPDATEA:   /* Add new resource record */
        buflen -= RRFIXEDSZ + datalen;
        if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
            return (-1);
        cp += n;
        __putshort(newrr->r_type, cp);
        cp += sizeof(u_short);
        __putshort(newrr->r_class, cp);
        cp += sizeof(u_short);
        __putlong(0, cp);
        cp += sizeof(u_long);
        __putshort(newrr->r_size, cp);
        cp += sizeof(u_short);
        if (newrr->r_size) {
#if !defined (_WINDLL) && !defined( _WIN32)
            bcopy(newrr->r_data, cp, newrr->r_size);
#else
            memcpy(cp, newrr->r_data, newrr->r_size);
#endif
            cp += newrr->r_size;
        }
        hp->ancount = htons(0);
        break;

#endif /* ALLOW_UPDATES */
    }
    return (cp - buf);
}
