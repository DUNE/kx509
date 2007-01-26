// WIN32 ONLY FILE	--	billdo 2001.0522

/*
 *	@doc RESOLVE
 *
 *	
 *	@module res_send.c | Contains the implementation of res_send
 *
 *
 *
	WSHelper DNS/Hesiod Library for WINSOCK
 */

/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
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
static char sccsid[] = "@(#)res_send.c	6.27 (Berkeley) 2/24/91";
#endif /* LIBC_SCCS and not lint */

/*
 * Send query to name server and wait for reply.
 */

#include <time.h>
#include <windows.h>
#include <winsock.h>

#define __DECLDLL__H
#undef  EXPORT
#undef  EXPORT32
#define EXPORT
#define EXPORT32

#include <arpa/nameser.h>
#include <stdio.h>
#include <resolv.h>
#include <string.h>

#include "u-compat.h"


#ifdef _DEBUG
#define DEBUG
#endif

#if defined (_WINDLL) || defined(_WINDOWS) || defined (_WIN32)
#define IS_WINDOWS
#else
#undef IS_WINDOWS
#endif

#ifdef IS_WINDOWS
#define IS_BAD_SOCKET(x) ((x) == INVALID_SOCKET)
#define GET_SOCKET_ERROR WSAGetLastError()
#define PRINT_STRING OutputDebugString
#define PERROR(x) \
{ \
    wsprintf(debstr, "res_send: %s (winsock error %d)\n", \
             x, WSAGetLastError()); \
    OutputDebugString(debstr); \
}
#define PSTDERR OutputDebugString
#define READ_SOCKET(a, b, c) recv(a, b, c, 0)
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#else
#define SOCKET int
#define IS_BAD_SOCKET(x) ((x) < 0)
#define GET_SOCKET_ERROR errno
#define PRINT_STRING printf
#define closesocket close
#define INVALID_SOCKET -1
#define wsprintf sprintf
#define PERROR perror
#define PSTDERR(x) fprintf(stderr, x)
#define READ_SOCKET read
#endif

#ifdef IS_WINDOWS
#if SOCKET_ERROR >= 0
#error "SOCKET_ERROR >= 0 -- see this line in the source for details"
/*
   If SOCKET_ERROR is non-negative, then search for (n <= 0) and
   replace it for (n == SOCKET_ERROR) || (n == 0)
   and search for (n < 0) and replace if for (n == SOCKET_ERROR)
*/
#endif
#endif

static SOCKET s = INVALID_SOCKET;
static struct sockaddr no_addr;

#ifndef FD_SET
#define NFDBITS         32
#define FD_SETSIZE      32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif

#if defined(DEBUG)
/* For debugging output */
char debstr[80];
#endif

#ifdef _WINDLL
void __p_query(char *);
#endif

/*

  @func EXPORT32 int EXPORT WINAPI | res_send |

   sends a query to name servers and returns an answer. It will call
   res_init() if RES_INIT is not set, send the query to the local name
   server, and handle timeouts and retries.  The length of the message
   is returned or -1 if there were errors.

Remarks

RES_AAONLY - Accept authoritative answers only. res_send() will
continue until it finds an authoritative answer or finds an error.
Currently this is not implemented.

RES_RECURSE - Set the recursion desired bit in queries. This is the
default. res_send() does not do iterative queries and expects the name
server to handle recursion.

  @parm const char *| buf | contains the query to send
  @parm int | buflen | the length of the query
  @parm char *| answer | the answer returned if any
  @parm int | anslen | the length of the answer

  @rdesc  The length of the message is returned or -1 if there were errors.

*/
#ifdef _WINDLL
EXPORT32 int EXPORT WINAPI
#endif
res_send(const char *buf, int buflen, char *answer, int anslen)
{
    register int n;
    int try, v_circuit, resplen, ns;
    int gotsomewhere = 0, connected = 0;
    int connreset = 0;
    u_short id, len;
    char *cp;
    fd_set dsmask;
    struct timeval timeout;
    HEADER *hp = (HEADER *) buf;
    HEADER *anhp = (HEADER *) answer;
#ifdef IS_WINDOWS
    HGLOBAL hTmpbuf;
    char *lpTmpbuf;
    int terrno = WSAETIMEDOUT;
#else
    struct iovec iov[2];
    int terrno = ETIMEDOUT;
#endif
    char junk[512];
    int write_failed;

#ifdef DEBUG
    if (_res.options & RES_DEBUG) {
        PRINT_STRING("res_send()\n");
        __p_query((char *)buf);
    }
#endif /* DEBUG */
    if (!(_res.options & RES_INIT))
        if (res_init() == -1) {
            return(-1);
        }
    v_circuit = (_res.options & RES_USEVC) || buflen > PACKETSZ;
    id = hp->id;
    /*
     * Send request, RETRY times, or until successful
     */
    for (try = 0; try < _res.retry; try++) {
        for (ns = 0; ns < _res.nscount; ns++) {
#ifdef DEBUG
            if (_res.options & RES_DEBUG) {
                wsprintf(debstr, "Querying server (# %d) address = %s\n",
                         ns+1, inet_ntoa(_res.nsaddr_list[ns].sin_addr));
                PRINT_STRING(debstr);
            }
#endif /* DEBUG */

            if( !_res.nsaddr_list[ns].sin_addr.S_un.S_addr )
		continue;	/* address of DNS server is 0.0.0.0 don't make a call XXX 11/20/96 */

	usevc:
            if (v_circuit) {
                int truncated = 0;

                /*
                 * Use virtual circuit;
                 * at most one attempt per server.
                 */
                try = _res.retry;

                if (IS_BAD_SOCKET(s)) {
                    s = socket(AF_INET, SOCK_STREAM, 0);
                    if (IS_BAD_SOCKET(s)) {
                        terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("socket (vc) failed");
#endif /* DEBUG */
                        continue;
                    }

                    if (IS_BAD_SOCKET(connect(s, (struct sockaddr *)
                                                &(_res.nsaddr_list[ns]),
                                                sizeof(struct sockaddr)))) {
                        terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("connect failed");
#endif /* DEBUG */
                        (void) closesocket(s);
                        s = INVALID_SOCKET;
                        continue;
                    }
                }
                /*
                 * Send length & message
                 */
                len = htons((u_short)buflen);
#ifndef IS_WINDOWS
                iov[0].iov_base = (caddr_t)&len;
                iov[0].iov_len = sizeof(len);
                iov[1].iov_base = (char *)buf;
                iov[1].iov_len = buflen;
                write_failed = (writev(s, iov, 2) != sizeof(len) + buflen);
#else
                hTmpbuf = GlobalAlloc(GHND, sizeof(len) + buflen);
                lpTmpbuf = GlobalLock(hTmpbuf);
                memcpy(lpTmpbuf, &len, sizeof(len));
                memcpy(sizeof(len)+lpTmpbuf, buf, buflen);
                write_failed = ((unsigned) send(s, lpTmpbuf, 
                                                sizeof(len) + buflen, 0) !=
                                sizeof(len) + buflen);
                GlobalUnlock(hTmpbuf);
                GlobalFree(hTmpbuf);
#endif
                if (write_failed) {
                    terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PERROR("write failed");
#endif /* DEBUG */
                    (void) closesocket(s);
                    s = INVALID_SOCKET;
                    continue;
                }
                /*
                 * Receive length & response
                 */
                cp = answer;
                len = sizeof(short);
                while (len != 0 &&
                       (n = recv(s, (char *)cp, (int)len, 0)) > 0)
                {
                    cp += n;
                    len -= n;
                }
                if (n <= 0) {
                    terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PERROR("read failed");
#endif /* DEBUG */
                    (void) closesocket(s);
                    s = INVALID_SOCKET;
                    /*
                     * A long running process might get its TCP
                     * connection reset if the remote server was
                     * restarted.  Requery the server instead of
                     * trying a new one.  When there is only one
                     * server, this means that a query might work
                     * instead of failing.  We only allow one reset
                     * per query to prevent looping.
                     */
                    if (terrno == ECONNRESET && !connreset) {
                        connreset = 1;
                        ns--;
                    }
                    continue;
                }
                cp = answer;
                if ((resplen = ntohs(*(u_short *)cp)) > anslen) {
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PSTDERR("response truncated\n");
#endif /* DEBUG */
                    len = anslen;
                    truncated = 1;
                } else
                    len = resplen;
                while (len != 0 &&
                       (n = READ_SOCKET(s, (char *)cp, (int)len)) > 0) {
                    cp += n;
                    len -= n;
                }
                if (n <= 0) {
                    terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PERROR("read failed");
#endif /* DEBUG */
                    (void) closesocket(s);
                    s = INVALID_SOCKET;
                    continue;
                }
                if (truncated) {
                    /*
                     * Flush rest of answer
                     * so connection stays in synch.
                     */
                    anhp->tc = 1;
                    len = resplen - anslen;
                    while (len != 0) {
                        n = (len > sizeof(junk) ?
                             sizeof(junk) : len);
                        if ((n = READ_SOCKET(s, junk, n)) > 0)
                            len -= n;
                        else
                            break;
                    }
                }
            } else { /* !vc_circuit */
                /*
                 * Use datagrams.
                 */
                if (IS_BAD_SOCKET(s)) {
                    s = socket(AF_INET, SOCK_DGRAM, 0);
                    if (IS_BAD_SOCKET(s)) {
                        terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("socket (dg) failed");
#endif /* DEBUG */
                        continue;
                    }
//#define USE_SENDTO
#ifndef USE_SENDTO
                    if (IS_BAD_SOCKET(connect(s, (struct sockaddr *)
                                                &(_res.nsaddr_list[ns]),
                                                sizeof(struct sockaddr)))) {
                        terrno = GET_SOCKET_ERROR;
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("connect failed");
#endif /* DEBUG */
                        (void) closesocket(s);
                        s = INVALID_SOCKET;
                        continue;
                    }
#endif /* USE_SENDTO */
                }
#if BSD >= 43
                /*
                 * I'm tired of answering this question, so:
                 * On a 4.3BSD+ machine (client and server,
                 * actually), sending to a nameserver datagram
                 * port with no nameserver will cause an
                 * ICMP port unreachable message to be returned.
                 * If our datagram socket is "connected" to the
                 * server, we get an ECONNREFUSED error on the next
                 * socket operation, and select returns if the
                 * error message is received.  We can thus detect
                 * the absence of a nameserver without timing out.
                 * If we have sent queries to at least two servers,
                 * however, we don't want to remain connected,
                 * as we wish to receive answers from the first
                 * server to respond.
                 */
                if (_res.nscount == 1 || (try == 0 && ns == 0)) {
                    /*
                     * Don't use connect if we might
                     * still receive a response
                     * from another server.
                     */
                    if (connected == 0) {
			if (IS_BAD_SOCKET(connect(s, (struct sockaddr *)
                                                    &_res.nsaddr_list[ns],
                                                    sizeof(struct sockaddr)))){
#ifdef DEBUG
                            if (_res.options & RES_DEBUG)
                                PERROR("connect");
#endif /* DEBUG */
                            continue;
                        }
                        connected = 1;
                    }
                    if (send(s, buf, buflen, 0) != buflen) {
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("send");
#endif /* DEBUG */
                        continue;
                    }
                } else {
                    /*
                     * Disconnect if we want to listen
                     * for responses from more than one server.
                     */
                    if (connected) {
                        (void) connect(s, &no_addr,
                                       sizeof(no_addr));
                        connected = 0;
                    }
#endif /* BSD */
                    if (
#ifdef USE_SENDTO
                        (sendto(s, buf, buflen, 0,
                                (struct sockaddr *)&_res.nsaddr_list[ns],
                                sizeof(struct sockaddr)) != buflen)
#else
                        (send(s, buf, buflen, 0) != buflen)
#endif /* USE_SENDTO */
                        ) {
#ifdef DEBUG
                        if (_res.options & RES_DEBUG)
                            PERROR("sendto");
#endif /* DEBUG */
                        continue;
                    }
#if BSD >= 43
                }
#endif

                /*
                 * Wait for reply
                 */
                timeout.tv_sec = (_res.retrans << try);
                if (try > 0)
                    timeout.tv_sec /= _res.nscount;
                if (timeout.tv_sec <= 0)
                    timeout.tv_sec = 1;
                timeout.tv_usec = 0;
wait:
                FD_ZERO(&dsmask);
                FD_SET(s, &dsmask);
                n = select(s+1, &dsmask, (fd_set *)NULL,
                           (fd_set *)NULL, &timeout);
                if (n < 0) {
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PERROR("select");
#endif /* DEBUG */
#ifndef USE_SENDTO
                    closesocket(s);
                    s = INVALID_SOCKET;
#endif
                    continue;
                }
                if (n == 0) {
                    /*
                     * timeout
                     */
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PRINT_STRING("timeout\n");
#endif /* DEBUG */
#if BSD >= 43
                    gotsomewhere = 1;
#endif
#ifndef USE_SENDTO
                    closesocket(s);
                    s = INVALID_SOCKET;
#endif
                    continue;
                }

                if ((resplen = recv(s, answer, anslen, 0)) <= 0) {
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PERROR("recvfrom");
#endif /* DEBUG */
#ifndef USE_SENDTO
                    closesocket(s);
                    s = INVALID_SOCKET;
#endif
                    continue;
                }
                gotsomewhere = 1;
                if (id != anhp->id) {
                    /*
                     * response from old query, ignore it
                     */
#ifdef DEBUG
                    if (_res.options & RES_DEBUG) {
                        PRINT_STRING("old answer:\n");
                        __p_query(answer);
                    }
#endif /* DEBUG */
                    goto wait;
                }
                if (!(_res.options & RES_IGNTC) && anhp->tc) {
                    /*
                     * get rest of answer;
                     * use TCP with same server.
                     */
#ifdef DEBUG
                    if (_res.options & RES_DEBUG)
                        PRINT_STRING("truncated answer\n");
#endif /* DEBUG */
                    (void) closesocket(s);
                    s = INVALID_SOCKET;
                    v_circuit = 1;
                    goto usevc;
                }
            }
#ifdef DEBUG
            if (_res.options & RES_DEBUG) {
                PRINT_STRING("got answer:\n");
                __p_query(answer);
            }
#endif /* DEBUG */
            /*
             * If using virtual circuits, we assume that the first server
             * is preferred * over the rest (i.e. it is on the local
             * machine) and only keep that one open.
             * If we have temporarily opened a virtual circuit,
             * or if we haven't been asked to keep a socket open,
             * close the socket.
             */
            if ((v_circuit &&
                 ((_res.options & RES_USEVC) == 0 || ns != 0)) ||
                (_res.options & RES_STAYOPEN) == 0) {
                (void) closesocket(s);
                s = INVALID_SOCKET;
            }
            return (resplen);
        }
    }
    if (!IS_BAD_SOCKET(s)) {
        (void) closesocket(s);
        s = INVALID_SOCKET;
    }
#ifndef IS_WINDOWS
    if (v_circuit == 0)
        if (gotsomewhere == 0)
            errno = ECONNREFUSED;   /* no nameservers found */
        else
            errno = ETIMEDOUT;      /* no answer obtained */
    else
        errno = terrno;
#else
    if (v_circuit == 0)
        if (gotsomewhere == 0)
            WSASetLastError(WSAECONNREFUSED);
        else
            WSASetLastError(WSAETIMEDOUT);
    else
        WSASetLastError(terrno);
#endif
    return (-1);
}

/*
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
#ifdef _WINDLL
void
#endif
_res_close()
{
    if (!IS_BAD_SOCKET(s)) {
        (void) closesocket(s);
        s = INVALID_SOCKET;
    }
}
