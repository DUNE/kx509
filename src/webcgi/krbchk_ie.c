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

#include <stdio.h> 
#include <errno.h> 
#include <string.h> 
#include <fcntl.h> 
 
#ifdef WIN32 
#define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                             // since wincrypt.h and openssl namepsaces collide
                             //  ex. X509_NAME is #define'd and typedef'd ...

#include <winsock.h>         // Must be included before <windows.h> !!! 
#include <windows.h> 
#include "kerb95.h"          // NOTE: This is the "kerberos.h" distributed 
                             // with kerb95, but it conflicts with the 
                             // Microsoft kerberos.h now distributed 
                             // with Windows development environements 
#include "pem.h" 
 
 
#else   /* WIN32 */ 
typedef unsigned long DWORD;
#endif  /* WIN32 */ 
 
 
#include <stdlib.h> 
#include "x509v3.h" 
#ifndef WIN32
#define DES_DEFS		// Prevent collision with K5 DES delarations
#include <krb.h>
#endif /* !WIN32 */
#include "doauth.h" 
#include "debug.h" 
 
 
int connect_x509(char *hostname, u_short port_no); 
 
 
#ifdef PRE_000108
#define X509_CA_HOSTNAME    "x509.citi.umich.edu" 
#else
#define X509_CA_HOSTNAME    "iaa2.ifs.umich.edu" 
#endif

#define KRBCHK_PORT     (u_short)9878 
#define BUF_LEN        2048 
 
 
#define CA_PRINC    "cert" 
#define CA_INST     "x509" 
#ifdef WIN32 
    CHAR    ucRealm[KRB_REALM_SZ]; 
#else 
    char    ucRealm[REALM_SZ+1]; 
#endif 
 
int getcert(RSA *rsa, char *buffer, DWORD *buflen, char **realm)
{ 
    char    *bufptr; 
#ifdef WIN32 
    CHAR    ucPrin[KRB_PRINCIPAL_SZ]; 
    CHAR    ucInst[KRB_INSTANCE_SZ]; 
#else 
    KTEXT_ST   authent; 
    char       dummy[MAX_K_NAME_SZ+1];
#endif 
    DWORD    i; 
    char    *hostname=X509_CA_HOSTNAME;
    char    *keyfile=NULL; 
    char    *outfile=NULL; 
    int     len; 
    int     s; 
#ifndef WIN32
    int     rc;
#endif  /* !WIN32 */
    long    wire_len, read_len, rcv_len; 
 
 
    /* CONNECT TO CA SERVER */ 
 
    if (!(s=connect_x509(hostname, KRBCHK_PORT))) 
    { 
       log_printf("getcert: connect_x509 failed\n"); 
       return(0); 
    } 
 
    bufptr = buffer; 
 
    /* DETERMINE REALM OF USER'S TICKET FILE */
    *realm = NULL;
#ifdef WIN32 
    if (!KrbGetCurrIdentity(ucPrin, ucInst, ucRealm))
    { 
            log_printf("KrbBuildAuthorization failed\n"); 
            return(0); 
    } 
#else
    if (krb_get_tf_fullname(tkt_string(), dummy, dummy, ucRealm))
    { 
            log_printf("krb_get_tf_fullname failed\n"); 
            return(0); 
    } 
#endif
    *realm = (char *)ucRealm;

#ifdef WIN32 
    /* ISSUE KRB4 "krb_mk_req" TO CA SERVER */ 
    strcpy(ucPrin, CA_PRINC); 
    strcpy(ucInst, CA_INST); 
    if (!KrbBuildAuthorization(ucPrin, ucInst, ucRealm, 
                               0, 0, &i, (BYTE *)bufptr, 4)) 
    { 
            log_printf("KrbBuildAuthorization failed\n"); 
            return(0); 
    } 
    log_printf("getcert: sending authentication request (len %d) to application server\n", i); 
    i = send(s, buffer, i, 0); 
#else   /* WIN32 */ 
    /* ISSUE KRB4 "krb_mk_req" TO CA SERVER */ 
    if (rc = krb_mk_req(&authent, CA_PRINC, CA_INST, ucRealm, 0L)) 
    { 
       log_printf("getcert: krb_mk_req failed\n"); 
       return(0); 
    } 
    i = send(s, authent.dat, authent.length, 0); 
#endif  /* WIN32 */ 
 
    /* SEND KEY-PAIR INFO TO CA SERVER */ 
 
    len = i2d_RSAPublicKey (rsa, (unsigned char **)&bufptr); 
     
    /* Send the length of the data, followed by the data itself */ 
 
    wire_len = htonl(len); 
 
    log_printf("getcert: sending %d bytes as length of public key (%d) to server\n", 
       sizeof(wire_len), len); 
 
    i = send(s, (char *)&wire_len, sizeof(wire_len), 0); 
    if (i != sizeof(wire_len)) 
    { 
      log_printf("getcert: error while sending length of the public key to the server (i=%d)\n", i); 
      return(0); 
    } 
 
    log_printf("getcert: sending %d (len) bytes of public key\n", len); 
 
    i = send(s, buffer, len, 0); 
    log_printf("getcert: sent %0d bytes of public key (rc = %d) \n", len, i); 
 
    /* RECV X.509 CERT FROM CA SERVER */ 
 
    i = recv (s, (char *)&wire_len, sizeof(wire_len), 0); 
    if (i != sizeof(wire_len)) 
    { 
       log_printf("getcert: Failed reading length of cert from server\n"); 
       return(0); 
    } 
 
    read_len = ntohl(wire_len); 
    log_printf("getcert: about to receive %d bytes of cert from server\n", read_len); 
 
    rcv_len = 0; 
    while (rcv_len < read_len) 
    { 
       i = recv(s, &buffer[rcv_len], BUF_LEN, 0); 
       if (i == -1) 
       { 
         log_printf("getcert: Failed reading socket\n%s\n", 
             strerror(errno)); 
         return(0); 
       } 
       rcv_len += i; 
    } 
 
#ifdef WIN32 
    closesocket(s); 
#else 
    close(s); 
#endif 
 
    *buflen = read_len; 
    log_printf("getcert: received %0d bytes of cert\n", read_len); 
 
    return(1); 
} 
 
