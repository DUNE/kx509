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
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#ifdef WIN32 
#define __WINCRYPT_H__       // PREVENT windows.h from including wincrypt.h
                             // since wincrypt.h and openssl namepsaces collide
                             //  ex. X509_NAME is #define'd and typedef'd ...

#include <winsock.h> 
#include <windows.h> 
#else /* WIN32 */ 
#include <netdb.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/socketvar.h> 
#include <sys/fcntl.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#endif /* WIN32 */ 
#include "x509v3.h" 
#include "debug.h" 
 
#define	BUF_LEN	2048 
#define	DEFBITS	1024 
 
typedef unsigned long DWORD; 
 
 
int 
connect_x509(char *hostname, u_short port_no) 
{ 
	char *rn = "connect_x509"; 
 
	struct sockaddr_in peeraddr; 
	struct hostent *phostent; 
	int	optrc; 
	int	s; 
 
	struct  linger linger  =  {1, 1};          /* Linger Option set to 1 */ 
						   /*   for 1 second         */ 
 
 
	phostent = gethostbyname (hostname);  
	if( phostent == NULL)  
	{ 
		log_printf("%s: unknown host\n", rn); 
		return 0; 
	} 
 
	log_printf("%s: Host official name: %s\n", rn, phostent->h_name); 
 
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)  
	{ 
#ifdef WIN32 
		log_printf("%s: Failed creating socket 0x%08x (%d)\n", 
		        rn, WSAGetLastError(), WSAGetLastError()); 
#else 
		log_printf("%s: Failed creating socket\n%s\n", 
		        rn, strerror(errno)); 
#endif 
		return 0; 
	} 
 
	log_printf("%s: Issuing connect to port %d\n", rn, port_no); 
	peeraddr.sin_family = AF_INET; 
	peeraddr.sin_port   = htons(port_no); 
	peeraddr.sin_addr.s_addr = ((struct in_addr *)(phostent->h_addr))->s_addr; 
	if (connect(s, (struct sockaddr *) &peeraddr, sizeof(struct sockaddr_in))  == -1)  
	{ 
#ifdef WIN32 
        log_printf("%s: Failed connecting socket 0x%08x (%d)\n", 
                rn, WSAGetLastError(), WSAGetLastError()); 
#else 
		log_printf("%s: Failed connecting socket\n%s\n", 
		        rn, strerror(errno));  
#endif 
  
		return 0; 
	} 
 
	/* 
	** set the linger option.  This gives us a "Graceful" close 
	** meaning we receive all the data before the socket closes. 
	*/ 
	optrc = setsockopt (s, SOL_SOCKET, SO_LINGER,  
		               (char *) &linger, sizeof (struct linger)); 
	if (optrc == -1) 
		log_printf("%s: Unable to set linger option on socket\n%s\n", 
		            rn, strerror(errno)); 
	return s; 
} 
 
 
