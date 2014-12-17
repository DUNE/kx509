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

#define MAXSTRLEN 	512
#define MAX_CERT_LEN	4096

/* attr name; attr values, separate by... who knows. spaces for now, yuck*/
typedef struct a_t {
  char *name;
  char *value;
} a_t;

void zeroit();

int parsepin();
#define NOSEP -1
char *concat(int sep,...);
char *strnchr();
char *getelt(a_t **alist, char *name);
int name_ok();
int doauth(a_t ***attrl, a_t ***tattrl);
#if defined(KX509_LIB)
int getcert(char *myserver, RSA **, X509 **, char *, int, char *, char *);
#else
int getcert(char *myserver, RSA **, X509 **, char *, int, char *);
#endif
RSA *client_genkey(int);
int bin_dump(char *cp, int s);
