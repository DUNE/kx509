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

#include "debug.h" 

/* Debug file for windows release version */ 
#ifndef DEBUG 
static FILE *dbgfile = NULL; 
#ifdef DEBUGGING_RELEASE
static int triedtoopen = 0; 		/* if debugging, create log file */
#else /* !DEBUGGING_RELEASE */
static int triedtoopen = 1; 		/* if not debugging, don't create log file */
#endif /* !DEBUGGING_RELEASE */
#endif 

#ifdef WIN32
extern	BOOL 	bSilent;
#endif /* WIN32 */
 
 
#ifdef WIN32 
 
void log_printf(char *fmt, ...) 
{ 
#ifdef DEBUG 
  char buffer[2048]; 
#endif 
 
  va_list vargs; 
 
  va_start(vargs,fmt); 
 
#ifdef DEBUG 
  vsprintf(buffer, fmt, vargs); 
  OutputDebugString(buffer); 
#else 
  if (dbgfile == NULL && triedtoopen == 0) 
  { 
    triedtoopen = 1; 
    dbgfile = fopen("c:\\temp\\kx509dbg.txt", "w"); 
  } 
  if (dbgfile != NULL) 
  { 
    vfprintf(dbgfile, fmt, vargs); 
    fflush(dbgfile); 
  } 
#endif 
 
  va_end(vargs); 
} 
 
#elif defined(macintosh)	/* macintosh version */

void log_printf(char *fmt, ...) 
{ 
#ifdef DEBUG 
	va_list	args;
 
	va_start(args, fmt); 
	vfprintf(stderr, fmt, args); 
 	va_end(args); 
#endif /* DEBUG */ 
}
 
#else	/* UNIX compatible version */ 
 
 

void log_printf(char *fmt, ...) 
{ 
  extern int debugPrint;
  va_list vargs; 
 
  if (debugPrint)
  {
    va_start(vargs, fmt); 
 
    vfprintf(stderr, fmt, vargs); 
 
    va_end(vargs); 
  }
} 

#endif /* WIN32 */ 




#ifdef WIN32 
 
void msg_printf(char *fmt, ...) 
{ 
  char buffer[2048]; 
 
  va_list vargs; 
 
  va_start(vargs,fmt); 
 
  vsprintf(buffer, fmt, vargs); 

  if (!bSilent)
	  MessageBox(0, buffer, "KX509: Kerberized acquisition of X.509 Certificate", MB_OK);
 
  va_end(vargs); 
} 
 
#elif defined(macintosh)	/* macintosh version */

void msg_printf(char *fmt, ...)
{ 
	va_list	args;
 
	va_start(args, fmt); 
	vfprintf(stdout, fmt, args); 
 	va_end(args); 
}
 
#else	/* UNIX compatible version */ 
 

void msg_printf(char *fmt, ...) 
{ 
  va_list vargs; 
 
  va_start(vargs, fmt); 
 
  vfprintf(stderr, fmt, vargs); 
 
  va_end(vargs); 
} 

#endif	/* WIN32 */ 

void log_hexdump(char * comment, void * in, int len)
{
    unsigned char *p = (unsigned char *)in;
    int i;

    log_printf("%s",comment);
    for (i=0; i<len; i++)
    {
        if ((i & 3) == 0) log_printf(" ");
        if ((i & 31) == 0) log_printf("\n    ");
        log_printf("%02x", p[i]);
    }
    log_printf("\n");
}
