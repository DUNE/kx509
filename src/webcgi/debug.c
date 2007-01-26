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
static int triedtoopen = 0; 
#endif 
 
 
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
    dbgfile = fopen("c:\\temp\\pkcs11dbg.txt", "w"); 
  } 
  if (dbgfile != NULL) 
  { 
    vfprintf(dbgfile, fmt, vargs); 
    fflush(dbgfile); 
  } 
#endif 
 
  va_end(vargs); 
} 
 
 
 
#else			/* UNIX compatible version */ 
 
void log_printf(va_alist) 
char *va_alist;
{ 
#ifdef DEBUG 
  va_list	ap; 
  char	*fmt; 
 
 
  va_start(ap); 
 
  fmt = va_arg(ap, char *); 
  vfprintf(stderr, fmt, ap); 
 
  va_end(ap); 
#endif /* DEBUG */ 
} 
#endif /* ANSI */ 
