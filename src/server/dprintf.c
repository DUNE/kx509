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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
int debug_mask;
#include <stdio.h>
#include <time.h>
char *ctime();

#ifdef HAVE_VFPRINTF
#ifdef HAVE_STDARG_H
#define USE_STDARG 1
#else
#define USE_VARARGS 1
#endif
#else
#define va_list long *
#endif

#ifdef USE_VARARGS
#include <varargs.h>
#endif
#ifdef USE_STDARG
#include <stdarg.h>
#endif

int general_debug;
FILE *debug_output;
int debug_notatstartofline;

#ifndef HAVE_VFPRINTF
dprintf(debugflag, fmt, args)
	long args;
	char *fmt;
#endif
#ifdef USE_VARARGS
dprintf(debugflag, fmt, va_alist)
	va_dcl
	char *fmt;
#endif
#ifdef USE_STDARG
dprintf(int debugflag, char *fmt, ...)
#endif
{
#ifdef HAVE_VFPRINTF
	va_list args;
#endif
	char *f;
	long now;

	if (!debugflag && !general_debug) return;
	if (!debug_output)
		debug_output = stderr;
#ifdef USE_VARARGS
	va_start(args);
#endif
#ifdef USE_STDARG
	va_start(args, fmt);
#endif
	if (!debug_notatstartofline)
	{
		now = time(0);
#ifdef CRYPTIC_LOGS
		fprintf (debug_output, "%d: bug ", now);
#else
		fprintf (debug_output, "%.15s: bug ", ctime(&now) + 4);
#endif

	}
#ifndef HAVE_VFPRINTF
	fprintf(debug_output, fmt,
		(&args)[0], (&args)[1], (&args)[2],
		(&args)[3], (&args)[4], (&args)[5],
		(&args)[6], (&args)[7], (&args)[8],
		(&args)[9], (&args)[10]);
#else
	vfprintf(debug_output, fmt, args);
	va_end (args);
#endif
	fflush(debug_output);
	if (*(f = fmt)) {
		for (; *f; ++f)
			;
		debug_notatstartofline = *--f != '\n';
	}
}

FILE *logfile;
#define log_notatstartofline debug_notatstartofline

vlogprintf(label, fmt, args)
	char *label;
	char *fmt;
	va_list args;
{
	long now;
	char *f;
#if 0
	printf ("vlogprintf: fmt=%lx args=%lx\n", fmt, args);
#endif
	if (!logfile)
		logfile = stderr;

	if (!log_notatstartofline)
	{
		now = time(0);
#ifdef CRYPTIC_LOGS
		fprintf (logfile, "%d: %s ", now, label);
#else
		fprintf (logfile, "%.15s: %s ", ctime(&now)+4, label);
#endif
	}
#ifndef HAVE_VFPRINTF
	fprintf(logfile, fmt,
		args[0], args[1], args[2], args[3], args[4], args[5],
		args[6], args[7], args[8], args[9], args[10]);
#else
	vfprintf(logfile, fmt, args);
#endif
	fflush(logfile);
	if (*(f = fmt)) {
		for (; *f; ++f)
			;
		log_notatstartofline = *--f != '\n';
	}
}

#ifndef HAVE_VFPRINTF
logprintf(label, fmt, args)
	char *label;
	long args;
#endif
#ifdef USE_VARARGS
logprintf(label, fmt, va_alist)
	char *label;
	va_dcl
	char *fmt;
#endif
#ifdef USE_STDARG
logprintf(char *label, char *fmt, ...)
#endif
{
	va_list args;
#ifdef USE_VARARGS
	va_start(args);
#endif
#ifdef USE_STDARG
	va_start(args, fmt);
#endif
#if 0
	printf ("tagprintf: fmt=%lx &fmt=%lx args=%lx\n",
		fmt, &fmt, args);
#endif
#ifndef HAVE_VFPRINTF
	vlogprintf(label, fmt, &args);
#else
	vlogprintf(label, fmt, args);
#endif
#ifdef HAVE_VFPRINTF
	va_end (args);
#endif
}

/*
 *	log call print - call this to log routine messages.
 *	the format string should end with a newline.
 */

#ifndef HAVE_VFPRINTF
int
lcprintf(fmt, args)
	long args;
	char *fmt;
{
	va_list args;

	va_start(args);
	vlcprintf("log", fmt, &args);
	va_end (args);
}
#endif

#ifdef USE_VARARGS
int
lcprintf(fmt, va_alist)
	va_dcl
	char *fmt;
{
	va_list args;

	va_start(args);
	vlcprintf("log", fmt, args);
	va_end (args);
}
#endif

#ifdef USE_STDARG
int
lcprintf(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlcprintf("log", fmt, args);
	va_end (args);
}
#endif

/*
 *	error (log call) print - called to log
 *	an exception.
 *	the format string should end with a newline.
 */

#ifndef HAVE_VFPRINTF
elcprintf(fmt, args)
	long args;
	char *fmt;
{
	va_list args;

	va_start(args);
	vlcprintf("err", fmt, &args);
	va_end (args);
}
#endif

#ifdef USE_VARARGS
elcprintf(fmt, va_alist)
	va_dcl
	char *fmt;
{
	va_list args;

	va_start(args);
	vlcprintf("err", fmt, args);
	va_end (args);
}
#endif

#ifdef USE_STDARG
elcprintf(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlcprintf("err", fmt, args);
	va_end (args);
}
#endif

vlcprintf(tag, fmt, args)
	char *tag;
	char *fmt;
	va_list args;
{
#ifdef VERBOSE_LOGS
	log_print_caller(tag);
#endif
	vlogprintf (tag, fmt, args);
}

/*
 * Open the log file(s).  Use the current date to
 * formulate the log file name
 */
OpenLogfiles()
{
	FILE *f;
	char fn[512];
	long now;
	struct tm *tp;
	extern char* logfile_name;

	now = time(0);
	tp = localtime(&now);
	sprintf (fn, "%s.%04d%02d%02d", logfile_name, tp->tm_year + 1900,
		tp->tm_mon + 1,
		tp->tm_mday);

	logfile = fopen(fn, "a");
	if (!logfile)
		logfile = stderr;
	debug_output = logfile;
	lcprintf("Begin logging\n");
}

/*
 * Reopen the log file(s).  This is called after
 * receiving a SIGHUP signal.  It allows the log
 * files to be rotated daily.
 */
ReopenLogfiles()
{
	if (logfile == stderr) return;

	lcprintf("Reopening the log file ...\n");
	fclose(logfile);

	OpenLogfiles();
}

set_debug_mask(cp)
	char *cp;
{
	int mf, m, result;
	result = 0;
	mf = 0;
	while (*cp)
	{
		m = 0;
		if (*cp == '*')
			m = ~0, ++cp;
		else if (*cp >= '0' && *cp <= '9')
		{
			while (*cp >= '0' && *cp <= '9')
			{
				m *= 10;
				m += (*cp++) - '0';
			}
		} else {
			if (*cp > 'a' && *cp < 'z')
				m = 1L << (*cp - ('@' + ('a' - 'A')));
			else
				m = 1L << (*cp - '@');
			++cp;
		}
		if (mf)
			result &= ~m;
		else
			result |= m;
		mf = 0;
		if (*cp == '-')
			mf = 1, ++cp;
	}
	debug_mask = result;
dprintf (1,"set debug mask = %ld\n", debug_mask);
}
