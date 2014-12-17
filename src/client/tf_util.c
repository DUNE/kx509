/* 
  Copyright (C) 1989 by the Massachusetts Institute of Technology

   Export of this software from the United States of America may
   require a specific license from the United States Government.
   It is the responsibility of any person or organization contemplating
   export to obtain such a license before exporting.

WITHIN THAT CONSTRAINT, Permission to use, copy, modify, and
distribute this software and its documentation for any purpose and
without fee is hereby granted, provided that the above copyright
notice appear in all copies and that both that copyright notice and
this permission notice appear in supporting documentation, and that
the name of M.I.T. not be used in advertising or publicity pertaining
to distribution of the software without specific, written prior
permission.  Furthermore if you modify this software you must label
your software as modified software and not distribute it in such a
fashion that it might be confused with the original M.I.T. software.
M.I.T. makes no representations about the suitability of
this software for any purpose.  It is provided "as is" without express
or implied warranty.

  */

/*
 * This file differs from the original tf_util.c in the following way:
 *	references to TKT_SHMEM have been removed
 *	no locking is done
 *	tf_init() for writing: any old file will be unlocked, destroyed, and created, before opening
 *	tf_init() for reading: the file will be opened
 */

#ifndef macintosh
# include "mit-copyright.h"
#endif /* !macintosh */

#ifdef macintosh
# include <KClient.h>
  /* constants that krb.h defines, but KClient.h does not */
# define NO_TKT_FIL	76
# define TKT_FIL_ACC	77
# define TKT_FIL_LCK	78
# define TKT_FIL_FMT	79
# define TKT_FIL_INI	80
# define KSUCCESS 0
# define KFAILURE 255
# define TKT_FILE "tktfile"
# define R_TKT_FIL 0
# define W_TKT_FIL 1
#else /* !macintosh */
# include <krb.h>
#endif /* macintosh */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef macintosh
# include <Errors.h>
# include <Files.h>
# include <Folders.h>
# include <unix.h>
  FSSpec spec;
# include "debug.h"
# define CALL_NOT_IN_CARBON 1
# include <TextUtils.h>
# undef CALL_NOT_IN_CARBON
#else /* !macintosh */
# include <sys/file.h>
#endif /* macintosh */

#include <fcntl.h>


#define TOO_BIG -1
#define TF_LCK_RETRY ((unsigned)2)	/* seconds to sleep before
					 * retry if ticket file is
					 * locked */
#ifdef macintosh
  int krb_debug = 0;
  extern int errno;
#else /* !macintosh */
  extern int krb_debug;
#endif /* macintosh */

#ifdef NEED_UTIMES
# include <sys/time.h>
# include <unistd.h>
# ifdef __SCO__
#  include <utime.h>
# endif /* __SCO__ */
# if defined(__svr4__) || defined(__SVR4)
#  include <utime.h>
# endif /* __svr4__ || __SVR4 */
  int utimes(path, times)
     char* path;
     struct timeval times[2];
  {
    struct utimbuf tv;
    tv.actime = times[0].tv_sec;
    tv.modtime = times[1].tv_sec;
    return utime(path,&tv);
  }
#endif /* NEED_UTIMES */

#ifndef LOCK_SH
# define   LOCK_SH   1    /* shared lock */
# define   LOCK_EX   2    /* exclusive lock */
# define   LOCK_NB   4    /* don't block when locking */
# define   LOCK_UN   8    /* unlock */
#endif /* LOCK_SH */

#include "tf_util.h"

#ifdef POSIX_FILE_LOCKS

/*
 * This function emulates a subset of flock()
 */
int emul_flock(int fd, int cmd)
{
    static struct flock flock_zero;
    struct flock f;

    f = flock_zero;

    memset(&f, 0, sizeof (f));

    if (cmd & LOCK_UN)
	f.l_type = F_UNLCK;
    if (cmd & LOCK_SH)
	f.l_type = F_RDLCK;
    if (cmd & LOCK_EX)
	f.l_type = F_WRLCK;

    return fcntl(fd, (cmd & LOCK_NB) ? F_SETLK : F_SETLKW, &f);
}

#define flock(f,c)	emul_flock(f,c)
#endif /* POSIX_FILE_LOCKS */

/*
 * fd must be initialized to something that won't ever occur as a real
 * file descriptor. Since open(2) returns only non-negative numbers as
 * valid file descriptors, and tf_init always stuffs the return value
 * from open in here even if it is an error flag, we must
 * 	a. Initialize fd to a negative number, to indicate that it is
 * 	   not initially valid.
 *	b. When checking for a valid fd, assume that negative values
 *	   are invalid (ie. when deciding whether tf_init has been
 *	   called.)
 *	c. In tf_close, be sure it gets reinitialized to a negative
 *	   number. 
 */

#ifdef macintosh
  static short refnum;
#else /* !macintosh */
  static int  fd = -1;
#endif /* macintosh */

static int  curpos;			/* Position in tfbfr */
static int  lastpos;			/* End of tfbfr */
static char tfbfr[BUFSIZ];		/* Buffer for ticket data */

static tf_gets(), tf_read();

/*
 * This file contains routines for manipulating the ticket cache file.
 *
 * The ticket file is in the following format:
 *
 *      principal's name        (null-terminated string)
 *      principal's instance    (null-terminated string)
 *      CREDENTIAL_1
 *      CREDENTIAL_2
 *      ...
 *      CREDENTIAL_n
 *      EOF
 *
 *      Where "CREDENTIAL_x" consists of the following fixed-length
 *      fields from the CREDENTIALS structure (see "krb.h"):
 *
 *              char            service[ANAME_SZ]
 *              char            instance[INST_SZ]
 *              char            realm[REALM_SZ]
 *              C_Block         session
 *              int             lifetime
 *              int             kvno
 *              KTEXT_ST        ticket_st
 *              long            issue_date
 *
 * Short description of routines:
 *
 * tf_init() opens the ticket file and locks it.
 *
 * tf_get_pname() returns the principal's name.
 *
 * tf_get_pinst() returns the principal's instance (may be null).
 *
 * tf_get_cred() returns the next CREDENTIALS record.
 *
 * tf_save_cred() appends a new CREDENTIAL record to the ticket file.
 *
 * tf_close() closes the ticket file and releases the lock.
 *
 * tf_gets() returns the next null-terminated string.  It's an internal
 * routine used by tf_get_pname(), tf_get_pinst(), and tf_get_cred().
 *
 * tf_read() reads a given number of bytes.  It's an internal routine
 * used by tf_get_cred().
 */

/*
 * tf_init() should be called before the other ticket file routines.
 * It takes the name of the ticket file to use, "tf_name", and a
 * read/write flag "rw" as arguments. 
 *
 * It tries to open the ticket file, checks the mode, and if everything
 * is okay, locks the file.  If it's opened for reading, the lock is
 * shared.  If it's opened for writing, the lock is exclusive. 
 *
 * Returns KSUCCESS if all went well, otherwise one of the following: 
 *
 * NO_TKT_FIL   - file wasn't there
 * TKT_FIL_ACC  - file was in wrong mode, etc.
 * TKT_FIL_LCK  - couldn't lock the file, even after a retry
 */

int tf_init(char *tf_name, int rw)
{
    int     wflag;
#ifdef macintosh
    SInt16 TempItemsVRefNum;
    SInt32 TempItemsDirID;
    char p_tf_name[64];
    OSType folderType;
    OSErr err;
#else /* !macintosh */
    uid_t   me, getuid();
    struct stat stat_buf;
#endif /* !macintosh */

    switch (rw) {
    case R_TKT_FIL:
	wflag = 0;
	break;
    case W_TKT_FIL:
	wflag = 1;
	break;
    default:
	if (krb_debug) fprintf(stderr, "tf_init: illegal parameter\n");
	log_printf("tf_init: rw not R_TKT_FIL nor W_TKT_FIL\n");
	return TKT_FIL_ACC;
    }

    /* If ticket cache selector is null, use default cache.  */
    if (tf_name == 0)
#ifdef macintosh
	tf_name = TKT_FILE;
#else /* !macintosh */
	tf_name = tkt_string();
#endif /* macintosh */

#ifdef macintosh
    /* check length of tf_name, copy it locally, and turn it into a P string*/
    if (strlen(tf_name) > sizeof(p_tf_name))
 	return NO_TKT_FIL;
    strcpy(p_tf_name, tf_name);
    c2pstr(p_tf_name);
        
    /* find the :Temporary Items: folder on the System disk */
# ifdef DEBUG
    folderType = kSystemDesktopFolderType;
# else /* !DEBUG */
    folderType = kTemporaryFolderType;
# endif /* DEBUG */
    if ((err = FindFolder(kOnSystemDisk, folderType, kCreateFolder,
		&TempItemsVRefNum, &TempItemsDirID)) != noErr && (err != fnfErr)) {
	log_printf("tf_init: FindFolder returned %d\n", err);
	return TKT_FIL_ACC;
    }

    /* get a FSSpec for file file located in the :Temporary Items: folder */
    if (((err = FSMakeFSSpec(TempItemsVRefNum, TempItemsDirID,
		(const unsigned char *)p_tf_name, &spec)) != noErr) && (err != fnfErr)) {
	log_printf("tf_init: FsMakeFsSSpec returned %d\n", err);
	return TKT_FIL_ACC;

    }
#endif /* macintosh */

#ifndef macintosh
    if (lstat(tf_name, &stat_buf) < 0)
	switch (errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}

    me = getuid();
    if ((stat_buf.st_uid != me && me != 0) ||
	((stat_buf.st_mode & S_IFMT) != S_IFREG)) {
	log_printf("tf_init: stat results look bad\n");
	return TKT_FIL_ACC;
    }
#endif /* !macintosh */

    /*
     * If "wflag" is set, open the ticket file in append-writeonly mode
     * and lock the ticket file in exclusive mode.  If unable to lock
     * the file, sleep and try again.  If we fail again, return with the
     * proper error message. 
     */

    curpos = sizeof(tfbfr);
    
    if (wflag) {
#ifdef macintosh
	/* If opening for write, remove old, and create a new one */
	err = FSpRstFLock(&spec);	/* to avoid vLckdErr from Delete */
	if ((err = FSpDelete(&spec)) == fBsyErr) {
	    log_printf("tf_init: RstFLock/Delete failed: %s is open\n", tf_name);
	    return TKT_FIL_ACC;
	}
	err = FSpCreate(&spec, (OSType)'Hyde', (OSType)'????', smSystemScript);

	if ((err = FSpOpenDF(&spec, fsRdWrPerm, &refnum)) != noErr) {
	    log_printf("tf_init: open returned %d for %s (read/write)\n", err, tf_name);
	    return TKT_FIL_ACC;
	}

#else /* !macintosh */
	fd = open(tf_name, O_RDWR, 0600);
	if (fd < 0) {
	    log_printf("tf_init: open returned %d for %s (read/write)\n", fd, tf_name);
	    return TKT_FIL_ACC;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
	    sleep(TF_LCK_RETRY);
	    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		(void) close(fd);
		fd = -1;
		return TKT_FIL_LCK;
	    }
	}
#endif /* !macintosh */
	log_printf("tf_init: success\n");
	return KSUCCESS;
    }
    /*
     * Otherwise "wflag" is not set and the ticket file should be opened
     * for read-only operations and locked for shared access. 
     */

#ifdef macintosh
    /* If opening for read, just open it */
    if ((err = FSpOpenDF(&spec, fsRdPerm, &refnum)) != noErr) {
	    log_printf("tf_init: open returned %d for %s (readonly)\n", err, tf_name);
	return TKT_FIL_ACC;
    }
#else /* !macintosh */
    fd = open(tf_name, O_RDONLY, 0600);
    if (fd < 0) {
	    log_printf("tf_init: open returned %d for %s (readonly)\n", fd, tf_name);
	return TKT_FIL_ACC;
    }
    if (flock(fd, LOCK_SH | LOCK_NB) < 0) {
	sleep(TF_LCK_RETRY);
	if (flock(fd, LOCK_SH | LOCK_NB) < 0) {
	    (void) close(fd);
	    fd = -1;
	    return TKT_FIL_LCK;
	}
    }
#endif /* !macintosh */
    log_printf("tf_init: success\n");
    return KSUCCESS;
}

/*
 * tf_get_pname() reads the principal's name from the ticket file. It
 * should only be called after tf_init() has been called.  The
 * principal's name is filled into the "p" parameter.  If all goes well,
 * KSUCCESS is returned.  If tf_init() wasn't called, TKT_FIL_INI is
 * returned.  If the name was null, or EOF was encountered, or the name
 * was longer than ANAME_SZ, TKT_FIL_FMT is returned. 
 */

int tf_get_pname(char *p)
{
#ifdef macintosh
    if (refnum < 0) {
#else /* !macintosh */
    if (fd < 0) {
#endif /* macintosh */
	if (krb_debug)
	    fprintf(stderr, "tf_get_pname called before tf_init.\n");
	log_printf("tf_get_pname called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if (tf_gets(p, ANAME_SZ) < 2)	/* can't be just a null */
	return TKT_FIL_FMT;
    return KSUCCESS;
}

/*
 * tf_get_pinst() reads the principal's instance from a ticket file.
 * It should only be called after tf_init() and tf_get_pname() have been
 * called.  The instance is filled into the "inst" parameter.  If all
 * goes well, KSUCCESS is returned.  If tf_init() wasn't called,
 * TKT_FIL_INI is returned.  If EOF was encountered, or the instance
 * was longer than ANAME_SZ, TKT_FIL_FMT is returned.  Note that the
 * instance may be null. 
 */

int tf_get_pinst(char *inst)
{
#ifdef macintosh
    if (refnum < 0) {
#else /* !macintosh */
    if (fd < 0) {
#endif /* macintosh */
	if (krb_debug)
	    fprintf(stderr, "tf_get_pinst called before tf_init.\n");
	log_printf("tf_get_pinst called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if (tf_gets(inst, INST_SZ) < 1)
	return TKT_FIL_FMT;
    return KSUCCESS;
}

/*
 * tf_get_cred() reads a CREDENTIALS record from a ticket file and fills
 * in the given structure "c".  It should only be called after tf_init(),
 * tf_get_pname(), and tf_get_pinst() have been called. If all goes well,
 * KSUCCESS is returned.  Possible error codes are: 
 *
 * TKT_FIL_INI  - tf_init wasn't called first
 * TKT_FIL_FMT  - bad format
 * EOF          - end of file encountered
 */

int tf_get_cred(CREDENTIALS *c)
{
    KTEXT   ticket = &c->ticket_st;	/* pointer to ticket */
    int     k_errno;
    long issue_date;

#ifdef macintosh
    if (refnum < 0) {
#else /* !macintosh */
    if (fd < 0) {
#endif /* macintosh */
	if (krb_debug)
	    fprintf(stderr, "tf_get_cred called before tf_init.\n");
	log_printf("tf_get_cred called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if ((k_errno = tf_gets(c->service, SNAME_SZ)) < 2)
	switch (k_errno) {
	case TOO_BIG:
	case 1:		/* can't be just a null */
	    tf_close();
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
    if ((k_errno = tf_gets(c->instance, INST_SZ)) < 1)
	switch (k_errno) {
	case TOO_BIG:
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
    if ((k_errno = tf_gets(c->realm, REALM_SZ)) < 2)
	switch (k_errno) {
	case TOO_BIG:
	case 1:		/* can't be just a null */
	    tf_close();
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
    if (
	tf_read((char *) (c->session), sizeof(c->session)) < 1 ||
	tf_read((char *) &(c->lifetime), sizeof(c->lifetime)) < 1 ||
	tf_read((char *) &(c->kvno), sizeof(c->kvno)) < 1 ||
	tf_read((char *) &(ticket->length), sizeof(ticket->length))
	< 1 ||
    /* don't try to read a silly amount into ticket->dat */
	ticket->length > MAX_KTXT_LEN ||
	tf_read((char *) (ticket->dat), ticket->length) < 1 ||
	tf_read((char *) &(issue_date), sizeof(issue_date)) < 1
	) {
	tf_close();
	return TKT_FIL_FMT;
    }
    c->issue_date = issue_date;
    return KSUCCESS;
}

/*
 * tf_close() closes the ticket file and sets "fd" to -1. If "fd" is
 * not a valid file descriptor, it just returns.  It also clears the
 * buffer used to read tickets.
 *
 * The return value is not defined.
 */

void tf_close()
{
#ifdef macintosh
    OSErr err;
    if (!(refnum < 0)) {
#else /* !macintosh */
    if (!(fd < 0)) {
#endif /* macintosh */
#ifdef macintosh
	err = FSpRstFLock(&spec);
#else /* !macintosh */
	(void) flock(fd, LOCK_UN);
#endif /* macintosh */
#ifdef macintosh
	FSClose(refnum);
	refnum = -1;
#else /* !macintosh */
	(void) close(fd);
	fd = -1;		/* see declaration of fd above */
#endif /* macintosh */
    }
    memset(tfbfr, 0, sizeof(tfbfr));
}

/*
 * tf_gets() is an internal routine.  It takes a string "s" and a count
 * "n", and reads from the file until either it has read "n" characters,
 * or until it reads a null byte. When finished, what has been read exists
 * in "s". If it encounters EOF or an error, it closes the ticket file. 
 *
 * Possible return values are:
 *
 * n            the number of bytes read (including null terminator)
 *              when all goes well
 *
 * 0            end of file or read error
 *
 * TOO_BIG      if "count" characters are read and no null is
 *		encountered. This is an indication that the ticket
 *		file is seriously ill.
 */

static int
tf_gets(register char *s, int n)
{
    register int count;
#ifdef macintosh
    OSErr err;
    long i;
#endif /* macintosh */

#ifdef macintosh
    if (refnum < 0) {
#else /* !macintosh */
    if (fd < 0) {
#endif /* macintosh */
	if (krb_debug)
	    fprintf(stderr, "tf_gets called before tf_init.\n");
	log_printf("tf_gets called before tf_init.\n");
	return TKT_FIL_INI;
    }
    for (count = n - 1; count > 0; --count) {
#ifdef macintosh
	if (curpos >= sizeof(tfbfr)) {
	    i = sizeof(tfbfr);
	    switch (err = FSRead(refnum, &i, tfbfr)) {
	    case noErr:
	    case eofErr:
	    	lastpos = i;
	    	curpos = 0;
	    	break;
	    default:
	    	log_printf("tf_gets: FSRead returned %d\n", err);
	    }
	}
#else /* !macintosh */
	if (curpos >= sizeof(tfbfr)) {
	    lastpos = read(fd, tfbfr, sizeof(tfbfr));
	    curpos = 0;
	}
#endif /* macintosh */
	if (curpos == lastpos) {
	    tf_close();
	    return 0;
	}
	*s = tfbfr[curpos++];
	if (*s++ == '\0')
	    return (n - count);
    }
    tf_close();
    return TOO_BIG;
}

/*
 * tf_read() is an internal routine.  It takes a string "s" and a count
 * "n", and reads from the file until "n" bytes have been read.  When
 * finished, what has been read exists in "s".  If it encounters EOF or
 * an error, it closes the ticket file.
 *
 * Possible return values are:
 *
 * n		the number of bytes read when all goes well
 *
 * 0		on end of file or read error
 */

static int
tf_read(register char *s, register int n)
{
    register int count;
#ifdef macintosh
    OSErr err;
    long i;
#endif /* macintosh */
    
    for (count = n; count > 0; --count) {
#ifdef macintosh
	if (curpos >= sizeof(tfbfr)) {
	    i = sizeof(tfbfr);
	    switch (err = FSRead(refnum, &i, tfbfr)) {
	    case noErr:
	    case eofErr:
	    	lastpos = i;
	    	curpos = 0;
	    	break;
	    default:
	    	log_printf("tf_gets: FSRead returned %d\n", err);
	    }
	}
#else /* !macintosh */
	if (curpos >= sizeof(tfbfr)) {
	    lastpos = read(fd, tfbfr, sizeof(tfbfr));
	    curpos = 0;
	}
#endif /* macintosh */
	if (curpos == lastpos) {
	    tf_close();
	    return 0;
	}
	*s++ = tfbfr[curpos++];
    }
    return n;
}
     
char   *tkt_string();

/*
 * tf_save_cred() appends an incoming ticket to the end of the ticket
 * file.  You must call tf_init() before calling tf_save_cred().
 *
 * The "service", "instance", and "realm" arguments specify the
 * server's name; "session" contains the session key to be used with
 * the ticket; "kvno" is the server key version number in which the
 * ticket is encrypted, "ticket" contains the actual ticket, and
 * "issue_date" is the time the ticket was requested (local host's time).
 *
 * Returns KSUCCESS if all goes well, TKT_FIL_INI if tf_init() wasn't
 * called previously, and KFAILURE for anything else that went wrong.
 */

int tf_save_cred(
    char   *service,		/* Service name */
    char   *instance,		/* Instance */
    char   *realm,		/* Auth domain */
    C_Block session,		/* Session key */
    int     lifetime,		/* Lifetime */
    int     kvno,		/* Key version number */
    KTEXT   ticket,		/* The ticket itself */
    long    issue_date)		/* The issue time */
{

    off_t   lseek();
#ifdef macintosh
    long    total_count;	/* count for file size */
    OSErr   err;
    long    count;
    char pname[SNAME_SZ], pinst[INST_SZ];
    long cname, cinst;		/* count for write */
#else /* !macintosh */
    int     count;		/* count for write */
#endif /* macintosh */

#ifdef macintosh
    if (refnum < 0) {
#else /* !macintosh */
    if (fd < 0) {		/* fd is ticket file as set by tf_init */
#endif /* macintosh */
	  if (krb_debug)
	      fprintf(stderr, "tf_save_cred called before tf_init.\n");
	  log_printf("tf_save_cred called before tf_init.\n");
	  return TKT_FIL_INI;
    }

#ifdef macintosh
    /* Find the start of the ticket file */
    SetFPos(refnum, fsFromStart, 0);
    /* Initialize the ticket file.  It contains a principal, instance, and the credentials */
    if ((err = KClientGetUserName((char *)&pname)) != noErr) {
	log_printf("tf_init: KClientGetUserName returned %d\n", err);
	tf_close();
	return TKT_FIL_ACC;
    }
    cname = strlen(pname) + 1;
    strcpy(pinst, "");
    cinst = strlen(pinst) + 1;
    if ( ((err = FSWrite(refnum, &cname, pname)) != noErr) ||
	 ((err = FSWrite(refnum, &cinst, pinst)) != noErr) ) {
	log_printf("tf_init: FSWrite returned %d\n", err);
	tf_close();
	return TKT_FIL_ACC;
    }
    total_count = 0;
    total_count += cname + cinst;
#else /* !macintosh */
    /* Find the end of the ticket file */
    (void) lseek(fd, (off_t)0, 2);
#endif /* macintosh */

    /* Write the ticket and associated data */
    /* Service */
    count = strlen(service) + 1;
#ifdef macintosh
    if ((err = FSWrite(refnum, &count, service)) != noErr)
#else /* !macintosh */
    if (write(fd, service, count) != count)
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Instance */
    count = strlen(instance) + 1;
#ifdef macintosh
    if ((err = FSWrite(refnum, &count, instance)) != noErr)
#else /* !macintosh */
    if (write(fd, instance, count) != count)
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Realm */
    count = strlen(realm) + 1;
#ifdef macintosh
    if ((err = FSWrite(refnum, &count, realm)) != noErr)
#else /* !macintosh */
    if (write(fd, realm, count) != count)
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Session key */
#ifdef macintosh
    count = 8;
    if ((err = FSWrite(refnum, &count, session)) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) session, 8) != 8)
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Lifetime */
#ifdef macintosh
    count = sizeof(int);
    if ((err = FSWrite(refnum, &count, &lifetime)) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) &lifetime, sizeof(int)) != sizeof(int))
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Key vno */
#ifdef macintosh
    count = sizeof(int);
    if ((err = FSWrite(refnum, &count, &kvno)) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) &kvno, sizeof(int)) != sizeof(int))
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Tkt length */
#ifdef macintosh
    count = sizeof(int);
    if ((err = FSWrite(refnum, &count, &(ticket->length))) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) &(ticket->length), sizeof(int)) !=
	sizeof(int))
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Ticket */
    count = ticket->length;
#ifdef macintosh
    if ((err = FSWrite(refnum, &count, (ticket->dat))) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) (ticket->dat), count) != count)
#endif /* macintosh */
	goto bad;
    total_count += count;
    /* Issue date */
#ifdef macintosh
    count = sizeof(long);
    if ((err = FSWrite(refnum, &count, &issue_date)) != noErr)
#else /* !macintosh */
    if (write(fd, (char *) &issue_date, sizeof(long))
	!= sizeof(long))
#endif /* macintosh */
	goto bad;
    total_count += count;

    SetEOF(refnum, total_count);
    /* Actually, we should check each write for success */
    return (KSUCCESS);
bad:
    log_printf("tf_save_cred: something \"bad\" happened\n");
    return (KFAILURE);
}
