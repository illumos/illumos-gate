/*
 * lib/krb5/os/lock_file.c
 *
 * Copyright 1990, 1998 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * libos: krb5_lock_file routine
 */

#include "k5-int.h"
#include <stdio.h>

#if !defined(_WIN32)

/* Unix version...  */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if defined(HAVE_FCNTL_H) && defined(F_SETLKW) && defined(F_RDLCK)
#define POSIX_FILE_LOCKS
#endif

#ifdef HAVE_FLOCK
#ifndef sysvimp
#include <sys/file.h>
#endif
#else
#ifndef LOCK_SH
#define LOCK_SH 0
#define LOCK_EX 0
#define LOCK_UN 0
#endif
#endif

/*ARGSUSED*/
krb5_error_code
krb5_lock_file(krb5_context context, int fd, int mode)
{
    int 		lock_flag = -1;
    krb5_error_code	retval = 0;
#ifdef POSIX_FILE_LOCKS
    int lock_cmd = F_SETLKW;
    struct flock lock_arg = { 0 };
#endif

    switch (mode & ~KRB5_LOCKMODE_DONTBLOCK) {
    case KRB5_LOCKMODE_SHARED:
#ifdef POSIX_FILE_LOCKS
	lock_arg.l_type = F_RDLCK;
#endif
	lock_flag = LOCK_SH;
	break;
    case KRB5_LOCKMODE_EXCLUSIVE:
#ifdef POSIX_FILE_LOCKS
	lock_arg.l_type = F_WRLCK;
#endif
	lock_flag = LOCK_EX;
	break;
    case KRB5_LOCKMODE_UNLOCK:
#ifdef POSIX_FILE_LOCKS
	lock_arg.l_type = F_UNLCK;
#endif
	lock_flag = LOCK_UN;
	break;
    }

    if (lock_flag == -1)
	return(KRB5_LIBOS_BADLOCKFLAG);

    if (mode & KRB5_LOCKMODE_DONTBLOCK) {
#ifdef POSIX_FILE_LOCKS
	lock_cmd = F_SETLK;
#endif
#ifdef HAVE_FLOCK
	lock_flag |= LOCK_NB;
#endif
    }

#ifdef POSIX_FILE_LOCKS
    lock_arg.l_whence = 0;
    lock_arg.l_start = 0;
    lock_arg.l_len = 0;
    if (fcntl(fd, lock_cmd, &lock_arg) == -1) {
	if (errno == EACCES || errno == EAGAIN)	/* see POSIX/IEEE 1003.1-1988,
						   6.5.2.4 */
	    return(EAGAIN);
	if (errno != EINVAL)	/* Fall back to flock if we get EINVAL */
	    return(errno);
	retval = errno;
    } else
	    return 0;		/* We succeeded.  Yay. */
#endif
    
#ifdef HAVE_FLOCK
    if (flock(fd, lock_flag) == -1)
	retval = errno;
#endif
    
    return retval;
}
#else   /* Windows or Macintosh */

krb5_error_code
krb5_lock_file(context, fd, mode)
    krb5_context context;
    int fd;
    int mode;
{
    return 0;
}
#endif
