/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * lib/krb5/rcache/rc_io.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */


/*
 * I/O functions for the replay cache default implementation.
 */

#if defined(_WIN32)
#  define PATH_SEPARATOR "\\"
#else
#  define PATH_SEPARATOR "/"
#endif

#define KRB5_RC_VNO	0x0501		/* krb5, rcache v 1 */

#include "k5-int.h"
#include <stdio.h> /* for P_tmpdir */
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h> /* SUNW */
#include <locale.h> /* Solaris Kerberos */
#include "rc_base.h"
#include "rc_file.h"
#include "rc_io.h"

#ifndef O_BINARY
#define O_BINARY    0
#endif

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_)
#include <netinet/in.h>
#endif
#else
#error find some way to use net-byte-order file version numbers.
#endif

/* Solaris Kerberos */
#define FREE_RC(x) ((void) free((char *) (x)))
#define UNIQUE getpid() /* hopefully unique number */

#define GETDIR (dir = getdir(), dirlen = strlen(dir) + sizeof(PATH_SEPARATOR) - 1)

static char *
getdir(void)
{
    char *dir;

#if defined(_WIN32)
	if (!(dir = getenv("TEMP")))
	    if (!(dir = getenv("TMP")))
		dir = "C:";
#else
     /* Solaris Kerberos */
     if (geteuid() == 0)
	 dir = "/var/krb5/rcache/root";
     else
	 dir = "/var/krb5/rcache";
#endif
     return dir;
}

krb5_error_code
krb5_rc_io_creat(krb5_context context, krb5_rc_iostuff *d, char **fn)
{
    char *c;
    krb5_int16 rc_vno = htons(KRB5_RC_VNO);
    krb5_error_code retval = 0;
    int do_not_unlink = 0;
    char *dir;
    size_t dirlen;

    GETDIR;
    if (fn && *fn)
    {
    /* Solaris Kerberos */
   if (*fn[0] == '/') {
	d->fn = strdup(*fn);
	if (d->fn == NULL)
		return (KRB5_RC_IO_MALLOC);
   } else {
	if (!(d->fn = malloc(strlen(*fn) + dirlen + 1)))
	    return KRB5_RC_IO_MALLOC;
	(void) strcpy(d->fn, dir);
	(void) strcat(d->fn, PATH_SEPARATOR);
	(void) strcat(d->fn, *fn);
   }
    d->fd = THREEPARAMOPEN(d->fn, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL |
		       O_BINARY, 0600);
    }
    else
    {
	/* %d is max 11 digits (-, 10 digits of 32-bit number)
	 * 11 + /krb5_RC + aaa = 24, +6 for slop */
	if (!(d->fn = malloc(30 + dirlen)))
	    return KRB5_RC_IO_MALLOC;
	if (fn)
	    if (!(*fn = malloc(35))) {
		FREE_RC(d->fn);
		return KRB5_RC_IO_MALLOC;
	    }
	(void) sprintf(d->fn, "%s%skrb5_RC%d", dir, PATH_SEPARATOR,
		       (int) UNIQUE);
	c = d->fn + strlen(d->fn);
	(void) strcpy(c, "aaa");
	while ((d->fd = THREEPARAMOPEN(d->fn, O_WRONLY | O_CREAT | O_TRUNC |
				       O_EXCL | O_BINARY, 0600)) == -1)
	{
	    if ((c[2]++) == 'z')
	    {
		c[2] = 'a';
		if ((c[1]++) == 'z')
		{
		    c[1] = 'a';
		    if ((c[0]++) == 'z')
			break; /* sigh */
		}
	    }
	}
	if (fn)
	    (void) strcpy(*fn, d->fn + dirlen);
    }
    if (d->fd == -1)
    {
	switch(errno)
	{
	case EFBIG:
#ifdef EDQUOT
	case EDQUOT:
#endif
	case ENOSPC:
	    retval = KRB5_RC_IO_SPACE;
	    goto cleanup;

	case EIO:
	    retval = KRB5_RC_IO_IO;
	    goto cleanup;

	case EPERM:
	case EACCES:
	case EROFS:
	case EEXIST:
	    retval = KRB5_RC_IO_PERM;
	    krb5_set_error_message(context, retval,
				dgettext(TEXT_DOMAIN,
					"Cannot create replay cache %s: %s"),
				d->fn ? d->fn : "<null>",
				strerror(errno));
	    do_not_unlink = 1;
	    goto cleanup;

	default:
	    retval = KRB5_RC_IO_UNKNOWN;
	    krb5_set_error_message(context, retval,
				dgettext(TEXT_DOMAIN,
					"Cannot create replay cache %s: %s"),
				d->fn ? d->fn : "<null>",
				strerror(errno));
	    goto cleanup;
	}
    }
    retval = krb5_rc_io_write(context, d, (krb5_pointer)&rc_vno,
			      sizeof(rc_vno));
    if (retval)
	goto cleanup;

    retval = krb5_rc_io_sync(context, d);

 cleanup:
    if (retval) {
	if (d->fn) {
	    if (!do_not_unlink)
		(void) unlink(d->fn);
	    FREE_RC(d->fn);
	    d->fn = NULL;
	}
	if (d->fd != -1) {
	  (void) close(d->fd);
	}
    }
    return retval;
}

static krb5_error_code
krb5_rc_io_open_internal(krb5_context context, krb5_rc_iostuff *d, char *fn,
			 char* full_pathname)
{
    krb5_int16 rc_vno;
    krb5_error_code retval = 0;
    int do_not_unlink = 1;
    struct stat lstatb, fstatb;
    int use_errno = 0;
    char *dir;
    size_t dirlen;

    GETDIR;
    if (fn[0] == '/') {
	d->fn = strdup(fn);
	if (d->fn == NULL)
		return (KRB5_RC_IO_MALLOC);
    } else {
	if (!(d->fn = malloc(strlen(fn) + dirlen + 1)))
	    return KRB5_RC_IO_MALLOC;
	(void) strcpy(d->fn, dir);
	(void) strcat(d->fn, PATH_SEPARATOR);
	(void) strcat(d->fn, fn);
    }

    /* Solaris: BEGIN made changes to be safer and better code structure */
    if ((d->fd = THREEPARAMOPEN(d->fn, O_RDWR|O_BINARY, 0600)) == -1) {
	use_errno = 1;
	goto cleanup;
    }

    do_not_unlink = 0;
    if (fstat(d->fd, &fstatb) == 0) {
#ifndef NO_USERID
	uid_t me;

	me = geteuid();
	/* must be owned by this user, to prevent some security problems with
	 * other users modifying replay cache stuff and must be a regular file
	 */
	if ((fstatb.st_uid != me) || ((fstatb.st_mode & S_IFMT) != S_IFREG)) {
	    retval = KRB5_RC_IO_PERM;
	    goto cleanup;
	}
#else
	/* make sure the rcache is a regular file */
	if (((fstatb.st_mode & S_IFMT) != S_IFREG)) {
	    retval = KRB5_RC_IO_PERM;

	    goto cleanup;
	}
#endif
	if (lstat(d->fn, &lstatb) == 0) {
	    /* Make sure fstat() and lstat() have accessed the same file */
	    if ((lstatb.st_ino != fstatb.st_ino) ||
		    (lstatb.st_dev != fstatb.st_dev)) {
		retval = KRB5_RC_IO_PERM;
		goto cleanup;
	    }

	    if ((lstatb.st_mode & S_IFMT) == S_IFLNK) {
		/* if we accessed the rcache via a symlink, bail out */
		syslog(LOG_ERR, "Error, krb replay cache %s is a symlink "
			   "and should be removed.\n", d->fn);
		retval = KRB5_RC_IO_PERM;
		goto cleanup;
	    }
	}
	else {
	    use_errno = 1;
	    goto cleanup;
	}
    }
    else {
	use_errno = 1;
	goto cleanup;
    }

    do_not_unlink = 0;
    retval = krb5_rc_io_read(context, d, (krb5_pointer) &rc_vno,
			     sizeof(rc_vno));
    if (retval)
	goto cleanup;

    if (ntohs(rc_vno) != KRB5_RC_VNO)
	retval = KRB5_RCACHE_BADVNO;

 cleanup:
    if (use_errno) {
	switch(errno)
	{
	    case EFBIG:
#ifdef EDQUOT
	    case EDQUOT:
#endif
	    case ENOSPC:
		retval = KRB5_RC_IO_SPACE;
		break;

	    case EIO:
		retval = KRB5_RC_IO_IO;
		break;

	    case EPERM:
	    case EACCES:
	    case EROFS:
		retval = KRB5_RC_IO_PERM;
	    	krb5_set_error_message (context, retval,
			    dgettext(TEXT_DOMAIN,
				"Cannot open replay cache %s: %s"),
			    d->fn, strerror(errno));
		break;

	    default:
		retval = KRB5_RC_IO_UNKNOWN;
		krb5_set_error_message (context, retval,
			    dgettext(TEXT_DOMAIN,
				"Cannot open replay cache %s: %s"),
			    d->fn, strerror(errno));
	}
    }
    /* Solaris: END made changes to be safer and better code structure */
    if (retval) {
	if (d->fn) {
	    if (!do_not_unlink)
		(void) unlink(d->fn);
	    FREE_RC(d->fn);
	    d->fn = NULL;
	}
	if (d->fd >= 0)
	     (void) close(d->fd);
    }
    return retval;
}

krb5_error_code
krb5_rc_io_open(krb5_context context, krb5_rc_iostuff *d, char *fn)
{
    return krb5_rc_io_open_internal(context, d, fn, NULL);
}

krb5_error_code
krb5_rc_io_move(krb5_context context, krb5_rc_iostuff *new1,
		krb5_rc_iostuff *old)
{
#if defined(_WIN32) || defined(__CYGWIN__)
    char *new_fn = NULL;
    char *old_fn = NULL;
    off_t offset = 0;
    krb5_error_code retval = 0;
    /*
     * Initial work around provided by Tom Sanfilippo to work around
     * poor Windows emulation of POSIX functions.  Rename and dup has
     * different semantics!
     *
     * Additional fixes and explanation provided by dalmeida@mit.edu:
     *
     * First, we save the offset of "old".  Then, we close and remove
     * the "new" file so we can do the rename.  We also close "old" to
     * make sure the rename succeeds (though that might not be
     * necessary on some systems).
     *
     * Next, we do the rename.  If all goes well, we seek the "new"
     * file to the position "old" was at.
     *
     * --- WARNING!!! ---
     *
     * Since "old" is now gone, we mourn its disappearance, but we
     * cannot emulate that Unix behavior...  THIS BEHAVIOR IS
     * DIFFERENT FROM UNIX.  However, it is ok because this function
     * gets called such that "old" gets closed right afterwards.
     */
    offset = lseek(old->fd, 0, SEEK_CUR);

    new_fn = new1->fn;
    new1->fn = NULL;
    close(new1->fd);
    new1->fd = -1;

    unlink(new_fn);

    old_fn = old->fn;
    old->fn = NULL;
    close(old->fd);
    old->fd = -1;

    if (rename(old_fn, new_fn) == -1) { /* MUST be atomic! */
	retval = KRB5_RC_IO_UNKNOWN;
	goto cleanup;
    }

    retval = krb5_rc_io_open_internal(context, new1, 0, new_fn);
    if (retval)
	goto cleanup;

    if (lseek(new1->fd, offset, SEEK_SET) == -1) {
	retval = KRB5_RC_IO_UNKNOWN;
	goto cleanup;
    }

 cleanup:
    free(new_fn);
    free(old_fn);
    return retval;
#else
    char *fn = NULL;
    if (rename(old->fn, new1->fn) == -1) /* MUST be atomic! */
	return KRB5_RC_IO_UNKNOWN;
    fn = new1->fn;
    new1->fn = NULL;		/* avoid clobbering */
    (void) krb5_rc_io_close(context, new1);
    new1->fn = fn;
    new1->fd = dup(old->fd);
    return 0;
#endif
}

krb5_error_code
krb5_rc_io_write(krb5_context context, krb5_rc_iostuff *d, krb5_pointer buf,
		 unsigned int num)
{
    if (write(d->fd, (char *) buf, num) == -1)
	switch(errno)
	{
#ifdef EDQUOT
	case EDQUOT:
#endif
	case EFBIG:
	case ENOSPC:
	    krb5_set_error_message (context, KRB5_RC_IO_SPACE,
				    dgettext(TEXT_DOMAIN,
					    "Can't write to replay cache %s: %s"),
				    d->fn, strerror(errno));
	    return KRB5_RC_IO_SPACE;
	case EIO:
	    krb5_set_error_message (context, KRB5_RC_IO_IO,
				    dgettext(TEXT_DOMAIN,
					    "Can't write to replay cache %s: %s"),
				    d->fn, strerror(errno));
	    return KRB5_RC_IO_IO;
	case EBADF:
	default:
	    krb5_set_error_message (context, KRB5_RC_IO_UNKNOWN,
				    dgettext(TEXT_DOMAIN,
					    "Can't write to replay cache %s: %s"),
				    d->fn, strerror(errno));
	    return KRB5_RC_IO_UNKNOWN;
	}
    return 0;
}

krb5_error_code
krb5_rc_io_sync(krb5_context context, krb5_rc_iostuff *d)
{
#if defined(_WIN32)
#ifndef fsync
#define fsync _commit
#endif
#endif
    if (fsync(d->fd) == -1) {
	switch(errno)
	{
	case EBADF: return KRB5_RC_IO_UNKNOWN;
	case EIO: return KRB5_RC_IO_IO;
	default:
	    krb5_set_error_message(context, KRB5_RC_IO_UNKNOWN,
				dgettext(TEXT_DOMAIN,
					"Cannot sync replay cache file %s: %s"),
				d->fn, strerror(errno));
	    return KRB5_RC_IO_UNKNOWN;
	}
    }
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_rc_io_read(krb5_context context, krb5_rc_iostuff *d, krb5_pointer buf,
		unsigned int num)
{
    int count;
    if ((count = read(d->fd, (char *) buf, num)) == -1)
	switch(errno)
	{
	case EIO: return KRB5_RC_IO_IO;
	case EBADF:
	default:
	    krb5_set_error_message(context, KRB5_RC_IO_UNKNOWN,
				dgettext(TEXT_DOMAIN,
					"Can't read from replay cache %s: %s"),
				d->fn, strerror(errno));
	    return KRB5_RC_IO_UNKNOWN;
	}
    if (count == 0)
	return KRB5_RC_IO_EOF;
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_rc_io_close(krb5_context context, krb5_rc_iostuff *d)
{
    if (d->fn != NULL) {
	FREE_RC(d->fn);
	d->fn = NULL;
    }
    if (d->fd != -1) {
	if (close(d->fd) == -1) /* can't happen */
	    return KRB5_RC_IO_UNKNOWN;
	d->fd = -1;
    }
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_rc_io_destroy(krb5_context context, krb5_rc_iostuff *d)
{
    if (unlink(d->fn) == -1)
	switch(errno)
	{
	case EIO:
	    krb5_set_error_message(context, KRB5_RC_IO_IO,
				dgettext(TEXT_DOMAIN,
					"Can't destroy replay cache %s: %s"),
				d->fn, strerror(errno));
	    return KRB5_RC_IO_IO;
	case EPERM:
	case EBUSY:
	case EROFS:
	    krb5_set_error_message(context, KRB5_RC_IO_PERM,
				dgettext(TEXT_DOMAIN,
					"Can't destroy replay cache %s: %s"),
				d->fn, strerror(errno));
	    return KRB5_RC_IO_PERM;
	case EBADF:
	default:
	    krb5_set_error_message(context, KRB5_RC_IO_UNKNOWN,
				dgettext(TEXT_DOMAIN,
					"Can't destroy replay cache %s: %s"),
				d->fn, strerror(errno));
	    return KRB5_RC_IO_UNKNOWN;
	}
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_rc_io_mark(krb5_context context, krb5_rc_iostuff *d)
{
    d->mark = lseek(d->fd, (off_t) 0, SEEK_CUR); /* can't fail */
    return 0;
}

/*ARGSUSED*/
krb5_error_code
krb5_rc_io_unmark(krb5_context context, krb5_rc_iostuff *d)
{
    (void) lseek(d->fd, d->mark, SEEK_SET); /* if it fails, tough luck */
    return 0;
}

/*ARGSUSED*/
long
krb5_rc_io_size(krb5_context context, krb5_rc_iostuff *d)
{
    struct stat statb;

    if (fstat(d->fd, &statb) == 0)
	return statb.st_size;
    else
	return 0;
}
