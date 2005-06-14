/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#if defined(_MSDOS) || defined(_WIN32)
#  define PATH_SEPARATOR "\\"
#else
#  define PATH_SEPARATOR "/"
#endif

#define KRB5_RC_VNO	0x0501		/* krb5, rcache v 1 */
#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO

#include <krb5.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h> /* SUNW */
#include "rc_base.h"
#include "rc_file.h"
#include "rc_io.h"

#ifndef O_BINARY
#define O_BINARY    0
#endif

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 #error find some way to use net-byte-order file version numbers.
#endif

#ifndef HAVE_ERRNO
extern int errno; /* this should be in errno.h, but isn't on some systems */
#endif

#define free(x) ((void) free((char *) (x)))
#define UNIQUE getpid() /* hopefully unique number */

static int dirlen = 0;
static char *dir;

/* The do ... while(0) is required to insure that GETDIR looks like a
   single statement in all situations (just {}'s may cause troubles in
   certain situations, such as nested if/else clauses. */

static int false = 0;
#define GETDIR do { if (!dirlen) getdir(); } while(false)

static void
getdir(void)
{
#if defined(_MSDOS) || defined(_WIN32)
     if (!(dir = getenv("TEMP")))
	 if (!(dir = getenv("TMP")))
	     dir = "C:\\";
#else
     if (geteuid() == 0)
	 dir = "/var/krb5/rcache/root";
     else
	 dir = "/var/krb5/rcache";
#endif
   dirlen = strlen(dir) + sizeof(PATH_SEPARATOR);
}

krb5_error_code krb5_rc_io_creat (context, d, fn)
    krb5_context context;
    krb5_rc_iostuff *d;
    char **fn;
{
 char *c;
 krb5_int16 rc_vno = htons(KRB5_RC_VNO);
 krb5_error_code retval;

 GETDIR;
 if (fn && *fn)
  {
   if (*fn[0] == '/') {
	d->fn = strdup(*fn);
	if (d->fn == NULL)
		return (KRB5_RC_IO_MALLOC);
   } else {
	if (!(d->fn = malloc(strlen(*fn) + dirlen + 1)))
		return KRB5_RC_IO_MALLOC;
	(void) strcpy(d->fn, dir);
	(void) strcat(d->fn, PATH_SEPARATOR);
	(void) strcat(d->fn,*fn);
   }
   d->fd = THREEPARAMOPEN(d->fn,O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_BINARY, 0600);
  }
 else
  {
      /* %d is max 11 digits (-, 10 digits of 32-bit number)
	 * 11 + /krb5_RC + aaa = 24, +6 for slop */
   if (!(d->fn = malloc(30 + dirlen)))
     return KRB5_RC_IO_MALLOC;
   if (fn)
     if (!(*fn = malloc(35)))
      { free(d->fn); return KRB5_RC_IO_MALLOC; }
   (void) sprintf(d->fn,"%s%skrb5_RC%d",dir,PATH_SEPARATOR,UNIQUE);
   c = d->fn + strlen(d->fn);
   (void) strcpy(c,"aaa");
   while ((d->fd = THREEPARAMOPEN(d->fn,O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_BINARY,0600)) == -1)
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
     (void) strcpy(*fn,d->fn + dirlen);
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
	    goto fail;
	case EIO:
	    retval = KRB5_RC_IO_IO; goto fail;

	case EPERM:
	case EACCES:
	case EROFS:
	case EEXIST:
	    retval = KRB5_RC_IO_PERM; goto no_unlink;

	default:
	    retval = KRB5_RC_IO_UNKNOWN; goto fail;
    }
    }
    if (((retval = krb5_rc_io_write(context, d, (krb5_pointer)&rc_vno, sizeof(rc_vno))) != 0) ||
	(retval = krb5_rc_io_sync(context, d) != 0))
    {
    fail:
     (void) unlink(d->fn);
    no_unlink:
     syslog(LOG_ERR, "Could not create replay cache %s\n", d->fn); /* SUNW */
     free(d->fn);
	d->fn = NULL;
     (void) close(d->fd);
     return retval;
 }
 return 0;
}

krb5_error_code krb5_rc_io_open (context, d, fn)
    krb5_context context;
    krb5_rc_iostuff *d;
    char *fn;
{
    krb5_int16 rc_vno;
    krb5_error_code retval = 0;
    int do_not_unlink = 1;
    struct stat lstatb, fstatb;
    int use_errno = 0;

    GETDIR;
    if (fn[0] == '/') {
	d->fn = strdup(fn);
	if (d->fn == NULL)
		return (KRB5_RC_IO_MALLOC);
    } else {
	if (!(d->fn = malloc(strlen(fn) + dirlen + 1)))
		return KRB5_RC_IO_MALLOC;
	(void) strcpy(d->fn,dir);
	(void) strcat(d->fn,PATH_SEPARATOR);
	(void) strcat(d->fn,fn);
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
		break;

	    default:
		retval = KRB5_RC_IO_UNKNOWN;
	}
    }
    /* Solaris: END made changes to be safer and better code structure */
    if (retval) {
	if (d->fn) {
	    if (!do_not_unlink) {
		/* unlink in case there is a bogus RC. */
		(void) unlink(d->fn);
	    }
	    free(d->fn);
	    d->fn = NULL;
	}
	(void) close(d->fd);
    }
    return retval;
}

krb5_error_code
krb5_rc_io_move(krb5_context context, krb5_rc_iostuff *new1,
		krb5_rc_iostuff *old)
{
    char *fn = NULL;

#if defined(_MSDOS) || defined(_WIN32)
    /*
     * Work around provided by Tom Sanfilippo to work around poor
     * Windows emulation of POSIX functions.  Rename and dup has
     * different semantics!
     */
    char *fn = NULL;
    GETDIR;
    close(new->fd);
    unlink(new->fn);
    close(old->fd);
    if (rename(old->fn,new->fn) == -1) /* MUST be atomic! */
	return KRB5_RC_IO_UNKNOWN;
    if (!(fn = malloc(strlen(new->fn) - dirlen + 1)))
	return KRB5_RC_IO_MALLOC;
    strcpy(fn, new->fn + dirlen);
    krb5_rc_io_close(context, new);
    krb5_rc_io_open(context, new, fn);
    free(fn);
#else
    if (rename(old->fn, new1->fn) == -1) /* MUST be atomic! */
	return KRB5_RC_IO_UNKNOWN;
    fn = new1->fn;
    new1->fn = NULL;		/* avoid clobbering */
    (void) krb5_rc_io_close(context, new1);
    new1->fn = fn;
#ifdef macintosh
    new1->fd = fcntl(old->fd, F_DUPFD);
#else
    new1->fd = dup(old->fd);
#endif
#endif
    return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_write (context, d, buf, num)
    krb5_context context;
    krb5_rc_iostuff *d;
    krb5_pointer buf;
    int num;
{
 if (write(d->fd,(char *) buf,num) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN;
     case EFBIG: return KRB5_RC_IO_SPACE;
#ifdef EDQUOT
     case EDQUOT: return KRB5_RC_IO_SPACE;
#endif
     case ENOSPC: return KRB5_RC_IO_SPACE;
     case EIO: return KRB5_RC_IO_IO;
     default: return KRB5_RC_IO_UNKNOWN;
    }
 return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_sync (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
#if !defined(MSDOS_FILESYSTEM) && !defined(macintosh)
    if (fsync(d->fd) == -1) {
      switch(errno)
      {
      case EBADF: return KRB5_RC_IO_UNKNOWN;
      case EIO: return KRB5_RC_IO_IO;
      default: return KRB5_RC_IO_UNKNOWN;
      }
    }
#endif
    return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_read (context, d, buf, num)
    krb5_context context;
    krb5_rc_iostuff *d;
    krb5_pointer buf;
    int num;
{
 int count;
 if ((count = read(d->fd,(char *) buf,num)) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN;
     case EIO: return KRB5_RC_IO_IO;
     default: return KRB5_RC_IO_UNKNOWN;
    }
 if (count == 0)
     return KRB5_RC_IO_EOF;
 return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_close (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 free(d->fn);
 d->fn = NULL;
 if (close(d->fd) == -1) /* can't happen */
   return KRB5_RC_IO_UNKNOWN;
 return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_destroy (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 if (unlink(d->fn) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN;
     case EIO: return KRB5_RC_IO_IO;
     case EPERM: return KRB5_RC_IO_PERM;
     case EBUSY: return KRB5_RC_IO_PERM;
     case EROFS: return KRB5_RC_IO_PERM;
     default: return KRB5_RC_IO_UNKNOWN;
    }
 return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_mark (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 d->mark = lseek(d->fd,0,SEEK_CUR); /* can't fail */
 return 0;
}

/*ARGSUSED*/
krb5_error_code krb5_rc_io_unmark (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 (void) lseek(d->fd,d->mark,SEEK_SET); /* if it fails, tough luck */
 return 0;
}

/*ARGSUSED*/
long
krb5_rc_io_size (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
    struct stat statb;

    if (fstat (d->fd, &statb) == 0)
	return statb.st_size;
    else
	return 0;
}
