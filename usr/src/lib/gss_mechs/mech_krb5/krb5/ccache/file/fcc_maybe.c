/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/file/fcc_maybe.c
 *
 * Copyright 1990, 1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for conditional open/close calls.
 */

#include <syslog.h>	/* SUNW */

#define NEED_SOCKETS    /* Only for ntohs, etc. */
#define NEED_LOWLEVEL_IO
#include <k5-int.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "fcc.h"

/* How long to block if flock fails with EAGAIN */
#define	LOCK_RETRIES	100
#define	WAIT_LENGTH	20	/* in milliseconds */

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 /*error find some way to use net-byte-order file version numbers.*/
#endif

krb5_error_code
krb5_fcc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code retval;

     if (data->fd == -1)
	 return KRB5_FCC_INTERNAL;

     retval = krb5_unlock_file(context, data->fd);
     ret = close (data->fd);
     data->fd = -1;
     if (retval)
	 return retval;
     else
     return (ret == -1) ? krb5_fcc_interpret (context, errno) : 0;
}

static krb5_error_code
krb5_fcc_open_nounlink(char *filename, int open_flag, int *ret_fd, int *new)
{
     struct stat lres;
     struct stat fres;
     int error;
     uid_t uid, euid;
     int fd;
     int newfile = 0;

     *ret_fd = -1;
     /*
      * SUNW
      * If we are opening in NOUNLINK mode, we have to check that the
      * existing file, if any, is not a symlink. If it is, we try to
      * delete and re-create it.
      */
     error = lstat(filename, &lres);
     if (error == -1 && errno != ENOENT) {
	  syslog(LOG_ERR, "lstat failed for %s [%m]", filename);
	  return (-1);
     }

     if (error == 0 && !S_ISREG(lres.st_mode)) {
	  syslog(LOG_WARNING, "%s is not a plain file!", filename);
	  syslog(LOG_WARNING, "trying to unlink %s", filename);
	  if (unlink(filename) != 0) {
	       syslog(LOG_ERR, "could not unlink %s [%m]", filename);
	       return (-1);
	  }
     }

     fd = THREEPARAMOPEN(filename, open_flag | O_NONBLOCK, 0600);
     if (fd == -1) {
	  if (errno == ENOENT) {
	       fd = THREEPARAMOPEN(filename,
				   open_flag | O_EXCL | O_CREAT, 0600);
	       if (fd != -1) {
		    newfile = 1;
	       } else {
		    /* If the file got created after the open we must retry */
		    if (errno == EEXIST)
			 return (0);
	       }
	  } else if (errno == EACCES) {
		    /*
		     * We failed since the file existed with wrong permissions.
		     * Let's try to unlink it and if that succeeds retry.
		     */
		    syslog(LOG_WARNING, "Insufficient permissions on %s",
			   filename);
		    syslog(LOG_WARNING, "trying to unlink %s", filename);
		    if (unlink(filename) != 0) {
			 syslog(LOG_ERR, "could not unlink %s [%m]", filename);
			 return (-1);
		    }
		    return (0);
	  }
     }
     /* If we still don't have a valid fd, we stop trying */
     if (fd == -1)
	  return (-1);

     /*
      * SUNW
      * If the file was not created now with a O_CREAT | O_EXCL open,
      * we have opened an existing file. We should check if the file
      * owner is us, if not, unlink and retry. If unlink fails we log
      * the error and return.
      */
     if (!newfile) {
	  if (fstat(fd, &fres) == -1) {
	       syslog(LOG_ERR, "lstat failed for %s [%m]", filename);
	       close(fd);
	       return (-1);
	  }
	  /* Check if this is the same file we lstat'd earlier */
	  if (lres.st_dev != fres.st_dev || lres.st_ino != fres.st_ino) {
	       syslog(LOG_ERR, "%s changed between stat and open!", filename);
	       close(fd);
	       return (-1);
	  }

	  uid = getuid();
	  euid = geteuid();
	  /*
	   * Some apps (gssd, via a priv version of getuid())
	   * "set" the real uid only, others
	   * (telnetd/login/pam_krb5, etc) set effective uid only.
	   */
	  if (fres.st_uid != uid && fres.st_uid != euid) {
	       close(fd);
	       syslog(LOG_WARNING,
		    "%s owned by %d instead of %d (euid=%d, uid=%d)",
		    filename, fres.st_uid, euid, euid, uid);
	       syslog(LOG_WARNING, "trying to unlink %s", filename);
	       if (unlink(filename) != 0) {
		    syslog(LOG_ERR, "could not unlink %s [%m]", filename);
		    return (-1);
	       }
	       return (0);
	  }
     }

     *new = newfile;
     *ret_fd = fd;
     return (0);
}

krb5_error_code
krb5_fcc_open_file (context, id, mode)
    krb5_context context;
    krb5_ccache id;
    int mode;
{
     krb5_os_context os_ctx = (krb5_os_context)context->os_context;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_ui_2 fcc_fvno;
     krb5_ui_2 fcc_flen;
     krb5_ui_2 fcc_tag;
     krb5_ui_2 fcc_taglen;
     int fd;
     int open_flag, lock_flag;
     krb5_error_code retval = 0;
     int retries;
     int newfile = 0;

     if (data->fd != -1) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) krb5_unlock_file(context, data->fd);
	  (void) close (data->fd);
	  data->fd = -1;
     }
     data->mode = mode;
     switch(mode) {
     case FCC_OPEN_AND_ERASE_NOUNLINK:
	    open_flag = O_RDWR;
	    break;
     case FCC_OPEN_AND_ERASE:
	 unlink(data->filename);
	 open_flag = O_CREAT|O_EXCL|O_TRUNC|O_RDWR;
	 break;
     case FCC_OPEN_RDWR:
	 open_flag = O_RDWR;
	 break;
     case FCC_OPEN_RDONLY:
     default:
	 open_flag = O_RDONLY;
	 break;
     }

     retries = 0;
fcc_retry:
     /*
      * SUNW
      * If we are opening in NOUNLINK mode, check whether we are opening a
      * symlink or a file owned by some other user and take preventive action.
      */
     newfile = 0;
     if (mode == FCC_OPEN_AND_ERASE_NOUNLINK) {
	  retval = krb5_fcc_open_nounlink(data->filename, open_flag,
					  &fd, &newfile);
	  if (retval == 0 && fd == -1)
	       goto fcc_retry;
     } else {
	  fd = THREEPARAMOPEN (data->filename, open_flag | O_BINARY, 0600);
     }
     if (fd == -1)
	  return krb5_fcc_interpret (context, errno);

     if (data->mode == FCC_OPEN_RDONLY)
	lock_flag = KRB5_LOCKMODE_SHARED;
     else
	lock_flag = KRB5_LOCKMODE_EXCLUSIVE;

     if ((retval = krb5_lock_file(context, fd, lock_flag))) {
	  (void) close(fd);
	  if (retval == EAGAIN && retries++ < LOCK_RETRIES) {
	       /* wait some time before retrying */
	       if (poll(NULL, 0, WAIT_LENGTH) == 0)
		    goto fcc_retry;
	  }
	  syslog(LOG_ERR, "Failed to lock %s [%m]", data->filename);
	  return retval;
     }

     if (mode == FCC_OPEN_AND_ERASE || mode == FCC_OPEN_AND_ERASE_NOUNLINK) {
	 int cnt;

	 /*
	  * SUNW
	  * If this file was not created, we have to flush existing data.
	  * This will happen only if we are doing an ERASE_NOUNLINK open.
	  */
	 if (newfile == 0 && (ftruncate(fd, 0) == -1)) {
	      syslog(LOG_ERR, "ftruncate failed for %s [%m]", data->filename);
	      close(fd);
	      return (krb5_fcc_interpret(context, errno));
	 }

	 /* write the version number */
	 fcc_fvno = htons(context->fcc_default_format);
	 data->version = context->fcc_default_format;
	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     retval = ((cnt == -1) ? krb5_fcc_interpret(context, errno) :
		       KRB5_CC_IO);
	     goto done;
	 }

	 data->fd = fd;
	
	 if (data->version == KRB5_FCC_FVNO_4) {
	     /* V4 of the credentials cache format allows for header tags */

	     fcc_flen = 0;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
		 fcc_flen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));

	     /* Write header length */
	     retval = krb5_fcc_store_ui_2(context, id, (krb5_int32)fcc_flen);
	     if (retval) goto done;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		 /* Write time offset tag */
		 fcc_tag = FCC_TAG_DELTATIME;
		 fcc_taglen = 2*sizeof(krb5_int32);
		
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_tag);
		 if (retval) goto done;
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_taglen);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->time_offset);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->usec_offset);
		 if (retval) goto done;
	     }
	 }
	 goto done;
     }

     /* verify a valid version number is there */
     if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	 sizeof(fcc_fvno)) {
	 retval = KRB5_CC_FORMAT;
	 goto done;
     }
     if ((fcc_fvno != htons(KRB5_FCC_FVNO_4)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_3)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_2)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_1)))
     {
	 retval = KRB5_CCACHE_BADVNO;
	 goto done;
     }

     data->version = ntohs(fcc_fvno);
     data->fd = fd;

     if (data->version == KRB5_FCC_FVNO_4) {
	 char buf[1024];

	 if (krb5_fcc_read_ui_2(context, id, &fcc_flen) ||
	     (fcc_flen > sizeof(buf)))
	 {
	     retval = KRB5_CC_FORMAT;
	     goto done;
	 }

	 while (fcc_flen) {
	     if ((fcc_flen < (2 * sizeof(krb5_ui_2))) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_tag) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_taglen) ||
		 (fcc_taglen > (fcc_flen - 2*sizeof(krb5_ui_2))))
	     {
		 retval = KRB5_CC_FORMAT;
		 goto done;
	     }

	     switch (fcc_tag) {
	     case FCC_TAG_DELTATIME:
		 if (fcc_taglen != 2*sizeof(krb5_int32)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
		     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
		 {
		     if (krb5_fcc_read(context, id, buf, fcc_taglen)) {
			 retval = KRB5_CC_FORMAT;
			 goto done;
		     }
		     break;
		 }
		 if (krb5_fcc_read_int32(context, id, &os_ctx->time_offset) ||
		     krb5_fcc_read_int32(context, id, &os_ctx->usec_offset))
		 {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 os_ctx->os_flags =
		     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
		      KRB5_OS_TOFFSET_VALID);
		 break;
	     default:
		 if (fcc_taglen && krb5_fcc_read(context,id,buf,fcc_taglen)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 break;
	     }
	     fcc_flen -= (2*sizeof(krb5_ui_2) + fcc_taglen);
	 }
     }

done:
     if (retval) {
	 data->fd = -1;
	 (void) krb5_unlock_file(context, fd);
	 (void) close(fd);
     }
     return retval;
}
