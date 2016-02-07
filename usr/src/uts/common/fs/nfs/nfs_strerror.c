/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains code to support better NFS error messages.  Death to
 * integer codes in user error messages!
 *
 * XXX Ideally this code should be more general and available to the entire
 * kernel (see RFE 1101936).  When this happens, this file can go away.
 */

#include <nfs/nfs.h>
#include <sys/null.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/varargs.h>

/* size of a temporary printf format buffer. */
#define	FMT_BUF_SIZE	1024

static void expand_format_string(int, const char *, char *, int);
static char *nfs_strerror(int);

/*
 * nfs_perror: Works like printf (format string and variable args) except
 * that it will substitute an error message for a "%m" string (like
 * syslog), using the given errno value.
 */

void
nfs_perror(int error, char *fmt, ...)
{
	va_list ap;
	char buf[FMT_BUF_SIZE];		/* massaged version of fmt */

	/* Expand %m */

	expand_format_string(error, fmt, buf, FMT_BUF_SIZE);

	/*
	 * Now pass the massaged format string and its arguments off to
	 * printf.
	 */

	va_start(ap, fmt);
	(void) vzprintf(getzoneid(), buf, ap);
	va_end(ap);
}

/*
 * nfs_cmn_err: Works like cmn_err (error level, format string, and
 * variable args) except that it will substitute an error message for a
 * "%m" string (like syslog), using the given errno value.
 */

void
nfs_cmn_err(int error, int level, char *fmt, ...)
{
	va_list ap;
	char buf[FMT_BUF_SIZE];		/* massaged version of fmt */

	/* Expand %m */

	expand_format_string(error, fmt, buf, FMT_BUF_SIZE);

	/*
	 * Now pass the massaged format string and its arguments off to
	 * cmn_err.
	 */

	va_start(ap, fmt);
	(void) vzcmn_err(getzoneid(), level, buf, ap);
	va_end(ap);
}

/*
 * expand_format_string: copy the printf format string from "fmt" to "buf",
 * expanding %m to the error string for "error".
 */

static void
expand_format_string(int error, const char *fmt, char *buf, int buf_chars)
{
	const char *from;		/* pointer into fmt */
	char *to;			/* pointer into buf */
	char *errmsg;			/* expansion for %m */
	char *trunc_msg = "Truncated NFS error message: ";
	zoneid_t zoneid = getzoneid();

	/*
	 * Copy the given format string into the result buffer, expanding
	 * %m as we go.  If the result buffer is too short, complain and
	 * truncate the message.  (We don't expect this to ever happen,
	 * though.)
	 */

	for (from = fmt, to = buf; *from; from++) {
		if (to >= buf + buf_chars - 1) {
			zprintf(zoneid, trunc_msg);
			break;
		}
		if (*from == '%' && *(from+1) == 'm') {
			errmsg = nfs_strerror(error);
			/*
			 * If there's an error message and room to display
			 * it, copy it in.  If there's no message or not
			 * enough room, try just printing an error number.
			 * (We assume that the error value is in a
			 * reasonable range.)  If there's no room for
			 * anything, bail out.
			 */
			if (errmsg != NULL &&
			    strlen(buf) + strlen(errmsg) < buf_chars) {
				(void) strcpy(to, errmsg);
				to += strlen(errmsg);
			} else if (strlen(buf) + strlen("error XXX") <
			    buf_chars) {
				(void) sprintf(to, "error %d", error);
				/*
				 * Don't try to guess how many characters
				 * were laid down.
				 */
				to = buf + strlen(buf);
			} else {
				zprintf(zoneid, trunc_msg);
				break;
			}
			from++;
		} else {
			*to++ = *from;
		}
	}
	*to = '\0';
}

/*
 * nfs_strerror: map an errno value to a string.  Not all possible errno
 * values are supported.
 *
 * If there is no string for the given errno value, return NULL.
 */

static char *
nfs_strerror(int errcode)
{
	char *result;

	switch (errcode) {
	case EPERM:
		result = "Not owner";
		break;
	case ENOENT:
		result = "No such file or directory";
		break;
	case EIO:
		result = "I/O error";
		break;
	case EACCES:
		result = "Permission denied";
		break;
	case EEXIST:
		result = "File exists";
		break;
	case ENOTDIR:
		result = "Not a directory";
		break;
	case EISDIR:
		result = "Is a directory";
		break;
	case EINVAL:
		result = "Invalid argument";
		break;
	case EFBIG:
		result = "File too large";
		break;
	case ENOSPC:
		result = "No space left on device";
		break;
	case EROFS:
		result = "Read-only file system";
		break;
	case EDQUOT:
		result = "Disc quota exceeded";
		break;
	case ENOTEMPTY:
		result = "Directory not empty";
		break;
	case ESTALE:
		result = "Stale NFS file handle";
		break;
	case ENOMEM:
		result = "Not enough memory";
		break;
	default:
		result = NULL;
		break;
	}

	return (result);
}
