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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYSEXITS_H
#define	_SYSEXITS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  SYSEXITS.H -- Exit status codes employed by the mail subsystem.
 *
 *	This include file attempts to categorize possible error
 *	exit statuses for mail subsystem.
 *
 *	Error numbers begin at EX__BASE to reduce the possibility of
 *	clashing with other exit statuses that random programs may
 *	already return.  The meaning of the codes is approximately
 *	as follows:
 *
 *	EX_USAGE -- The command was used incorrectly, e.g., with
 *		the wrong number of arguments, a bad flag, a bad
 *		syntax in a parameter, or whatever.
 *	EX_DATAERR -- The input data was incorrect in some way.
 *		This should only be used for user's data & not
 *		system files.
 *	EX_NOINPUT -- An input file (not a system file) did not
 *		exist or was not readable.  This could also include
 *		errors like "No message" to a mailer (if it cared
 *		to catch it).
 *	EX_NOUSER -- The user specified did not exist.  This might
 *		be used for mail addresses or remote logins.
 *	EX_NOHOST -- The host specified did not exist.  This is used
 *		in mail addresses or network requests.
 *	EX_UNAVAILABLE -- A service is unavailable.  This can occur
 *		if a support program or file does not exist.  This
 *		can also be used as a catchall message when something
 *		you wanted to do doesn't work, but you don't know
 *		why.
 *	EX_SOFTWARE -- An internal software error has been detected.
 *		This should be limited to non-operating system related
 *		errors as possible.
 *	EX_OSERR -- An operating system error has been detected.
 *		This is intended to be used for such things as "cannot
 *		fork", "cannot create pipe", or the like.  It includes
 *		things like getuid returning a user that does not
 *		exist in the passwd file.
 *	EX_OSFILE -- Some system file (e.g., /etc/passwd, /etc/utmp,
 *		etc.) does not exist, cannot be opened, or has some
 *		sort of error (e.g., syntax error).
 *	EX_CANTCREAT -- A (user specified) output file cannot be
 *		created.
 *	EX_IOERR -- An error occurred while doing I/O on some file.
 *	EX_TEMPFAIL -- temporary failure, indicating something that
 *		is not really an error.  In sendmail, this means
 *		that a mailer (e.g.) could not create a connection,
 *		and the request should be reattempted later.
 *	EX_PROTOCOL -- the remote system returned something that
 *		was "not possible" during a protocol exchange.
 *	EX_NOPERM -- You did not have sufficient permission to
 *		perform the operation.  This is not intended for
 *		file system problems, which should use NOINPUT or
 *		CANTCREAT, but rather for higher level permissions.
 *		For example, kre uses this to restrict who students
 *		can send mail to.
 */

#define	EX_OK		0	/* successful termination */

#define	EX__BASE	64	/* base value for error messages */

#define	EX_USAGE	64	/* command line usage error */
#define	EX_DATAERR	65	/* data format error */
#define	EX_NOINPUT	66	/* cannot open input */
#define	EX_NOUSER	67	/* addressee unknown */
#define	EX_NOHOST	68	/* host name unknown */
#define	EX_UNAVAILABLE	69	/* service unavailable */
#define	EX_SOFTWARE	70	/* internal software error */
#define	EX_OSERR	71	/* system error (e.g., can't fork) */
#define	EX_OSFILE	72	/* critical OS file missing */
#define	EX_CANTCREAT	73	/* can't create (user) output file */
#define	EX_IOERR	74	/* input/output error */
#define	EX_TEMPFAIL	75	/* temp failure; user is invited to retry */
#define	EX_PROTOCOL	76	/* remote error in protocol */
#define	EX_NOPERM	77	/* permission denied */
#define	EX_CONFIG	78	/* configuration error */

#define	EX_NOTFOUND	79	/* entry not found */
#define	EX__MAX	79	/* maximum listed value */


#ifdef __cplusplus
}
#endif

#endif	/* _SYSEXITS_H */
