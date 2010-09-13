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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<stdio.h>
#include	<stdarg.h>
#include	"users.h"

extern	char	*errmsgs[];
extern	int	lasterrmsg;
extern	char	*cmdname;

/*
 *	synopsis: errmsg(msgid, (arg1, ..., argN))
 */

void
errmsg(int msgid, ...)
{
	va_list	args;

	va_start(args, msgid);

	if (msgid >= 0 && msgid < lasterrmsg) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) vfprintf(stderr, errmsgs[ msgid ], args);
	}

	va_end(args);
}

void
warningmsg(int what, char *name)
{
	if ((what & WARN_NAME_TOO_LONG) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name too long.\n", name);
	}
	if ((what & WARN_BAD_GROUP_NAME) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name should be all lower case"
			" or numeric.\n", name);
	}
	if ((what & WARN_BAD_PROJ_NAME) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name should be all lower case"
			" or numeric.\n", name);
	}
	if ((what & WARN_BAD_LOGNAME_CHAR) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name should be all alphanumeric,"
			" '-', '_', or '.'\n", name);
	}
	if ((what & WARN_BAD_LOGNAME_FIRST) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name first character"
			" should be alphabetic.\n", name);
	}
	if ((what & WARN_NO_LOWERCHAR) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s name should have at least one "
			"lower case character.\n", name);
	}
	if ((what & WARN_LOGGED_IN) != 0) {
		(void) fprintf(stderr, "UX: %s: ", cmdname);
		(void) fprintf(stderr, "%s is currently logged in, some changes"
			" may not take effect until next login.\n", name);
	}
}
