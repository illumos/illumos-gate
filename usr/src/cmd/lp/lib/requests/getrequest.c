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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.14	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "requests.h"

extern struct {
	char			*v;
	short			len;
}			reqheadings[];

/**
 ** getrequest() - EXTRACT REQUEST STRUCTURE FROM DISK FILE
 **/

REQUEST *
#if	defined(__STDC__)
getrequest (
	char *			file
)
#else
getrequest (file)
	char			*file;
#endif
{
	static REQUEST		reqbuf;

	char			buf[BUFSIZ],
				*path,
				*p;

	int fd;

	int			fld;


	/*
	 * Full pathname? If so the file must lie in LP's
	 * regular temporary directory.
	 */
	if (*file == '/') {
		if (!STRNEQU(file, Lp_Tmp, strlen(Lp_Tmp))) {
			errno = EINVAL;
			return (0);
		}
		path = Strdup(file);

	/*
	 * A relative pathname (such as system/name)?
	 * If so we'll locate it under LP's regular temporary
	 * directory.
	 */
	} else if (strchr(file, '/')) {
		if (!(path = makepath(Lp_Tmp, file, (char *)0)))
			return (0);

	/*
	 * It must be a simple name. Locate this under the
	 * special temporary directory that is linked to the
	 * regular place for the local system.
	 */
	} else if (!(path = makepath(Lp_Temp, file, (char *)0)))
		return (0);
    

	if ((fd = open_locked(path, "r", 0)) < 0) {
		Free (path);
		return (0);
	}
	Free (path);

	reqbuf.copies		= 1;
	reqbuf.destination	= 0;
	reqbuf.file_list	= 0;
	reqbuf.form		= 0;
	reqbuf.actions		= 0;
	reqbuf.alert		= 0;
	reqbuf.options		= 0;
	reqbuf.priority		= -1;
	reqbuf.pages		= 0;
	reqbuf.charset		= 0;
	reqbuf.modes		= 0;
	reqbuf.title		= 0;
	reqbuf.input_type	= 0;
	reqbuf.user		= 0;
	reqbuf.outcome		= 0;
	reqbuf.version		= VERSION_OLD_LP;

	errno = 0;
	while (fdgets(buf, BUFSIZ, fd)) {

		buf[strlen(buf) - 1] = 0;

		for (fld = 0; fld < RQ_MAX; fld++)
			if (
				reqheadings[fld].v
			     && reqheadings[fld].len
			     && STRNEQU(
					buf,
					reqheadings[fld].v,
					reqheadings[fld].len
				)
			) {
				p = buf + reqheadings[fld].len;
				break;
			}

		/*
		 * To allow future extensions to not impact applications
		 * using old versions of this routine, ignore strange
		 * fields.
		 */
		if (fld >= RQ_MAX)
			continue;

		switch (fld) {

		case RQ_COPIES:
			reqbuf.copies = atoi(p);
			break;

		case RQ_DEST:
			reqbuf.destination = Strdup(p);
			break;

		case RQ_FILE:
			appendlist (&reqbuf.file_list, p);
			break;

		case RQ_FORM:
			if (!STREQU(p, NAME_ANY))
				reqbuf.form = Strdup(p);
			break;

		case RQ_HANDL:
			if (STREQU(p, NAME_RESUME))
				reqbuf.actions |= ACT_RESUME;
			else if (STREQU(p, NAME_HOLD))
				reqbuf.actions |= ACT_HOLD;
			else if (STREQU(p, NAME_IMMEDIATE))
				reqbuf.actions |= ACT_IMMEDIATE;
			break;

		case RQ_NOTIFY:
			if (STREQU(p, "M"))
				reqbuf.actions |= ACT_MAIL;
			else if (STREQU(p, "W"))
				reqbuf.actions |= ACT_WRITE;
			else if (STREQU(p, "N"))
				reqbuf.actions |= ACT_NOTIFY;
			else
				reqbuf.alert = Strdup(p);
			break;

		case RQ_OPTS:
			reqbuf.options = Strdup(p);
			break;

		case RQ_PRIOR:
			reqbuf.priority = atoi(p);
			break;

		case RQ_PAGES:
			reqbuf.pages = Strdup(p);
			break;

		case RQ_CHARS:
			if (!STREQU(p, NAME_ANY))
				reqbuf.charset = Strdup(p);
			break;

		case RQ_TITLE:
			reqbuf.title = Strdup(p);
			break;

		case RQ_MODES:
			reqbuf.modes = Strdup(p);
			break;

		case RQ_TYPE:
			reqbuf.input_type = Strdup(p);
			break;

		case RQ_USER:
			reqbuf.user = Strdup(p);
			break;

		case RQ_RAW:
			reqbuf.actions |= ACT_RAW;
			break;

		case RQ_FAST:
			reqbuf.actions |= ACT_FAST;
			break;

		case RQ_STAT:
			reqbuf.outcome = (ushort)strtol(p, (char **)0, 16);
			break;

		case RQ_VERSION:
			reqbuf.version = atoi(p);
			break;

		}

	}
	if (errno != 0) {
		int			save_errno = errno;

		close(fd);
		errno = save_errno;
		return (0);
	}
	close(fd);

	/*
	 * Now go through the structure and see if we have
	 * anything strange.
	 */
	if (
		reqbuf.copies <= 0
	     || !reqbuf.file_list || !*(reqbuf.file_list)
	     || reqbuf.priority < -1 || 39 < reqbuf.priority
	     || STREQU(reqbuf.input_type, NAME_ANY)
	     || STREQU(reqbuf.input_type, NAME_TERMINFO)
	) {
		freerequest (&reqbuf);
		errno = EBADF;
		return (0);
	}

	/*
	 * Guarantee some return values won't be null or empty.
	 */
	if (!reqbuf.destination || !*reqbuf.destination) {
		if (reqbuf.destination)
			Free (reqbuf.destination);
		reqbuf.destination = Strdup(NAME_ANY);
	}
	if (!reqbuf.input_type || !*reqbuf.input_type) {
		if (reqbuf.input_type)
			Free (reqbuf.input_type);
		reqbuf.input_type = Strdup(NAME_SIMPLE);
	}

	return (&reqbuf);
}
