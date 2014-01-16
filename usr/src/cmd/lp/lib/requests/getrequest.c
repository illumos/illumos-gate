/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
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
	REQUEST		*reqp;

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

	reqp = calloc(sizeof (*reqp), 1);
	reqp->copies		= 1;
	reqp->priority		= -1;

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
			reqp->copies = atoi(p);
			break;

		case RQ_DEST:
			reqp->destination = Strdup(p);
			break;

		case RQ_FILE:
			appendlist (&reqp->file_list, p);
			break;

		case RQ_FORM:
			if (!STREQU(p, NAME_ANY))
				reqp->form = Strdup(p);
			break;

		case RQ_HANDL:
			if (STREQU(p, NAME_RESUME))
				reqp->actions |= ACT_RESUME;
			else if (STREQU(p, NAME_HOLD))
				reqp->actions |= ACT_HOLD;
			else if (STREQU(p, NAME_IMMEDIATE))
				reqp->actions |= ACT_IMMEDIATE;
			break;

		case RQ_NOTIFY:
			if (STREQU(p, "M"))
				reqp->actions |= ACT_MAIL;
			else if (STREQU(p, "W"))
				reqp->actions |= ACT_WRITE;
			else if (STREQU(p, "N"))
				reqp->actions |= ACT_NOTIFY;
			else
				reqp->alert = Strdup(p);
			break;

		case RQ_OPTS:
			reqp->options = Strdup(p);
			break;

		case RQ_PRIOR:
			reqp->priority = atoi(p);
			break;

		case RQ_PAGES:
			reqp->pages = Strdup(p);
			break;

		case RQ_CHARS:
			if (!STREQU(p, NAME_ANY))
				reqp->charset = Strdup(p);
			break;

		case RQ_TITLE:
			reqp->title = Strdup(p);
			break;

		case RQ_MODES:
			reqp->modes = Strdup(p);
			break;

		case RQ_TYPE:
			reqp->input_type = Strdup(p);
			break;

		case RQ_USER:
			reqp->user = Strdup(p);
			break;

		case RQ_RAW:
			reqp->actions |= ACT_RAW;
			break;

		case RQ_FAST:
			reqp->actions |= ACT_FAST;
			break;

		case RQ_STAT:
			reqp->outcome = (ushort)strtol(p, (char **)0, 16);
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
		reqp->copies <= 0
	     || !reqp->file_list || !*(reqp->file_list)
	     || reqp->priority < -1 || 39 < reqp->priority
	     || STREQU(reqp->input_type, NAME_ANY)
	     || STREQU(reqp->input_type, NAME_TERMINFO)
	) {
		freerequest (reqp);
		errno = EBADF;
		return (0);
	}

	/*
	 * Guarantee some return values won't be null or empty.
	 */
	if (!reqp->destination || !*reqp->destination) {
		if (reqp->destination)
			Free (reqp->destination);
		reqp->destination = Strdup(NAME_ANY);
	}
	if (!reqp->input_type || !*reqp->input_type) {
		if (reqp->input_type)
			Free (reqp->input_type);
		reqp->input_type = Strdup(NAME_SIMPLE);
	}

	return (reqp);
}
