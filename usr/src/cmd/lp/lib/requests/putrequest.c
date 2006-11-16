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
#include "sys/utsname.h"
#include "stdlib.h"

#include "lp.h"
#include "requests.h"

extern struct {
	char			*v;
	short			len;
}			reqheadings[];

/**
 ** putrequest() - WRITE REQUEST STRUCTURE TO DISK FILE
 **/

int
#if	defined(__STDC__)
putrequest (
	char *			file,
	REQUEST *		reqbufp
)
#else
putrequest (file, reqbufp)
	char			*file;
	REQUEST			*reqbufp;
#endif
{
	char			**pp,
				*path;

	int fd;

	int			fld;

	/*
	 * First go through the structure and see if we have
	 * anything strange.
	 */
	if (
		reqbufp->copies <= 0
	     || !(reqbufp->destination)
	     || !reqbufp->file_list || !*(reqbufp->file_list)
	     || (reqbufp->actions & (ACT_MAIL|ACT_WRITE))
			&& (reqbufp->alert && *(reqbufp->alert))
	     || reqbufp->priority < -1 || 39 < reqbufp->priority
	) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Now open the file and write out the request.
	 */

	/*
	 * Full pathname? If so the file must lie in LP's
	 * regular temporary directory.
	 */
	if (*file == '/') {
		if (!STRNEQU(file, Lp_Tmp, strlen(Lp_Tmp))) {
			errno = EINVAL;
			return (-1);
		}
		path = Strdup(file);

	/*
	 * A relative pathname (such as system/name)?
	 * If so we'll locate it under LP's regular temporary
	 * directory.
	 */
	} else if (strchr(file, '/')) {
		if (!(path = makepath(Lp_Tmp, file, (char *)0)))
			return (-1);

	/*
	 * If must be a simple name. Locate this under the
	 * special temporary directory that is linked to the
	 * regular place for the local system.
	 */
	} else if (!(path = makepath(Lp_Temp, file, (char *)0)))
		return (-1);

	if ((fd = open_locked(path, "w", MODE_NOREAD)) < 0) {
		Free (path);
		return (-1);
	}
	Free (path);

	for (fld = 0; fld < RQ_MAX; fld++)  switch (fld) {

#define HEAD	reqheadings[fld].v

	case RQ_COPIES:
		(void)fdprintf(fd, "%s%d\n", HEAD, reqbufp->copies);
		break;

	case RQ_DEST:
		(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->destination);
		break;

	case RQ_FILE:
		for (pp = reqbufp->file_list; *pp; pp++)
			(void)fdprintf(fd, "%s%s\n", HEAD, *pp);
		break;

	case RQ_FORM:
		if (reqbufp->form)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->form);
		break;

	case RQ_HANDL:
		if ((reqbufp->actions & ACT_SPECIAL) == ACT_IMMEDIATE)
			(void)fdprintf(fd, "%s%s\n", HEAD, NAME_IMMEDIATE);
		else if ((reqbufp->actions & ACT_SPECIAL) == ACT_RESUME)
			(void)fdprintf(fd, "%s%s\n", HEAD, NAME_RESUME);
		else if ((reqbufp->actions & ACT_SPECIAL) == ACT_HOLD)
			(void)fdprintf(fd, "%s%s\n", HEAD, NAME_HOLD);
		break;

	case RQ_NOTIFY:
		if (reqbufp->actions & ACT_MAIL)
			(void)fdprintf(fd, "%sM\n", HEAD);
		else if (reqbufp->actions & ACT_WRITE)
			(void)fdprintf(fd, "%sW\n", HEAD);
		else if (reqbufp->actions & ACT_NOTIFY)
			(void)fdprintf(fd, "%sN\n", HEAD);
		else if (reqbufp->alert && *(reqbufp->alert))
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->alert);
		break;

	case RQ_OPTS:
		if (reqbufp->options)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->options);
		break;

	case RQ_PRIOR:
		if (reqbufp->priority != -1)
			(void)fdprintf(fd, "%s%d\n", HEAD, reqbufp->priority);
		break;

	case RQ_PAGES:
		if (reqbufp->pages)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->pages);
		break;

	case RQ_CHARS:
		if (reqbufp->charset)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->charset);
		break;

	case RQ_TITLE:
		if (reqbufp->title)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->title);
		break;

	case RQ_MODES:
		if (reqbufp->modes)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->modes);
		break;

	case RQ_TYPE:
		if (reqbufp->input_type)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->input_type);
		break;

	case RQ_USER:
		if (reqbufp->user)
			(void)fdprintf(fd, "%s%s\n", HEAD, reqbufp->user);
		break;

	case RQ_RAW:
		if (reqbufp->actions & ACT_RAW)
			(void)fdprintf(fd, "%s\n", HEAD);
		break;

	case RQ_FAST:
		if (reqbufp->actions & ACT_FAST)
			(void)fdprintf(fd, "%s\n", HEAD);
		break;

	case RQ_STAT:
		(void)fdprintf(fd, "%s%#6.4x\n", HEAD, reqbufp->outcome);
		break;
	
	}

	close(fd);
	return (0);
}
