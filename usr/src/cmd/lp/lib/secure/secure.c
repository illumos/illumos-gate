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

#include "string.h"
#include "sys/param.h"
#include "stdlib.h"

#include "lp.h"
#include "secure.h"

/**
 ** getsecure() - EXTRACT SECURE REQUEST STRUCTURE FROM DISK FILE
 **/

SECURE *
getsecure(char *file)
{
	static SECURE		secbuf;

	char			buf[BUFSIZ],
				*path;

	int fd;

	int			fld;


	if (*file == '/')
		path = Strdup(file);
	else
		path = makepath(Lp_Requests, file, (char *)0);
	if (!path)
		return (0);

	if ((fd = open_locked(path, "r", MODE_NOREAD)) < 0) {
		Free (path);
		return (0);
	}
	Free (path);

	secbuf.user = 0;
	errno = 0;
	for (
		fld = 0;
		fld < SC_MAX && fdgets(buf, BUFSIZ, fd);
		fld++
	) {
		buf[strlen(buf) - 1] = 0;
		switch (fld) {

		case SC_REQID:
			secbuf.req_id = Strdup(buf);
			break;

		case SC_UID:
			secbuf.uid = (uid_t)atol(buf);
			break;

		case SC_USER:
			secbuf.user = Strdup(buf);
			break;

		case SC_GID:
			secbuf.gid = (gid_t)atol(buf);
			break;

		case SC_SIZE:
			secbuf.size = (size_t)atol(buf);
			break;

		case SC_DATE:
			secbuf.date = (time_t)atol(buf);
			break;

		case SC_SYSTEM:
			secbuf.system = Strdup(buf);
			break;
		}
	}
	if (errno != 0 || fld != SC_MAX) {
		int			save_errno = errno;

		freesecure (&secbuf);
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
	        secbuf.uid > MAXUID || secbuf.uid < -1
	     || !secbuf.user
	     || secbuf.gid > MAXUID || secbuf.gid < -1
	     || secbuf.size == 0
	     || secbuf.date <= 0
	) {
		freesecure (&secbuf);
		errno = EBADF;
		return (0);
	}

	return (&secbuf);
}

/**
 ** putsecure() - WRITE SECURE REQUEST STRUCTURE TO DISK FILE
 **/

int
putsecure(char *file, SECURE *secbufp)
{
	char			*path;

	int fd;

	int			fld;

	if (*file == '/')
		path = Strdup(file);
	else
		path = makepath(Lp_Requests, file, (char *)0);
	if (!path)
		return (-1);

	if ((fd = open_locked(path, "w", MODE_NOREAD)) < 0) {
		Free (path);
		return (-1);
	}
	Free (path);

	if (
		!secbufp->req_id ||
		!secbufp->user
	)
		return (-1);

	for (fld = 0; fld < SC_MAX; fld++)

		switch (fld) {

		case SC_REQID:
			(void)fdprintf(fd, "%s\n", secbufp->req_id);
			break;

		case SC_UID:
			(void)fdprintf(fd, "%ld\n", secbufp->uid);
			break;

		case SC_USER:
			(void)fdprintf(fd, "%s\n", secbufp->user);
			break;

		case SC_GID:
			(void)fdprintf(fd, "%ld\n", secbufp->gid);
			break;

		case SC_SIZE:
			(void)fdprintf(fd, "%lu\n", secbufp->size);
			break;

		case SC_DATE:
			(void)fdprintf(fd, "%ld\n", secbufp->date);
			break;

		case SC_SYSTEM:
			(void)fdprintf(fd, "%s\n", secbufp->system);
			break;
		}

	close(fd);

	return (0);
}

/*
**  rmsecure ()
**
**	o  'reqfilep' is of the form 'node-name/request-file'
**	   e.g. 'sfcalv/123-0'.
*/
int
rmsecure (char *reqfilep)
{
	int	n;
	char *	pathp;

	pathp = makepath (Lp_Requests, reqfilep, (char *) 0);
	if (! pathp)
		return	-1;

	n = Unlink (pathp);
	Free (pathp);

	return	n;
}

/**
 ** freesecure() - FREE A SECURE STRUCTURE
 **/

void
freesecure(SECURE *secbufp)
{
	if (!secbufp)
		return;
	if (secbufp->req_id)
		Free (secbufp->req_id);
	if (secbufp->user)
		Free (secbufp->user);
	if (secbufp->system)
		Free (secbufp->system);
	return;
}

