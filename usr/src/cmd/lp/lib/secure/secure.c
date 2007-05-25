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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "sys/param.h"
#include "stdlib.h"

#include "lp.h"
#include "secure.h"
#include <tsol/label.h>

/**
 ** getsecure() - EXTRACT SECURE REQUEST STRUCTURE FROM DISK FILE
 **/

SECURE *
getsecure(char *file)
{
	SECURE		*secp;

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

	secp = calloc(sizeof (*secp), 1);

	secp->user = 0;
	errno = 0;
	for (
		fld = 0;
		fld < SC_MAX && fdgets(buf, BUFSIZ, fd);
		fld++
	) {
		buf[strlen(buf) - 1] = 0;
		switch (fld) {

		case SC_REQID:
			secp->req_id = Strdup(buf);
			break;

		case SC_UID:
			secp->uid = (uid_t)atol(buf);
			break;

		case SC_USER:
			secp->user = Strdup(buf);
			break;

		case SC_GID:
			secp->gid = (gid_t)atol(buf);
			break;

		case SC_SIZE:
			secp->size = (size_t)atol(buf);
			break;

		case SC_DATE:
			secp->date = (time_t)atol(buf);
			break;

		case SC_SLABEL:
			secp->slabel = Strdup(buf);
			break;
		}
	}
	if (errno != 0 || fld != SC_MAX) {
		int			save_errno = errno;

		freesecure (secp);
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
	        secp->uid > MAXUID
	     || !secp->user
	     || secp->gid > MAXUID
	     || secp->size == 0
	     || secp->date <= 0
	) {
		freesecure (secp);
		errno = EBADF;
		return (0);
	}

	return (secp);
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
			(void)fdprintf(fd, "%u\n", secbufp->uid);
			break;

		case SC_USER:
			(void)fdprintf(fd, "%s\n", secbufp->user);
			break;

		case SC_GID:
			(void)fdprintf(fd, "%u\n", secbufp->gid);
			break;

		case SC_SIZE:
			(void)fdprintf(fd, "%lu\n", secbufp->size);
			break;

		case SC_DATE:
			(void)fdprintf(fd, "%ld\n", secbufp->date);
			break;

		case SC_SLABEL:
			if (secbufp->slabel == NULL) {
				if (is_system_labeled()) {
					m_label_t *sl;

					sl = m_label_alloc(MAC_LABEL);
					(void) getplabel(sl);
					if (label_to_str(sl, &(secbufp->slabel),
					    M_INTERNAL, DEF_NAMES) != 0) {
						perror("label_to_str");
						secbufp->slabel =
						    strdup("bad_label");
					}
					m_label_free(sl);
					(void) fdprintf(fd, "%s\n",
					    secbufp->slabel);
				} else {
					(void) fdprintf(fd, "none\n");
				}
			} else {
				(void) fdprintf(fd, "%s\n", secbufp->slabel);
			}
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
	Free (secbufp);

	return;
}
