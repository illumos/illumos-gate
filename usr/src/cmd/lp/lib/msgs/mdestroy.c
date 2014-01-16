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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/
# include	<string.h>
# include	<stropts.h>
# include	<errno.h>
# include	<stdlib.h>
# include	<unistd.h>

# include	"lp.h"
# include	"msgs.h"

int mdestroy(MESG *md)
{
	struct pollfd pfd;
	struct strrecvfd    recbuf;

	if (!md || md->type != MD_MASTER || md->file == NULL) {
		errno = EINVAL;
		return(-1);
	}

	if (fdetach(md->file) != 0)
		return(-1);

	pfd.fd = md->readfd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 500) > 0) {
		if (ioctl(md->readfd, I_RECVFD, &recbuf) == 0)
			close(recbuf.fd);
	}

	/*
	 * Pop connld module
	 */
	if (ioctl(md->writefd, I_POP, 0) != 0)
		return(-1);

	Free(md->file);
	md->file = NULL;

	(void) mdisconnect(md);

	return(0);
}
