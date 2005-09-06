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
 * Data Link API - Unbind Descriptor
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/dlpi.h>
#include <errno.h>
#include <dluser.h>
#include <dlhdr.h>

extern struct dl_descriptor *_getdesc();

int
dl_unbind(int fd)
{
	struct dl_descriptor *dl;
	struct strbuf ctl;
	int flags;
	union DL_primitives prim;

	if ((dl = _getdesc(fd)) == NULL) {
		errno = EBADF;
		return (-1);
	}
	if (dl->info.state == DLSTATE_IDLE) {
		ctl.maxlen = ctl.len = sizeof (dl_unbind_req_t);
		ctl.buf = (char *)&prim;
		memset(&prim, '\0', sizeof (prim));
		prim.dl_primitive = DL_UNBIND_REQ;
	} else {
		dl->error = DLOUTSTATE;
		return (-1);
	}
	if (putmsg(fd, &ctl, NULL, 0) < 0) {
		dl->error = DLSYSERR;
		return (-1);
	}
	ctl.maxlen = sizeof (prim);
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0) {
		dl->error = DLSYSERR;
		return (-1);
	}
	if (prim.dl_primitive != DL_OK_ACK) {
		dl->error = DLOUTSTATE;
		return (-1);
	}
	return (0);
}
