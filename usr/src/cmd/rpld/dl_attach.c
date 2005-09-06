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
 * Data Link API - Attach physical unit
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
dl_attach(int fd, int unit)
{
	struct dl_descriptor *dl;
	struct strbuf ctl;
	int flags;

	dl = _getdesc(fd);
	if (dl != NULL) {
		union DL_primitives prim;

		if (dl->info.state != DL_UNATTACHED) {
			if (dl->info.style != DL_STYLE_2)
				dl->error = DLNOTSUPP;
			else if (dl->info.state == DL_BOUND)
				dl->error = DLBOUND;
			else
				dl->error = DLSYSERR;
			return (-1);
		}

		prim.dl_primitive = DL_ATTACH_REQ;
		/* this is opaque data of 32-bits */
		prim.attach_req.dl_ppa = unit;
		ctl.maxlen = ctl.len = sizeof (prim);
		ctl.len = ctl.len = sizeof (prim.attach_req);
		ctl.buf = (char *)&prim;
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
		switch (prim.dl_primitive) {
		case DL_ERROR_ACK:
			dl->error = prim.error_ack.dl_errno;
			errno = prim.error_ack.dl_unix_errno;
			return (-1);
		case DL_OK_ACK:
			dl->info.state = DLSTATE_UNBOUND;
			return (0);
		default:
			dl->error = DLBADPRIM;
			return (-1);
		}
	}
	return (-1);
}
