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
 * Data Link API - Send Data
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/dlpi.h>
#include <dluser.h>
#include <dlhdr.h>

extern struct dl_descriptor *_getdesc();

int
#if defined(DLPI_1)
dl_snd(int fd, char *buff, int bufflen, struct dl_address *addr)
#else
dl_snd(int fd, char *buff, int bufflen, struct dl_address *addr,
    dl_priority_t *priority)
#endif
{
	struct dl_descriptor *dl;
	struct strbuf ctl, data;

	if ((dl = _getdesc(fd)) != NULL) {
		union DL_primitives prim;

		if (dl->info.state != DLSTATE_IDLE) {
			dl->error = DLUNBOUND;
			return (-1);
		}
		memset(&prim, '\0', sizeof (prim));
		prim.unitdata_req.dl_primitive = DL_UNITDATA_REQ;
#if !defined(DLPI_1)
		if (priority != NULL)
			prim.unitdata_req.dl_priority = *priority;
#endif
		prim.unitdata_req.dl_dest_addr_length = addr->dla_dlen;
		prim.unitdata_req.dl_dest_addr_offset =
		    sizeof (dl_unitdata_req_t);
		memcpy(((unsigned char *)&prim)+sizeof (dl_unitdata_req_t),
		    addr->dla_daddr, addr->dla_dlen);
		ctl.maxlen = ctl.len =
		    sizeof (dl_unitdata_req_t) + addr->dla_dlen;
		ctl.buf = (char *)&prim;
		data.maxlen = data.len = bufflen;
		data.buf = buff;
		if (putmsg(fd, &ctl, &data, 0) < 0) {
			dl->error = DLSYSERR;
			return (-1);
		}
		return (0);
	}
	return (-1);
}
