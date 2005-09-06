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
 * Data Link API - Bind
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
dl_bind(int fd, int sap, int xidtest, int oitype)
{
	struct dl_descriptor *dl;
	struct strbuf ctl;
	int flags;

	dl = _getdesc(fd);
	if (dl != NULL) {
		union DL_primitives prim;

		if (dl->info.state != DL_UNBOUND) {
			dl->error = DLBOUND;
			return (-1);
		}

		ctl.maxlen = ctl.len = sizeof (dl_bind_req_t);
		ctl.buf = (char *)&prim;
		memset(&prim, '\0', sizeof (prim));
		prim.dl_primitive = DL_BIND_REQ;
		prim.bind_req.dl_sap = sap;
#if defined(SNAP) && defined(DLPI_1)
		if (sap == 0xAA) {
			memcpy(&prim.bind_req.GROWTH_field[0], oi, 3);
			prim.bind_req.GROWTH_field[1] = oitype;
		}
#endif
#if !defined(DLPI_1)
		prim.bind_req.dl_max_conind = 0;
		prim.bind_req.dl_conn_mgmt = 0;
		prim.bind_req.dl_xidtest_flg = xidtest;
		prim.bind_req.dl_service_mode = DL_CLDLS;
#endif
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
			printf("error=%d\n", dl->error);
			return (-1);
		case DL_BIND_ACK:
			dl->info.state = DLSTATE_IDLE;
			if (sap > 1500)
				/* patch things for later use */
				dl->info.addr_len = 8;
			else if (sap < 512) {
				if (sap == 0xAA)
					dl->info.addr_len = 12;
				else
					dl->info.addr_len = 7;
			}
			return (0);
		default:
			printf("bad prim\n");
			dl->error = DLBADPRIM;
			return (-1);
		}
	}
	printf("fell through\n");
	return (-1);
}
