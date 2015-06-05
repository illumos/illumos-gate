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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/list.h>
#include <assert.h>
#include <alloca.h>
#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <synch.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <umem.h>

#include <smbsrv/smb_door.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/libsmbns.h>
#include "smbd.h"


/*
 * Special version of smb_door_dispatch() for the
 * "fake" smbsrv (running in user space).
 *
 * This is called via function pointer from
 * smbsrv: smb_kdoor_upcall()
 *
 * The args and response go RPC encoded, just so we can
 * borrow some of the common doorsvc code, even though
 * there's no need for RPC encoding in this scenario.
 */
int
fksmbd_door_dispatch(smb_doorarg_t *da)
{

	smbd_arg_t	dop_arg;
	smb_doorhdr_t	*hdr;
	char		*rbuf = NULL;
	char		*argp = da->da_arg.data_ptr;
	size_t		arg_size = da->da_arg.data_size;
	size_t		hdr_size, rsize;

	/*
	 * Decode
	 *
	 * da->da_arg.data_ptr  = (arg data, xdr encoded)
	 * da->da_arg.data_size = (arg data len)
	 */

	bzero(&dop_arg, sizeof (smbd_arg_t));
	hdr = &dop_arg.hdr;
	hdr_size = xdr_sizeof(smb_doorhdr_xdr, hdr);

	if ((argp == NULL) || (arg_size < hdr_size)) {
		syslog(LOG_DEBUG, "fksmbd_door_dispatch: bad args");
		return (-1);
	}

	if (smb_doorhdr_decode(hdr, (uint8_t *)argp, hdr_size) == -1) {
		syslog(LOG_DEBUG, "smbd_door_dispatch: header decode failed");
		return (-1);
	}

	if ((hdr->dh_magic != SMB_DOOR_HDR_MAGIC) ||
	    (hdr->dh_flags != SMB_DF_FAKE_KERNEL)) {
		syslog(LOG_DEBUG, "fksmbd_door_dispatch: invalid header");
		return (-1);
	}

	dop_arg.opname = smb_doorhdr_opname(hdr->dh_op);
	dop_arg.data = argp + hdr_size;
	dop_arg.datalen = hdr->dh_datalen;

	if (hdr->dh_op == SMB_DR_ASYNC_RESPONSE) {
		/*
		 * ASYNC_RESPONSE is not used here.
		 */
		syslog(LOG_DEBUG, "fksmbd_door_dispatch: ASYNC?");
		return (-1);
	}

	/*
	 * Dispatch
	 *
	 * Call the common smbd_doorsvc.c code.
	 */
	(void) smbd_door_dispatch_op(&dop_arg);

	/*
	 * Encode
	 *
	 * da->da_arg.rbuf  = (return data buf)
	 * da->da_arg.rsize = (return data size)
	 *
	 * Note that the return data buffer initially
	 * points to the same buffer as the args.
	 * If that's not large enough, umem_alloc.
	 */

	rsize = dop_arg.rsize + hdr_size;
	rbuf = umem_alloc(rsize, UMEM_DEFAULT);
	if (rbuf == NULL) {
		syslog(LOG_DEBUG, "fksmbd_door_dispatch[%s]: alloc %m",
		    dop_arg.opname);
		return (-1);
	}

	/* Copy caller's return data after the header. */
	if (dop_arg.rbuf != NULL) {
		(void) memcpy(rbuf + hdr_size, dop_arg.rbuf, dop_arg.rsize);
		free(dop_arg.rbuf);
	}

	hdr->dh_datalen = dop_arg.rsize;
	(void) smb_doorhdr_encode(hdr, (uint8_t *)rbuf, hdr_size);

	/* Let's update da->da_hdr too. */
	da->da_hdr = *hdr;

	/*
	 * Was door_return()
	 * NB: The "fake kernel" smbsrv code will umem_free rbuf.
	 */
	da->da_arg.rbuf = rbuf;
	da->da_arg.rsize = rsize;

	return (0);
}
