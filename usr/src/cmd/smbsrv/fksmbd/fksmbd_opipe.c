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

static int smbd_opipe_exec(uint32_t fid);


/*
 * Process smbd opipe requests.
 *
 * This is a special version of smb_opipe_dispatch()
 * for the "fake" smbsrv (running in user space).
 * This is called via function pointer from
 * smbsrv: smb_opipe_door_call()
 *
 * Very similar to smbd_opipe_dispatch()
 */
int
fksmbd_opipe_dispatch(door_arg_t *da)
{
	uint8_t *buf = (uint8_t *)da->data_ptr;
	smb_doorhdr_t hdr;
	size_t hdr_size;
	uint8_t *data;
	uint32_t datalen;

	if (!smbd_online())
		return (-1);

	bzero(&hdr, sizeof (smb_doorhdr_t));
	hdr_size = xdr_sizeof(smb_doorhdr_xdr, &hdr);

	if (da->data_ptr == NULL || da->data_size < hdr_size)
		return (-1);

	if (smb_doorhdr_decode(&hdr, buf, hdr_size) == -1)
		return (-1);

	if ((hdr.dh_magic != SMB_OPIPE_HDR_MAGIC) || (hdr.dh_fid == 0))
		return (-1);

	if (hdr.dh_datalen > SMB_OPIPE_DOOR_BUFSIZE)
		hdr.dh_datalen = SMB_OPIPE_DOOR_BUFSIZE;

	data = buf + hdr_size;
	datalen = hdr.dh_datalen;

	switch (hdr.dh_op) {
	case SMB_OPIPE_OPEN:
		hdr.dh_door_rc = ndr_pipe_open(hdr.dh_fid, data, datalen);
		hdr.dh_datalen = 0;
		hdr.dh_resid = 0;
		datalen = hdr_size;
		break;

	case SMB_OPIPE_CLOSE:
		hdr.dh_door_rc = ndr_pipe_close(hdr.dh_fid);
		hdr.dh_datalen = 0;
		hdr.dh_resid = 0;
		datalen = hdr_size;
		break;

	case SMB_OPIPE_READ:
		data = (uint8_t *)buf + hdr_size;
		datalen = hdr.dh_datalen;
		hdr.dh_door_rc = ndr_pipe_read(hdr.dh_fid, data, &datalen,
		    &hdr.dh_resid);
		hdr.dh_datalen = datalen;
		datalen += hdr_size;
		break;

	case SMB_OPIPE_WRITE:
		hdr.dh_door_rc = ndr_pipe_write(hdr.dh_fid, data, datalen);
		hdr.dh_datalen = 0;
		hdr.dh_resid = 0;
		datalen = hdr_size;
		break;

	case SMB_OPIPE_EXEC:
		hdr.dh_door_rc = smbd_opipe_exec(hdr.dh_fid);
		hdr.dh_datalen = 0;
		hdr.dh_resid = 0;
		datalen = hdr_size;
		break;

	default:
		return (-1);
	}

	(void) smb_doorhdr_encode(&hdr, (uint8_t *)buf, hdr_size);
	return (0);
}

/*
 * Normal (from a real kernel) up calls get a thread here.
 * In the "fake" kernel (all user space) we don't need that.
 * NB: arg will be freed by ndr_pipe_transact()
 */
static int
smbd_opipe_exec(uint32_t fid)
{
	uint32_t	*arg;

	if ((arg = malloc(sizeof (uint32_t))) == NULL)
		return (ENOMEM);

	*arg = fid;

	(void) ndr_pipe_transact(arg);

	return (0);
}
