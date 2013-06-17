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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This module provides the interface to NDR RPC.
 */

#include <sys/stat.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_door.h>

/*
 * opipe door client (to user space door server).
 */
void
smb_opipe_door_init(smb_server_t *sv)
{
	sv->sv_opipe_door_id = -1;
	mutex_init(&sv->sv_opipe_door_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_opipe_door_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_opipe_door_fini(smb_server_t *sv)
{
	smb_opipe_door_close(sv);
	cv_destroy(&sv->sv_opipe_door_cv);
	mutex_destroy(&sv->sv_opipe_door_mutex);
}

void
fksmb_opipe_door_open(smb_server_t *sv, void *varg)
{
	/* varg is the "door" dispatch function. */
	sv->sv_opipe_door_hd = varg;
}

/*
 * Close the (user space) door.
 */
void
smb_opipe_door_close(smb_server_t *sv)
{
	sv->sv_opipe_door_hd = NULL;
	sv->sv_opipe_door_id = -1;
}


/*
 * opipe door call interface.
 * Door serialization and call reference accounting is handled here.
 */
int
smb_opipe_door_call(smb_opipe_t *opipe)
{
	smb_server_t *sv = opipe->p_server;
	fksmb_opipe_disp_func_t *func;
	door_arg_t da;
	smb_doorhdr_t hdr;
	int rc;

	if (sv == NULL)
		return (EFAULT);
	if (smb_server_is_stopping(sv))
		return (-1);

	func = (fksmb_opipe_disp_func_t *)(sv->sv_opipe_door_hd);
	if (func == NULL)
		return (EFAULT);

	da.data_ptr = (char *)opipe->p_doorbuf;
	da.data_size = SMB_OPIPE_DOOR_BUFSIZE;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)opipe->p_doorbuf;
	da.rsize = SMB_OPIPE_DOOR_BUFSIZE;


	/*
	 * Do the "upcall" to smbd-d.  In-kernel, this is:
	 * door_ki_upcall_limited(...)
	 */
	rc = (*func)(&da);
	if (rc != 0)
		return (rc);

	/* Check for door_return(NULL, 0, NULL, 0) */
	if (rc != 0 || da.data_size == 0 || da.rsize == 0)
		return (-1);

	if (smb_doorhdr_decode(&hdr, (uint8_t *)da.data_ptr, da.rsize) == -1)
		return (-1);

	if ((hdr.dh_magic != SMB_OPIPE_HDR_MAGIC) ||
	    (hdr.dh_fid != opipe->p_hdr.dh_fid) ||
	    (hdr.dh_op != opipe->p_hdr.dh_op) ||
	    (hdr.dh_door_rc != 0) ||
	    (hdr.dh_datalen > SMB_OPIPE_DOOR_BUFSIZE)) {
		return (-1);
	}

	opipe->p_hdr.dh_datalen = hdr.dh_datalen;
	opipe->p_hdr.dh_resid = hdr.dh_resid;
	return (0);
}
