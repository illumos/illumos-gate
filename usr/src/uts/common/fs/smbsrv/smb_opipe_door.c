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
 * This module provides the interface to the opipe door.
 * (used by the NDR RPC services).
 */

#include <sys/stat.h>
#include <sys/door.h>
#include <sys/door_data.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_xdr.h>

#ifdef	_FAKE_KERNEL
#error	"See libfksmbsrv"
#endif	/* _FAKE_KERNEL */

static int smb_opipe_door_upcall(smb_opipe_t *);

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

/*
 * Open the (user space) door.  If the door is already open,
 * close it first because the door-id has probably changed.
 */
int
smb_opipe_door_open(smb_server_t *sv, int door_id)
{
	smb_opipe_door_close(sv);

	mutex_enter(&sv->sv_opipe_door_mutex);
	sv->sv_opipe_door_ncall = 0;

	if (sv->sv_opipe_door_hd == NULL) {
		sv->sv_opipe_door_id = door_id;
		sv->sv_opipe_door_hd = door_ki_lookup(door_id);
	}

	mutex_exit(&sv->sv_opipe_door_mutex);
	return ((sv->sv_opipe_door_hd == NULL)  ? -1 : 0);
}

/*
 * Close the (user space) door.
 */
void
smb_opipe_door_close(smb_server_t *sv)
{
	mutex_enter(&sv->sv_opipe_door_mutex);

	if (sv->sv_opipe_door_hd != NULL) {
		while (sv->sv_opipe_door_ncall > 0)
			cv_wait(&sv->sv_opipe_door_cv,
			    &sv->sv_opipe_door_mutex);

		door_ki_rele(sv->sv_opipe_door_hd);
		sv->sv_opipe_door_hd = NULL;
	}

	mutex_exit(&sv->sv_opipe_door_mutex);
}

/*
 * opipe door call interface.
 * Door serialization and call reference accounting is handled here.
 */
int
smb_opipe_door_call(smb_opipe_t *opipe)
{
	int rc;
	smb_server_t *sv = opipe->p_server;

	mutex_enter(&sv->sv_opipe_door_mutex);

	if (sv->sv_opipe_door_hd == NULL) {
		mutex_exit(&sv->sv_opipe_door_mutex);

		if (smb_opipe_door_open(sv, sv->sv_opipe_door_id) != 0)
			return (-1);

		mutex_enter(&sv->sv_opipe_door_mutex);
	}

	sv->sv_opipe_door_ncall++;
	mutex_exit(&sv->sv_opipe_door_mutex);

	rc = smb_opipe_door_upcall(opipe);

	mutex_enter(&sv->sv_opipe_door_mutex);
	if ((--sv->sv_opipe_door_ncall) == 0)
		cv_signal(&sv->sv_opipe_door_cv);
	mutex_exit(&sv->sv_opipe_door_mutex);
	return (rc);
}

/*
 * Door upcall wrapper - handles data marshalling.
 * This function should only be called by smb_opipe_door_call.
 */
static int
smb_opipe_door_upcall(smb_opipe_t *opipe)
{
	smb_server_t *sv = opipe->p_server;
	door_arg_t da;
	smb_doorhdr_t hdr;
	int i;
	int rc;

	da.data_ptr = (char *)opipe->p_doorbuf;
	da.data_size = SMB_OPIPE_DOOR_BUFSIZE;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)opipe->p_doorbuf;
	da.rsize = SMB_OPIPE_DOOR_BUFSIZE;

	for (i = 0; i < 3; ++i) {
		if (smb_server_is_stopping(sv))
			return (-1);

		if ((rc = door_ki_upcall_limited(sv->sv_opipe_door_hd,
		    &da, NULL, SIZE_MAX, 0)) == 0)
			break;

		if (rc != EAGAIN && rc != EINTR)
			return (-1);
	}

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
