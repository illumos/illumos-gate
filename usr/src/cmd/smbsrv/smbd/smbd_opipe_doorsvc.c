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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include "smbd.h"

static int smbd_opipe_fd = -1;
static int smbd_opipe_cookie = 0x50495045;	/* PIPE */
static pthread_mutex_t smbd_opipe_mutex = PTHREAD_MUTEX_INITIALIZER;
static smbd_door_t smbd_opipe_sdh;

static void smbd_opipe_dispatch(void *, char *, size_t, door_desc_t *, uint_t);
static int smbd_opipe_exec_async(uint32_t);

/*
 * Create the smbd opipe door service.
 * Returns the door descriptor on success.  Otherwise returns -1.
 */
int
smbd_opipe_start(void)
{
	(void) pthread_mutex_lock(&smbd_opipe_mutex);

	if (smbd_opipe_fd != -1) {
		(void) pthread_mutex_unlock(&smbd_opipe_mutex);
		errno = EEXIST;
		return (-1);
	}

	smbd_door_init(&smbd_opipe_sdh, "opipe");

	errno = 0;
	if ((smbd_opipe_fd = door_create(smbd_opipe_dispatch,
	    &smbd_opipe_cookie, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		smbd_opipe_fd = -1;
	}

	(void) pthread_mutex_unlock(&smbd_opipe_mutex);
	return (smbd_opipe_fd);
}

/*
 * Stop the smbd opipe door service.
 */
void
smbd_opipe_stop(void)
{
	(void) pthread_mutex_lock(&smbd_opipe_mutex);

	smbd_door_fini(&smbd_opipe_sdh);

	if (smbd_opipe_fd != -1) {
		(void) door_revoke(smbd_opipe_fd);
		smbd_opipe_fd = -1;
	}

	(void) pthread_mutex_unlock(&smbd_opipe_mutex);
}

/*
 * Process smbd opipe requests.
 */
/*ARGSUSED*/
static void
smbd_opipe_dispatch(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dd, uint_t n_desc)
{
	char buf[SMB_OPIPE_DOOR_BUFSIZE];
	smb_doorhdr_t hdr;
	size_t hdr_size;
	uint8_t *data;
	uint32_t datalen;

	smbd_door_enter(&smbd_opipe_sdh);

	if (!smbd_online())
		smbd_door_return(&smbd_opipe_sdh, NULL, 0, NULL, 0);

	bzero(&hdr, sizeof (smb_doorhdr_t));
	hdr_size = xdr_sizeof(smb_doorhdr_xdr, &hdr);

	if ((cookie != &smbd_opipe_cookie) || (argp == NULL) ||
	    (arg_size < hdr_size)) {
		smbd_door_return(&smbd_opipe_sdh, NULL, 0, NULL, 0);
	}

	if (smb_doorhdr_decode(&hdr, (uint8_t *)argp, hdr_size) == -1)
		smbd_door_return(&smbd_opipe_sdh, NULL, 0, NULL, 0);

	if ((hdr.dh_magic != SMB_OPIPE_HDR_MAGIC) || (hdr.dh_fid == 0))
		smbd_door_return(&smbd_opipe_sdh, NULL, 0, NULL, 0);

	if (hdr.dh_datalen > SMB_OPIPE_DOOR_BUFSIZE)
		hdr.dh_datalen = SMB_OPIPE_DOOR_BUFSIZE;

	data = (uint8_t *)argp + hdr_size;
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
		hdr.dh_door_rc = smbd_opipe_exec_async(hdr.dh_fid);

		hdr.dh_datalen = 0;
		hdr.dh_resid = 0;
		datalen = hdr_size;
		break;

	default:
		smbd_door_return(&smbd_opipe_sdh, NULL, 0, NULL, 0);
		break;
	}

	(void) smb_doorhdr_encode(&hdr, (uint8_t *)buf, hdr_size);
	smbd_door_return(&smbd_opipe_sdh, buf, datalen, NULL, 0);
}

/*
 * On success, arg will be freed by the thread.
 */
static int
smbd_opipe_exec_async(uint32_t fid)
{
	pthread_attr_t	attr;
	pthread_t	tid;
	uint32_t	*arg;
	int		rc;

	if ((arg = malloc(sizeof (uint32_t))) == NULL)
		return (ENOMEM);

	*arg = fid;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, ndr_pipe_transact, arg);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		free(arg);
	return (rc);
}
