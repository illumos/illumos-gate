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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/mlsvc_util.h>


static int smbd_opipe_fd = -1;
static int smbd_opipe_cookie = 0x50495045;	/* PIPE */
static pthread_mutex_t smbd_opipe_mutex = PTHREAD_MUTEX_INITIALIZER;

static void smbd_opipe_dispatch(void *, char *, size_t, door_desc_t *, uint_t);

/*
 * Create the smbd opipe door service.
 * Returns the door descriptor on success.  Otherwise returns -1.
 */
int
smbd_opipe_dsrv_start(void)
{
	(void) pthread_mutex_lock(&smbd_opipe_mutex);

	if (smbd_opipe_fd != -1) {
		(void) pthread_mutex_unlock(&smbd_opipe_mutex);
		errno = EEXIST;
		return (-1);
	}

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
smbd_opipe_dsrv_stop(void)
{
	(void) pthread_mutex_lock(&smbd_opipe_mutex);

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
	smb_opipe_hdr_t hdr;
	size_t hdr_size;
	uint8_t *data;
	uint32_t datalen;

	bzero(&hdr, sizeof (smb_opipe_hdr_t));
	hdr_size = xdr_sizeof(smb_opipe_hdr_xdr, &hdr);

	if ((cookie != &smbd_opipe_cookie) || (argp == NULL) ||
	    (arg_size < hdr_size)) {
		(void) door_return(NULL, 0, NULL, 0);
	}

	if (smb_opipe_hdr_decode(&hdr, (uint8_t *)argp, hdr_size) == -1)
		(void) door_return(NULL, 0, NULL, 0);

	if ((hdr.oh_magic != SMB_OPIPE_HDR_MAGIC) || (hdr.oh_fid == 0))
		(void) door_return(NULL, 0, NULL, 0);

	if (hdr.oh_datalen > SMB_OPIPE_DOOR_BUFSIZE)
		hdr.oh_datalen = SMB_OPIPE_DOOR_BUFSIZE;

	data = (uint8_t *)argp + hdr_size;
	datalen = hdr.oh_datalen;

	switch (hdr.oh_op) {
	case SMB_OPIPE_OPEN:
		hdr.oh_status = ndr_s_open(hdr.oh_fid, data, datalen);

		hdr.oh_datalen = 0;
		hdr.oh_resid = 0;
		datalen = hdr_size;
		break;

	case SMB_OPIPE_CLOSE:
		hdr.oh_status = ndr_s_close(hdr.oh_fid);

		hdr.oh_datalen = 0;
		hdr.oh_resid = 0;
		datalen = hdr_size;
		break;

	case SMB_OPIPE_READ:
		data = (uint8_t *)buf + hdr_size;
		datalen = hdr.oh_datalen;

		hdr.oh_status = ndr_s_read(hdr.oh_fid, data, &datalen,
		    &hdr.oh_resid);

		hdr.oh_datalen = datalen;
		datalen += hdr_size;
		break;

	case SMB_OPIPE_WRITE:
		hdr.oh_status = ndr_s_write(hdr.oh_fid, data, datalen);

		hdr.oh_datalen = 0;
		hdr.oh_resid = 0;
		datalen = hdr_size;
		break;

	default:
		(void) door_return(NULL, 0, NULL, 0);
		break;
	}

	(void) smb_opipe_hdr_encode(&hdr, (uint8_t *)buf, hdr_size);
	(void) door_return(buf, datalen, NULL, 0);
}
