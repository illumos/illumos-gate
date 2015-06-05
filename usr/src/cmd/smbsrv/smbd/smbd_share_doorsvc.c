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

/*
 * LanMan share door server
 */

#include <door.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smbinfo.h>
#include "smbd.h"

#define	SMB_SHARE_DSRV_VERSION	1
#define	SMB_SHARE_DSRV_COOKIE	((void*)(0xdeadbeef^SMB_SHARE_DSRV_VERSION))

static int smb_share_dsrv_fd = -1;
static pthread_mutex_t smb_share_dsrv_mtx = PTHREAD_MUTEX_INITIALIZER;
static smbd_door_t smb_share_sdh;

static void smbd_share_dispatch(void *, char *, size_t, door_desc_t *, uint_t);

/*
 * Start the LanMan share door service.
 * Returns 0 on success. Otherwise, -1.
 */
int
smbd_share_start(void)
{
	int		newfd;
	const char	*door_name;

	(void) pthread_mutex_lock(&smb_share_dsrv_mtx);

	if (smb_share_dsrv_fd != -1) {
		syslog(LOG_ERR, "smbd_share_start: duplicate");
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (smb_share_dsrv_fd);
	}

	smbd_door_init(&smb_share_sdh, "share");

	if ((smb_share_dsrv_fd = door_create(smbd_share_dispatch,
	    SMB_SHARE_DSRV_COOKIE, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		syslog(LOG_ERR, "smbd_share_start: door_create: %s",
		    strerror(errno));
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	door_name = getenv("SMB_SHARE_DNAME");
	if (door_name == NULL)
		door_name = SMB_SHARE_DNAME;

	(void) unlink(door_name);

	if ((newfd = creat(door_name, 0644)) < 0) {
		syslog(LOG_ERR, "smbd_share_start: open: %s",
		    strerror(errno));
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(door_name);

	if (fattach(smb_share_dsrv_fd, door_name) < 0) {
		syslog(LOG_ERR, "smbd_share_start: fattach: %s",
		    strerror(errno));
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
	return (smb_share_dsrv_fd);
}

/*
 * Stop the LanMan share door service.
 */
void
smbd_share_stop(void)
{
	(void) pthread_mutex_lock(&smb_share_dsrv_mtx);

	smbd_door_fini(&smb_share_sdh);

	if (smb_share_dsrv_fd != -1) {
		const char *door_name;

		door_name = getenv("SMB_SHARE_DNAME");
		if (door_name == NULL)
			door_name = SMB_SHARE_DNAME;
		(void) fdetach(door_name);
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
	}

	(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
}

/*
 * This function with which the LMSHARE door is associated
 * will invoke the appropriate CIFS share management function
 * based on the request type of the door call.
 */
/*ARGSUSED*/
static void
smbd_share_dispatch(void *cookie, char *ptr, size_t size, door_desc_t *dp,
    uint_t n_desc)
{
	uint32_t rc;
	int req_type;
	char buf[SMB_SHARE_DSIZE];
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int dec_status;
	unsigned int enc_status;
	char *sharename, *sharename2;
	smb_share_t lmshr_info;
	smb_shrlist_t lmshr_list;
	int offset;

	smbd_door_enter(&smb_share_sdh);

	if ((cookie != SMB_SHARE_DSRV_COOKIE) || (ptr == NULL) ||
	    (size < sizeof (uint32_t))) {
		smbd_door_return(&smb_share_sdh, NULL, 0, NULL, 0);
	}

	dec_ctx = smb_dr_decode_start(ptr, size);
	enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
	req_type = smb_dr_get_uint32(dec_ctx);

	switch (req_type) {
	case SMB_SHROP_NUM_SHARES:
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = smb_shr_count();
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		break;

	case SMB_SHROP_DELETE:
		sharename = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc = smb_shr_remove(sharename);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		break;

	case SMB_SHROP_RENAME:
		sharename = smb_dr_get_string(dec_ctx);
		sharename2 = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			smb_dr_free_string(sharename2);
			goto decode_error;
		}

		rc = smb_shr_rename(sharename, sharename2);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		smb_dr_free_string(sharename2);
		break;

	case SMB_SHROP_ADD:
		smb_dr_get_share(dec_ctx, &lmshr_info);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = smb_shr_add(&lmshr_info);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_share(enc_ctx, &lmshr_info);
		break;

	case SMB_SHROP_MODIFY:
		smb_dr_get_share(dec_ctx, &lmshr_info);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			goto decode_error;
		}

		rc = smb_shr_modify(&lmshr_info);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);

		break;

	case SMB_SHROP_LIST:
		offset = smb_dr_get_int32(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		smb_shr_list(offset, &lmshr_list);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_buf(enc_ctx, (unsigned char *)&lmshr_list,
		    sizeof (smb_shrlist_t));
		break;

	default:
		dec_status = smb_dr_decode_finish(dec_ctx);
		goto decode_error;
	}

	if ((enc_status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DERROR);
		smb_dr_put_uint32(enc_ctx, enc_status);
		(void) smb_dr_encode_finish(enc_ctx, &used);
	}

	smbd_door_return(&smb_share_sdh, buf, used, NULL, 0);
	return;

decode_error:
	smb_dr_put_int32(enc_ctx, SMB_SHARE_DERROR);
	smb_dr_put_uint32(enc_ctx, dec_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);
	smbd_door_return(&smb_share_sdh, buf, used, NULL, 0);
}
