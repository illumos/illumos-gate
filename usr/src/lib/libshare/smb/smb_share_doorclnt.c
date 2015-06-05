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
 * User-space door client for LanMan share management.
 */

#include <syslog.h>
#include <door.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb.h>

#define	SMB_SHARE_DOOR_CALL_RETRIES		3

static int smb_share_dfd = -1;
static uint64_t smb_share_dncall = 0;
static mutex_t smb_share_dmtx;
static cond_t smb_share_dcv;

static int smb_share_door_clnt_open(void);
static void smb_share_door_clnt_close(void);

void
smb_share_door_clnt_init(void)
{
	(void) mutex_lock(&smb_share_dmtx);
	(void) smb_share_door_clnt_open();
	(void) mutex_unlock(&smb_share_dmtx);
}

void
smb_share_door_clnt_fini(void)
{
	(void) mutex_lock(&smb_share_dmtx);
	smb_share_door_clnt_close();
	(void) mutex_unlock(&smb_share_dmtx);
}

/*
 * Open smb_share_door.  This is a private call for use by
 * smb_share_door_clnt_enter() and must be called with smb_share_dmtx held.
 *
 * Returns the door fd on success.  Otherwise, -1.
 */
static int
smb_share_door_clnt_open(void)
{
	const char	*door_name;

	if (smb_share_dfd == -1) {
		door_name = getenv("SMB_SHARE_DNAME");
		if (door_name == NULL)
			door_name = SMB_SHARE_DNAME;

		if ((smb_share_dfd = open(door_name, O_RDONLY)) < 0)
			smb_share_dfd = -1;
		else
			smb_share_dncall = 0;
	}

	return (smb_share_dfd);
}

/*
 * Close smb_share_door.
 * Private call that must be called with smb_share_dmtx held.
 */
static void
smb_share_door_clnt_close(void)
{
	if (smb_share_dfd != -1) {
		while (smb_share_dncall > 0)
			(void) cond_wait(&smb_share_dcv, &smb_share_dmtx);

		if (smb_share_dfd != -1) {
			(void) close(smb_share_dfd);
			smb_share_dfd = -1;
		}
	}
}

/*
 * Entry handler for smb_share_door calls.
 */
static door_arg_t *
smb_share_door_clnt_enter(void)
{
	door_arg_t *arg;
	char *buf;

	(void) mutex_lock(&smb_share_dmtx);

	if (smb_share_door_clnt_open() == -1) {
		(void) mutex_unlock(&smb_share_dmtx);
		return (NULL);
	}

	if ((arg = malloc(sizeof (door_arg_t) + SMB_SHARE_DSIZE)) != NULL) {
		buf = ((char *)arg) + sizeof (door_arg_t);
		bzero(arg, sizeof (door_arg_t));
		arg->data_ptr = buf;
		arg->rbuf = buf;
		arg->rsize = SMB_SHARE_DSIZE;

		++smb_share_dncall;
	}

	(void) mutex_unlock(&smb_share_dmtx);
	return (arg);
}

/*
 * Exit handler for smb_share_door calls.
 */
static void
smb_share_door_clnt_exit(door_arg_t *arg, boolean_t must_close, char *errmsg)
{
	if (errmsg)
		syslog(LOG_DEBUG, "smb_share_door: %s failed", errmsg);

	(void) mutex_lock(&smb_share_dmtx);
	free(arg);
	--smb_share_dncall;
	(void) cond_signal(&smb_share_dcv);

	if (must_close)
		smb_share_door_clnt_close();

	(void) mutex_unlock(&smb_share_dmtx);
}

static int
smb_share_door_call(int fd, door_arg_t *arg)
{
	int rc;
	int i;

	for (i = 0; i < SMB_SHARE_DOOR_CALL_RETRIES; ++i) {
		errno = 0;

		if ((rc = door_call(fd, arg)) == 0)
			break;

		if (errno != EAGAIN && errno != EINTR)
			break;
	}

	return (rc);
}

static int
smb_share_dchk(smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);

	if (status != SMB_SHARE_DSUCCESS) {
		if (status == SMB_SHARE_DERROR)
			(void) smb_dr_get_uint32(dec_ctx);
		return (-1);
	}

	return (0);
}

uint32_t
smb_share_list(int offset, smb_shrlist_t *list)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	bzero(list, sizeof (smb_shrlist_t));

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_LIST);
	smb_dr_put_int32(enc_ctx, offset);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (NERR_InternalError);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	(void) smb_dr_get_buf(dec_ctx, (unsigned char *)list,
	    sizeof (smb_shrlist_t));
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (NERR_Success);
}

int
smb_share_count(void)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t num_shares;
	int rc;

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (-1);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_NUM_SHARES);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (-1);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (-1);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (-1);
	}

	num_shares = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (-1);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (num_shares);
}

uint32_t
smb_share_delete(char *share_name)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_DELETE);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (NERR_InternalError);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (rc);

}

uint32_t
smb_share_rename(char *from, char *to)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_RENAME);
	smb_dr_put_string(enc_ctx, from);
	smb_dr_put_string(enc_ctx, to);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (NERR_InternalError);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (rc);
}

uint32_t
smb_share_create(smb_share_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_ADD);
	smb_dr_put_share(enc_ctx, si);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (NERR_InternalError);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_share(dec_ctx, si);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (rc);
}

uint32_t
smb_share_modify(smb_share_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_door_clnt_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_MODIFY);
	smb_dr_put_share(enc_ctx, si);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "encode");
		return (NERR_InternalError);
	}

	if (smb_share_door_call(smb_share_dfd, arg) < 0) {
		smb_share_door_clnt_exit(arg, B_TRUE, "door call");
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_door_clnt_exit(arg, B_FALSE, "decode");
		return (NERR_InternalError);
	}

	smb_share_door_clnt_exit(arg, B_FALSE, NULL);
	return (rc);
}
