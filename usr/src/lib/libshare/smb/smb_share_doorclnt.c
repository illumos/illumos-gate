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

#pragma ident	"@(#)smb_share_doorclnt.c	1.5	08/08/05 SMI"

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
#include <smbsrv/lmerr.h>
#include <smbsrv/cifs.h>

static int smb_share_dfd = -1;
static uint64_t smb_share_dncall = 0;
static mutex_t smb_share_dmtx;
static cond_t smb_share_dcv;

/*
 * Open the lmshrd door.  This is a private call for use by
 * smb_share_denter() and must be called with smb_share_dmtx held.
 *
 * Returns the door fd on success.  Otherwise, -1.
 */
static int
smb_share_dopen(void)
{
	if (smb_share_dfd == -1) {
		if ((smb_share_dfd = open(SMB_SHARE_DNAME, O_RDONLY)) < 0)
			smb_share_dfd = -1;
		else
			smb_share_dncall = 0;
	}

	return (smb_share_dfd);
}

/*
 * Close the lmshrd door.
 */
void
smb_share_dclose(void)
{
	(void) mutex_lock(&smb_share_dmtx);

	if (smb_share_dfd != -1) {
		while (smb_share_dncall > 0)
			(void) cond_wait(&smb_share_dcv, &smb_share_dmtx);

		if (smb_share_dfd != -1) {
			(void) close(smb_share_dfd);
			smb_share_dfd = -1;
		}
	}

	(void) mutex_unlock(&smb_share_dmtx);
}

/*
 * Entry handler for lmshrd door calls.
 */
static door_arg_t *
smb_share_denter(void)
{
	door_arg_t *arg;
	char *buf;

	(void) mutex_lock(&smb_share_dmtx);

	if (smb_share_dopen() == -1) {
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
 * Exit handler for lmshrd door calls.
 */
static void
smb_share_dexit(door_arg_t *arg, char *errmsg)
{
	if (errmsg)
		syslog(LOG_DEBUG, "lmshrd_door: %s", errmsg);

	(void) mutex_lock(&smb_share_dmtx);
	free(arg);
	--smb_share_dncall;
	(void) cond_signal(&smb_share_dcv);
	(void) mutex_unlock(&smb_share_dmtx);
}

/*
 * Return 0 upon success. Otherwise, -1.
 */
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

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_LIST);
	smb_dr_put_int32(enc_ctx, offset);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	(void) smb_dr_get_buf(dec_ctx, (unsigned char *)list,
	    sizeof (smb_shrlist_t));
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
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

	if ((arg = smb_share_denter()) == NULL)
		return (-1);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_NUM_SHARES);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (-1);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (-1);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (-1);
	}

	num_shares = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (-1);
	}

	smb_share_dexit(arg, NULL);
	return (num_shares);
}

uint32_t
smb_share_delete(char *share_name)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_DELETE);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
	return (rc);

}

uint32_t
smb_share_rename(char *from, char *to)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_RENAME);
	smb_dr_put_string(enc_ctx, from);
	smb_dr_put_string(enc_ctx, to);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
	return (rc);
}

uint32_t
smb_share_get(char *share_name, smb_share_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_GETINFO);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_share(dec_ctx, si);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
	return (rc);
}

uint32_t
smb_share_create(smb_share_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_ADD);
	smb_dr_put_share(enc_ctx, si);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_share(dec_ctx, si);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
	return (rc);
}

uint32_t
smb_share_modify(char *sharename, char *cmnt, char *ad_container)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	uint32_t rc;

	if ((arg = smb_share_denter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, SMB_SHROP_MODIFY);
	smb_dr_put_string(enc_ctx, sharename);
	smb_dr_put_string(enc_ctx, cmnt);
	smb_dr_put_string(enc_ctx, ad_container);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		smb_share_dexit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(smb_share_dfd, arg) < 0) {
		smb_share_dexit(arg, "door call error");
		smb_share_dclose();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (smb_share_dchk(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		smb_share_dexit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_share_dexit(arg, NULL);
	return (rc);
}
