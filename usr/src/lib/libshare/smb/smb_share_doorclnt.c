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
#include <smbsrv/lmshare.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/cifs.h>

static int lmshrd_fildes = -1;
static uint64_t lmshrd_door_ncall = 0;
static mutex_t lmshrd_mutex;
static cond_t lmshrd_cv;

char *lmshrd_desc[] = {
	"",
	"LmshrdNumShares",
	"LmshrdDelete",
	"LmshrdRename",
	"LmshrdGetinfo",
	"LmshrdAdd",
	"LmshrdSetinfo",
	"LmshrdExists",
	"LmshrdIsSpecial",
	"LmshrdIsRestricted",
	"LmshrdIsAdmin",
	"LmshrdIsValid",
	"LmshrdIsDir",
	"LmshrdList",
	"LmshrdNumTrans",
	"N/A",
	0
};

/*
 * Open the lmshrd door.  This is a private call for use by
 * lmshrd_door_enter() and must be called with lmshrd_mutex held.
 *
 * Returns the door fd on success.  Otherwise, -1.
 */
static int
lmshrd_door_open(void)
{
	if (lmshrd_fildes == -1) {
		if ((lmshrd_fildes = open(LMSHR_DOOR_NAME, O_RDONLY)) < 0)
			lmshrd_fildes = -1;
		else
			lmshrd_door_ncall = 0;
	}

	return (lmshrd_fildes);
}

/*
 * Close the lmshrd door.
 */
void
lmshrd_door_close(void)
{
	(void) mutex_lock(&lmshrd_mutex);

	if (lmshrd_fildes != -1) {
		while (lmshrd_door_ncall > 0)
			(void) cond_wait(&lmshrd_cv, &lmshrd_mutex);

		if (lmshrd_fildes != -1) {
			(void) close(lmshrd_fildes);
			lmshrd_fildes = -1;
		}
	}

	(void) mutex_unlock(&lmshrd_mutex);
}

/*
 * Entry handler for lmshrd door calls.
 */
static door_arg_t *
lmshrd_door_enter(void)
{
	door_arg_t *arg;
	char *buf;

	(void) mutex_lock(&lmshrd_mutex);

	if (lmshrd_door_open() == -1) {
		(void) mutex_unlock(&lmshrd_mutex);
		return (NULL);
	}

	if ((arg = malloc(sizeof (door_arg_t) + LMSHR_DOOR_SIZE)) != NULL) {
		buf = ((char *)arg) + sizeof (door_arg_t);
		bzero(arg, sizeof (door_arg_t));
		arg->data_ptr = buf;
		arg->rbuf = buf;
		arg->rsize = LMSHR_DOOR_SIZE;

		++lmshrd_door_ncall;
	}

	(void) mutex_unlock(&lmshrd_mutex);
	return (arg);
}

/*
 * Exit handler for lmshrd door calls.
 */
static void
lmshrd_door_exit(door_arg_t *arg, char *errmsg)
{
	if (errmsg)
		syslog(LOG_DEBUG, "lmshrd_door: %s", errmsg);

	(void) mutex_lock(&lmshrd_mutex);
	free(arg);
	--lmshrd_door_ncall;
	(void) cond_signal(&lmshrd_cv);
	(void) mutex_unlock(&lmshrd_mutex);
}

/*
 * Return 0 upon success. Otherwise, -1.
 */
static int
lmshrd_door_check_status(smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);

	if (status != LMSHR_DOOR_SRV_SUCCESS) {
		if (status == LMSHR_DOOR_SRV_ERROR)
			(void) smb_dr_get_uint32(dec_ctx);
		return (-1);
	}

	return (0);
}

DWORD
lmshrd_list(int offset, lmshare_list_t *list)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_LIST);
	smb_dr_put_int32(enc_ctx, offset);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	smb_dr_get_lmshr_list(dec_ctx, list);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (NERR_Success);
}

int
lmshrd_num_shares(void)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD num_shares;
	int rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (-1);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_NUM_SHARES);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (-1);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (-1);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (-1);
	}

	num_shares = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (-1);
	}

	lmshrd_door_exit(arg, NULL);
	return (num_shares);
}

DWORD
lmshrd_delete(char *share_name)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_DELETE);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);

}

DWORD
lmshrd_rename(char *from, char *to)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_RENAME);
	smb_dr_put_string(enc_ctx, from);
	smb_dr_put_string(enc_ctx, to);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);
}

DWORD
lmshrd_getinfo(char *share_name, lmshare_info_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_GETINFO);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshare(dec_ctx, si);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);
}

DWORD
lmshrd_add(lmshare_info_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_ADD);
	smb_dr_put_lmshare(enc_ctx, si);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshare(dec_ctx, si);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);
}

DWORD
lmshrd_setinfo(lmshare_info_t *si)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	DWORD rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_SETINFO);
	smb_dr_put_lmshare(enc_ctx, si);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);
}

static int
lmshrd_check(char *share_name, int opcode)
{
	door_arg_t *arg;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int rc;

	if ((arg = lmshrd_door_enter()) == NULL)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(arg->data_ptr, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_string(enc_ctx, share_name);

	rc = smb_dr_encode_finish(enc_ctx, (unsigned int *)&arg->data_size);
	if (rc != 0) {
		lmshrd_door_exit(arg, "encode error");
		return (NERR_InternalError);
	}

	if (door_call(lmshrd_fildes, arg) < 0) {
		lmshrd_door_exit(arg, "door call error");
		lmshrd_door_close();
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg->data_ptr, arg->data_size);
	if (lmshrd_door_check_status(dec_ctx) != 0) {
		(void) smb_dr_decode_finish(dec_ctx);
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	rc = smb_dr_get_int32(dec_ctx);
	if (smb_dr_decode_finish(dec_ctx) != 0) {
		lmshrd_door_exit(arg, "decode error");
		return (NERR_InternalError);
	}

	lmshrd_door_exit(arg, NULL);
	return (rc);
}

int
lmshrd_exists(char *share_name)
{
	return (lmshrd_check(share_name, LMSHR_DOOR_EXISTS));
}

int
lmshrd_is_special(char *share_name)
{
	return (lmshrd_check(share_name, LMSHR_DOOR_IS_SPECIAL));
}

int
lmshrd_is_restricted(char *share_name)
{
	return (lmshrd_check(share_name, LMSHR_DOOR_IS_RESTRICTED));
}

int
lmshrd_is_admin(char *share_name)
{
	return (lmshrd_check(share_name, LMSHR_DOOR_IS_ADMIN));
}

int
lmshrd_is_valid(char *share_name)
{
	return (lmshrd_check(share_name, LMSHR_DOOR_IS_VALID));
}

int
lmshrd_is_dir(char *path)
{
	return (lmshrd_check(path, LMSHR_DOOR_IS_DIR));
}
