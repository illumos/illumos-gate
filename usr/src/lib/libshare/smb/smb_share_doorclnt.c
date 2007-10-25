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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#include <smbsrv/libsmb.h>

#include <smbsrv/lmshare.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/cifs.h>

int lmshrd_fildes = -1;

char *lmshrd_desc[] = {
	"",
	"LmshrdOpenIter",
	"LmshrdCloseIter",
	"LmshrdIterate",
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
	"LmshrdListTrans",
	"LmshrdNumTrans",
	"N/A",
	0
};

/*
 * Returns 0 on success. Otherwise, -1.
 */
static int
lmshrd_door_open(int opcode)
{
	int rc = 0;

	if (lmshrd_fildes == -1 &&
	    (lmshrd_fildes = open(LMSHR_DOOR_NAME, O_RDONLY)) < 0) {
		syslog(LOG_DEBUG, "%s: open %s failed %s", lmshrd_desc[opcode],
		    LMSHR_DOOR_NAME, strerror(errno));
		rc = -1;
	}
	return (rc);
}

/*
 * Return 0 upon success. Otherwise, -1.
 */
static int
lmshrd_door_check_srv_status(int opcode, smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);
	int err;
	int rc = -1;

	switch (status) {
	case LMSHR_DOOR_SRV_SUCCESS:
		rc = 0;
		break;

	case LMSHR_DOOR_SRV_ERROR:
		err = smb_dr_get_uint32(dec_ctx);
		syslog(LOG_ERR, "%s: Encountered door server error %s",
		    lmshrd_desc[opcode], strerror(err));
		break;

	default:
		syslog(LOG_ERR, "%s: Unknown door server status",
		    lmshrd_desc[opcode]);
	}

	if (rc != 0) {
		if ((err = smb_dr_decode_finish(dec_ctx)) != 0)
			syslog(LOG_ERR, "%s: Decode error %s",
			    lmshrd_desc[opcode], strerror(err));
	}

	return (rc);
}

uint64_t
lmshrd_open_iterator(int mode)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	uint64_t lmshr_iter = 0;
	int opcode = LMSHR_DOOR_OPEN_ITERATOR;

	if (lmshrd_door_open(opcode) == -1)
		return (lmshr_iter);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (lmshr_iter);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_int32(enc_ctx, mode);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (lmshr_iter);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (lmshr_iter);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (lmshr_iter);
	}

	lmshr_iter = smb_dr_get_lmshr_iterator(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (lmshr_iter);
	}

	(void) free(buf);
	return (lmshr_iter);
}


DWORD
lmshrd_close_iterator(uint64_t iterator)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	int opcode = LMSHR_DOOR_CLOSE_ITERATOR;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshr_iterator(enc_ctx, iterator);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (NERR_Success);
}

DWORD
lmshrd_iterate(uint64_t iterator, lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	int opcode = LMSHR_DOOR_ITERATE;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	bzero(si, sizeof (lmshare_info_t));
	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshr_iterator(enc_ctx, iterator);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	smb_dr_get_lmshare(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (NERR_Success);
}

DWORD
lmshrd_list(int offset, lmshare_list_t *list)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_LIST;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);

	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_int32(enc_ctx, offset);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshr_list(dec_ctx, list);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);

	return (rc);
}

int
lmshrd_num_shares(void)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	DWORD num_shares;
	int opcode = LMSHR_DOOR_NUM_SHARES;

	if (lmshrd_door_open(opcode) == -1)
		return (-1);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (-1);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_NUM_SHARES);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (-1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (-1);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (-1);
	}

	num_shares = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (-1);
	}

	(void) free(buf);
	return (num_shares);
}

DWORD
lmshrd_delete(char *share_name)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_DELETE;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_DELETE);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (rc);

}

DWORD
lmshrd_rename(char *from, char *to)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_RENAME;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_RENAME);
	smb_dr_put_string(enc_ctx, from);
	smb_dr_put_string(enc_ctx, to);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (rc);
}

DWORD
lmshrd_getinfo(char *share_name, lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_GETINFO;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, LMSHR_DOOR_GETINFO);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshare(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (rc);
}

DWORD
lmshrd_add(lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_ADD;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshare(enc_ctx, si);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshare(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (rc);
}

DWORD
lmshrd_setinfo(lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = LMSHR_DOOR_SETINFO;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshare(enc_ctx, si);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
	return (rc);
}

static int
lmshrd_check(char *share_name, int opcode)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status, rc;

	if (lmshrd_door_open(opcode) == -1)
		return (NERR_InternalError);

	buf = malloc(LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_call(lmshrd_fildes, &arg) < 0) {
		syslog(LOG_DEBUG, "%s: Door call failed %s",
		    lmshrd_desc[opcode], strerror(errno));
		(void) free(buf);
		lmshrd_fildes = -1;
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		(void) free(buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_int32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    lmshrd_desc[opcode], strerror(status));
		(void) free(buf);
		return (NERR_InternalError);
	}

	(void) free(buf);
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

static char *
lmshare_decode_type(unsigned int stype)
{
	switch (stype) {
	case STYPE_DISKTREE:
		return ("Disk");
	case STYPE_PRINTQ:
		return ("Print Queue");
	case STYPE_DEVICE:
		return ("Device");
	case STYPE_IPC:
		return ("IPC");
	case STYPE_DFS:
		return ("DFS");
	case STYPE_SPECIAL:
		return ("Special");
	default:
		return ("Unknown");
	};
}


static void
lmshare_loginfo(FILE *fp, lmshare_info_t *si)
{
	if (!si) {
		return;
	}

	(void) fprintf(fp, "\n%s Information:\n", si->share_name);
	(void) fprintf(fp, "\tFolder: %s\n", si->directory);
	(void) fprintf(fp, "\tType: %s\n", lmshare_decode_type(si->stype));
	(void) fprintf(fp, "\tComment: %s\n", si->comment);

	(void) fprintf(fp, "\tStatus: %s\n",
	    ((si->mode & LMSHRM_TRANS) ? "Transient" : "Permanent"));

	(void) fprintf(fp, "\tContainer: %s\n", si->container);
}

int
lmshrd_dump_hash(char *logfname)
{
	lmshare_info_t si;
	uint64_t it;
	FILE *fp;

	if ((logfname == 0) || (*logfname == 0))
		fp = stdout;
	else {
		fp = fopen(logfname, "w");
		if (fp == 0) {
			syslog(LOG_WARNING, "LmshareDump [%s]:"
			    " cannot create logfile", logfname);
			syslog(LOG_WARNING, "LmshareDump:"
			    " output will be written on screen");
		}
	}

	it = lmshrd_open_iterator(LMSHRM_PERM);
	if (it == NULL) {
		syslog(LOG_ERR, "LmshareDump: resource shortage");
		if (fp && fp != stdout) {
			(void) fclose(fp);
		}
		return (1);
	}

	if (lmshrd_iterate(it, &si) != NERR_Success) {
		syslog(LOG_ERR, "LmshareDump: Iterator iterate failed");
		if (fp && fp != stdout) {
			(void) fclose(fp);
		}
		return (1);
	}
	while (*si.share_name != 0) {
		lmshare_loginfo(fp, &si);
		if (lmshrd_iterate(it, &si) != NERR_Success) {
			syslog(LOG_ERR, "LmshareDump: Iterator iterate failed");
			if (fp && fp != stdout) {
				(void) fclose(fp);
			}
			return (1);
		}
	}

	if (lmshrd_close_iterator(it) != NERR_Success) {
		syslog(LOG_ERR, "LmshareDump: Iterator close failed");
		if (fp && fp != stdout) {
			(void) fclose(fp);
		}
		return (1);
	}
	if (fp && fp != stdout) {
		(void) fclose(fp);
	}
	return (0);
}
