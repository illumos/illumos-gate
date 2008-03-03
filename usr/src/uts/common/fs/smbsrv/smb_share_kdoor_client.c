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
 * Kernel door client for LanMan share management.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <smbsrv/lmshare.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smbinfo.h>

const char *lmshrd_desc[] = {
	"",
	"LmshrkOpenIter",
	"LmshrkCloseIter",
	"LmshrkIterate",
	"LmshrkNumShares",
	"",
	"",
	"LmshrkGetinfo",
	"",
	"",
	"LmshrkExists",
	"LmshrkIsSpecial",
	"LmshrkIsRestricted",
	"LmshrkIsAdmin",
	"LmshrkIsValid",
	"LmshrkIsDir",
	"LmshrkList",
	"LmshrkListTrans",
	"LmshrkNumTrans",
	"SmbGetKConfig",
	NULL
};

static int lmshrd_door_check_srv_status(int, smb_dr_ctx_t *);

/*
 * lmshrd_kclient_init
 *
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
door_handle_t
lmshrd_kclient_init(int door_id)
{
	return (door_ki_lookup(door_id));
}

/*
 * lmshrd_kclient_fini
 *
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
void
lmshrd_kclient_fini(door_handle_t dhdl)
{
	ASSERT(dhdl != NULL);
	if (dhdl)
		door_ki_rele(dhdl);
}

uint64_t
lmshrd_open_iterator(door_handle_t dhdl, int mode)
{
	door_arg_t	arg;
	char		*buf;
	unsigned int	used;
	smb_dr_ctx_t	*dec_ctx;
	smb_dr_ctx_t	*enc_ctx;
	unsigned int	status = 0;
	uint64_t	lmshr_iter = 0;

	int opcode = LMSHR_DOOR_OPEN_ITERATOR;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (lmshr_iter);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_int32(enc_ctx, mode);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (lmshr_iter);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (lmshr_iter);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (lmshr_iter);
	}

	lmshr_iter = smb_dr_get_lmshr_iterator(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (lmshr_iter);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (lmshr_iter);
}

uint32_t
lmshrd_close_iterator(door_handle_t dhdl, uint64_t iterator)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	int opcode = LMSHR_DOOR_CLOSE_ITERATOR;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshr_iterator(enc_ctx, iterator);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (NERR_Success);
}

uint32_t
lmshrd_iterate(door_handle_t dhdl, uint64_t iterator, lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	int opcode = LMSHR_DOOR_ITERATE;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	bzero(si, sizeof (lmshare_info_t));
	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_lmshr_iterator(enc_ctx, iterator);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	smb_dr_get_lmshare(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (NERR_Success);
}

int
lmshrd_num_shares(door_handle_t dhdl)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int status = 0;
	uint32_t num_shares;
	int opcode = LMSHR_DOOR_NUM_SHARES;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (-1);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (-1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (-1);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (-1);
	}

	num_shares = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (-1);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (num_shares);
}

uint32_t
lmshrd_getinfo(door_handle_t dhdl, char *share_name, lmshare_info_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	uint32_t rc;
	int opcode = LMSHR_DOOR_GETINFO;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_lmshare(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (rc);
}

int
lmshrd_check(door_handle_t dhdl, char *share_name, int opcode)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status, rc;

	buf = MEM_MALLOC("lmshrd_kclient", LMSHR_DOOR_SIZE);
	if (!buf)
		return (NERR_InternalError);

	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "%s: Encode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = LMSHR_DOOR_SIZE;

	if (door_ki_upcall(dhdl, &arg) != 0) {
		cmn_err(CE_WARN, "%s: Door call failed", lmshrd_desc[opcode]);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_int32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "%s: Decode error %d",
		    lmshrd_desc[opcode], status);
		MEM_FREE("lmshrd_kclient", buf);
		return (NERR_InternalError);
	}

	MEM_FREE("lmshrd_kclient", buf);
	return (rc);
}

int
lmshrd_exists(door_handle_t dhdl, char *share_name)
{
	return (lmshrd_check(dhdl, share_name, LMSHR_DOOR_EXISTS));
}

int
lmshrd_is_special(door_handle_t dhdl, char *share_name)
{
	return (lmshrd_check(dhdl, share_name, LMSHR_DOOR_IS_SPECIAL));
}

int
lmshrd_is_restricted(door_handle_t dhdl, char *share_name)
{
	return (lmshrd_check(dhdl, share_name, LMSHR_DOOR_IS_RESTRICTED));
}

int
lmshrd_is_admin(door_handle_t dhdl, char *share_name)
{
	return (lmshrd_check(dhdl, share_name, LMSHR_DOOR_IS_ADMIN));
}

int
lmshrd_is_valid(door_handle_t dhdl, char *share_name)
{
	return (lmshrd_check(dhdl, share_name, LMSHR_DOOR_IS_VALID));
}

int
lmshrd_is_dir(door_handle_t dhdl, char *path)
{
	return (lmshrd_check(dhdl, path, LMSHR_DOOR_IS_DIR));
}

/*
 * This is a special interface that will be utilized by ZFS to cause
 * a share to be added/removed
 *
 * arg is either a lmshare_info_t or share_name from userspace.
 * It will need to be copied into the kernel.   It is lmshare_info_t
 * for add operations and share_name for delete operations.
 */
int
lmshrd_share_upcall(door_handle_t dhdl, void *arg, boolean_t add_share)
{
	door_arg_t	doorarg = { 0 };
	char		*buf = NULL;
	char		*str = NULL;
	int		error;
	int		rc;
	unsigned int	used;
	smb_dr_ctx_t	*dec_ctx;
	smb_dr_ctx_t	*enc_ctx;
	lmshare_info_t	*lmshare = NULL;
	int		opcode;

	opcode = add_share == B_TRUE ? LMSHR_DOOR_ADD : LMSHR_DOOR_DELETE;

	buf = MEM_MALLOC("lmshrd_share_upcall", LMSHR_DOOR_SIZE);
	enc_ctx = smb_dr_encode_start(buf, LMSHR_DOOR_SIZE);
	smb_dr_put_uint32(enc_ctx, opcode);

	switch (opcode) {
	case LMSHR_DOOR_ADD:
		lmshare = MEM_MALLOC("lmshrd_share_upcall",
		    sizeof (lmshare_info_t));

		if (error = xcopyin(arg, lmshare, sizeof (lmshare_info_t))) {
			MEM_FREE("lmshrd_share_upcall", lmshare);
			MEM_FREE("lmshrd_share_upcall", buf);
			return (error);
		}
		smb_dr_put_lmshare(enc_ctx, lmshare);
		break;

	case LMSHR_DOOR_DELETE:
		str = MEM_MALLOC("lmshrd_share_upcall", MAXPATHLEN);
		if (error = copyinstr(arg, str, MAXPATHLEN, NULL)) {
			MEM_FREE("lmshrd_share_upcall", buf);
			MEM_FREE("lmshrd_share_upcall", str);
			return (error);
		}
		smb_dr_put_string(enc_ctx, str);
		MEM_FREE("lmshrd_share_upcall", str);
		break;
	}

	if ((error = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		MEM_FREE("lmshrd_share_upcall", buf);
		if (lmshare)
			MEM_FREE("lmshrd_share_upcall", lmshare);
		return (NERR_InternalError);
	}

	doorarg.data_ptr = buf;
	doorarg.data_size = used;
	doorarg.rbuf = buf;
	doorarg.rsize = LMSHR_DOOR_SIZE;

	error = door_ki_upcall(dhdl, &doorarg);

	if (error) {
		MEM_FREE("lmshrd_share_upcall", buf);
		if (lmshare)
			MEM_FREE("lmshrd_share_upcall", lmshare);
		return (error);
	}

	dec_ctx = smb_dr_decode_start(doorarg.data_ptr, doorarg.data_size);
	if (lmshrd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("lmshrd_share_upcall", buf);
		if (lmshare)
			MEM_FREE("lmshrd_share_upcall", lmshare);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (opcode == LMSHR_DOOR_ADD)
		smb_dr_get_lmshare(dec_ctx, lmshare);

	if (smb_dr_decode_finish(dec_ctx)) {
		MEM_FREE("lmshrd_share_upcall", buf);
		if (lmshare)
			MEM_FREE("lmshrd_share_upcall", lmshare);
		return (NERR_InternalError);
	}

	MEM_FREE("lmshrd_share_upcall", buf);
	if (lmshare)
		MEM_FREE("lmshrd_share_upcall", lmshare);
	return ((rc == NERR_DuplicateShare && add_share) ? 0 : rc);
}

/*
 * Return 0 upon success. Otherwise, -1.
 */
static int
lmshrd_door_check_srv_status(int opcode, smb_dr_ctx_t *dec_ctx)
{
	int	status = smb_dr_get_int32(dec_ctx);
	int	err;
	int	rc = -1;

	switch (status) {
	case LMSHR_DOOR_SRV_SUCCESS:
		rc = 0;
		break;

	case LMSHR_DOOR_SRV_ERROR:
		err = smb_dr_get_uint32(dec_ctx);
		cmn_err(CE_WARN, "%s: Encountered door server error %d",
		    lmshrd_desc[opcode], err);
		break;

	default:
		cmn_err(CE_WARN, "%s: Unknown door server status",
		    lmshrd_desc[opcode]);
	}

	if (rc != 0) {
		if ((err = smb_dr_decode_finish(dec_ctx)) != 0)
			cmn_err(CE_WARN, "%s: Decode error %d",
			    lmshrd_desc[opcode], err);
	}

	return (rc);
}
