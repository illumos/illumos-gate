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
#include <smbsrv/lmerr.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smbinfo.h>

static int smb_kshare_chk_dsrv_status(int, smb_dr_ctx_t *);

/*
 * smb_kshare_init
 *
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
door_handle_t
smb_kshare_init(int door_id)
{
	return (door_ki_lookup(door_id));
}

/*
 * smb_kshare_fini
 *
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
void
smb_kshare_fini(door_handle_t dhdl)
{
	if (dhdl)
		door_ki_rele(dhdl);
}

uint32_t
smb_kshare_getinfo(door_handle_t dhdl, char *share_name, smb_share_t *si)
{
	door_arg_t arg;
	char *buf;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	uint32_t rc;
	int opcode = SMB_SHROP_GETINFO;

	buf = kmem_alloc(SMB_SHARE_DSIZE, KM_SLEEP);

	enc_ctx = smb_dr_encode_start(buf, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_string(enc_ctx, share_name);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "smb_kshare_getinfo: Encode error %d",
		    status);
		kmem_free(buf, SMB_SHARE_DSIZE);
		return (NERR_InternalError);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = SMB_SHARE_DSIZE;

	if (door_ki_upcall_limited(dhdl, &arg, NULL, SIZE_MAX, 0) != 0) {
		cmn_err(CE_WARN, "smb_kshare_getinfo: Door call failed");
		kmem_free(buf, SMB_SHARE_DSIZE);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (smb_kshare_chk_dsrv_status(opcode, dec_ctx) != 0) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	smb_dr_get_share(dec_ctx, si);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "smb_kshare_getinfo: Decode error %d",
		    status);
		rc = NERR_InternalError;
	}

	kmem_free(buf, SMB_SHARE_DSIZE);
	return (rc);
}

uint32_t
smb_kshare_enum(door_handle_t dhdl, smb_enumshare_info_t *enuminfo)
{
	door_arg_t arg;
	char *door_buf;
	int door_bufsz;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	uint32_t rc;
	int opcode = SMB_SHROP_ENUM;

	enuminfo->es_ntotal = enuminfo->es_nsent = 0;

	door_bufsz = enuminfo->es_bufsize + strlen(enuminfo->es_username)
	    + sizeof (smb_enumshare_info_t);
	door_buf = kmem_alloc(door_bufsz, KM_SLEEP);

	enc_ctx = smb_dr_encode_start(door_buf, door_bufsz);
	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_ushort(enc_ctx, enuminfo->es_bufsize);
	smb_dr_put_string(enc_ctx, enuminfo->es_username);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		cmn_err(CE_WARN, "smb_kshare_enum: Encode error %d", status);
		kmem_free(door_buf, door_bufsz);
		return (NERR_InternalError);
	}

	arg.data_ptr = door_buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = door_buf;
	arg.rsize = door_bufsz;

	if (door_ki_upcall_limited(dhdl, &arg, NULL, SIZE_MAX, 0) != 0) {
		cmn_err(CE_WARN, "smb_kshare_enum: Door call failed");
		kmem_free(door_buf, door_bufsz);
		return (NERR_InternalError);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (smb_kshare_chk_dsrv_status(opcode, dec_ctx) != 0) {
		kmem_free(door_buf, door_bufsz);
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (rc == NERR_Success) {
		enuminfo->es_ntotal = smb_dr_get_ushort(dec_ctx);
		enuminfo->es_nsent = smb_dr_get_ushort(dec_ctx);
		enuminfo->es_datasize = smb_dr_get_ushort(dec_ctx);
		(void) smb_dr_get_buf(dec_ctx,
		    (unsigned char *)enuminfo->es_buf,
		    enuminfo->es_bufsize);
	}

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		cmn_err(CE_WARN, "smb_kshare_enum: Decode error %d", status);
		rc = NERR_InternalError;
	}

	kmem_free(door_buf, door_bufsz);
	return (rc);
}

/*
 * This is a special interface that will be utilized by ZFS to cause
 * a share to be added/removed
 *
 * arg is either a smb_share_t or share_name from userspace.
 * It will need to be copied into the kernel.   It is smb_share_t
 * for add operations and share_name for delete operations.
 */
int
smb_kshare_upcall(door_handle_t dhdl, void *arg, boolean_t add_share)
{
	door_arg_t	doorarg = { 0 };
	char		*buf = NULL;
	char		*str = NULL;
	int		error;
	int		rc;
	unsigned int	used;
	smb_dr_ctx_t	*dec_ctx;
	smb_dr_ctx_t	*enc_ctx;
	smb_share_t	*lmshare = NULL;
	int		opcode;

	opcode = (add_share) ? SMB_SHROP_ADD : SMB_SHROP_DELETE;

	buf = kmem_alloc(SMB_SHARE_DSIZE, KM_SLEEP);
	enc_ctx = smb_dr_encode_start(buf, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, opcode);

	switch (opcode) {
	case SMB_SHROP_ADD:
		lmshare = kmem_alloc(sizeof (smb_share_t), KM_SLEEP);
		if (error = xcopyin(arg, lmshare, sizeof (smb_share_t))) {
			kmem_free(lmshare, sizeof (smb_share_t));
			kmem_free(buf, SMB_SHARE_DSIZE);
			return (error);
		}
		smb_dr_put_share(enc_ctx, lmshare);
		break;

	case SMB_SHROP_DELETE:
		str = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (error = copyinstr(arg, str, MAXPATHLEN, NULL)) {
			kmem_free(str, MAXPATHLEN);
			kmem_free(buf, SMB_SHARE_DSIZE);
			return (error);
		}
		smb_dr_put_string(enc_ctx, str);
		kmem_free(str, MAXPATHLEN);
		break;
	}

	if ((error = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (NERR_InternalError);
	}

	doorarg.data_ptr = buf;
	doorarg.data_size = used;
	doorarg.rbuf = buf;
	doorarg.rsize = SMB_SHARE_DSIZE;

	error = door_ki_upcall_limited(dhdl, &doorarg, NULL, SIZE_MAX, 0);

	if (error) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (error);
	}

	dec_ctx = smb_dr_decode_start(doorarg.data_ptr, doorarg.data_size);
	if (smb_kshare_chk_dsrv_status(opcode, dec_ctx) != 0) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (opcode == SMB_SHROP_ADD)
		smb_dr_get_share(dec_ctx, lmshare);

	if (smb_dr_decode_finish(dec_ctx))
		rc = NERR_InternalError;

	kmem_free(buf, SMB_SHARE_DSIZE);
	if (lmshare)
		kmem_free(lmshare, sizeof (smb_share_t));

	return ((rc == NERR_DuplicateShare && add_share) ? 0 : rc);
}

/*
 * Return 0 upon success. Otherwise > 0
 */
static int
smb_kshare_chk_dsrv_status(int opcode, smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);
	int err;

	switch (status) {
	case SMB_SHARE_DSUCCESS:
		return (0);

	case SMB_SHARE_DERROR:
		err = smb_dr_get_uint32(dec_ctx);
		cmn_err(CE_WARN, "%d: Encountered door server error %d",
		    opcode, err);
		(void) smb_dr_decode_finish(dec_ctx);
		return (err);
	}

	ASSERT(0);
	return (EINVAL);
}
