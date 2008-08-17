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

#pragma ident	"@(#)smb_kdoor_ops.c	1.5	08/08/05 SMI"

/*
 * Kernel door operations
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_share.h>

/* SMB kernel module's door operation table */
smb_kdr_op_t smb_kdoorsrv_optab[] =
{
	smb_kdr_op_user_num,
	smb_kdr_op_users,
	smb_kdr_op_share
};

int
smb_kdr_is_valid_opcode(int opcode)
{
	if (opcode < 0 ||
	    opcode > (sizeof (smb_kdoorsrv_optab) / sizeof (smb_kdr_op_t)))
		return (-1);
	else
		return (0);
}

/*ARGSUSED*/
char *
smb_kdr_op_user_num(char *argp, size_t arg_size, size_t *rbufsize, int *errno)
{
	uint32_t num;
	char *rbuf;

	*errno = SMB_DR_OP_SUCCESS;
	num = smb_server_get_user_count();
	rbuf = smb_kdr_encode_common(SMB_DR_OP_SUCCESS, &num, xdr_uint32_t,
	    rbufsize);
	if (!rbuf) {
		*errno = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
		return (NULL);
	}

	return (rbuf);
}

char *
smb_kdr_op_users(char *argp, size_t arg_size, size_t *rbufsize, int *errno)
{
	smb_dr_ulist_t *ulist;
	uint32_t offset;
	char *rbuf = NULL;

	*errno = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;
	if (smb_kdr_decode_common(argp, arg_size, xdr_uint32_t, &offset) != 0) {
		*errno = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	ulist = kmem_zalloc(sizeof (smb_dr_ulist_t), KM_SLEEP);
	(void) smb_server_dr_ulist_get(offset, ulist, SMB_DR_MAX_USERS);

	if ((rbuf = smb_kdr_encode_common(SMB_DR_OP_SUCCESS, ulist,
	    xdr_smb_dr_ulist_t, rbufsize)) == NULL) {
		*errno = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	smb_user_list_free(ulist);
	kmem_free(ulist, sizeof (smb_dr_ulist_t));
	return (rbuf);
}

/*
 * smb_kdr_op_share()
 *
 * This function decodes an smb_dr_kshare_t structure from userland and
 * calls smb_share() to take action depending on whether a share is being
 * enabled or disabled.
 */

char *
smb_kdr_op_share(char *argp, size_t arg_size, size_t *rbufsize, int *errno)
{
	smb_dr_kshare_t *kshare;
	char *rbuf = NULL;
	int error = 0;

	*errno = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	kshare = smb_dr_decode_kshare(argp, arg_size);

	if (kshare == NULL) {
		*errno = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	switch (kshare->k_op) {
	case SMB_SHROP_ADD:
		error = smb_server_share_export(kshare->k_path);
		break;
	case SMB_SHROP_DELETE:
		error = smb_server_share_unexport(kshare->k_path,
		    kshare->k_sharename);
		break;
	default:
		ASSERT(0);
		error = EINVAL;
		break;
	}

	smb_dr_kshare_free(kshare);

	rbuf = smb_kdr_encode_common(SMB_DR_OP_SUCCESS, &error, xdr_int32_t,
	    rbufsize);

	if (!rbuf) {
		*errno = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
		return (NULL);
	}

	return (rbuf);
}
