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

#pragma ident	"@(#)smb_downcalls.c	1.3	08/08/05 SMI"

/*
 * Down calls to SMB Kmod for obtaining various kernel door services.
 */

#include <syslog.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/xdr.h>
#include <sys/errno.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/libsmb.h>

/* indexed via opcode (smb_kdr_opcode_t) */
char *smb_dwncall_info[] = {
	"SmbDwncallNumUser",
	"SmbDwncallUserList",
	"SmbDwncallShare",
	0
};

static smb_dwncall_get_desc_t get_dwncall_desc;

int
smb_dwncall_install_callback(smb_dwncall_get_desc_t get_desc_cb)
{
	if (!get_desc_cb)
		return (-1);

	get_dwncall_desc = get_desc_cb;
	return (0);
}

static int
smb_dwncall_init_fd(uint_t opcode)
{
	int fd;

	if (!get_dwncall_desc) {
		syslog(LOG_DEBUG, "%s: failed (unable to get fd)",
		    smb_dwncall_info[opcode]);
		return (-1);
	}

	if ((fd = get_dwncall_desc()) == -1) {
		syslog(LOG_ERR, "%s: failed (invalid fd)",
		    smb_dwncall_info[opcode]);
		return (-1);
	}

	return (fd);
}

uint64_t
smb_dwncall_user_num()
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int64_t num;
	uint_t opcode = SMB_KDR_USER_NUM;
	int fd;

	if ((fd = smb_dwncall_init_fd(opcode)) < 0)
		return (0);

	buf = smb_dr_set_opcode(opcode, &buflen);
	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smb_dwncall_info[opcode]);
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &num) != 0) {
			num = -1;
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	return (num);
}

/*
 * smb_dwncall_get_users
 *
 * The calling function must free the output parameter 'users'.
 */
int
smb_dwncall_get_users(int offset, smb_dr_ulist_t *users)
{
	char *buf = NULL, *rbufp;
	size_t buflen, rbufsize;
	uint_t opcode = SMB_KDR_USER_LIST;
	int fd, rc = -1;

	bzero(users, sizeof (smb_dr_ulist_t));
	if ((fd = smb_dwncall_init_fd(opcode)) < 0)
		return (-1);

	buf = smb_dr_encode_common(opcode, &offset, xdr_uint32_t, &buflen);
	if (!buf) {
		syslog(LOG_ERR, "smb_dwncall_get_users: encode error");
		return (-1);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smb_dwncall_info[opcode]);


	if (rbufp) {
		rc = smb_dr_decode_common(rbufp  + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_smb_dr_ulist_t, users);
		if (rc)
			syslog(LOG_ERR, "smb_dwncall_get_users: decode error");
		else
			rc = users->dul_cnt;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	return (rc);
}

/*
 * smb_dwncall_share()
 *
 * This is a downcall to the kernel that is executed
 * upon share enable and disable.
 */

int
smb_dwncall_share(int op, char *path, char *sharename)
{
	char *buf = NULL, *rbufp;
	size_t buflen, rbufsize;
	int32_t opcode = SMB_KDR_SHARE;
	smb_dr_kshare_t kshare;
	int fd, rc = 0;

	if ((op != SMB_SHROP_ADD) &&
	    (op != SMB_SHROP_DELETE))
		return (EINVAL);

	if ((fd = smb_dwncall_init_fd(opcode)) < 0) {
		syslog(LOG_ERR, "smb_dwncall_share: init error");
		return (EBADF);
	}

	kshare.k_op = op;
	kshare.k_path = strdup(path);
	kshare.k_sharename = strdup(sharename);

	buf = smb_dr_encode_kshare(&kshare, &buflen);

	if (!buf) {
		syslog(LOG_ERR, "smb_dwncall_share: encode error");
		return (ENOMEM);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smb_dwncall_info[opcode]);

	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_int32_t, &rc) != 0) {
			rc = ENOMEM;
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	return (rc);
}
