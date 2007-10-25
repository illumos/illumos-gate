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
 * Door calls invoked by CLIs to obtain various SMB door service provided
 * by SMB daemon.
 */

#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

/* indexed via opcode (smb_dr_opcode_t) */
char *smbapi_desc[] = {
	"",
	"",
	"",
	"",
	"SmbapiUserList",
	"SmbGroupAdd",
	"SmbGroupDelete",
	"SmbGroupAddMember",
	"SmbGroupRemoveMember",
	"SmbGroupGetCount",
	"SmbGroupGetCacheSize",
	"SmbGroupModify",
	"SmbGroupPresentablePrivNum",
	"SmbGroupPresentablePriv",
	"SmbGroupGetPriv",
	"SmbGroupSetPriv",
	"SmbGroupListGroups",
	"SmbGroupListMembers",
	"SmbGroupMembersCount",
	0
};

/*
 * This function will return information on the connected users
 * starting at the given offset.
 *
 * At most 50 users (i.e. SMB_DR_MAX_USER) will be returned via this
 * function. Multiple calls might be needed to obtain all connected
 * users.
 *
 * smb_dr_ulist_free must be called to free memory allocated for the
 * account and workstation fields of each user in the returned list.
 */
int
smb_api_ulist(int offset, smb_dr_ulist_t *users)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	int rc = -1;
	uint_t opcode = SMB_DR_USER_LIST;
	int fd;

	bzero(users, sizeof (smb_dr_ulist_t));
	buf = smb_dr_encode_common(opcode, &offset, xdr_uint32_t, &buflen);
	if (!buf)
		return (-1);

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (-1);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);
	if (rbufp) {
		rc = smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_smb_dr_ulist_t, users);

	}
	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

/* Routines for SMB Group Door Client APIs */
uint32_t
smb_group_add(char *gname, char *desc)
{
	ntgrp_dr_arg_t *args;
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_ADD;
	int fd;

	if ((gname == 0) || (*gname == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->desc = desc;
	if ((buf = smb_dr_encode_common(opcode, args,
	    xdr_ntgrp_dr_arg_t, &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_delete(char *gname)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_DELETE;
	int fd;

	if ((gname == 0) || (*gname == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((buf = smb_dr_encode_string(opcode, gname, &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_member_add(char *gname, char *member)
{
	ntgrp_dr_arg_t *args;
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_MEMBER_ADD;
	int fd;

	if ((gname == 0) || (*gname == 0) ||
	    (member == 0) || (*member == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->member = member;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_member_remove(char *gname, char *member)
{
	ntgrp_dr_arg_t *args;
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_MEMBER_REMOVE;
	int fd;

	if ((gname == 0) || (*gname == 0) ||
	    (member == 0) || (*member == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->member = member;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}


uint32_t
smb_group_count(int *cnt)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	uint_t opcode = SMB_DR_GROUP_COUNT;
	int fd;

	if (cnt == 0) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}
	*cnt = 0;
	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME,
	    smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_set_opcode(opcode, &buflen)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, cnt) != 0) {
			(void) close(fd);
			return (NT_STATUS_INVALID_PARAMETER);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_cachesize(int *sz)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	uint_t opcode = SMB_DR_GROUP_CACHE_SIZE;
	int fd;

	if (sz == 0) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}
	*sz = 0;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME,
	    smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_set_opcode(opcode, &buflen)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, sz) != 0) {
			(void) close(fd);
			return (NT_STATUS_INVALID_PARAMETER);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_modify(char *gname, char *newgname, char *desc)
{
	ntgrp_dr_arg_t *args;
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_MODIFY;
	int fd;

	if ((gname == 0) || (*gname == 0) ||
	    (newgname == 0) || (*newgname == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->desc = desc;
	args->newgname = newgname;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_priv_num(int *num)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_PRIV_NUM;
	int fd;

	if (num == 0) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}
	*num = 0;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME,
	    smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_set_opcode(opcode, &buflen)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, num) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_priv_list(ntpriv_list_t **list)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_PRIV_LIST;
	int fd;
	*list = NULL;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME,
	    smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	if ((buf = smb_dr_set_opcode(opcode, &buflen)) == 0) {
		(void) close(fd);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result */
	if (rbufp) {
		if ((*list = smb_dr_decode_grp_privlist(
		    rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET)) == 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_priv_get(char *gname, uint32_t privid, uint32_t *privval)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	ntgrp_dr_arg_t *args;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_PRIV_GET;
	int fd;
	uint32_t retval;

	*privval = SE_PRIVILEGE_DISABLED;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->privid = privid;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t,
		    &retval) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
		*privval = retval;
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_priv_set(char *gname, uint32_t privid, uint32_t priv_attr)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	ntgrp_dr_arg_t *args;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_PRIV_SET;
	int fd;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->privid = privid;
	args->priv_attr = priv_attr;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_uint32_t, &rc) != 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_list(int offset, ntgrp_list_t **list, char *scope, int type)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	ntgrp_dr_arg_t *args;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_LIST;
	int fd;
	*list = NULL;

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->offset = offset;
	args->type = type;
	args->scope = scope;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if ((*list = smb_dr_decode_grp_list(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET)) == 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_member_list(char *gname, int offset, ntgrp_member_list_t **members)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	ntgrp_dr_arg_t *args;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_MEMBER_LIST;
	int fd;
	*members = NULL;

	if ((gname == 0) || (*gname == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory for ret_mem_list",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	args->gname = gname;
	args->offset = offset;
	if ((buf = smb_dr_encode_common(opcode, args, xdr_ntgrp_dr_arg_t,
	    &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		free(args);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}
	free(args);

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if (rbufp) {
		if ((*members = smb_dr_decode_grp_memberlist(
		    rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET)) == 0) {
			(void) close(fd);
			return (NT_STATUS_INTERNAL_ERROR);
		}
		rc = NT_STATUS_SUCCESS;
	}

	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	(void) close(fd);
	return (rc);
}

uint32_t
smb_group_member_count(char *gname, int *cnt)
{
	char *buf, *rbufp;
	size_t buflen, rbufsize;
	ntgrp_dr_arg_t *dec_args;
	uint32_t rc = NT_STATUS_UNSUCCESSFUL;
	int opcode = SMB_DR_GROUP_MEMBER_COUNT;
	int fd;

	if ((gname == 0) || (*gname == 0) || (cnt == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)",
		    smbapi_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smb_dr_clnt_open(&fd, SMB_DR_SVC_NAME, smbapi_desc[opcode]) == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/* Encode */
	if ((buf = smb_dr_encode_string(opcode, gname, &buflen)) == 0) {
		syslog(LOG_ERR, "%s: Encode error", smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rbufp = smb_dr_clnt_call(fd, buf, buflen, &rbufsize,
	    smbapi_desc[opcode]);

	/* Decode Result. */
	if ((dec_args = (ntgrp_dr_arg_t *)
	    malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR, "%s: cannot allocate memory",
		    smbapi_desc[opcode]);
		(void) close(fd);
		return (NT_STATUS_NO_MEMORY);
	}
	bzero(dec_args, sizeof (ntgrp_dr_arg_t));
	if (rbufp) {
		if (smb_dr_decode_common(rbufp + SMB_DR_DATA_OFFSET,
		    rbufsize - SMB_DR_DATA_OFFSET, xdr_ntgrp_dr_arg_t, dec_args)
		    != 0) {
			free(dec_args);
			(void) close(fd);
			return (dec_args->ntstatus);
		}
	}
	*cnt = dec_args->count;
	rc = dec_args->ntstatus;
	smb_dr_clnt_free(buf, buflen, rbufp, rbufsize);
	free(dec_args);
	(void) close(fd);
	return (rc);
}

/* Helper functions for local group door service to free up data structures */
void
smb_group_free_privlist(ntpriv_list_t *list, int deletelist)
{
	int i;
	if (!list)
		return;
	if (list->privs != NULL) {
		for (i = 0; i < list->cnt; i++) {
			if (list->privs[i] != NULL) {
				free(list->privs[i]->name);
				free(list->privs[i]);
			}
		}
		if (deletelist)
			free(list);
	}
}

void
smb_group_free_list(ntgrp_list_t *list, int entries_only)
{
	int i;

	if (!list) {
		return;
	}

	for (i = 0; i < list->cnt; i++) {
		free(list->groups[i].name);
		free(list->groups[i].desc);
		free(list->groups[i].type);
		free(list->groups[i].sid);
	}
	if (!entries_only)
		free(list);
}

void
smb_group_free_memberlist(ntgrp_member_list_t *members,
    int entries_only)
{
	int i;

	if (!members) {
		return;
	}

	for (i = 0; i < members->cnt; i++) {
		free(members->members[i]);
	}
	if (!entries_only)
		free(members);
}
