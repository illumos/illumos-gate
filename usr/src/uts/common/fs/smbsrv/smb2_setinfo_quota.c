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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_SET_INFO
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

/*
 * Similar to smb_nt_transact_set_quota()
 */
uint32_t
smb2_setinfo_quota(smb_request_t *sr, smb_setinfo_t *si)
{
	char		*root_path;
	uint32_t	status = NT_STATUS_SUCCESS;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_node_t	*tnode;
	smb_quota_set_t request;
	uint32_t	reply;
	list_t 		*quota_list;

	bzero(&request, sizeof (smb_quota_set_t));

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA))
		return (NT_STATUS_NOT_SUPPORTED);

	if (!smb_user_is_admin(sr->uid_user))
		return (NT_STATUS_ACCESS_DENIED);

	if ((ofile->f_node == NULL) ||
	    (ofile->f_ftype != SMB_FTYPE_DISK))
		return (NT_STATUS_ACCESS_DENIED);

	tnode = sr->tid_tree->t_snode;
	root_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (smb_node_getmntpath(tnode, root_path, MAXPATHLEN) != 0) {
		smbsr_release_file(sr);
		kmem_free(root_path, MAXPATHLEN);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	quota_list = &request.qs_quota_list;
	list_create(quota_list, sizeof (smb_quota_t),
	    offsetof(smb_quota_t, q_list_node));

	status = smb_quota_decode_quotas(&si->si_data, quota_list);
	if (status == NT_STATUS_SUCCESS) {
		request.qs_root_path = root_path;
		if (smb_quota_set(sr->sr_server, &request, &reply) != 0) {
			status = NT_STATUS_INTERNAL_ERROR;
		} else {
			status = reply;
			xdr_free(xdr_uint32_t, (char *)&reply);
		}
	}

	kmem_free(root_path, MAXPATHLEN);
	smb_quota_free_quotas(&request.qs_quota_list);
	smbsr_release_file(sr);

	return (status);
}
