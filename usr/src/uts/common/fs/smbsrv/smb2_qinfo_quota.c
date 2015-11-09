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
 * Dispatch function for SMB2_QUERY_INFO
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

uint32_t
smb2_qinfo_quota(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))
	uint8_t		single, restart;
	uint32_t	sidlistlen, startsidlen, startsidoff;
	smb_node_t	*tnode;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_quota_query_t request;
	smb_quota_response_t reply;
	uint32_t status = NT_STATUS_SUCCESS;
	int rc;

	bzero(&request, sizeof (smb_quota_query_t));
	bzero(&reply, sizeof (smb_quota_response_t));

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA))
		return (NT_STATUS_NOT_SUPPORTED);

	if ((ofile->f_node == NULL) ||
	    (ofile->f_ftype != SMB_FTYPE_DISK))
		return (NT_STATUS_NOT_SUPPORTED);

	rc = smb_mbc_decodef(
	    &sr->smb_data, "bb..lll",
	    &single,		/* b */
	    &restart,		/* b */
	    /* reserved		  .. */
	    &sidlistlen,	/* l */
	    &startsidlen,	/* l */
	    &startsidoff);	/* l */
	if (rc)
		return (NT_STATUS_INVALID_PARAMETER);

	if ((sidlistlen != 0) && (startsidlen != 0))
		return (NT_STATUS_INVALID_PARAMETER);


	tnode = sr->tid_tree->t_snode;
	request.qq_root_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (smb_node_getmntpath(tnode, request.qq_root_path, MAXPATHLEN) != 0) {
		kmem_free(request.qq_root_path, MAXPATHLEN);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (sidlistlen != 0)
		request.qq_query_op = SMB_QUOTA_QUERY_SIDLIST;
	else if (startsidlen != 0)
		request.qq_query_op = SMB_QUOTA_QUERY_STARTSID;
	else
		request.qq_query_op = SMB_QUOTA_QUERY_ALL;

	request.qq_single = single;
	request.qq_restart = restart;
	smb_quota_max_quota(&sr->raw_data, &request);

	status = smb_quota_init_sids(&sr->smb_data, &request, ofile);

	if (status == NT_STATUS_SUCCESS) {
		if (smb_quota_query(sr->sr_server, &request, &reply) != 0) {
			status = NT_STATUS_INTERNAL_ERROR;
		} else {
			status = reply.qr_status;
			if (status == NT_STATUS_SUCCESS) {
				status = smb_quota_encode_quotas(
				    &sr->raw_data,
				    &request, &reply, ofile);
			}
			xdr_free(smb_quota_response_xdr, (char *)&reply);
		}
	}

	kmem_free(request.qq_root_path, MAXPATHLEN);
	smb_quota_free_sids(&request);

	if (status != NT_STATUS_SUCCESS) {
		if (status == NT_STATUS_NO_MORE_ENTRIES) {
			smb_ofile_set_quota_resume(ofile, NULL);
			smbsr_warn(sr, status, 0, 0);
			status = NT_STATUS_SUCCESS;
		} else {
			smbsr_error(sr, status, 0, 0);
		}
	}

	return (status);
}
