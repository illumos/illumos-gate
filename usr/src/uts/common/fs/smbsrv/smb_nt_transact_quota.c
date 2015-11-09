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

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * smb_nt_transact_query_quota
 *
 * This method allows the client to retrieve quota information from
 * the server. The result of the call is returned to the client in the
 * Data part of the transaction response.
 *
 * On entry, the 'TotalParameterCount' field must be equal to 16, and the
 * client parameter block must be encoded with the following parameters:
 *
 * Request                    Description
 * ========================== ==================================
 * WORD fid                   SMB file identifier of the target directory
 * BYTE ReturnSingleEntry     A boolean indicating whether to return
 *                            a single entry (TRUE) or multiple entries (FALSE).
 * BYTE RestartScan           A boolean indicating whether to continue from
 *                            the previous request (FALSE) or restart a new
 *                            sequence (TRUE).
 * DWORD SidListLength        The length, in bytes, of the SidList in the
 *                            data block or 0 if there is no SidList.
 * DWORD StartSidLength       If SidListLength is 0 (i.e. there is no SidList
 *                            in the data block), then this is either:
 *                                 1) the (non-zero) length in bytes of the
 *                                    StartSid in the parameter buffer, or
 *                                 2) if 0, there is no StartSid in the
 *                                    parameter buffer, in which case, all SIDs
 *                                    are to be enumerated as if they were
 *                                    passed in the SidList.
 *                            Otherwise, StartSidLength is ignored.
 * DWORD StartSidOffset       The offset, in bytes, to the StartSid in the
 *                            parameter block (if one exists).
 *
 * One of SidListLength and StartSidLength must be 0.
 *
 * An SMB_COM_NT_TRANSACTION response is sent in reply when the request
 * is successful.  The 'TotalParameterCount' is set to 4, and the parameter
 * block in the server response contains a 32-bit unsigned integer
 * indicating the length, in bytes, of the returned quota information.
 * The 'TotalDataCount' is set to indicate the length of the data buffer,
 * and the data buffer contains the following quota information:
 *
 *  Data Block Encoding                Description
 *  ================================== =================================
 *  ULONG NextEntryOffset;             Offset to start of next entry from
 *                                     start of this entry, or 0 for the
 *                                     final entry
 *  ULONG SidLength;                   Length (bytes) of SID
 *  SMB_TIME ChangeTime;               Time that the quota was last changed
 *  LARGE_INTEGER QuotaUsed;           Amount of quota (bytes) used by user
 *  LARGE_INTEGER QuotaThreshold;      Quota warning limit (bytes) for user
 *  LARGE_INTEGER QuotaLimit;          The quota limit (bytes) for this user
 *  USHORT Sid;                        Search handle
 */
smb_sdrc_t
smb_nt_transact_query_quota(smb_request_t *sr, smb_xa_t *xa)
{
	uint8_t		single, restart;
	uint32_t	sidlistlen, startsidlen, startsidoff;
	smb_node_t	*tnode;
	smb_ofile_t	*ofile;
	smb_quota_query_t request;
	smb_quota_response_t reply;
	uint32_t status = NT_STATUS_SUCCESS;

	bzero(&request, sizeof (smb_quota_query_t));
	bzero(&reply, sizeof (smb_quota_response_t));

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA)) {
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED, 0, 0);
		return (SDRC_ERROR);
	}

	if (xa->smb_tpscnt != 16) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%wbblll", sr, &sr->smb_fid,
	    &single, &restart, &sidlistlen, &startsidlen, &startsidoff)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	if ((sidlistlen != 0) && (startsidlen != 0)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	smbsr_lookup_file(sr);
	ofile = sr->fid_ofile;
	if (ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	if ((ofile->f_node == NULL) || (ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		smbsr_release_file(sr);
		return (SDRC_ERROR);
	}

	tnode = sr->tid_tree->t_snode;
	request.qq_root_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (smb_node_getmntpath(tnode, request.qq_root_path, MAXPATHLEN) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, ERRDOS,
		    ERROR_INVALID_PARAMETER);
		smbsr_release_file(sr);
		kmem_free(request.qq_root_path, MAXPATHLEN);
		return (SDRC_ERROR);
	}

	if (sidlistlen != 0)
		request.qq_query_op = SMB_QUOTA_QUERY_SIDLIST;
	else if (startsidlen != 0)
		request.qq_query_op = SMB_QUOTA_QUERY_STARTSID;
	else
		request.qq_query_op = SMB_QUOTA_QUERY_ALL;

	request.qq_single = single;
	request.qq_restart = restart;
	smb_quota_max_quota(&xa->rep_data_mb, &request);

	status = smb_quota_init_sids(&xa->req_data_mb, &request, ofile);

	if (status == NT_STATUS_SUCCESS) {
		if (smb_quota_query(sr->sr_server, &request, &reply) != 0) {
			status = NT_STATUS_INTERNAL_ERROR;
		} else {
			status = reply.qr_status;
			if (status == NT_STATUS_SUCCESS) {
				status = smb_quota_encode_quotas(
				    &xa->rep_data_mb,
				    &request, &reply, ofile);
			}
			(void) smb_mbc_encodef(&xa->rep_param_mb, "l",
			    xa->rep_data_mb.chain_offset);
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
		(void) smb_mbc_encodef(&xa->rep_param_mb, "l", 0);
	}

	smbsr_release_file(sr);
	return ((status == NT_STATUS_SUCCESS) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_nt_transact_set_quota
 *
 * This method allows the client to set quota information on the server.
 * The result status of the call is returned to the client in the
 * 'status' field of the SMB response header.
 *
 * On entry, the 'TotalParameterCount' field must be equal to 2, and the
 * client parameter block must be encoded with the following parameters:
 *
 *  Data Block Encoding                Description
 *  ================================== =================================
 *  ULONG NextEntryOffset;             Offset to start of next entry from
 *                                     start of this entry, or 0 for the
 *                                     final entry
 *  ULONG SidLength;                   Length (bytes) of SID
 *  SMB_TIME ChangeTime;               Time that the quota was last changed
 *  LARGE_INTEGER QuotaUsed;           Amount of quota (bytes) used by user
 *  LARGE_INTEGER QuotaThreshold;      Quota warning limit (bytes) for user
 *  LARGE_INTEGER QuotaLimit;          The quota limit (bytes) for this user
 *  VARIABLE Sid;                      Security identifier of the user
 *
 * An SMB_COM_NT_TRANSACTION response is sent in reply when the request
 * is successful.  The 'TotalParameterCount' and the 'TotalDataCount' are set
 * to 0, and the parameter block 'Status' field in the server SMB response
 * header contains a 32-bit unsigned integer indicating the result status
 * (NT_STATUS_SUCCESS if successful).
 *
 * Only users with Admin privileges (i.e. of the BUILTIN/Administrators
 * group) will be allowed to set quotas.
 */
smb_sdrc_t
smb_nt_transact_set_quota(smb_request_t *sr, smb_xa_t *xa)
{
	char		*root_path;
	uint32_t	status = NT_STATUS_SUCCESS;
	smb_node_t	*tnode;
	smb_ofile_t	*ofile;
	smb_quota_set_t request;
	uint32_t	reply;
	list_t 		*quota_list;

	bzero(&request, sizeof (smb_quota_set_t));

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA)) {
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED, 0, 0);
		return (SDRC_ERROR);
	}

	if (!smb_user_is_admin(sr->uid_user)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
		return (-1);
	}

	if (xa->smb_tpscnt != 2) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%w", sr,
	    &sr->smb_fid)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	smbsr_lookup_file(sr);
	ofile = sr->fid_ofile;
	if (ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	if ((ofile->f_node == NULL) || (ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		smbsr_release_file(sr);
		return (SDRC_ERROR);
	}

	tnode = sr->tid_tree->t_snode;
	root_path  = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (smb_node_getmntpath(tnode, root_path, MAXPATHLEN) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, ERRDOS,
		    ERROR_INVALID_PARAMETER);
		smbsr_release_file(sr);
		kmem_free(root_path, MAXPATHLEN);
		return (SDRC_ERROR);
	}

	quota_list = &request.qs_quota_list;
	list_create(quota_list, sizeof (smb_quota_t),
	    offsetof(smb_quota_t, q_list_node));

	status = smb_quota_decode_quotas(&xa->req_data_mb, quota_list);
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

	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, status, 0, 0);
		(void) smb_mbc_encodef(&xa->rep_param_mb, "l", 0);
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}
