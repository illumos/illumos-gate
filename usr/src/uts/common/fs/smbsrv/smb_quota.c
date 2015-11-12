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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/string.h>
#include <sys/fs/zfs.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_door.h>
#include <smbsrv/smb_idmap.h>

/*
 * A user/group quota entry passed over the wire consists of:
 * - next offset (uint32_t)
 * - length of SID (uint32_t)
 * - last modified time (uint64_t)
 * - quota used (uint64_t)
 * - quota limit (uint64_t)
 * - quota threahold (uint64_t)
 * - variable length sid - max = 32 bytes
 * SMB_QUOTA_SIZE_NO_SID is the size of the above, excluding the sid.
 */
#define	SMB_QUOTA_SIZE_NO_SID \
	((2 * sizeof (uint32_t)) + (4 * sizeof (uint64_t)))
#define	SMB_QUOTA_EST_SIZE (SMB_QUOTA_SIZE_NO_SID + SMB_EST_SID_SIZE)
#define	SMB_QUOTA_MAX_SIZE (SMB_QUOTA_SIZE_NO_SID + SMB_MAX_SID_SIZE)


/*
 * smb_quota_init_sids
 *
 * If the query is of type SMB_QUOTA_QUERY_SIDLIST or
 * SMB_QUOTA_QUERY_STARTSID decode the list of sids from
 * the client request into request->qq_sid_list.
 * Otherwise (type SMB_QUOTA_QUERY_ALL) find the resume sid
 * and insert it into request->qq_sid_list, or reset the
 * resume sid to NULL if request->qq_restart.
 *
 * Returns: NT_STATUS codes
 */
uint32_t
smb_quota_init_sids(mbuf_chain_t *mbc, smb_quota_query_t *request,
    smb_ofile_t *ofile)
{
	smb_quota_sid_t *sid;
	list_t *sid_list;
	uint32_t status = NT_STATUS_SUCCESS;

	sid_list = &request->qq_sid_list;
	list_create(sid_list, sizeof (smb_quota_sid_t),
	    offsetof(smb_quota_sid_t, qs_list_node));

	switch (request->qq_query_op) {
	case SMB_QUOTA_QUERY_SIDLIST:
	case SMB_QUOTA_QUERY_STARTSID:
		status = smb_quota_decode_sids(mbc, sid_list);
		break;
	case SMB_QUOTA_QUERY_ALL:
		if (request->qq_restart)
			smb_ofile_set_quota_resume(ofile, NULL);
		else {
			sid = kmem_zalloc(sizeof (smb_quota_sid_t), KM_SLEEP);
			list_insert_tail(sid_list, sid);
			smb_ofile_get_quota_resume(ofile, sid->qs_sidstr,
			    SMB_SID_STRSZ);
			if (*sid->qs_sidstr == '\0')
				status = NT_STATUS_INVALID_PARAMETER;
		}
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	return (status);
}

/*
 * smb_quota_free_sids
 */
void
smb_quota_free_sids(smb_quota_query_t *request)
{
	list_t *sid_list;
	smb_quota_sid_t *sid;

	sid_list = &request->qq_sid_list;

	while ((sid = list_head(sid_list)) != NULL) {
		list_remove(sid_list, sid);
		kmem_free(sid, sizeof (smb_quota_sid_t));
	}

	list_destroy(sid_list);
}

/*
 * smb_quota_decode_sids
 *
 * Decode the SIDs from the data block and stores them in string form in list.
 * Eaxh sid entry comprises:
 *	next_offset (4 bytes) - offset of next entry
 *	sid length (4 bytes)
 *	sid (variable length = sidlen)
 * The last entry will have a next_offset value of 0.
 *
 * Returns NT_STATUS codes.
 */
uint32_t
smb_quota_decode_sids(mbuf_chain_t *mbc, list_t *list)
{
	uint32_t	offset, mb_offset, sid_offset, bytes_left;
	uint32_t	next_offset, sidlen;
	smb_sid_t	*sid;
	smb_quota_sid_t	*qsid;
	uint32_t status = NT_STATUS_SUCCESS;
	struct mbuf_chain sidbuf;
	int rc;

	offset = 0;
	do {
		mb_offset = offset + mbc->chain_offset;
		bytes_left = mbc->max_bytes - mb_offset;
		rc = MBC_SHADOW_CHAIN(&sidbuf, mbc,
		    mb_offset, bytes_left);
		if (rc != 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		if (smb_mbc_decodef(&sidbuf, "ll", &next_offset, &sidlen)) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		sid_offset = offset + (2 * sizeof (uint32_t));
		sid = smb_decode_sid(mbc, sid_offset);
		if (sid == NULL) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		qsid = kmem_zalloc(sizeof (smb_quota_sid_t), KM_SLEEP);
		smb_sid_tostr(sid, qsid->qs_sidstr);
		smb_sid_free(sid);
		sid = NULL;

		list_insert_tail(list, qsid);
		offset += next_offset;
	} while ((next_offset != 0) && (bytes_left > 0));

	return (status);
}

/*
 * smb_quota_max_quota
 *
 * If the query is if type SMB_QUOTA_QUERY_SIDLIST a quota entry
 * is returned for each sid in the sidlist. request->qr_max_quota
 * is set to 0 and is unused.
 * Otherwise (for SMB_QUOTA_QUERY_STARTSID and SMB_QUOTA_QUERY_ALL)
 * max_quota is the maximum number of quota entries requested from
 * the file system (via door call smb_quota_query()).
 * If single is set max_quota is set to 1. If single is not set
 * max quota is calculated as the number of quotas of size
 * SMB_QUOTA_EST_SIZE that would fit in the response buffer.
 */
void
smb_quota_max_quota(mbuf_chain_t *mbc, smb_quota_query_t *request)
{
	if (request->qq_query_op == SMB_QUOTA_QUERY_SIDLIST)
		request->qq_max_quota = 0;
	else if (request->qq_single)
		request->qq_max_quota = 1;
	else
		request->qq_max_quota = (mbc->max_bytes / SMB_QUOTA_EST_SIZE);
}

/*
 * smb_quota_decode_quotas
 *
 * Decode the quota entries into a list_t of smb_quota_t.
 * SMB_QUOTA_SIZE_NO_SID is the size of a quota entry,
 * excluding the sid.
 * The last entry will have a next_offset value of 0.
 *
 * Returns NT_STATUS codes.
 */
uint32_t
smb_quota_decode_quotas(mbuf_chain_t *mbc, list_t *list)
{
	uint32_t	offset, mb_offset, sid_offset, bytes_left;
	uint32_t	next_offset, sidlen;
	uint64_t	mtime;
	smb_sid_t	*sid;
	smb_quota_t	*quota;
	uint32_t	status = NT_STATUS_SUCCESS;
	struct mbuf_chain quotabuf;
	int rc;

	offset = 0;
	do {
		mb_offset = offset + mbc->chain_offset;
		bytes_left = mbc->max_bytes - mb_offset;
		rc = MBC_SHADOW_CHAIN(&quotabuf, mbc,
		    mb_offset, bytes_left);
		if (rc != 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		quota = kmem_zalloc(sizeof (smb_quota_t), KM_SLEEP);

		if (smb_mbc_decodef(&quotabuf, "llqqqq",
		    &next_offset, &sidlen, &mtime,
		    &quota->q_used, &quota->q_thresh, &quota->q_limit)) {
			kmem_free(quota, sizeof (smb_quota_t));
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		sid_offset = offset + SMB_QUOTA_SIZE_NO_SID;
		sid = smb_decode_sid(mbc, sid_offset);
		if (sid == NULL) {
			kmem_free(quota, sizeof (smb_quota_t));
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		bzero(quota->q_sidstr, SMB_SID_STRSZ);
		smb_sid_tostr(sid, quota->q_sidstr);
		smb_sid_free(sid);
		sid = NULL;

		list_insert_tail(list, quota);
		offset += next_offset;
	} while ((next_offset != 0) && (bytes_left > 0));

	return (status);
}

/*
 * smb_quota_free_quotas
 */
void
smb_quota_free_quotas(list_t *list)
{
	smb_quota_t *quota;

	while ((quota = list_head(list)) != NULL) {
		list_remove(list, quota);
		kmem_free(quota, sizeof (smb_quota_t));
	}

	list_destroy(list);
}

/*
 * smb_quota_encode_quotas
 *
 * Encode the quota entries from a list_t of smb_quota_t.
 * SMB_QUOTA_SIZE_NO_SID is the size of a quota entry,
 * excluding the sid.
 * The last entry will have a next_offset value of 0.
 * Sets the last encoded SID as the resume sid.
 */
uint32_t
smb_quota_encode_quotas(mbuf_chain_t *mbc, smb_quota_query_t *request,
    smb_quota_response_t *reply, smb_ofile_t *ofile)
{
	uint32_t next_offset, sid_offset;
	uint64_t mtime = 0;
	uint32_t sidlen, pad;
	smb_sid_t *sid;
	char *sidstr = NULL, *resume = NULL;
	smb_quota_t *quota, *next_quota;
	list_t *list = &reply->qr_quota_list;

	int rc;
	uint32_t status = NT_STATUS_SUCCESS;

	quota = list_head(list);
	while (quota) {
		next_quota = list_next(list, quota);
		sidstr = quota->q_sidstr;
		if ((sid = smb_sid_fromstr(sidstr)) == NULL) {
			quota = next_quota;
			continue;
		}

		sidlen = smb_sid_len(sid);
		sid_offset = SMB_QUOTA_SIZE_NO_SID;
		next_offset = sid_offset + sidlen;
		pad = smb_pad_align(next_offset, 8);
		next_offset += pad;

		if (!MBC_ROOM_FOR(mbc, next_offset)) {
			smb_sid_free(sid);
			break;
		}
		if (!MBC_ROOM_FOR(mbc,
		    next_offset + SMB_QUOTA_MAX_SIZE)) {
			next_quota = NULL;
		}

		rc = smb_mbc_encodef(mbc, "llqqqq",
		    next_quota ? next_offset : 0, sidlen, mtime,
		    quota->q_used, quota->q_thresh, quota->q_limit);
		if (rc == 0) {
			smb_encode_sid(mbc, sid);
			rc = smb_mbc_encodef(mbc, "#.", pad);
		}

		smb_sid_free(sid);

		if (rc != 0) {
			status = NT_STATUS_INTERNAL_ERROR;
			break;
		}

		resume = sidstr;
		quota = next_quota;
	}

	if ((status == NT_STATUS_SUCCESS) &&
	    ((request->qq_query_op == SMB_QUOTA_QUERY_STARTSID) ||
	    (request->qq_query_op == SMB_QUOTA_QUERY_ALL))) {
		smb_ofile_set_quota_resume(ofile, resume);
	}

	return (status);
}

/*
 * smb_quota_query_user_quota
 *
 * Get user quota information for a single user (uid)
 * for the current file system.
 * Find the user's sid, insert it in the sidlist of a
 * smb_quota_query_t request and invoke the door call
 * smb_quota_query() to obtain the quota information.
 *
 * Returns: NT_STATUS codes.
 */
uint32_t
smb_quota_query_user_quota(smb_request_t *sr, uid_t uid, smb_quota_t *quota)
{
	smb_sid_t *sid;
	smb_quota_sid_t qsid;
	smb_quota_query_t request;
	smb_quota_response_t reply;
	list_t *sid_list;
	smb_quota_t *q;
	smb_node_t *tnode;
	uint32_t status = NT_STATUS_SUCCESS;

	if (smb_idmap_getsid(uid, SMB_IDMAP_USER, &sid) != IDMAP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	smb_sid_tostr(sid, qsid.qs_sidstr);
	smb_sid_free(sid);

	bzero(&request, sizeof (smb_quota_query_t));
	bzero(&reply, sizeof (smb_quota_response_t));

	tnode = sr->tid_tree->t_snode;
	request.qq_root_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (smb_node_getmntpath(tnode, request.qq_root_path, MAXPATHLEN) != 0) {
		kmem_free(request.qq_root_path, MAXPATHLEN);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	sid_list = &request.qq_sid_list;
	list_create(sid_list, sizeof (smb_quota_sid_t),
	    offsetof(smb_quota_sid_t, qs_list_node));
	list_insert_tail(sid_list, &qsid);

	request.qq_query_op = SMB_QUOTA_QUERY_SIDLIST;
	request.qq_single = B_TRUE;

	if (smb_quota_query(sr->sr_server, &request, &reply) != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
	} else {
		if (reply.qr_status != NT_STATUS_SUCCESS) {
			status = reply.qr_status;
		} else {
			q = list_head(&reply.qr_quota_list);
			if ((q == NULL) ||
			    (strcmp(qsid.qs_sidstr, q->q_sidstr) != 0)) {
				/* should never happen */
				status = NT_STATUS_INTERNAL_ERROR;
			} else {
				bcopy(q, quota, sizeof (smb_quota_t));
			}
		}
		xdr_free(smb_quota_response_xdr, (char *)&reply);
	}

	kmem_free(request.qq_root_path, MAXPATHLEN);
	list_remove(sid_list, &qsid);
	list_destroy(sid_list);

	return (status);
}

/*
 * smb_quota_query
 *
 * Door call to query quotas for the provided filesystem path.
 * Returns: -1 - door call (or encode/decode) failure.
 *	     0 - success. Status set in reply.
 */
int
smb_quota_query(smb_server_t *sv, smb_quota_query_t *request,
    smb_quota_response_t *reply)
{
	int	rc;

	rc = smb_kdoor_upcall(sv, SMB_DR_QUOTA_QUERY,
	    request, smb_quota_query_xdr, reply, smb_quota_response_xdr);

	return (rc);
}

/*
 * smb_quota_set
 *
 * Door call to set quotas for the provided filesystem path.
 * Returns: -1 - door call (or encode/decode) failure.
 *	     0 - success. Status set in reply.
 */
int
smb_quota_set(smb_server_t *sv, smb_quota_set_t *request, uint32_t *reply)
{
	int	rc;

	rc = smb_kdoor_upcall(sv, SMB_DR_QUOTA_SET,
	    request, smb_quota_set_xdr, reply, xdr_uint32_t);

	return (rc);
}
