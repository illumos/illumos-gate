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

#include <smbsrv/smbvar.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nterror.h>
#include <smbsrv/doserror.h>
#include <smbsrv/cifs.h>

static void smb_encode_sd(struct smb_xa *, smb_sd_t *, uint32_t);
static void smb_encode_sid(struct smb_xa *, nt_sid_t *);
static void smb_encode_sacl(struct smb_xa *, smb_acl_t *);
static void smb_encode_dacl(struct smb_xa *, smb_acl_t *);

uint32_t smb_decode_sd(struct smb_xa *, smb_sd_t *);
static nt_sid_t *smb_decode_sid(struct smb_xa *, uint32_t);
static smb_acl_t *smb_decode_acl(struct smb_xa *, uint32_t);

/*
 * smb_nt_transact_query_security_info
 *
 * This command allows the client to retrieve the security descriptor
 * on a file. The result of the call is returned to the client in the
 * Data part of the transaction response.
 *
 * Some clients specify a non-zero maximum data return size (mdrcnt)
 * for the SD and some specify zero. In either case, if the mdrcnt is
 * too small we need to return NT_STATUS_BUFFER_TOO_SMALL and a buffer
 * size hint. The client should then retry with the appropriate buffer
 * size.
 *
 *  Client Parameter Block             Description
 *  ================================== =================================
 *
 *  USHORT Fid;                        FID of target
 *  USHORT Reserved;                   MBZ
 *  ULONG secinfo;                     Fields of descriptor to set
 *
 *   Data Block Encoding                Description
 *   ================================== ==================================
 *
 *   Data[TotalDataCount]               Security Descriptor information
 */

int
smb_nt_transact_query_security_info(struct smb_request *sr, struct smb_xa *xa)
{
	smb_sd_t sd;
	uint32_t secinfo;
	uint32_t sdlen;
	uint32_t status;
	smb_error_t err;

	if (smb_decode_mbc(&xa->req_param_mb, "w2.l",
	    &sr->smb_fid, &secinfo) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}


	if ((sr->fid_ofile->f_node == NULL) ||
	    (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		/* NOTREACHED */
	}

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		secinfo &= ~SMB_SACL_SECINFO;
	}

	status = smb_sd_read(sr, &sd, secinfo);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, status, 0, 0);
		/* NOTREACHED */
	}

	sdlen = smb_sd_len(&sd, secinfo);
	if (sdlen == 0) {
		smb_sd_term(&sd);
		smbsr_error(sr, NT_STATUS_INVALID_SECURITY_DESCR, 0, 0);
		/* NOTREACHED */
	}

	if (sdlen > xa->smb_mdrcnt) {
		/*
		 * The maximum data return count specified by the
		 * client is not big enough to hold the security
		 * descriptor. We have to return an error but we
		 * should provide a buffer size hint for the client.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "l", sdlen);
		err.severity = ERROR_SEVERITY_ERROR;
		err.status   = NT_STATUS_BUFFER_TOO_SMALL;
		err.errcls   = ERRDOS;
		err.errcode  = ERROR_INSUFFICIENT_BUFFER;
		smbsr_set_error(sr, &err);
		smb_sd_term(&sd);
		return (SDRC_NORMAL_REPLY);
	}

	smb_encode_sd(xa, &sd, secinfo);
	(void) smb_encode_mbc(&xa->rep_param_mb, "l", sdlen);
	smb_sd_term(&sd);
	return (SDRC_NORMAL_REPLY);
}

/*
 * smb_nt_transact_set_security_info
 *
 * This command allows the client to change the security descriptor on a
 * file. All we do here is decode the parameters and the data. The data
 * is passed directly to smb_nt_set_security_object, with the security
 * information describing the information to set. There are no response
 * parameters or data.
 *
 *   Client Parameter Block Encoding    Description
 *   ================================== ==================================
 *   USHORT Fid;                        FID of target
 *   USHORT Reserved;                   MBZ
 *   ULONG SecurityInformation;         Fields of SD that to set
 *
 *   Data Block Encoding                Description
 *   ================================== ==================================
 *   Data[TotalDataCount]               Security Descriptor information
 */
int
smb_nt_transact_set_security_info(struct smb_request *sr, struct smb_xa *xa)
{
	smb_sd_t sd;
	uint32_t secinfo;
	uint32_t status;

	if (smb_decode_mbc(&xa->req_param_mb, "w2.l",
	    &sr->smb_fid, &secinfo) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	if ((sr->fid_ofile->f_node == NULL) ||
	    (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, 0, 0);
		/* NOTREACHED */
	}

	if (sr->fid_ofile->f_node->flags & NODE_READ_ONLY) {
		smbsr_error(sr, NT_STATUS_MEDIA_WRITE_PROTECTED, 0, 0);
		/* NOTREACHED */
	}

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		secinfo &= ~SMB_SACL_SECINFO;
	}

	if ((secinfo & SMB_ALL_SECINFO) == 0) {
		return (NT_STATUS_SUCCESS);
	}

	status = smb_decode_sd(xa, &sd);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, status, 0, 0);
		/* NOTREACHED */
	}

	if (((secinfo & SMB_OWNER_SECINFO) && (sd.sd_owner == NULL)) ||
	    ((secinfo & SMB_GROUP_SECINFO) && (sd.sd_group == NULL))) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		/* NOTREACHED */
	}

	status = smb_sd_write(sr, &sd, secinfo);
	smb_sd_term(&sd);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, status, 0, 0);
		/* NOTREACHED */
	}

	return (SDRC_NORMAL_REPLY);
}

/*
 * smb_encode_sd
 *
 * Encodes given security descriptor in the reply buffer.
 */
static void
smb_encode_sd(struct smb_xa *xa, smb_sd_t *sd, uint32_t secinfo)
{
	uint32_t offset = SMB_SD_HDRSIZE;

	/* encode header */
	(void) smb_encode_mbc(&xa->rep_data_mb, "b.w",
	    sd->sd_revision, sd->sd_control | SE_SELF_RELATIVE);

	/* owner offset */
	if (secinfo & SMB_OWNER_SECINFO) {
		ASSERT(sd->sd_owner);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", offset);
		offset += nt_sid_length(sd->sd_owner);
	} else {
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
	}

	/* group offset */
	if (secinfo & SMB_GROUP_SECINFO) {
		ASSERT(sd->sd_group);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", offset);
		offset += nt_sid_length(sd->sd_group);
	} else {
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
	}

	/* SACL offset */
	if ((secinfo & SMB_SACL_SECINFO) && (sd->sd_sacl)) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", offset);
		offset += smb_acl_len(sd->sd_sacl);
	} else {
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
	}

	/* DACL offset */
	if ((secinfo & SMB_DACL_SECINFO) && (sd->sd_dacl))
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", offset);
	else
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);

	if (secinfo & SMB_OWNER_SECINFO)
		smb_encode_sid(xa, sd->sd_owner);

	if (secinfo & SMB_GROUP_SECINFO)
		smb_encode_sid(xa, sd->sd_group);

	if (secinfo & SMB_SACL_SECINFO)
		smb_encode_sacl(xa, sd->sd_sacl);

	if (secinfo & SMB_DACL_SECINFO)
		smb_encode_dacl(xa, sd->sd_dacl);
}

/*
 * smb_encode_sid
 *
 * Encodes given SID in the reply buffer.
 */
static void
smb_encode_sid(struct smb_xa *xa, nt_sid_t *sid)
{
	int i;

	(void) smb_encode_mbc(&xa->rep_data_mb, "bb",
	    sid->Revision, sid->SubAuthCount);

	for (i = 0; i < NT_SID_AUTH_MAX; i++) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "b",
		    sid->Authority[i]);
	}

	for (i = 0; i < sid->SubAuthCount; i++) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "l",
		    sid->SubAuthority[i]);
	}
}

/*
 * smb_encode_sacl
 *
 * Encodes given SACL in the reply buffer.
 */
static void
smb_encode_sacl(struct smb_xa *xa, smb_acl_t *acl)
{
	smb_ace_t *ace;
	int i;

	if (acl == NULL)
		return;

	/* encode header */
	(void) smb_encode_mbc(&xa->rep_data_mb, "b.ww2.", acl->sl_revision,
	    acl->sl_bsize, acl->sl_acecnt);

	for (i = 0, ace = acl->sl_aces; i < acl->sl_acecnt; i++, ace++) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "bbwl",
		    ace->se_hdr.se_type, ace->se_hdr.se_flags,
		    ace->se_hdr.se_bsize, ace->se_mask);

		smb_encode_sid(xa, ace->se_sid);
	}
}

/*
 * smb_encode_dacl
 *
 * Encodes given DACL in the reply buffer.
 */
static void
smb_encode_dacl(struct smb_xa *xa, smb_acl_t *acl)
{
	smb_ace_t *ace;

	if (acl == NULL)
		return;

	/* encode header */
	(void) smb_encode_mbc(&xa->rep_data_mb, "b.ww2.", acl->sl_revision,
	    acl->sl_bsize, acl->sl_acecnt);

	ace = list_head(&acl->sl_sorted);
	while (ace) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "bbwl",
		    ace->se_hdr.se_type, ace->se_hdr.se_flags,
		    ace->se_hdr.se_bsize, ace->se_mask);

		smb_encode_sid(xa, ace->se_sid);
		ace = list_next(&acl->sl_sorted, ace);
	}
}

/*
 * smb_decode_sd
 *
 * Decodes the security descriptor in the request buffer
 * and set the fields of 'sd' appropraitely. Upon successful
 * return, caller must free allocated memories by calling
 * smb_sd_term().
 */
uint32_t
smb_decode_sd(struct smb_xa *xa, smb_sd_t *sd)
{
	struct mbuf_chain sdbuf;
	uint32_t owner_offs;
	uint32_t group_offs;
	uint32_t sacl_offs;
	uint32_t dacl_offs;

	smb_sd_init(sd, SECURITY_DESCRIPTOR_REVISION);

	(void) MBC_SHADOW_CHAIN(&sdbuf, &xa->req_data_mb,
	    xa->req_data_mb.chain_offset,
	    xa->req_data_mb.max_bytes - xa->req_data_mb.chain_offset);

	if (smb_decode_mbc(&sdbuf, "b.wllll",
	    &sd->sd_revision, &sd->sd_control,
	    &owner_offs, &group_offs, &sacl_offs, &dacl_offs))
		goto decode_error;

	sd->sd_control &= ~SE_SELF_RELATIVE;

	if (owner_offs != 0) {
		if (owner_offs < SMB_SD_HDRSIZE)
			goto decode_error;

		sd->sd_owner = smb_decode_sid(xa, owner_offs);
		if (sd->sd_owner == NULL)
			goto decode_error;
	}

	if (group_offs != 0) {
		if (group_offs < SMB_SD_HDRSIZE)
			goto decode_error;

		sd->sd_group = smb_decode_sid(xa, group_offs);
		if (sd->sd_group == NULL)
			goto decode_error;
	}

	if (sacl_offs != 0) {
		if ((sd->sd_control & SE_SACL_PRESENT) == 0)
			goto decode_error;

		if (sacl_offs < SMB_SD_HDRSIZE)
			goto decode_error;

		sd->sd_sacl = smb_decode_acl(xa, sacl_offs);
		if (sd->sd_sacl == NULL)
			goto decode_error;
	}

	if (dacl_offs != 0) {
		if ((sd->sd_control & SE_DACL_PRESENT) == 0)
			goto decode_error;

		if (dacl_offs < SMB_SD_HDRSIZE)
			goto decode_error;

		sd->sd_dacl = smb_decode_acl(xa, dacl_offs);
		if (sd->sd_dacl == NULL)
			goto decode_error;
	}

	return (NT_STATUS_SUCCESS);

decode_error:
	smb_sd_term(sd);
	return (NT_STATUS_INVALID_SECURITY_DESCR);
}

/*
 * smb_decode_sid
 *
 * Allocates memory and decodes the SID in the request buffer
 * Upon successful return, caller must free the allocated memory
 * by calling MEM_FREE()
 */
static nt_sid_t *
smb_decode_sid(struct smb_xa *xa, uint32_t offset)
{
	uint8_t revision;
	uint8_t subauth_cnt;
	struct mbuf_chain sidbuf;
	nt_sid_t *sid;
	int sidlen;
	int bytes_left;
	int i;

	offset += xa->req_data_mb.chain_offset;
	bytes_left = xa->req_data_mb.max_bytes - offset;
	if (bytes_left < sizeof (nt_sid_t))
		return (NULL);

	(void) MBC_SHADOW_CHAIN(&sidbuf, &xa->req_data_mb, offset, bytes_left);

	if (smb_decode_mbc(&sidbuf, "bb", &revision, &subauth_cnt))
		return (NULL);

	sidlen = sizeof (nt_sid_t) - sizeof (uint32_t) +
	    (subauth_cnt * sizeof (uint32_t));
	sid = MEM_MALLOC("smbsrv", sidlen);

	sid->Revision = revision;
	sid->SubAuthCount = subauth_cnt;

	for (i = 0; i < NT_SID_AUTH_MAX; i++) {
		if (smb_decode_mbc(&sidbuf, "b", &sid->Authority[i]))
			goto decode_err;
	}

	for (i = 0; i < sid->SubAuthCount; i++) {
		if (smb_decode_mbc(&sidbuf, "l", &sid->SubAuthority[i]))
			goto decode_err;
	}

	return (sid);

decode_err:
	MEM_FREE("smbsrv", sid);
	return (NULL);
}

/*
 * smb_decode_acl
 *
 * Allocates memory and decodes the ACL in the request buffer
 * Upon successful return, caller must free the allocated memory
 * by calling smb_acl_free().
 */
static smb_acl_t *
smb_decode_acl(struct smb_xa *xa, uint32_t offset)
{
	struct mbuf_chain aclbuf;
	smb_acl_t *acl;
	smb_ace_t *ace;
	uint8_t revision;
	uint16_t size;
	uint16_t acecnt;
	int bytes_left;
	uint32_t sid_offs = offset;
	int sidlen;
	int i;

	offset += xa->req_data_mb.chain_offset;
	bytes_left = xa->req_data_mb.max_bytes - offset;
	if (bytes_left < SMB_ACL_HDRSIZE)
		return (NULL);

	(void) MBC_SHADOW_CHAIN(&aclbuf, &xa->req_data_mb, offset, bytes_left);

	if (smb_decode_mbc(&aclbuf, "b.ww2.", &revision, &size, &acecnt))
		return (NULL);

	if (size == 0)
		return (NULL);

	acl = smb_acl_alloc(revision, size, acecnt);

	sid_offs += SMB_ACL_HDRSIZE;
	for (i = 0, ace = acl->sl_aces; i < acl->sl_acecnt; i++, ace++) {
		if (smb_decode_mbc(&aclbuf, "bbwl",
		    &ace->se_hdr.se_type, &ace->se_hdr.se_flags,
		    &ace->se_hdr.se_bsize, &ace->se_mask))
			goto decode_error;

		sid_offs += SMB_ACE_HDRSIZE + sizeof (ace->se_mask);
		ace->se_sid = smb_decode_sid(xa, sid_offs);
		if (ace->se_sid == NULL)
			goto decode_error;
		sidlen = nt_sid_length(ace->se_sid);
		aclbuf.chain_offset += sidlen;
		sid_offs += sidlen;
	}

	return (acl);

decode_error:
	smb_acl_free(acl);
	return (NULL);
}
