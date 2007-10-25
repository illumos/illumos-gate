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

#include <smbsrv/smb_secdesc.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

extern uint32_t smb_sd_read(smb_request_t *sr, smb_sdbuf_t **sr_sd,
    uint32_t secinfo, uint32_t *buflen);
extern uint32_t smb_sd_write(smb_request_t *sr, smb_sdbuf_t *sr_sd,
    uint32_t secinfo);

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
	smb_sdbuf_t	*sr_sd;
	uint32_t	secinfo;
	uint32_t	sr_sdlen;
	uint32_t	status;

	if (smb_decode_mbc(&xa->req_param_mb, "w2.l",
	    &sr->smb_fid, &secinfo) != 0) {
		/*
		 * It's not clear why ERRnomem is returned here.
		 * This should rarely happen and we're not sure if
		 * it's going to break something if we change this
		 * error code, so we're going to keep it for now.
		 */
		smbsr_raise_error(sr, ERRSRV, ERRnomem);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}


	if ((sr->fid_ofile->f_node == NULL) ||
	    (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_raise_nt_error(sr, NT_STATUS_ACCESS_DENIED);
		/* NOTREACHED */
	}

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		secinfo &= ~SMB_SACL_SECINFO;
	}

	sr_sdlen = xa->smb_mdrcnt;
	status = smb_sd_read(sr, &sr_sd, secinfo, &sr_sdlen);

	if (status != NT_STATUS_SUCCESS) {
		if (status == NT_STATUS_BUFFER_TOO_SMALL) {
			/*
			 * The maximum data return count specified by the
			 * client is not big enough to hold the security
			 * descriptor. We have to return an error but we
			 * can provide a buffer size hint for the client.
			 */
			(void) smb_encode_mbc(&xa->rep_param_mb, "l", sr_sdlen);
			smbsr_setup_nt_status(sr, ERROR_SEVERITY_ERROR,
			    NT_STATUS_BUFFER_TOO_SMALL);
			return (SDRC_NORMAL_REPLY);
		}

		smbsr_raise_nt_error(sr, status);
		/* NOTREACHED */
	}

	(void) smb_encode_mbc(&xa->rep_data_mb, "#c", (int)sr_sdlen, sr_sd);
	(void) smb_encode_mbc(&xa->rep_param_mb, "l", sr_sdlen);

	kmem_free(sr_sd, sr_sdlen);
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
	smb_sdbuf_t *sd_buf;
	uint32_t sec_info;
	uint32_t status;

	if (smb_decode_mbc(&xa->req_param_mb, "w2.l",
	    &sr->smb_fid, &sec_info) != 0) {
		smbsr_raise_nt_error(sr, NT_STATUS_INVALID_PARAMETER);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	if ((sr->fid_ofile->f_node == NULL) ||
	    (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK)) {
		smbsr_raise_nt_error(sr, NT_STATUS_ACCESS_DENIED);
		/* NOTREACHED */
	}

	if (sr->fid_ofile->f_node->flags & NODE_READ_ONLY) {
		smbsr_raise_nt_error(sr, NT_STATUS_MEDIA_WRITE_PROTECTED);
		/* NOTREACHED */
	}

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		sec_info &= ~SMB_SACL_SECINFO;
	}

	if ((sec_info & SMB_ALL_SECINFO) == 0) {
		return (NT_STATUS_SUCCESS);
	}

	sd_buf = kmem_alloc(xa->smb_tdscnt, KM_SLEEP);

	if ((smb_decode_mbc(&xa->req_data_mb, "#c",
	    xa->smb_tdscnt, (char *)sd_buf)) != 0) {
		kmem_free(sd_buf, xa->smb_tdscnt);
		smbsr_raise_nt_error(sr, NT_STATUS_BUFFER_TOO_SMALL);
		/* NOTREACHED */
	}

	status = smb_sd_write(sr, sd_buf, sec_info);
	kmem_free(sd_buf, xa->smb_tdscnt);

	if (status != NT_STATUS_SUCCESS) {
		smbsr_raise_nt_error(sr, status);
		/* NOTREACHED */
	}

	return (SDRC_NORMAL_REPLY);
}
