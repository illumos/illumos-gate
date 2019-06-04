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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_IOCTL
 * [MS-SMB2] 3.3.5.15
 */

#include <smbsrv/smb2_kproto.h>
#include <smb/winioctl.h>

struct smb2_ioctbl_ent {
	uint32_t	te_code;
	uint32_t	te_flags;
	uint32_t	(*te_func)(smb_request_t *, smb_fsctl_t *);
};
static struct smb2_ioctbl_ent smb2_ioc_tbl[];

/* te_flags */
#define	ITF_IPC_ONLY	1
#define	ITF_NO_FID	2
#define	ITF_DISK_FID	4

smb_sdrc_t
smb2_ioctl(smb_request_t *sr)
{
	smb2fid_t smb2fid;
	smb_fsctl_t fsctl;
	mbuf_chain_t in_mbc;
	struct smb2_ioctbl_ent *te;
	uint32_t InputOffset;
	uint32_t MaxInputResp;
	uint32_t OutputOffset;
	uint32_t Flags;
	uint32_t status = 0;
	uint16_t StructSize;
	int rc = 0;

	/* Todo: put fsctl in sr->arg.ioctl (visible in dtrace probes) */
	bzero(&in_mbc, sizeof (in_mbc));

	/*
	 * Decode SMB2 Ioctl request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "w..lqqlllllll4.",
	    &StructSize,		/* w */
	    /* reserved			  .. */
	    &fsctl.CtlCode,		/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &InputOffset,		/* l */
	    &fsctl.InputCount,		/* l */
	    &MaxInputResp,		/* l */
	    &OutputOffset,		/* l */
	    &fsctl.OutputCount,		/* l */
	    &fsctl.MaxOutputResp,	/* l */
	    &Flags);			/* l */
	    /* reserved2		  4. */
	if (rc || StructSize != 57)
		return (SDRC_ERROR);

	/*
	 * If there's an input buffer, setup a shadow.
	 */
	if (fsctl.InputCount) {
		if (InputOffset < (SMB2_HDR_SIZE + 56))
			return (SDRC_ERROR);
		if (fsctl.InputCount > smb2_max_trans)
			return (SDRC_ERROR);
		rc = MBC_SHADOW_CHAIN(&in_mbc, &sr->smb_data,
		    sr->smb2_cmd_hdr + InputOffset, fsctl.InputCount);
		if (rc) {
			return (SDRC_ERROR);
		}
	}
	fsctl.in_mbc = &in_mbc;

	/*
	 * If output is possible, setup the output mbuf_chain
	 */
	if (fsctl.MaxOutputResp > smb2_max_trans)
		fsctl.MaxOutputResp = smb2_max_trans;
	sr->raw_data.max_bytes = fsctl.MaxOutputResp;
	fsctl.out_mbc = &sr->raw_data;

	/*
	 * [MS-SMB2] 3.3.5.15
	 *
	 * If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL
	 * the server MUST fail the request with STATUS_NOT_SUPPORTED.
	 *
	 * If the CtlCode is any of (... see switch below...) and the
	 * value of FileId in the SMB2 Header of the request is not
	 * 0xFFFFFFFFFFFFFFFF, then the server MUST fail the request
	 * with STATUS_INVALID_PARAMETER.  (Otherwise lookup the FID.)
	 */
	if (Flags != SMB2_0_IOCTL_IS_FSCTL) {
		status = NT_STATUS_NOT_SUPPORTED;
	} else switch (fsctl.CtlCode) {
	case FSCTL_DFS_GET_REFERRALS:
	case FSCTL_DFS_GET_REFERRALS_EX:
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	case FSCTL_PIPE_WAIT:
		if (smb2fid.temporal != ~0LL ||
		    smb2fid.persistent != ~0LL) {
			status = NT_STATUS_INVALID_PARAMETER;
		}
		break;
	default:
		status = smb2sr_lookup_fid(sr, &smb2fid);
		if (status != 0) {
			status = NT_STATUS_FILE_CLOSED;
		}
		break;
	}

	/*
	 * Keep FID lookup before the start probe.
	 */
	DTRACE_SMB2_START(op__Ioctl, smb_request_t *, sr);

	if (status)
		goto errout;

	for (te = smb2_ioc_tbl; te->te_code; te++) {
		if (te->te_code == fsctl.CtlCode)
			break;
	}
	if (te->te_code == 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "smb2_ioctl: unknown code 0x%x",
		    fsctl.CtlCode);
#endif
		status = NT_STATUS_NOT_SUPPORTED;
		goto errout;
	}

	/*
	 * Some requests are only valid on IPC$
	 */
	if ((te->te_flags & ITF_IPC_ONLY) != 0 &&
	    !STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		status = NT_STATUS_INVALID_DEVICE_REQUEST;
		goto errout;
	}

	/*
	 * Note: some ioctls require a "disk" fid.
	 */
	if (te->te_flags & ITF_DISK_FID) {
		if (sr->fid_ofile == NULL ||
		    !SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
	}

	/*
	 * Dispatch to the handler for CtlCode
	 */
	status = (te->te_func)(sr, &fsctl);

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Ioctl, smb_request_t *, sr);

	if (status != 0) {
		if (NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_ERROR) {
			/* no error data */
			smb2sr_put_error(sr, status);
			return (SDRC_SUCCESS);
		}
		/* Warnings like NT_STATUS_BUFFER_OVERFLOW are OK. */
	}

	fsctl.InputCount = 0;
	InputOffset = SMB2_HDR_SIZE + 48;

	fsctl.OutputCount = MBC_LENGTH(&sr->raw_data);
	OutputOffset = (fsctl.OutputCount) ? InputOffset : 0;

	/*
	 * Encode SMB2 Ioctl reply
	 */
	StructSize = 49;
	rc = smb_mbc_encodef(
	    &sr->reply, "w..lqqlllll4.#C",
	    StructSize,			/* w */
	    /* reserved			  .. */
	    fsctl.CtlCode,		/* l */
	    smb2fid.persistent,		/* q */
	    smb2fid.temporal,		/* q */
	    InputOffset,		/* l */
	    fsctl.InputCount,		/* l */
	    OutputOffset,		/* l */
	    fsctl.OutputCount,		/* l */
	    Flags,			/* l */
	    /* reserved2		  4. */
	    fsctl.OutputCount,		/* # */
	    &sr->raw_data);		/* C */
	if (rc)
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;

	return (SDRC_SUCCESS);
}

/* ARGSUSED */
static uint32_t
smb2_fsctl_notsup(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

static struct smb2_ioctbl_ent
smb2_ioc_tbl[] = {

	/*
	 * FILE_DEVICE_DFS (6)
	 */
	{ FSCTL_DFS_GET_REFERRALS,
	    ITF_IPC_ONLY | ITF_NO_FID,		smb_dfs_get_referrals },
	{ FSCTL_DFS_GET_REFERRALS_EX,
	    ITF_IPC_ONLY | ITF_NO_FID,		smb_dfs_get_referrals },

	/*
	 * FILE_DEVICE_FILE_SYSTEM (9)
	 */
	{ FSCTL_SET_REPARSE_POINT,	0,	smb2_fsctl_notsup },
	{ FSCTL_CREATE_OR_GET_OBJECT_ID, 0,	smb2_fsctl_notsup },
	{ FSCTL_FILE_LEVEL_TRIM,	0,	smb2_fsctl_notsup },

	/*
	 * FILE_DEVICE_NAMED_PIPE (17)
	 */
	{ FSCTL_PIPE_PEEK,
	    ITF_IPC_ONLY,			smb_opipe_fsctl },
	{ FSCTL_PIPE_TRANSCEIVE,
	    ITF_IPC_ONLY,			smb_opipe_fsctl },
	{ FSCTL_PIPE_WAIT,
	    ITF_IPC_ONLY | ITF_NO_FID,		smb_opipe_fsctl },

	/*
	 * FILE_DEVICE_NETWORK_FILE_SYSTEM (20)
	 */
	{ FSCTL_SRV_ENUMERATE_SNAPSHOTS,
	    ITF_DISK_FID,			smb_vss_enum_snapshots },
	{ FSCTL_SRV_REQUEST_RESUME_KEY,	0,	smb2_fsctl_notsup },
	{ FSCTL_SRV_COPYCHUNK,		0,	smb2_fsctl_notsup },
	{ FSCTL_SRV_COPYCHUNK_WRITE,	0,	smb2_fsctl_notsup },
	{ FSCTL_SRV_READ_HASH,		0,	smb2_fsctl_notsup },

	{ FSCTL_LMR_REQUEST_RESILIENCY,
	    ITF_NO_FID,		smb2_fsctl_notsup },
	{ FSCTL_QUERY_NETWORK_INTERFACE_INFO,
	    ITF_NO_FID,		smb2_fsctl_notsup },
	{ FSCTL_VALIDATE_NEGOTIATE_INFO,
	    ITF_NO_FID,		smb2_fsctl_vneginfo },

	/*
	 * End marker
	 */
	{ 0, 0, 0 }
};
