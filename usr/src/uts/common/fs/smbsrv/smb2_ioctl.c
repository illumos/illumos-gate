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

smb_sdrc_t
smb2_ioctl(smb_request_t *sr)
{
	smb2fid_t smb2fid;
	smb_fsctl_t fsctl;
	mbuf_chain_t in_mbc;
	uint32_t InputOffset;
	uint32_t MaxInputResp;
	uint32_t OutputOffset;
	uint32_t Flags;
	uint32_t status = 0;
	uint16_t StructSize;
	uint16_t DeviceType;
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

	/*
	 * Dispatch to the handler for CtlCode
	 * See CTL_CODE() in winioctl.h
	 */
	DeviceType = fsctl.CtlCode >> 16;
	switch (DeviceType) {
	case FILE_DEVICE_DFS:		/* 6 */
		status = smb_dfs_fsctl(sr, &fsctl);
		break;
	case FILE_DEVICE_FILE_SYSTEM:	/* 9 */
		status = smb2_fsctl_fs(sr, &fsctl);
		break;
	case FILE_DEVICE_NAMED_PIPE:	/* 17 */
		status = smb_opipe_fsctl(sr, &fsctl);
		break;
	case FILE_DEVICE_NETWORK_FILE_SYSTEM: /* 20 */
		status = smb2_fsctl_netfs(sr, &fsctl);
		break;
	default:
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Ioctl, smb_request_t *, sr);

	if (status != 0) {
		/*
		 * NT status codes with severity "error" normally cause
		 * an error response with no data.  However, there are
		 * exceptions like smb2_fsctl_copychunk that may return
		 * severity==error _with_ a data part.
		 */
		if ((NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_ERROR) &&
		    (fsctl.CtlCode != FSCTL_SRV_COPYCHUNK) &&
		    (fsctl.CtlCode != FSCTL_SRV_COPYCHUNK_WRITE)) {
			/* no error data */
			smb2sr_put_error(sr, status);
			return (SDRC_SUCCESS);
		}
		/* Else, error response _with_ data. */
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
	    0,			/* Flags   l */
	    /* reserved2		  4. */
	    fsctl.OutputCount,		/* # */
	    &sr->raw_data);		/* C */
	if (rc)
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;

	return (SDRC_SUCCESS);
}
