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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * File Change Notification (FCN)
 * SMB1 specific part.
 */

/*
 * SMB: nt_transact_notify_change
 *
 *  Client Setup Words                 Description
 *  ================================== =================================
 *
 *  ULONG CompletionFilter;            Specifies operation to monitor
 *  USHORT Fid;                        Fid of directory to monitor
 *  BOOLEAN WatchTree;                 TRUE = watch all subdirectories too
 *  UCHAR Reserved;                    MBZ
 *
 * This command notifies the client when the directory specified by Fid is
 * modified.  See smb_notify.c for details.
 *
 * The MaxParameterCount field in the NT transact header determines
 * the size of the buffer used to return change information:
 *
 *  Server Response                    Description
 *  ================================== ================================
 *  ParameterCount                     # of bytes of change data
 *  Parameters[ ParameterCount ]       FILE_NOTIFY_INFORMATION
 *                                      structures
 *
 * See smb_notify.c for details of FILE_NOTIFY_INFORMATION
 */

#include <smbsrv/smb_kproto.h>

/*
 * smb_nt_transact_notify_change
 *
 * Handle and SMB NT transact NOTIFY CHANGE request.
 * Basically, wait until "something has changed", and either
 * return information about what changed, or return a special
 * error telling the client "many things changed".
 *
 * The implementation uses a per-node list of waiting notify
 * requests like this one, each with a blocked worker thead.
 * Later, FEM and/or smbsrv events wake these threads, which
 * then send the reply to the client.
 */
smb_sdrc_t
smb_nt_transact_notify_change(smb_request_t *sr, struct smb_xa *xa)
{
	mbuf_chain_t		tmp_mbc;
	uint32_t		oBufSize;
	uint32_t		CompletionFilter;
	unsigned char		WatchTree;
	uint32_t		status;

	if (smb_mbc_decodef(&xa->req_setup_mb, "lwb",
	    &CompletionFilter, &sr->smb_fid, &WatchTree) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	oBufSize = xa->rep_param_mb.max_bytes;
	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (WatchTree)
		CompletionFilter |= FILE_NOTIFY_CHANGE_EV_SUBDIR;

	/*
	 * Check for events and consume, non-blocking.
	 * Special return STATUS_PENDING means:
	 *   No events; caller must call "act2" next.
	 */
	status = smb_notify_act1(sr, oBufSize, CompletionFilter);
	if (status == NT_STATUS_PENDING) {
		status = smb_notify_act2(sr);
		if (status == NT_STATUS_PENDING) {
			/* See: smb_nt_transact_notify_finish */
			return (SDRC_SR_KEPT);
		}
		/* else: some other error, or even success */
	}

	/*
	 * SMB1 expects an empty trans response after the
	 * FID we're watching is closed.
	 */
	if (status == NT_STATUS_NOTIFY_CLEANUP) {
		status = 0;
		MBC_FLUSH(&sr->raw_data);
	}

	if (status != 0) {
		smbsr_status(sr, status, 0, 0);
		if (NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_ERROR)
			return (SDRC_ERROR);
		/* Else continue with NT_STATUS_NOTIFY_ENUM_DIR etc. */
	}

	/*
	 * The nt_trans call expects the output in rep_param_mb,
	 * but our common code puts it in raw_data.  Move it
	 * where the caller expects it via swaping the two,
	 * which lets the normal cleanup take care of both.
	 */
	tmp_mbc = xa->rep_param_mb;
	xa->rep_param_mb = sr->raw_data;
	sr->raw_data = tmp_mbc;

	return (SDRC_SUCCESS);
}

/*
 * This is called via taskq_dispatch in smb_notify.c
 * to finish up an NT transact notify change request.
 */
void
smb_nt_transact_notify_finish(void *arg)
{
	smb_request_t	*sr = arg;
	struct smb_xa	*xa;
	smb_disp_stats_t *sds;
	int		total_bytes, n_setup, n_param, n_data;
	int		param_off, param_pad, data_off, data_pad;
	uint32_t	status;

	SMB_REQ_VALID(sr);

	/*
	 * Common part of notify, puts data in sr->raw_data
	 */
	status = smb_notify_act3(sr);

	/*
	 * SMB1 expects an empty trans response after the
	 * FID we're watching is closed.
	 */
	if (status == NT_STATUS_NOTIFY_CLEANUP) {
		status = 0;
		MBC_FLUSH(&sr->raw_data);
	}

	if (status != 0) {
		smbsr_status(sr, status, 0, 0);
		if (NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_ERROR) {
			(void) smb_mbc_encodef(&sr->reply, "bwbw",
			    (short)0, 0L, (short)0, 0L);
			goto sendit;
		}
		/* Else continue with NT_STATUS_NOTIFY_ENUM_DIR etc. */
	}

	/*
	 * setup the NT transact reply
	 *
	 * Note that this is a copy/paste of code from
	 * smb_nt_trans_dispatch(), with minor changes.
	 * Intentionally keeping this similar to the
	 * original rather than hand-optimizing.
	 *
	 * The "setup" and "data" parts of this trans reply
	 * (n_setup, n_data, rep_setup_mb, rep_data_mb) are
	 * always empty.  sr->raw_data replaces rep_param_mb.
	 */
	xa = sr->r_xa;
	n_setup = MBC_LENGTH(&xa->rep_setup_mb);
	n_param = MBC_LENGTH(&sr->raw_data);
	n_data  = MBC_LENGTH(&xa->rep_data_mb);

	n_setup = (n_setup + 1) / 2;	/* Convert to setup words */
	param_pad = 1;			/* must be one */
	param_off = param_pad + 32 + 37 + (n_setup << 1) + 2;
	/* Pad to 4 bytes */
	data_pad = (4 - ((param_off + n_param) & 3)) % 4;
	/* Param off from hdr */
	data_off = param_off + n_param + data_pad;
	total_bytes = param_pad + n_param + data_pad + n_data;

	(void) smbsr_encode_result(sr, 18+n_setup, total_bytes,
	    "b3.llllllllbCw#.C#.C",
	    18 + n_setup,	/* wct */
	    n_param,		/* Total Parameter Bytes */
	    n_data,		/* Total Data Bytes */
	    n_param,		/* Total Parameter Bytes this buffer */
	    param_off,		/* Param offset from header start */
	    0,			/* Param displacement */
	    n_data,		/* Total Data Bytes this buffer */
	    data_off,		/* Data offset from header start */
	    0,			/* Data displacement */
	    n_setup,		/* suwcnt */
	    &xa->rep_setup_mb,	/* setup[] */
	    total_bytes,	/* Total data bytes */
	    param_pad,
	    &sr->raw_data,	/* output mbc */
	    data_pad,
	    &xa->rep_data_mb);

sendit:
	sds = &sr->sr_server->sv_disp_stats1[sr->smb_com];
	atomic_add_64(&sds->sdt_txb, (int64_t)sr->reply.chain_offset);

	smbsr_send_reply(sr);	/* also puts the SMB header. */
	smbsr_cleanup(sr);

	mutex_enter(&sr->sr_mutex);
	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	mutex_exit(&sr->sr_mutex);

	smb_request_free(sr);
}
