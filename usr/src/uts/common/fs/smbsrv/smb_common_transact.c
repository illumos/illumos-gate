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
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/oem.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/mailslot.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/nterror.h>

#define	MAX_SHARE_NAME_LEN	13
#define	SHARE_INFO_1_SIZE	(MAX_SHARE_NAME_LEN + sizeof (char) + \
    sizeof (short) + sizeof (uint32_t))

/*
 * count of bytes in server response packet
 * except parameters and data. Note that setup
 * word count is zero.
 */
#define	RESP_HEADER_LEN		24

/*
 * NB. I started by using common functions for transaction/transaction2
 * and transaction_secondary/transaction2_secondary because they
 * are respectively so similar. However, it turned out to be a bad
 * idea because of quirky differences. Be sure if you modify one
 * of these four functions to check and see if the modification should
 * be applied to its peer.
 */

static int smb_trans_ready(struct smb_xa *);
static smb_sdrc_t smb_trans_dispatch(struct smb_request *, struct smb_xa *);
static smb_sdrc_t smb_trans2_dispatch(struct smb_request *, struct smb_xa *);
static smb_sdrc_t smb_nt_transact_query_quota(struct smb_request *,
    struct smb_xa *);

smb_sdrc_t
smb_pre_transaction(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_transaction(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_transaction(smb_request_t *sr)
{
	int		rc;
	unsigned char	msrcnt, suwcnt;
	uint16_t	tpscnt, tdscnt, mprcnt, mdrcnt, flags;
	uint16_t	pscnt, psoff, dscnt, dsoff;
	uint32_t	timeo;
	struct smb_xa *xa;
	char *stn;
	int ready;

	rc = smbsr_decode_vwv(sr, SMB_TRANSHDR_ED_FMT,
	    &tpscnt, &tdscnt, &mprcnt, &mdrcnt, &msrcnt, &flags,
	    &timeo, &pscnt, &psoff, &dscnt, &dsoff, &suwcnt);

	if (rc != 0)
		return (SDRC_ERROR);

	xa = smb_xa_create(sr->session, sr, tpscnt, tdscnt, mprcnt, mdrcnt,
	    msrcnt, suwcnt);
	if (xa == NULL) {
		smbsr_error(sr, 0, ERRSRV, ERRnoroom);
		return (SDRC_ERROR);
	}

	/* Should be some alignment stuff here in SMB? */
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE) {
		rc = smbsr_decode_data(sr, "%.U", sr, &stn);
	} else {
		rc = smbsr_decode_data(sr, "%s", sr,  &stn);
	}
	if (rc != 0) {
		smb_xa_rele(sr->session, xa);
		return (SDRC_ERROR);
	}
	xa->xa_smb_trans_name = MEM_STRDUP("smb", stn);

	xa->smb_flags  = flags;
	xa->smb_timeout = timeo;
	xa->req_disp_param = pscnt;
	xa->req_disp_data  = dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_setup_mb, &sr->smb_vwv,
	    sr->smb_vwv.chain_offset, suwcnt * 2)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	ready = smb_trans_ready(xa);

	if (smb_xa_open(xa)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRsrverror);
		return (SDRC_ERROR);
	}
	sr->r_xa = xa;

	if (!ready) {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if (!smb_xa_complete(xa)) {
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	return (smb_trans_dispatch(sr, xa));
}

smb_sdrc_t
smb_pre_transaction_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__TransactionSecondary__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_transaction_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__TransactionSecondary__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_transaction_secondary(smb_request_t *sr)
{
	uint16_t tpscnt, tdscnt, pscnt, psdisp;
	uint16_t dscnt, dsoff, dsdisp, psoff;
	smb_xa_t *xa;
	int rc;

	if ((xa = smbsr_lookup_xa(sr)) == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRsrverror);
		return (SDRC_ERROR);
	}

	if (sr->session->signing.flags & SMB_SIGNING_ENABLED) {
		if (smb_sign_check_secondary(sr, xa->reply_seqnum) != 0) {
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRDOS, ERRnoaccess);
			return (SDRC_ERROR);
		}
	}

	if (xa->smb_com != SMB_COM_TRANSACTION) {
		return (SDRC_DROP_VC);
	}

	rc = smbsr_decode_vwv(sr, SMB_TRANSSHDR_ED_FMT, &tpscnt, &tdscnt,
	    &pscnt, &psoff, &psdisp, &dscnt, &dsoff, &dsdisp);

	if (rc != 0)
		return (SDRC_ERROR);

	mutex_enter(&xa->xa_mutex);
	xa->smb_tpscnt = tpscnt;	/* might have shrunk */
	xa->smb_tdscnt = tdscnt;	/* might have shrunk */
	xa->req_disp_param = psdisp+pscnt;
	xa->req_disp_data  = dsdisp+dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	mutex_exit(&xa->xa_mutex);

	if (!smb_trans_ready(xa))
		return (SDRC_NO_REPLY);

	if (!smb_xa_complete(xa))
		return (SDRC_NO_REPLY);

	return (smb_trans_dispatch(sr, xa));
}

smb_sdrc_t
smb_pre_ioctl(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Ioctl__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_ioctl(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Ioctl__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_ioctl(smb_request_t *sr)
{
	uint16_t fid, category, function, tpscnt, tdscnt, mprcnt;
	uint16_t mdrcnt, pscnt, pdoff, dscnt, dsoff;
	uint32_t timeout;
	int rc;

	rc = smbsr_decode_vwv(sr, "wwwwwwwl2.wwww", &fid, &category, &function,
	    &tpscnt, &tdscnt, &mprcnt, &mdrcnt, &timeout, &pscnt,
	    &pdoff, &dscnt, &dsoff);

	if (rc != 0)
		return (SDRC_ERROR);

	return (SDRC_NOT_IMPLEMENTED);
}

smb_sdrc_t
smb_pre_transaction2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction2__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_transaction2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_transaction2(struct smb_request *sr)
{
	unsigned char	msrcnt, suwcnt;
	uint16_t	tpscnt, tdscnt, mprcnt, mdrcnt, flags;
	uint16_t	pscnt, psoff, dscnt, dsoff;
	uint32_t	timeo;
	smb_xa_t *xa;
	int ready;
	int rc;

	rc = smbsr_decode_vwv(sr, SMB_TRANSHDR_ED_FMT, &tpscnt, &tdscnt,
	    &mprcnt, &mdrcnt, &msrcnt, &flags, &timeo, &pscnt, &psoff, &dscnt,
	    &dsoff, &suwcnt);

	if (rc != 0)
		return (SDRC_ERROR);

	xa = smb_xa_create(sr->session, sr, tpscnt, tdscnt, mprcnt, mdrcnt,
	    msrcnt, suwcnt);
	if (xa == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRnoroom);
		return (SDRC_ERROR);
	}

	xa->smb_flags  = flags;
	xa->smb_timeout = timeo;
	xa->req_disp_param = pscnt;
	xa->req_disp_data  = dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_setup_mb, &sr->smb_vwv,
	    sr->smb_vwv.chain_offset, suwcnt*2)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	ready = smb_trans_ready(xa);

	if (smb_xa_open(xa)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRsrverror);
		return (SDRC_ERROR);
	}
	sr->r_xa = xa;

	if (!ready) {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if (!smb_xa_complete(xa)) {
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	return (smb_trans2_dispatch(sr, xa));
}

smb_sdrc_t
smb_pre_transaction2_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction2Secondary__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_transaction2_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Transaction2Secondary__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_transaction2_secondary(smb_request_t *sr)
{
	uint16_t tpscnt, tdscnt, fid;
	uint16_t pscnt, psoff, psdisp, dscnt, dsoff, dsdisp;
	smb_xa_t *xa;
	int rc;

	if ((xa = smbsr_lookup_xa(sr)) == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRsrverror);
		return (SDRC_ERROR);
	}

	if (sr->session->signing.flags & SMB_SIGNING_ENABLED) {
		if (smb_sign_check_secondary(sr, xa->reply_seqnum) != 0) {
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRDOS, ERRnoaccess);
			return (SDRC_ERROR);
		}
	}

	if (xa->smb_com != SMB_COM_TRANSACTION2) {
		return (SDRC_DROP_VC);
	}

	rc = smbsr_decode_vwv(sr, SMB_TRANS2SHDR_ED_FMT, &tpscnt, &tdscnt,
	    &pscnt, &psoff, &psdisp, &dscnt, &dsoff, &dsdisp, &fid);

	if (rc != 0)
		return (SDRC_ERROR);

	mutex_enter(&xa->xa_mutex);
	xa->smb_tpscnt = tpscnt;	/* might have shrunk */
	xa->smb_tdscnt = tdscnt;	/* might have shrunk */
	xa->xa_smb_fid = fid;		/* overwrite rules? */
	xa->req_disp_param = psdisp + pscnt;
	xa->req_disp_data  = dsdisp + dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	mutex_exit(&xa->xa_mutex);

	if (!smb_trans_ready(xa))
		return (SDRC_NO_REPLY);

	if (!smb_xa_complete(xa))
		return (SDRC_NO_REPLY);

	return (smb_trans2_dispatch(sr, xa));
}

static smb_sdrc_t
smb_nt_trans_dispatch(struct smb_request *sr, struct smb_xa *xa)
{
	int rc;
	int total_bytes, n_setup, n_param, n_data;
	int param_off, param_pad, data_off, data_pad;

	n_setup = (xa->smb_msrcnt < 200) ? xa->smb_msrcnt : 200;
	n_setup++;
	n_setup = n_setup & ~0x0001;
	n_param = (xa->smb_mprcnt < smb_maxbufsize)
	    ? xa->smb_mprcnt : smb_maxbufsize;
	n_param++;
	n_param = n_param & ~0x0001;
	rc = smb_maxbufsize - (SMBHEADERSIZE + 28 + n_setup + n_param);
	n_data = (xa->smb_mdrcnt < rc) ? xa->smb_mdrcnt : rc;
	MBC_INIT(&xa->rep_setup_mb, n_setup * 2);
	MBC_INIT(&xa->rep_param_mb, n_param);
	MBC_INIT(&xa->rep_data_mb, n_data);

	switch (xa->smb_func) {
	case NT_TRANSACT_CREATE:
		if ((rc = smb_pre_nt_transact_create(sr, xa)) == 0)
			rc = smb_nt_transact_create(sr, xa);
		smb_post_nt_transact_create(sr, xa);
		break;
	case NT_TRANSACT_NOTIFY_CHANGE:
		rc = smb_nt_transact_notify_change(sr, xa);
		break;
	case NT_TRANSACT_QUERY_SECURITY_DESC:
		rc = smb_nt_transact_query_security_info(sr, xa);
		break;
	case NT_TRANSACT_SET_SECURITY_DESC:
		rc = smb_nt_transact_set_security_info(sr, xa);
		break;
	case NT_TRANSACT_IOCTL:
		rc = smb_nt_transact_ioctl(sr, xa);
		break;

	case NT_TRANSACT_QUERY_QUOTA:
		(void) smb_nt_transact_query_quota(sr, xa);
		smbsr_error(sr, 0, ERRSRV, ERRaccess);
		return (SDRC_ERROR);

	case NT_TRANSACT_SET_QUOTA:
		smbsr_error(sr, 0, ERRSRV, ERRaccess);
		return (SDRC_ERROR);

	default:
		smbsr_error(sr, 0, ERRSRV, ERRsmbcmd);
		return (SDRC_ERROR);
	}

	switch (rc) {
	case SDRC_SUCCESS:
		break;

	case SDRC_DROP_VC:
	case SDRC_NO_REPLY:
	case SDRC_ERROR:
		return (rc);

	case SDRC_NOT_IMPLEMENTED:
		smbsr_error(sr, 0, ERRSRV, ERRsmbcmd);
		return (SDRC_ERROR);

	default:
		break;
	}

	n_setup = MBC_LENGTH(&xa->rep_setup_mb);
	n_param = MBC_LENGTH(&xa->rep_param_mb);
	n_data  = MBC_LENGTH(&xa->rep_data_mb);

	if (xa->smb_msrcnt < n_setup ||
	    xa->smb_mprcnt < n_param ||
	    xa->smb_mdrcnt < n_data) {
		smbsr_error(sr, 0, ERRSRV, ERRsmbcmd);
		return (SDRC_ERROR);
	}

	/* neato, blast it over there */

	n_setup = (n_setup + 1) / 2;		/* Conver to setup words */
	param_pad = 1;				/* must be one */
	param_off = param_pad + 32 + 37 + (n_setup << 1) + 2;
	data_pad = (4 - ((param_off + n_param) & 3)) % 4; /* Pad to 4 byte */
	data_off = param_off + n_param + data_pad; /* Param off from hdr */
	total_bytes = param_pad + n_param + data_pad + n_data;

	rc = smbsr_encode_result(sr, 18+n_setup, total_bytes,
	    "b 3. llllllllb C w #. C #. C",
	    18 + n_setup,		/* wct */
	    n_param,			/* Total Parameter Bytes */
	    n_data,			/* Total Data Bytes */
	    n_param,			/* Total Parameter Bytes this buffer */
	    param_off,			/* Param offset from header start */
	    0,				/* Param displacement */
	    n_data,			/* Total Data Bytes this buffer */
	    data_off,			/* Data offset from header start */
	    0,				/* Data displacement */
	    n_setup,			/* suwcnt */
	    &xa->rep_setup_mb,		/* setup[] */
	    total_bytes,		/* Total data bytes */
	    param_pad,
	    &xa->rep_param_mb,
	    data_pad,
	    &xa->rep_data_mb);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}


/*
 * smb_nt_transact_query_quota
 *
 * There are 16 parameter bytes: fid, flags and 12 zero bytes.
 */
static smb_sdrc_t
smb_nt_transact_query_quota(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t fid;
	uint16_t flags;

	if (smb_decode_mbc(&xa->req_param_mb, "%ww", sr, &fid, &flags))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

smb_sdrc_t
smb_pre_nt_transact(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtTransact__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_nt_transact(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtTransact__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_nt_transact(struct smb_request *sr)
{
	uint16_t	Function;
	unsigned char	MaxSetupCount, SetupCount;
	uint32_t	TotalParameterCount, TotalDataCount;
	uint32_t	MaxParameterCount, MaxDataCount, pscnt;
	uint32_t	psoff, dscnt, dsoff;
	smb_xa_t *xa;
	int ready;
	int rc;

	rc = smbsr_decode_vwv(sr, SMB_NT_TRANSHDR_ED_FMT, &MaxSetupCount,
	    &TotalParameterCount, &TotalDataCount, &MaxParameterCount,
	    &MaxDataCount, &pscnt, &psoff, &dscnt,
	    &dsoff, &SetupCount, &Function);

	if (rc != 0)
		return (SDRC_ERROR);

	xa = smb_xa_create(sr->session, sr, TotalParameterCount, TotalDataCount,
	    MaxParameterCount, MaxDataCount, MaxSetupCount, SetupCount);
	if (xa == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRnoroom);
		return (SDRC_ERROR);
	}

	xa->smb_flags  = 0;
	xa->smb_timeout = 0;
	xa->smb_func = Function;
	xa->req_disp_param = pscnt;
	xa->req_disp_data  = dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_setup_mb, &sr->smb_vwv,
	    sr->smb_vwv.chain_offset, SetupCount * 2)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	ready = smb_trans_ready(xa);

	if (smb_xa_open(xa)) {
		smb_xa_rele(sr->session, xa);
		smbsr_error(sr, 0, ERRDOS, ERRsrverror);
		return (SDRC_ERROR);
	}
	sr->r_xa = xa;

	if (!ready) {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if (!smb_xa_complete(xa)) {
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}

	return (smb_nt_trans_dispatch(sr, xa));
}

smb_sdrc_t
smb_pre_nt_transact_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtTransactSecondary__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_nt_transact_secondary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtTransactSecondary__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_nt_transact_secondary(struct smb_request *sr)
{
	uint16_t tpscnt, tdscnt, fid;
	uint16_t pscnt, psoff, psdisp, dscnt, dsoff, dsdisp;
	smb_xa_t *xa;
	int rc;

	if ((xa = smbsr_lookup_xa(sr)) == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRsrverror);
		return (SDRC_ERROR);
	}

	if (sr->session->signing.flags & SMB_SIGNING_ENABLED) {
		if (smb_sign_check_secondary(sr, xa->reply_seqnum) != 0) {
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRDOS, ERRnoaccess);
			return (SDRC_ERROR);
		}
	}

	if (xa->smb_com != SMB_COM_TRANSACTION2) {
		return (SDRC_DROP_VC);
	}

	rc = smbsr_decode_vwv(sr, SMB_TRANS2SHDR_ED_FMT, &tpscnt, &tdscnt,
	    &pscnt, &psoff, &psdisp, &dscnt, &dsoff, &dsdisp, &fid);

	if (rc != 0)
		return (SDRC_ERROR);

	mutex_enter(&xa->xa_mutex);
	xa->smb_tpscnt = tpscnt;	/* might have shrunk */
	xa->smb_tdscnt = tdscnt;	/* might have shrunk */
	xa->xa_smb_fid = fid;		/* overwrite rules? */
	xa->req_disp_param = psdisp+pscnt;
	xa->req_disp_data  = dsdisp+dscnt;

	if (MBC_SHADOW_CHAIN(&xa->req_param_mb, &sr->command, psoff, pscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	if (MBC_SHADOW_CHAIN(&xa->req_data_mb, &sr->command, dsoff, dscnt)) {
		mutex_exit(&xa->xa_mutex);
		smb_xa_close(xa);
		smbsr_error(sr, 0, ERRDOS, ERRbadformat);
		return (SDRC_ERROR);
	}
	mutex_exit(&xa->xa_mutex);

	if (!smb_trans_ready(xa))
		return (SDRC_NO_REPLY);

	if (!smb_xa_complete(xa))
		return (SDRC_NO_REPLY);

	return (smb_nt_trans_dispatch(sr, xa));
}

static int
smb_trans_ready(struct smb_xa *xa)
{
	int rc;

	mutex_enter(&xa->xa_mutex);
	rc = xa->req_disp_data >= xa->smb_tdscnt &&
	    xa->req_disp_param >= xa->smb_tpscnt;
	mutex_exit(&xa->xa_mutex);

	return (rc);
}


/*
 * smb_emit_SHARE_INFO_0
 *
 * This function will convert unicode chars to oem chars before
 * and store the result in a fixed length, MAX_SHARE_NAME_LEN, buffer. If the
 * length after conversion is longer than 12, -1 will be reported
 * to indicate an error. The fixed length is a limitation of the
 * smb protocol.
 */
static int
smb_emit_SHARE_INFO_0(struct mbuf_chain *output, unsigned char *name)
{
	unsigned int cpid = oem_get_smb_cpid();
	unsigned int length;
	char name_buf[MAX_SHARE_NAME_LEN];
	mts_wchar_t *unibuf;
	char *tmpbuf;
	int rc = 0;

	tmpbuf = (name == NULL) ? "" : (char *)name;
	length = strlen(tmpbuf) + 1;

	unibuf = kmem_alloc(length * sizeof (mts_wchar_t), KM_SLEEP);
	(void) mts_mbstowcs(unibuf, tmpbuf, length);

	tmpbuf = kmem_alloc(length, KM_SLEEP);
	if (unicodestooems(tmpbuf, unibuf, length, cpid) == 0)
		(void) strcpy(tmpbuf, (char *)name);

	if (strlen(tmpbuf) + 1 <= MAX_SHARE_NAME_LEN) {
		bzero(name_buf, sizeof (name_buf));
		(void) strcpy(name_buf, tmpbuf);
		(void) smb_encode_mbc(output, "13c", name_buf);
	} else {
		rc = -1;
	}

	kmem_free(unibuf, length * sizeof (mts_wchar_t));
	kmem_free(tmpbuf, length);

	return (rc);
}

static int
smb_emit_SHARE_INFO_1(struct mbuf_chain *output, struct mbuf_chain *text,
    unsigned char *name, uint16_t type,
    unsigned char *comment)
{
	if (smb_emit_SHARE_INFO_0(output, name) < 0)
		return (-1);

	(void) smb_encode_mbc(output, ".wl", type, MBC_LENGTH(text));
	(void) smb_encode_mbc(text, "s",
	    (comment ? comment : (unsigned char *)"No comment"));
	return (0);
}

static void /*ARGSUSED*/
smb_emit_SHARE_INFO_2(struct mbuf_chain *output, struct mbuf_chain *text,
	struct smb_request *sr, unsigned char *name, uint16_t type,
	unsigned char *comment, uint16_t access, char *path, char *password)
{
	unsigned char	pword[9];

	/*
	 * XXX PGD.  Is there a bug here?  We zero pword, copy password
	 * into pword then ignore it and use password for smb_encode_mbc?
	 */
	bzero(pword, sizeof (pword));
	(void) strncpy((char *)pword, password, sizeof (pword));
	(void) smb_emit_SHARE_INFO_1(output, text, name, type, comment);
	(void) smb_encode_mbc(output, "wwwl9c.",
	    access,
	    sr->sr_cfg->skc_maxconnections,
	    smb_server_get_session_count(),
	    MBC_LENGTH(text),
	    password);
	(void) smb_encode_mbc(text, "s", path);
}

/*
 * is_long_sharename
 *
 * This function is extracted from smb_emit_SHARE_INFO_0 only for
 * finding shares that their names are longer than MAX_SHARE_NAME_LEN.
 *
 * The function returns 1 for long share names and 0 when the length
 * is Ok.
 */
static boolean_t
is_long_sharename(unsigned char *name)
{
	unsigned int cpid = oem_get_smb_cpid();
	size_t length;
	mts_wchar_t *unibuf;
	char *tmpbuf;
	boolean_t islong;

	tmpbuf = (name == NULL) ? "" : (char *)name;
	length = strlen(tmpbuf) + 1;

	unibuf = kmem_alloc(length * sizeof (mts_wchar_t), KM_SLEEP);
	(void) mts_mbstowcs(unibuf, tmpbuf, length);

	tmpbuf = kmem_alloc(length, KM_SLEEP);
	if (unicodestooems(tmpbuf, unibuf, length, cpid) == 0)
		(void) strcpy(tmpbuf, (char *)name);

	islong = (strlen(tmpbuf) + 1 > MAX_SHARE_NAME_LEN);

	kmem_free(unibuf, length * sizeof (mts_wchar_t));
	kmem_free(tmpbuf, length);

	return (islong);
}

/*
 * This structure holds information about shares which will
 * fit in the specified client buffer size.
 *
 * sei_bufsize: Client specified buffer size
 * sei_count: Maximum number of shares that can be
 *            sent in the buffer.
 *
 * The return data section consists of a number of SHARE_INFO_1 structures.
 * In case there are multiple SHARE_INFO_1 data structures to return this
 * function put all fixed length part of these structures in the return buffer
 * and then put all the variable length data (shares' comment) at the end of
 * buffer.
 *
 * sei_info_len: Size of fixed length part of SHARE_INFO_1
 *               structures for sei_count shares
 * sei_cmnt_len: Size of comments for sei_count shares
 */
typedef struct {
	uint16_t sei_bufsize;
	short sei_count;
	int   sei_infolen;
	int   sei_cmntlen;
} smb_share_enum_t;

/*
 * smb_share_update_info
 *
 * Check to see if the given buffer has enough
 * room to fit the information of the given share.
 * If there is enough room update the passed max_???
 * information.
 *
 * Return 1 if buffer is not full yet, 0 if it's full.
 */
static int
smb_share_update_info(door_handle_t dhdl, lmshare_info_t *si,
    smb_share_enum_t *shr_enum_info)
{
	int cmnt_len;
	int new_info_len = shr_enum_info->sei_infolen;
	int new_cmnt_len = shr_enum_info->sei_cmntlen;

	if (lmshrd_is_special(dhdl, si->share_name))
		cmnt_len = 1;
	else
		cmnt_len = (strlen(si->comment) + 1);

	new_info_len += SHARE_INFO_1_SIZE;
	new_cmnt_len += cmnt_len;

	if ((new_info_len + new_cmnt_len) < shr_enum_info->sei_bufsize) {
		shr_enum_info->sei_count++;
		shr_enum_info->sei_infolen = new_info_len;
		shr_enum_info->sei_cmntlen = new_cmnt_len;
		return (1);
	}

	return (0);
}

/*
 * smb_share_skip_share
 *
 * Determines whether the given share should be enumerated
 * or not. The share will not be enumerated if its name is
 * long or it's autohome share.
 *
 * Return 1 if the share should be skipped; otherwise returns
 * 0
 */
static int
smb_share_skip_share(lmshare_info_t *si)
{
	if (is_long_sharename((unsigned char *)si->share_name)) {
		return (1);
	}

	/* Skip autohome share if autohome filter is enabled */
	if (si->mode == LMSHRM_TRANS) {
		return (1);
	}

	return (0);
}

/*
 * smb_share_add_autohome
 *
 * Determines if an autohome share should be added to shares' list
 * for the given user.
 * Autohome will be add when all the following conditions are true:
 *
 *  1. Autohome feature is enabled
 *  2. A share with the same name as the given user exists
 *  3. The share is not a permanent share
 *  4. Share name is not longer than maximum allowed
 */
static int
smb_share_add_autohome(door_handle_t dhdl, char *username, lmshare_info_t *si)
{
	int do_add = 0;

	do_add = (lmshrd_getinfo(dhdl, username, si) == NERR_Success) &&
	    (si->mode & LMSHRM_TRANS) &&
	    (!is_long_sharename((unsigned char *)(si->share_name)));

	return (do_add);
}

/*
 * smb_share_total_info
 *
 * This function calculates following informations
 *	- Maximum number of shares that can be sent for clients
 *	  according to its buffer size (cli_bufsize)
 *	- length of fixed information about above shares
 *	- length of comments of above shares
 *	- total number of shares that their names are no longer
 *	  than MAX_SHARE_NAME_LEN.
 *
 * Added SMB user object to the parameter list to filter out other
 * user autohome shares.
 */
static void
smb_share_total_info(door_handle_t dhdl, smb_share_enum_t *shr_enum_info,
    short *tot_shares_num, smb_user_t *user)
{
	uint64_t iterator;
	lmshare_info_t *si;
	struct lmshare_info *auto_si;
	int more_room = 1;

	si = kmem_zalloc(sizeof (lmshare_info_t), KM_SLEEP);
	auto_si = kmem_zalloc(sizeof (struct lmshare_info), KM_SLEEP);

	*tot_shares_num = 0;
	shr_enum_info->sei_count = 0;
	shr_enum_info->sei_infolen = 0;
	shr_enum_info->sei_cmntlen = 0;

	if (smb_share_add_autohome(dhdl, user->u_name, auto_si)) {
		(*tot_shares_num)++;
		more_room = smb_share_update_info(dhdl, auto_si, shr_enum_info);
	}

	iterator = lmshrd_open_iterator(dhdl, LMSHRM_ALL);
	if (iterator == 0) {
		kmem_free(si, sizeof (lmshare_info_t));
		kmem_free(auto_si, sizeof (struct lmshare_info));
		return;
	}

	/* check for door errors */
	if (lmshrd_iterate(dhdl, iterator, si) != NERR_Success) {
		(void) lmshrd_close_iterator(dhdl, iterator);
		kmem_free(si, sizeof (lmshare_info_t));
		kmem_free(auto_si, sizeof (struct lmshare_info));
		return;
	}

	while (*si->share_name != 0) {
		if (smb_share_skip_share(si)) {
			/* check for door errors */
			if (lmshrd_iterate(dhdl, iterator, si) !=
			    NERR_Success) {
				(void) lmshrd_close_iterator(dhdl, iterator);
				kmem_free(si, sizeof (lmshare_info_t));
				kmem_free(auto_si,
				    sizeof (struct lmshare_info));
				return;
			}
			continue;
		}

		(*tot_shares_num)++;

		if (more_room) {
			more_room = smb_share_update_info(dhdl, si,
			    shr_enum_info);
		}

		/* check for door errors */
		if (lmshrd_iterate(dhdl, iterator, si) != NERR_Success) {
			(void) lmshrd_close_iterator(dhdl, iterator);
			kmem_free(si, sizeof (lmshare_info_t));
			kmem_free(auto_si, sizeof (struct lmshare_info));
			return;
		}
	}

	(void) lmshrd_close_iterator(dhdl, iterator);
	kmem_free(si, sizeof (lmshare_info_t));
	kmem_free(auto_si, sizeof (struct lmshare_info));
}

/*
 * smb_encode_SHARE_INFO_1
 *
 * This function is extracted from smb_emit_SHARE_INFO_1 and only
 * encodes fixed part of SHARE_INFO_1 structure.
 *
 * The function returns -1 if encoding fails and 0 on success.
 */
static int
smb_encode_SHARE_INFO_1(struct mbuf_chain *output, unsigned char *name,
    uint16_t type, int cmnt_len)
{
	if (smb_emit_SHARE_INFO_0(output, name) < 0)
		return (-1);
	(void) smb_encode_mbc(output, ".wl", type, cmnt_len);
	return (0);
}

/*
 * collect_shares_info
 *
 * This function encodes information of shares_num of shares
 * into data_mb and cmnt_str.
 *
 * Added SMB user object to the parameter list to filter out other
 * user autohome shares.
 *
 */
static void
collect_shares_info(door_handle_t dhdl, uint64_t iterator, int shares_num,
    struct mbuf_chain *data_mb, char *cmnt_str, int *cmnt_len, smb_user_t *user,
    int first_resp)
{
	int i = 0;
	lmshare_info_t *si;
	struct lmshare_info *tsi;
	int is_special;

	si = kmem_zalloc(sizeof (lmshare_info_t), KM_SLEEP);
	tsi = kmem_zalloc(sizeof (struct lmshare_info), KM_SLEEP);

	if (first_resp && smb_share_add_autohome(dhdl, user->u_name, tsi)) {
		if (smb_encode_SHARE_INFO_1(data_mb,
		    (unsigned char *)tsi->share_name,
		    tsi->stype, *cmnt_len) == 0) {
			(void) memcpy(cmnt_str+(*cmnt_len),
			    tsi->comment, strlen(tsi->comment)+1);
			(*cmnt_len) += (strlen(tsi->comment) + 1);
			i++;
		}
	}

	/* check for door errors */
	if (lmshrd_iterate(dhdl, iterator, si) != NERR_Success) {
		kmem_free(si, sizeof (lmshare_info_t));
		kmem_free(tsi, sizeof (struct lmshare_info));
		return;
	}

	while ((i < shares_num) && (*si->share_name != 0)) {
		if (smb_share_skip_share(si)) {
			goto next;
		}


		is_special = lmshrd_is_special(dhdl, si->share_name);
		/* check for door errors */
		if (is_special == NERR_InternalError) {
			kmem_free(si, sizeof (lmshare_info_t));
			kmem_free(tsi, sizeof (struct lmshare_info));
			return;
		}

		if (is_special) {
			si->stype |= STYPE_HIDDEN;
			if (smb_encode_SHARE_INFO_1(data_mb,
			    (unsigned char *)si->share_name,
			    si->stype, *cmnt_len) < 0) {
				goto next;
			}
			cmnt_str[*cmnt_len] = '\0';
			(*cmnt_len)++;
		} else {
			if (smb_encode_SHARE_INFO_1(data_mb,
			    (unsigned char *)si->share_name, si->stype,
			    *cmnt_len) < 0) {
				goto next;
			}
			(void) memcpy(cmnt_str+(*cmnt_len), si->comment,
			    strlen(si->comment)+1);
			(*cmnt_len) += (strlen(si->comment) + 1);
		}

	next:
		/* check for door errors */
		if (lmshrd_iterate(dhdl, iterator, si) != NERR_Success) {
			kmem_free(si, sizeof (lmshare_info_t));
			kmem_free(tsi, sizeof (struct lmshare_info));
			return;
		}
	}
	kmem_free(si, sizeof (lmshare_info_t));
	kmem_free(tsi, sizeof (struct lmshare_info));
}

int
smb_trans_net_share_enum(struct smb_request *sr, struct smb_xa *xa)
{
	door_handle_t dhdl = sr->sr_server->sv_lmshrd;
	smb_share_enum_t shr_enum_info;
	short left_shares_cnt;		/* Number of shares not sent yet */

	/*
	 * Number of shares that should be sent
	 * in the current response packet.
	 * It can be a number between 0 and
	 * max_share_scnt.
	 */
	short shares_scnt;

	/*
	 * Maximum number of shares that can be
	 * sent in one response packet regarding
	 * the maximum negotiated buffer size
	 * for SMB messages.
	 */
	short max_shares_per_packet;

	/*
	 * Total number of shares on the server
	 * that their name is not greater than
	 * MAX_SHARE_NAME_LEN
	 */
	short shares_tot_num;

	/*
	 * Size of total data (info + cmnt)
	 * that should be sent for client
	 */
	int shares_tot_byte;

	/*
	 * Maximum size of data that can be
	 * sent in one SMB transaction response
	 * according to the maximum negotiated
	 * buffer size for SMB  packets
	 */
	int data_buf_limit;

	/*
	 * Number of comment bytes that will
	 * be sent in the current response
	 */
	uint16_t cmnt_scnt;

	/*
	 * Number of data bytes that will
	 * be sent in the current response
	 */
	uint16_t data_scnt;

	/*
	 * Total number of data bytes that
	 * are sent till now. This is only
	 * used for calculating current data
	 * displacement
	 */
	uint16_t tot_data_scnt;

	/*
	 * Number of parameter bytes should
	 * be sent for the current response.
	 * It is 8 for the 1st response and
	 * 0 for others
	 */
	uint16_t param_scnt;

	/* number of setup and parameter bytes */
	uint16_t n_setup, n_param;

	/* data and parameter displacement */
	uint16_t data_disp, param_disp;

	/* return status by the 1st reply */
	uint16_t ret_stat;

	/* parameter and data offset and pad */
	int param_off, param_pad, data_off, data_pad;

	/*
	 * total bytes of parameters and data
	 * in the packet, plus the pad bytes.
	 */
	int tot_packet_bytes;

	char first_resp;
	uint16_t opcode, level, cli_bufsize;
	unsigned char *r_fmt;
	char fmt[10];
	uint64_t iterator;
	char *cmnt_str, *cmnt_start;
	int cmnt_len;
	struct mbuf_chain reply;
	smb_user_t *user;
	size_t cmnt_size;

	user = sr->uid_user;
	ASSERT(user);

	/*
	 * Initialize the mbuf chain of reply to zero. If it is not
	 * zero, code inside the while loop will try to free the chain.
	 */
	bzero(&reply, sizeof (struct mbuf_chain));

	if (smb_decode_mbc(&xa->req_param_mb, "%wss(lev)w(size)w", sr,
	    &opcode, &r_fmt, &r_fmt, &level, &cli_bufsize) != 0)
		return (SDRC_NOT_IMPLEMENTED);

	if (level != 1) {
		(void) smb_encode_mbc(&xa->rep_param_mb, "wwww",
		    NERR_BadTransactConfig, 0, 0, 0);
		return (SDRC_SUCCESS);
	}

	n_setup = 0;	/* Setup count for NetShareEnum SMB is 0 */
	n_param = 8;
	data_buf_limit = sr->session->smb_msg_size -
	    (SMB_HEADER_ED_LEN + RESP_HEADER_LEN + n_param);

	shr_enum_info.sei_bufsize = cli_bufsize;
	smb_share_total_info(dhdl, &shr_enum_info, &shares_tot_num, user);

	shares_tot_byte = shr_enum_info.sei_infolen + shr_enum_info.sei_cmntlen;

	/* Check buffer to have enough space */
	if (shares_tot_byte == 0) {
		(void) smb_encode_mbc(&xa->rep_param_mb, "wwww",
		    ERROR_NOT_ENOUGH_MEMORY, 0, 0, 0);
		return (SDRC_SUCCESS);
	}

	max_shares_per_packet = data_buf_limit / SHARE_INFO_1_SIZE;

	shares_scnt = (shr_enum_info.sei_count > max_shares_per_packet)
	    ? max_shares_per_packet : shr_enum_info.sei_count;

	cmnt_size = shr_enum_info.sei_cmntlen * sizeof (char);
	cmnt_str = kmem_alloc(cmnt_size, KM_SLEEP);
	cmnt_len = 0;
	/* save start of buffer to free it at the end of function */
	cmnt_start = cmnt_str;

	iterator = lmshrd_open_iterator(dhdl, LMSHRM_ALL);

	if (iterator == NULL) {
		kmem_free(cmnt_start, cmnt_size);
		return (SDRC_DROP_VC);
	}

	/*
	 * The rep_setup_mb is already initialized in smb_trans_dispatch().
	 * Calling MBC_INIT() will initialized the structure and so the
	 * pointer to the mbuf chains will be lost. Therefore, we need
	 * to free the resources before calling MBC_INIT() again.
	 */
	m_freem(xa->rep_setup_mb.chain);
	MBC_INIT(&xa->rep_setup_mb, n_setup * 2);

	left_shares_cnt = shr_enum_info.sei_count;
	tot_data_scnt = 0;
	cmnt_scnt = 0;

	first_resp = 1;
	while (tot_data_scnt < shares_tot_byte) {
		/*
		 * Calling MBC_INIT() will initialized the structure and so the
		 * pointer to the mbuf chains will be lost. Therefore, we need
		 * to free the resources if any before calling MBC_INIT().
		 */
		m_freem(xa->rep_data_mb.chain);
		MBC_INIT(&xa->rep_data_mb, data_buf_limit);
		collect_shares_info(dhdl, iterator,
		    shares_scnt, &xa->rep_data_mb, cmnt_str, &cmnt_len, user,
		    first_resp);
		data_scnt = shares_scnt * SHARE_INFO_1_SIZE;
		left_shares_cnt -= shares_scnt;
		if (left_shares_cnt < max_shares_per_packet)
			shares_scnt = left_shares_cnt;
		if (left_shares_cnt == 0) {
			/*
			 * Now send comments.
			 * Append comments to the end of share_info_1
			 * structures.
			 */
			cmnt_scnt = data_buf_limit -
			    MBC_LENGTH(&xa->rep_data_mb);
			if (cmnt_scnt > shr_enum_info.sei_cmntlen) {
				/*LINTED E_ASSIGN_NARROW_CONV*/
				cmnt_scnt = shr_enum_info.sei_cmntlen;
			}
			(void) sprintf(fmt, "%dc", cmnt_scnt);
			(void) smb_encode_mbc(&xa->rep_data_mb, fmt, cmnt_str);
			cmnt_str += cmnt_scnt;
			shr_enum_info.sei_cmntlen -= cmnt_scnt;
		}
		data_scnt += cmnt_scnt;
		tot_data_scnt += data_scnt;

		/* Only the 1st response packet contains parameters */
		param_scnt = (first_resp) ? n_param : 0;
		param_pad = 1;				/* always one */
		param_off = SMB_HEADER_ED_LEN + RESP_HEADER_LEN;
		param_disp = (first_resp) ? 0 : n_param;

		/*
		 * Calling MBC_INIT() will initialized the structure and so the
		 * pointer to the mbuf chains will be lost. Therefore, we need
		 * to free the resources if any before calling MBC_INIT().
		 */
		m_freem(xa->rep_param_mb.chain);
		MBC_INIT(&xa->rep_param_mb, param_scnt);
		if (first_resp) {
			first_resp = 0;
			/* Prepare parameters for the 1st response packet */
			ret_stat = (shares_tot_num > shr_enum_info.sei_count)
			    ? ERROR_MORE_DATA : 0;
			(void) smb_encode_mbc(&xa->rep_param_mb, "wwww",
			    ret_stat, -shr_enum_info.sei_infolen,
			    shr_enum_info.sei_count,
			    shares_tot_num);
		}

		data_pad = (param_off + n_param) & 1;	/* Pad to short */

		/* data off from hdr start */
		data_off = param_off + param_scnt + data_pad;
		data_disp = tot_data_scnt - data_scnt;
		tot_packet_bytes = param_pad + param_scnt + data_pad +
		    data_scnt;

		/*
		 * Calling MBC_INIT() will initialized the structure and so the
		 * pointer to the mbuf chains will be lost. Therefore, we need
		 * to free the resources if any before calling MBC_INIT().
		 */
		m_freem(reply.chain);
		MBC_INIT(&reply, SMB_HEADER_ED_LEN
		    + sizeof (uchar_t)		/* word parameters count */
		    + 10*sizeof (ushort_t)	/* word parameters */
		    + n_setup*sizeof (ushort_t)	/* setup parameters */
		    + sizeof (ushort_t)		/* total data byte count */
		    + tot_packet_bytes);

		(void) smb_encode_mbc(&reply, SMB_HEADER_ED_FMT,
		    sr->first_smb_com,
		    sr->smb_rcls,
		    sr->smb_reh,
		    sr->smb_err,
		    sr->smb_flg | SMB_FLAGS_REPLY,
		    sr->smb_flg2,
		    sr->smb_pid_high,
		    sr->smb_sig,
		    sr->smb_tid,
		    sr->smb_pid,
		    sr->smb_uid,
		    sr->smb_mid);

		(void) smb_encode_mbc(&reply,
		    "b ww 2. www www b . C w #. C #. C",
		    10 + n_setup,	/* wct */
		    n_param,		/* Total Parameter Bytes */
		    shares_tot_byte,	/* Total Data Bytes */
		    param_scnt,		/* Total Parameter Bytes this buffer */
		    param_off,		/* Param offset from header start */
		    param_disp,		/* Param displacement */
		    data_scnt,		/* Total Data Bytes this buffer */
		    data_off,		/* Data offset from header start */
		    data_disp,		/* Data displacement */
		    n_setup,		/* suwcnt */
		    &xa->rep_setup_mb, 	/* setup[] */
		    tot_packet_bytes,	/* Total data bytes */
		    param_pad,
		    &xa->rep_param_mb,
		    data_pad,
		    &xa->rep_data_mb);

		if (sr->session->signing.flags & SMB_SIGNING_ENABLED)
			smb_sign_reply(sr, NULL);

		(void) smb_session_send(sr->session, 0, &reply);
	}

	(void) lmshrd_close_iterator(dhdl, iterator);
	kmem_free(cmnt_start, cmnt_size);
	return (SDRC_NO_REPLY);
}

int
smb_trans_net_share_get_info(smb_request_t *sr, struct smb_xa *xa)
{
	uint16_t		opcode, level, max_bytes, access;
	uint32_t		type;
	unsigned char		*req_fmt;
	unsigned char		*rep_fmt;
	struct mbuf_chain	str_mb;
	char			*share;
	char			*path;
	char			*password;
	char			*comment;
	lmshare_info_t		si;
	int			shr_found;

	if (smb_decode_mbc(&xa->req_param_mb, "%wsss(lev)w(size)w", sr,
	    &opcode, &req_fmt, &rep_fmt, &share, &level, &max_bytes) != 0)
		return (SDRC_NOT_IMPLEMENTED);

	(void) utf8_strlwr(share);
	shr_found = lmshrd_getinfo(sr->sr_server->sv_lmshrd, share, &si);
	if (strcmp(share, "ipc$") == 0) {
		type = STYPE_IPC;
		path = "";
		password = "";
		access = SHARE_ACCESS_ALL;
	} else if (shr_found) {
		path = si.directory;
		type = STYPE_DISKTREE;
		if (path[strlen(path)] == '$')
			type |= STYPE_HIDDEN;
		password = "";
		access = SHARE_ACCESS_ALL;
	} else {
		/* We have no idea what this share is... */
		(void) smb_encode_mbc(&xa->rep_param_mb, "www",
		    NERR_NetNameNotFound, 0, 0);
		return (SDRC_SUCCESS);
	}

	if (shr_found)
		comment = si.comment;
	else
		comment = "";

	password = "";

	MBC_INIT(&str_mb, max_bytes);

	switch (level) {
	case 0 :
		(void) smb_emit_SHARE_INFO_0(&xa->rep_data_mb,
		    (unsigned char *)share);
		break;

	case 1 :
		(void) smb_emit_SHARE_INFO_1(&xa->rep_data_mb, &str_mb,
		    (unsigned char *)share, type,
		    (unsigned char *)comment);
		break;

	case 2 :
		smb_emit_SHARE_INFO_2(&xa->rep_data_mb, &str_mb, sr,
		    (unsigned char *)share, type, (unsigned char *)comment,
		    access, path, password);
	default:
		m_freem(str_mb.chain);
		return (SDRC_NOT_IMPLEMENTED);
	}

	(void) smb_encode_mbc(&xa->rep_param_mb, "www", 0,
	    -MBC_LENGTH(&xa->rep_data_mb),
	    MBC_LENGTH(&xa->rep_data_mb) + MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&xa->rep_data_mb, "C", &str_mb);
	m_freem(str_mb.chain);
	return (SDRC_SUCCESS);
}

int
smb_trans_net_workstation_get_info(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t		opcode, level, max_bytes;
	unsigned char		*req_fmt;
	unsigned char		*rep_fmt;
	struct mbuf_chain	str_mb;
	char *domain;
	char *hostname;

	if ((smb_decode_mbc(&xa->req_param_mb, "%wss(lev)w(size)w", sr,
	    &opcode, &req_fmt, &rep_fmt, &level, &max_bytes) != 0) ||
	    (level != 10)) {
		(void) smb_encode_mbc(&xa->rep_param_mb, "wwww",
		    NERR_BadTransactConfig, 0, 0, 0);
		return (SDRC_SUCCESS);
	}

	domain = sr->sr_cfg->skc_resource_domain;
	hostname = sr->sr_cfg->skc_hostname;

	MBC_INIT(&str_mb, max_bytes);

	(void) smb_encode_mbc(&str_mb, "."); /* Prevent NULL pointers */

	(void) smb_encode_mbc(&xa->rep_data_mb, "l", MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&str_mb, "s", hostname);
	(void) smb_encode_mbc(&xa->rep_data_mb, "l", MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&str_mb, "s", "nobody");
	(void) smb_encode_mbc(&xa->rep_data_mb, "l", MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&str_mb, "s", domain);
	(void) smb_encode_mbc(&xa->rep_data_mb, "bbl",
	    SMB_VERSION_MAJOR, SMB_VERSION_MINOR, MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&str_mb, "s", domain);
	(void) smb_encode_mbc(&xa->rep_data_mb, "l", MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&str_mb, "s", domain);

	(void) smb_encode_mbc(&xa->rep_param_mb, "www", 0,
	    -MBC_LENGTH(&xa->rep_data_mb),
	    MBC_LENGTH(&xa->rep_data_mb) + MBC_LENGTH(&str_mb));
	(void) smb_encode_mbc(&xa->rep_data_mb, "C", &str_mb);
	m_freem(str_mb.chain);
	return (SDRC_SUCCESS);
}

int
smb_trans_net_user_get_info(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t		opcode, level, max_bytes;
	unsigned char		*req_fmt;
	unsigned char		*rep_fmt;
	unsigned char		*user;
	int rc;

	rc = smb_decode_mbc(&xa->req_param_mb, "%wssww", sr,
	    &opcode,
	    &req_fmt,
	    &rep_fmt,
	    &user,
	    &level,
	    &max_bytes);

	if (rc != 0)
		return (SDRC_NOT_IMPLEMENTED);

	(void) smb_encode_mbc(&xa->rep_param_mb, "www",
	    NERR_UserNotFound, 0, 0);
	return (SDRC_SUCCESS);
}

smb_sdrc_t
smb_trans_server_get_info(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t		opcode, level, buf_size;
	char			*req_fmt;
	char			*rep_fmt;
	char			server_name[16];
	struct mbuf_chain	str_mb;
	char *hostname;
	char *comment;

	if (smb_decode_mbc(&xa->req_param_mb, "%wssww", sr,
	    &opcode, &req_fmt, &rep_fmt, &level, &buf_size) != 0) {
		return (SDRC_ERROR);
	}

	comment = sr->sr_cfg->skc_system_comment;
	hostname = sr->sr_cfg->skc_hostname;

	MBC_INIT(&str_mb, buf_size);

	bzero(server_name, sizeof (server_name));
	(void) strncpy(server_name, hostname, sizeof (server_name));

	switch (level) {
	case 0:
		(void) smb_encode_mbc(&xa->rep_data_mb, "16c", server_name);
		break;
	case 1:
		(void) smb_encode_mbc(&str_mb, "."); /* Prevent NULL pointers */
		(void) smb_encode_mbc(&xa->rep_data_mb, "16cbbll", server_name,
		    SMB_VERSION_MAJOR, SMB_VERSION_MINOR,
		    MY_SERVER_TYPE, MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", comment);
		break;
	case 2:
		/* B16BBDzDDDWWzWWWWWWWB21BzWWWWWWWWWWWWWWWWWWWWWWz */
		(void) smb_encode_mbc(&str_mb, "."); /* Prevent NULL pointers */
					/*  B16BBDz */
		(void) smb_encode_mbc(&xa->rep_data_mb, "16cbbll", server_name,
		    SMB_VERSION_MAJOR,
		    SMB_VERSION_MINOR, MY_SERVER_TYPE, MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", comment);
		(void) smb_encode_mbc(&xa->rep_data_mb, "lllwwl",
		    (uint32_t)1,
		    (uint32_t)2,
		    (uint32_t)3,
		    (uint16_t)4,
		    (uint16_t)5,
		    MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", "str1");
		(void) smb_encode_mbc(&xa->rep_data_mb, "wwwwwww21cbl",
		    (uint16_t)6,
		    (uint16_t)7,
		    (uint16_t)8,
		    (uint16_t)9,
		    (uint16_t)10,
		    (uint16_t)11,
		    (uint16_t)12,
		    "21 byte comment       ",
		    (unsigned char)13,
		    MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", "str2");
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    "wwwwwwwwwwwwwwwwwwwwwwl",
		    (uint16_t)14,
		    (uint16_t)15,
		    (uint16_t)16,
		    (uint16_t)17,
		    (uint16_t)18,
		    (uint16_t)19,
		    (uint16_t)20,
		    (uint16_t)21,
		    (uint16_t)22,
		    (uint16_t)23,
		    (uint16_t)24,
		    (uint16_t)25,
		    (uint16_t)26,
		    (uint16_t)27,
		    (uint16_t)28,
		    (uint16_t)29,
		    (uint16_t)20,
		    (uint16_t)31,
		    (uint16_t)32,
		    (uint16_t)33,
		    (uint16_t)34,
		    (uint16_t)35,
		    MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", "str3");
		break;
	default:
		m_freem(str_mb.chain);
		return (SDRC_NOT_IMPLEMENTED);
	}

	(void) smb_encode_mbc(&xa->rep_param_mb, "www", 0,
	    -MBC_LENGTH(&xa->rep_data_mb),
	    (MBC_LENGTH(&xa->rep_data_mb)) +
	    (MBC_LENGTH(&str_mb)));
	(void) smb_encode_mbc(&xa->rep_data_mb, "C", &str_mb);
	m_freem(str_mb.chain);
	return (SDRC_SUCCESS);
}

/*
 * 6.4 The NetServerEnum2 RAP Service
 *
 * The NetServerEnum2 RAP service lists all computers of the specified type
 * or types that are visible in the specified domains. It may also
 * enumerate domains.
 *
 * The following definition uses the notation and terminology defined in
 * the CIFS Remote Administration Protocol specification, which is required
 * in order to make it well-defined. The definition is:
 *
 *     uint16_t NetServerEnum2 (
 *         uint16_t  sLevel,
 *         RCVBUF          pbBuffer,
 *         RCVBUFLEN       cbBuffer,
 *         ENTCOUNT        pcEntriesRead,
 *         uint16_t  *pcTotalAvail,
 *         uint32_t   fServerType,
 *         char            *pszDomain,
 *     );
 *
 * where:
 *
 *    sLevel specifies the level of detail (0 or 1) requested.
 *
 *    pbBuffer points to the buffer to receive the returned data. If the
 *    function is successful, the buffer contains a sequence of
 *    server_info_x structures, where x is 0 or 1, depending on the
 *    level of detail requested.
 *
 *    cbBuffer specifies the size, in bytes, of the buffer pointed to by
 *    the pbBuffer parameter.
 *
 *    pcEntriesRead points to a 16 bit variable that receives a count of
 *    the number of servers enumerated in the buffer. This count is
 *    valid only if NetServerEnum2 returns the NERR_Success or
 *    ERROR_MORE_DATA values.
 *
 *    pcTotal Avail points to a 16 bit variable that receives a count of
 *    the total number of available entries. This count is valid only if
 *    NetServerEnum2 returns the NERR_Success or ERROR_MORE_DATA values.
 *
 *     fServerType specifies the type or types of computers to enumerate.
 *     Computers that match at least one of the specified types are
 *     returned in the buffer. Possible values are defined in the request
 *     parameters section.
 *
 *    pszDomain points to a null-terminated string that contains the
 *    name of the workgroup in which to enumerate computers of the
 *    specified type or types. If the pszDomain parameter is a null
 *    string or a null pointer, servers are enumerated for the current
 *    domain of the computer.
 *
 * 6.4.1 Transaction Request Parameters section
 *
 * The Transaction request parameters section in this instance contains:
 * . The 16 bit function number for NetServerEnum2 which is 104.
 * . The parameter descriptor string which is "WrLehDz".
 * . The data descriptor string for the (returned) data which is "B16" for
 *   level detail 0 or "B16BBDz" for level detail 1.
 * . The actual parameters as described by the parameter descriptor
 *   string.
 *
 * The parameters are:
 * . A 16 bit integer with a value of 0 or 1 (corresponding to the "W" in
 *   the parameter descriptor string. This represents the level of detail
 *   the server is expected to return
 * . A 16 bit integer that contains the size of the receive buffer.
 * . A 32 bit integer that represents the type of servers the function
 *   should enumerate. The possible values may be any of the following or
 *   a combination of the following:
 *
 * SV_TYPE_WORKSTATION        0x00000001 All workstations
 * SV_TYPE_SERVER             0x00000002 All servers
 * SV_TYPE_SQLSERVER          0x00000004 Any server running with SQL
 *                                       server
 * SV_TYPE_DOMAIN_CTRL        0x00000008 Primary domain controller
 * SV_TYPE_DOMAIN_BAKCTRL     0x00000010 Backup domain controller
 * SV_TYPE_TIME_SOURCE        0x00000020 Server running the timesource
 *                                       service
 * SV_TYPE_AFP                0x00000040 Apple File Protocol servers
 * SV_TYPE_NOVELL             0x00000080 Novell servers
 * SV_TYPE_DOMAIN_MEMBER      0x00000100 Domain Member
 * SV_TYPE_PRINTQ_SERVER      0x00000200 Server sharing print queue
 * SV_TYPE_DIALIN_SERVER      0x00000400 Server running dialin service.
 * SV_TYPE_XENIX_SERVER       0x00000800 Xenix server
 * SV_TYPE_NT                 0x00001000 NT server
 * SV_TYPE_WFW                0x00002000 Server running Windows for
 *                                       Workgroups
 * SV_TYPE_SERVER_NT          0x00008000 Windows NT non DC server
 * SV_TYPE_POTENTIAL_BROWSER  0x00010000 Server that can run the browser
 *                                       service
 * SV_TYPE_BACKUP_BROWSER     0x00020000 Backup browser server
 * SV_TYPE_MASTER_BROWSER     0x00040000 Master browser server
 * SV_TYPE_DOMAIN_MASTER      0x00080000 Domain Master Browser server
 * SV_TYPE_LOCAL_LIST_ONLY    0x40000000 Enumerate only entries marked
 *                                       "local"
 * SV_TYPE_DOMAIN_ENUM        0x80000000 Enumerate Domains. The pszDomain
 *                                       parameter must be NULL.
 *
 * . A null terminated ASCII string representing the pszDomain parameter
 *   described above
 *
 * 6.4.2 Transaction Request Data section
 *
 * There is no data or auxiliary data to send as part of the request.
 *
 * 6.4.3 Transaction Response Parameters section
 *
 * The transaction response parameters section consists of:
 * . A 16 bit word indicating the return status. The possible values are:
 *
 * Code                   Value  Description
 * NERR_Success           0      No errors encountered
 * ERROR_MORE_DATA        234    Additional data is available
 * NERR_ServerNotStarted  2114   The RAP service on the remote computer
 *                               is not running
 * NERR_BadTransactConfig 2141   The server is not configured for
 *                               transactions, IPC$ is not shared
 *
 * . A 16 bit "converter" word.
 * . A 16 bit number representing the number of entries returned.
 * . A 16 bit number representing the total number of available entries.
 *   If the supplied buffer is large enough, this will equal the number of
 *   entries returned.
 *
 * 6.4.4 Transaction Response Data section
 *
 * The return data section consists of a number of SERVER_INFO_1 structures.
 * The number of such structures present is determined by the third entry
 * (described above) in the return parameters section.
 *
 * At level detail 0, the Transaction response data section contains a
 * number of SERVER_INFO_0 data structure. The number of such structures is
 * equal to the 16 bit number returned by the server in the third parameter
 * in the Transaction response parameter section. The SERVER_INFO_0 data
 * structure is defined as:
 *
 *     struct SERVER_INFO_0 {
 *         char        sv0_name[16];
 *     };
 *
 *  where:
 *
 *    sv0_name is a null-terminated string that specifies the name of a
 *    computer or domain .
 *
 * At level detail 1, the Transaction response data section contains a
 * number of SERVER_INFO_1 data structure. The number of such structures is
 * equal to the 16 bit number returned by the server in the third parameter
 * in the Transaction response parameter section. The SERVER_INFO_1 data
 * structure is defined as:
 *
 *     struct SERVER_INFO_1 {
 *         char            sv1_name[16];
 *         char            sv1_version_major;
 *         char            sv1_version_minor;
 *         uint32_t   sv1_type;
 *         char        *sv1_comment_or_master_browser;
 *     };
 *
 *    sv1_name contains a null-terminated string that specifies the name
 *    of a computer, or a domain name if SV_TYPE_DOMAIN_ENUM is set in
 *    sv1_type.
 *
 *    sv1_version_major whatever was specified in the HostAnnouncement
 *    or DomainAnnouncement frame with which the entry was registered.
 *
 *    sv1_version_minor whatever was specified in the HostAnnouncement
 *    or DomainAnnouncement frame with which the entry was registered.
 *
 *    sv1_type specifies the type of software the computer is running.
 *    The member can be one or a combination of the values defined above
 *    in the Transaction request parameters section for fServerType.
 *
 *
 *    sv1_comment_or_master_browser points to a null-terminated string. If
 *    the sv1_type indicates that the entry is for a domain, this
 *    specifies the name of server running the domain master browser;
 *    otherwise, it specifies a comment describing the server. The comment
 *    can be a null string or the pointer may be a null pointer.
 *
 *    In case there are multiple SERVER_INFO_1 data structures to
 *    return, the server may put all these fixed length structures in
 *    the return buffer, leave some space and then put all the variable
 *    length data (the actual value of the sv1_comment strings) at the
 *    end of the buffer.
 *
 * There is no auxiliary data to receive.
 */

int
smb_trans_net_server_enum2(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t opcode, level, max_bytes;
	uint32_t server_type;
	unsigned char *domain;
	struct mbuf_chain str_mb;
	char *hostname, *s;
	smb_kmod_cfg_t *si;

	if (smb_decode_mbc(&xa->req_param_mb,
	    "%w s(request format) s(reply format) wwls", sr, &opcode, &s, &s,
	    &level, &max_bytes, &server_type, &domain) != 0)
		return (SDRC_NOT_IMPLEMENTED);

	si = sr->sr_cfg;

	if (utf8_strcasecmp(si->skc_resource_domain, (char *)domain) != 0) {
		(void) smb_encode_mbc(&xa->rep_param_mb, "wwww", 0, 0, 0, 0);
		return (SDRC_SUCCESS);
	}

	if ((server_type & MY_SERVER_TYPE) == 0) {
		(void) smb_encode_mbc(&xa->rep_param_mb, "wwww", 0, 0, 0, 0);
		return (SDRC_SUCCESS);
	}

	MBC_INIT(&str_mb, max_bytes);

	hostname = si->skc_hostname;

	(void) smb_encode_mbc(&xa->rep_data_mb, "16c", hostname);
	if (level == 1) {
		(void) smb_encode_mbc(&xa->rep_data_mb, "bbll",
		    SMB_VERSION_MAJOR, SMB_VERSION_MINOR,
		    MY_SERVER_TYPE, MBC_LENGTH(&str_mb));
		(void) smb_encode_mbc(&str_mb, "s", si->skc_system_comment);
	}

	(void) smb_encode_mbc(&xa->rep_param_mb, "wwww", 0,
	    -MBC_LENGTH(&xa->rep_data_mb), 1, 1);
	(void) smb_encode_mbc(&xa->rep_data_mb, "m", str_mb.chain);
	return (SDRC_SUCCESS);
}

/*
 * is_supported_pipe
 *
 * Currently, just return 0 if the pipe is \\PIPE\repl otherwise
 * return 1.
 */
int
is_supported_pipe(char *pname)
{
	if (utf8_strcasecmp(pname, PIPE_REPL) == 0)
		return (0);

	return (1);
}

static smb_sdrc_t
smb_trans_dispatch(struct smb_request *sr, struct smb_xa *xa)
{
	int		rc, pos;
	int		total_bytes, n_setup, n_param, n_data;
	int		param_off, param_pad, data_off, data_pad;
	uint16_t	opcode;
	uint16_t	devstate;
	char		*req_fmt;
	char		*rep_fmt;
	struct vardata_block vdb;

	n_setup = (xa->smb_msrcnt < 200) ? xa->smb_msrcnt : 200;
	n_setup++;
	n_setup = n_setup & ~0x0001;
	n_param = (xa->smb_mprcnt < smb_maxbufsize)
	    ? xa->smb_mprcnt : smb_maxbufsize;
	n_param++;
	n_param = n_param & ~0x0001;
	rc = smb_maxbufsize - (SMBHEADERSIZE + 28 + n_setup + n_param);
	n_data =  (xa->smb_mdrcnt < rc) ? xa->smb_mdrcnt : rc;
	MBC_INIT(&xa->rep_setup_mb, n_setup * 2);
	MBC_INIT(&xa->rep_param_mb, n_param);
	MBC_INIT(&xa->rep_data_mb, n_data);

	if (xa->smb_suwcnt > 0 && STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		rc = smb_decode_mbc(&xa->req_setup_mb, "ww", &opcode,
		    &sr->smb_fid);
		if (rc != 0)
			goto trans_err_not_supported;
		switch (opcode) {
		case TRANS_SET_NMPIPE_STATE:
			if ((rc = smb_decode_mbc(&xa->req_param_mb, "w",
			    &devstate)) != 0)
				goto trans_err_not_supported;

			rc = SDRC_SUCCESS;
			break;

		case TRANS_TRANSACT_NMPIPE:
			sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree,
			    sr->smb_fid);
			if (sr->fid_ofile == NULL) {
				smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
				    ERRDOS, ERRbadfid);
				return (SDRC_ERROR);
			}

			rc = smb_decode_mbc(&xa->req_data_mb, "#B",
			    xa->smb_tdscnt, &vdb);
			if (rc != 0)
				goto trans_err_not_supported;

			rc = smb_rpc_transact(sr, &vdb.uio);
			break;

		case TRANS_WAIT_NMPIPE:
			if (is_supported_pipe(xa->xa_smb_trans_name) == 0) {
				smbsr_error(sr, 0, ERRDOS, ERRbadfile);
				return (SDRC_ERROR);
			}
			rc = SDRC_SUCCESS;
			break;

		default:
			goto trans_err_not_supported;
		}
	} else {
		if ((utf8_strcasecmp(xa->xa_smb_trans_name,
		    PIPE_LANMAN) != 0) &&
		    (utf8_strcasecmp(
		    xa->xa_smb_trans_name, MAILSLOT_LANMAN) != 0) &&
		    (utf8_strcasecmp(
		    xa->xa_smb_trans_name, MAILSLOT_BROWSE) != 0) &&
		    (utf8_strcasecmp(
		    xa->xa_smb_trans_name, MAILSLOT_MSBROWSE) != 0))
			goto trans_err_not_supported;

		if ((rc = smb_decode_mbc(&xa->req_param_mb, "%wss\b", sr,
		    &opcode, &req_fmt, &rep_fmt)) != 0)
			goto trans_err_not_supported;

		/* for now, only respond to the */
		switch (opcode) {
		case API_WshareEnum:
			rc = smb_trans_net_share_enum(sr, xa);
			break;

		case API_WshareGetInfo:
			rc = smb_trans_net_share_get_info(sr, xa);
			break;

		case API_WserverGetInfo:
			rc = smb_trans_server_get_info(sr, xa);
			break;

		case API_WUserGetInfo:
			rc = smb_trans_net_user_get_info(sr, xa);
			break;

		case API_WWkstaGetInfo:
			rc = smb_trans_net_workstation_get_info(sr, xa);
			break;

		case API_NetServerEnum2:
			rc = smb_trans_net_server_enum2(sr, xa);
			break;

		default:
			goto trans_err_not_supported;
		}
	}

	switch (rc) {
	case SDRC_SUCCESS:
		break;

	case SDRC_DROP_VC:
	case SDRC_NO_REPLY:
	case SDRC_ERROR:
		return (rc);

	case SDRC_NOT_IMPLEMENTED:
		goto trans_err_not_supported;

	default:
		break;
	}

	n_setup = MBC_LENGTH(&xa->rep_setup_mb);
	n_param = MBC_LENGTH(&xa->rep_param_mb);
	n_data  = MBC_LENGTH(&xa->rep_data_mb);

	if (xa->smb_msrcnt < n_setup ||
	    xa->smb_mprcnt < n_param ||
	    xa->smb_mdrcnt < n_data) {
		goto trans_err_too_small;
	}

	/* neato, blast it over there */

	n_setup = (n_setup + 1) / 2;		/* Convert to setup words */
	param_pad = 1;				/* always one */
	param_off = param_pad + 32 + 21 + (n_setup << 1) + 2;
	data_pad = (param_off + n_param) & 1;	/* Pad to short */
	/* Param off from hdr start */
	data_off = param_off + n_param + data_pad;
	total_bytes = param_pad + n_param + data_pad + n_data;

	rc = smbsr_encode_result(sr, 10+n_setup, total_bytes,
	    "b ww 2. www www b . C w #. C #. C",
	    10 + n_setup,		/* wct */
	    n_param,			/* Total Parameter Bytes */
	    n_data,			/* Total Data Bytes */
	    n_param,			/* Total Parameter Bytes this buffer */
	    param_off,			/* Param offset from header start */
	    0,				/* Param displacement */
	    n_data,			/* Total Data Bytes this buffer */
	    data_off,			/* Data offset from header start */
	    0,				/* Data displacement */
	    n_setup,			/* suwcnt */
	    &xa->rep_setup_mb, /* setup[] */
	    total_bytes,		/* Total data bytes */
	    param_pad,
	    &xa->rep_param_mb,
	    data_pad,
	    &xa->rep_data_mb);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);

trans_err_too_small:
	rc = NERR_BufTooSmall;
	goto trans_err;

trans_err_not_supported:
	rc = ERROR_NOT_SUPPORTED;
	goto trans_err;

trans_err:
	pos = MBC_LENGTH(&sr->reply) + 23;
	rc = smbsr_encode_result(sr, 10, 4, "b ww 2. www www b . w ww",
	    10,		/* wct */
	    4, 0,	/* tpscnt tdscnt */
	    4, pos, 0,	/* pscnt psoff psdisp */
	    0, 0, 0,	/* dscnt dsoff dsdisp */
	    0,		/* suwcnt */
	    4,		/* bcc */
	    rc,
	    0);		/* converter word? */
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

static smb_sdrc_t
smb_trans2_dispatch(struct smb_request *sr, struct smb_xa *xa)
{
	int		rc, pos;
	int		total_bytes, n_setup, n_param, n_data;
	int		param_off, param_pad, data_off, data_pad;
	uint16_t	opcode;
	uint16_t  nt_unknown_secret = 0x0100;
	char *fmt;

	n_setup = (xa->smb_msrcnt < 200) ? xa->smb_msrcnt : 200;
	n_setup++;
	n_setup = n_setup & ~0x0001;
	n_param = (xa->smb_mprcnt < smb_maxbufsize)
	    ? xa->smb_mprcnt : smb_maxbufsize;
	n_param++;
	n_param = n_param & ~0x0001;
	rc = smb_maxbufsize - (SMBHEADERSIZE + 28 + n_setup + n_param);
	n_data =  (xa->smb_mdrcnt < rc) ? xa->smb_mdrcnt : rc;
	MBC_INIT(&xa->rep_setup_mb, n_setup * 2);
	MBC_INIT(&xa->rep_param_mb, n_param);
	MBC_INIT(&xa->rep_data_mb, n_data);

	if (smb_decode_mbc(&xa->req_setup_mb, "w", &opcode) != 0)
		goto trans_err_not_supported;

	/*
	 * Save this for /proc to read later.
	 */
	xa->smb_func = opcode;

	/* for now, only respond to the */
	switch (opcode) {
	case TRANS2_CREATE_DIRECTORY:
		rc = smb_com_trans2_create_directory(sr, xa);
		break;

	case TRANS2_FIND_FIRST2:
		/*
		 * Should have enough room to send the response
		 * data back to client.
		 */
		if (n_data == 0) {
			smbsr_error(sr, NT_STATUS_INFO_LENGTH_MISMATCH,
			    ERRDOS, ERROR_BAD_LENGTH);
			return (SDRC_ERROR);
		}
		rc = smb_com_trans2_find_first2(sr, xa);
		break;

	case TRANS2_FIND_NEXT2:
		/*
		 * Should have enough room to send the response
		 * data back to client.
		 */
		if (n_data == 0) {
			smbsr_error(sr, NT_STATUS_INFO_LENGTH_MISMATCH,
			    ERRDOS, ERROR_BAD_LENGTH);
			return (SDRC_ERROR);
		}
		rc = smb_com_trans2_find_next2(sr, xa);
		break;

	case TRANS2_QUERY_FS_INFORMATION:
		/*
		 * Should have enough room to send the response
		 * data back to client.
		 */
		if (n_data == 0) {
			smbsr_error(sr, NT_STATUS_INFO_LENGTH_MISMATCH,
			    ERRDOS, ERROR_BAD_LENGTH);
			return (SDRC_ERROR);
		}
		rc = smb_com_trans2_query_fs_information(sr, xa);
		break;

	case TRANS2_QUERY_PATH_INFORMATION:
		/*
		 * Should have enough room to send the response
		 * data back to client.
		 */
		if (n_data == 0) {
			smbsr_error(sr, NT_STATUS_INFO_LENGTH_MISMATCH,
			    ERRDOS, ERROR_BAD_LENGTH);
			return (SDRC_ERROR);
		}
		rc = smb_com_trans2_query_path_information(sr, xa);
		break;

	case TRANS2_QUERY_FILE_INFORMATION:
		/*
		 * Should have enough room to send the response
		 * data back to client.
		 */
		if (n_data == 0) {
			smbsr_error(sr, NT_STATUS_INFO_LENGTH_MISMATCH,
			    ERRDOS, ERROR_BAD_LENGTH);
			return (SDRC_ERROR);
		}
		rc = smb_com_trans2_query_file_information(sr, xa);
		break;

	case TRANS2_SET_PATH_INFORMATION:
		rc = smb_com_trans2_set_path_information(sr, xa);
		break;

	case TRANS2_SET_FILE_INFORMATION:
		rc = smb_com_trans2_set_file_information(sr, xa);
		break;
	default:
		goto trans_err_not_supported;
	}

	switch (rc) {
	case SDRC_SUCCESS:
		break;

	case SDRC_DROP_VC:
	case SDRC_NO_REPLY:
	case SDRC_ERROR:
		return (rc);

	case SDRC_NOT_IMPLEMENTED:
		goto trans_err_not_supported;

	default:
		break;
	}

	n_setup = MBC_LENGTH(&xa->rep_setup_mb);
	n_param = MBC_LENGTH(&xa->rep_param_mb);
	n_data  = MBC_LENGTH(&xa->rep_data_mb);

	if (xa->smb_msrcnt < n_setup ||
	    xa->smb_mprcnt < n_param ||
	    xa->smb_mdrcnt < n_data) {
		goto trans_err_too_small;
	}

	/* neato, blast it over there */

	n_setup = (n_setup + 1) / 2;		/* Conver to setup words */
	param_pad = 1;				/* must be one */
	param_off = param_pad + 32 + 21 + (n_setup << 1) + 2;

	/*
	 * Including the nt_unknown_secret value persuades netmon to
	 * display the correct data format for QueryPathInfo and
	 * QueryFileInfo.
	 */
	if (opcode == TRANS2_QUERY_FILE_INFORMATION ||
	    opcode == TRANS2_QUERY_PATH_INFORMATION) {
		data_pad = sizeof (uint16_t);
		data_off = param_off + n_param + data_pad;
		fmt = "b ww 2. www www b . C w #. C w C";
		nt_unknown_secret = 0x0100;
	}
	else
	{
		data_pad = (param_off + n_param) & 1; /* Pad to short */
		/* Param off from hdr start */
		data_off = param_off + n_param + data_pad;
		fmt = "b ww 2. www www b . C w #. C #. C";
		/*LINTED E_ASSIGN_NARROW_CONV*/
		nt_unknown_secret = data_pad;
	}

	total_bytes = param_pad + n_param + data_pad + n_data;

	rc = smbsr_encode_result(sr, 10+n_setup, total_bytes,
	    fmt,
	    10 + n_setup,		/* wct */
	    n_param,			/* Total Parameter Bytes */
	    n_data /* + data_pad */,	/* Total Data Bytes */
	    n_param,			/* Total Parameter Bytes this buffer */
	    param_off,			/* Param offset from header start */
	    0,				/* Param displacement */
	    n_data /* + data_pad */,	/* Total Data Bytes this buffer */
	    data_off,			/* Data offset from header start */
	    0,				/* Data displacement */
	    n_setup,			/* suwcnt */
	    &xa->rep_setup_mb,		/* setup[] */
	    total_bytes,		/* Total data bytes */
	    param_pad,
	    &xa->rep_param_mb,
	    nt_unknown_secret,
	    &xa->rep_data_mb);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);

trans_err_too_small:
	rc = NERR_BufTooSmall;
	goto trans_err;

trans_err_not_supported:
	rc = ERROR_NOT_SUPPORTED;
	goto trans_err;

trans_err:
	pos = MBC_LENGTH(&sr->reply) + 23;
	rc = smbsr_encode_result(sr, 10, 4, "b ww 2. www www b . w ww",
	    10,		/* wct */
	    4, 0,	/* tpscnt tdscnt */
	    4, pos, 0,	/* pscnt psoff psdisp */
	    0, 0, 0,	/* dscnt dsoff dsdisp */
	    0,		/* suwcnt */
	    4,		/* bcc */
	    rc,
	    0);		/* converter word? */
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

smb_xa_t *
smb_xa_create(
    smb_session_t	*session,
    smb_request_t	*sr,
    uint32_t		total_parameter_count,
    uint32_t		total_data_count,
    uint32_t		max_parameter_count,
    uint32_t		max_data_count,
    uint32_t		max_setup_count,
    uint32_t		setup_word_count)
{
	smb_xa_t	*xa, *nxa;
	smb_llist_t	*xlist;

	xa = MEM_ZALLOC("xa", sizeof (smb_xa_t));
	xa->xa_refcnt = 1;
	xa->smb_com = sr->smb_com;
	xa->smb_flg = sr->smb_flg;
	xa->smb_flg2 = sr->smb_flg2;
	xa->smb_tid = sr->smb_tid;
	xa->smb_pid = sr->smb_pid;
	xa->smb_uid = sr->smb_uid;
	xa->xa_smb_mid = sr->smb_mid;
	xa->reply_seqnum = sr->reply_seqnum;
	xa->smb_tpscnt = total_parameter_count;
	xa->smb_tdscnt = total_data_count;
	xa->smb_mprcnt = max_parameter_count;
	xa->smb_mdrcnt = max_data_count;
	xa->smb_msrcnt = max_setup_count;
	xa->smb_suwcnt = setup_word_count;
	xa->xa_session = session;
	xa->xa_magic = SMB_XA_MAGIC;

	/*
	 * The new xa structure is checked against the current list to see
	 * if it exists already.
	 */
	xlist = &session->s_xa_list;
	smb_llist_enter(xlist, RW_WRITER);
	nxa = smb_llist_head(xlist);
	while (nxa) {
		ASSERT(nxa->xa_magic == SMB_XA_MAGIC);
		if (nxa->xa_smb_mid == xa->xa_smb_mid &&
		    nxa->smb_pid == xa->smb_pid &&
		    !SMB_XA_CLOSED(nxa) &&
		    !(nxa->xa_flags & SMB_XA_FLAG_COMPLETE)) {
			smb_llist_exit(xlist);
			MEM_FREE("xa", xa);
			return (NULL);
		}
		nxa = smb_llist_next(xlist, nxa);
	}
	smb_llist_insert_tail(xlist, xa);
	smb_llist_exit(xlist);
	return (xa);
}

void
smb_xa_delete(smb_xa_t *xa)
{
	ASSERT(xa->xa_refcnt == 0);
	ASSERT(SMB_XA_CLOSED(xa));

	if (xa->xa_smb_trans_name)
		MEM_FREE("smb", xa->xa_smb_trans_name);

	if (xa->rep_setup_mb.chain != NULL)
		m_freem(xa->rep_setup_mb.chain);
	if (xa->rep_param_mb.chain != NULL)
		m_freem(xa->rep_param_mb.chain);
	if (xa->rep_data_mb.chain != NULL)
		m_freem(xa->rep_data_mb.chain);

	xa->xa_magic = (uint32_t)~SMB_XA_MAGIC;
	MEM_FREE("xa", xa);
}

smb_xa_t *
smb_xa_hold(smb_xa_t *xa)
{
	mutex_enter(&xa->xa_mutex);
	xa->xa_refcnt++;
	ASSERT(xa->xa_refcnt);
	mutex_exit(&xa->xa_mutex);
	return (xa);
}

void
smb_xa_rele(smb_session_t *session, smb_xa_t *xa)
{
	mutex_enter(&xa->xa_mutex);
	ASSERT(xa->xa_refcnt);
	xa->xa_refcnt--;
	if (SMB_XA_CLOSED(xa) && (xa->xa_refcnt == 0)) {
		mutex_exit(&xa->xa_mutex);
		smb_llist_enter(&session->s_xa_list, RW_WRITER);
		smb_llist_remove(&session->s_xa_list, xa);
		smb_llist_exit(&session->s_xa_list);
		smb_xa_delete(xa);
		return;
	}
	mutex_exit(&xa->xa_mutex);
}

int
smb_xa_open(smb_xa_t *xa)
{
	int rc;

	mutex_enter(&xa->xa_mutex);

	ASSERT((xa->xa_flags & SMB_XA_FLAG_OPEN) == 0);

	if ((xa->xa_flags & SMB_XA_FLAG_CLOSE) == 0) {
		xa->xa_flags |= SMB_XA_FLAG_OPEN;
		rc = 0;
	} else {
		rc = ERROR_INVALID_HANDLE;
	}

	mutex_exit(&xa->xa_mutex);

	return (rc);
}

void
smb_xa_close(smb_xa_t *xa)
{
	mutex_enter(&xa->xa_mutex);
	xa->xa_flags |= SMB_XA_FLAG_CLOSE;
	xa->xa_flags &= ~SMB_XA_FLAG_OPEN;

	if (xa->xa_refcnt == 0) {
		mutex_exit(&xa->xa_mutex);
		smb_llist_enter(&xa->xa_session->s_xa_list, RW_WRITER);
		smb_llist_remove(&xa->xa_session->s_xa_list, xa);
		smb_llist_exit(&xa->xa_session->s_xa_list);
		smb_xa_delete(xa);
		return;
	}

	mutex_exit(&xa->xa_mutex);
}

int
smb_xa_complete(smb_xa_t *xa)
{
	int rc;

	mutex_enter(&xa->xa_mutex);
	if (xa->xa_flags & (SMB_XA_FLAG_COMPLETE | SMB_XA_FLAG_CLOSE)) {
		rc = 0;
	} else {
		rc = 1;
		xa->xa_flags |= SMB_XA_FLAG_COMPLETE;
	}
	mutex_exit(&xa->xa_mutex);
	return (rc);
}

smb_xa_t *
smb_xa_find(
    smb_session_t	*session,
    uint16_t		pid,
    uint16_t		mid)
{
	smb_xa_t	*xa;
	smb_llist_t	*xlist;

	xlist = &session->s_xa_list;
	smb_llist_enter(xlist, RW_READER);
	xa = smb_llist_head(xlist);
	while (xa) {
		mutex_enter(&xa->xa_mutex);
		if (xa->xa_smb_mid == mid &&
		    xa->smb_pid == pid &&
		    !SMB_XA_CLOSED(xa) &&
		    !(xa->xa_flags & SMB_XA_FLAG_COMPLETE)) {
			xa->xa_refcnt++;
			ASSERT(xa->xa_refcnt);
			mutex_exit(&xa->xa_mutex);
			break;
		}
		mutex_exit(&xa->xa_mutex);
		xa = smb_llist_next(xlist, xa);
	}
	smb_llist_exit(xlist);
	return (xa);
}
