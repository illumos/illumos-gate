/*
 * Copyright (c) 2011 - 2013 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <sys/note.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>

#include <smb/ntaccess.h>
#include <smb/winioctl.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb2_rq.h>

/*
 * Supported dialects.  Keep sorted by number because of how the
 * vc_maxver check below may truncate this list.
 */
#define	NDIALECTS	3
static const uint16_t smb2_dialects[NDIALECTS] = {
	SMB2_DIALECT_0210,
	SMB2_DIALECT_0300,
	SMB2_DIALECT_0302,
};

/* Optional capabilities we advertise (none yet). */
uint32_t smb2_clnt_caps =
    SMB2_CAP_LARGE_MTU |
    SMB2_CAP_ENCRYPTION;

/* How many credits to ask for during ssn. setup. */
uint16_t smb2_ss_req_credits = 64;

/*
 * Default timeout values, all in seconds.
 * Make these tunable (only via mdb for now).
 */
int smb2_timo_notice = 15;
int smb2_timo_default = 30;
int smb2_timo_logon = 45;
int smb2_timo_open = 45;
int smb2_timo_read = 45;
int smb2_timo_write = 60;
int smb2_timo_append = 90;

/*
 * This is a special handler for the odd SMB1-to-SMB2 negotiate
 * response, where an SMB1 request gets an SMB2 response.
 *
 * Unlike most parse functions here, this needs to parse both
 * the SMB2 header and the nego. response body.  Note that
 * the only "SMB2" dialect our SMB1 negotiate offered was
 * { SMB_DIALECT_SMB2_FF, "SMB 2.???"} so the only valid
 * SMB2 dialect we should get is: SMB2_DIALECT_02ff
 */
int
smb2_parse_smb1nego_resp(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	struct smb_sopt *sp = &vcp->vc_sopt;
	struct mdchain *mdp;
	uint16_t length = 0;
	int error;

	/* Get pointer to response data */
	smb_rq_getreply(rqp, &mdp);

	error = smb2_rq_parsehdr(rqp);
	if (error != 0)
		return (error);

	/*
	 * Parse SMB 2/3 Negotiate Response
	 * We are already pointing to begining of Response data
	 */

	/* Check structure size is 65 */
	md_get_uint16le(mdp, &length);
	if (length != 65)
		return (EBADRPC);

	/* Get Security Mode */
	md_get_uint16le(mdp, &sp->sv2_security_mode);

	/* Get Dialect. */
	error = md_get_uint16le(mdp, &sp->sv_proto);
	if (error != 0)
		return (error);

	/* What dialect did we get? */
	if (sp->sv_proto != SMB2_DIALECT_02ff) {
		SMBERROR("Unknown dialect 0x%x\n", sp->sv_proto);
		return (EINVAL);
	}
	/* Set our (internal) SMB1 dialect also. */
	sp->sv_proto = SMB_DIALECT_SMB2_FF;

	/*
	 * This request did not go through smb2_iod_addrq and
	 * smb2_iod_process() so the SMB2 message ID state is
	 * behind what we need it to be.  Fix that.
	 */
	vcp->vc2_next_message_id = 1;
	vcp->vc2_limit_message_id = 2;

	/*
	 * Skip parsing the rest.  We'll get a normal
	 * SMB2 negotiate next and do negotiate then.
	 */
	return (0);
}

int
smb2_smb_negotiate(struct smb_vc *vcp, struct smb_cred *scred)
{
	smb_sopt_t *sp = &vcp->vc_sopt;
	smbioc_ssn_work_t *wk = &vcp->vc_work;
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp = NULL;
	struct mdchain *mdp = NULL;
	uint16_t *ndialects_p;
	uint16_t ndialects = NDIALECTS;
	boolean_t will_sign = B_FALSE;
	uint16_t length = 0;
	uint16_t security_mode;
	uint16_t sec_buf_off;
	uint16_t sec_buf_len;
	int err, i;

	/*
	 * Compute security mode
	 */
	if (vcp->vc_vopt & SMBVOPT_SIGNING_REQUIRED) {
		security_mode = SMB2_NEGOTIATE_SIGNING_REQUIRED;
	} else {
		security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	}

	err = smb_rq_alloc(VCTOCP(vcp), SMB2_NEGOTIATE, scred, &rqp);
	if (err)
		return (err);

	/*
	 * Build the SMB2 negotiate request.
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 36);		/* Struct Size */
	ndialects_p = mb_reserve(mbp, 2);	/* Dialect Count */
	mb_put_uint16le(mbp, security_mode);
	mb_put_uint16le(mbp, 0);		/*  Reserved */
	mb_put_uint32le(mbp, smb2_clnt_caps);
	mb_put_mem(mbp, vcp->vc_cl_guid, 16, MB_MSYSTEM);
	mb_put_uint64le(mbp, 0);		/* Start Time */
	for (i = 0; i < ndialects; i++) {	/* Dialects */
		if (smb2_dialects[i] > vcp->vc_maxver)
			break;
		mb_put_uint16le(mbp, smb2_dialects[i]);
	}
	*ndialects_p = htoles(i);

	/*
	 * Do the OTW call.
	 */
	err = smb2_rq_internal(rqp, smb2_timo_default);
	if (err) {
		goto errout;
	}
	/* Should only get status success. */
	if (rqp->sr_error != NT_STATUS_SUCCESS) {
		err = ENOTSUP;
		goto errout;
	}

	/*
	 * Decode the negotiate response
	 */
	smb_rq_getreply(rqp, &mdp);

	md_get_uint16le(mdp, &length);	/* Struct size */
	if (length != 65) {
		err = EBADRPC;
		goto errout;
	}

	md_get_uint16le(mdp, &sp->sv2_security_mode);
	md_get_uint16le(mdp, &sp->sv_proto); /* dialect */
	md_get_uint16le(mdp, NULL);	/* reserved */
	md_get_mem(mdp, sp->sv2_guid, 16, MB_MSYSTEM);
	md_get_uint32le(mdp, &sp->sv2_capabilities);
	md_get_uint32le(mdp, &sp->sv2_maxtransact);
	md_get_uint32le(mdp, &sp->sv2_maxread);
	md_get_uint32le(mdp, &sp->sv2_maxwrite);
	md_get_uint64le(mdp, NULL);	/* curr_time */
	md_get_uint64le(mdp, NULL);	/* boot_time */

	/* Get Security Blob offset and length */
	md_get_uint16le(mdp, &sec_buf_off);
	err = md_get_uint16le(mdp, &sec_buf_len);
	if (err != 0)
		goto errout;
	md_get_uint32le(mdp, NULL);	/* reserved */

	/*
	 * Security buffer offset is from the beginning of SMB 2 Header
	 * Calculate how much further we have to go to get to it.
	 * Current offset is: SMB2_HDRLEN + 64
	 */
	if (sec_buf_len != 0) {
		int skip = (int)sec_buf_off - (SMB2_HDRLEN + 64);
		if (skip < 0) {
			err = EBADRPC;
			goto errout;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}

		/*
		 * Copy the security blob out to user space.
		 * Buffer addr,size in vc_auth_rbuf,rlen
		 */
		if (wk->wk_u_auth_rlen < sec_buf_len) {
			SMBSDEBUG("vc_auth_rbuf too small");
			/* Give caller required size. */
			wk->wk_u_auth_rlen = sec_buf_len;
			err = EMSGSIZE;
			goto errout;
		}
		wk->wk_u_auth_rlen = sec_buf_len;
		err = md_get_mem(mdp, wk->wk_u_auth_rbuf.lp_ptr,
		    sec_buf_len, MB_MUSER);
		if (err) {
			goto errout;
		}
	}

	/*
	 * Decoded everything.  Now decisions.
	 */

	/*
	 * Turn on signing if either Server or client requires it,
	 * except: anonymous sessions can't sign.
	 */
	if ((sp->sv2_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    (vcp->vc_vopt & SMBVOPT_SIGNING_REQUIRED))
		will_sign = B_TRUE;
	if (vcp->vc_vopt & SMBVOPT_ANONYMOUS)
		will_sign = B_FALSE;
	SMBSDEBUG("Security signatures: %d", (int)will_sign);
	if (will_sign)
		vcp->vc_flags |= SMBV_SIGNING;

	/*
	 * ToDo - too many places are looking at sv_caps, so for now
	 * set the SMB1 capabilities too.  Later we should use the
	 * sv2_capabilities for SMB 2+.
	 */
	sp->sv_caps =  (SMB_CAP_UNICODE |
			SMB_CAP_LARGE_FILES |
			SMB_CAP_STATUS32 |
			SMB_CAP_LARGE_READX |
			SMB_CAP_LARGE_WRITEX |
			SMB_CAP_EXT_SECURITY);
	if (sp->sv2_capabilities & SMB2_CAP_DFS)
		sp->sv_caps |= SMB_CAP_DFS;

	if (sp->sv_proto >= SMB2_DIALECT_0300 &&
	    (sp->sv2_capabilities & SMB2_CAP_ENCRYPTION) != 0) {
		nsmb_crypt_init_mech(vcp);
	}

	/*
	 * A few sanity checks on what we received,
	 * becuse we will send these in ssnsetup.
	 *
	 * Maximum outstanding requests (we care),
	 * and Max. VCs (we only use one).  Also,
	 * MaxBufferSize lower limit per spec.
	 */
	if (sp->sv2_maxread < 0x8000) {
		SMBSDEBUG("maxread too small\n");
		err = ENOTSUP;
		goto errout;
	}
	if (sp->sv2_maxwrite < 0x8000) {
		SMBSDEBUG("maxwrite too small\n");
		err = ENOTSUP;
		goto errout;
	}
	if (sp->sv2_maxtransact < 0x4000) {
		SMBSDEBUG("maxtransact too small\n");
		err = ENOTSUP;
		goto errout;
	}

	/* Here too, fill SMB1 fields */
	vcp->vc_rxmax = sp->sv2_maxread;
	vcp->vc_wxmax = sp->sv2_maxwrite;
	vcp->vc_txmax = sp->sv2_maxtransact;

	smb_rq_done(rqp);
	return (0);

errout:
	smb_rq_done(rqp);
	if (err == 0)
		err = EBADRPC;
	return (err);
}

int
smb2_smb_ssnsetup(struct smb_vc *vcp, struct smb_cred *scred)
{
	smbioc_ssn_work_t *wk = &vcp->vc_work;
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp = NULL;
	struct mdchain *mdp = NULL;
	char *sb;
	int err, ret;
	uint16_t sblen;
	uint16_t length = 0;
	uint16_t session_flags;
	uint16_t sec_buf_off;
	uint16_t sec_buf_len;
	uint8_t security_mode;

	/*
	 * Compute security mode
	 */
	if (vcp->vc_vopt & SMBVOPT_SIGNING_REQUIRED) {
		security_mode = SMB2_NEGOTIATE_SIGNING_REQUIRED;
	} else {
		security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	}

	sb = wk->wk_u_auth_wbuf.lp_ptr;
	sblen = (uint16_t)wk->wk_u_auth_wlen;

	err = smb_rq_alloc(VCTOCP(vcp), SMB2_SESSION_SETUP, scred, &rqp);
	if (err != 0) {
		ret = err;
		goto out;
	}

	/*
	 * Always ask for some credits. The server usually will
	 * only grant these credits once we've authenticated.
	 */
	rqp->sr2_creditsrequested = smb2_ss_req_credits;

	/*
	 * Build the SMB Session Setup request.
	 */
	smb_rq_getrequest(rqp, &mbp);

	mb_put_uint16le(mbp, 25);	/* Struct size */
	mb_put_uint8(mbp, 0);		/* VcNumber */
	mb_put_uint8(mbp, security_mode);
	mb_put_uint32le(mbp, smb2_clnt_caps);	/* Capabilities */
	mb_put_uint32le(mbp, 0);	/* Channel - always 0 */

	/*
	 * Security buffer offset and length.  Normally would use
	 * ptr = mb_reserve() and fill in later, but since only a
	 * small amount of fixed-size stuff follows (12 bytes)
	 * we can just compute the offset now.
	 */
	mb_put_uint16le(mbp, mbp->mb_count + 12);
	mb_put_uint16le(mbp, sblen);
	mb_put_uint64le(mbp, vcp->vc2_prev_session_id);
	err = mb_put_mem(mbp, sb, sblen, MB_MUSER);
	if (err != 0) {
		ret = err;
		goto out;
	}

	/*
	 * Run the request.  The return value here should be the
	 * return from this function, unless we fail decoding.
	 * Note: NT_STATUS_MORE_PROCESSING_REQUIRED is OK, and
	 * the caller expects EINPROGRESS for that case.
	 */
	ret = smb2_rq_internal(rqp, smb2_timo_logon);
	if (ret != 0)
		goto out;
	switch (rqp->sr_error) {
	case NT_STATUS_SUCCESS:
		break;
	case NT_STATUS_MORE_PROCESSING_REQUIRED:
		/* Keep going, but return... */
		ret = EINPROGRESS;
		break;
	default:
		ret = EAUTH;
		goto out;
	}

	/*
	 * After the first Session Setup Response,
	 * save the session ID.
	 */
	if (vcp->vc2_session_id == 0)
		vcp->vc2_session_id = rqp->sr2_rspsessionid;

	/*
	 * Decode the session setup response
	 */
	smb_rq_getreply(rqp, &mdp);

	md_get_uint16le(mdp, &length);	/* Struct size */
	if (length != 9) {
		ret = EBADRPC;
		goto out;
	}

	md_get_uint16le(mdp, &session_flags);
	md_get_uint16le(mdp, &sec_buf_off);
	err = md_get_uint16le(mdp, &sec_buf_len);
	if (err != 0) {
		ret = err;
		goto out;
	}

	/*
	 * Security buffer offset is from the beginning of SMB 2 Header
	 * Calculate how much further we have to go to get to it.
	 * Current offset is: SMB2_HDRLEN + 8
	 */
	if (sec_buf_len != 0) {
		int skip = (int)sec_buf_off - (SMB2_HDRLEN + 8);
		if (skip < 0) {
			ret = EBADRPC;
			goto out;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}

		/*
		 * Copy the security blob out to user space.
		 * Buffer addr,size in vc_auth_rbuf,rlen
		 */
		if (wk->wk_u_auth_rlen < sec_buf_len) {
			SMBSDEBUG("vc_auth_rbuf too small");
			/* Give caller required size. */
			wk->wk_u_auth_rlen = sec_buf_len;
			ret = EMSGSIZE;
			goto out;
		}
		wk->wk_u_auth_rlen = sec_buf_len;
		err = md_get_mem(mdp, wk->wk_u_auth_rbuf.lp_ptr,
		    sec_buf_len, MB_MUSER);
		if (err != 0) {
			ret = err;
			goto out;
		}
	}

	if (ret == 0) {
		/*
		 * Final session setup response
		 */
		vcp->vc_sopt.sv2_sessflags = session_flags;
		if ((vcp->vc_sopt.sv2_sessflags &
		    SMB2_SESSION_FLAG_ENCRYPT_DATA) != 0 &&
		    vcp->vc3_crypt_mech == NULL) {
			cmn_err(CE_NOTE, "SMB server requires encryption"
			    " but no crypto mechanism found");
			ret = ENOTSUP;
			goto out;
		}
	}

out:
	if (err != 0 && err != EINPROGRESS) {
		/* Session ID no longer valid. */
		vcp->vc2_session_id = 0;
	}
	if (rqp)
		smb_rq_done(rqp);

	return (ret);
}

int
smb2_smb_logoff(struct smb_vc *vcp, struct smb_cred *scred)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	if (vcp->vc2_session_id == 0)
		return (0);

	error = smb_rq_alloc(VCTOCP(vcp), SMB2_LOGOFF, scred, &rqp);
	if (error)
		return (error);

	/*
	 * Fill in Logoff part
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 4);	/* Struct size */
	mb_put_uint16le(mbp, 0);	/* Reserved */

	/*
	 * Run this with a relatively short timeout. (5 sec.)
	 * We don't really care about the result here.
	 * Also, don't reconnect for this, of course!
	 */
	rqp->sr_flags |= SMBR_NORECONNECT;
	error = smb2_rq_internal(rqp, 5);
	smb_rq_done(rqp);
	return (error);
}

int
smb2_smb_treeconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp;
	struct mdchain *mdp;
	char *unc_name = NULL;
	int error, unc_len;
	uint16_t plen, *plenp;
	uint16_t options = 0;
	uint_t cnt0;
	uint32_t net_stype;
	uint16_t structure_size = 0;
	uint8_t smb2stype;

	vcp = SSTOVC(ssp);

	/*
	 * Make this a "VC-level" request, so it will have
	 * rqp->sr_share == NULL, and smb_iod_sendrq()
	 * will send it with TID = SMB_TID_UNKNOWN
	 *
	 * This also serves to bypass the wait for
	 * share state changes, which this call is
	 * trying to carry out.
	 */
	error = smb_rq_alloc(VCTOCP(vcp), SMB2_TREE_CONNECT, scred, &rqp);
	if (error)
		return (error);

	/*
	 * Build the UNC name, i.e. "//server/share"
	 * but with backslashes of course.
	 * size math: three slashes, one null.
	 */
	unc_len = 4 + strlen(vcp->vc_srvname) + strlen(ssp->ss_name);
	unc_name = kmem_alloc(unc_len, KM_SLEEP);
	(void) snprintf(unc_name, unc_len, "\\\\%s\\%s",
	    vcp->vc_srvname, ssp->ss_name);
	SMBSDEBUG("unc_name: \"%s\"", unc_name);

	/*
	 * Build the request.
	 */
	mbp = &rqp->sr_rq;

	mb_put_uint16le(mbp, 9);	/* Struct size */
	mb_put_uint16le(mbp, 0);	/* Reserved */
	mb_put_uint16le(mbp, 72);	/* Path Offset */

	/*
	 * Fill in path length after we put the string, so we know
	 * the length after conversion from UTF-8 to UCS-2.
	 */
	plenp = mb_reserve(mbp, 2);
	cnt0 = mbp->mb_count;

	/* UNC resource name (without the null) */
	error = smb_put_dmem(mbp, vcp, unc_name, unc_len - 1,
	    SMB_CS_NONE, NULL);
	if (error)
		goto out;

	/* Now go back and fill in the path length. */
	plen = (uint16_t)(mbp->mb_count - cnt0);
	*plenp = htoles(plen);

	/*
	 * Run the request.
	 *
	 * Using NOINTR_RECV because we don't want to risk
	 * missing a successful tree connect response,
	 * which would "leak" Tree IDs.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb2_rq_simple(rqp);
	SMBSDEBUG("%d\n", error);
	if (error) {
		/*
		 * If we get the server name wrong, i.e. due to
		 * mis-configured name services, this will be
		 * NT_STATUS_DUPLICATE_NAME.  Log this error.
		 */
		SMBERROR("(%s) failed, status=0x%x",
		    unc_name, rqp->sr_error);
		goto out;
	}

	/*
	 * Parse the tree connect response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 16 */
	md_get_uint16le(mdp, &structure_size);
	if (structure_size != 16) {
		error = EBADRPC;
		goto out;
	}

	md_get_uint8(mdp, &smb2stype);
	md_get_uint8(mdp, NULL);	/* reserved */
	md_get_uint32le(mdp, &ssp->ss2_share_flags);
	md_get_uint32le(mdp, &ssp->ss2_share_caps);
	error = md_get_uint32le(mdp, NULL);	/* maxAccessRights */
	if (error)
		goto out;

	/*
	 * If the share requires encryption, make sure we can.
	 */
	if ((ssp->ss2_share_flags & SMB2_SHAREFLAG_ENCRYPT_DATA) != 0 &&
	    vcp->vc3_crypt_mech == NULL) {
		cmn_err(CE_NOTE, "SMB share requires encryption"
		    " but no crypto mechanism found");
		error = ENOTSUP;
		goto out;
	}

	/*
	 * Convert SMB2 share type to NetShareEnum share type
	 */
	switch (smb2stype) {
	case SMB2_SHARE_TYPE_DISK:
		net_stype = STYPE_DISKTREE;
		break;
	case SMB2_SHARE_TYPE_PIPE:
		net_stype = STYPE_IPC;
		break;
	case SMB2_SHARE_TYPE_PRINT:
		net_stype = STYPE_PRINTQ;
		break;
	default:
		net_stype = STYPE_UNKNOWN;
		break;
	}
	ssp->ss_type = net_stype;

	/*
	 * Map SMB 2/3 capabilities to SMB 1 options,
	 * for common code that looks there.
	 */
	if (ssp->ss2_share_caps & SMB2_SHARE_CAP_DFS)
		options |= SMB_SHARE_IS_IN_DFS;

	/* Update share state */
	SMB_SS_LOCK(ssp);
	ssp->ss2_tree_id = rqp->sr2_rsptreeid;
	ssp->ss_vcgenid = vcp->vc_genid;
	ssp->ss_options = options;
	ssp->ss_flags |= SMBS_CONNECTED;
	SMB_SS_UNLOCK(ssp);

out:
	if (unc_name)
		kmem_free(unc_name, unc_len);
	smb_rq_done(rqp);
	return (error);
}

int
smb2_smb_treedisconnect(struct smb_share *ssp, struct smb_cred *scred)
{
	struct smb_vc *vcp;
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	if (ssp->ss2_tree_id == SMB2_TID_UNKNOWN)
		return (0);

	/*
	 * Build this as a "VC-level" request, so it will
	 * avoid testing the _GONE flag on the share,
	 * which has already been set at this point.
	 * Add the share pointer "by hand" below, so
	 * smb_iod_sendrq will plug in the TID.
	 */
	vcp = SSTOVC(ssp);
	error = smb_rq_alloc(VCTOCP(vcp), SMB2_TREE_DISCONNECT, scred, &rqp);
	if (error)
		return (error);
	rqp->sr_share = ssp; /* See "by hand" above. */

	/*
	 * Fill in SMB2 Tree Disconnect part
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 4);	/* Struct size */
	mb_put_uint16le(mbp, 0);	/* Reserved */

	/*
	 * Run this with a relatively short timeout. (5 sec.)
	 * We don't really care about the result here, but we
	 * do need to make sure we send this out, or we could
	 * "leak" active tree IDs on interrupt or timeout.
	 * The NOINTR_SEND flag makes this request immune to
	 * interrupt or timeout until the send is done.
	 * Also, don't reconnect for this, of course!
	 */
	rqp->sr_flags |= (SMBR_NOINTR_SEND | SMBR_NORECONNECT);
	error = smb2_rq_simple_timed(rqp, 5);

	smb_rq_done(rqp);

	/* Whether we get an error or not... */
	ssp->ss2_tree_id = SMB2_TID_UNKNOWN;

	return (error);
}

/*
 * Put the name, first skipping a leading slash.
 */
static int
put_name_skip_slash(struct mbchain *mbp, struct mbchain *name_mbp)
{
	mblk_t *m;

	if (name_mbp == NULL)
		return (0);
	m = name_mbp->mb_top;
	if (m == NULL)
		return (0);

	/* Use a dup of the message to leave the passed one untouched. */
	m = dupmsg(m);
	if (m == NULL)
		return (ENOSR);

	if (MBLKL(m) >= 2 &&
	    m->b_rptr[0] == '\\' &&
	    m->b_rptr[1] == '\0')
		m->b_rptr += 2;

	return (mb_put_mbuf(mbp, m));
}

/*
 * Modern create/open of file or directory.
 *
 * The passed name is a full path relative to the share root.
 * Callers prepare paths with a leading slash (backslash)
 * because that's what SMB1 expected.  SMB2 does not allow the
 * leading slash here.  To make life simpler for callers skip a
 * leading slash here.  That allows callers use use common logic
 * for building paths without needing to know if the connection
 * is using SMB1 or SMB2 (just build paths with a leading slash).
 */
int
smb2_smb_ntcreate(
	struct smb_share *ssp,
	struct mbchain	*name_mb,
	struct mbchain	*cctx_in,
	struct mdchain	*cctx_out,
	uint32_t cr_flags,	/* create flags */
	uint32_t req_acc,	/* requested access */
	uint32_t efa,		/* ext. file attrs (DOS attr +) */
	uint32_t share_acc,
	uint32_t open_disp,	/* open disposition */
	uint32_t createopt,	/* NTCREATEX_OPTIONS_ */
	uint32_t impersonate,	/* NTCREATEX_IMPERSONATION_... */
	struct smb_cred *scrp,
	smb2fid_t *fidp,	/* returned FID */
	uint32_t *cr_act_p,	/* optional create action */
	struct smbfattr *fap)	/* optional attributes */
{
	struct smbfattr fa;
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint16_t *name_offp;
	uint16_t *name_lenp;
	uint32_t *cctx_offp;
	uint32_t *cctx_lenp;
	uint32_t rcc_off, rcc_len;
	smb2fid_t smb2_fid;
	uint64_t llongint;
	uint32_t longint, createact;
	uint_t off, len;
	int error;
	uint16_t StructSize = 57;	// [MS-SMB2]

	bzero(&fa, sizeof (fa));

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_CREATE, scrp, &rqp);
	if (error)
		return (error);

	/*
	 * Todo: Assemble creat contexts (if needed)
	 * into an mbchain.
	 */

	/*
	 * Build the SMB 2/3 Create Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, StructSize);
	mb_put_uint8(mbp, 0);				/* Security flags */
	mb_put_uint8(mbp, SMB2_OPLOCK_LEVEL_NONE);	/* Oplock level */
	mb_put_uint32le(mbp, impersonate);	/* Impersonation Level */
	mb_put_uint64le(mbp, cr_flags);
	mb_put_uint64le(mbp, 0);			/* Reserved */
	mb_put_uint32le(mbp, req_acc);
	mb_put_uint32le(mbp, efa);			/* File attributes */
	mb_put_uint32le(mbp, share_acc);		/* Share access */
	mb_put_uint32le(mbp, open_disp);		/* Create disposition */
	mb_put_uint32le(mbp, createopt);		/* Create options */

	name_offp = mb_reserve(mbp, 2);			/* Name offset */
	name_lenp = mb_reserve(mbp, 2);			/* Name len */

	cctx_offp = mb_reserve(mbp, 4);			/* Context offset */
	cctx_lenp = mb_reserve(mbp, 4);			/* Context len */

	/*
	 * Put the file name, which is provided in an mbchain.
	 * If there's a leading slash, skip it (see above).
	 */
	off = mbp->mb_count;
	*name_offp = htoles((uint16_t)off);
	error = put_name_skip_slash(mbp, name_mb);
	if (error)
		goto out;
	len = mbp->mb_count - off;
	*name_lenp = htoles((uint16_t)len);

	/*
	 * Now the create contexts (if provided)
	 */
	if (cctx_in != NULL) {
		off = mbp->mb_count;
		*cctx_offp = htolel((uint32_t)off);
		mb_put_mbchain(mbp, cctx_in);
		len = mbp->mb_count - off;
		*cctx_lenp = htolel((uint32_t)len);
	} else {
		*cctx_offp = 0;
		*cctx_lenp = 0;
	}

	/*
	 * If we didn't put any variable-sized data, we'll have
	 * put exactly 56 bytes of data, and we need to pad out
	 * this request to the 57 bytes StructSize indicated.
	 */
	if (mbp->mb_count < (StructSize + SMB2_HDRLEN))
		mb_put_uint8(mbp, 0);

	/*
	 * Don't want to risk missing a successful
	 * open response, or we could "leak" FIDs.
	 */
	rqp->sr_flags |= SMBR_NOINTR_RECV;
	error = smb2_rq_simple_timed(rqp, smb2_timo_open);
	if (error)
		goto out;

	/*
	 * Parse SMB 2/3 Create Response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 89 */
	error = md_get_uint16le(mdp, &StructSize);
	if (StructSize != 89) {
		error = EBADRPC;
		goto out;
	}

	md_get_uint8(mdp, NULL);		/* oplock lvl granted */
	md_get_uint8(mdp, NULL);		/* mbz */
	md_get_uint32le(mdp, &createact);	/* create_action */
	md_get_uint64le(mdp, &llongint);	/* creation time */
	smb_time_NT2local(llongint, &fa.fa_createtime);
	md_get_uint64le(mdp, &llongint);	/* access time */
	smb_time_NT2local(llongint, &fa.fa_atime);
	md_get_uint64le(mdp, &llongint);	/* write time */
	smb_time_NT2local(llongint, &fa.fa_mtime);
	md_get_uint64le(mdp, &llongint);	/* change time */
	smb_time_NT2local(llongint, &fa.fa_ctime);
	md_get_uint64le(mdp, &llongint);	/* allocation size */
	fa.fa_allocsz = llongint;
	md_get_uint64le(mdp, &llongint);	/* EOF position */
	fa.fa_size = llongint;
	md_get_uint32le(mdp, &longint);		/* attributes */
	fa.fa_attr = longint;
	md_get_uint32le(mdp, NULL);		/* reserved */

	/* Get SMB 2/3 File ID and create user fid to return */
	md_get_uint64le(mdp, &smb2_fid.fid_persistent);
	error = md_get_uint64le(mdp, &smb2_fid.fid_volatile);
	if (error)
		goto out;

	/* Get Context Offset */
	error = md_get_uint32le(mdp, &rcc_off);
	if (error)
		goto out;
	/* Get Context Length */
	error = md_get_uint32le(mdp, &rcc_len);
	if (error)
		goto out;

	/*
	 * If the caller wants the returned create contexts, parse.
	 * Context offset is from the beginning of SMB 2/3 Header
	 * Calculate how much further we have to go to get to it.
	 * Current offset is: SMB2_HDRLEN + 88
	 */
	if (rcc_len != 0) {
		int skip = (int)rcc_off - (SMB2_HDRLEN + 88);
		if (skip < 0) {
			error = EBADRPC;
			goto out;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}
		if (cctx_out != NULL) {
			mblk_t *m = NULL;
			error = md_get_mbuf(mdp, rcc_len, &m);
			if (error)
				goto out;
			md_initm(cctx_out, m);
		}
	}

out:
	smb_rq_done(rqp);
	if (error)
		return (error);

	*fidp = smb2_fid;
	if (cr_act_p)
		*cr_act_p = createact;
	if (fap)
		*fap = fa; /* struct copy */

	return (0);
}

int
smb2_smb_close(struct smb_share *ssp, smb2fid_t *fid, struct smb_cred *scrp)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_CLOSE, scrp, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2/3 Close Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 24);		/* Struct size */
	mb_put_uint16le(mbp, 0);		/* Flags */
	mb_put_uint32le(mbp, 0);		/* Reserved */

	mb_put_uint64le(mbp, fid->fid_persistent);
	mb_put_uint64le(mbp, fid->fid_volatile);

	/* Make sure we send, but only if already connected */
	rqp->sr_flags |= (SMBR_NOINTR_SEND | SMBR_NORECONNECT);
	error = smb2_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

int
smb2_smb_ioctl(
	struct smb_share *ssp,
	smb2fid_t *fid,
	struct mbchain	*data_in,
	struct mdchain	*data_out,
	uint32_t *data_out_sz,	/* max / returned */
	uint32_t ctl_code,
	struct smb_cred *scrp)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint32_t *data_in_offp;
	uint32_t *data_in_lenp;
	uint32_t data_out_off;
	uint32_t data_out_len;
	uint16_t length = 0;
	uint_t off, len;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_IOCTL, scrp, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2 IOCTL Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 57);		/* Struct size */
	mb_put_uint16le(mbp, 0);		/* Reserved */
	mb_put_uint32le(mbp, ctl_code);

	mb_put_uint64le(mbp, fid->fid_persistent);
	mb_put_uint64le(mbp, fid->fid_volatile);

	data_in_offp = mb_reserve(mbp, 4);
	data_in_lenp = mb_reserve(mbp, 4);
	mb_put_uint32le(mbp, 0);		/* Max input resp */

	mb_put_uint32le(mbp, 0);		/* Output offset */
	mb_put_uint32le(mbp, 0);		/* Output count */
	mb_put_uint32le(mbp, *data_out_sz);

	mb_put_uint32le(mbp, SMB2_IOCTL_IS_FSCTL); /* Flags */
	mb_put_uint32le(mbp, 0);		/* Reserved2 */

	/*
	 * Now data_in (if provided)
	 */
	if (data_in != NULL) {
		off = mbp->mb_count;
		*data_in_offp = htolel((uint32_t)off);
		mb_put_mbchain(mbp, data_in);
		len = mbp->mb_count - off;
		*data_in_lenp = htolel((uint32_t)len);
	} else {
		*data_in_offp = 0;
		*data_in_lenp = 0;
	}

	/*
	 * Run the request
	 */
	error = smb2_rq_simple_timed(rqp, smb2_timo_default);
	if (error)
		goto out;

	/*
	 * Parse SMB 2 Ioctl Response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 49 */
	md_get_uint16le(mdp, &length);
	if (length != 49) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint16le(mdp, NULL);	/* reserved */
	md_get_uint32le(mdp, NULL);	/* Get CtlCode */
	md_get_uint64le(mdp, NULL);	/* fid_persistent */
	md_get_uint64le(mdp, NULL);	/* fid_volatile */
	md_get_uint32le(mdp, NULL);	/* Get Input offset */
	md_get_uint32le(mdp, NULL);	/* Get Input count */

	error = md_get_uint32le(mdp, &data_out_off);
	if (error)
		goto out;
	error = md_get_uint32le(mdp, &data_out_len);
	if (error)
		goto out;

	md_get_uint32le(mdp, NULL);	/* Flags */
	md_get_uint32le(mdp, NULL);	/* reserved */

	/*
	 * If the caller wants the ioctl output data, parse.
	 * Current offset is: SMB2_HDRLEN + 48
	 * Always return the received length.
	 */
	*data_out_sz = data_out_len;
	if (data_out_len != 0) {
		int skip = (int)data_out_off - (SMB2_HDRLEN + 48);
		if (skip < 0) {
			error = EBADRPC;
			goto out;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}
		if (data_out != NULL) {
			mblk_t *m = NULL;
			error = md_get_mbuf(mdp, data_out_len, &m);
			if (error)
				goto out;
			md_initm(data_out, m);
		}
	}

out:
	smb_rq_done(rqp);

	return (error);
}

int
smb2_smb_read(smb_fh_t *fhp, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_share *ssp = FHTOSS(fhp);
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint64_t off64 = uiop->uio_loffset;
	uint32_t rlen;
	uint16_t length = 0;
	uint8_t data_offset;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_READ, scred, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2 Read Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 49);		/* Struct size */
	mb_put_uint16le(mbp, 0);		/* Padding and Reserved */

	mb_put_uint32le(mbp, *lenp);		/* Length of read */
	mb_put_uint64le(mbp, off64);		/* Offset */

	mb_put_uint64le(mbp, fhp->fh_fid2.fid_persistent);
	mb_put_uint64le(mbp, fhp->fh_fid2.fid_volatile);

	mb_put_uint32le(mbp, 1);	/* MinCount */
					/* (only indicates blocking) */

	mb_put_uint32le(mbp, 0);	/* Channel */
	mb_put_uint32le(mbp, 0);	/* Remaining */
	mb_put_uint32le(mbp, 0);	/* Channel offset/len */
	mb_put_uint8(mbp, 0);		/* data "blob" (pad) */

	if (timo == 0)
		timo = smb2_timo_read;
	error = smb2_rq_simple_timed(rqp, timo);
	if (error)
		goto out;

	/*
	 * Parse SMB 2 Read Response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 17 */
	md_get_uint16le(mdp, &length);
	if (length != 17) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint8(mdp, &data_offset);
	md_get_uint8(mdp, NULL);		/* reserved */

	/* Get Data Length read */
	error = md_get_uint32le(mdp, &rlen);
	if (error)
		goto out;

	md_get_uint32le(mdp, NULL);	/* Data Remaining (always 0) */
	md_get_uint32le(mdp, NULL);	/* Get Reserved2 (always 0) */

	/*
	 * Data offset is from the beginning of SMB 2/3 Header
	 * Calculate how much further we have to go to get to it.
	 */
	if (data_offset < (SMB2_HDRLEN + 16)) {
		error = EBADRPC;
		goto out;
	}
	if (data_offset > (SMB2_HDRLEN + 16)) {
		int skip = data_offset - (SMB2_HDRLEN + 16);
		md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
	}

	/*
	 * Get the data
	 */
	if (rlen == 0) {
		*lenp = rlen;
		goto out;
	}
	/* paranoid */
	if (rlen > *lenp) {
		SMBSDEBUG("bad server! rlen %d, len %d\n",
		    rlen, *lenp);
		rlen = *lenp;
	}

	error = md_get_uio(mdp, uiop, rlen);
	if (error)
		goto out;

	/* Success */
	*lenp = rlen;

out:
	smb_rq_done(rqp);
	return (error);
}

int
smb2_smb_write(smb_fh_t *fhp, uint32_t *lenp,
	uio_t *uiop, smb_cred_t *scred, int timo)
{
	struct smb_share *ssp = FHTOSS(fhp);
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;
	uint64_t off64 = uiop->uio_loffset;
	uint32_t rlen;
	uint16_t data_offset;
	uint16_t length = 0;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_WRITE, scred, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2 Write Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 49);		/* Struct size */
	data_offset = SMB2_HDRLEN + 48;
	mb_put_uint16le(mbp, data_offset);	/* Data Offset */
	mb_put_uint32le(mbp, *lenp);		/* Length of write */
	mb_put_uint64le(mbp, off64);		/* Offset */

	mb_put_uint64le(mbp, fhp->fh_fid2.fid_persistent);
	mb_put_uint64le(mbp, fhp->fh_fid2.fid_volatile);

	mb_put_uint32le(mbp, 0);		/* Channel */
	mb_put_uint32le(mbp, 0);		/* Remaining */
	mb_put_uint32le(mbp, 0);		/* Channel offset/len */
	mb_put_uint32le(mbp, 0);		/* Write flags */

	error = mb_put_uio(mbp, uiop, *lenp);
	if (error)
		goto out;

	if (timo == 0)
		timo = smb2_timo_write;
	error = smb2_rq_simple_timed(rqp, timo);
	if (error)
		goto out;

	/*
	 * Parse SMB 2/3 Write Response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 17 */
	md_get_uint16le(mdp, &length);
	if (length != 17) {
		error = EBADRPC;
		goto out;
	}

	md_get_uint16le(mdp, NULL);    /* Get Reserved */

	/* Get Data Length written */
	error = md_get_uint32le(mdp, &rlen);
	if (error)
		goto out;

	/* Get Data Remaining (always 0) */
	md_get_uint32le(mdp, NULL);

	/* Get Reserved2 (always 0) */
	md_get_uint32le(mdp, NULL);

	/* Success */
	*lenp = rlen;

out:
	smb_rq_done(rqp);
	return (error);
}

/*
 * Note: the IOD calls this, so this request must not wait for
 * connection state changes, etc. (uses smb2_rq_internal)
 */
int
smb2_smb_echo(struct smb_vc *vcp, struct smb_cred *scred, int timo)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	error = smb_rq_alloc(VCTOCP(vcp), SMB2_ECHO, scred, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2 Echo Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 4);		/* Struct size */
	mb_put_uint16le(mbp, 0);		/* Reserved */

	rqp->sr_flags |= SMBR_NORECONNECT;
	error = smb2_rq_internal(rqp, timo);

	smb_rq_done(rqp);
	return (error);
}
