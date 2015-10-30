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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_token.h>

smb_sdrc_t
smb_pre_session_setup_andx(smb_request_t *sr)
{
	smb_arg_sessionsetup_t	*sinfo;
	char			*native_os;
	char			*native_lm;
	int			rc = 0;

	sinfo = smb_srm_zalloc(sr, sizeof (smb_arg_sessionsetup_t));
	sr->sr_ssetup = sinfo;

	/*
	 * Enforce the minimum word count seen in the old protocol,
	 * to make sure we have enough to decode the common stuff.
	 * Further wcnt checks below.
	 */
	if (sr->smb_wct < 10) {
		rc = -1;
		goto done;
	}

	/*
	 * Parse common part of SMB session setup.
	 * skip: vcnumber(2), sesskey(4)
	 */
	rc = smbsr_decode_vwv(sr, "b.www6.",
	    &sr->andx_com, &sr->andx_off,
	    &sinfo->ssi_maxbufsize, &sinfo->ssi_maxmpxcount);
	if (rc != 0)
		goto done;

	if (sr->session->dialect < NT_LM_0_12) {

		sinfo->ssi_type = SMB_SSNSETUP_PRE_NTLM012;
		sinfo->ssi_capabilities = 0;

		rc = smbsr_decode_vwv(sr, "w4.",
		    &sinfo->ssi_lmpwlen);
		if (rc != 0)
			goto done;

		sinfo->ssi_lmpwd = smb_srm_zalloc(sr, sinfo->ssi_lmpwlen + 1);
		rc = smbsr_decode_data(sr, "%#c", sr, sinfo->ssi_lmpwlen,
		    sinfo->ssi_lmpwd);
		if (rc != 0)
			goto done;

		sinfo->ssi_lmpwd[sinfo->ssi_lmpwlen] = 0;

		if (smbsr_decode_data(sr, "%u", sr, &sinfo->ssi_user) != 0)
			sinfo->ssi_user = "";

		if (smbsr_decode_data(sr, "%u", sr, &sinfo->ssi_domain) != 0)
			sinfo->ssi_domain = "";

		goto part2;
	}

	/*
	 * We have dialect >= NT_LM_0_12
	 */
	if (sr->smb_wct == 13) {
		/* Old style (non-extended) request. */
		sinfo->ssi_type = SMB_SSNSETUP_NTLM012_NOEXT;

		rc = smbsr_decode_vwv(sr, "ww4.l",
		    &sinfo->ssi_lmpwlen,
		    &sinfo->ssi_ntpwlen,
		    &sinfo->ssi_capabilities);
		if (rc != 0)
			goto done;

		/* paranoid: ignore cap. ext. sec. here */
		sinfo->ssi_capabilities &= ~CAP_EXTENDED_SECURITY;

		sinfo->ssi_lmpwd = smb_srm_zalloc(sr, sinfo->ssi_lmpwlen + 1);
		sinfo->ssi_ntpwd = smb_srm_zalloc(sr, sinfo->ssi_ntpwlen + 1);

		rc = smbsr_decode_data(sr, "%#c#cuu", sr,
		    sinfo->ssi_lmpwlen, sinfo->ssi_lmpwd,
		    sinfo->ssi_ntpwlen, sinfo->ssi_ntpwd,
		    &sinfo->ssi_user, &sinfo->ssi_domain);
		if (rc != 0)
			goto done;

		sinfo->ssi_lmpwd[sinfo->ssi_lmpwlen] = 0;
		sinfo->ssi_ntpwd[sinfo->ssi_ntpwlen] = 0;

		goto part2;
	}

	if (sr->smb_wct == 12) {
		/* New style (extended) request. */
		sinfo->ssi_type = SMB_SSNSETUP_NTLM012_EXTSEC;

		rc = smbsr_decode_vwv(sr, "w4.l",
		    &sinfo->ssi_iseclen,
		    &sinfo->ssi_capabilities);
		if (rc != 0)
			goto done;

		if ((sinfo->ssi_capabilities & CAP_EXTENDED_SECURITY) == 0) {
			rc = -1;
			goto done;
		}

		sinfo->ssi_isecblob = smb_srm_zalloc(sr, sinfo->ssi_iseclen);
		rc = smbsr_decode_data(sr, "%#c", sr,
		    sinfo->ssi_iseclen, sinfo->ssi_isecblob);
		if (rc != 0)
			goto done;

		goto part2;
	}

	/* Invalid message */
	rc = -1;
	goto done;

part2:
	/*
	 * Get the "Native OS" and "Native LanMan" strings.
	 * These are not critical to protocol function, so
	 * if we can't parse them, just guess "NT".
	 * These strings are free'd with the sr.
	 *
	 * In NTLM 0.12, the padding between the Native OS and Native LM
	 * is a bit strange.  On NT4.0, there is a 2 byte pad between the
	 * OS (Windows NT 1381) and LM (Windows NT 4.0).  On Windows 2000,
	 * there is no padding between the OS (Windows 2000 2195) and LM
	 * (Windows 2000 5.0). If the padding is removed from the decode
	 * string the NT4.0 LM comes out as an empty string.  So if the
	 * client's native OS is Win NT, assume extra padding.
	 */
	rc = smbsr_decode_data(sr, "%u", sr, &native_os);
	if (rc != 0 || native_os == NULL)
		sinfo->ssi_native_os = NATIVE_OS_WINNT;
	else
		sinfo->ssi_native_os = smbnative_os_value(native_os);

	if (sinfo->ssi_native_os == NATIVE_OS_WINNT)
		rc = smbsr_decode_data(sr, "%,u", sr, &native_lm);
	else
		rc = smbsr_decode_data(sr, "%u", sr, &native_lm);
	if (rc != 0 || native_lm == NULL)
		sinfo->ssi_native_lm = NATIVE_LM_NT;
	else
		sinfo->ssi_native_lm = smbnative_lm_value(native_lm);
	rc = 0;

done:
	if (rc != 0) {
		cmn_err(CE_NOTE,
		    "SmbSessonSetupX: client %s invalid request",
		    sr->session->ip_addr_str);
	}

	DTRACE_SMB_2(op__SessionSetupX__start, smb_request_t *, sr,
	    smb_arg_sessionsetup_t, sinfo);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_session_setup_andx(smb_request_t *sr)
{
	smb_arg_sessionsetup_t	*sinfo = sr->sr_ssetup;

	DTRACE_SMB_2(op__SessionSetupX__done, smb_request_t *, sr,
	    smb_arg_sessionsetup_t, sinfo);

	if (sinfo->ssi_lmpwd != NULL)
		bzero(sinfo->ssi_lmpwd, sinfo->ssi_lmpwlen);

	if (sinfo->ssi_ntpwd != NULL)
		bzero(sinfo->ssi_ntpwd, sinfo->ssi_ntpwlen);
}

/*
 *
 * NT systems use different native OS and native LanMan values dependent on
 * whether they are acting as a client or a server.  NT 4.0 server responds
 * with the following values:
 *
 *      NativeOS:       Windows NT 4.0
 *      NativeLM:       NT LAN Manager 4.0
 */
smb_sdrc_t
smb_com_session_setup_andx(smb_request_t *sr)
{
	smb_arg_sessionsetup_t	*sinfo = sr->sr_ssetup;
	uint32_t		status;
	uint16_t		action;
	int			rc;

	/*
	 * Some stuff we do only in the first in a (possible)
	 * sequence of session setup requests.
	 */
	if (sinfo->ssi_type != SMB_SSNSETUP_NTLM012_EXTSEC ||
	    sr->smb_uid == 0 || sr->smb_uid == 0xFFFF) {

		/* This is a first (or only) call */
		sr->session->smb_msg_size = sinfo->ssi_maxbufsize;
		sr->session->smb_max_mpx = sinfo->ssi_maxmpxcount;
		sr->session->capabilities = sinfo->ssi_capabilities;

		if (!smb_oplock_levelII)
			sr->session->capabilities &= ~CAP_LEVEL_II_OPLOCKS;

		sr->session->native_os = sinfo->ssi_native_os;
		sr->session->native_lm = sinfo->ssi_native_lm;
	}

	/*
	 * The "meat" of authentication happens here.
	 */
	if (sinfo->ssi_type == SMB_SSNSETUP_NTLM012_EXTSEC)
		status = smb_authenticate_ext(sr);
	else
		status = smb_authenticate_old(sr);

	switch (status) {

	case NT_STATUS_SUCCESS:
		break;

	/*
	 * This is not really an error, but tells the client
	 * it should send another session setup request.
	 */
	case NT_STATUS_MORE_PROCESSING_REQUIRED:
		smbsr_error(sr, status, 0, 0);
		break;

	case NT_STATUS_ACCESS_DENIED:
		smbsr_error(sr, status, ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);

	case NT_STATUS_TOO_MANY_SESSIONS:
		smbsr_error(sr, status, ERRSRV, ERRtoomanyuids);
		return (SDRC_ERROR);

	case NT_STATUS_NO_LOGON_SERVERS:
		smbsr_error(sr, status, ERRDOS, ERROR_NO_LOGON_SERVERS);
		return (SDRC_ERROR);

	case NT_STATUS_NETLOGON_NOT_STARTED:
		smbsr_error(sr, status, ERRDOS, ERROR_NETLOGON_NOT_STARTED);
		return (SDRC_ERROR);

	case NT_STATUS_USER_SESSION_DELETED:
		smbsr_error(sr, status, ERRSRV, ERRbaduid);
		return (SDRC_ERROR);

	case NT_STATUS_INSUFF_SERVER_RESOURCES:
		smbsr_error(sr, status, ERRSRV, ERRnoresource);
		return (SDRC_ERROR);

	case NT_STATUS_INTERNAL_ERROR:
	default:
		smbsr_error(sr, status, ERRSRV, ERRsrverror);
		return (SDRC_ERROR);
	}

	action = SMB_USER_IS_GUEST(sr->uid_user) ? 1 : 0;

	switch (sinfo->ssi_type) {

	default:
	case SMB_SSNSETUP_PRE_NTLM012:
	case SMB_SSNSETUP_NTLM012_NOEXT:

		rc = smbsr_encode_result(sr, 3, VAR_BCC, "bb.www%uuu",
		    3,
		    sr->andx_com,
		    -1,			/* andx_off */
		    action,
		    VAR_BCC,
		    sr,
		    sr->sr_cfg->skc_native_os,
		    sr->sr_cfg->skc_native_lm,
		    sr->sr_cfg->skc_nbdomain);
		break;

	case SMB_SSNSETUP_NTLM012_EXTSEC:

		rc = smbsr_encode_result(sr, 4, VAR_BCC, "bb.wwww%#cuuu",
		    4,
		    sr->andx_com,
		    -1,			/* andx_off */
		    action,
		    sinfo->ssi_oseclen,
		    VAR_BCC,
		    sr,
		    sinfo->ssi_oseclen,
		    sinfo->ssi_osecblob,
		    sr->sr_cfg->skc_native_os,
		    sr->sr_cfg->skc_native_lm,
		    sr->sr_cfg->skc_nbdomain);
		break;
	}

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
