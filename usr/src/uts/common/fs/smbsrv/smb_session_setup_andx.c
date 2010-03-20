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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_token.h>

typedef struct smb_sessionsetup_info {
	char		*ssi_user;
	char		*ssi_domain;
	char		*ssi_native_os;
	char		*ssi_native_lm;
	uint16_t	ssi_cipwlen;
	uint8_t		*ssi_cipwd;
	uint16_t	ssi_cspwlen;
	uint8_t		*ssi_cspwd;
	uint16_t	ssi_maxbufsize;
	uint16_t	ssi_maxmpxcount;
	uint16_t	ssi_vcnumber;
	uint32_t	ssi_capabilities;
	uint32_t	ssi_sesskey;
} smb_sessionsetup_info_t;

#define	SMB_AUTH_FAILED	-1
#define	SMB_AUTH_USER	0
#define	SMB_AUTH_GUEST	1

static int smb_authenticate(smb_request_t *, smb_sessionsetup_info_t *,
    smb_session_key_t **);

smb_sdrc_t
smb_pre_session_setup_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SessionSetupX__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_session_setup_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SessionSetupX__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_session_setup_andx(smb_request_t *sr)
{
	smb_sessionsetup_info_t	sinfo;
	smb_session_key_t	*session_key = NULL;
	char			ipaddr_buf[INET6_ADDRSTRLEN];
	int			native_lm;
	int			auth_res;
	int			rc;

	bzero(&sinfo, sizeof (smb_sessionsetup_info_t));

	if (sr->session->dialect >= NT_LM_0_12) {
		rc = smbsr_decode_vwv(sr, "b.wwwwlww4.l", &sr->andx_com,
		    &sr->andx_off, &sinfo.ssi_maxbufsize,
		    &sinfo.ssi_maxmpxcount, &sinfo.ssi_vcnumber,
		    &sinfo.ssi_sesskey, &sinfo.ssi_cipwlen,
		    &sinfo.ssi_cspwlen, &sinfo.ssi_capabilities);

		if (rc != 0)
			return (SDRC_ERROR);

		sinfo.ssi_cipwd = smb_srm_zalloc(sr, sinfo.ssi_cipwlen + 1);
		sinfo.ssi_cspwd = smb_srm_zalloc(sr, sinfo.ssi_cspwlen + 1);

		/*
		 * The padding between the Native OS and Native LM is a
		 * bit strange. On NT4.0, there is a 2 byte pad between
		 * the OS (Windows NT 1381) and LM (Windows NT 4.0).
		 * On Windows 2000, there is no padding between the OS
		 * (Windows 2000 2195) and LM (Windows 2000 5.0).
		 *
		 * If the padding is removed from this decode string
		 * the NT4.0 LM comes out as an empty string.
		 *
		 * So if the client's native OS is Win NT we consider
		 * the padding otherwise we don't.
		 */
		rc = smbsr_decode_data(sr, "%#c#cuuu",
		    sr,
		    sinfo.ssi_cipwlen, sinfo.ssi_cipwd,
		    sinfo.ssi_cspwlen, sinfo.ssi_cspwd,
		    &sinfo.ssi_user,
		    &sinfo.ssi_domain,
		    &sinfo.ssi_native_os);

		if (rc != 0)
			return (SDRC_ERROR);

		sinfo.ssi_cipwd[sinfo.ssi_cipwlen] = 0;
		sinfo.ssi_cspwd[sinfo.ssi_cspwlen] = 0;

		sr->session->native_os =
		    smbnative_os_value(sinfo.ssi_native_os);

		if (sr->session->native_os == NATIVE_OS_WINNT)
			rc = smbsr_decode_data(sr, "%,u", sr,
			    &sinfo.ssi_native_lm);
		else
			rc = smbsr_decode_data(sr, "%u", sr,
			    &sinfo.ssi_native_lm);

		/*
		 * If the Native Lanman cannot be determined,
		 * default to Windows NT.
		 */
		if (rc != 0 || sinfo.ssi_native_lm == NULL)
			sinfo.ssi_native_lm = "NT LAN Manager 4.0";
	} else {
		rc = smbsr_decode_vwv(sr, "b.wwwwlw4.", &sr->andx_com,
		    &sr->andx_off, &sinfo.ssi_maxbufsize,
		    &sinfo.ssi_maxmpxcount,
		    &sinfo.ssi_vcnumber, &sinfo.ssi_sesskey,
		    &sinfo.ssi_cipwlen);

		if (rc != 0)
			return (SDRC_ERROR);

		sinfo.ssi_cipwd = smb_srm_zalloc(sr, sinfo.ssi_cipwlen + 1);
		rc = smbsr_decode_data(sr, "%#c", sr, sinfo.ssi_cipwlen,
		    sinfo.ssi_cipwd);
		if (rc != 0)
			return (SDRC_ERROR);

		sinfo.ssi_cipwd[sinfo.ssi_cipwlen] = 0;

		/*
		 * Despite the CIFS/1.0 spec, the rest of this message is
		 * not always present. We need to try to get the account
		 * name and the primary domain but we don't care about the
		 * the native OS or native LanMan fields.
		 */
		if (smbsr_decode_data(sr, "%u", sr, &sinfo.ssi_user) != 0)
			sinfo.ssi_user = "";

		if (smbsr_decode_data(sr, "%u", sr, &sinfo.ssi_domain) != 0)
			sinfo.ssi_domain = "";

		sr->session->native_os = NATIVE_OS_WINNT;
		sinfo.ssi_native_lm = "NT LAN Manager 4.0";
	}

	/*
	 * If the sinfo.ssi_vcnumber is zero, we can discard any
	 * other connections associated with this client.
	 */
	sr->session->vcnumber = sinfo.ssi_vcnumber;
	if (sinfo.ssi_vcnumber == 0)
		smb_server_reconnection_check(sr->sr_server, sr->session);

	auth_res = smb_authenticate(sr, &sinfo, &session_key);
	if (auth_res == SMB_AUTH_FAILED)
		return (SDRC_ERROR);

	native_lm = smbnative_lm_value(sinfo.ssi_native_lm);
	if (native_lm == NATIVE_LM_WIN2000)
		sinfo.ssi_capabilities |= CAP_LARGE_FILES |
		    CAP_LARGE_READX | CAP_LARGE_WRITEX;

	sr->session->smb_msg_size = sinfo.ssi_maxbufsize;
	sr->session->capabilities = sinfo.ssi_capabilities;

	/*
	 * Check to see if SMB signing is enable, but if it is already turned
	 * on leave it.
	 * The first authenticated logon provides the MAC key and sequence
	 * numbers for signing all further session on the
	 * same network connection.
	 */
	if (!(sr->session->signing.flags & SMB_SIGNING_ENABLED) &&
	    (sr->session->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED) &&
	    (sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    session_key)
		smb_sign_init(sr, session_key, (char *)sinfo.ssi_cspwd,
		    sinfo.ssi_cspwlen);

	if (!(sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    (sr->sr_cfg->skc_signing_required)) {
		(void) smb_inet_ntop(&sr->session->ipaddr, ipaddr_buf,
		    SMB_IPSTRLEN(sr->session->ipaddr.a_family));
		cmn_err(CE_NOTE,
		    "SmbSessonSetupX: client %s is not capable of signing",
		    ipaddr_buf);
		smbsr_error(sr, NT_STATUS_LOGON_FAILURE,
		    ERRDOS, ERROR_LOGON_FAILURE);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_result(sr, 3, VAR_BCC, "bb.www%uuu",
	    3,
	    sr->andx_com,
	    -1,			/* andx_off */
	    (auth_res == SMB_AUTH_GUEST) ? 1 : 0,
	    VAR_BCC,
	    sr,
	    smbnative_os_str(&sr->sr_cfg->skc_version),
	    smbnative_lm_str(&sr->sr_cfg->skc_version),
	    sr->sr_cfg->skc_nbdomain);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Tries to authenticate the connected user.
 *
 * It first tries to see if the user has already been authenticated.
 * If a match is found, the user structure in the session is duplicated
 * and the function returns. Otherwise, user information is passed to
 * smbd for authentication. If smbd can authenticate the user an access
 * token structure is returned. A cred_t and user structure is created
 * based on the returned access token.
 */
static int
smb_authenticate(smb_request_t *sr, smb_sessionsetup_info_t *sinfo,
    smb_session_key_t **session_key)
{
	char		*hostname = sr->sr_cfg->skc_hostname;
	int		security = sr->sr_cfg->skc_secmode;
	smb_token_t	*usr_token = NULL;
	smb_user_t	*user = NULL;
	smb_logon_t	user_info;
	boolean_t	need_lookup = B_FALSE;
	uint32_t	privileges;
	cred_t		*cr;
	char		*buf = NULL;
	char		*p;

	bzero(&user_info, sizeof (smb_logon_t));

	if ((*sinfo->ssi_user == '\0') &&
	    (sinfo->ssi_cspwlen == 0) &&
	    (sinfo->ssi_cipwlen == 0 ||
	    (sinfo->ssi_cipwlen == 1 && *sinfo->ssi_cipwd == '\0'))) {
		user_info.lg_e_username = "anonymous";
		user_info.lg_flags |= SMB_ATF_ANON;
	} else {
		user_info.lg_e_username = sinfo->ssi_user;
	}
	user_info.lg_e_domain = sinfo->ssi_domain;

	/*
	 * Handle user@domain format.
	 *
	 * We need to extract the user and domain names but
	 * should keep the request data as is. This is important
	 * for some forms of authentication.
	 */
	if (*sinfo->ssi_domain == '\0') {
		buf = smb_mem_strdup(sinfo->ssi_user);
		if ((p = strchr(buf, '@')) != NULL) {
			*p = '\0';
			user_info.lg_e_username = buf;
			user_info.lg_e_domain = p + 1;
		}
	}

	/*
	 * See if this user has already been authenticated.
	 *
	 * If no domain name is provided we cannot determine whether
	 * this is a local or domain user when server is operating
	 * in domain mode, so lookup will be done after authentication.
	 */
	if (security == SMB_SECMODE_WORKGRP) {
		user = smb_session_dup_user(sr->session, hostname,
		    user_info.lg_e_username);
	} else if (*user_info.lg_e_domain != '\0') {
		user = smb_session_dup_user(sr->session, user_info.lg_e_domain,
		    user_info.lg_e_username);
	} else {
		need_lookup = B_TRUE;
	}

	if (user != NULL) {
		sr->user_cr = user->u_cred;
		sr->smb_uid = user->u_uid;
		sr->uid_user = user;

		smb_mem_free(buf);

		return ((user->u_flags & SMB_USER_FLAG_GUEST)
		    ? SMB_AUTH_GUEST : SMB_AUTH_USER);
	}

	user_info.lg_level = NETR_NETWORK_LOGON;
	user_info.lg_domain = sinfo->ssi_domain;
	user_info.lg_username = sinfo->ssi_user;
	user_info.lg_workstation = sr->session->workstation;
	user_info.lg_clnt_ipaddr = sr->session->ipaddr;
	user_info.lg_local_ipaddr = sr->session->local_ipaddr;
	user_info.lg_local_port = sr->session->s_local_port;
	user_info.lg_challenge_key.val = sr->session->challenge_key;
	user_info.lg_challenge_key.len = sr->session->challenge_len;
	user_info.lg_nt_password.val = sinfo->ssi_cspwd;
	user_info.lg_nt_password.len = sinfo->ssi_cspwlen;
	user_info.lg_lm_password.val = sinfo->ssi_cipwd;
	user_info.lg_lm_password.len = sinfo->ssi_cipwlen;
	user_info.lg_native_os = sr->session->native_os;
	user_info.lg_native_lm = smbnative_lm_value(sinfo->ssi_native_lm);

	DTRACE_PROBE1(smb__sessionsetup__clntinfo, smb_logon_t *,
	    &user_info);

	usr_token = smb_get_token(&user_info);

	smb_mem_free(buf);

	if (usr_token == NULL) {
		smbsr_error(sr, 0, ERRSRV, ERRbadpw);
		return (SMB_AUTH_FAILED);
	}

	if (need_lookup) {
		user = smb_session_dup_user(sr->session,
		    usr_token->tkn_domain_name, usr_token->tkn_account_name);

		if (user != NULL) {
			sr->user_cr = user->u_cred;
			sr->smb_uid = user->u_uid;
			sr->uid_user = user;

			smb_token_free(usr_token);
			return ((user->u_flags & SMB_USER_FLAG_GUEST)
			    ? SMB_AUTH_GUEST : SMB_AUTH_USER);
		}
	}

	if (usr_token->tkn_session_key) {
		*session_key = smb_srm_zalloc(sr, sizeof (smb_session_key_t));
		(void) memcpy(*session_key, usr_token->tkn_session_key,
		    sizeof (smb_session_key_t));
	}

	if ((cr = smb_cred_create(usr_token, &privileges)) != NULL) {
		user = smb_user_login(sr->session, cr,
		    usr_token->tkn_domain_name,
		    usr_token->tkn_account_name,
		    usr_token->tkn_flags,
		    privileges,
		    usr_token->tkn_audit_sid);

		smb_cred_rele(user->u_cred);
		if (user->u_privcred)
			smb_cred_rele(user->u_privcred);
	}

	smb_token_free(usr_token);

	if (user == NULL) {
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_HANDLE);
		return (SMB_AUTH_FAILED);
	}

	sr->user_cr = user->u_cred;
	sr->smb_uid = user->u_uid;
	sr->uid_user = user;

	return ((user->u_flags & SMB_USER_FLAG_GUEST)
	    ? SMB_AUTH_GUEST : SMB_AUTH_USER);
}
