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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_token.h>

static int smb_authenticate(smb_request_t *, smb_arg_sessionsetup_t *,
    smb_session_key_t **);
static int smb_authenticate_core(smb_request_t *, smb_arg_sessionsetup_t *,
    smb_session_key_t **);
static cred_t *smb_cred_create(smb_token_t *);
static void smb_cred_set_sid(smb_id_t *id, ksid_t *ksid);
static ksidlist_t *smb_cred_set_sidlist(smb_ids_t *token_grps);
static uint32_t smb_priv_xlate(smb_token_t *);

/*
 * In NTLM 0.12, the padding between the Native OS and Native LM is a bit
 * strange.  On NT4.0, there is a 2 byte pad between the OS (Windows NT 1381)
 * and LM (Windows NT 4.0).  On Windows 2000, there is no padding between
 * the OS (Windows 2000 2195) and LM (Windows 2000 5.0).
 * If the padding is removed from the decode string the NT4.0 LM comes out
 * as an empty string.  So if the client's native OS is Win NT we consider
 * the padding otherwise we don't.
 *
 * For Pre-NTLM 0.12, despite the CIFS/1.0 spec, the user and domain are
 * not always present in the message.  We try to get the account name and
 * the primary domain but we don't care about the the native OS or native
 * LM fields.
 *
 * If the Native LM cannot be determined, default to Windows NT.
 */
smb_sdrc_t
smb_pre_session_setup_andx(smb_request_t *sr)
{
	smb_arg_sessionsetup_t	*sinfo;
	char			*native_os;
	char			*native_lm;
	uint16_t		maxbufsize;
	uint16_t		vcnumber;
	int			rc = 0;

	sinfo = smb_srm_zalloc(sr, sizeof (smb_arg_sessionsetup_t));
	sr->sr_ssetup = sinfo;

	if (sr->session->dialect >= NT_LM_0_12) {
		rc = smbsr_decode_vwv(sr, "b.wwwwlww4.l", &sr->andx_com,
		    &sr->andx_off, &maxbufsize,
		    &sinfo->ssi_maxmpxcount, &vcnumber,
		    &sinfo->ssi_sesskey, &sinfo->ssi_cipwlen,
		    &sinfo->ssi_cspwlen, &sinfo->ssi_capabilities);
		if (rc != 0)
			goto pre_session_setup_andx_done;

		sinfo->ssi_cipwd = smb_srm_zalloc(sr, sinfo->ssi_cipwlen + 1);
		sinfo->ssi_cspwd = smb_srm_zalloc(sr, sinfo->ssi_cspwlen + 1);

		rc = smbsr_decode_data(sr, "%#c#cuuu",
		    sr,
		    sinfo->ssi_cipwlen, sinfo->ssi_cipwd,
		    sinfo->ssi_cspwlen, sinfo->ssi_cspwd,
		    &sinfo->ssi_user,
		    &sinfo->ssi_domain,
		    &native_os);
		if (rc != 0)
			goto pre_session_setup_andx_done;

		sinfo->ssi_cipwd[sinfo->ssi_cipwlen] = 0;
		sinfo->ssi_cspwd[sinfo->ssi_cspwlen] = 0;

		sr->session->native_os = smbnative_os_value(native_os);

		if (sr->session->native_os == NATIVE_OS_WINNT)
			rc = smbsr_decode_data(sr, "%,u", sr, &native_lm);
		else
			rc = smbsr_decode_data(sr, "%u", sr, &native_lm);

		if (rc != 0 || native_lm == NULL)
			native_lm = "NT LAN Manager 4.0";

		sr->session->native_lm = smbnative_lm_value(native_lm);
	} else {
		rc = smbsr_decode_vwv(sr, "b.wwwwlw4.", &sr->andx_com,
		    &sr->andx_off, &maxbufsize,
		    &sinfo->ssi_maxmpxcount, &vcnumber,
		    &sinfo->ssi_sesskey, &sinfo->ssi_cipwlen);
		if (rc != 0)
			goto pre_session_setup_andx_done;

		sinfo->ssi_cipwd = smb_srm_zalloc(sr, sinfo->ssi_cipwlen + 1);
		rc = smbsr_decode_data(sr, "%#c", sr, sinfo->ssi_cipwlen,
		    sinfo->ssi_cipwd);
		if (rc != 0)
			goto pre_session_setup_andx_done;

		sinfo->ssi_cipwd[sinfo->ssi_cipwlen] = 0;

		if (smbsr_decode_data(sr, "%u", sr, &sinfo->ssi_user) != 0)
			sinfo->ssi_user = "";

		if (smbsr_decode_data(sr, "%u", sr, &sinfo->ssi_domain) != 0)
			sinfo->ssi_domain = "";

		native_lm = "NT LAN Manager 4.0";
		sr->session->native_os = NATIVE_OS_WINNT;
		sr->session->native_lm = smbnative_lm_value(native_lm);
	}

	sr->session->vcnumber = vcnumber;
	sr->session->smb_msg_size = maxbufsize;

pre_session_setup_andx_done:
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

	if (sinfo->ssi_cipwd != NULL)
		bzero(sinfo->ssi_cipwd, sinfo->ssi_cipwlen + 1);

	if (sinfo->ssi_cspwd != NULL)
		bzero(sinfo->ssi_cspwd, sinfo->ssi_cspwlen + 1);
}

/*
 * If signing has not already been enabled on this session check to see if
 * it should be enabled.  The first authenticated logon provides the MAC
 * key and sequence numbers for signing all subsequent sessions on the same
 * connection.
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
	smb_session_key_t	*session_key = NULL;
	char			ipaddr_buf[INET6_ADDRSTRLEN];
	int			rc;

	if (smb_authenticate(sr, sinfo, &session_key) != 0)
		return (SDRC_ERROR);

	if (sr->session->native_lm == NATIVE_LM_WIN2000)
		sinfo->ssi_capabilities |= CAP_LARGE_FILES |
		    CAP_LARGE_READX | CAP_LARGE_WRITEX;

	if (!smb_oplock_levelII)
		sr->session->capabilities &= ~CAP_LEVEL_II_OPLOCKS;

	sr->session->capabilities = sinfo->ssi_capabilities;

	if (!(sr->session->signing.flags & SMB_SIGNING_ENABLED) &&
	    (sr->session->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED) &&
	    (sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    session_key)
		smb_sign_init(sr, session_key, (char *)sinfo->ssi_cspwd,
		    sinfo->ssi_cspwlen);

	if (!(sr->smb_flg2 & SMB_FLAGS2_SMB_SECURITY_SIGNATURE) &&
	    (sr->sr_cfg->skc_signing_required)) {
		(void) smb_inet_ntop(&sr->session->ipaddr, ipaddr_buf,
		    SMB_IPSTRLEN(sr->session->ipaddr.a_family));
		cmn_err(CE_NOTE,
		    "SmbSessonSetupX: client %s does not support signing",
		    ipaddr_buf);
		smbsr_error(sr, NT_STATUS_LOGON_FAILURE,
		    ERRDOS, ERROR_LOGON_FAILURE);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_result(sr, 3, VAR_BCC, "bb.www%uuu",
	    3,
	    sr->andx_com,
	    -1,			/* andx_off */
	    sinfo->ssi_guest ? 1 : 0,
	    VAR_BCC,
	    sr,
	    smbnative_os_str(&sr->sr_cfg->skc_version),
	    smbnative_lm_str(&sr->sr_cfg->skc_version),
	    sr->sr_cfg->skc_nbdomain);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

static int
smb_authenticate(smb_request_t *sr, smb_arg_sessionsetup_t *sinfo,
    smb_session_key_t **session_key)
{
	int		rc;
	smb_server_t	*sv = sr->sr_server;

	if (smb_threshold_enter(&sv->sv_ssetup_ct) != 0) {
		smbsr_error(sr, RPC_NT_SERVER_TOO_BUSY, 0, 0);
		return (-1);
	}

	rc = smb_authenticate_core(sr, sinfo, session_key);
	smb_threshold_exit(&sv->sv_ssetup_ct);
	return (rc);
}

/*
 * Authenticate a user.  If the user has already been authenticated on
 * this session, we can simply dup the user and return.
 *
 * Otherwise, the user information is passed to smbd for authentication.
 * If smbd can authenticate the user an access token is returned and we
 * generate a cred and new user based on the token.
 */
static int
smb_authenticate_core(smb_request_t *sr, smb_arg_sessionsetup_t *sinfo,
    smb_session_key_t **session_key)
{
	char		*hostname = sr->sr_cfg->skc_hostname;
	int		security = sr->sr_cfg->skc_secmode;
	smb_token_t	*token = NULL;
	smb_user_t	*user = NULL;
	smb_logon_t	user_info;
	boolean_t	need_lookup = B_FALSE;
	uint32_t	privileges;
	cred_t		*cr;
	char		*buf = NULL;
	char		*p;

	bzero(&user_info, sizeof (smb_logon_t));
	user_info.lg_e_domain = sinfo->ssi_domain;

	if ((*sinfo->ssi_user == '\0') &&
	    (sinfo->ssi_cspwlen == 0) &&
	    (sinfo->ssi_cipwlen == 0 ||
	    (sinfo->ssi_cipwlen == 1 && *sinfo->ssi_cipwd == '\0'))) {
		user_info.lg_e_username = "anonymous";
		user_info.lg_flags |= SMB_ATF_ANON;
	} else {
		user_info.lg_e_username = sinfo->ssi_user;
	}

	/*
	 * Handle user@domain format.  We need to retain the original
	 * data as this is important in some forms of authentication.
	 */
	if (*sinfo->ssi_domain == '\0') {
		buf = smb_srm_strdup(sr, sinfo->ssi_user);
		if ((p = strchr(buf, '@')) != NULL) {
			*p = '\0';
			user_info.lg_e_username = buf;
			user_info.lg_e_domain = p + 1;
		}
	}

	/*
	 * If no domain name has been provided in domain mode we cannot
	 * determine if this is a local user or a domain user without
	 * obtaining an access token.  So we postpone the lookup until
	 * after authentication.
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
		sinfo->ssi_guest = SMB_USER_IS_GUEST(user);
		sr->user_cr = user->u_cred;
		sr->smb_uid = user->u_uid;
		sr->uid_user = user;
		return (0);
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
	user_info.lg_native_lm = sr->session->native_lm;

	DTRACE_PROBE1(smb__sessionsetup__clntinfo, smb_logon_t *, &user_info);

	if ((token = smb_get_token(sr->session, &user_info)) == NULL) {
		smbsr_error(sr, 0, ERRSRV, ERRbadpw);
		return (-1);
	}

	if (need_lookup) {
		user = smb_session_dup_user(sr->session,
		    token->tkn_domain_name, token->tkn_account_name);
		if (user != NULL) {
			sinfo->ssi_guest = SMB_USER_IS_GUEST(user);
			sr->user_cr = user->u_cred;
			sr->smb_uid = user->u_uid;
			sr->uid_user = user;
			smb_token_free(token);
			return (0);
		}
	}

	if (token->tkn_session_key) {
		*session_key = smb_srm_zalloc(sr, sizeof (smb_session_key_t));
		bcopy(token->tkn_session_key, *session_key,
		    sizeof (smb_session_key_t));
	}

	if ((cr = smb_cred_create(token)) == NULL) {
		smb_token_free(token);
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_HANDLE);
		return (-1);
	}

	privileges = smb_priv_xlate(token);

	user = smb_user_login(sr->session, cr,
	    token->tkn_domain_name, token->tkn_account_name,
	    token->tkn_flags, privileges, token->tkn_audit_sid);

	crfree(cr);
	smb_token_free(token);

	if (user == NULL) {
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_HANDLE);
		return (-1);
	}

	sinfo->ssi_guest = SMB_USER_IS_GUEST(user);
	sr->user_cr = user->u_cred;
	sr->smb_uid = user->u_uid;
	sr->uid_user = user;
	return (0);
}

/*
 * Allocate a Solaris cred and initialize it based on the access token.
 *
 * If the user can be mapped to a non-ephemeral ID, the cred gid is set
 * to the Solaris user's primary group.
 *
 * If the mapped UID is ephemeral, or the primary group could not be
 * obtained, the cred gid is set to whatever Solaris group is mapped
 * to the token's primary group.
 */
static cred_t *
smb_cred_create(smb_token_t *token)
{
	ksid_t			ksid;
	ksidlist_t		*ksidlist = NULL;
	smb_posix_grps_t	*posix_grps;
	cred_t			*cr;
	gid_t			gid;

	ASSERT(token);
	ASSERT(token->tkn_posix_grps);
	posix_grps = token->tkn_posix_grps;

	cr = crget();
	ASSERT(cr != NULL);

	if (!IDMAP_ID_IS_EPHEMERAL(token->tkn_user.i_id) &&
	    (posix_grps->pg_ngrps != 0)) {
		gid = posix_grps->pg_grps[0];
	} else {
		gid = token->tkn_primary_grp.i_id;
	}

	if (crsetugid(cr, token->tkn_user.i_id, gid) != 0) {
		crfree(cr);
		return (NULL);
	}

	if (crsetgroups(cr, posix_grps->pg_ngrps, posix_grps->pg_grps) != 0) {
		crfree(cr);
		return (NULL);
	}

	smb_cred_set_sid(&token->tkn_user, &ksid);
	crsetsid(cr, &ksid, KSID_USER);
	smb_cred_set_sid(&token->tkn_primary_grp, &ksid);
	crsetsid(cr, &ksid, KSID_GROUP);
	smb_cred_set_sid(&token->tkn_owner, &ksid);
	crsetsid(cr, &ksid, KSID_OWNER);
	ksidlist = smb_cred_set_sidlist(&token->tkn_win_grps);
	crsetsidlist(cr, ksidlist);

	if (smb_token_query_privilege(token, SE_TAKE_OWNERSHIP_LUID))
		(void) crsetpriv(cr, PRIV_FILE_CHOWN, NULL);

	return (cr);
}

/*
 * Initialize the ksid based on the given smb_id_t.
 */
static void
smb_cred_set_sid(smb_id_t *id, ksid_t *ksid)
{
	char sidstr[SMB_SID_STRSZ];
	int rc;

	ASSERT(id);
	ASSERT(id->i_sid);

	ksid->ks_id = id->i_id;
	smb_sid_tostr(id->i_sid, sidstr);
	rc = smb_sid_splitstr(sidstr, &ksid->ks_rid);
	ASSERT(rc == 0);

	ksid->ks_attr = id->i_attrs;
	ksid->ks_domain = ksid_lookupdomain(sidstr);
}

/*
 * Allocate and initialize the ksidlist based on the access token group list.
 */
static ksidlist_t *
smb_cred_set_sidlist(smb_ids_t *token_grps)
{
	int i;
	ksidlist_t *lp;

	lp = kmem_zalloc(KSIDLIST_MEM(token_grps->i_cnt), KM_SLEEP);
	lp->ksl_ref = 1;
	lp->ksl_nsid = token_grps->i_cnt;
	lp->ksl_neid = 0;

	for (i = 0; i < lp->ksl_nsid; i++) {
		smb_cred_set_sid(&token_grps->i_ids[i], &lp->ksl_sids[i]);
		if (lp->ksl_sids[i].ks_id > IDMAP_WK__MAX_GID)
			lp->ksl_neid++;
	}

	return (lp);
}

/*
 * Convert access token privileges to local definitions.
 */
static uint32_t
smb_priv_xlate(smb_token_t *token)
{
	uint32_t	privileges = 0;

	if (smb_token_query_privilege(token, SE_BACKUP_LUID))
		privileges |= SMB_USER_PRIV_BACKUP;

	if (smb_token_query_privilege(token, SE_RESTORE_LUID))
		privileges |= SMB_USER_PRIV_RESTORE;

	if (smb_token_query_privilege(token, SE_TAKE_OWNERSHIP_LUID))
		privileges |= SMB_USER_PRIV_TAKE_OWNERSHIP;

	if (smb_token_query_privilege(token, SE_SECURITY_LUID))
		privileges |= SMB_USER_PRIV_SECURITY;

	return (privileges);
}
