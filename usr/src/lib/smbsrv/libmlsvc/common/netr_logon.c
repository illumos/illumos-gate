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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2023 RackTop Systems, Inc.
 */

/*
 * NETR SamLogon and SamLogoff RPC client functions.
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <alloca.h>
#include <unistd.h>
#include <netdb.h>
#include <thread.h>

#include <libmlrpc/libmlrpc.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/netlogon.ndl>
#include <smbsrv/netrauth.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <mlsvc.h>

uint32_t netlogon_logon(smb_logon_t *, smb_token_t *, smb_domainex_t *);
static uint32_t netr_server_samlogon(mlsvc_handle_t *, netr_info_t *, char *,
    smb_logon_t *, smb_token_t *);
static void netr_invalidate_chain(netr_info_t *);
static void netr_interactive_samlogon(netr_info_t *, smb_logon_t *,
    struct netr_logon_info1 *);
static void netr_network_samlogon(ndr_heap_t *, netr_info_t *,
    smb_logon_t *, struct netr_logon_info2 *);
static void netr_setup_identity(ndr_heap_t *, smb_logon_t *,
    netr_logon_id_t *);
static uint32_t netr_setup_domain_groups(struct netr_validation_info3 *,
    smb_ids_t *);
static uint32_t netr_setup_krb5res_groups(struct krb5_validation_info *,
    smb_ids_t *);
static uint32_t netr_setup_token_wingrps(struct netr_validation_info3 *,
    smb_token_t *);

/*
 * Shared with netr_auth.c
 */
extern netr_info_t netr_global_info;

static mutex_t netlogon_mutex;
static cond_t netlogon_cv;
static boolean_t netlogon_busy = B_FALSE;
static boolean_t netlogon_abort = B_FALSE;

/*
 * Helper for Kerberos authentication
 */
uint32_t
smb_decode_krb5_pac(smb_token_t *token, char *data, uint_t len)
{
	struct krb5_validation_info info;
	ndr_buf_t *nbuf;
	smb_sid_t *domsid;
	uint32_t status = NT_STATUS_NO_MEMORY;
	int rc;

	bzero(&info, sizeof (info));

	/* Need to keep this until we're done with &info */
	nbuf = ndr_buf_init(&TYPEINFO(netr_interface));
	if (nbuf == NULL)
		goto out;

	rc = ndr_buf_decode(nbuf, NDR_PTYPE_PAC,
	    NETR_OPNUM_decode_krb5_pac, data, len, &info);
	if (rc != NDR_DRC_OK) {
		status = RPC_NT_PROTOCOL_ERROR;
		goto out;
	}

	/*
	 * Copy the decoded info into the token,
	 * similar to netr_setup_token()
	 */
	domsid = (smb_sid_t *)info.info3.LogonDomainId;

	token->tkn_user.i_sid = smb_sid_splice(domsid,
	    info.info3.UserId);
	if (token->tkn_user.i_sid == NULL)
		goto out;

	token->tkn_primary_grp.i_sid = smb_sid_splice(domsid,
	    info.info3.PrimaryGroupId);
	if (token->tkn_primary_grp.i_sid == NULL)
		goto out;

	if (info.info3.EffectiveName.str) {
		token->tkn_account_name =
		    strdup((char *)info.info3.EffectiveName.str);
		if (token->tkn_account_name == NULL)
			goto out;
	}

	if (info.info3.LogonDomainName.str) {
		token->tkn_domain_name =
		    strdup((char *)info.info3.LogonDomainName.str);
		if (token->tkn_domain_name == NULL)
			goto out;
	}

	status = netr_setup_domain_groups(&info.info3, &token->tkn_win_grps);
	if (status != NT_STATUS_SUCCESS)
		goto out;

	if (info.rg_rid_cnt != 0) {
		status = netr_setup_krb5res_groups(&info, &token->tkn_win_grps);
		if (status != NT_STATUS_SUCCESS)
			goto out;
	}

	status = netr_setup_token_wingrps(&info.info3, token);

out:
	if (nbuf != NULL)
		ndr_buf_fini(nbuf);

	return (status);
}

/*
 * Abort impending domain logon requests.
 */
void
smb_logon_abort(void)
{
	(void) mutex_lock(&netlogon_mutex);
	if (netlogon_busy && !netlogon_abort)
		syslog(LOG_DEBUG, "logon abort");
	netlogon_abort = B_TRUE;
	(void) cond_broadcast(&netlogon_cv);
	(void) mutex_unlock(&netlogon_mutex);
}

/*
 * This is the entry point for authenticating domain users.
 *
 * If we are not going to attempt to authenticate the user,
 * this function must return without updating the status.
 *
 * If the user is successfully authenticated, we build an
 * access token and the status will be NT_STATUS_SUCCESS.
 * Otherwise, the token contents are invalid.
 *
 * This will retry a few times for errors indicating that the
 * current DC might have gone off-line or become too busy etc.
 * With such errors, smb_ddiscover_bad_dc is called and then
 * the smb_domain_getinfo call here waits for new DC info.
 */
int smb_netr_logon_retries = 3;
void
smb_logon_domain(smb_logon_t *user_info, smb_token_t *token)
{
	smb_domainex_t	di;
	uint32_t	status;
	int		retries = smb_netr_logon_retries;

	if (user_info->lg_secmode != SMB_SECMODE_DOMAIN)
		return;

	if (user_info->lg_domain_type == SMB_DOMAIN_LOCAL)
		return;

	while (--retries > 0) {

		if (!smb_domain_getinfo(&di)) {
			syslog(LOG_ERR, "logon DC getinfo failed");
			status = NT_STATUS_NO_LOGON_SERVERS;
			goto out;
		}

		(void) mutex_lock(&netlogon_mutex);
		while (netlogon_busy && !netlogon_abort)
			(void) cond_wait(&netlogon_cv, &netlogon_mutex);

		if (netlogon_abort) {
			(void) mutex_unlock(&netlogon_mutex);
			status = NT_STATUS_REQUEST_ABORTED;
			goto out;
		}

		netlogon_busy = B_TRUE;
		(void) mutex_unlock(&netlogon_mutex);

		status = netlogon_logon(user_info, token, &di);

		(void) mutex_lock(&netlogon_mutex);
		netlogon_busy = B_FALSE;
		if (netlogon_abort)
			status = NT_STATUS_REQUEST_ABORTED;
		(void) cond_signal(&netlogon_cv);
		(void) mutex_unlock(&netlogon_mutex);

		switch (status) {
		case NT_STATUS_BAD_NETWORK_PATH:
		case NT_STATUS_BAD_NETWORK_NAME:
		case RPC_NT_SERVER_TOO_BUSY:
			/*
			 * May retry with a new DC, or if we're
			 * out of retries, will return...
			 */
			status = NT_STATUS_NO_LOGON_SERVERS;
			break;
		default:
			goto out;
		}
	}

out:
	if (status != NT_STATUS_SUCCESS)
		syslog(LOG_INFO, "logon[%s\\%s]: %s", user_info->lg_e_domain,
		    user_info->lg_e_username, xlate_nt_status(status));
	user_info->lg_status = status;
}

static uint32_t
netr_get_handle(char *server, char *domain, mlsvc_handle_t *netr_handle)
{
	uint32_t status;
	boolean_t did_renego = B_FALSE;

reauth:
	if ((netr_global_info.flags & NETR_FLG_VALID) == 0 ||
	    !smb_match_netlogon_seqnum()) {
		/*
		 * This does netr_server_req_challenge() and
		 * netr_server_authenticate2(), updating the
		 * current netlogon sequence number.
		 */
		status = netlogon_auth(server, domain, NETR_FLG_NULL);

		if (status != 0) {
			syslog(LOG_ERR, "%s: auth failed (%s)",
			    __func__, xlate_nt_status(status));
			return (status);
		}

		netr_global_info.flags |= NETR_FLG_VALID;
	}

	/*
	 * This netr_open_secure call does the work to connect to the DC,
	 * get the IPC share, open the named pipe, RPC bind, etc.
	 */
	status = netr_open_secure(server, domain, netr_handle);
	if (status != 0) {
		/*
		 * This may have failed because the DC restarted.
		 * Re-negotiate once.
		 */
		if (!did_renego) {
			did_renego = B_TRUE;
			netr_invalidate_chain(&netr_global_info);
			syslog(LOG_ERR, "%s: open failed (%s); "
			    "renegotiating...",
			    __func__, xlate_nt_status(status));
			goto reauth;
		}
		syslog(LOG_ERR, "%s: open failed (%s)",
		    __func__, xlate_nt_status(status));
	}

	return (status);
}

/*
 * Run a netr_server_samlogon call, dealing with the possible need to
 * re-establish the NetLogon credential chain.  If that fails, return
 * NT_STATUS_DOMAIN_TRUST_INCONSISTENT indicating the machine account
 * needs it's password reset (or whatever).  Other errors are from the
 * netr_server_samlogon() call including the many possibilities listed
 * above that function.
 */
uint32_t
netlogon_logon(smb_logon_t *user_info, smb_token_t *token, smb_domainex_t *di)
{
	char server[MAXHOSTNAMELEN];
	mlsvc_handle_t netr_handle;
	uint32_t status;
	boolean_t did_reauth = B_FALSE;

	if (di->d_dci.dc_name[0] != '\0' &&
	    (*netr_global_info.server != '\0')) {
		(void) snprintf(server, sizeof (server),
		    "\\\\%s", di->d_dci.dc_name);
		if (strncasecmp(netr_global_info.server,
		    server, strlen(server)) != 0)
			netr_invalidate_chain(&netr_global_info);
	}

reauth:
	status = netr_get_handle(di->d_dci.dc_name,
	    di->d_primary.di_nbname, &netr_handle);

	if (status != 0) {
		syslog(LOG_ERR, "%s: failed to get handle (%s)",
		    __func__, xlate_nt_status(status));
		return (NT_STATUS_DOMAIN_TRUST_INCONSISTENT);
	}

	status = netr_server_samlogon(&netr_handle,
	    &netr_global_info, di->d_dci.dc_name, user_info, token);

	if (status == NT_STATUS_INSUFFICIENT_LOGON_INFO) {
		if (!did_reauth) {
			/* Call netlogon_auth() again, just once. */
			(void) netr_close(&netr_handle);
			did_reauth = B_TRUE;
			goto reauth;
		}
		status = NT_STATUS_DOMAIN_TRUST_INCONSISTENT;
	}

	(void) netr_close(&netr_handle);

	return (status);
}

/*
 * Helper for mlsvc_netlogon
 *
 * Call netlogon_auth with appropriate locks etc.
 * Serialize like smb_logon_domain does for
 * netlogon_logon / netlogon_auth
 */
uint32_t
smb_netlogon_check(char *server, char *domain)
{
	mlsvc_handle_t netr_handle;
	uint32_t	status;

	(void) mutex_lock(&netlogon_mutex);
	while (netlogon_busy)
		(void) cond_wait(&netlogon_cv, &netlogon_mutex);

	netlogon_busy = B_TRUE;
	(void) mutex_unlock(&netlogon_mutex);

	/*
	 * Like netlogon_logon(), but no netr_server_samlogon call.
	 * We're just making sure we can connect to the NETLOGON server.
	 */
	status = netr_get_handle(server, domain, &netr_handle);
	if (status == 0)
		(void) netr_close(&netr_handle);
	else
		syslog(LOG_ERR, "%s: failed to get handle (%s)",
		    __func__, xlate_nt_status(status));

	(void) mutex_lock(&netlogon_mutex);
	netlogon_busy = B_FALSE;
	(void) cond_signal(&netlogon_cv);
	(void) mutex_unlock(&netlogon_mutex);

	return (status);
}

static uint32_t
netr_setup_token(struct netr_validation_info3 *info3, smb_logon_t *user_info,
    netr_info_t *netr_info, smb_token_t *token)
{
	char *username, *domain;
	unsigned char rc4key[SMBAUTH_SESSION_KEY_SZ];
	smb_sid_t *domsid;
	uint32_t status;
	char nbdomain[NETBIOS_NAME_SZ];

	domsid = (smb_sid_t *)info3->LogonDomainId;

	token->tkn_user.i_sid = smb_sid_splice(domsid, info3->UserId);
	if (token->tkn_user.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	token->tkn_primary_grp.i_sid = smb_sid_splice(domsid,
	    info3->PrimaryGroupId);
	if (token->tkn_primary_grp.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	username = (info3->EffectiveName.str)
	    ? (char *)info3->EffectiveName.str : user_info->lg_e_username;

	if (info3->LogonDomainName.str) {
		domain = (char *)info3->LogonDomainName.str;
	} else if (*user_info->lg_e_domain != '\0') {
		domain = user_info->lg_e_domain;
	} else {
		(void) smb_getdomainname(nbdomain, sizeof (nbdomain));
		domain = nbdomain;
	}

	if (username)
		token->tkn_account_name = strdup(username);
	if (domain)
		token->tkn_domain_name = strdup(domain);

	if (token->tkn_account_name == NULL || token->tkn_domain_name == NULL)
		return (NT_STATUS_NO_MEMORY);

	status = netr_setup_domain_groups(info3, &token->tkn_win_grps);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	status = netr_setup_token_wingrps(info3, token);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	/*
	 * The UserSessionKey in NetrSamLogon RPC is obfuscated using the
	 * session key obtained in the NETLOGON credential chain.
	 * An 8 byte session key is zero extended to 16 bytes. This 16 byte
	 * key is the key to the RC4 algorithm. The RC4 byte stream is
	 * exclusively ored with the 16 byte UserSessionKey to recover
	 * the the clear form.
	 */
	if ((token->tkn_ssnkey.val = malloc(SMBAUTH_SESSION_KEY_SZ)) == NULL)
		return (NT_STATUS_NO_MEMORY);
	token->tkn_ssnkey.len = SMBAUTH_SESSION_KEY_SZ;
	bzero(rc4key, SMBAUTH_SESSION_KEY_SZ);
	bcopy(netr_info->session_key.key, rc4key, netr_info->session_key.len);
	bcopy(info3->UserSessionKey.data, token->tkn_ssnkey.val,
	    SMBAUTH_SESSION_KEY_SZ);
	rand_hash((unsigned char *)token->tkn_ssnkey.val,
	    SMBAUTH_SESSION_KEY_SZ, rc4key, SMBAUTH_SESSION_KEY_SZ);

	return (NT_STATUS_SUCCESS);
}

/*
 * netr_server_samlogon
 *
 * NetrServerSamLogon RPC: interactive or network. It is assumed that
 * we have already authenticated with the PDC. If everything works,
 * we build a user info structure and return it, where the caller will
 * probably build an access token.
 *
 * Returns an NT status. There are numerous possibilities here.
 * For example:
 *	NT_STATUS_INVALID_INFO_CLASS
 *	NT_STATUS_INVALID_PARAMETER
 *	NT_STATUS_ACCESS_DENIED
 *	NT_STATUS_PASSWORD_MUST_CHANGE
 *	NT_STATUS_NO_SUCH_USER
 *	NT_STATUS_WRONG_PASSWORD
 *	NT_STATUS_LOGON_FAILURE
 *	NT_STATUS_ACCOUNT_RESTRICTION
 *	NT_STATUS_INVALID_LOGON_HOURS
 *	NT_STATUS_INVALID_WORKSTATION
 *	NT_STATUS_INTERNAL_ERROR
 *	NT_STATUS_PASSWORD_EXPIRED
 *	NT_STATUS_ACCOUNT_DISABLED
 */
uint32_t
netr_server_samlogon(mlsvc_handle_t *netr_handle, netr_info_t *netr_info,
    char *server, smb_logon_t *user_info, smb_token_t *token)
{
	struct netr_SamLogon logon_op;
	struct netr_SamLogonEx logon_ex_op;
	struct netr_authenticator auth;
	struct netr_authenticator ret_auth;
	struct netr_logon_info1 info1;
	struct netr_logon_info2 info2;
	struct netr_validation_info3 *info3;
	union netr_validation_u *valid_info;
	union netr_logon_info_u *logon_info;
	LPTSTR servername, hostname;
	ndr_heap_t *heap;
	int opnum;
	int rc, len;
	uint32_t status, *rpc_status;
	void *rpc_arg;

	/*
	 * Should we get the server and hostname from netr_info?
	 */

	len = strlen(server) + 4;
	servername = ndr_rpc_malloc(netr_handle, len);
	hostname = ndr_rpc_malloc(netr_handle, NETBIOS_NAME_SZ);
	if (servername == NULL || hostname == NULL) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	(void) snprintf((char *)servername, len, "\\\\%s", server);
	if (smb_getnetbiosname((char *)hostname, NETBIOS_NAME_SZ) != 0) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = netr_setup_authenticator(netr_info, &auth, &ret_auth);
	if (rc != SMBAUTH_SUCCESS) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	/*
	 * If we use Secure RPC, we can use SamLogonEx instead of SamLogon.
	 * SamLogonEx doesn't use NetLogon authenticators, instead relying
	 * on Secure RPC to provide security.
	 * This allows us to avoid being bitten by mitigations in
	 * the authenticator verification logic on DCs.
	 */
	if (netr_info->use_logon_ex &&
	    (netr_info->nego_flags & NETR_NEGO_SECURE_RPC_FLAG) != 0) {
		bzero(&logon_ex_op, sizeof (struct netr_SamLogonEx));
		logon_ex_op.servername = servername;
		logon_ex_op.hostname = hostname;
		logon_ex_op.logon_info.logon_level = user_info->lg_level;
		logon_ex_op.logon_info.switch_value = user_info->lg_level;
		logon_ex_op.validation_level = NETR_VALIDATION_LEVEL3;
		logon_ex_op.extra_flags = 0;
		logon_info = &logon_ex_op.logon_info.ru;
		valid_info = &logon_ex_op.ru;
		rpc_status = &logon_ex_op.status;
		rpc_arg = &logon_ex_op;
		opnum = NETR_OPNUM_SamLogonEx;
	} else {
		bzero(&logon_op, sizeof (struct netr_SamLogon));
		logon_op.servername = servername;
		logon_op.hostname = hostname;
		logon_op.auth = &auth;
		logon_op.ret_auth = &ret_auth;
		logon_op.logon_info.logon_level = user_info->lg_level;
		logon_op.logon_info.switch_value = user_info->lg_level;
		logon_op.validation_level = NETR_VALIDATION_LEVEL3;
		logon_info = &logon_op.logon_info.ru;
		valid_info = &logon_op.ru;
		rpc_status = &logon_op.status;
		rpc_arg = &logon_op;
		opnum = NETR_OPNUM_SamLogon;
	}
	heap = ndr_rpc_get_heap(netr_handle);

	switch (user_info->lg_level) {
	case NETR_INTERACTIVE_LOGON:
		netr_setup_identity(heap, user_info, &info1.identity);
		netr_interactive_samlogon(netr_info, user_info, &info1);
		logon_info->info1 = &info1;
		break;

	case NETR_NETWORK_LOGON:
		if (user_info->lg_challenge_key.len < 8 ||
		    user_info->lg_challenge_key.val == NULL) {
			ndr_rpc_release(netr_handle);
			return (NT_STATUS_INVALID_PARAMETER);
		}
		netr_setup_identity(heap, user_info, &info2.identity);
		netr_network_samlogon(heap, netr_info, user_info, &info2);
		logon_info->info2 = &info2;
		break;

	default:
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rc = ndr_rpc_call(netr_handle, opnum, rpc_arg);
	if (rc != 0) {
		netr_invalidate_chain(netr_info);
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (*rpc_status != 0) {
		status = NT_SC_VALUE(*rpc_status);

		/*
		 * We need to validate the chain even though we have
		 * a non-zero status. If the status is ACCESS_DENIED
		 * this will trigger a new credential chain. However,
		 * a valid credential is returned with some status
		 * codes; for example, WRONG_PASSWORD.
		 *
		 * SamLogonEx doesn't use authenticators - nothing to validate.
		 */
		if (rpc_arg == &logon_op)
			(void) netr_validate_chain(netr_info,
			    logon_op.ret_auth);
	} else {
		if (rpc_arg == &logon_op) {
			status = netr_validate_chain(netr_info,
			    logon_op.ret_auth);
			if (status == NT_STATUS_INSUFFICIENT_LOGON_INFO) {
				ndr_rpc_release(netr_handle);
				return (status);
			}
		}

		info3 = valid_info->info3;
		status = netr_setup_token(info3, user_info, netr_info, token);
	}

	ndr_rpc_release(netr_handle);
	return (status);
}

/*
 * netr_interactive_samlogon
 *
 * Set things up for an interactive SamLogon. Copy the NT and LM
 * passwords to the logon structure and hash them with the session
 * key.
 */
static void
netr_interactive_samlogon(netr_info_t *netr_info, smb_logon_t *user_info,
    struct netr_logon_info1 *info1)
{
	BYTE key[NETR_OWF_PASSWORD_SZ];

	(void) memcpy(&info1->lm_owf_password,
	    user_info->lg_lm_password.val, sizeof (netr_owf_password_t));

	(void) memcpy(&info1->nt_owf_password,
	    user_info->lg_nt_password.val, sizeof (netr_owf_password_t));

	(void) memset(key, 0, NETR_OWF_PASSWORD_SZ);
	(void) memcpy(key, netr_info->session_key.key,
	    netr_info->session_key.len);

	rand_hash((unsigned char *)&info1->lm_owf_password,
	    NETR_OWF_PASSWORD_SZ, key, NETR_OWF_PASSWORD_SZ);

	rand_hash((unsigned char *)&info1->nt_owf_password,
	    NETR_OWF_PASSWORD_SZ, key, NETR_OWF_PASSWORD_SZ);
}

/*
 * netr_network_samlogon
 *
 * Set things up for a network SamLogon.  We provide a copy of the random
 * challenge, that we sent to the client, to the domain controller.  This
 * is the key that the client will have used to encrypt the NT and LM
 * passwords.  Note that Windows 9x clients may not provide both passwords.
 */
/*ARGSUSED*/
static void
netr_network_samlogon(ndr_heap_t *heap, netr_info_t *netr_info,
    smb_logon_t *user_info, struct netr_logon_info2 *info2)
{
	uint32_t len;

	if (user_info->lg_challenge_key.len >= 8 &&
	    user_info->lg_challenge_key.val != 0) {
		bcopy(user_info->lg_challenge_key.val,
		    info2->lm_challenge.data, 8);
	} else {
		bzero(info2->lm_challenge.data, 8);
	}

	if ((len = user_info->lg_nt_password.len) != 0) {
		ndr_heap_mkvcb(heap, user_info->lg_nt_password.val, len,
		    (ndr_vcbuf_t *)&info2->nt_response);
	} else {
		bzero(&info2->nt_response, sizeof (netr_vcbuf_t));
	}

	if ((len = user_info->lg_lm_password.len) != 0) {
		ndr_heap_mkvcb(heap, user_info->lg_lm_password.val, len,
		    (ndr_vcbuf_t *)&info2->lm_response);
	} else {
		bzero(&info2->lm_response, sizeof (netr_vcbuf_t));
	}
}

/*
 * netr_setup_authenticator
 *
 * Set up the request and return authenticators. A new credential is
 * generated from the session key, the current client credential and
 * the current time, i.e.
 *
 *		NewCredential = Cred(SessionKey, OldCredential, time);
 *
 * The timestamp, which is used as a random seed, is stored in both
 * the request and return authenticators.
 *
 * If any difficulties occur using the cryptographic framework, the
 * function returns SMBAUTH_FAILURE.  Otherwise SMBAUTH_SUCCESS is
 * returned.
 */
int
netr_setup_authenticator(netr_info_t *netr_info,
    struct netr_authenticator *auth, struct netr_authenticator *ret_auth)
{
	int rc;
	bzero(auth, sizeof (struct netr_authenticator));

	/*
	 * Windows DCs will reject Authenticators if none of the first
	 * 5 bytes of the ClientStoredCredential are unique.
	 * Keep retrying until we've generated one that satisfies this.
	 */
	netr_info->timestamp = time(0) - 1;
	do {
		auth->timestamp = ++netr_info->timestamp;
		rc = netr_gen_credentials(netr_info->session_key.key,
		    &netr_info->client_credential,
		    netr_info->timestamp,
		    (netr_cred_t *)&auth->credential, B_TRUE);
		if (rc != SMBAUTH_SUCCESS && rc != SMBAUTH_RETRY)
			return (SMBAUTH_FAILURE);
	} while (rc == SMBAUTH_RETRY);

	if (ret_auth) {
		bzero(ret_auth, sizeof (struct netr_authenticator));
		ret_auth->timestamp = netr_info->timestamp;
	}

	return (SMBAUTH_SUCCESS);
}

/*
 * Validate the returned credentials and update the credential chain.
 * The server returns an updated client credential rather than a new
 * server credential.  The server uses (timestamp + 1) when generating
 * the credential.
 *
 * Generate the new seed for the credential chain. The new seed is
 * formed by adding (timestamp + 1) to the current client credential.
 * The only quirk is the uint32_t style addition.
 *
 * Returns NT_STATUS_INSUFFICIENT_LOGON_INFO if auth->credential is a
 * NULL pointer. The Authenticator field of the SamLogon response packet
 * sent by the Samba 3 PDC always return NULL pointer if the received
 * SamLogon request is not immediately followed by the ServerReqChallenge
 * and ServerAuthenticate2 requests.
 *
 * Returns NT_STATUS_SUCCESS if the server returned a valid credential.
 * Otherwise we retirm NT_STATUS_UNSUCCESSFUL.
 */
uint32_t
netr_validate_chain(netr_info_t *netr_info, struct netr_authenticator *auth)
{
	netr_cred_t cred;
	uint32_t result = NT_STATUS_SUCCESS;
	uint32_t *dwp;

	++netr_info->timestamp;

	if (netr_gen_credentials(netr_info->session_key.key,
	    &netr_info->client_credential,
	    netr_info->timestamp, &cred, B_FALSE) != SMBAUTH_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	if (auth == NULL) {
		/*
		 * If the validation fails, destroy the credential chain.
		 * This should trigger a new authentication chain.
		 */
		netr_invalidate_chain(netr_info);
		return (NT_STATUS_INSUFFICIENT_LOGON_INFO);
	}

	result = memcmp(&cred, &auth->credential, sizeof (netr_cred_t));
	if (result != 0) {
		/*
		 * If the validation fails, destroy the credential chain.
		 * This should trigger a new authentication chain.
		 */
		netr_invalidate_chain(netr_info);
		result = NT_STATUS_UNSUCCESSFUL;
	} else {
		/*
		 * Otherwise generate the next step in the chain.
		 */
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		dwp = (uint32_t *)&netr_info->client_credential;
		dwp[0] += netr_info->timestamp;

		netr_info->flags |= NETR_FLG_VALID;
	}

	return (result);
}

/*
 * netr_invalidate_chain
 *
 * Mark the credential chain as invalid so that it will be recreated
 * on the next attempt.
 */
static void
netr_invalidate_chain(netr_info_t *netr_info)
{
	if ((netr_info->flags & NETR_FLG_VALID) == 0)
		return;

	netr_info->flags &= ~NETR_FLG_VALID;
	explicit_bzero(&netr_info->session_key,
	    sizeof (netr_info->session_key));
	explicit_bzero(&netr_info->rpc_seal_key,
	    sizeof (netr_info->rpc_seal_key));
	explicit_bzero(&netr_info->client_credential,
	    sizeof (netr_info->client_credential));
	explicit_bzero(&netr_info->server_credential,
	    sizeof (netr_info->server_credential));
}

/*
 * netr_setup_identity
 *
 * Set up the client identity information. All of this information is
 * specifically related to the client user and workstation attempting
 * to access this system. It may not be in our primary domain.
 *
 * I don't know what logon_id is, it seems to be a unique identifier.
 * Increment it before each use.
 */
static void
netr_setup_identity(ndr_heap_t *heap, smb_logon_t *user_info,
    netr_logon_id_t *identity)
{
	static mutex_t logon_id_mutex;
	static uint32_t logon_id;

	(void) mutex_lock(&logon_id_mutex);

	if (logon_id == 0)
		logon_id = 0xDCD0;

	++logon_id;
	user_info->lg_logon_id = logon_id;

	(void) mutex_unlock(&logon_id_mutex);

	/*
	 * [MS-APDS] 3.1.5.2 "NTLM Network Logon" says to set
	 * ParameterControl to the 'E' + 'K' bits.  Those are:
	 * (1 << 5) | (1 << 11), a.k.a
	 */
	identity->parameter_control =
	    MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
	    MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;
	identity->logon_id.LowPart = logon_id;
	identity->logon_id.HighPart = 0;

	ndr_heap_mkvcs(heap, user_info->lg_domain,
	    (ndr_vcstr_t *)&identity->domain_name);

	ndr_heap_mkvcs(heap, user_info->lg_username,
	    (ndr_vcstr_t *)&identity->username);

	/*
	 * Some systems prefix the client workstation name with \\.
	 * It doesn't seem to make any difference whether it's there
	 * or not.
	 */
	ndr_heap_mkvcs(heap, user_info->lg_workstation,
	    (ndr_vcstr_t *)&identity->workstation);
}

/*
 * Add local and well-known group membership to the given
 * token.  Called after domain groups have been added.
 */
static uint32_t
netr_setup_token_wingrps(struct netr_validation_info3 *info3 __unused,
    smb_token_t *token)
{
	uint32_t status;

	status = smb_sam_usr_groups(token->tkn_user.i_sid,
	    &token->tkn_win_grps);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	status = smb_wka_token_groups(token->tkn_flags, &token->tkn_win_grps);

	return (status);
}

/*
 * Converts groups information in the returned structure by domain controller
 * (info3) to an internal representation (gids)
 */
static uint32_t
netr_setup_domain_groups(struct netr_validation_info3 *info3, smb_ids_t *gids)
{
	smb_sid_t *domain_sid;
	smb_id_t *ids;
	int i, total_cnt;

	if ((i = info3->GroupCount) == 0)
		i++;
	i += info3->SidCount;

	total_cnt = gids->i_cnt + i;

	gids->i_ids = realloc(gids->i_ids, total_cnt * sizeof (smb_id_t));
	if (gids->i_ids == NULL)
		return (NT_STATUS_NO_MEMORY);

	domain_sid = (smb_sid_t *)info3->LogonDomainId;

	ids = gids->i_ids + gids->i_cnt;
	for (i = 0; i < info3->GroupCount; i++, gids->i_cnt++, ids++) {
		ids->i_sid = smb_sid_splice(domain_sid, info3->GroupIds[i].rid);
		if (ids->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);

		ids->i_attrs = info3->GroupIds[i].attributes;
	}

	if (info3->GroupCount == 0) {
		/*
		 * if there's no global group should add the primary group.
		 */
		ids->i_sid = smb_sid_splice(domain_sid, info3->PrimaryGroupId);
		if (ids->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);

		ids->i_attrs = 0x7;
		gids->i_cnt++;
		ids++;
	}

	/* Add the extra SIDs */
	for (i = 0; i < info3->SidCount; i++, gids->i_cnt++, ids++) {
		ids->i_sid = smb_sid_dup((smb_sid_t *)info3->ExtraSids[i].sid);
		if (ids->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);

		ids->i_attrs = info3->ExtraSids[i].attributes;
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Converts additional "resource" groups (from krb5_validation_info)
 * into the internal representation (gids), appending to the list
 * already put in place by netr_setup_domain_groups().
 */
static uint32_t netr_setup_krb5res_groups(struct krb5_validation_info *info,
    smb_ids_t *gids)
{
	smb_sid_t *domain_sid;
	smb_id_t *ids;
	int i, total_cnt;

	total_cnt = gids->i_cnt + info->rg_rid_cnt;

	gids->i_ids = realloc(gids->i_ids, total_cnt * sizeof (smb_id_t));
	if (gids->i_ids == NULL)
		return (NT_STATUS_NO_MEMORY);

	domain_sid = (smb_sid_t *)info->rg_dom_sid;

	ids = gids->i_ids + gids->i_cnt;
	for (i = 0; i < info->rg_rid_cnt; i++, gids->i_cnt++, ids++) {
		ids->i_sid = smb_sid_splice(domain_sid, info->rg_rids[i].rid);
		if (ids->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);
		ids->i_attrs = info->rg_rids[i].attributes;
	}

	return (0);
}
