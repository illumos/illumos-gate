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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
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

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/netlogon.ndl>
#include <smbsrv/netrauth.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <mlsvc.h>

#define	NETLOGON_ATTEMPTS	2

static uint32_t netlogon_logon(smb_logon_t *, smb_token_t *);
static uint32_t netr_server_samlogon(mlsvc_handle_t *, netr_info_t *, char *,
    smb_logon_t *, smb_token_t *);
static void netr_invalidate_chain(void);
static void netr_interactive_samlogon(netr_info_t *, smb_logon_t *,
    struct netr_logon_info1 *);
static void netr_network_samlogon(ndr_heap_t *, netr_info_t *,
    smb_logon_t *, struct netr_logon_info2 *);
static void netr_setup_identity(ndr_heap_t *, smb_logon_t *,
    netr_logon_id_t *);
static boolean_t netr_isadmin(struct netr_validation_info3 *);
static uint32_t netr_setup_domain_groups(struct netr_validation_info3 *,
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
 */
void
smb_logon_domain(smb_logon_t *user_info, smb_token_t *token)
{
	uint32_t	status;
	int		i;

	if (user_info->lg_secmode != SMB_SECMODE_DOMAIN)
		return;

	if (user_info->lg_domain_type == SMB_DOMAIN_LOCAL)
		return;

	for (i = 0; i < NETLOGON_ATTEMPTS; ++i) {
		(void) mutex_lock(&netlogon_mutex);
		while (netlogon_busy && !netlogon_abort)
			(void) cond_wait(&netlogon_cv, &netlogon_mutex);

		if (netlogon_abort) {
			(void) mutex_unlock(&netlogon_mutex);
			user_info->lg_status = NT_STATUS_REQUEST_ABORTED;
			return;
		}

		netlogon_busy = B_TRUE;
		(void) mutex_unlock(&netlogon_mutex);

		status = netlogon_logon(user_info, token);

		(void) mutex_lock(&netlogon_mutex);
		netlogon_busy = B_FALSE;
		if (netlogon_abort)
			status = NT_STATUS_REQUEST_ABORTED;
		(void) cond_signal(&netlogon_cv);
		(void) mutex_unlock(&netlogon_mutex);

		if (status != NT_STATUS_CANT_ACCESS_DOMAIN_INFO)
			break;
	}

	if (status != NT_STATUS_SUCCESS)
		syslog(LOG_INFO, "logon[%s\\%s]: %s", user_info->lg_e_domain,
		    user_info->lg_e_username, xlate_nt_status(status));

	user_info->lg_status = status;
}

static uint32_t
netlogon_logon(smb_logon_t *user_info, smb_token_t *token)
{
	char resource_domain[SMB_PI_MAX_DOMAIN];
	char server[NETBIOS_NAME_SZ * 2];
	mlsvc_handle_t netr_handle;
	smb_domainex_t di;
	uint32_t status;
	int retries = 0;

	(void) smb_getdomainname(resource_domain, SMB_PI_MAX_DOMAIN);

	/* Avoid interfering with DC discovery. */
	if (smb_ddiscover_wait() != 0 ||
	    !smb_domain_getinfo(&di)) {
		netr_invalidate_chain();
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	do {
		if (netr_open(di.d_dc, di.d_primary.di_nbname, &netr_handle)
		    != 0)
			return (NT_STATUS_OPEN_FAILED);

		if (di.d_dc && (*netr_global_info.server != '\0')) {
			(void) snprintf(server, sizeof (server),
			    "\\\\%s", di.d_dc);
			if (strncasecmp(netr_global_info.server,
			    server, strlen(server)) != 0)
				netr_invalidate_chain();
		}

		if ((netr_global_info.flags & NETR_FLG_VALID) == 0 ||
		    !smb_match_netlogon_seqnum()) {
			status = netlogon_auth(di.d_dc, &netr_handle,
			    NETR_FLG_NULL);

			if (status != 0) {
				(void) netr_close(&netr_handle);
				return (NT_STATUS_LOGON_FAILURE);
			}

			netr_global_info.flags |= NETR_FLG_VALID;
		}

		status = netr_server_samlogon(&netr_handle,
		    &netr_global_info, di.d_dc, user_info, token);

		(void) netr_close(&netr_handle);
	} while (status == NT_STATUS_INSUFFICIENT_LOGON_INFO && retries++ < 3);

	if (retries >= 3)
		status = NT_STATUS_LOGON_FAILURE;

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
	if ((token->tkn_session_key = malloc(SMBAUTH_SESSION_KEY_SZ)) == NULL)
		return (NT_STATUS_NO_MEMORY);
	bzero(rc4key, SMBAUTH_SESSION_KEY_SZ);
	bcopy(netr_info->session_key.key, rc4key, netr_info->session_key.len);
	bcopy(info3->UserSessionKey.data, token->tkn_session_key,
	    SMBAUTH_SESSION_KEY_SZ);
	rand_hash((unsigned char *)token->tkn_session_key,
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
	struct netr_SamLogon arg;
	struct netr_authenticator auth;
	struct netr_authenticator ret_auth;
	struct netr_logon_info1 info1;
	struct netr_logon_info2 info2;
	struct netr_validation_info3 *info3;
	ndr_heap_t *heap;
	int opnum;
	int rc, len;
	uint32_t status;

	bzero(&arg, sizeof (struct netr_SamLogon));
	opnum = NETR_OPNUM_SamLogon;

	/*
	 * Should we get the server and hostname from netr_info?
	 */

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(netr_handle, len);
	arg.hostname = ndr_rpc_malloc(netr_handle, NETBIOS_NAME_SZ);
	if (arg.servername == NULL || arg.hostname == NULL) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	if (smb_getnetbiosname((char *)arg.hostname, NETBIOS_NAME_SZ) != 0) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = netr_setup_authenticator(netr_info, &auth, &ret_auth);
	if (rc != SMBAUTH_SUCCESS) {
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	arg.auth = &auth;
	arg.ret_auth = &ret_auth;
	arg.validation_level = NETR_VALIDATION_LEVEL3;
	arg.logon_info.logon_level = user_info->lg_level;
	arg.logon_info.switch_value = user_info->lg_level;

	heap = ndr_rpc_get_heap(netr_handle);

	switch (user_info->lg_level) {
	case NETR_INTERACTIVE_LOGON:
		netr_setup_identity(heap, user_info, &info1.identity);
		netr_interactive_samlogon(netr_info, user_info, &info1);
		arg.logon_info.ru.info1 = &info1;
		break;

	case NETR_NETWORK_LOGON:
		if (user_info->lg_challenge_key.len < 8 ||
		    user_info->lg_challenge_key.val == NULL) {
			ndr_rpc_release(netr_handle);
			return (NT_STATUS_INVALID_PARAMETER);
		}
		netr_setup_identity(heap, user_info, &info2.identity);
		netr_network_samlogon(heap, netr_info, user_info, &info2);
		arg.logon_info.ru.info2 = &info2;
		break;

	default:
		ndr_rpc_release(netr_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rc = ndr_rpc_call(netr_handle, opnum, &arg);
	if (rc != 0) {
		bzero(netr_info, sizeof (netr_info_t));
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);

		/*
		 * We need to validate the chain even though we have
		 * a non-zero status. If the status is ACCESS_DENIED
		 * this will trigger a new credential chain. However,
		 * a valid credential is returned with some status
		 * codes; for example, WRONG_PASSWORD.
		 */
		(void) netr_validate_chain(netr_info, arg.ret_auth);
	} else {
		status = netr_validate_chain(netr_info, arg.ret_auth);
		if (status == NT_STATUS_INSUFFICIENT_LOGON_INFO) {
			ndr_rpc_release(netr_handle);
			return (status);
		}

		info3 = arg.ru.info3;
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
	bzero(auth, sizeof (struct netr_authenticator));

	netr_info->timestamp = time(0);
	auth->timestamp = netr_info->timestamp;

	if (netr_gen_credentials(netr_info->session_key.key,
	    &netr_info->client_credential,
	    netr_info->timestamp,
	    (netr_cred_t *)&auth->credential) != SMBAUTH_SUCCESS)
		return (SMBAUTH_FAILURE);

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
	    netr_info->timestamp, &cred) != SMBAUTH_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	if (&auth->credential == 0) {
		/*
		 * If the validation fails, destroy the credential chain.
		 * This should trigger a new authentication chain.
		 */
		bzero(netr_info, sizeof (netr_info_t));
		return (NT_STATUS_INSUFFICIENT_LOGON_INFO);
	}

	result = memcmp(&cred, &auth->credential, sizeof (netr_cred_t));
	if (result != 0) {
		/*
		 * If the validation fails, destroy the credential chain.
		 * This should trigger a new authentication chain.
		 */
		bzero(netr_info, sizeof (netr_info_t));
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
netr_invalidate_chain(void)
{
	netr_global_info.flags &= ~NETR_FLG_VALID;
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

	identity->parameter_control = 0;
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
 * Sets up domain, local and well-known group membership for the given
 * token. Two assumptions have been made here:
 *
 *   a) token already contains a valid user SID so that group
 *      memberships can be established
 *
 *   b) token belongs to a domain user
 */
static uint32_t
netr_setup_token_wingrps(struct netr_validation_info3 *info3,
    smb_token_t *token)
{
	smb_ids_t tkn_grps;
	uint32_t status;

	tkn_grps.i_cnt = 0;
	tkn_grps.i_ids = NULL;

	status = netr_setup_domain_groups(info3, &tkn_grps);
	if (status != NT_STATUS_SUCCESS) {
		smb_ids_free(&tkn_grps);
		return (status);
	}

	status = smb_sam_usr_groups(token->tkn_user.i_sid, &tkn_grps);
	if (status != NT_STATUS_SUCCESS) {
		smb_ids_free(&tkn_grps);
		return (status);
	}

	if (netr_isadmin(info3))
		token->tkn_flags |= SMB_ATF_ADMIN;

	status = smb_wka_token_groups(token->tkn_flags, &tkn_grps);
	if (status == NT_STATUS_SUCCESS)
		token->tkn_win_grps = tkn_grps;
	else
		smb_ids_free(&tkn_grps);

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
 * Determines if the given user is the domain Administrator or a
 * member of Domain Admins
 */
static boolean_t
netr_isadmin(struct netr_validation_info3 *info3)
{
	smb_domain_t di;
	int i;

	if (!smb_domain_lookup_sid((smb_sid_t *)info3->LogonDomainId, &di))
		return (B_FALSE);

	if (di.di_type != SMB_DOMAIN_PRIMARY)
		return (B_FALSE);

	if ((info3->UserId == DOMAIN_USER_RID_ADMIN) ||
	    (info3->PrimaryGroupId == DOMAIN_GROUP_RID_ADMINS))
		return (B_TRUE);

	for (i = 0; i < info3->GroupCount; i++)
		if (info3->GroupIds[i].rid == DOMAIN_GROUP_RID_ADMINS)
			return (B_TRUE);

	return (B_FALSE);
}
