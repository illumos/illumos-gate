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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <smbsrv/libsmb.h>
#include <smbsrv/ndl/netlogon.ndl>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/netrauth.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/smb_token.h>

extern int netr_open(char *server, char *domain, mlsvc_handle_t *netr_handle);
extern int netr_close(mlsvc_handle_t *netr_handle);
extern DWORD netlogon_auth(char *server, mlsvc_handle_t *netr_handle,
    DWORD flags);
extern int netr_setup_authenticator(netr_info_t *, struct netr_authenticator *,
    struct netr_authenticator *);
extern DWORD netr_validate_chain(netr_info_t *, struct netr_authenticator *);

static DWORD netr_server_samlogon(mlsvc_handle_t *, netr_info_t *, char *,
    netr_client_t *, smb_userinfo_t *);
static void netr_invalidate_chain(void);
static void netr_interactive_samlogon(netr_info_t *, netr_client_t *,
    struct netr_logon_info1 *);
static void netr_network_samlogon(netr_info_t *, netr_client_t *,
    netr_response_t *, netr_response_t *, struct netr_logon_info2 *);
static void netr_setup_identity(mlrpc_heap_t *, netr_client_t *,
    netr_logon_id_t *);

/*
 * Shared with netr_auth.c
 */
extern netr_info_t netr_global_info;

/*
 * netlogon_logon
 *
 * This is the entry point for authenticating a remote logon. The
 * parameters here all refer to the remote user and workstation, i.e.
 * the domain is the user's account domain, not our primary domain.
 * In order to make it easy to track which domain is being used at
 * each stage, and to reduce the number of things being pushed on the
 * stack, the client information is bundled up in the clnt structure.
 *
 * If the user is successfully authenticated, an access token will be
 * built and NT_STATUS_SUCCESS will be returned. Otherwise a non-zero
 * NT status will be returned, in which case the token contents will
 * be invalid.
 */
DWORD
netlogon_logon(netr_client_t *clnt, smb_userinfo_t *user_info)
{
	char resource_domain[SMB_PI_MAX_DOMAIN];
	mlsvc_handle_t netr_handle;
	smb_ntdomain_t *di;
	DWORD status;
	int retries = 0;

	smb_config_rdlock();
	(void) strlcpy(resource_domain, smb_config_getstr(SMB_CI_DOMAIN_NAME),
	    sizeof (resource_domain));
	smb_config_unlock();

	/*
	 * If the SMB info cache is not valid,
	 * try to locate a domain controller.
	 */
	if ((di = smb_getdomaininfo(0)) == NULL) {
		(void) mlsvc_locate_domain_controller(resource_domain);

		if ((di = smb_getdomaininfo(0)) == NULL)
			return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	if ((mlsvc_echo(di->server)) < 0) {
		/*
		 * We had a session to the DC but it's not responding.
		 * So drop the credential chain and find another DC.
		 */
		netr_invalidate_chain();
		(void) mlsvc_locate_domain_controller(resource_domain);

		if ((di = smb_getdomaininfo(0)) == NULL)
			return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	do {
		status = netr_open(di->server, di->domain, &netr_handle);
		if (status != 0)
			return (status);

		if ((netr_global_info.flags & NETR_FLG_VALID) == 0) {
			status = netlogon_auth(di->server, &netr_handle,
			    NETR_FLG_NULL);

			if (status != 0) {
				(void) netr_close(&netr_handle);
				return (NT_STATUS_LOGON_FAILURE);
			}

			netr_global_info.flags |= NETR_FLG_VALID;
		}

		status = netr_server_samlogon(&netr_handle,
		    &netr_global_info, di->server, clnt, user_info);

		(void) netr_close(&netr_handle);
	} while (status == NT_STATUS_INSUFFICIENT_LOGON_INFO && retries++ < 3);

	if (retries >= 3)
		status = NT_STATUS_LOGON_FAILURE;

	return (status);
}

static DWORD
netr_setup_userinfo(struct netr_validation_info3 *info3,
    smb_userinfo_t *user_info, netr_client_t *clnt)
{
	smb_sid_attrs_t *other_grps;
	char *username, *domain;
	int i, nbytes;

	user_info->sid_name_use = SidTypeUser;
	user_info->rid = info3->UserId;
	user_info->primary_group_rid = info3->PrimaryGroupId;
	user_info->domain_sid = nt_sid_dup((nt_sid_t *)info3->LogonDomainId);

	if (user_info->domain_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	user_info->user_sid = nt_sid_splice(user_info->domain_sid,
	    user_info->rid);
	if (user_info->user_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	user_info->pgrp_sid = nt_sid_splice(user_info->domain_sid,
	    user_info->primary_group_rid);
	if (user_info->pgrp_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	username = (info3->EffectiveName.str)
	    ? (char *)info3->EffectiveName.str : clnt->username;
	domain = (info3->LogonDomainName.str)
	    ? (char *)info3->LogonDomainName.str : clnt->domain;

	if (username)
		user_info->name = strdup(username);
	if (domain)
		user_info->domain_name = strdup(domain);

	if (user_info->name == NULL || user_info->domain_name == NULL)
		return (NT_STATUS_NO_MEMORY);

	nbytes = info3->GroupCount * sizeof (smb_rid_attrs_t);
	if (nbytes) {
		if ((user_info->groups = malloc(nbytes)) != NULL) {
			user_info->n_groups = info3->GroupCount;
			(void) memcpy(user_info->groups,
			    info3->GroupIds, nbytes);
		} else {
			return (NT_STATUS_NO_MEMORY);
		}
	}

	nbytes = info3->SidCount * sizeof (smb_sid_attrs_t);
	if (nbytes) {
		if ((other_grps = malloc(nbytes)) != NULL) {
			user_info->other_grps = other_grps;
			for (i = 0; i < info3->SidCount; i++) {
				other_grps[i].attrs =
				    info3->ExtraSids[i].attributes;

				other_grps[i].sid = nt_sid_dup(
				    (nt_sid_t *)info3->ExtraSids[i].sid);

				if (other_grps[i].sid == NULL)
					break;
			}
			user_info->n_other_grps = i;
		} else {
			return (NT_STATUS_NO_MEMORY);
		}
	}

	mlsvc_setadmin_user_info(user_info);
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
DWORD
netr_server_samlogon(mlsvc_handle_t *netr_handle, netr_info_t *netr_info,
    char *server, netr_client_t *clnt, smb_userinfo_t *user_info)
{
	struct netr_SamLogon arg;
	struct netr_authenticator auth;
	struct netr_authenticator ret_auth;
	struct netr_logon_info1 info1;
	struct netr_logon_info2 info2;
	struct netr_validation_info3 *info3;
	netr_response_t nt_rsp;
	netr_response_t lm_rsp;
	mlrpc_heapref_t heap;
	int opnum;
	int rc, len;
	DWORD status;

	bzero(&arg, sizeof (struct netr_SamLogon));
	opnum = NETR_OPNUM_SamLogon;
	(void) mlsvc_rpc_init(&heap);

	/*
	 * Should we get the server and hostname from netr_info?
	 */
	len = strlen(server) + 4;
	arg.servername = alloca(len);
	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);

	arg.hostname = alloca(MLSVC_DOMAIN_NAME_MAX);
	rc = smb_gethostname((char *)arg.hostname, MLSVC_DOMAIN_NAME_MAX, 0);
	if (rc != 0) {
		mlrpc_heap_destroy(heap.heap);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = netr_setup_authenticator(netr_info, &auth, &ret_auth);
	if (rc != SMBAUTH_SUCCESS) {
		mlrpc_heap_destroy(heap.heap);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	arg.auth = &auth;
	arg.ret_auth = &ret_auth;
	arg.validation_level = NETR_VALIDATION_LEVEL3;
	arg.logon_info.logon_level = clnt->logon_level;
	arg.logon_info.switch_value = clnt->logon_level;

	switch (clnt->logon_level) {
	case NETR_INTERACTIVE_LOGON:
		netr_setup_identity(heap.heap, clnt, &info1.identity);
		netr_interactive_samlogon(netr_info, clnt, &info1);
		arg.logon_info.ru.info1 = &info1;
		break;

	case NETR_NETWORK_LOGON:
		netr_setup_identity(heap.heap, clnt, &info2.identity);
		netr_network_samlogon(netr_info, clnt, &nt_rsp, &lm_rsp,
		    &info2);
		arg.logon_info.ru.info2 = &info2;
		break;

	default:
		mlrpc_heap_destroy(heap.heap);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rc = mlsvc_rpc_call(netr_handle->context, opnum, &arg, &heap);
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
			mlsvc_rpc_free(netr_handle->context, &heap);
			return (status);
		}

		info3 = arg.ru.info3;
		status = netr_setup_userinfo(info3, user_info, clnt);
	}

	mlsvc_rpc_free(netr_handle->context, &heap);
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
netr_interactive_samlogon(netr_info_t *netr_info, netr_client_t *clnt,
    struct netr_logon_info1 *info1)
{
	BYTE key[NETR_OWF_PASSWORD_SZ];

	(void) memcpy(&info1->lm_owf_password,
	    clnt->lm_password.lm_password_val, sizeof (netr_owf_password_t));

	(void) memcpy(&info1->nt_owf_password,
	    clnt->nt_password.nt_password_val, sizeof (netr_owf_password_t));

	(void) memset(key, 0, NETR_OWF_PASSWORD_SZ);
	(void) memcpy(key, netr_info->session_key, NETR_SESSION_KEY_SZ);

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
netr_network_samlogon(netr_info_t *netr_info, netr_client_t *clnt,
    netr_response_t *ntr, netr_response_t *lmr, struct netr_logon_info2 *info2)
{
	bcopy(clnt->challenge_key.challenge_key_val, info2->lm_challenge.data,
	    8);

	if (clnt->nt_password.nt_password_len == NETR_CR_PASSWORD_SIZE) {
		ntr->length = NETR_CR_PASSWORD_SIZE;
		ntr->start = 0;
		ntr->max_length = NETR_CR_PASSWORD_SIZE;
		bcopy(clnt->nt_password.nt_password_val, ntr->data,
		    NETR_CR_PASSWORD_SIZE);

		info2->nt_response.length = NETR_CR_PASSWORD_SIZE;
		info2->nt_response.max_length = NETR_CR_PASSWORD_SIZE;
		info2->nt_response.data = ntr;
	} else {
		info2->nt_response.length = 0;
		info2->nt_response.max_length = 0;
		info2->nt_response.data = 0;
	}

	if (clnt->lm_password.lm_password_len == NETR_CR_PASSWORD_SIZE) {
		lmr->length = NETR_CR_PASSWORD_SIZE;
		lmr->start = 0;
		lmr->max_length = NETR_CR_PASSWORD_SIZE;
		bcopy(clnt->lm_password.lm_password_val, lmr->data,
		    NETR_CR_PASSWORD_SIZE);

		info2->lm_response.length = NETR_CR_PASSWORD_SIZE;
		info2->lm_response.max_length = NETR_CR_PASSWORD_SIZE;
		info2->lm_response.data = lmr;
	} else {
		info2->lm_response.length = 0;
		info2->lm_response.max_length = 0;
		info2->lm_response.data = 0;
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

#ifdef _BIG_ENDIAN
	netr_info->timestamp = 0;
#else
	netr_info->timestamp = time(0) << 8;
#endif
	auth->timestamp = netr_info->timestamp;

	if (netr_gen_credentials(netr_info->session_key,
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
 * The only quirk is the DWORD style addition.
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
DWORD
netr_validate_chain(netr_info_t *netr_info, struct netr_authenticator *auth)
{
	netr_cred_t cred;
	DWORD result = NT_STATUS_SUCCESS;
	DWORD *dwp;

	++netr_info->timestamp;

	if (netr_gen_credentials(netr_info->session_key,
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
		dwp = (DWORD *)&netr_info->client_credential;
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
netr_setup_identity(mlrpc_heap_t *heap, netr_client_t *clnt,
    netr_logon_id_t *identity)
{
	static DWORD logon_id;

	if (logon_id == 0)
		logon_id = 0xDCD0;

	++logon_id;
	clnt->logon_id = logon_id;

	identity->parameter_control = 0;
	identity->logon_id.LowPart = logon_id;
	identity->logon_id.HighPart = 0;

	mlrpc_heap_mkvcs(heap, clnt->domain,
	    (mlrpc_vcbuf_t *)&identity->domain_name);

	mlrpc_heap_mkvcs(heap, clnt->username,
	    (mlrpc_vcbuf_t *)&identity->username);

	/*
	 * Some systems prefix the client workstation name with \\.
	 * It doesn't seem to make any difference whether it's there
	 * or not.
	 */
	mlrpc_heap_mkvcs(heap, clnt->workstation,
	    (mlrpc_vcbuf_t *)&identity->workstation);
}
