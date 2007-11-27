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
 * NETR challenge/response client functions.
 *
 * NT_STATUS_INVALID_PARAMETER
 * NT_STATUS_NO_TRUST_SAM_ACCOUNT
 * NT_STATUS_ACCESS_DENIED
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/netlogon.ndl>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/netrauth.h>

int netr_setup_authenticator(netr_info_t *, struct netr_authenticator *,
    struct netr_authenticator *);
DWORD netr_validate_chain(netr_info_t *, struct netr_authenticator *);

static int netr_server_req_challenge(mlsvc_handle_t *, netr_info_t *);
static int netr_server_authenticate2(mlsvc_handle_t *, netr_info_t *);
static int netr_gen_password(BYTE *, BYTE *, BYTE *);

/*
 * Shared with netr_logon.c
 */
netr_info_t netr_global_info;

/*
 * netlogon_auth
 *
 * This is the core of the NETLOGON authentication protocol.
 * Do the challenge response authentication.
 *
 * Prior to calling this function, an anonymous session to the NETLOGON
 * pipe on a domain controller(server) should have already been opened.
 */
DWORD
netlogon_auth(char *server, mlsvc_handle_t *netr_handle, DWORD flags)
{
	netr_info_t *netr_info;
	int rc;
	DWORD leout_rc[2];

	netr_info = &netr_global_info;
	bzero(netr_info, sizeof (netr_info_t));

	netr_info->flags |= flags;

	rc = smb_getnetbiosname(netr_info->hostname, MLSVC_DOMAIN_NAME_MAX);
	if (rc != 0)
		return (NT_STATUS_UNSUCCESSFUL);

	(void) snprintf(netr_info->server, sizeof (netr_info->server),
	    "\\\\%s", server);

	LE_OUT32(&leout_rc[0], random());
	LE_OUT32(&leout_rc[1], random());
	(void) memcpy(&netr_info->client_challenge, leout_rc,
	    sizeof (struct netr_credential));

	if ((rc = netr_server_req_challenge(netr_handle, netr_info)) == 0) {
		rc = netr_server_authenticate2(netr_handle, netr_info);
		if (rc == 0)
			netr_info->flags |= NETR_FLG_VALID;
	}

	return ((rc) ? NT_STATUS_UNSUCCESSFUL : NT_STATUS_SUCCESS);
}

/*
 * netr_open
 *
 * Open an anonymous session to the NETLOGON pipe on a domain
 * controller and bind to the NETR RPC interface. We store the
 * remote server's native OS type - we may need it due to
 * differences between versions of Windows.
 */
int
netr_open(char *server, char *domain, mlsvc_handle_t *netr_handle)
{
	int fid;
	int remote_os = 0;
	int remote_lm = 0;
	int server_pdc;
	char *user = smbrdr_ipc_get_user();

	if (mlsvc_logon(server, domain, user) != 0)
		return (-1);

	fid = mlsvc_open_pipe(server, domain, user, "\\NETLOGON");
	if (fid < 0)
		return (-1);

	if (mlsvc_rpc_bind(netr_handle, fid, "NETR") < 0) {
		(void) mlsvc_close_pipe(fid);
		return (-1);
	}

	(void) mlsvc_session_native_values(fid, &remote_os, &remote_lm,
	    &server_pdc);
	netr_handle->context->server_os = remote_os;
	netr_handle->context->server_pdc = server_pdc;
	return (0);
}

/*
 * netr_close
 *
 * Close a NETLOGON pipe and free the RPC context.
 */
int
netr_close(mlsvc_handle_t *netr_handle)
{
	(void) mlsvc_close_pipe(netr_handle->context->fid);
	free(netr_handle->context);
	return (0);
}

/*
 * netr_server_req_challenge
 */
static int
netr_server_req_challenge(mlsvc_handle_t *netr_handle, netr_info_t *netr_info)
{
	struct netr_ServerReqChallenge arg;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	bzero(&arg, sizeof (struct netr_ServerReqChallenge));
	opnum = NETR_OPNUM_ServerReqChallenge;

	arg.servername = (unsigned char *)netr_info->server;
	arg.hostname = (unsigned char *)netr_info->hostname;

	(void) memcpy(&arg.client_challenge, &netr_info->client_challenge,
	    sizeof (struct netr_credential));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(netr_handle->context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			mlsvc_rpc_report_status(opnum, arg.status);
			rc = -1;
		} else {
			(void) memcpy(&netr_info->server_challenge,
			    &arg.server_challenge,
			    sizeof (struct netr_credential));
		}
	}

	mlsvc_rpc_free(netr_handle->context, &heap);
	return (rc);
}

/*
 * netr_server_authenticate2
 */
static int
netr_server_authenticate2(mlsvc_handle_t *netr_handle, netr_info_t *netr_info)
{
	struct netr_ServerAuthenticate2 arg;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;
	char account_name[MLSVC_DOMAIN_NAME_MAX * 2];

	bzero(&arg, sizeof (struct netr_ServerAuthenticate2));
	opnum = NETR_OPNUM_ServerAuthenticate2;

	(void) snprintf(account_name, sizeof (account_name), "%s$",
	    netr_info->hostname);

	arg.servername = (unsigned char *)netr_info->server;
	arg.account_name = (unsigned char *)account_name;
	arg.account_type = NETR_WKSTA_TRUST_ACCOUNT_TYPE;
	arg.hostname = (unsigned char *)netr_info->hostname;
	arg.negotiate_flags = NETR_NEGOTIATE_FLAGS;

	smb_tracef("server=[%s] account_name=[%s] hostname=[%s]\n",
	    netr_info->server, account_name, netr_info->hostname);

	if (netr_gen_session_key(netr_info) != SMBAUTH_SUCCESS)
		return (-1);

	if (netr_gen_credentials(netr_info->session_key,
	    &netr_info->client_challenge,
	    0,
	    &netr_info->client_credential) != SMBAUTH_SUCCESS) {
		return (-1);
	}

	if (netr_gen_credentials(netr_info->session_key,
	    &netr_info->server_challenge,
	    0,
	    &netr_info->server_credential) != SMBAUTH_SUCCESS) {
		return (-1);
	}

	(void) memcpy(&arg.client_credential, &netr_info->client_credential,
	    sizeof (struct netr_credential));

	(void) mlsvc_rpc_init(&heap);

	rc = mlsvc_rpc_call(netr_handle->context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			mlsvc_rpc_report_status(opnum, arg.status);
			rc = -1;
		} else {
			rc = memcmp(&netr_info->server_credential,
			    &arg.server_credential,
			    sizeof (struct netr_credential));
		}
	}

	mlsvc_rpc_free(netr_handle->context, &heap);
	return (rc);
}

/*
 * netr_gen_session_key
 *
 * Generate a session key from the client and server challenges. The
 * algorithm is a two stage hash. For the first hash, the input is
 * the combination of the client and server challenges, the key is
 * the first 8 bytes of the password. The initial password is formed
 * using the NT password hash on the local hostname in lower case.
 * The result is stored in a temporary buffer.
 *
 *		input:	challenge
 *		key:	passwd lower 8 bytes
 *		output:	intermediate result
 *
 * For the second hash, the input is the result of the first hash and
 * the key is the last 8 bytes of the password.
 *
 *		input:	result of first hash
 *		key:	passwd upper 8 bytes
 *		output:	session_key
 *
 * The final output should be the session key.
 *
 *		FYI: smb_auth_DES(output, key, input)
 *
 * If any difficulties occur using the cryptographic framework, the
 * function returns SMBAUTH_FAILURE.  Otherwise SMBAUTH_SUCCESS is
 * returned.
 */
int
netr_gen_session_key(netr_info_t *netr_info)
{
	unsigned char md4hash[32];
	unsigned char buffer[8];
	DWORD data[2];
	DWORD *client_challenge;
	DWORD *server_challenge;
	int rc;
	char *machine_passwd;
	DWORD le_data[2];

	client_challenge = (DWORD *)(uintptr_t)&netr_info->client_challenge;
	server_challenge = (DWORD *)(uintptr_t)&netr_info->server_challenge;
	bzero(md4hash, 32);

	/*
	 * We should check (netr_info->flags & NETR_FLG_INIT) and use
	 * the appropriate password but it isn't working yet.  So we
	 * always use the default one for now.
	 */
	smb_config_rdlock();
	machine_passwd = smb_config_getstr(SMB_CI_MACHINE_PASSWD);

	if (!machine_passwd || *machine_passwd == 0) {
		smb_config_unlock();
		return (-1);
	}

	bzero(netr_info->password, sizeof (netr_info->password));
	(void) strlcpy((char *)netr_info->password, (char *)machine_passwd,
	    sizeof (netr_info->password));

	rc = smb_auth_ntlm_hash((char *)machine_passwd, md4hash);
	smb_config_unlock();

	if (rc != SMBAUTH_SUCCESS)
		return (SMBAUTH_FAILURE);

	data[0] = LE_IN32(&client_challenge[0]) + LE_IN32(&server_challenge[0]);
	data[1] = LE_IN32(&client_challenge[1]) + LE_IN32(&server_challenge[1]);
	LE_OUT32(&le_data[0], data[0]);
	LE_OUT32(&le_data[1], data[1]);

	rc = smb_auth_DES(buffer, 8, md4hash, 8, (unsigned char *)le_data, 8);
	if (rc != SMBAUTH_SUCCESS)
		return (rc);

	rc = smb_auth_DES(netr_info->session_key, 8, &md4hash[9], 8, buffer, 8);
	return (rc);
}

/*
 * netr_gen_credentials
 *
 * Generate a set of credentials from a challenge and a session key.
 * The algorithm is a two stage hash. For the first hash, the
 * timestamp is added to the challenge and the result is stored in a
 * temporary buffer:
 *
 *		input:	challenge (including timestamp)
 *		key:	session_key
 *		output:	intermediate result
 *
 * For the second hash, the input is the result of the first hash and
 * a strange partial key is used:
 *
 *		input:	result of first hash
 *		key:	funny partial key
 *		output:	credentiails
 *
 * The final output should be an encrypted set of credentials.
 *
 *		FYI: smb_auth_DES(output, key, input)
 *
 * If any difficulties occur using the cryptographic framework, the
 * function returns SMBAUTH_FAILURE.  Otherwise SMBAUTH_SUCCESS is
 * returned.
 */
int
netr_gen_credentials(BYTE *session_key, netr_cred_t *challenge,
    DWORD timestamp, netr_cred_t *out_cred)
{
	unsigned char buffer[8];
	unsigned char partial_key[8];
	DWORD data[2];
	DWORD le_data[2];
	DWORD *p;
	int rc;

	p = (DWORD *)(uintptr_t)challenge;
	data[0] = LE_IN32(&p[0]) + timestamp;
	data[1] = LE_IN32(&p[1]);

	LE_OUT32(&le_data[0], data[0]);
	LE_OUT32(&le_data[1], data[1]);

	if (smb_auth_DES(buffer, 8, session_key, 8,
	    (unsigned char *)le_data, 8) != SMBAUTH_SUCCESS)
		return (SMBAUTH_FAILURE);

	bzero(partial_key, 8);
	partial_key[0] = session_key[7];

	rc = smb_auth_DES((unsigned char *)out_cred, 8, partial_key, 8,
	    buffer, 8);
	return (rc);
}

/*
 * netr_server_password_set
 *
 * Attempt to change the trust account password for this system.
 *
 * Note that this call may legitimately fail if the registry on the
 * domain controller has been setup to deny attempts to change the
 * trust account password. In this case we should just continue to
 * use the original password.
 *
 * Possible status values:
 *	NT_STATUS_ACCESS_DENIED
 */
int
netr_server_password_set(mlsvc_handle_t *netr_handle, netr_info_t *netr_info)
{
	struct netr_PasswordSet  arg;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;
	BYTE new_password[NETR_OWF_PASSWORD_SZ];
	char account_name[MLSVC_DOMAIN_NAME_MAX * 2];

	bzero(&arg, sizeof (struct netr_PasswordSet));
	opnum = NETR_OPNUM_ServerPasswordSet;

	(void) snprintf(account_name, sizeof (account_name), "%s$",
	    netr_info->hostname);

	arg.servername = (unsigned char *)netr_info->server;
	arg.account_name = (unsigned char *)account_name;
	arg.account_type = NETR_WKSTA_TRUST_ACCOUNT_TYPE;
	arg.hostname = (unsigned char *)netr_info->hostname;

	/*
	 * Set up the client side authenticator.
	 */
	if (netr_setup_authenticator(netr_info, &arg.auth, 0) !=
	    SMBAUTH_SUCCESS) {
		return (-1);
	}

	/*
	 * Generate a new password from the old password.
	 */
	if (netr_gen_password(netr_info->session_key,
	    netr_info->password, new_password) == SMBAUTH_FAILURE) {
		return (-1);
	}

	(void) memcpy(&arg.uas_new_password, &new_password,
	    NETR_OWF_PASSWORD_SZ);

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(netr_handle->context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0)) {
		mlsvc_rpc_report_status(opnum, arg.status);
		mlsvc_rpc_free(netr_handle->context, &heap);
		return (-1);
	}

	/*
	 * Check the returned credentials.  The server returns the new
	 * client credential rather than the new server credentiali,
	 * as documented elsewhere.
	 *
	 * Generate the new seed for the credential chain.  Increment
	 * the timestamp and add it to the client challenge.  Then we
	 * need to copy the challenge to the credential field in
	 * preparation for the next cycle.
	 */
	if (netr_validate_chain(netr_info, &arg.auth) == 0) {
		/*
		 * Save the new password.
		 */
		(void) memcpy(netr_info->password, new_password,
		    NETR_OWF_PASSWORD_SZ);
	}

	mlsvc_rpc_free(netr_handle->context, &heap);
	return (0);
}

/*
 * netr_gen_password
 *
 * Generate a new pasword from the old password  and the session key.
 * The algorithm is a two stage hash. The session key is used in the
 * first hash but only part of the session key is used in the second
 * hash.
 *
 * If any difficulties occur using the cryptographic framework, the
 * function returns SMBAUTH_FAILURE.  Otherwise SMBAUTH_SUCCESS is
 * returned.
 */
static int
netr_gen_password(BYTE *session_key, BYTE *old_password, BYTE *new_password)
{
	unsigned char partial_key[8];
	int rv;

	rv = smb_auth_DES(new_password, 8, session_key, 8, old_password, 8);
	if (rv != SMBAUTH_SUCCESS)
		return (rv);

	bzero(partial_key, 8);
	partial_key[0] = session_key[7];

	rv = smb_auth_DES(&new_password[8], 8, partial_key, 8,
	    &old_password[8], 8);
	return (rv);
}
