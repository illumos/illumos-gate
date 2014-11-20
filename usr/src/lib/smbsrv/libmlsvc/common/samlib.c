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
 * This module provides the high level interface to the SAM RPC
 * functions.
 */

#include <sys/types.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>

#include <alloca.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ntaccess.h>
#include <lsalib.h>
#include <samlib.h>

#ifdef _LITTLE_ENDIAN
/* little-endian values on little-endian */
#define	htolel(x)	((uint32_t)(x))
#define	letohl(x)	((uint32_t)(x))
#else	/* (BYTE_ORDER == LITTLE_ENDIAN) */
/* little-endian values on big-endian (swap) */
#define	letohl(x) 	BSWAP_32(x)
#define	htolel(x) 	BSWAP_32(x)
#endif	/* (BYTE_ORDER == LITTLE_ENDIAN) */

/*
 * Valid values for the OEM OWF password encryption.
 */
#define	SAM_KEYLEN		16

static void samr_fill_userpw(struct samr_user_password *, const char *);
static void samr_make_encrypted_password(
	struct samr_encr_passwd *epw,
	char *new_pw_clear,
	uint8_t *crypt_key);


/*
 * Todo: Implement "unjoin" domain, which would use the
 * sam_remove_trust_account code below.
 */

/*
 * sam_remove_trust_account
 *
 * Attempt to remove the workstation trust account for this system.
 * Administrator access is required to perform this operation.
 *
 * Returns NT status codes.
 */
DWORD
sam_remove_trust_account(char *server, char *domain)
{
	char account_name[SMB_SAMACCT_MAXLEN];

	if (smb_getsamaccount(account_name, SMB_SAMACCT_MAXLEN) != 0)
		return (NT_STATUS_INTERNAL_ERROR);

	return (sam_delete_account(server, domain, account_name));
}


/*
 * sam_delete_account
 *
 * Attempt to remove an account from the SAM database on the specified
 * server.
 *
 * Returns NT status codes.
 */
DWORD
sam_delete_account(char *server, char *domain_name, char *account_name)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	mlsvc_handle_t user_handle;
	smb_account_t ainfo;
	smb_sid_t *sid;
	DWORD access_mask;
	DWORD status;
	int rc;
	char user[SMB_USERNAME_MAXLEN];

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	rc = samr_open(server, domain_name, user, SAM_LOOKUP_INFORMATION,
	    &samr_handle);
	if (rc != 0)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	sid = samr_lookup_domain(&samr_handle, domain_name);
	if (sid == NULL) {
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto out_samr_hdl;
	}

	status = samr_open_domain(&samr_handle, SAM_LOOKUP_INFORMATION,
	    (struct samr_sid *)sid, &domain_handle);
	if (status != NT_STATUS_SUCCESS)
		goto out_sid_ptr;

	status = samr_lookup_domain_names(&domain_handle, account_name, &ainfo);
	if (status != NT_STATUS_SUCCESS)
		goto out_dom_hdl;

	access_mask = STANDARD_RIGHTS_EXECUTE | DELETE;
	status = samr_open_user(&domain_handle, access_mask,
	    ainfo.a_rid, &user_handle);
	if (status != NT_STATUS_SUCCESS)
		goto out_dom_hdl;

	status = samr_delete_user(&user_handle);

	(void) samr_close_handle(&user_handle);
out_dom_hdl:
	(void) samr_close_handle(&domain_handle);
out_sid_ptr:
	free(sid);
out_samr_hdl:
	(void) samr_close_handle(&samr_handle);

	return (status);
}


/*
 * sam_lookup_name
 *
 * Lookup an account name in the SAM database on the specified domain
 * controller. Provides the account RID on success.
 *
 * Returns NT status codes.
 */
DWORD
sam_lookup_name(char *server, char *domain_name, char *account_name,
    DWORD *rid_ret)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	smb_account_t ainfo;
	struct samr_sid *domain_sid;
	int rc;
	DWORD status;
	char user[SMB_USERNAME_MAXLEN];

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	*rid_ret = 0;

	rc = samr_open(server, domain_name, user, SAM_LOOKUP_INFORMATION,
	    &samr_handle);

	if (rc != 0)
		return (NT_STATUS_OPEN_FAILED);

	domain_sid = (struct samr_sid *)samr_lookup_domain(&samr_handle,
	    domain_name);
	if (domain_sid == NULL) {
		(void) samr_close_handle(&samr_handle);
		return (NT_STATUS_NO_SUCH_DOMAIN);
	}

	status = samr_open_domain(&samr_handle, SAM_LOOKUP_INFORMATION,
	    domain_sid, &domain_handle);
	if (status == NT_STATUS_SUCCESS) {
		status = samr_lookup_domain_names(&domain_handle,
		    account_name, &ainfo);
		if (status == NT_STATUS_SUCCESS)
			*rid_ret = ainfo.a_rid;

		(void) samr_close_handle(&domain_handle);
	}

	(void) samr_close_handle(&samr_handle);
	return (status);
}

/*
 * sam_get_local_domains
 *
 * Query a remote server to get the list of local domains that it
 * supports.
 *
 * Returns NT status codes.
 */
DWORD
sam_get_local_domains(char *server, char *domain_name)
{
	mlsvc_handle_t samr_handle;
	DWORD status;
	int rc;
	char user[SMB_USERNAME_MAXLEN];

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	rc = samr_open(server, domain_name, user, SAM_ENUM_LOCAL_DOMAIN,
	    &samr_handle);
	if (rc != 0)
		return (NT_STATUS_OPEN_FAILED);

	status = samr_enum_local_domains(&samr_handle);
	(void) samr_close_handle(&samr_handle);
	return (status);
}

/*
 * Set the account control flags on some account for which we
 * have already opened a SAM handle with appropriate rights,
 * passed in here as sam_handle, along with the new flags.
 */
DWORD
netr_set_user_control(
	mlsvc_handle_t *user_handle,
	DWORD UserAccountControl)
{
	struct samr_SetUserInfo16 info;

	info.UserAccountControl = UserAccountControl;
	return (samr_set_user_info(user_handle, 16, &info));
}

/*
 * Set the password on some account, for which we have already
 * opened a SAM handle with appropriate rights, passed in here
 * as sam_handle, along with the new password as cleartext.
 *
 * This builds a struct SAMPR_USER_INTERNAL5_INFORMATION [MS-SAMR]
 * containing the new password, encrypted with our session key.
 */
DWORD
netr_set_user_password(
	mlsvc_handle_t *user_handle,
	char *new_pw_clear)
{
	unsigned char ssn_key[SMBAUTH_HASH_SZ];
	struct samr_SetUserInfo24 info;

	if (ndr_rpc_get_ssnkey(user_handle, ssn_key, SMBAUTH_HASH_SZ))
		return (NT_STATUS_INTERNAL_ERROR);

	(void) memset(&info, 0, sizeof (info));
	samr_make_encrypted_password(&info.encr_pw, new_pw_clear, ssn_key);

	/* Rather not leave the session key around. */
	(void) memset(ssn_key, 0, sizeof (ssn_key));

	return (samr_set_user_info(user_handle, 24, &info));
}

/*
 * Change a password like NetUserChangePassword(),
 * but where we already know which AD server to use,
 * so we don't request the domain name or search for
 * an AD server for that domain here.
 */
DWORD
netr_change_password(
	char *server,
	char *account,
	char *old_pw_clear,
	char *new_pw_clear)
{
	struct samr_encr_passwd epw;
	struct samr_encr_hash old_hash;
	uint8_t old_nt_hash[SAMR_PWHASH_LEN];
	uint8_t new_nt_hash[SAMR_PWHASH_LEN];
	mlsvc_handle_t handle;
	DWORD rc;

	/*
	 * Create an RPC handle to this server, bound to SAMR.
	 */
	rc = ndr_rpc_bind(&handle, server, "", "", "SAMR");
	if (rc)
		return (RPC_NT_SERVER_UNAVAILABLE);

	/*
	 * Encrypt the new p/w (plus random filler) with the
	 * old password, and send the old p/w encrypted with
	 * the new p/w hash to prove we know the old p/w.
	 * Details:  [MS-SAMR 3.1.5.10.3]
	 */
	(void) smb_auth_ntlm_hash(old_pw_clear, old_nt_hash);
	(void) smb_auth_ntlm_hash(new_pw_clear, new_nt_hash);
	samr_make_encrypted_password(&epw, new_pw_clear, old_nt_hash);

	(void) smb_auth_DES(old_hash.data, SAMR_PWHASH_LEN,
	    new_nt_hash, 14, /* key */
	    old_nt_hash, SAMR_PWHASH_LEN);

	/*
	 * Finally, ready to try the OtW call.
	 */
	rc = samr_change_password(
	    &handle, server, account,
	    &epw, &old_hash);

	/* Avoid leaving cleartext (or equivalent) around. */
	(void) memset(old_nt_hash, 0, sizeof (old_nt_hash));
	(void) memset(new_nt_hash, 0, sizeof (new_nt_hash));

	ndr_rpc_unbind(&handle);
	return (rc);
}

/*
 * Build an encrypted password, as used by samr_set_user_info
 * and samr_change_password.  Note: This builds the unencrypted
 * form in one union arm, and encrypts it in the other union arm.
 */
void
samr_make_encrypted_password(
	struct samr_encr_passwd *epw,
	char *new_pw_clear,
	uint8_t *crypt_key)
{
	union {
		struct samr_user_password u;
		struct samr_encr_passwd e;
	} pwu;

	samr_fill_userpw(&pwu.u, new_pw_clear);

	(void) smb_auth_RC4(pwu.e.data, sizeof (pwu.e.data),
	    crypt_key, SAMR_PWHASH_LEN,
	    pwu.e.data, sizeof (pwu.e.data));

	(void) memcpy(epw->data, pwu.e.data, sizeof (pwu.e.data));
	(void) memset(pwu.e.data, 0, sizeof (pwu.e.data));
}

/*
 * This fills in a samr_user_password (a.k.a. SAMPR_USER_PASSWORD
 * in the MS Net API) which has the new password "right justified"
 * in the buffer, and any space on the left filled with random junk
 * to improve the quality of the encryption that is subsequently
 * applied to this buffer before it goes over the wire.
 */
static void
samr_fill_userpw(struct samr_user_password *upw, const char *new_pw)
{
	smb_wchar_t *pbuf;
	uint32_t pwlen_bytes;
	size_t pwlen_wchars;

	/*
	 * First fill the whole buffer with the random junk.
	 * (Slightly less random when debugging:)
	 */
#ifdef DEBUG
	(void) memset(upw->Buffer, '*', sizeof (upw->Buffer));
#else
	randomize((char *)upw->Buffer, sizeof (upw->Buffer));
#endif

	/*
	 * Now overwrite the last pwlen characters of
	 * that buffer with the password, and set the
	 * length field so the receiving end knows where
	 * the junk ends and the real password starts.
	 */
	pwlen_wchars = smb_wcequiv_strlen(new_pw) / 2;
	if (pwlen_wchars > SAMR_USER_PWLEN)
		pwlen_wchars = SAMR_USER_PWLEN;
	pwlen_bytes = pwlen_wchars * 2;

	pbuf = &upw->Buffer[SAMR_USER_PWLEN - pwlen_wchars];
	(void) smb_mbstowcs(pbuf, new_pw, pwlen_wchars);

	/* Yes, this is in Bytes, not wchars. */
	upw->Length = htolel(pwlen_bytes);
}
