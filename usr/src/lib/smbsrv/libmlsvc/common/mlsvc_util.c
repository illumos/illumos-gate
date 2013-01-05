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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Utility functions to support the RPC interface library.
 */

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <note.h>
#include <syslog.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/netrauth.h>
#include <libsmbrdr.h>
#include <lsalib.h>
#include <samlib.h>
#include <mlsvc.h>

static DWORD
mlsvc_join_rpc(smb_domainex_t *dxi,
	char *admin_user, char *admin_pw,
	char *machine_name, char *machine_pw);
static DWORD
mlsvc_join_noauth(smb_domainex_t *dxi,
	char *machine_name, char *machine_pw);


DWORD
mlsvc_netlogon(char *server, char *domain)
{
	mlsvc_handle_t netr_handle;
	DWORD status;

	status = netr_open(server, domain, &netr_handle);
	if (status != 0) {
		syslog(LOG_NOTICE, "Failed to connect to %s "
		    "for domain %s (%s)", server, domain,
		    xlate_nt_status(status));
		return (status);
	}

	status = netlogon_auth(server, &netr_handle, NETR_FLG_INIT);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE, "Failed to establish NETLOGON "
		    "credential chain with DC: %s (%s)", server,
		    xlate_nt_status(status));
		syslog(LOG_NOTICE, "The machine account information on the "
		    "domain controller does not match the local storage.");
		syslog(LOG_NOTICE, "To correct this, use 'smbadm join'");
	}
	(void) netr_close(&netr_handle);

	return (status);
}

/*
 * Join the specified domain.  The method varies depending on whether
 * we're using "secure join" (using an administrative account to join)
 * or "unsecure join" (using a pre-created machine account).  In the
 * latter case, the machine account is created "by hand" before this
 * machine attempts to join, and we just change the password from the
 * (weak) default password for a new machine account to a random one.
 *
 * Returns NT status codes.
 */
void
mlsvc_join(smb_joininfo_t *info, smb_joinres_t *res)
{
	static unsigned char zero_hash[SMBAUTH_HASH_SZ];
	char machine_name[SMB_SAMACCT_MAXLEN];
	char machine_pw[NETR_MACHINE_ACCT_PASSWD_MAX];
	unsigned char passwd_hash[SMBAUTH_HASH_SZ];
	smb_domainex_t dxi;
	smb_domain_t *di = &dxi.d_primary;
	DWORD status;
	int rc;

	bzero(&dxi, sizeof (dxi));

	/*
	 * Domain join support: AD (Kerberos+LDAP) or MS-RPC?
	 */
	boolean_t ads_enabled = smb_config_get_ads_enable();

	if (smb_getsamaccount(machine_name, sizeof (machine_name)) != 0) {
		res->status = NT_STATUS_INVALID_COMPUTER_NAME;
		return;
	}

	(void) smb_gen_random_passwd(machine_pw, sizeof (machine_pw));

	/*
	 * Ensure that any previous membership of this domain has
	 * been cleared from the environment before we start. This
	 * will ensure that we don't attempt a NETLOGON_SAMLOGON
	 * when attempting to find the PDC.
	 */
	(void) smb_config_setbool(SMB_CI_DOMAIN_MEMB, B_FALSE);

	if (info->domain_username[0] != '\0') {
		(void) smb_auth_ntlm_hash(info->domain_passwd, passwd_hash);
		smb_ipc_set(info->domain_username, passwd_hash);
	} else {
		smb_ipc_set(MLSVC_ANON_USER, zero_hash);
	}

	/*
	 * Tentatively set the idmap domain to the one we're joining,
	 * so that the DC locator in idmap knows what to look for.
	 * Ditto the SMB server domain.
	 */
	if (smb_config_set_idmap_domain(info->domain_name) != 0)
		syslog(LOG_NOTICE, "Failed to set idmap domain name");
	if (smb_config_refresh_idmap() != 0)
		syslog(LOG_NOTICE, "Failed to refresh idmap service");

	/* Clear DNS local (ADS) lookup cache. */
	smb_ads_refresh(B_FALSE);

	/*
	 * Locate a DC for this domain.  Intentionally bypass the
	 * ddiscover service here because we're still joining.
	 * This also allows better reporting of any failures.
	 */
	status = smb_ads_lookup_msdcs(info->domain_name, &dxi.d_dci);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR,
		    "smbd: failed to locate AD server for domain %s (%s)",
		    info->domain_name, xlate_nt_status(status));
		goto out;
	}

	/*
	 * Found a DC.  Report what we found along with the return status
	 * so that admin will know which AD server we were talking to.
	 */
	(void) strlcpy(res->dc_name, dxi.d_dci.dc_name, MAXHOSTNAMELEN);
	syslog(LOG_INFO, "smbd: found AD server %s", dxi.d_dci.dc_name);

	/*
	 * Domain discovery needs to authenticate with the AD server.
	 * Disconnect any existing connection with the domain controller
	 * to make sure we won't use any prior authentication context
	 * our redirector might have.
	 */
	mlsvc_disconnect(dxi.d_dci.dc_name);

	/*
	 * Get the domain policy info (domain SID etc).
	 * Here too, bypass the smb_ddiscover_service.
	 */
	status = smb_ddiscover_main(info->domain_name, &dxi);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR,
		    "smbd: failed getting domain info for %s (%s)",
		    info->domain_name, xlate_nt_status(status));
		goto out;
	}
	/*
	 * After a successful smbd_ddiscover_main() call
	 * we should call smb_domain_save() to update the
	 * data shown by smbadm list.  Do that at the end,
	 * only if all goes well with joining the domain.
	 */

	/*
	 * Create or update our machine account on the DC.
	 * A non-null user means we do "secure join".
	 */
	if (info->domain_username[0] != '\0') {
		/*
		 * If enabled, try to join using AD Services.
		 */
		status = NT_STATUS_UNSUCCESSFUL;
		if (ads_enabled) {
			res->join_err = smb_ads_join(di->di_fqname,
			    info->domain_username, info->domain_passwd,
			    machine_pw);
			if (res->join_err == SMB_ADS_SUCCESS) {
				status = NT_STATUS_SUCCESS;
			}
		} else {
			syslog(LOG_DEBUG, "use_ads=false (do RPC join)");

			/*
			 * If ADS was disabled, join using RPC.
			 */
			status = mlsvc_join_rpc(&dxi,
			    info->domain_username,
			    info->domain_passwd,
			    machine_name, machine_pw);
		}

	} else {
		/*
		 * Doing "Unsecure join" (pre-created account)
		 */
		status = mlsvc_join_noauth(&dxi, machine_name, machine_pw);
	}

	if (status != NT_STATUS_SUCCESS)
		goto out;

	/*
	 * Make sure we can authenticate using the
	 * (new, or updated) machine account.
	 */
	(void) smb_auth_ntlm_hash(machine_pw, passwd_hash);
	smb_ipc_set(machine_name, passwd_hash);
	rc = smbrdr_logon(dxi.d_dci.dc_name, di->di_nbname, machine_name);
	if (rc != 0) {
		syslog(LOG_NOTICE, "Authenticate with "
		    "new/updated machine account: %s",
		    strerror(rc));
		res->join_err = SMB_ADJOIN_ERR_AUTH_NETLOGON;
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto out;
	}

	/*
	 * Store the new machine account password, and
	 * SMB_CI_DOMAIN_MEMB etc.
	 */
	rc = smb_setdomainprops(NULL, dxi.d_dci.dc_name, machine_pw);
	if (rc != 0) {
		syslog(LOG_NOTICE,
		    "Failed to save machine account password");
		res->join_err = SMB_ADJOIN_ERR_STORE_PROPS;
		status = NT_STATUS_INTERNAL_DB_ERROR;
		goto out;
	}

	/*
	 * Update idmap config?
	 * Already set the domain_name above.
	 */

	/*
	 * Save the SMB server config.  Sets: SMB_CI_DOMAIN_*
	 * Should unify SMB vs idmap configs.
	 */
	smb_config_setdomaininfo(di->di_nbname, di->di_fqname,
	    di->di_sid,
	    di->di_u.di_dns.ddi_forest,
	    di->di_u.di_dns.ddi_guid);
	smb_ipc_commit();
	smb_domain_save();

	status = 0;

out:

	if (status != 0) {
		/*
		 * Undo the tentative domain settings.
		 */
		(void) smb_config_set_idmap_domain("");
		(void) smb_config_refresh_idmap();
		smb_ipc_rollback();
	}

	/* Avoid leaving cleartext passwords around. */
	bzero(machine_pw, sizeof (machine_pw));
	bzero(passwd_hash, sizeof (passwd_hash));

	res->status = status;
}

static DWORD
mlsvc_join_rpc(smb_domainex_t *dxi,
	char *admin_user, char *admin_pw,
	char *machine_name,  char *machine_pw)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	mlsvc_handle_t user_handle;
	smb_account_t ainfo;
	char *server = dxi->d_dci.dc_name;
	smb_domain_t *di = &dxi->d_primary;
	DWORD account_flags;
	DWORD rid;
	DWORD status;
	int rc;

	/* Caller did smb_ipc_set() so we don't need the pw for now. */
	_NOTE(ARGUNUSED(admin_pw));

	rc = samr_open(server, di->di_nbname, admin_user,
	    MAXIMUM_ALLOWED, &samr_handle);
	if (rc != 0) {
		syslog(LOG_NOTICE, "sam_connect to server %s failed", server);
		return (RPC_NT_SERVER_UNAVAILABLE);
	}
	/* have samr_handle */

	status = samr_open_domain(&samr_handle, MAXIMUM_ALLOWED,
	    (struct samr_sid *)di->di_binsid, &domain_handle);
	if (status != NT_STATUS_SUCCESS)
		goto out_samr_handle;
	/* have domain_handle */

	account_flags = SAMR_AF_WORKSTATION_TRUST_ACCOUNT;
	status = samr_create_user(&domain_handle, machine_name,
	    account_flags, &rid, &user_handle);
	if (status == NT_STATUS_USER_EXISTS) {
		status = samr_lookup_domain_names(&domain_handle,
		    machine_name, &ainfo);
		if (status != NT_STATUS_SUCCESS)
			goto out_domain_handle;
		status = samr_open_user(&domain_handle, MAXIMUM_ALLOWED,
		    ainfo.a_rid, &user_handle);
	}
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "smbd: failed to open machine account (%s)",
		    xlate_nt_status(status));
		goto out_domain_handle;
	}

	/*
	 * The account exists, and we have user_handle open
	 * on that account.  Set the password and flags.
	 */

	status = netr_set_user_password(&user_handle, machine_pw);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "smbd: failed to set machine account password (%s)",
		    xlate_nt_status(status));
		goto out_user_handle;
	}

	account_flags |= SAMR_AF_DONT_EXPIRE_PASSWD;
	status = netr_set_user_control(&user_handle, account_flags);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "Set machine account control flags: %s",
		    xlate_nt_status(status));
		goto out_user_handle;
	}

out_user_handle:
	(void) samr_close_handle(&user_handle);
out_domain_handle:
	(void) samr_close_handle(&domain_handle);
out_samr_handle:
	(void) samr_close_handle(&samr_handle);

	return (status);
}

/*
 * Doing "Unsecure join" (using a pre-created machine account).
 * All we need to do is change the password from the default
 * to a random string.
 *
 * Note: this is a work in progres.  Nexenta issue 11960
 * (allow joining an AD domain using a pre-created computer account)
 * It turns out that to change the machine account password,
 * we need to use a different RPC call, performed over the
 * NetLogon secure channel.  (See netr_server_password_set2)
 */
static DWORD
mlsvc_join_noauth(smb_domainex_t *dxi,
	char *machine_name, char *machine_pw)
{
	char old_pw[SMB_SAMACCT_MAXLEN];
	DWORD status;

	/*
	 * Compose the current (default) password for the
	 * pre-created machine account, which is just the
	 * account name in lower case, truncated to 14
	 * characters.
	 */
	if (smb_gethostname(old_pw, sizeof (old_pw), SMB_CASE_LOWER) != 0)
		return (NT_STATUS_INTERNAL_ERROR);
	old_pw[14] = '\0';

	status = netr_change_password(dxi->d_dci.dc_name, machine_name,
	    old_pw, machine_pw);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "Change machine account password: %s",
		    xlate_nt_status(status));
	}
	return (status);
}

void
mlsvc_disconnect(const char *server)
{
	smbrdr_disconnect(server);
}

/*
 * A few more helper functions for RPC services.
 */

/*
 * Check whether or not the specified user has administrator privileges,
 * i.e. is a member of Domain Admins or Administrators.
 * Returns true if the user is an administrator, otherwise returns false.
 */
boolean_t
ndr_is_admin(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return (ctx->ui_flags & SMB_ATF_ADMIN);
}

/*
 * Check whether or not the specified user has power-user privileges,
 * i.e. is a member of Domain Admins, Administrators or Power Users.
 * This is typically required for operations such as managing shares.
 * Returns true if the user is a power user, otherwise returns false.
 */
boolean_t
ndr_is_poweruser(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return ((ctx->ui_flags & SMB_ATF_ADMIN) ||
	    (ctx->ui_flags & SMB_ATF_POWERUSER));
}

int32_t
ndr_native_os(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return (ctx->ui_native_os);
}
