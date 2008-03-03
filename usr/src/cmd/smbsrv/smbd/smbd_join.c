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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syslog.h>
#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/lsalib.h>

/*
 * Maximum time to wait for a domain controller (30 seconds).
 */
#define	SMB_NETLOGON_TIMEOUT	30

/*
 * Flags used in conjunction with the location and query condition
 * variables.
 */
#define	SMB_NETLF_LOCATE_DC	0x00000001
#define	SMB_NETLF_LSA_QUERY	0x00000002

typedef struct smb_netlogon_info {
	char snli_domain[SMB_PI_MAX_DOMAIN];
	char snli_dc[MAXHOSTNAMELEN];
	unsigned snli_flags;
	mutex_t snli_locate_mtx;
	cond_t snli_locate_cv;
	mutex_t snli_query_mtx;
	cond_t snli_query_cv;
	uint32_t snli_status;
} smb_netlogon_info_t;

static smb_netlogon_info_t smb_netlogon_info;

/* NT4 domain support is not yet available. */
static boolean_t nt4_domain_support = B_FALSE;

static pthread_t lsa_monitor_thr;
static pthread_t dc_browser_thr;

static void *smb_netlogon_lsa_monitor(void *arg);
static void *smb_netlogon_dc_browser(void *arg);

/*
 * Inline convenience function to find out if the domain information is
 * valid. The caller can decide whether or not to wait.
 */
static boolean_t
smb_ntdomain_is_valid(uint32_t timeout)
{
	smb_ntdomain_t *info;

	if ((info = smb_getdomaininfo(timeout)) != 0) {
		if (info->ipaddr != 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Retrieve the kpasswd server from krb5.conf.
 */
static int
smbd_get_kpasswd_srv(char *srv, size_t len)
{
	FILE *fp;
	static char buf[512];
	char *p;

	*srv = '\0';
	p = getenv("KRB5_CONFIG");
	if (p == NULL || *p == '\0')
		p = "/etc/krb5/krb5.conf";

	if ((fp = fopen(p, "r")) == NULL)
		return (-1);

	while (fgets(buf, sizeof (buf), fp)) {

		/* Weed out any comment text */
		(void) trim_whitespace(buf);
		if (*buf == '#')
			continue;

		if ((p = strstr(buf, "kpasswd_server")) != NULL) {
			if ((p = strchr(p, '=')) != NULL) {
				(void) trim_whitespace(++p);
				(void) strlcpy(srv, p, len);
			}
			break;
		}
	}

	(void) fclose(fp);
	return ((*srv == '\0') ? -1 : 0);
}

/*
 * smbd_join
 *
 * Joins the specified domain/workgroup
 */
uint32_t
smbd_join(smb_joininfo_t *info)
{
	smb_ntdomain_t *pi;
	uint32_t status;
	unsigned char passwd_hash[SMBAUTH_HASH_SZ];
	char plain_passwd[PASS_LEN + 1];
	char plain_user[PASS_LEN + 1];
	char nbt_domain[SMB_PI_MAX_DOMAIN];
	char fqdn[MAXHOSTNAMELEN];
	char dc[MAXHOSTNAMELEN];
	char kpasswd_domain[MAXHOSTNAMELEN];

	(void) smb_config_getstr(SMB_CI_KPASSWD_DOMAIN, kpasswd_domain,
	    MAXHOSTNAMELEN);

	if (info->mode == SMB_SECMODE_WORKGRP) {
		if ((smb_config_get_secmode() == SMB_SECMODE_DOMAIN) &&
		    kpasswd_domain == '\0') {

			if (ads_domain_change_cleanup("") != 0) {
				syslog(LOG_ERR, "smbd: unable to remove the"
				    " old keys from the Kerberos keytab. "
				    "Please remove the old keys for your "
				    "host principal.");
			}
		}

		(void) smb_config_getstr(SMB_CI_DOMAIN_NAME, nbt_domain,
		    sizeof (nbt_domain));

		(void) smb_config_set_secmode(info->mode);
		(void) smb_config_setstr(SMB_CI_DOMAIN_NAME, info->domain_name);

		if (strcasecmp(nbt_domain, info->domain_name))
			smb_browser_reconfig();

		return (NT_STATUS_SUCCESS);
	}

	/*
	 * Ensure that any previous membership of this domain has
	 * been cleared from the environment before we start. This
	 * will ensure that we don't attempt a NETLOGON_SAMLOGON
	 * when attempting to find the PDC.
	 */
	(void) smb_config_setbool(SMB_CI_DOMAIN_MEMB, B_FALSE);

	(void) strlcpy(plain_user, info->domain_username, sizeof (plain_user));
	(void) strlcpy(plain_passwd, info->domain_passwd,
	    sizeof (plain_passwd));
	(void) smb_resolve_netbiosname(info->domain_name, nbt_domain,
	    sizeof (nbt_domain));

	if (smb_resolve_fqdn(info->domain_name, fqdn, sizeof (fqdn)) != 1) {
		syslog(LOG_ERR, "smbd: fully-qualified domain name is unknown");
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (ads_domain_change_cleanup(fqdn)) {
		syslog(LOG_ERR, "smbd: unable to remove the old keys from the"
		    " Kerberos keytab. Please remove the old keys for your "
		    "host principal.");
		return (NT_STATUS_INTERNAL_ERROR);
	}

	if (smb_auth_ntlm_hash(plain_passwd, passwd_hash) != SMBAUTH_SUCCESS) {
		status = NT_STATUS_INTERNAL_ERROR;
		syslog(LOG_ERR, "smbd: could not compute ntlm hash for '%s'",
		    plain_user);
		return (status);
	}

	smbrdr_ipc_set(plain_user, passwd_hash);

	(void) smbd_get_kpasswd_srv(dc, sizeof (dc));
	if (smbd_locate_dc(nbt_domain, dc)) {
		if ((pi = smb_getdomaininfo(0)) == 0) {
			status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
			if (*dc == '\0')
				syslog(LOG_ERR, "smbd: could not get domain "
				    "controller information for '%s'",
				    info->domain_name);
			else
				syslog(LOG_ERR, "smbd: could not get the "
				    "specified domain controller information "
				    "'%s'", dc);
			return (status);
		}

		/*
		 * Temporary delay before creating
		 * the workstation trust account.
		 */
		(void) sleep(2);
		status = mlsvc_join(pi->server, pi->domain,
		    plain_user, plain_passwd);

		if (status == NT_STATUS_SUCCESS) {
			(void) smb_config_set_secmode(SMB_SECMODE_DOMAIN);
			(void) smb_config_setstr(SMB_CI_DOMAIN_NAME,
			    info->domain_name);
			smbrdr_ipc_commit();
			return (status);
		}

		smbrdr_ipc_rollback();
		syslog(LOG_ERR, "smbd: failed joining %s (%s)",
		    info->domain_name, xlate_nt_status(status));
		return (status);
	}

	smbrdr_ipc_rollback();
	syslog(LOG_ERR, "smbd: failed locating domain controller for %s",
	    info->domain_name);
	return (NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND);
}

/*
 * smbd_locate_dc
 *
 * This is the entry point for discovering a domain controller for the
 * specified domain. The caller may block here for around 30 seconds if
 * the system has to go to the network and find a domain controller.
 * Sometime it would be good to change this to smb_locate_pdc and allow
 * the caller to specify whether or not he wants to wait for a response.
 *
 * The actual work of discovering a DC is handled by other threads.
 * All we do here is signal the request and wait for a DC or a timeout.
 *
 * domain - domain to be discovered
 * dc - preferred DC. If the preferred DC is set to empty string, it
 *      will attempt to discover any DC in the specified domain.
 *
 * Returns B_TRUE if a domain controller is available.
 */
boolean_t
smbd_locate_dc(char *domain, char *dc)
{
	int rc;
	timestruc_t to;

	if (domain == NULL || *domain == '\0')
		return (B_FALSE);

	(void) mutex_lock(&smb_netlogon_info.snli_locate_mtx);

	if ((smb_netlogon_info.snli_flags & SMB_NETLF_LOCATE_DC) == 0) {
		smb_netlogon_info.snli_flags |= SMB_NETLF_LOCATE_DC;
		(void) strlcpy(smb_netlogon_info.snli_domain, domain,
		    SMB_PI_MAX_DOMAIN);
		(void) strlcpy(smb_netlogon_info.snli_dc, dc,
		    MAXHOSTNAMELEN);
		(void) cond_broadcast(&smb_netlogon_info.snli_locate_cv);
	}

	while (smb_netlogon_info.snli_flags & SMB_NETLF_LOCATE_DC) {
		to.tv_sec = SMB_NETLOGON_TIMEOUT;
		to.tv_nsec = 0;
		rc = cond_reltimedwait(&smb_netlogon_info.snli_locate_cv,
		    &smb_netlogon_info.snli_locate_mtx, &to);

		if (rc == ETIME)
			break;
	}

	(void) mutex_unlock(&smb_netlogon_info.snli_locate_mtx);

	return (smb_ntdomain_is_valid(0));
}

/*
 * smb_netlogon_init
 *
 * Initialization of the DC browser and LSA monitor threads.
 * Returns 0 on success, an error number if thread creation fails.
 */
int
smb_netlogon_init(void)
{
	pthread_attr_t tattr;
	int rc;

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&lsa_monitor_thr, &tattr,
	    smb_netlogon_lsa_monitor, 0);
	if (rc != 0)
		goto nli_exit;
	rc = pthread_create(&dc_browser_thr, &tattr,
	    smb_netlogon_dc_browser, 0);
	if (rc != 0) {
		(void) pthread_cancel(lsa_monitor_thr);
		(void) pthread_join(lsa_monitor_thr, NULL);
	}

nli_exit:
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

/*
 * smb_netlogon_dc_browser
 *
 * This is the DC browser thread: it gets woken up whenever someone
 * wants to locate a domain controller.
 *
 * With the introduction of Windows 2000, NetBIOS is no longer a
 * requirement for NT domains. If NetBIOS has been disabled on the
 * network there will be no browsers and we won't get any response
 * to netlogon requests. So we try to find a DC controller via ADS
 * first. If ADS is disabled or the DNS query fails, we drop back
 * to the netlogon protocol.
 *
 * This function will block for up to 30 seconds waiting for the PDC
 * to be discovered. Sometime it would be good to change this to
 * smb_locate_pdc and allow the caller to specify whether or not he
 * wants to wait for a response.
 *
 */
/*ARGSUSED*/
static void *
smb_netlogon_dc_browser(void *arg)
{
	boolean_t rc;
	char resource_domain[SMB_PI_MAX_DOMAIN];
	char dc[MAXHOSTNAMELEN];

	for (;;) {
		(void) mutex_lock(&smb_netlogon_info.snli_locate_mtx);

		while ((smb_netlogon_info.snli_flags & SMB_NETLF_LOCATE_DC) ==
		    0) {
			(void) cond_wait(&smb_netlogon_info.snli_locate_cv,
			    &smb_netlogon_info.snli_locate_mtx);
		}

		(void) mutex_unlock(&smb_netlogon_info.snli_locate_mtx);
		(void) strlcpy(resource_domain, smb_netlogon_info.snli_domain,
		    SMB_PI_MAX_DOMAIN);
		(void) strlcpy(dc, smb_netlogon_info.snli_dc, MAXHOSTNAMELEN);

		smb_setdomaininfo(NULL, NULL, 0);
		if ((msdcs_lookup_ads(resource_domain, dc) == 0) &&
		    (nt4_domain_support)) {
			/* Try to locate a DC via NetBIOS */
			smb_browser_netlogon(resource_domain);
		}

		rc = smb_ntdomain_is_valid(SMB_NETLOGON_TIMEOUT);

		(void) mutex_lock(&smb_netlogon_info.snli_locate_mtx);
		smb_netlogon_info.snli_flags &= ~SMB_NETLF_LOCATE_DC;
		(void) cond_broadcast(&smb_netlogon_info.snli_locate_cv);
		(void) mutex_unlock(&smb_netlogon_info.snli_locate_mtx);

		if (rc != B_TRUE) {
			/*
			 * Notify the LSA monitor to update the
			 * primary and trusted domain information.
			 */
			(void) mutex_lock(&smb_netlogon_info.snli_query_mtx);
			smb_netlogon_info.snli_flags |= SMB_NETLF_LSA_QUERY;
			(void) cond_broadcast(&smb_netlogon_info.snli_query_cv);
			(void) mutex_unlock(&smb_netlogon_info.snli_query_mtx);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * smb_netlogon_lsa_monitor
 *
 * This monitor should run as a separate thread. It waits on a condition
 * variable until someone indicates that the LSA domain information needs
 * to be refreshed. It then queries the DC for the NT domain information:
 * primary, account and trusted domains. The condition variable should be
 * signaled whenever a DC is selected.
 *
 * Note that the LSA query calls require the DC information and this task
 * may end up blocked on the DC location protocol, which is why this
 * monitor is run as a separate thread. This should only happen if the DC
 * goes down immediately after we located it.
 */
/*ARGSUSED*/
static void *
smb_netlogon_lsa_monitor(void *arg)
{
	uint32_t status;

	for (;;) {
		(void) mutex_lock(&smb_netlogon_info.snli_query_mtx);

		while ((smb_netlogon_info.snli_flags & SMB_NETLF_LSA_QUERY) ==
		    0) {
			(void) cond_wait(&smb_netlogon_info.snli_query_cv,
			    &smb_netlogon_info.snli_query_mtx);
		}

		smb_netlogon_info.snli_flags &= ~SMB_NETLF_LSA_QUERY;
		(void) mutex_unlock(&smb_netlogon_info.snli_query_mtx);

		/*
		 * Skip the LSA query if Authenticated IPC is supported
		 * and the credential is not yet set.
		 */
		if (smbrdr_ipc_skip_lsa_query() == 0) {
			status = lsa_query_primary_domain_info();
			if (status == NT_STATUS_SUCCESS) {
				if (lsa_query_account_domain_info()
				    != NT_STATUS_SUCCESS) {
					syslog(LOG_DEBUG,
					    "NetlogonLSAMonitor: query "
					    "account info failed");
				}
				if (lsa_enum_trusted_domains()
				    != NT_STATUS_SUCCESS) {
					syslog(LOG_DEBUG,
					    "NetlogonLSAMonitor: enum "
					    "trusted domain failed");
				}
			} else {
				syslog(LOG_DEBUG,
				    "NetlogonLSAMonitor: update failed");
			}
		}
	}

	/*NOTREACHED*/
	return (NULL);
}


/*
 * smb_set_netlogon_cred
 *
 * If the system is joined to an AD domain via kclient, SMB daemon will need
 * to establish the NETLOGON credential chain.
 *
 * Since the kclient has updated the machine password stored in SMF
 * repository, the cached ipc_info must be updated accordingly by calling
 * smbrdr_ipc_commit.
 *
 * Due to potential replication delays in a multiple DC environment, the
 * NETLOGON rpc request must be sent to the DC, to which the KPASSWD request
 * is sent. If the DC discovered by the SMB daemon is different than the
 * kpasswd server, the current connection with the DC will be torn down
 * and a DC discovery process will be triggered to locate the kpasswd
 * server.
 *
 * If joining a new domain, the domain_name property must be set after a
 * successful credential chain setup.
 */
void
smb_set_netlogon_cred(void)
{
	smb_ntdomain_t *dp;
	smb_ntdomain_t domain_info;
	char kpasswd_srv[MAXHOSTNAMELEN];
	char kpasswd_domain[MAXHOSTNAMELEN];
	char sam_acct[MLSVC_ACCOUNT_NAME_MAX];
	char *ipc_usr, *dom;
	boolean_t new_domain = B_FALSE;

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return;

	if (smb_match_netlogon_seqnum())
		return;

	(void) smb_config_getstr(SMB_CI_KPASSWD_SRV, kpasswd_srv,
	    sizeof (kpasswd_srv));

	if (*kpasswd_srv == '\0')
		return;

	/*
	 * If the domain join initiated by smbadm join CLI is in
	 * progress, don't do anything.
	 */
	(void) smb_gethostname(sam_acct, MLSVC_ACCOUNT_NAME_MAX - 1, 0);
	(void) strlcat(sam_acct, "$", MLSVC_ACCOUNT_NAME_MAX);
	ipc_usr = smbrdr_ipc_get_user();
	if (strcasecmp(ipc_usr, sam_acct))
		return;

	if ((dp = smb_getdomaininfo(0)) == NULL) {
		*domain_info.server = '\0';
		(void) smb_getdomainname(domain_info.domain,
		    sizeof (domain_info.domain));
		dp = &domain_info;
	}

	(void) smb_config_getstr(SMB_CI_KPASSWD_DOMAIN, kpasswd_domain,
	    sizeof (kpasswd_domain));

	if (*kpasswd_domain != '\0' &&
	    strncasecmp(kpasswd_domain, dp->domain, strlen(dp->domain))) {
		dom = kpasswd_domain;
		new_domain = B_TRUE;
	} else {
		dom = dp->domain;
	}

	/*
	 * DC discovery will be triggered if the domain info is not
	 * currently cached or the SMB daemon has previously discovered a DC
	 * that is different than the kpasswd server.
	 */
	if (new_domain || strcasecmp(dp->server, kpasswd_srv) != 0) {
		if (*dp->server != '\0')
			mlsvc_disconnect(dp->server);

		if (!smbd_locate_dc(dom, kpasswd_srv))
			(void) smbd_locate_dc(dp->domain, "");

		if ((dp = smb_getdomaininfo(0)) == NULL) {
			smbrdr_ipc_commit();
			return;
		}
	}

	smbrdr_ipc_commit();
	if (mlsvc_netlogon(dp->server, dp->domain)) {
		syslog(LOG_ERR, "NETLOGON credential chain establishment"
		    " failed");
	} else {
		if (new_domain) {
			(void) smb_config_setstr(SMB_CI_DOMAIN_NAME,
			    kpasswd_domain);
			(void) smb_config_setstr(SMB_CI_KPASSWD_DOMAIN,
			    kpasswd_domain);
		}
	}

}
