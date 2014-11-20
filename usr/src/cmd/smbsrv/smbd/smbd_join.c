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

#include <syslog.h>
#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include "smbd.h"

#define	SMBD_DC_MONITOR_ATTEMPTS		3
#define	SMBD_DC_MONITOR_RETRY_INTERVAL		3	/* seconds */
#define	SMBD_DC_MONITOR_INTERVAL		60	/* seconds */

extern smbd_t smbd;

static mutex_t smbd_dc_mutex;
static cond_t smbd_dc_cv;

static void *smbd_dc_monitor(void *);
static void smbd_dc_update(void);
/* Todo: static boolean_t smbd_set_netlogon_cred(void); */
static uint32_t smbd_join_workgroup(smb_joininfo_t *);
static uint32_t smbd_join_domain(smb_joininfo_t *);

/*
 * Launch the DC discovery and monitor thread.
 */
int
smbd_dc_monitor_init(void)
{
	pthread_attr_t	attr;
	int		rc;

	(void) smb_config_getstr(SMB_CI_ADS_SITE, smbd.s_site,
	    MAXHOSTNAMELEN);
	(void) smb_config_getip(SMB_CI_DOMAIN_SRV, &smbd.s_pdc);
	smb_ads_init();

	if (smbd.s_secmode != SMB_SECMODE_DOMAIN)
		return (0);

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smbd.s_dc_monitor_tid, &attr, smbd_dc_monitor,
	    NULL);
	(void) pthread_attr_destroy(&attr);
	return (rc);
}

void
smbd_dc_monitor_refresh(void)
{
	char		site[MAXHOSTNAMELEN];
	smb_inaddr_t	pdc;

	site[0] = '\0';
	bzero(&pdc, sizeof (smb_inaddr_t));
	(void) smb_config_getstr(SMB_CI_ADS_SITE, site, MAXHOSTNAMELEN);
	(void) smb_config_getip(SMB_CI_DOMAIN_SRV, &pdc);

	(void) mutex_lock(&smbd_dc_mutex);

	if ((bcmp(&smbd.s_pdc, &pdc, sizeof (smb_inaddr_t)) != 0) ||
	    (smb_strcasecmp(smbd.s_site, site, 0) != 0)) {
		bcopy(&pdc, &smbd.s_pdc, sizeof (smb_inaddr_t));
		(void) strlcpy(smbd.s_site, site, MAXHOSTNAMELEN);
		smbd.s_pdc_changed = B_TRUE;
		(void) cond_signal(&smbd_dc_cv);
	}

	(void) mutex_unlock(&smbd_dc_mutex);
}

/*ARGSUSED*/
static void *
smbd_dc_monitor(void *arg)
{
	boolean_t	ds_not_responding = B_FALSE;
	boolean_t	ds_cfg_changed = B_FALSE;
	timestruc_t	delay;
	int		i;

	smbd_dc_update();
	smbd_online_wait("smbd_dc_monitor");

	while (smbd_online()) {
		delay.tv_sec = SMBD_DC_MONITOR_INTERVAL;
		delay.tv_nsec = 0;

		(void) mutex_lock(&smbd_dc_mutex);
		(void) cond_reltimedwait(&smbd_dc_cv, &smbd_dc_mutex, &delay);

		if (smbd.s_pdc_changed) {
			smbd.s_pdc_changed = B_FALSE;
			ds_cfg_changed = B_TRUE;
		}

		(void) mutex_unlock(&smbd_dc_mutex);

		for (i = 0; i < SMBD_DC_MONITOR_ATTEMPTS; ++i) {
			if (dssetup_check_service() == 0) {
				ds_not_responding = B_FALSE;
				break;
			}

			ds_not_responding = B_TRUE;
			(void) sleep(SMBD_DC_MONITOR_RETRY_INTERVAL);
		}

		if (ds_not_responding)
			smb_log(smbd.s_loghd, LOG_NOTICE,
			    "smbd_dc_monitor: domain service not responding");

		if (ds_not_responding || ds_cfg_changed) {
			ds_cfg_changed = B_FALSE;
			smb_ads_refresh();
			smbd_dc_update();
		}
	}

	smbd.s_dc_monitor_tid = 0;
	return (NULL);
}

/*
 * Locate a domain controller in the current resource domain and Update
 * the Netlogon credential chain.
 *
 * The domain configuration will be updated upon successful DC discovery.
 */
static void
smbd_dc_update(void)
{
	char		domain[MAXHOSTNAMELEN];
	smb_domainex_t	info;
	smb_domain_t	*di;
	DWORD		status;

	if (smb_getfqdomainname(domain, MAXHOSTNAMELEN) != 0) {
		(void) smb_getdomainname(domain, MAXHOSTNAMELEN);
		(void) smb_strupr(domain);
	}

	if (!smb_locate_dc(domain, "", &info)) {
		smb_log(smbd.s_loghd, LOG_NOTICE,
		    "smbd_dc_update: %s: locate failed", domain);
		return;
	}

	di = &info.d_primary;
	smb_log(smbd.s_loghd, LOG_NOTICE,
	    "smbd_dc_update: %s: located %s", domain, info.d_dc);

	status = mlsvc_netlogon(info.d_dc, di->di_nbname);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "failed to establish NETLOGON credential chain");

		/*
		 * Restart required because the domain changed
		 * or the credential chain setup failed.
		 */
		smb_log(smbd.s_loghd, LOG_NOTICE,
		    "smbd_dc_update: smb/server restart required");

		if (smb_smf_restart_service() != 0)
			smb_log(smbd.s_loghd, LOG_ERR,
			    "restart failed: run 'svcs -xv smb/server'"
			    " for more information");
	}
}

/*
 * smbd_join
 *
 * Joins the specified domain/workgroup.
 *
 * If the security mode or domain name is being changed,
 * the caller must restart the service.
 */
uint32_t
smbd_join(smb_joininfo_t *info)
{
	uint32_t status;

	dssetup_clear_domain_info();
	if (info->mode == SMB_SECMODE_WORKGRP)
		status = smbd_join_workgroup(info);
	else
		status = smbd_join_domain(info);

	return (status);
}

static uint32_t
smbd_join_workgroup(smb_joininfo_t *info)
{
	char nb_domain[SMB_PI_MAX_DOMAIN];

	(void) smb_config_getstr(SMB_CI_DOMAIN_NAME, nb_domain,
	    sizeof (nb_domain));

	smbd_set_secmode(SMB_SECMODE_WORKGRP);
	smb_config_setdomaininfo(info->domain_name, "", "", "", "");

	if (strcasecmp(nb_domain, info->domain_name))
		smb_browser_reconfig();

	return (NT_STATUS_SUCCESS);
}

static uint32_t
smbd_join_domain(smb_joininfo_t *info)
{
	static unsigned char zero_hash[SMBAUTH_HASH_SZ];
	smb_domainex_t dxi;
	smb_domain_t *di;
	uint32_t status;

	/*
	 * Ensure that any previous membership of this domain has
	 * been cleared from the environment before we start. This
	 * will ensure that we don't attempt a NETLOGON_SAMLOGON
	 * when attempting to find the PDC.
	 */
	(void) smb_config_setbool(SMB_CI_DOMAIN_MEMB, B_FALSE);

	/* Clear DNS local (ADS) lookup cache too. */
	smb_ads_refresh();

	/*
	 * Use a NULL session while searching for a DC, and
	 * while getting information about the domain.
	 */
	smb_ipc_set(MLSVC_ANON_USER, zero_hash);

	if (!smb_locate_dc(info->domain_name, "", &dxi)) {
		syslog(LOG_ERR, "smbd: failed locating "
		    "domain controller for %s",
		    info->domain_name);
		status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		goto errout;
	}

	/* info->domain_name could either be NetBIOS domain name or FQDN */
	status = mlsvc_join(&dxi, info->domain_username, info->domain_passwd);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "smbd: failed joining %s (%s)",
		    info->domain_name, xlate_nt_status(status));
		goto errout;
	}

	/*
	 * Success!
	 *
	 * Strange, mlsvc_join does some of the work to
	 * save the config, then the rest happens here.
	 * Todo: Do the config update all in one place.
	 */
	di = &dxi.d_primary;
	smbd_set_secmode(SMB_SECMODE_DOMAIN);
	smb_config_setdomaininfo(di->di_nbname, di->di_fqname,
	    di->di_sid,
	    di->di_u.di_dns.ddi_forest,
	    di->di_u.di_dns.ddi_guid);
	smb_ipc_commit();
	return (status);

errout:
	smb_ipc_rollback();
	return (status);
}
