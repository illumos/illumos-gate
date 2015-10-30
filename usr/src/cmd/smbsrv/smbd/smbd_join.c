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

#include <syslog.h>
#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
static int smbd_dc_check(smb_domainex_t *);
/* Todo: static boolean_t smbd_set_netlogon_cred(void); */
static void smbd_join_workgroup(smb_joininfo_t *, smb_joinres_t *);
static void smbd_join_domain(smb_joininfo_t *, smb_joinres_t *);

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

/*
 * Refresh the DC monitor.  Called from SMF refresh and when idmap
 * finds a different DC from what we were using previously.
 * Update our domain (and current DC) information.
 */
void
smbd_dc_monitor_refresh(void)
{

	syslog(LOG_INFO, "smbd_dc_monitor_refresh");

	smb_ddiscover_refresh();

	(void) mutex_lock(&smbd_dc_mutex);

	smbd.s_pdc_changed = B_TRUE;
	(void) cond_signal(&smbd_dc_cv);

	(void) mutex_unlock(&smbd_dc_mutex);
}

/*ARGSUSED*/
static void *
smbd_dc_monitor(void *arg)
{
	smb_domainex_t	di;
	boolean_t	ds_not_responding;
	boolean_t	ds_cfg_changed;
	timestruc_t	delay;
	int		i;

	/* Wait for smb_dclocator_init() to complete. */
	smbd_online_wait("smbd_dc_monitor");
	smbd_dc_update();

	while (smbd_online()) {
		ds_not_responding = B_FALSE;
		ds_cfg_changed = B_FALSE;
		delay.tv_sec = SMBD_DC_MONITOR_INTERVAL;
		delay.tv_nsec = 0;

		(void) mutex_lock(&smbd_dc_mutex);
		(void) cond_reltimedwait(&smbd_dc_cv, &smbd_dc_mutex, &delay);

		if (smbd.s_pdc_changed) {
			smbd.s_pdc_changed = B_FALSE;
			ds_cfg_changed = B_TRUE;
			/* NB: smb_ddiscover_refresh was called. */
		}

		(void) mutex_unlock(&smbd_dc_mutex);

		if (ds_cfg_changed) {
			syslog(LOG_DEBUG, "smbd_dc_monitor: config changed");
			goto rediscover;
		}

		if (!smb_domain_getinfo(&di)) {
			syslog(LOG_DEBUG, "smbd_dc_monitor: no domain info");
			goto rediscover;
		}

		if (di.d_dci.dc_name[0] == '\0') {
			syslog(LOG_DEBUG, "smbd_dc_monitor: no DC name");
			goto rediscover;
		}

		for (i = 0; i < SMBD_DC_MONITOR_ATTEMPTS; ++i) {
			if (smbd_dc_check(&di) == 0) {
				ds_not_responding = B_FALSE;
				break;
			}

			ds_not_responding = B_TRUE;
			(void) sleep(SMBD_DC_MONITOR_RETRY_INTERVAL);
		}

		if (ds_not_responding) {
			syslog(LOG_NOTICE,
			    "smbd_dc_monitor: DC not responding: %s",
			    di.d_dci.dc_name);
			smb_ddiscover_bad_dc(di.d_dci.dc_name);
		}

		if (ds_not_responding || ds_cfg_changed) {
		rediscover:
			/*
			 * An smb_ads_refresh will be done by the
			 * smb_ddiscover_service when necessary.
			 * Note: smbd_dc_monitor_refresh was already
			 * called if appropriate.
			 */
			smbd_dc_update();
		}
	}

	smbd.s_dc_monitor_tid = 0;
	return (NULL);
}

/*
 * Simply attempt a connection to the DC.
 */
static int
smbd_dc_check(smb_domainex_t *di)
{
	struct sockaddr sa;
	int salen = 0;
	int sock = -1;
	int tmo = 5 * 1000;	/* 5 sec. */
	int rc;

	bzero(&sa, sizeof (sa));
	switch (di->d_dci.dc_addr.a_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (void *)&sa;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(IPPORT_SMB);
		sin->sin_addr.s_addr = di->d_dci.dc_addr.a_ipv4;
		salen = sizeof (*sin);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (void *)&sa;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(IPPORT_SMB);
		(void) memcpy(&sin6->sin6_addr,
		    &di->d_dci.dc_addr.a_ipv6,
		    sizeof (in6_addr_t));
		salen = sizeof (*sin6);
		break;
	}
	default:
		return (-1);
	}

	sock = socket(di->d_dci.dc_addr.a_family, SOCK_STREAM, 0);
	if (sock < 0)
		return (errno);
	(void) setsockopt(sock, IPPROTO_TCP,
	    TCP_CONN_ABORT_THRESHOLD, &tmo, sizeof (tmo));

	rc = connect(sock, &sa, salen);
	if (rc < 0)
		rc = errno;

	(void) close(sock);
	return (rc);
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

	/*
	 * Don't want this active until we're a domain member.
	 */
	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return;

	if (smb_getfqdomainname(domain, MAXHOSTNAMELEN) != 0)
		return;

	if (domain[0] == '\0') {
		syslog(LOG_NOTICE,
		    "smbd_dc_update: no domain name set");
		return;
	}

	if (!smb_locate_dc(domain, &info)) {
		syslog(LOG_NOTICE,
		    "smbd_dc_update: %s: locate failed", domain);
		return;
	}

	di = &info.d_primary;
	syslog(LOG_INFO,
	    "smbd_dc_update: %s: located %s", domain, info.d_dci.dc_name);

	status = mlsvc_netlogon(info.d_dci.dc_name, di->di_nbname);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE,
		    "failed to establish NETLOGON credential chain");
		syslog(LOG_NOTICE, " with server %s for domain %s (%s)",
		    info.d_dci.dc_name, domain,
		    xlate_nt_status(status));
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
void
smbd_join(smb_joininfo_t *info, smb_joinres_t *res)
{
	dssetup_clear_domain_info();
	if (info->mode == SMB_SECMODE_WORKGRP)
		smbd_join_workgroup(info, res);
	else
		smbd_join_domain(info, res);
}

static void
smbd_join_workgroup(smb_joininfo_t *info, smb_joinres_t *res)
{
	char nb_domain[SMB_PI_MAX_DOMAIN];

	syslog(LOG_DEBUG, "smbd: join workgroup: %s", info->domain_name);

	(void) smb_config_getstr(SMB_CI_DOMAIN_NAME, nb_domain,
	    sizeof (nb_domain));

	smbd_set_secmode(SMB_SECMODE_WORKGRP);
	smb_config_setdomaininfo(info->domain_name, "", "", "", "");
	(void) smb_config_set_idmap_domain("");
	(void) smb_config_refresh_idmap();

	if (strcasecmp(nb_domain, info->domain_name))
		smb_browser_reconfig();

	res->status = NT_STATUS_SUCCESS;
}

static void
smbd_join_domain(smb_joininfo_t *info, smb_joinres_t *res)
{

	syslog(LOG_DEBUG, "smbd: join domain: %s", info->domain_name);

	/* info->domain_name could either be NetBIOS domain name or FQDN */
	mlsvc_join(info, res);
	if (res->status == 0) {
		smbd_set_secmode(SMB_SECMODE_DOMAIN);
	} else {
		syslog(LOG_ERR, "smbd: failed joining %s (%s)",
		    info->domain_name, xlate_nt_status(res->status));
	}
}
