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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <syslog.h>
#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <assert.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <lsalib.h>
#include <mlsvc.h>

/*
 * DC Locator
 */
#define	SMB_DCLOCATOR_TIMEOUT	45	/* seconds */
#define	SMB_IS_FQDN(domain)	(strchr(domain, '.') != NULL)

typedef struct smb_dclocator {
	smb_dcinfo_t	sdl_dci; /* .dc_name .dc_addr */
	char		sdl_domain[SMB_PI_MAX_DOMAIN];
	boolean_t	sdl_locate;
	boolean_t	sdl_bad_dc;
	boolean_t	sdl_cfg_chg;
	mutex_t		sdl_mtx;
	cond_t		sdl_cv;
	uint32_t	sdl_status;
} smb_dclocator_t;

static smb_dclocator_t smb_dclocator;
static pthread_t smb_dclocator_thr;

static void *smb_ddiscover_service(void *);
static uint32_t smb_ddiscover_qinfo(char *, char *, smb_domainex_t *);
static void smb_ddiscover_enum_trusted(char *, char *, smb_domainex_t *);
static uint32_t smb_ddiscover_use_config(char *, smb_domainex_t *);
static void smb_domainex_free(smb_domainex_t *);
static void smb_set_krb5_realm(char *);

/*
 * ===================================================================
 * API to initialize DC locator thread, trigger DC discovery, and
 * get the discovered DC and/or domain information.
 * ===================================================================
 */

/*
 * Initialization of the DC locator thread.
 * Returns 0 on success, an error number if thread creation fails.
 */
int
smb_dclocator_init(void)
{
	pthread_attr_t tattr;
	int rc;

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smb_dclocator_thr, &tattr,
	    smb_ddiscover_service, &smb_dclocator);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

/*
 * This is the entry point for discovering a domain controller for the
 * specified domain.  Called during join domain, and then periodically
 * by smbd_dc_update (the "DC monitor" thread).
 *
 * The actual work of discovering a DC is handled by DC locator thread.
 * All we do here is signal the request and wait for a DC or a timeout.
 *
 * Input parameters:
 *  domain - domain to be discovered (can either be NetBIOS or DNS domain)
 *
 * Output parameter:
 *  dp - on success, dp will be filled with the discovered DC and domain
 *       information.
 *
 * Returns B_TRUE if the DC/domain info is available.
 */
boolean_t
smb_locate_dc(char *domain, smb_domainex_t *dp)
{
	int rc;
	boolean_t rv;
	timestruc_t to;
	smb_domainex_t domain_info;

	if (domain == NULL || *domain == '\0') {
		syslog(LOG_DEBUG, "smb_locate_dc NULL dom");
		smb_set_krb5_realm(NULL);
		return (B_FALSE);
	}

	(void) mutex_lock(&smb_dclocator.sdl_mtx);

	if (strcmp(smb_dclocator.sdl_domain, domain)) {
		(void) strlcpy(smb_dclocator.sdl_domain, domain,
		    sizeof (smb_dclocator.sdl_domain));
		smb_dclocator.sdl_cfg_chg = B_TRUE;
		syslog(LOG_DEBUG, "smb_locate_dc new dom=%s", domain);
		smb_set_krb5_realm(domain);
	}

	if (!smb_dclocator.sdl_locate) {
		smb_dclocator.sdl_locate = B_TRUE;
		(void) cond_broadcast(&smb_dclocator.sdl_cv);
	}

	while (smb_dclocator.sdl_locate) {
		to.tv_sec = SMB_DCLOCATOR_TIMEOUT;
		to.tv_nsec = 0;
		rc = cond_reltimedwait(&smb_dclocator.sdl_cv,
		    &smb_dclocator.sdl_mtx, &to);

		if (rc == ETIME) {
			syslog(LOG_NOTICE, "smb_locate_dc timeout");
			rv = B_FALSE;
			goto out;
		}
	}
	if (smb_dclocator.sdl_status != 0) {
		syslog(LOG_NOTICE, "smb_locate_dc status 0x%x",
		    smb_dclocator.sdl_status);
		rv = B_FALSE;
		goto out;
	}

	if (dp == NULL)
		dp = &domain_info;
	rv = smb_domain_getinfo(dp);

out:
	(void) mutex_unlock(&smb_dclocator.sdl_mtx);

	return (rv);
}

/*
 * Tell the domain discovery service to run again now,
 * and assume changed configuration (i.e. a new DC).
 * Like the first part of smb_locate_dc().
 *
 * Note: This is called from the service refresh handler
 * and the door handler to tell the ddiscover thread to
 * request the new DC from idmap.  Therefore, we must not
 * trigger a new idmap discovery run from here, or that
 * would start a ping-pong match.
 */
/* ARGSUSED */
void
smb_ddiscover_refresh()
{

	(void) mutex_lock(&smb_dclocator.sdl_mtx);

	if (smb_dclocator.sdl_cfg_chg == B_FALSE) {
		smb_dclocator.sdl_cfg_chg = B_TRUE;
		syslog(LOG_DEBUG, "smb_ddiscover_refresh set cfg changed");
	}
	if (!smb_dclocator.sdl_locate) {
		smb_dclocator.sdl_locate = B_TRUE;
		(void) cond_broadcast(&smb_dclocator.sdl_cv);
	}

	(void) mutex_unlock(&smb_dclocator.sdl_mtx);
}

/*
 * Called by our client-side threads after they fail to connect to
 * the DC given to them by smb_locate_dc().  This is often called
 * after some delay, because the connection timeout delays these
 * threads for a while, so it's quite common that the DC locator
 * service has already started looking for a new DC.  These late
 * notifications should not continually restart the DC locator.
 */
void
smb_ddiscover_bad_dc(char *bad_dc)
{

	assert(bad_dc[0] != '\0');

	(void) mutex_lock(&smb_dclocator.sdl_mtx);

	syslog(LOG_DEBUG, "smb_ddiscover_bad_dc, cur=%s, bad=%s",
	    smb_dclocator.sdl_dci.dc_name, bad_dc);

	if (strcmp(smb_dclocator.sdl_dci.dc_name, bad_dc)) {
		/*
		 * The "bad" DC is no longer the current one.
		 * Probably a late "bad DC" report.
		 */
		goto out;
	}
	if (smb_dclocator.sdl_bad_dc) {
		/* Someone already marked the current DC as "bad". */
		syslog(LOG_DEBUG, "smb_ddiscover_bad_dc repeat");
		goto out;
	}

	/*
	 * Mark the current DC as "bad" and let the DC Locator
	 * run again if it's not already.
	 */
	syslog(LOG_INFO, "smb_ddiscover, bad DC: %s", bad_dc);
	smb_dclocator.sdl_bad_dc = B_TRUE;

	/* In-line smb_ddiscover_kick */
	if (!smb_dclocator.sdl_locate) {
		smb_dclocator.sdl_locate = B_TRUE;
		(void) cond_broadcast(&smb_dclocator.sdl_cv);
	}

out:
	(void) mutex_unlock(&smb_dclocator.sdl_mtx);
}

/*
 * If domain discovery is running, wait for it to finish.
 */
int
smb_ddiscover_wait(void)
{
	timestruc_t to;
	int rc = 0;

	(void) mutex_lock(&smb_dclocator.sdl_mtx);

	if (smb_dclocator.sdl_locate) {
		to.tv_sec = SMB_DCLOCATOR_TIMEOUT;
		to.tv_nsec = 0;
		rc = cond_reltimedwait(&smb_dclocator.sdl_cv,
		    &smb_dclocator.sdl_mtx, &to);
	}

	(void) mutex_unlock(&smb_dclocator.sdl_mtx);

	return (rc);
}


/*
 * ==========================================================
 * DC discovery functions
 * ==========================================================
 */

/*
 * This is the domain and DC discovery service: it gets woken up whenever
 * there is need to locate a domain controller.
 *
 * Upon success, the SMB domain cache will be populated with the discovered
 * DC and domain info.
 */
/*ARGSUSED*/
static void *
smb_ddiscover_service(void *arg)
{
	smb_domainex_t dxi;
	smb_dclocator_t *sdl = arg;
	uint32_t status;
	boolean_t bad_dc;
	boolean_t cfg_chg;

	for (;;) {
		/*
		 * Wait to be signaled for work by one of:
		 * smb_locate_dc(), smb_ddiscover_refresh(),
		 * smb_ddiscover_bad_dc()
		 */
		syslog(LOG_DEBUG, "smb_ddiscover_service waiting");

		(void) mutex_lock(&sdl->sdl_mtx);
		while (!sdl->sdl_locate)
			(void) cond_wait(&sdl->sdl_cv,
			    &sdl->sdl_mtx);

		if (!smb_config_getbool(SMB_CI_DOMAIN_MEMB)) {
			sdl->sdl_status = NT_STATUS_INVALID_SERVER_STATE;
			syslog(LOG_DEBUG, "smb_ddiscover_service: "
			    "not a domain member");
			goto wait_again;
		}

		/*
		 * Want to know if these change below.
		 * Note: mutex held here
		 */
	find_again:
		bad_dc = sdl->sdl_bad_dc;
		sdl->sdl_bad_dc = B_FALSE;
		if (bad_dc) {
			/*
			 * Need to clear the current DC name or
			 * ddiscover_bad_dc will keep setting bad_dc
			 */
			sdl->sdl_dci.dc_name[0] = '\0';
		}
		cfg_chg = sdl->sdl_cfg_chg;
		sdl->sdl_cfg_chg = B_FALSE;

		(void) mutex_unlock(&sdl->sdl_mtx);

		syslog(LOG_DEBUG, "smb_ddiscover_service running "
		    "cfg_chg=%d bad_dc=%d", (int)cfg_chg, (int)bad_dc);

		/*
		 * Clear the cached DC now so that we'll ask idmap again.
		 * If our current DC gave us errors, force rediscovery.
		 */
		smb_ads_refresh(bad_dc);

		/*
		 * Search for the DC, save the result.
		 */
		bzero(&dxi, sizeof (dxi));
		status = smb_ddiscover_main(sdl->sdl_domain, &dxi);
		if (status == 0)
			smb_domain_save();
		(void) mutex_lock(&sdl->sdl_mtx);
		sdl->sdl_status = status;
		if (status == 0)
			sdl->sdl_dci = dxi.d_dci;

		/*
		 * Run again if either of cfg_chg or bad_dc
		 * was turned on during smb_ddiscover_main().
		 * Note: mutex held here.
		 */
		if (sdl->sdl_bad_dc) {
			syslog(LOG_DEBUG, "smb_ddiscover_service "
			    "restart because bad_dc was set");
			goto find_again;
		}
		if (sdl->sdl_cfg_chg) {
			syslog(LOG_DEBUG, "smb_ddiscover_service "
			    "restart because cfg_chg was set");
			goto find_again;
		}

	wait_again:
		sdl->sdl_locate = B_FALSE;
		sdl->sdl_bad_dc = B_FALSE;
		sdl->sdl_cfg_chg = B_FALSE;
		(void) cond_broadcast(&sdl->sdl_cv);
		(void) mutex_unlock(&sdl->sdl_mtx);
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Discovers a domain controller for the specified domain via DNS.
 * After the domain controller is discovered successfully primary and
 * trusted domain infromation will be queried using RPC queries.
 *
 * Caller should zero out *dxi before calling, and after a
 * successful return should call:  smb_domain_save()
 */
uint32_t
smb_ddiscover_main(char *domain, smb_domainex_t *dxi)
{
	uint32_t status;

	if (domain[0] == '\0') {
		syslog(LOG_DEBUG, "smb_ddiscover_main NULL domain");
		return (NT_STATUS_INTERNAL_ERROR);
	}

	if (smb_domain_start_update() != SMB_DOMAIN_SUCCESS) {
		syslog(LOG_DEBUG, "smb_ddiscover_main can't get lock");
		return (NT_STATUS_INTERNAL_ERROR);
	}

	status = smb_ads_lookup_msdcs(domain, &dxi->d_dci);
	if (status != 0) {
		syslog(LOG_DEBUG, "smb_ddiscover_main can't find DC (%s)",
		    xlate_nt_status(status));
		goto out;
	}

	status = smb_ddiscover_qinfo(domain, dxi->d_dci.dc_name, dxi);
	if (status != 0) {
		syslog(LOG_DEBUG,
		    "smb_ddiscover_main can't get domain info (%s)",
		    xlate_nt_status(status));
		goto out;
	}

	smb_domain_update(dxi);

out:
	smb_domain_end_update();

	/* Don't need the trusted domain list anymore. */
	smb_domainex_free(dxi);

	return (status);
}

/*
 * Obtain primary and trusted domain information using LSA queries.
 *
 * domain - either NetBIOS or fully-qualified domain name
 */
static uint32_t
smb_ddiscover_qinfo(char *domain, char *server, smb_domainex_t *dxi)
{
	uint32_t ret, tmp;

	/* If we must return failure, use this first one. */
	ret = lsa_query_dns_domain_info(server, domain, &dxi->d_primary);
	if (ret == NT_STATUS_SUCCESS)
		goto success;
	tmp = smb_ddiscover_use_config(domain, dxi);
	if (tmp == NT_STATUS_SUCCESS)
		goto success;
	tmp = lsa_query_primary_domain_info(server, domain, &dxi->d_primary);
	if (tmp == NT_STATUS_SUCCESS)
		goto success;

	/* All of the above failed. */
	return (ret);

success:
	smb_ddiscover_enum_trusted(domain, server, dxi);
	return (NT_STATUS_SUCCESS);
}

/*
 * Obtain trusted domains information using LSA queries.
 *
 * domain - either NetBIOS or fully-qualified domain name.
 */
static void
smb_ddiscover_enum_trusted(char *domain, char *server, smb_domainex_t *dxi)
{
	smb_trusted_domains_t *list;
	uint32_t status;

	list = &dxi->d_trusted;
	status = lsa_enum_trusted_domains_ex(server, domain, list);
	if (status != NT_STATUS_SUCCESS)
		(void) lsa_enum_trusted_domains(server, domain, list);
}

/*
 * If the domain to be discovered matches the current domain (i.e the
 * value of either domain or fqdn configuration), then get the primary
 * domain information from SMF.
 */
static uint32_t
smb_ddiscover_use_config(char *domain, smb_domainex_t *dxi)
{
	boolean_t use;
	smb_domain_t *dinfo;

	dinfo = &dxi->d_primary;
	bzero(dinfo, sizeof (smb_domain_t));

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return (NT_STATUS_UNSUCCESSFUL);

	smb_config_getdomaininfo(dinfo->di_nbname, dinfo->di_fqname,
	    NULL, NULL, NULL);

	if (SMB_IS_FQDN(domain))
		use = (smb_strcasecmp(dinfo->di_fqname, domain, 0) == 0);
	else
		use = (smb_strcasecmp(dinfo->di_nbname, domain, 0) == 0);

	if (use)
		smb_config_getdomaininfo(NULL, NULL, dinfo->di_sid,
		    dinfo->di_u.di_dns.ddi_forest,
		    dinfo->di_u.di_dns.ddi_guid);

	return ((use) ? NT_STATUS_SUCCESS : NT_STATUS_UNSUCCESSFUL);
}

static void
smb_domainex_free(smb_domainex_t *dxi)
{
	free(dxi->d_trusted.td_domains);
	dxi->d_trusted.td_domains = NULL;
}

static void
smb_set_krb5_realm(char *domain)
{
	static char realm[MAXHOSTNAMELEN];

	if (domain == NULL || domain[0] == '\0') {
		(void) unsetenv("KRB5_DEFAULT_REALM");
		return;
	}

	/* In case krb5.conf is not configured, set the default realm. */
	(void) strlcpy(realm, domain, sizeof (realm));
	(void) smb_strupr(realm);

	(void) setenv("KRB5_DEFAULT_REALM", realm, 1);
}
