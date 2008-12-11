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
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/ntstatus.h>
#include <lsalib.h>

/*
 * Domain cache states
 */
#define	SMB_DCACHE_STATE_INVALID	0
#define	SMB_DCACHE_STATE_UPDATING	1
#define	SMB_DCACHE_STATE_VALID		2

typedef struct smb_domain_cache {
	uint32_t	c_state;
	smb_domain_t	c_cache;
	mutex_t		c_mtx;
	cond_t		c_cv;
} smb_domain_cache_t;

static smb_domain_cache_t smb_dcache;

/* functions to manipulate the domain cache */
static void smb_dcache_init(void);
static void smb_dcache_updating(void);
static void smb_dcache_invalid(void);
static void smb_dcache_valid(smb_domain_t *);
static void smb_dcache_set(uint32_t, smb_domain_t *);

/*
 * DC Locator
 */
#define	SMB_DCLOCATOR_TIMEOUT	45
#define	SMB_IS_FQDN(domain)	(strchr(domain, '.') != NULL)

typedef struct smb_dclocator {
	char sdl_domain[SMB_PI_MAX_DOMAIN];
	char sdl_dc[MAXHOSTNAMELEN];
	boolean_t sdl_locate;
	mutex_t sdl_mtx;
	cond_t sdl_cv;
	uint32_t sdl_status;
} smb_dclocator_t;

static smb_dclocator_t smb_dclocator;
static pthread_t smb_dclocator_thr;

static void *smb_dclocator_main(void *);
static boolean_t smb_dc_discovery(char *, char *, smb_domain_t *);
static boolean_t smb_match_domains(char *, char *, uint32_t);
static uint32_t smb_domain_query(char *, char *, smb_domain_t *);
static void smb_domain_update_tabent(int, lsa_nt_domaininfo_t *);
static void smb_domain_populate_table(char *, char *);
static boolean_t smb_domain_use_config(char *, smb_domain_t *);

/*
 * ===================================================================
 * API to initialize DC locator thread, trigger DC discovery, and
 * get the discovered DC and/or domain information.
 * ===================================================================
 */

/*
 * smb_dclocator_init
 *
 * Initialization of the DC locator thread.
 * Returns 0 on success, an error number if thread creation fails.
 */
int
smb_dclocator_init(void)
{
	pthread_attr_t tattr;
	int rc;

	smb_dcache_init();
	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smb_dclocator_thr, &tattr,
	    smb_dclocator_main, 0);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

/*
 * smb_locate_dc
 *
 * This is the entry point for discovering a domain controller for the
 * specified domain.
 *
 * The actual work of discovering a DC is handled by DC locator thread.
 * All we do here is signal the request and wait for a DC or a timeout.
 *
 * Input parameters:
 *  domain - domain to be discovered (can either be NetBIOS or DNS domain)
 *  dc - preferred DC. If the preferred DC is set to empty string, it
 *       will attempt to discover any DC in the specified domain.
 *
 * Output parameter:
 *  dp - on success, dp will be filled with the discovered DC and domain
 *       information.
 * Returns B_TRUE if the DC/domain info is available.
 */
boolean_t
smb_locate_dc(char *domain, char *dc, smb_domain_t *dp)
{
	int rc;
	timestruc_t to;
	smb_domain_t domain_info;

	if (domain == NULL || *domain == '\0')
		return (B_FALSE);

	(void) mutex_lock(&smb_dclocator.sdl_mtx);

	if (!smb_dclocator.sdl_locate) {
		smb_dclocator.sdl_locate = B_TRUE;
		(void) strlcpy(smb_dclocator.sdl_domain, domain,
		    SMB_PI_MAX_DOMAIN);
		(void) strlcpy(smb_dclocator.sdl_dc, dc,
		    MAXHOSTNAMELEN);
		(void) cond_broadcast(&smb_dclocator.sdl_cv);
	}

	while (smb_dclocator.sdl_locate) {
		to.tv_sec = SMB_DCLOCATOR_TIMEOUT;
		to.tv_nsec = 0;
		rc = cond_reltimedwait(&smb_dclocator.sdl_cv,
		    &smb_dclocator.sdl_mtx, &to);

		if (rc == ETIME)
			break;
	}

	if (dp == NULL)
		dp = &domain_info;
	rc = smb_domain_getinfo(dp);
	(void) mutex_unlock(&smb_dclocator.sdl_mtx);

	return (rc);
}

/*
 * smb_domain_getinfo
 *
 * If the DC discovery process is underway, this function will wait on
 * a condition variable until the state of SMB domain cache sets to
 * either VALID/INVALID.
 *
 * Returns a copy of the domain cache.
 */
boolean_t
smb_domain_getinfo(smb_domain_t *dp)
{
	timestruc_t to;
	int err;
	boolean_t rc;

	(void) mutex_lock(&smb_dcache.c_mtx);
	to.tv_sec = SMB_DCLOCATOR_TIMEOUT;
	to.tv_nsec = 0;
	while (smb_dcache.c_state == SMB_DCACHE_STATE_UPDATING) {
		err = cond_reltimedwait(&smb_dcache.c_cv, &smb_dcache.c_mtx,
		    &to);
		if (err == ETIME)
			break;
	}

	if (smb_dcache.c_state == SMB_DCACHE_STATE_VALID) {
		bcopy(&smb_dcache.c_cache, dp, sizeof (smb_domain_t));
		rc = B_TRUE;
	} else {
		bzero(dp, sizeof (smb_domain_t));
		rc = B_FALSE;
	}

	(void) mutex_unlock(&smb_dcache.c_mtx);
	return (rc);
}


/*
 * =====================================================================
 * Private functions used by DC locator thread to manipulate the domain
 * cache.
 * ======================================================================
 */

static void
smb_dcache_init(void)
{
	(void) mutex_lock(&smb_dcache.c_mtx);
	smb_dcache.c_state = SMB_DCACHE_STATE_INVALID;
	bzero(&smb_dcache.c_cache, sizeof (smb_domain_t));
	(void) mutex_unlock(&smb_dcache.c_mtx);
}

/*
 * Set the cache state to UPDATING
 */
static void
smb_dcache_updating(void)
{
	smb_dcache_set(SMB_DCACHE_STATE_UPDATING, NULL);
}

/*
 * Set the cache state to INVALID
 */
static void
smb_dcache_invalid(void)
{
	smb_dcache_set(SMB_DCACHE_STATE_INVALID, NULL);
}

/*
 * Set the cache state to VALID and populate the cache
 */
static void
smb_dcache_valid(smb_domain_t *dp)
{
	smb_dcache_set(SMB_DCACHE_STATE_VALID, dp);
}

/*
 * This function will update both the state and the contents of the
 * SMB domain cache.  If one attempts to set the state to
 * SMB_DCACHE_STATE_UPDATING, the domain cache will be updated based
 * on 'dp' argument. Otherwise, 'dp' is ignored.
 */
static void
smb_dcache_set(uint32_t state, smb_domain_t *dp)
{
	(void) mutex_lock(&smb_dcache.c_mtx);
	switch (state) {
	case  SMB_DCACHE_STATE_INVALID:
		break;

	case SMB_DCACHE_STATE_UPDATING:
		bzero(&smb_dcache.c_cache, sizeof (smb_domain_t));
		break;

	case SMB_DCACHE_STATE_VALID:
		assert(dp);
		bcopy(dp, &smb_dcache.c_cache, sizeof (smb_domain_t));
		break;

	default:
		(void) mutex_unlock(&smb_dcache.c_mtx);
		return;

	}

	smb_dcache.c_state = state;
	(void) cond_broadcast(&smb_dcache.c_cv);
	(void) mutex_unlock(&smb_dcache.c_mtx);
}

/*
 * ==========================================================
 * DC discovery functions
 * ==========================================================
 */

/*
 * smb_dclocator_main
 *
 * This is the DC discovery thread: it gets woken up whenever someone
 * wants to locate a domain controller.
 *
 * The state of the SMB domain cache will be initialized to
 * SMB_DCACHE_STATE_UPDATING when the discovery process starts and will be
 * transitioned to SMB_DCACHE_STATE_VALID/INVALID depending on the outcome of
 * the discovery.
 *
 * If the discovery process is underway, callers of smb_domain_getinfo()
 * will wait on a condition variable until the state of SMB domain cache
 * sets to either VALID/INVALID.
 *
 * Upon success, the SMB domain cache will be populated with the discovered DC
 * and domain info.
 */
/*ARGSUSED*/
static void *
smb_dclocator_main(void *arg)
{
	char domain[SMB_PI_MAX_DOMAIN];
	char sought_dc[MAXHOSTNAMELEN];
	smb_domain_t dinfo;

	for (;;) {
		(void) mutex_lock(&smb_dclocator.sdl_mtx);

		while (!smb_dclocator.sdl_locate)
			(void) cond_wait(&smb_dclocator.sdl_cv,
			    &smb_dclocator.sdl_mtx);

		(void) strlcpy(domain, smb_dclocator.sdl_domain,
		    SMB_PI_MAX_DOMAIN);
		(void) strlcpy(sought_dc, smb_dclocator.sdl_dc, MAXHOSTNAMELEN);
		(void) mutex_unlock(&smb_dclocator.sdl_mtx);

		smb_dcache_updating();
		if (smb_dc_discovery(domain, sought_dc, &dinfo))
			smb_dcache_valid(&dinfo);
		else
			smb_dcache_invalid();

		(void) mutex_lock(&smb_dclocator.sdl_mtx);
		smb_dclocator.sdl_locate = B_FALSE;
		(void) cond_broadcast(&smb_dclocator.sdl_cv);
		(void) mutex_unlock(&smb_dclocator.sdl_mtx);
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * smb_dc_discovery
 *
 * If FQDN is specified, DC discovery will be done via DNS query only.
 * If NetBIOS name of a domain is specified, DC discovery thread will
 * use netlogon protocol to locate a DC. Upon failure, it will
 * try to resolve it via DNS, i.e. find out if it is the first label
 * of a DNS domain name. If the corresponding DNS name is found, DC
 * discovery will be done via DNS query.
 *
 * Once the domain controller is found, it then queries the DC for domain
 * information. If the LSA queries fail, the domain information stored in
 * SMF might be used to set the SMB domain cache if the the discovered domain
 * is the same as the previously joined domain.
 *
 * If the fully-qualified domain name is derived from the DNS config
 * file, the NetBIOS domain name specified by the user will be compared
 * against the NetBIOS domain name obtained via LSA query.  If there is
 * a mismatch, the DC discovery will fail since the discovered DC is
 * actually for another domain, whose first label of its FQDN somehow
 * matches with the NetBIOS name of the domain we're interested in.
 */
static boolean_t
smb_dc_discovery(char *domain, char *server, smb_domain_t *dinfo)
{
	char derived_dnsdomain[MAXHOSTNAMELEN];
	boolean_t netlogon_ok = B_FALSE;

	*derived_dnsdomain = '\0';
	if (!SMB_IS_FQDN(domain)) {
		if (smb_browser_netlogon(domain, dinfo->d_dc, MAXHOSTNAMELEN))
			netlogon_ok = B_TRUE;
		else if (!smb_match_domains(domain, derived_dnsdomain,
		    MAXHOSTNAMELEN))
			return (B_FALSE);
	}

	if (!netlogon_ok && !smb_ads_lookup_msdcs(
	    (SMB_IS_FQDN(domain) ? domain : derived_dnsdomain), server,
	    dinfo->d_dc, MAXHOSTNAMELEN))
		return (B_FALSE);

	if ((smb_domain_query(domain, dinfo->d_dc, dinfo)
	    != NT_STATUS_SUCCESS) &&
	    (!smb_domain_use_config(domain, dinfo)))
			return (B_FALSE);

	if (*derived_dnsdomain != '\0' &&
	    utf8_strcasecmp(domain, dinfo->d_nbdomain))
		return (B_FALSE);

	/*
	 * Now that we get the fully-qualified DNS name of the
	 * domain via LSA query. Verifies ADS configuration
	 * if we previously locate a DC via NetBIOS. On success,
	 * ADS cache will be populated.
	 */
	if (netlogon_ok) {
		if (smb_ads_lookup_msdcs(dinfo->d_fqdomain, server,
		    dinfo->d_dc, MAXHOSTNAMELEN) == 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Tries to find a matching DNS domain for the given NetBIOS domain
 * name by checking the first label of system's configured DNS domains.
 * If a match is found, it'll be returned in the passed buffer.
 */
static boolean_t
smb_match_domains(char *nb_domain, char *buf, uint32_t len)
{
	struct __res_state res_state;
	int i;
	char *entry, *p;
	char first_label[MAXHOSTNAMELEN];
	boolean_t found;

	if (!nb_domain || !buf)
		return (B_FALSE);

	*buf = '\0';
	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state))
		return (B_FALSE);

	found = B_FALSE;
	entry = res_state.defdname;
	for (i = 0; entry != NULL; i++) {
		(void) strlcpy(first_label, entry, MAXHOSTNAMELEN);
		if ((p = strchr(first_label, '.')) != NULL) {
			*p = '\0';
			if (strlen(first_label) > 15)
				first_label[15] = '\0';
		}

		if (utf8_strcasecmp(nb_domain, first_label) == 0) {
			found = B_TRUE;
			(void) strlcpy(buf, entry, len);
			break;
		}

		entry = res_state.dnsrch[i];
	}


	res_ndestroy(&res_state);
	return (found);
}

/*
 * smb_domain_query
 *
 * If the the NetBIOS name of an AD domain doesn't match with the
 * first label of its fully-qualified DNS name, it is not possible
 * to derive one name format from another.
 * The missing domain info can be obtained via LSA query, DNS domain info.
 *
 * domain - either NetBIOS or fully-qualified domain name
 *
 */
static uint32_t
smb_domain_query(char *domain, char *server, smb_domain_t *dp)
{
	uint32_t rc;
	lsa_info_t info;

	rc = lsa_query_dns_domain_info(server, domain, &info);
	if (rc == NT_STATUS_SUCCESS) {
		lsa_dns_domaininfo_t *dnsinfo = &info.i_domain.di_dns;
		(void) strlcpy(dp->d_nbdomain, dnsinfo->d_nbdomain,
		    sizeof (dp->d_nbdomain));
		(void) strlcpy(dp->d_fqdomain, dnsinfo->d_fqdomain,
		    sizeof (dp->d_fqdomain));
		(void) strlcpy(dp->d_forest, dnsinfo->d_forest,
		    sizeof (dp->d_forest));
		ndr_uuid_unparse((ndr_uuid_t *)&dnsinfo->d_guid, dp->d_guid);
		smb_sid_free(dnsinfo->d_sid);
	}

	smb_domain_populate_table(domain, server);
	return (rc);
}

/*
 * smb_domain_populate_table
 *
 * Populates the domain tablele with primary, account and trusted
 * domain info.
 * domain - either NetBIOS or fully-qualified domain name.
 */
static void
smb_domain_populate_table(char *domain, char *server)
{
	lsa_info_t info;
	lsa_nt_domaininfo_t *nt_info;
	int i;

	if (lsa_query_primary_domain_info(server, domain, &info)
	    == NT_STATUS_SUCCESS) {
		nt_info = &info.i_domain.di_primary;
		smb_domain_update_tabent(NT_DOMAIN_PRIMARY, nt_info);
		lsa_free_info(&info);
	}

	if (lsa_query_account_domain_info(server, domain, &info)
	    == NT_STATUS_SUCCESS) {
		nt_info = &info.i_domain.di_account;
		smb_domain_update_tabent(NT_DOMAIN_ACCOUNT, nt_info);
		lsa_free_info(&info);
	}

	if (lsa_enum_trusted_domains(server, domain, &info)
	    == NT_STATUS_SUCCESS) {
		lsa_trusted_domainlist_t *list = &info.i_domain.di_trust;
		for (i = 0; i < list->t_num; i++) {
			nt_info = &list->t_domains[i];
			smb_domain_update_tabent(NT_DOMAIN_TRUSTED, nt_info);
		}

		lsa_free_info(&info);
	}


}

static void
smb_domain_update_tabent(int domain_type, lsa_nt_domaininfo_t *info)
{
	nt_domain_t *entry;
	nt_domain_flush(domain_type);
	entry = nt_domain_new(domain_type, info->n_domain, info->n_sid);
	(void) nt_domain_add(entry);
}

/*
 * smb_domain_use_config
 *
 * If the domain to be discovered matches the current domain (i.e the
 * value of either domain or fqdn configuration), the output parameter
 * 'dinfo' will be set to the information stored in SMF.
 */
static boolean_t
smb_domain_use_config(char *domain, smb_domain_t *dinfo)
{
	smb_domain_t orig;
	boolean_t use;

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return (B_FALSE);

	smb_config_getdomaininfo(orig.d_nbdomain, orig.d_fqdomain,
	    orig.d_forest, orig.d_guid);

	if (SMB_IS_FQDN(domain)) {
		use = (utf8_strcasecmp(orig.d_fqdomain, domain) == 0);
	} else {
		use = (utf8_strcasecmp(orig.d_nbdomain, domain) == 0);
	}

	if (use) {
		(void) strlcpy(dinfo->d_nbdomain, orig.d_nbdomain,
		    sizeof (dinfo->d_nbdomain));
		(void) strlcpy(dinfo->d_fqdomain, orig.d_fqdomain,
		    sizeof (dinfo->d_fqdomain));
		(void) strlcpy(dinfo->d_forest, orig.d_forest,
		    sizeof (dinfo->d_forest));
		(void) bcopy(orig.d_guid, dinfo->d_guid,
		    sizeof (dinfo->d_guid));
	}

	return (use);
}
