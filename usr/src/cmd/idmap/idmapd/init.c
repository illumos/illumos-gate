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

/*
 * Initialization routines
 */

#include "idmapd.h"
#include <signal.h>
#include <thread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpcsvc/daemon_utils.h>


int
init_mapping_system()
{
	int rc = 0;

	if ((rc = load_config()) < 0)
		return (rc);

	(void) setegid(DAEMON_GID);
	(void) seteuid(DAEMON_UID);
	if (init_dbs() < 0) {
		rc = -1;
		fini_mapping_system();
	}
	(void) seteuid(0);
	(void) setegid(0);

	return (rc);
}

void
fini_mapping_system()
{
	fini_dbs();
}

int
load_config()
{
	int rc;
	if ((_idmapdstate.cfg = idmap_cfg_init()) == NULL) {
		degrade_svc(0, "failed to initialize config");
		return (-1);
	}

	rc = idmap_cfg_upgrade(_idmapdstate.cfg);
	if (rc != 0) {
		degrade_svc(0, "fatal error while upgrading configuration");
		return (rc);
	}

	rc = idmap_cfg_load(_idmapdstate.cfg, 0);
	if (rc < -1) {
		/* Total failure */
		degrade_svc(0, "fatal error while loading configuration");
		return (rc);
	}

	if (rc != 0)
		/* Partial failure */
		idmapdlog(LOG_ERR, "Various errors occurred while loading "
		    "the configuration; check the logs");

	if ((rc = idmap_cfg_start_updates()) < 0) {
		/* Total failure */
		degrade_svc(0, "could not start config updater");
		return (rc);
	}

	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Initial configuration loaded");

	return (0);
}


void
reload_gcs()
{
	int		i, j;
	adutils_ad_t	**new_gcs;
	adutils_ad_t	**old_gcs = _idmapdstate.gcs;
	int		new_num_gcs;
	int		old_num_gcs = _idmapdstate.num_gcs;
	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;
	idmap_trustedforest_t *trustfor = pgcfg->trusted_forests;
	int		num_trustfor = pgcfg->num_trusted_forests;
	ad_disc_domainsinforest_t *domain_in_forest;

	if (pgcfg->use_ads == B_FALSE ||
	    pgcfg->domain_name == NULL) {
		/*
		 * ADS disabled, or no domain name specified.
		 * Not using adutils. (but still can use lsa)
		 */
		new_gcs = NULL;
		new_num_gcs = 0;
		goto out;
	}

	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		/*
		 * No GCs.  Continue to use the previous AD config in case
		 * that's still good but auto-discovery had a transient failure.
		 * If that stops working we'll go into degraded mode anyways
		 * when it does.
		 */
		idmapdlog(LOG_INFO,
		    "Global Catalog servers not configured/discoverable");
		return;
	}

	new_num_gcs = 1 + num_trustfor;
	new_gcs = calloc(new_num_gcs, sizeof (adutils_ad_t *));
	if (new_gcs == NULL) {
		degrade_svc(0, "could not allocate AD context array "
		    "(out of memory)");
		return;
	}

	if (adutils_ad_alloc(&new_gcs[0], NULL, ADUTILS_AD_GLOBAL_CATALOG) !=
	    ADUTILS_SUCCESS) {
		free(new_gcs);
		degrade_svc(0, "could not initialize AD context "
		    "(out of memory)");
		return;
	}

	for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++) {
		if (idmap_add_ds(new_gcs[0],
		    pgcfg->global_catalog[i].host,
		    pgcfg->global_catalog[i].port) != 0) {
			adutils_ad_free(&new_gcs[0]);
			free(new_gcs);
			degrade_svc(0, "could not set AD hosts "
			    "(out of memory)");
			return;
		}
	}

	if (pgcfg->domains_in_forest != NULL) {
		for (i = 0; pgcfg->domains_in_forest[i].domain[0] != '\0';
		    i++) {
			if (adutils_add_domain(new_gcs[0],
			    pgcfg->domains_in_forest[i].domain,
			    pgcfg->domains_in_forest[i].sid) != 0) {
				adutils_ad_free(&new_gcs[0]);
				free(new_gcs);
				degrade_svc(0, "could not set AD domains "
				    "(out of memory)");
				return;
			}
		}
	}

	for (i = 0; i < num_trustfor; i++) {
		if (adutils_ad_alloc(&new_gcs[i + 1], NULL,
		    ADUTILS_AD_GLOBAL_CATALOG) != ADUTILS_SUCCESS) {
			degrade_svc(0, "could not initialize trusted AD "
			    "context (out of memory)");
				new_num_gcs = i + 1;
				goto out;
		}
		for (j = 0; trustfor[i].global_catalog[j].host[0] != '\0';
		    j++) {
			if (idmap_add_ds(new_gcs[i + 1],
			    trustfor[i].global_catalog[j].host,
			    trustfor[i].global_catalog[j].port) != 0) {
				adutils_ad_free(&new_gcs[i + 1]);
				degrade_svc(0, "could not set trusted "
				    "AD hosts (out of memory)");
				new_num_gcs = i + 1;
				goto out;
			}
		}
		for (j = 0; trustfor[i].domains_in_forest[j].domain[0] != '\0';
		    j++) {
			domain_in_forest = &trustfor[i].domains_in_forest[j];
			/* Only add domains which are marked */
			if (domain_in_forest->trusted) {
				if (adutils_add_domain(new_gcs[i + 1],
				    domain_in_forest->domain,
				    domain_in_forest->sid) != 0) {
					adutils_ad_free(&new_gcs[i + 1]);
					degrade_svc(0, "could not set trusted "
					    "AD domains (out of memory)");
					new_num_gcs = i + 1;
					goto out;
				}
			}
		}
	}

out:
	_idmapdstate.gcs = new_gcs;
	_idmapdstate.num_gcs = new_num_gcs;

	if (old_gcs != NULL) {
		for (i = 0; i < old_num_gcs; i++)
			adutils_ad_free(&old_gcs[i]);
		free(old_gcs);
	}
}

/*
 * NEEDSWORK:  This should load entries for domain servers for all known
 * domains - the joined domain, other domains in the forest, and trusted
 * domains in other forests.  However, we don't yet discover any DCs other
 * than the DCs for the joined domain.
 */
static
void
reload_dcs(void)
{
	int		i;
	adutils_ad_t	**new_dcs;
	adutils_ad_t	**old_dcs = _idmapdstate.dcs;
	int		new_num_dcs;
	int		old_num_dcs = _idmapdstate.num_dcs;
	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;

	if (pgcfg->use_ads == B_FALSE ||
	    pgcfg->domain_name == NULL) {
		/*
		 * ADS disabled, or no domain name specified.
		 * Not using adutils. (but still can use lsa)
		 */
		new_dcs = NULL;
		new_num_dcs = 0;
		goto out;
	}

	if (pgcfg->domain_controller == NULL ||
	    pgcfg->domain_controller[0].host[0] == '\0') {
		/*
		 * No DCs.  Continue to use the previous AD config in case
		 * that's still good but auto-discovery had a transient failure.
		 * If that stops working we'll go into degraded mode anyways
		 * when it does.
		 */
		idmapdlog(LOG_INFO,
		    "Domain controller servers not configured/discoverable");
		return;
	}

	new_num_dcs = 1;
	new_dcs = calloc(new_num_dcs, sizeof (adutils_ad_t *));
	if (new_dcs == NULL)
		goto nomem;

	if (adutils_ad_alloc(&new_dcs[0], pgcfg->domain_name,
	    ADUTILS_AD_DATA) != ADUTILS_SUCCESS)
		goto nomem;

	for (i = 0; pgcfg->domain_controller[i].host[0] != '\0'; i++) {
		if (idmap_add_ds(new_dcs[0],
		    pgcfg->domain_controller[i].host,
		    pgcfg->domain_controller[i].port) != 0)
			goto nomem;
	}

	/*
	 * NEEDSWORK:  All we need here is to add the domain and SID for
	 * this DC to the list of domains supported by this entry.  Isn't
	 * there an easier way to find the SID than to walk through the list
	 * of all of the domains in the forest?
	 */
	ad_disc_domainsinforest_t *dif = pgcfg->domains_in_forest;
	if (dif != NULL) {
		for (; dif->domain[0] != '\0'; dif++) {
			if (domain_eq(pgcfg->domain_name, dif->domain)) {
				if (adutils_add_domain(new_dcs[0],
				    dif->domain, dif->sid) != 0)
					goto nomem;
				break;
			}
		}
	}

out:
	_idmapdstate.dcs = new_dcs;
	_idmapdstate.num_dcs = new_num_dcs;

	if (old_dcs != NULL) {
		for (i = 0; i < old_num_dcs; i++)
			adutils_ad_free(&old_dcs[i]);
		free(old_dcs);
	}

	return;

nomem:
	degrade_svc(0, "out of memory");

	if (new_dcs != NULL) {
		if (new_dcs[0] != NULL)
			adutils_ad_free(&new_dcs[0]);
		free(new_dcs);
	}
}


void
reload_ad(void)
{
	reload_gcs();
	reload_dcs();
}

void
print_idmapdstate(void)
{
	int i, j;
	idmap_pg_config_t *pgcfg;
	idmap_trustedforest_t *tf;

	RDLOCK_CONFIG();

	if (_idmapdstate.cfg == NULL) {
		idmapdlog(LOG_INFO, "Null configuration");
		UNLOCK_CONFIG();
		return;
	}

	pgcfg = &_idmapdstate.cfg->pgcfg;

	idmapdlog(LOG_DEBUG, "list_size_limit=%llu", pgcfg->list_size_limit);
	idmapdlog(LOG_DEBUG, "default_domain=%s",
	    CHECK_NULL(pgcfg->default_domain));
	idmapdlog(LOG_DEBUG, "domain_name=%s", CHECK_NULL(pgcfg->domain_name));
	idmapdlog(LOG_DEBUG, "machine_sid=%s", CHECK_NULL(pgcfg->machine_sid));
	if (pgcfg->domain_controller == NULL ||
	    pgcfg->domain_controller[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No domain controllers known");
	} else {
		for (i = 0; pgcfg->domain_controller[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "domain_controller=%s port=%d",
			    pgcfg->domain_controller[i].host,
			    pgcfg->domain_controller[i].port);
	}
	idmapdlog(LOG_DEBUG, "forest_name=%s", CHECK_NULL(pgcfg->forest_name));
	idmapdlog(LOG_DEBUG, "site_name=%s", CHECK_NULL(pgcfg->site_name));
	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No global catalog servers known");
	} else {
		for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "global_catalog=%s port=%d",
			    pgcfg->global_catalog[i].host,
			    pgcfg->global_catalog[i].port);
	}
	if (pgcfg->domains_in_forest == NULL ||
	    pgcfg->domains_in_forest[0].domain[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No domains in forest %s known",
		    CHECK_NULL(pgcfg->forest_name));
	} else {
		for (i = 0; pgcfg->domains_in_forest[i].domain[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "domains in forest %s = %s",
			    CHECK_NULL(pgcfg->forest_name),
			    pgcfg->domains_in_forest[i].domain);
	}
	if (pgcfg->trusted_domains == NULL ||
	    pgcfg->trusted_domains[0].domain[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No trusted domains known");
	} else {
		for (i = 0; pgcfg->trusted_domains[i].domain[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "trusted domain = %s",
			    pgcfg->trusted_domains[i].domain);
	}

	for (i = 0; i < pgcfg->num_trusted_forests; i++) {
		tf = &pgcfg->trusted_forests[i];
		for (j = 0; tf->global_catalog[j].host[0] != '\0'; j++)
			idmapdlog(LOG_DEBUG,
			    "trusted forest %s global_catalog=%s port=%d",
			    tf->forest_name,
			    tf->global_catalog[j].host,
			    tf->global_catalog[j].port);
		for (j = 0; tf->domains_in_forest[j].domain[0] != '\0'; j++) {
			if (tf->domains_in_forest[j].trusted) {
				idmapdlog(LOG_DEBUG,
				    "trusted forest %s domain=%s",
				    tf->forest_name,
				    tf->domains_in_forest[j].domain);
			}
		}
	}

	idmapdlog(LOG_DEBUG, "directory_based_mapping=%s",
	    enum_lookup(pgcfg->directory_based_mapping, directory_mapping_map));
	idmapdlog(LOG_DEBUG, "ad_unixuser_attr=%s",
	    CHECK_NULL(pgcfg->ad_unixuser_attr));
	idmapdlog(LOG_DEBUG, "ad_unixgroup_attr=%s",
	    CHECK_NULL(pgcfg->ad_unixgroup_attr));
	idmapdlog(LOG_DEBUG, "nldap_winname_attr=%s",
	    CHECK_NULL(pgcfg->nldap_winname_attr));

	UNLOCK_CONFIG();
}

int
create_directory(const char *path, uid_t uid, gid_t gid)
{
	int	rc;

	if ((rc = mkdir(path, 0700)) < 0 && errno != EEXIST) {
		idmapdlog(LOG_ERR, "Error creating directory %s (%s)",
		    path, strerror(errno));
		return (-1);
	}

	if (lchown(path, uid, gid) < 0) {
		idmapdlog(LOG_ERR, "Error creating directory %s (%s)",
		    path, strerror(errno));
		if (rc == 0)
			(void) rmdir(path);
		return (-1);
	}
	return (0);
}
