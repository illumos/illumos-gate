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
 */

/*
 * This file is here for legacy support.
 */

#include <atomic.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <libdllink.h>
#include <libscf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <libnwam.h>
#include "known_wlans.h"
#include "llp.h"
#include "ncu.h"
#include "util.h"

/*
 * This file formerly contained the routines that manipulate Link Layer
 * Profiles (aka LLPs) and various support functions.  Now only code
 * necessary for parsing the legacy /etc/nwam/llp file on upgrade is included,
 * since this legacy configuration needs to be translated into the User NCP.
 */

#define	OUR_OLD_DHCP_WAIT_TIME_PROP_NAME	"dhcp_wait_time"
#define	OUR_OLD_USE_NET_SVC_PROP_NAME		"use_net_svc"
#define	OUR_OLD_IDLE_TIME_PROP_NAME		"idle_time"

static struct qelem llp_list;

/*
 * Global variable to hold the highest priority.  Need to use the atomic
 * integer arithmetic functions to update it.
 */
static uint32_t llp_highest_pri;

/* Specifies if static address has been configured in /etc/nwam/llp */
static boolean_t static_configured = B_FALSE;

static enum interface_type
find_if_type(const char *name)
{
	uint32_t media;
	enum interface_type type;

	if (name == NULL) {
		nlog(LOG_DEBUG, "find_if_type: no ifname; "
		    "returning IF_UNKNOWN");
		return (IF_UNKNOWN);
	}

	type = IF_WIRED;
	if (dladm_name2info(dld_handle, name, NULL, NULL, NULL, &media) !=
	    DLADM_STATUS_OK) {
		if (strncmp(name, "ip.tun", 6) == 0 ||
		    strncmp(name, "ip6.tun", 7) == 0 ||
		    strncmp(name, "ip.6to4tun", 10) == 0)
			/*
			 * We'll need to update our tunnel detection once
			 * the clearview/tun project is integrated; tunnel
			 * names won't necessarily be ip.tunN.
			 */
			type = IF_TUN;
	} else if (media == DL_WIFI) {
		type = IF_WIRELESS;
	}

	return (type);
}

static void
llp_list_free(void)
{
	llp_t *llp;

	while (llp_list.q_forw != &llp_list) {
		llp = (llp_t *)llp_list.q_forw;
		remque(&llp->llp_links);
		free(llp->llp_ipv6addrstr);
		free(llp->llp_ipv4addrstr);
		free(llp);
	}
}

static void
initialize_llp(void)
{
	llp_list.q_forw = llp_list.q_back = &llp_list;
}

static llp_t *
llp_lookup(const char *link)
{
	llp_t *llp;

	if (link == NULL)
		return (NULL);

	for (llp = (llp_t *)llp_list.q_forw; llp != (llp_t *)&llp_list;
	    llp = (llp_t *)llp->llp_links.q_forw) {
		if (strcmp(link, llp->llp_lname) == 0)
			break;
	}
	if (llp == (llp_t *)&llp_list)
		llp = NULL;
	return (llp);
}

/*
 * Create the named LLP with default settings.  Called only in main thread.
 */
static llp_t *
llp_add(const char *name)
{
	llp_t *llp;

	if ((llp = calloc(1, sizeof (llp_t))) == NULL) {
		nlog(LOG_ERR, "llp_add: cannot allocate LLP: %m");
		return (NULL);
	}

	if (strlcpy(llp->llp_lname, name, sizeof (llp->llp_lname)) >=
	    sizeof (llp->llp_lname)) {
		nlog(LOG_ERR, "llp_add: linkname '%s' too long; ignoring entry",
		    name);
		free(llp);
		return (NULL);
	}

	llp->llp_fileorder = llp->llp_pri =
	    atomic_add_32_nv(&llp_highest_pri, 1);
	llp->llp_ipv4src = IPV4SRC_DHCP;
	llp->llp_type = find_if_type(llp->llp_lname);
	llp->llp_ipv6onlink = B_TRUE;

	/*
	 * should be a no-op, but for now, make sure we only
	 * create llps for wired and wireless interfaces.
	 */
	if (llp->llp_type != IF_WIRED && llp->llp_type != IF_WIRELESS) {
		nlog(LOG_ERR, "llp_add: wrong type of interface for %s", name);
		free(llp);
		return (NULL);
	}
	insque(&llp->llp_links, llp_list.q_back);

	nlog(LOG_DEBUG, "llp_add: "
	    "created llp for link %s, priority %d", llp->llp_lname,
	    llp->llp_pri);
	return (llp);
}

static int
parse_llp_config(void)
{
	static const char STATICSTR[] = "static";
	static const char DHCP[] = "dhcp";
	static const char IPV6[] = "ipv6";
	static const char NOIPV6[] = "noipv6";
	static const char PRIORITY[] = "priority";
	FILE *fp;
	char line[LINE_MAX];
	char *cp, *lasts, *lstr, *srcstr, *addrstr;
	int lnum;
	llp_t *llp;

	initialize_llp();

	fp = fopen(LLPFILE, "r+");
	if (fp == NULL) {
		if (errno == ENOENT)
			return (errno);
		nlog(LOG_ERR, "parse_llp_config: "
		    "open legacy LLP config file: %m");
		return (-1);
	}

	for (lnum = 1; fgets(line, sizeof (line), fp) != NULL; lnum++) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		nlog(LOG_DEBUG, "parse_llp_config: "
		    "parsing legacy LLP conf file line %d...", lnum);

		if (((lstr = strtok_r(cp, " \t", &lasts)) == NULL) ||
		    ((srcstr = strtok_r(NULL, " \t", &lasts)) == NULL)) {
			nlog(LOG_ERR, "parse_llp_config: line %d: "
			    "not enough tokens; ignoring entry", lnum);
			continue;
		}

		if ((llp = llp_lookup(lstr)) == NULL &&
		    (llp = llp_add(lstr)) == NULL) {
			nlog(LOG_ERR, "parse_llp_config: line %d: "
			    "cannot add entry", lnum);
			continue;
		}

		if (strcasecmp(srcstr, STATICSTR) == 0) {
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL ||
			    atoi(addrstr) == 0) { /* crude check for number */
				nlog(LOG_ERR, "parse_llp_config: line %d: "
				    "missing ipaddr for static config", lnum);
			} else if ((addrstr = strdup(addrstr)) == NULL) {
				nlog(LOG_ERR, "parse_llp_config: line %d: "
				    "cannot save address", lnum);
			} else {
				free(llp->llp_ipv4addrstr);
				llp->llp_ipv4src = IPV4SRC_STATIC;
				llp->llp_ipv4addrstr = addrstr;
			}

		} else if (strcasecmp(srcstr, DHCP) == 0) {
			llp->llp_ipv4src = IPV4SRC_DHCP;

		} else if (strcasecmp(srcstr, IPV6) == 0) {
			llp->llp_ipv6onlink = B_TRUE;
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL) {
				(void) 0;
			} else if ((addrstr = strdup(addrstr)) == NULL) {
				nlog(LOG_ERR, "parse_llp_config: line %d: "
				    "cannot save address", lnum);
			} else {
				free(llp->llp_ipv6addrstr);
				llp->llp_ipv6addrstr = addrstr;
			}

		} else if (strcasecmp(srcstr, NOIPV6) == 0) {
			llp->llp_ipv6onlink = B_FALSE;

		} else if (strcasecmp(srcstr, PRIORITY) == 0) {
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL) {
				nlog(LOG_ERR,
				    "parse_llp_config: line %d: "
				    "missing priority value", lnum);
			} else {
				llp->llp_pri = atoi(addrstr);
			}

		} else {
			nlog(LOG_ERR, "parse_llp_config: line %d: "
			    "unrecognized field '%s'", lnum, srcstr);
		}
	}

	(void) fclose(fp);
	return (0);
}

/*
 * Translate legacy LLP config into the user NCP.
 */
static int
upgrade_llp_config(void)
{
	llp_t *wp;
	nwam_ncp_handle_t user_ncp;
	nwam_ncu_handle_t phys_ncu = NULL, ip_ncu = NULL;
	nwam_error_t err;
	uint64_t uintval;
	char *strval;
	const char *prop;

	switch (parse_llp_config()) {
	case -1:
		return (0);
	case ENOENT:
		return (ENOENT);
	default:
		break;
	}

	err = nwam_ncp_create(NWAM_NCP_NAME_USER, 0, &user_ncp);
	switch (err) {
	case NWAM_SUCCESS:
		break;
	case NWAM_ERROR_BIND:
	case NWAM_ERROR_INTERNAL:
		nlog(LOG_ERR, "upgrade_llp_config: "
		    "could not create User NCP: %s", nwam_strerror(err));
		llp_list_free();
		return (EAGAIN);
	default:
		nlog(LOG_ERR, "upgrade_llp_config: error creating User NCP: %s",
		    nwam_strerror(err));
		llp_list_free();
		return (0);
	}

	nlog(LOG_DEBUG, "upgrade_llp_config: walking llp list");

	for (wp = (llp_t *)llp_list.q_forw; wp != (llp_t *)&llp_list;
	    wp = (llp_t *)wp->llp_links.q_forw) {

		nlog(LOG_DEBUG, "upgrade_llp_config: "
		    "upgrading llp %s", wp->llp_lname);

		if (nwam_ncu_create(user_ncp, wp->llp_lname,
		    NWAM_NCU_TYPE_INTERFACE, NWAM_NCU_CLASS_IP, &ip_ncu)
		    != NWAM_SUCCESS ||
		    nwam_ncu_create(user_ncp, wp->llp_lname, NWAM_NCU_TYPE_LINK,
		    NWAM_NCU_CLASS_PHYS, &phys_ncu) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade_llp_config: llp %s: "
			    "could not create NCUs: %s", wp->llp_lname,
			    nwam_strerror(err));
			break;
		}

		/* Link NCU properties */
		prop = NWAM_NCU_PROP_ACTIVATION_MODE;
		uintval = NWAM_ACTIVATION_MODE_PRIORITIZED;
		if ((err = nwamd_set_ncu_uint(phys_ncu, &uintval, 1, prop))
		    != NWAM_SUCCESS)
			break;

		prop = NWAM_NCU_PROP_PRIORITY_MODE;
		uintval = NWAM_PRIORITY_MODE_EXCLUSIVE;
		if ((err = nwamd_set_ncu_uint(phys_ncu, &uintval, 1, prop))
		    != NWAM_SUCCESS)
			break;

		prop = NWAM_NCU_PROP_PRIORITY_GROUP;
		uintval = wp->llp_pri;
		if ((err = nwamd_set_ncu_uint(phys_ncu, &uintval, 1, prop))
		    != NWAM_SUCCESS)
			break;

		/* IP NCU properties */
		if (wp->llp_ipv4addrstr != NULL) {
			/* Set v4 address and specify static addrsrc */
			prop = NWAM_NCU_PROP_IPV4_ADDRSRC;
			uintval = NWAM_ADDRSRC_STATIC;
			if ((err = nwamd_set_ncu_uint(ip_ncu, &uintval, 1,
			    prop)) != NWAM_SUCCESS)
				break;

			prop = NWAM_NCU_PROP_IPV4_ADDR;
			strval = wp->llp_ipv4addrstr;
			if ((err = nwamd_set_ncu_string(ip_ncu, &strval, 1,
			    prop)) != NWAM_SUCCESS)
				break;

			static_configured = B_TRUE;
		}

		if (wp->llp_ipv6addrstr != NULL) {
			/* Set v6 address and specify static addrsrc */
			prop = NWAM_NCU_PROP_IPV6_ADDRSRC;
			uintval = NWAM_ADDRSRC_STATIC;
			if ((err = nwamd_set_ncu_uint(ip_ncu, &uintval, 1,
			    prop)) != NWAM_SUCCESS)
				break;

			prop = NWAM_NCU_PROP_IPV6_ADDR;
			strval = wp->llp_ipv6addrstr;
			if ((err = nwamd_set_ncu_string(ip_ncu, &strval, 1,
			    prop)) != NWAM_SUCCESS)
				break;

			static_configured = B_TRUE;
		}

		if (!wp->llp_ipv6onlink) {
			prop = NWAM_NCU_PROP_IP_VERSION;
			uintval = IPV4_VERSION;
			if ((err = nwamd_set_ncu_uint(ip_ncu, &uintval, 1,
			    prop)) != NWAM_SUCCESS)
				break;
		}

		if ((err = nwam_ncu_commit(ip_ncu, 0)) != NWAM_SUCCESS ||
		    (err = nwam_ncu_commit(phys_ncu, 0)) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade_llp_config: llp %s: "
			    "could not commit NCUs: %s", wp->llp_lname,
			    nwam_strerror(err));
			/* Schedule a retry - root filesystem may be readonly */
			llp_list_free();
			nwam_ncu_free(ip_ncu);
			nwam_ncu_free(phys_ncu);
			(void) nwam_ncp_destroy(user_ncp, 0);
			return (EAGAIN);
		}
	}

	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "upgrade_llp_config: llp %s: "
		    "could not set value for property %s: %s", wp->llp_lname,
		    prop, nwam_strerror(err));
	}
	llp_list_free();
	nwam_ncu_free(ip_ncu);
	nwam_ncu_free(phys_ncu);
	nwam_ncp_free(user_ncp);
	return (0);
}

/*
 * Upgrade legacy llp and known_wifi_nets files. Note - it is possible that
 * the root filesystem is not writable at this point, so we need to schedule
 * a retry of the upgrade operation in the event that committing the new
 * config fails.
 */
/* ARGSUSED0 */
void
nwamd_handle_upgrade(nwamd_event_t event)
{
	nwamd_event_t upgrade_event;
	uint64_t dhcp_wait_time, idle_time;
	boolean_t use_net_svc;

	switch (upgrade_llp_config()) {
	case -1:
	case ENOENT:
		/* Nothing readable to upgrade */
		break;
	case EAGAIN:
		/*
		 * Schedule retry in NWAMD_READONLY_RETRY_INTERVAL seconds
		 * as root fs may be readonly.
		 *
		 * The upgrade event is of type NCU, but has no associated
		 * object (we use the event type to map to the appropriate
		 * event/method mappings, so to find the NCU upgrade event
		 * method we specify type NCU while not specifying an
		 * object since all NCUs have to be upgraded.
		 */
		upgrade_event = nwamd_event_init(NWAM_EVENT_TYPE_UPGRADE,
		    NWAM_OBJECT_TYPE_NCP, 0, NULL);
		if (upgrade_event == NULL) {
			nlog(LOG_ERR, "nwamd_handle_upgrade: "
			    "could not create retry event to upgrade "
			    "%s configuration", LLPFILE);
			return;
		}
		nwamd_event_enqueue_timed(upgrade_event,
		    NWAMD_READONLY_RETRY_INTERVAL);
		return;
	default:
		break;
	}

	/*
	 * If static_configured is set, then at least one static address is
	 * configured in /etc/nwam/llp.  Enable the User NCP in this case.
	 */
	if (static_configured) {
		nlog(LOG_DEBUG, "nwamd_handle_upgrade: "
		    "static address configured, enabling User NCP");
		(void) pthread_mutex_lock(&active_ncp_mutex);
		(void) strlcpy(active_ncp, NWAM_NCP_NAME_USER,
		    NWAM_MAX_NAME_LEN);
		(void) pthread_mutex_unlock(&active_ncp_mutex);
	}

	/* upgrade /etc/nwam/known_wifi_nets */
	upgrade_known_wifi_nets_config();

	/*
	 * SMF property nwamd/dhcp_wait_time in Phase 0/0.5 has been
	 * replaced by nwamd/ncu_wait_time property.  If the dhcp_wait_time
	 * property exists (which means it has been changed by the user),
	 * set its value to ncu_wait_time and remove the property.
	 */
	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG,
	    OUR_OLD_DHCP_WAIT_TIME_PROP_NAME, &dhcp_wait_time) == 0) {
		(void) nwamd_set_count_property(OUR_FMRI, OUR_PG,
		    OUR_NCU_WAIT_TIME_PROP_NAME, dhcp_wait_time);
		(void) nwamd_delete_scf_property(OUR_FMRI, OUR_PG,
		    OUR_OLD_DHCP_WAIT_TIME_PROP_NAME);
		nlog(LOG_DEBUG, "nwamd_handle_upgrade: "
		    "converted '%s' to '%s' with value of %lld",
		    OUR_OLD_DHCP_WAIT_TIME_PROP_NAME,
		    OUR_NCU_WAIT_TIME_PROP_NAME, dhcp_wait_time);
	}

	/*
	 * If the user has changed Phase 0/0.5 properties that don't exist in
	 * Phase 1, manifest-import reports a warning; but those properties are
	 * not removed.  nwamd/use_net_svc and nwamd/idle_time are two
	 * properties that don't exist in Phase 1.  If they exist, remove them.
	 */
	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG,
	    OUR_OLD_IDLE_TIME_PROP_NAME, &idle_time) == 0) {
		(void) nwamd_delete_scf_property(OUR_FMRI, OUR_PG,
		    OUR_OLD_IDLE_TIME_PROP_NAME);
	}
	if (nwamd_lookup_boolean_property(OUR_FMRI, OUR_PG,
	    OUR_OLD_USE_NET_SVC_PROP_NAME, &use_net_svc) == 0) {
		(void) nwamd_delete_scf_property(OUR_FMRI, OUR_PG,
		    OUR_OLD_USE_NET_SVC_PROP_NAME);
	}

	nlog(LOG_DEBUG, "nwamd_handle_upgrade: "
	    "creating version property, setting to 1\n");
	(void) nwamd_set_count_property(OUR_FMRI, OUR_PG,
	    OUR_VERSION_PROP_NAME, 1U);
	(void) smf_refresh_instance(OUR_FMRI);
}
