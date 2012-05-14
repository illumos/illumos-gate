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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlwlan.h>
#include <libgen.h>
#include <libnwam.h>

#include "events.h"
#include "known_wlans.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * known_wlans.c - contains routines which handle the known WLAN abstraction.
 */

#define	KNOWN_WIFI_NETS_FILE		"/etc/nwam/known_wifi_nets"

/* enum for parsing each line of /etc/nwam/known_wifi_nets */
typedef enum {
	ESSID = 0,
	BSSID,
	MAX_FIELDS
} known_wifi_nets_fields_t;

/* Structure for one BSSID */
typedef struct bssid {
	struct qelem	bssid_links;
	char		*bssid;
} bssid_t;

/* Structure for an ESSID and its BSSIDs */
typedef struct kw {
	struct qelem	kw_links;
	char		kw_essid[NWAM_MAX_NAME_LEN];
	uint32_t	kw_num_bssids;
	struct qelem	kw_bssids;
} kw_t;

/* Holds the linked-list of ESSIDs to make Known WLANs out of */
static struct qelem kw_list;

/* Used in walking secobjs looking for an ESSID prefix match. */
struct nwamd_secobj_arg {
	char nsa_essid_prefix[DLADM_WLAN_MAX_KEYNAME_LEN];
	char nsa_keyname[DLADM_WLAN_MAX_KEYNAME_LEN];
	dladm_wlan_key_t *nsa_key;
	uint64_t nsa_secmode;
};

static void
kw_list_init(void)
{
	kw_list.q_forw = kw_list.q_back = &kw_list;
}

static void
kw_list_free(void)
{
	kw_t *kw;
	bssid_t *b;

	while (kw_list.q_forw != &kw_list) {
		kw = (kw_t *)kw_list.q_forw;

		/* free kw_bssids */
		while (kw->kw_bssids.q_forw != &kw->kw_bssids) {
			b = (bssid_t *)kw->kw_bssids.q_forw;
			remque(&b->bssid_links);
			free(b->bssid);
			free(b);
		}
		remque(&kw->kw_links);
		free(kw);
	}
}

/* Returns the entry in kw_list for the given ESSID.  NULL if non-existent */
static kw_t *
kw_lookup(const char *essid)
{
	kw_t *kw;

	if (essid == NULL)
		return (NULL);

	for (kw = (kw_t *)kw_list.q_forw;
	    kw != (kw_t *)&kw_list;
	    kw = (kw_t *)kw->kw_links.q_forw) {
		if (strcmp(essid, kw->kw_essid) == 0)
			return (kw);
	}
	return (NULL);
}

/* Adds an ESSID/BSSID combination to kw_list.  Returns B_TRUE on success. */
static boolean_t
kw_add(const char *essid, const char *bssid)
{
	kw_t *kw;
	bssid_t *b;

	if ((b = calloc(1, sizeof (bssid_t))) == NULL) {
		nlog(LOG_ERR, "kw_add: cannot allocate for bssid_t: %m");
		return (B_FALSE);
	}
	if ((kw = calloc(1, sizeof (kw_t))) == NULL) {
		nlog(LOG_ERR, "kw_add: cannot allocate for kw_t: %m");
		free(b);
		return (B_FALSE);
	}
	kw->kw_bssids.q_forw = kw->kw_bssids.q_back = &kw->kw_bssids;

	b->bssid = strdup(bssid);
	(void) strlcpy(kw->kw_essid, essid, sizeof (kw->kw_essid));
	kw->kw_num_bssids = 1;

	insque(&b->bssid_links, kw->kw_bssids.q_back);
	insque(&kw->kw_links, kw_list.q_back);

	nlog(LOG_DEBUG, "kw_add: added Known WLAN %s, BSSID %s", essid, bssid);
	return (B_TRUE);
}

/*
 * Add the BSSID to the given kw.  Since /etc/nwam/known_wifi_nets is
 * populated such that the wifi networks visited later are towards the end
 * of the file, remove the give kw from its current position and append it
 * to the end of kw_list.  This ensures that kw_list is in the reverse
 * order of visited wifi networks.  Returns B_TRUE on success.
 */
static boolean_t
kw_update(kw_t *kw, const char *bssid)
{
	bssid_t *b;

	if ((b = calloc(1, sizeof (bssid_t))) == NULL) {
		nlog(LOG_ERR, "kw_update: cannot allocate for bssid_t: %m");
		return (B_FALSE);
	}

	b->bssid = strdup(bssid);
	insque(&b->bssid_links, kw->kw_bssids.q_back);
	kw->kw_num_bssids++;

	/* remove kw from current position */
	remque(&kw->kw_links);
	/* and insert at end */
	insque(&kw->kw_links, kw_list.q_back);

	nlog(LOG_DEBUG, "kw_update: appended BSSID %s to Known WLAN %s",
	    bssid, kw->kw_essid);
	return (B_TRUE);
}

/*
 * Parses /etc/nwam/known_wifi_nets and populates kw_list, with the oldest
 * wifi networks first in the list.  Returns the number of unique entries
 * in kw_list (to use for priority values).
 */
static int
parse_known_wifi_nets(void)
{
	FILE *fp;
	char line[LINE_MAX];
	char *cp, *tok[MAX_FIELDS];
	int lnum, num_kw = 0;
	kw_t *kw;

	kw_list_init();

	/*
	 * The file format is:
	 * essid\tbssid (essid followed by tab followed by bssid)
	 */
	fp = fopen(KNOWN_WIFI_NETS_FILE, "r");
	if (fp == NULL)
		return (0);
	for (lnum = 1; fgets(line, sizeof (line), fp) != NULL; lnum++) {

		cp = line;
		while (isspace(*cp))
			cp++;
		if (*cp == '#' || *cp == '\0')
			continue;

		if (bufsplit(cp, MAX_FIELDS, tok) != MAX_FIELDS) {
			syslog(LOG_ERR, "%s:%d: wrong number of tokens; "
			    "ignoring entry", KNOWN_WIFI_NETS_FILE, lnum);
			continue;
		}

		if ((kw = kw_lookup(tok[ESSID])) == NULL) {
			if (!kw_add(tok[ESSID], tok[BSSID])) {
				nlog(LOG_ERR,
				    "%s:%d: cannot add entry (%s,%s) to list",
				    KNOWN_WIFI_NETS_FILE, lnum,
				    tok[ESSID], tok[BSSID]);
			} else {
				num_kw++;
			}
		} else {
			if (!kw_update(kw, tok[BSSID])) {
				nlog(LOG_ERR,
				    "%s:%d:cannot update entry (%s,%s) to list",
				    KNOWN_WIFI_NETS_FILE, lnum,
				    tok[ESSID], tok[BSSID]);
			}
		}
		/* next line ... */
	}

	(void) fclose(fp);
	return (num_kw);
}

/*
 * Walk security objects looking for one that matches the essid prefix.
 * Store the key and keyname if a match is found - we use the last match
 * as the key for the known WLAN, since it is the most recently updated.
 */
/* ARGSUSED0 */
static boolean_t
find_secobj_matching_prefix(dladm_handle_t dh, void *arg,
    const char *secobjname)
{
	struct nwamd_secobj_arg *nsa = arg;

	if (strncmp(nsa->nsa_essid_prefix, secobjname,
	    strlen(nsa->nsa_essid_prefix)) == 0) {
		nlog(LOG_DEBUG, "find_secobj_matching_prefix: "
		    "found secobj with prefix %s : %s\n",
		    nsa->nsa_essid_prefix, secobjname);
		/* Free last key found (if any) */
		if (nsa->nsa_key != NULL)
			free(nsa->nsa_key);
		/* Retrive key so we can get security mode */
		nsa->nsa_key = nwamd_wlan_get_key_named(secobjname, 0);
		(void) strlcpy(nsa->nsa_keyname, secobjname,
		    sizeof (nsa->nsa_keyname));
		switch (nsa->nsa_key->wk_class) {
		case DLADM_SECOBJ_CLASS_WEP:
			nsa->nsa_secmode = DLADM_WLAN_SECMODE_WEP;
			nlog(LOG_DEBUG, "find_secobj_matching_prefix: "
			    "got WEP key %s", nsa->nsa_keyname);
			break;
		case DLADM_SECOBJ_CLASS_WPA:
			nsa->nsa_secmode = DLADM_WLAN_SECMODE_WPA;
			nlog(LOG_DEBUG, "find_secobj_matching_prefix: "
			    "got WPA key %s", nsa->nsa_keyname);
			break;
		default:
			/* shouldn't happen */
			nsa->nsa_secmode = DLADM_WLAN_SECMODE_NONE;
			nlog(LOG_ERR, "find_secobj_matching_prefix: "
			    "key class for key %s was invalid",
			    nsa->nsa_keyname);
			break;
		}
	}
	return (B_TRUE);
}


/* Upgrade /etc/nwam/known_wifi_nets file to new libnwam-based config model */
void
upgrade_known_wifi_nets_config(void)
{
	kw_t *kw;
	bssid_t *b;
	nwam_known_wlan_handle_t kwh;
	char **bssids;
	nwam_error_t err;
	uint64_t priority;
	int i, num_kw;
	struct nwamd_secobj_arg nsa;

	nlog(LOG_INFO, "Upgrading %s to Known WLANs", KNOWN_WIFI_NETS_FILE);

	/* Parse /etc/nwam/known_wifi_nets */
	num_kw = parse_known_wifi_nets();

	/* Create Known WLANs for each unique ESSID */
	for (kw = (kw_t *)kw_list.q_forw, priority = num_kw-1;
	    kw != (kw_t *)&kw_list;
	    kw = (kw_t *)kw->kw_links.q_forw, priority--) {
		nwam_value_t priorityval = NULL;
		nwam_value_t bssidsval = NULL;
		nwam_value_t secmodeval = NULL;
		nwam_value_t keynameval = NULL;

		nlog(LOG_DEBUG, "Creating Known WLAN %s", kw->kw_essid);

		if ((err = nwam_known_wlan_create(kw->kw_essid, &kwh))
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not create known wlan: %s", kw->kw_essid,
			    nwam_strerror(err));
			continue;
		}

		/* priority of this ESSID */
		if ((err = nwam_value_create_uint64(priority, &priorityval))
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not create priority value: %s", kw->kw_essid,
			    nwam_strerror(err));
			nwam_known_wlan_free(kwh);
			continue;
		}
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_PRIORITY, priorityval);
		nwam_value_free(priorityval);
		if (err != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not set priority value: %s", kw->kw_essid,
			    nwam_strerror(err));
			nwam_known_wlan_free(kwh);
			continue;
		}

		/* loop through kw->kw_bssids and create an array of bssids */
		bssids = calloc(kw->kw_num_bssids, sizeof (char *));
		if (bssids == NULL) {
			nwam_known_wlan_free(kwh);
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not calloc for bssids: %m", kw->kw_essid);
			continue;
		}
		for (b = (bssid_t *)kw->kw_bssids.q_forw, i = 0;
		    b != (bssid_t *)&kw->kw_bssids;
		    b = (bssid_t *)b->bssid_links.q_forw, i++) {
			bssids[i] = strdup(b->bssid);
		}

		/* BSSIDs for this ESSID */
		if ((err = nwam_value_create_string_array(bssids,
		    kw->kw_num_bssids, &bssidsval)) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not create bssids value: %s", kw->kw_essid,
			    nwam_strerror(err));
			for (i = 0; i < kw->kw_num_bssids; i++)
				free(bssids[i]);
			free(bssids);
			nwam_known_wlan_free(kwh);
			continue;
		}
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_BSSIDS, bssidsval);
		nwam_value_free(bssidsval);
		for (i = 0; i < kw->kw_num_bssids; i++)
			free(bssids[i]);
		free(bssids);
		if (err != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not set bssids: %s", kw->kw_essid,
			    nwam_strerror(err));
			nwam_known_wlan_free(kwh);
			continue;
		}

		/*
		 * Retrieve last key matching ESSID prefix if any, and set
		 * the retrieved key name and security mode.
		 */
		nwamd_set_key_name(kw->kw_essid, NULL, nsa.nsa_essid_prefix,
		    sizeof (nsa.nsa_essid_prefix));
		nsa.nsa_key = NULL;
		nsa.nsa_secmode = DLADM_WLAN_SECMODE_NONE;
		(void) dladm_walk_secobj(dld_handle, &nsa,
		    find_secobj_matching_prefix, DLADM_OPT_PERSIST);
		if (nsa.nsa_key != NULL) {
			if ((err = nwam_value_create_string(nsa.nsa_keyname,
			    &keynameval)) == NWAM_SUCCESS) {
				(void) nwam_known_wlan_set_prop_value(kwh,
				    NWAM_KNOWN_WLAN_PROP_KEYNAME, keynameval);
			}
			free(nsa.nsa_key);
			nwam_value_free(keynameval);
		}

		if ((err = nwam_value_create_uint64(nsa.nsa_secmode,
		    &secmodeval)) != NWAM_SUCCESS ||
		    (err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_SECURITY_MODE, secmodeval))
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not set security mode: %s",
			    kw->kw_essid, nwam_strerror(err));
			nwam_value_free(secmodeval);
			nwam_known_wlan_free(kwh);
			continue;
		}

		/* commit, no collision checking by libnwam */
		err = nwam_known_wlan_commit(kwh,
		    NWAM_FLAG_KNOWN_WLAN_NO_COLLISION_CHECK);
		nwam_known_wlan_free(kwh);
		if (err != NWAM_SUCCESS) {
			nlog(LOG_ERR, "upgrade wlan %s: "
			    "could not commit wlan: %s", kw->kw_essid,
			    nwam_strerror(err));
		}
		/* next ... */
	}

	kw_list_free();
}

nwam_error_t
known_wlan_get_keyname(const char *essid, char *name)
{
	nwam_known_wlan_handle_t kwh = NULL;
	nwam_value_t keynameval = NULL;
	char *keyname;
	nwam_error_t err;

	if ((err = nwam_known_wlan_read(essid, 0, &kwh)) != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_KEYNAME, &keynameval)) == NWAM_SUCCESS &&
	    (err = nwam_value_get_string(keynameval, &keyname))
	    == NWAM_SUCCESS) {
		(void) strlcpy(name, keyname, NWAM_MAX_VALUE_LEN);
	}
	if (keynameval != NULL)
		nwam_value_free(keynameval);

	if (kwh != NULL)
		nwam_known_wlan_free(kwh);

	return (err);
}

/* Performs a scan on a wifi link NCU */
/* ARGSUSED */
static int
nwamd_ncu_known_wlan_committed(nwamd_object_t object, void *data)
{
	nwamd_ncu_t *ncu_data = object->nwamd_object_data;

	if (ncu_data->ncu_type != NWAM_NCU_TYPE_LINK)
		return (0);

	/* network selection will be done only if possible */
	if (ncu_data->ncu_link.nwamd_link_media == DL_WIFI)
		(void) nwamd_wlan_scan(ncu_data->ncu_name);
	return (0);
}

/* Handle known WLAN initialization/refresh event */
/* ARGSUSED */
void
nwamd_known_wlan_handle_init_event(nwamd_event_t known_wlan_event)
{
	/*
	 * Since the Known WLAN list has changed, do a rescan so that the
	 * best network is selected.
	 */
	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
	    nwamd_ncu_known_wlan_committed, NULL);
}

void
nwamd_known_wlan_handle_action_event(nwamd_event_t known_wlan_event)
{
	switch (known_wlan_event->event_msg->nwe_data.nwe_object_action.
	    nwe_action) {
	case NWAM_ACTION_ADD:
	case NWAM_ACTION_REFRESH:
		nwamd_known_wlan_handle_init_event(known_wlan_event);
		break;
	case NWAM_ACTION_DESTROY:
		/* Nothing needs to be done for destroy */
		break;
	/* all other events are invalid for known WLANs */
	case NWAM_ACTION_ENABLE:
	case NWAM_ACTION_DISABLE:
	default:
		nlog(LOG_INFO, "nwam_known_wlan_handle_action_event: "
		    "unexpected action");
		break;
	}
}

int
nwamd_known_wlan_action(const char *known_wlan, nwam_action_t action)
{
	nwamd_event_t known_wlan_event = nwamd_event_init_object_action
	    (NWAM_OBJECT_TYPE_KNOWN_WLAN, known_wlan, NULL, action);
	if (known_wlan_event == NULL)
		return (1);
	nwamd_event_enqueue(known_wlan_event);
	return (0);
}
