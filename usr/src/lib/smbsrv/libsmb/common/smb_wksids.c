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

/*
 * This module provides the interface to builtin domain information.
 * These are the predefined groups and aliases in the NT AUTHORITY or
 * BUILTIN domains, and some other miscellaneous bits.
 */

#include <stdlib.h>
#include <string.h>
#include <synch.h>

#include <smbsrv/smb_sid.h>
#include <smbsrv/string.h>

/*
 * This table should contain all of the NT builtin domain names.
 */
static char *domain[] = {
	"LOCAL",
	"BUILTIN",
	"NT AUTHORITY",
	"UNKNOWN"
};

static int wk_init = 0;
static rwlock_t wk_rwlock;

/*
 * This table should contain all of the builtin domains, groups and
 * aliases. The order is important because we do string compares on
 * the SIDs. For each domain, ensure that the domain SID appears
 * before any aliases in that domain.
 */
static smb_wka_t wka_tbl[] = {
	{ SidTypeWellKnownGroup, 0, "S-1-0-0",		"Null",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-1-0",		"Everyone",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-2-0",		"LOCAL",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-0",		"CREATOR OWNER",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-1",		"CREATOR GROUP",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-2",		"CREATOR OWNER SERVER",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-3",		"CREATOR GROUP SERVER",
	    0, NULL, NULL},
	{ SidTypeDomain, 1, "S-1-4",			"NON UNIQUE",
	    0, NULL, NULL},
	{ SidTypeDomain, 2, "S-1-5",			"NT AUTHORITY",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-1",		"DIALUP",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-2",		"NETWORK",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-3",		"BATCH",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-4",		"INTERACTIVE",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-6",		"SERVICE",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-7",		"ANONYMOUS",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-8",		"PROXY",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-9",		"SERVER",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-10",		"SELF",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-11",		"Authenticated Users",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-12",		"RESTRICTED",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-18",		"SYSTEM",
	    0, NULL, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-21",		"NON_UNIQUE",
	    0, NULL, NULL},
	{ SidTypeDomain, 2, "S-1-5-32",			"BUILTIN",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-544",		"Administrators",
	    SMB_WKAFLG_LGRP_ENABLE,
	    "Members can fully administer the computer/domain", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-545",		"Users",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-546",		"Guests",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-547",		"Power Users",
	    SMB_WKAFLG_LGRP_ENABLE, "Members can share directories", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-548",		"Account Operators",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-549",		"Server Operators",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-550",		"Print Operators",
	    0, NULL, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-551",		"Backup Operators",
	    SMB_WKAFLG_LGRP_ENABLE,
	    "Members can bypass file security to back up files", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-552",		"Replicator",
	    0, NULL, NULL}
};

#define	SMB_WKA_NUM	(sizeof (wka_tbl)/sizeof (wka_tbl[0]))

/*
 * smb_wka_lookup_sid
 *
 * Search the wka_tbl looking for a match on the specified SID. If the
 * SID matches a builtin entry, the associated name is returned.
 * Otherwise a null pointer is returned.
 */
char *
smb_wka_lookup_sid(smb_sid_t *sid, uint16_t *sid_name_use)
{
	smb_wka_t *entry;
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (smb_sid_cmp(sid, entry->wka_binsid)) {
			if (sid_name_use)
				*sid_name_use = entry->wka_type;
			return (entry->wka_name);
		}
	}

	return (NULL);
}


/*
 * smb_wka_lookup_name
 *
 * Search the wka_tbl looking for a match on the specified name. If the
 * name matches a builtin entry, the associated SID (which is in
 * malloc'd memory) is returned. Otherwise a null pointer is returned.
 */
smb_sid_t *
smb_wka_lookup_name(char *name, uint16_t *sid_name_use)
{
	smb_wka_t *entry;
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (!utf8_strcasecmp(name, entry->wka_name)) {
			if (sid_name_use)
				*sid_name_use = entry->wka_type;
			return (smb_sid_dup(entry->wka_binsid));
		}
	}

	return (NULL);
}

/*
 * smb_wka_lookup
 *
 * Search the wka_tbl looking for a match on the specified name. If the
 * name matches a builtin entry then pointer to that entry will be
 * returned. Otherwise 0 is returned.
 */
smb_wka_t *
smb_wka_lookup(char *name)
{
	smb_wka_t *entry;
	int i;

	(void) rw_rdlock(&wk_rwlock);
	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (!utf8_strcasecmp(name, entry->wka_name)) {
			(void) rw_unlock(&wk_rwlock);
			return (entry);
		}
	}

	(void) rw_unlock(&wk_rwlock);
	return (NULL);
}


/*
 * smb_wka_is_wellknown
 *
 * Search the wka_tbl looking for a match on the specified name. If the
 * name matches a builtin entry returns 1. Otherwise returns 0.
 */
boolean_t
smb_wka_is_wellknown(char *name)
{
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		if (utf8_strcasecmp(name, wka_tbl[i].wka_name) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_wka_lookup_domain
 *
 * Return the builtin domain name for the specified alias or group name.
 */
char *
smb_wka_lookup_domain(char *name)
{
	smb_wka_t *entry;
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (!utf8_strcasecmp(name, entry->wka_name))
			return (domain[entry->wka_domidx]);
	}

	return (NULL);
}

/*
 * smb_wka_init
 *
 * Generate binary SIDs from the string SIDs in the table
 * and set the proper field.
 *
 * Caller MUST not store the binary SID pointer anywhere that
 * could lead to freeing it.
 *
 * This function should only be called once.
 */
int
smb_wka_init(void)
{
	smb_wka_t *entry;
	int i;

	(void) rw_wrlock(&wk_rwlock);
	if (wk_init) {
		(void) rw_unlock(&wk_rwlock);
		return (1);
	}

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];
		entry->wka_binsid = smb_sid_fromstr(entry->wka_sid);
		if (entry->wka_binsid == NULL) {
			(void) rw_unlock(&wk_rwlock);
			smb_wka_fini();
			return (0);
		}
	}

	wk_init = 1;
	(void) rw_unlock(&wk_rwlock);
	return (1);
}

void
smb_wka_fini(void)
{
	int i;

	(void) rw_wrlock(&wk_rwlock);
	if (wk_init == 0) {
		(void) rw_unlock(&wk_rwlock);
		return;
	}

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		if (wka_tbl[i].wka_binsid) {
			free(wka_tbl[i].wka_binsid);
			wka_tbl[i].wka_binsid = NULL;
		}
	}

	wk_init = 0;
	(void) rw_unlock(&wk_rwlock);
}
