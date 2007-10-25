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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides the interface to builtin domain information.
 * These are the predefined groups and aliases in the NT AUTHORITY or
 * BUILTIN domains, and some other miscellaneous bits.
 */

#include <string.h>
#include <synch.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/string.h>
#include <smbsrv/alloc.h>

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
static well_known_account_t wkt[] = {
	{ SidTypeWellKnownGroup, 0, "S-1-0-0",		"Null",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-1-0",		"Everyone",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-2-0",		"LOCAL",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-0",		"CREATOR OWNER",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-1",		"CREATOR GROUP",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-2",		"CREATOR OWNER SERVER",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 1, "S-1-3-3",		"CREATOR GROUP SERVER",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeDomain, 1, "S-1-4",			"NON UNIQUE",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeDomain, 2, "S-1-5",		"NT AUTHORITY",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-1",		"DIALUP",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-2",		"NETWORK",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-3",		"BATCH",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-4",		"INTERACTIVE",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-6",		"SERVICE",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-7",		"ANONYMOUS",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-8",		"PROXY",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-9",		"SERVER",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-10",		"SELF",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-11",		"Authenticated Users",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-12",		"RESTRICTED",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-18",		"SYSTEM",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeWellKnownGroup, 2, "S-1-5-21",		"NON_UNIQUE",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeDomain, 2, "S-1-5-32",			"BUILTIN",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-544",		"Administrators",
	    0, "Members can fully administer the computer/domain", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-545",		"Users",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-546",		"Guests",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-547",		"Power Users",
	    0, "Members can share directories", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-548",		"Account Operators",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-549",		"Server Operators",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-550",		"Print Operators",
	    LGF_HIDDEN, 0, NULL},
	{ SidTypeAlias, 1, "S-1-5-32-551",		"Backup Operators",
	    0, "Members can bypass file security to back up files", NULL },
	{ SidTypeAlias, 1, "S-1-5-32-552",		"Replicator",
	    LGF_HIDDEN, 0, NULL}
};


/*
 * nt_builtin_lookup_sid
 *
 * Search the wkt looking for a match on the specified SID. If the
 * SID matches a builtin entry, the associated name is returned.
 * Otherwise a null pointer is returned.
 */
char *
nt_builtin_lookup_sid(nt_sid_t *sid, WORD *sid_name_use)
{
	well_known_account_t *entry;
	char *sidbuf;
	int sidlen;
	int i;

	if ((sidbuf = nt_sid_format(sid)) == 0)	{
		return (0);
	}

	sidlen = strlen(sidbuf);

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];

		if (strncmp(sidbuf, entry->sid, sidlen) == 0) {
			if (sid_name_use)
				*sid_name_use = entry->sid_name_use;
			free(sidbuf);
			return (entry->name);
		}
	}

	free(sidbuf);
	return (0);
}


/*
 * nt_builtin_lookup_name
 *
 * Search the wkt looking for a match on the specified name. If the
 * name matches a builtin entry, the associated SID (which is in
 * malloc'd memory) is returned. Otherwise a null pointer is returned.
 */
nt_sid_t *
nt_builtin_lookup_name(char *name, WORD *sid_name_use)
{
	well_known_account_t *entry;
	int i;

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];

		if (!utf8_strcasecmp(name, entry->name)) {
			if (sid_name_use)
				*sid_name_use = entry->sid_name_use;
			return (nt_sid_strtosid(entry->sid));
		}
	}

	return (0);
}

/*
 * nt_builtin_lookup
 *
 * Search the wkt looking for a match on the specified name. If the
 * name matches a builtin entry then pointer to that entry will be
 * returned. Otherwise 0 is returned.
 */
well_known_account_t *
nt_builtin_lookup(char *name)
{
	well_known_account_t *entry;
	int i;

	(void) rw_rdlock(&wk_rwlock);
	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];

		if (!utf8_strcasecmp(name, entry->name)) {
			(void) rw_unlock(&wk_rwlock);
			return (entry);
		}
	}

	(void) rw_unlock(&wk_rwlock);
	return (0);
}


/*
 * nt_builtin_is_wellknown
 *
 * Search the wkt looking for a match on the specified name. If the
 * name matches a builtin entry returns 1. Otherwise returns 0.
 */
int
nt_builtin_is_wellknown(char *name)
{
	well_known_account_t *entry;
	int i;

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];

		if (!utf8_strcasecmp(name, entry->name)) {
			return (1);
		}
	}

	return (0);
}

/*
 * nt_builtin_lookup_domain
 *
 * Return the builtin domain name for the specified alias or group name.
 */
char *
nt_builtin_lookup_domain(char *name)
{
	well_known_account_t *entry;
	char *domain_name;
	int i;

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];

		if (!utf8_strcasecmp(name, entry->name)) {
			domain_name = domain[entry->domain_ix];
			return (domain_name);
		}
	}

	return (0);
}

/*
 * nt_builtin_findfirst
 *
 * Returns pointer to the first entry of well known sids table.
 */
well_known_account_t *
nt_builtin_findfirst(DWORD *iterator)
{
	*iterator = 1;
	return (&wkt[0]);
}

/*
 * nt_builtin_findnext
 *
 * Returns pointer to the entry of well known sids table specified
 * by the iterator. Increments iterator to point to the next entry.
 */
well_known_account_t *
nt_builtin_findnext(DWORD *iterator)
{
	if (*iterator < sizeof (wkt)/sizeof (wkt[0]))
		return (&wkt[(*iterator)++]);

	return (0);
}

/*
 * nt_builtin_init
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
nt_builtin_init()
{
	well_known_account_t *entry;
	int i;

	(void) rw_wrlock(&wk_rwlock);
	if (wk_init) {
		(void) rw_unlock(&wk_rwlock);
		return (1);
	}

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		entry = &wkt[i];
		entry->binsid = nt_sid_strtosid(entry->sid);
		if (entry->binsid == NULL) {
			(void) rw_unlock(&wk_rwlock);
			nt_builtin_fini();
			return (0);
		}
	}

	wk_init = 1;
	(void) rw_unlock(&wk_rwlock);
	return (1);
}

void
nt_builtin_fini()
{
	int i;

	(void) rw_wrlock(&wk_rwlock);
	if (wk_init == 0) {
		(void) rw_unlock(&wk_rwlock);
		return;
	}

	for (i = 0; i < sizeof (wkt)/sizeof (wkt[0]); ++i) {
		if (wkt[i].binsid) {
			free(wkt[i].binsid);
			wkt[i].binsid = NULL;
		}
	}

	wk_init = 0;
	(void) rw_unlock(&wk_rwlock);
}
