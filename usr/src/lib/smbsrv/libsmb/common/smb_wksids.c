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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <synch.h>

#include <smbsrv/libsmb.h>

static int wk_init = 0;
static rwlock_t wk_rwlock;

static char *wka_nbdomain[] = {
	"",
	"NT Pseudo Domain",
	"NT Authority",
	"Builtin",
	"Internet$",
};

/*
 * Predefined well known accounts table
 */
static smb_wka_t wka_tbl[] = {
	{ 0, "S-1-0-0",		"Null",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-1-0",		"Everyone",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-2-0",		"Local",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-3-0",		"Creator Owner",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-3-1",		"Creator Group",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-3-2",		"Creator Owner Server",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-3-3",		"Creator Group Server",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 0, "S-1-3-4",		"Owner Rights",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 1, "S-1-5",		"NT Pseudo Domain",
		SidTypeDomain, 0, NULL, NULL },
	{ 2, "S-1-5-1",		"Dialup",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-2",		"Network",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-3",		"Batch",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-4",		"Interactive",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-6",		"Service",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-7",		"Anonymous",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-8",		"Proxy",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-9",		"Enterprise Domain Controllers",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-10",	"Self",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-11",	"Authenticated Users",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-12",	"Restricted",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-13",	"Terminal Server User",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-14",	"Remote Interactive Logon",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-15",	"This Organization",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-18",	"System",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-19",	"Local Service",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-20",	"Network Service",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-33",	"Write Restricted",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 2, "S-1-5-1000",	"Other Organization",
		SidTypeWellKnownGroup, 0, NULL, NULL },
	{ 3, "S-1-5-32",	"Builtin",
		SidTypeDomain, 0, NULL, NULL },
	{ 4, "S-1-7",		"Internet$",
		SidTypeDomain, 0, NULL, NULL },

	{ 3, "S-1-5-32-544",	"Administrators", SidTypeAlias,
	    SMB_WKAFLG_LGRP_ENABLE,
	    "Members can fully administer the computer/domain", NULL },
	{ 3, "S-1-5-32-545",	"Users",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-546",	"Guests",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-547",	"Power Users", SidTypeAlias,
	    SMB_WKAFLG_LGRP_ENABLE, "Members can share directories", NULL },
	{ 3, "S-1-5-32-548",	"Account Operators",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-549",	"Server Operators",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-550",	"Print Operators",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-551",	"Backup Operators", SidTypeAlias,
	    SMB_WKAFLG_LGRP_ENABLE,
	    "Members can bypass file security to back up files", NULL },
	{ 3, "S-1-5-32-552",	"Replicator",
		SidTypeAlias, 0, NULL, NULL }
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
			return (wka_nbdomain[entry->wka_domidx]);
	}

	return (NULL);
}

/*
 * Returns the Netbios domain name for the given index
 */
char *
smb_wka_get_domain(int idx)
{
	if ((idx >= 0) && (idx < SMB_WKA_NUM))
		return (wka_nbdomain[idx]);

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
