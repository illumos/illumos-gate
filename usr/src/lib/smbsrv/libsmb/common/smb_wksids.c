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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <smbsrv/libsmb.h>

static char *wka_nbdomain[] = {
	"",
	"NT Pseudo Domain",
	"NT Authority",
	"Builtin",
	"Internet$"
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
	{ 0, "S-1-3-5",		"Group Rights",
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
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-766",	"Current Owner",
		SidTypeAlias, 0, NULL, NULL },
	{ 3, "S-1-5-32-767",	"Current Group",
		SidTypeAlias, 0, NULL, NULL },
};

#define	SMB_WKA_NUM	(sizeof (wka_tbl)/sizeof (wka_tbl[0]))

static int smb_wka_init(void);
static void smb_wka_fini(void);

/*
 * Looks up well known accounts table for the given SID.
 * Upon success returns a pointer to the account entry in
 * the table, otherwise returns NULL.
 */
smb_wka_t *
smb_wka_lookup_sid(smb_sid_t *sid)
{
	smb_wka_t *entry;
	int i;

	if (!smb_wka_init())
		return (NULL);

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (entry->wka_binsid == NULL)
			return (NULL);

		if (smb_sid_cmp(sid, entry->wka_binsid))
			return (entry);
	}

	return (NULL);
}

/*
 * Looks up well known accounts table for the given name.
 * Upon success returns a pointer to the binary SID of the
 * entry, otherwise returns NULL.
 */
smb_sid_t *
smb_wka_get_sid(const char *name)
{
	smb_wka_t *entry;
	smb_sid_t *sid = NULL;

	if (!smb_wka_init())
		return (NULL);

	if ((entry = smb_wka_lookup_name(name)) != NULL)
		sid = entry->wka_binsid;

	return (sid);
}

/*
 * Looks up well known accounts table for the given name.
 * Upon success returns a pointer to the account entry in
 * the table, otherwise returns NULL.
 */
smb_wka_t *
smb_wka_lookup_name(const char *name)
{
	smb_wka_t *entry;
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (!smb_strcasecmp(name, entry->wka_name, 0))
			return (entry);
	}

	return (NULL);
}

/*
 * Lookup a name in the BUILTIN domain.
 */
smb_wka_t *
smb_wka_lookup_builtin(const char *name)
{
	smb_wka_t	*entry;
	int		i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		if (entry->wka_domidx != 3)
			continue;

		if (!smb_strcasecmp(name, entry->wka_name, 0))
			return (entry);
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
 * This function adds well known groups to groups in a user's
 * access token (gids).
 *
 * "Network" SID is added for all users connecting over CIFS.
 *
 * "Authenticated Users" SID is added for all users except Guest
 * and Anonymous.
 *
 * "Guests" SID is added for guest users and Administrators SID
 * is added for admin users.
 */
uint32_t
smb_wka_token_groups(uint32_t flags, smb_ids_t *gids)
{
	smb_id_t *id;
	int total_cnt;

	total_cnt = gids->i_cnt + 3;

	gids->i_ids = realloc(gids->i_ids, total_cnt * sizeof (smb_id_t));
	if (gids->i_ids == NULL)
		return (NT_STATUS_NO_MEMORY);

	id = gids->i_ids + gids->i_cnt;
	id->i_sid = smb_sid_dup(smb_wka_get_sid("Network"));
	id->i_attrs = 0x7;
	if (id->i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);
	id++;
	gids->i_cnt++;

	if ((flags & SMB_ATF_ANON) == 0) {
		if (flags & SMB_ATF_GUEST)
			id->i_sid = smb_sid_dup(smb_wka_get_sid("Guests"));
		else
			id->i_sid =
			    smb_sid_dup(smb_wka_get_sid("Authenticated Users"));
		id->i_attrs = 0x7;
		if (id->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);
		id++;
		gids->i_cnt++;
	}

	if (flags & SMB_ATF_ADMIN) {
		id->i_sid = smb_sid_dup(smb_wka_get_sid("Administrators"));
		id->i_attrs = 0x7;
		if (id->i_sid == NULL)
			return (NT_STATUS_NO_MEMORY);
		gids->i_cnt++;
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Generate binary SIDs from the string SIDs for the well-known
 * accounts table.  Callers MUST not free the binary SID pointer.
 */
static int
smb_wka_init(void)
{
	static boolean_t wka_init = B_FALSE;
	static mutex_t	wka_mutex;
	smb_wka_t	*entry;
	int		i;

	(void) mutex_lock(&wka_mutex);
	if (wka_init) {
		(void) mutex_unlock(&wka_mutex);
		return (B_TRUE);
	}

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		entry = &wka_tbl[i];

		entry->wka_binsid = smb_sid_fromstr(entry->wka_sid);
		if (entry->wka_binsid == NULL) {
			smb_wka_fini();
			(void) mutex_unlock(&wka_mutex);
			return (B_FALSE);
		}
	}

	wka_init = B_TRUE;
	(void) mutex_unlock(&wka_mutex);
	return (B_TRUE);
}

/*
 * Private cleanup for smb_wka_init.
 */
static void
smb_wka_fini(void)
{
	int i;

	for (i = 0; i < SMB_WKA_NUM; ++i) {
		if (wka_tbl[i].wka_binsid) {
			free(wka_tbl[i].wka_binsid);
			wka_tbl[i].wka_binsid = NULL;
		}
	}
}
