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

/*
 * Information about well-known (builtin) names, and functions to retrieve
 * information about them.
 */

#include <assert.h>
#include <string.h>
#include "idmapd.h"
#include "miscutils.h"

/*
 * Table for well-known SIDs.
 *
 * Background:
 *
 * Some of the well-known principals are stored under:
 * cn=WellKnown Security Principals, cn=Configuration, dc=<forestRootDomain>
 * They belong to objectClass "foreignSecurityPrincipal". They don't have
 * "samAccountName" nor "userPrincipalName" attributes. Their names are
 * available in "cn" and "name" attributes. Some of these principals have a
 * second entry under CN=ForeignSecurityPrincipals,dc=<forestRootDomain> and
 * these duplicate entries have the stringified SID in the "name" and "cn"
 * attributes instead of the actual name.
 *
 * Those of the form S-1-5-32-X are Builtin groups and are stored in the
 * cn=builtin container (except, Power Users which is not stored in AD)
 *
 * These principals are and will remain constant. Therefore doing AD lookups
 * provides no benefit. Also, using hard-coded table (and thus avoiding AD
 * lookup) improves performance and avoids additional complexity in the
 * adutils.c code. Moreover these SIDs can be used when no Active Directory
 * is available (such as the CIFS server's "workgroup" mode).
 *
 * Notes:
 * 1. Currently we don't support localization of well-known SID names,
 * unlike Windows.
 *
 * 2. Other well-known SIDs i.e. S-1-5-<domain>-<w-k RID> are not stored
 * here. AD does have normal user/group objects for these objects and
 * can be looked up using the existing AD lookup code.
 *
 * 3. See comments above lookup_wksids_sid2pid() for more information
 * on how we lookup the wksids table.
 *
 * 4. If this table contains two entries for a particular Windows name,
 * so as to offer both UID and GID mappings, the preferred mapping (the
 * one that matches Windows usage) must be listed first.  That is the
 * entry that will be used when the caller specifies IDMAP_POSIXID
 * ("don't care") as the target.
 *
 * Entries here come from KB243330, MS-LSAT, and
 * http://technet.microsoft.com/en-us/library/cc755854.aspx
 * http://technet.microsoft.com/en-us/library/cc755925.aspx
 * http://msdn.microsoft.com/en-us/library/cc980032(PROT.10).aspx
 */
static wksids_table_t wksids[] = {
	/* S-1-0	Null Authority */
	{"S-1-0", 0, "", "Nobody", 1, SENTINEL_PID, -1, 1},

	/* S-1-1	World Authority */
	{"S-1-1", 0, "", "Everyone", 0, SENTINEL_PID, -1, -1},

	/* S-1-2	Local Authority */
	{"S-1-2", 0, "", "Local", 0, SENTINEL_PID, -1, -1},
	{"S-1-2", 1, "", "Console Logon", 0, SENTINEL_PID, -1, -1},

	/* S-1-3	Creator Authority */
	{"S-1-3", 0, "", "Creator Owner", 1, IDMAP_WK_CREATOR_OWNER_UID, 1, 0},
	{"S-1-3", 1, "", "Creator Group", 0, IDMAP_WK_CREATOR_GROUP_GID, 0, 0},
	{"S-1-3", 2, "", "Creator Owner Server", 1, SENTINEL_PID, -1, -1},
	{"S-1-3", 3, "", "Creator Group Server", 0, SENTINEL_PID, -1, 1},
	{"S-1-3", 4, "", "Owner Rights", 0, SENTINEL_PID, -1, -1},

	/* S-1-4	Non-unique Authority */

	/* S-1-5	NT Authority */
	{"S-1-5", 1, "", "Dialup", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 2, "", "Network", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 3, "", "Batch", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 4, "", "Interactive", 0, SENTINEL_PID, -1, -1},
	/* S-1-5-5-X-Y	Logon Session */
	{"S-1-5", 6, "", "Service", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 7, "", "Anonymous Logon", 0, GID_NOBODY, 0, 0},
	{"S-1-5", 7, "", "Anonymous Logon", 0, UID_NOBODY, 1, 0},
	{"S-1-5", 8, "", "Proxy", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 9, "", "Enterprise Domain Controllers", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5", 10, "", "Self", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 11, "", "Authenticated Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 12, "", "Restricted", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 13, "", "Terminal Server Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 14, "", "Remote Interactive Logon", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 15, "", "This Organization", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 17, "", "IUSR", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 18, "", "Local System", 0, IDMAP_WK_LOCAL_SYSTEM_GID, 0, 0},
	{"S-1-5", 19, "", "Local Service", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 20, "", "Network Service", 0, SENTINEL_PID, -1, -1},

	/* S-1-5-21-<domain>	Machine-local definitions */
	{NULL, 498, NULL, "Enterprise Read-only Domain Controllers", 0,
	    SENTINEL_PID, -1, -1},
	{NULL, 500, NULL, "Administrator", 1, SENTINEL_PID, 1, -1},
	{NULL, 501, NULL, "Guest", 1, SENTINEL_PID, 1, -1},
	{NULL, 502, NULL, "KRBTGT", 1, SENTINEL_PID, 1, -1},
	{NULL, 512, NULL, "Domain Admins", 0, SENTINEL_PID, -1, -1},
	{NULL, 513, NULL, "Domain Users", 0, SENTINEL_PID, -1, -1},
	{NULL, 514, NULL, "Domain Guests", 0, SENTINEL_PID, -1, -1},
	{NULL, 515, NULL, "Domain Computers", 0, SENTINEL_PID, -1, -1},
	{NULL, 516, NULL, "Domain Controllers", 0, SENTINEL_PID, -1, -1},
	{NULL, 517, NULL, "Cert Publishers", 0, SENTINEL_PID, -1, -1},
	{NULL, 518, NULL, "Schema Admins", 0, SENTINEL_PID, -1, -1},
	{NULL, 519, NULL, "Enterprise Admins", 0, SENTINEL_PID, -1, -1},
	{NULL, 520, NULL, "Global Policy Creator Owners", 0,
	    SENTINEL_PID, -1, -1},
	{NULL, 533, NULL, "RAS and IAS Servers", 0, SENTINEL_PID, -1, -1},

	/* S-1-5-32	BUILTIN */
	{"S-1-5-32", 544, "BUILTIN", "Administrators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 545, "BUILTIN", "Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 546, "BUILTIN", "Guests", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 547, "BUILTIN", "Power Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 548, "BUILTIN", "Account Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 549, "BUILTIN", "Server Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 550, "BUILTIN", "Print Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 551, "BUILTIN", "Backup Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 552, "BUILTIN", "Replicator", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 554, "BUILTIN", "Pre-Windows 2000 Compatible Access", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 555, "BUILTIN", "Remote Desktop Users", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 556, "BUILTIN", "Network Configuration Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 557, "BUILTIN", "Incoming Forest Trust Builders", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 558, "BUILTIN", "Performance Monitor Users", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 559, "BUILTIN", "Performance Log Users", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 560, "BUILTIN", "Windows Authorization Access Group", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 561, "BUILTIN", "Terminal Server License Servers", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 562, "BUILTIN", "Distributed COM Users", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 568, "BUILTIN", "IIS_IUSRS", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 569, "BUILTIN", "Cryptographic Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 573, "BUILTIN", "Event Log Readers", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 574, "BUILTIN", "Certificate Service DCOM Access", 0,
	    SENTINEL_PID, -1, -1},

	{"S-1-5", 33, "", "Write Restricted", 0, SENTINEL_PID, -1, -1},

	/* S-1-5-64	NT Authority */
	{"S-1-5-64", 10, "", "NTLM Authentication", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-64", 14, "", "SChannel Authentication", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-64", 21, "", "Digest Authentication", 0, SENTINEL_PID, -1, -1},

	/* S-1-5-80-a-b-c-d NT Service */

	{"S-1-5", 1000, "", "Other Organization", 0, SENTINEL_PID, -1, -1},

	/* S-1-7 Internet$ */

	/*
	 * S-1-16	Mandatory Label
	 * S-1-16-0	Untrusted Mandatory Level
	 * S-1-16-4096	Low Mandatory Level
	 * S-1-16-8192	Medium Mandatory Level
	 * S-1-16-8448	Medium Plus Mandatory Level
	 * S-1-16-12288	High Mandatory Level
	 * S-1-16-16384	System Mandatory Level
	 * S-1-16-20480	Protected Process Mandatory Level
	 */
};

/*
 * Find a wksid entry for the specified Windows name and domain, of the
 * specified type.
 *
 * Ignore entries intended only for U2W use.
 */
const
wksids_table_t *
find_wksid_by_name(const char *name, const char *domain, int type)
{
	int i;

	RDLOCK_CONFIG();
	int len = strlen(_idmapdstate.hostname);
	char my_host_name[len + 1];
	(void) strcpy(my_host_name, _idmapdstate.hostname);
	UNLOCK_CONFIG();

	for (i = 0; i < NELEM(wksids); i++) {
		/* Check to see if this entry yields the desired type */
		switch (type) {
		case IDMAP_UID:
			if (wksids[i].is_user == 0)
				continue;
			break;
		case IDMAP_GID:
			if (wksids[i].is_user == 1)
				continue;
			break;
		case IDMAP_POSIXID:
			break;
		default:
			assert(FALSE);
		}

		if (strcasecmp(wksids[i].winname, name) != 0)
			continue;

		if (!EMPTY_STRING(domain)) {
			const char *dom;

			if (wksids[i].domain != NULL) {
				dom = wksids[i].domain;
			} else {
				dom = my_host_name;
			}
			if (strcasecmp(dom, domain) != 0)
				continue;
		}

		/*
		 * We have a Windows name, so ignore entries that are only
		 * usable for mapping UNIX->Windows.  (Note:  the current
		 * table does not have any such entries.)
		 */
		if (wksids[i].direction == IDMAP_DIRECTION_U2W)
			continue;

		return (&wksids[i]);
	}

	return (NULL);
}

/*
 * Find a wksid entry for the specified SID, of the specified type.
 *
 * Ignore entries intended only for U2W use.
 */
const
wksids_table_t *
find_wksid_by_sid(const char *sid, int rid, int type)
{
	int i;

	RDLOCK_CONFIG();
	int len = strlen(_idmapdstate.cfg->pgcfg.machine_sid);
	char my_machine_sid[len + 1];
	(void) strcpy(my_machine_sid, _idmapdstate.cfg->pgcfg.machine_sid);
	UNLOCK_CONFIG();

	for (i = 0; i < NELEM(wksids); i++) {
		int sidcmp;

		/* Check to see if this entry yields the desired type */
		switch (type) {
		case IDMAP_UID:
			if (wksids[i].is_user == 0)
				continue;
			break;
		case IDMAP_GID:
			if (wksids[i].is_user == 1)
				continue;
			break;
		case IDMAP_POSIXID:
			break;
		default:
			assert(FALSE);
		}

		if (wksids[i].sidprefix != NULL) {
			sidcmp = strcasecmp(wksids[i].sidprefix, sid);
		} else {
			sidcmp = strcasecmp(my_machine_sid, sid);
		}

		if (sidcmp != 0)
			continue;
		if (wksids[i].rid != rid)
			continue;

		/*
		 * We have a SID, so ignore entries that are only usable
		 * for mapping UNIX->Windows.  (Note:  the current table
		 * does not have any such entries.)
		 */
		if (wksids[i].direction == IDMAP_DIRECTION_U2W)
			continue;

		return (&wksids[i]);
	}

	return (NULL);
}

/*
 * Find a wksid entry for the specified pid, of the specified type.
 * Ignore entries that do not specify U2W mappings.
 */
const
wksids_table_t *
find_wksid_by_pid(uid_t pid, int is_user)
{
	int i;

	if (pid == SENTINEL_PID)
		return (NULL);

	for (i = 0; i < NELEM(wksids); i++) {
		if (wksids[i].pid == pid &&
		    wksids[i].is_user == is_user &&
		    (wksids[i].direction == IDMAP_DIRECTION_BI ||
		    wksids[i].direction == IDMAP_DIRECTION_U2W)) {
			return (&wksids[i]);
		}
	}
	return (NULL);
}

/*
 * It is probably a bug that both this and find_wksid_by_sid exist,
 * but for now the distinction is primarily that one takes {machinesid,rid}
 * and the other takes a full SID.
 */
const
wksids_table_t *
find_wk_by_sid(char *sid)
{
	int i;

	RDLOCK_CONFIG();
	int len = strlen(_idmapdstate.cfg->pgcfg.machine_sid);
	char my_machine_sid[len + 1];
	(void) strcpy(my_machine_sid, _idmapdstate.cfg->pgcfg.machine_sid);
	UNLOCK_CONFIG();

	for (i = 0; i < NELEM(wksids); i++) {
		int len;
		const char *prefix;
		char *p;
		unsigned long rid;

		if (wksids[i].sidprefix == NULL)
			prefix = my_machine_sid;
		else
			prefix = wksids[i].sidprefix;

		len = strlen(prefix);

		/*
		 * Check to see whether the SID we're looking for starts
		 * with this prefix, then a -, then a single RID, and it's
		 * the right RID.
		 */
		if (strncasecmp(sid, prefix, len) != 0)
			continue;
		if (sid[len] != '-')
			continue;
		rid = strtoul(sid + len + 1, &p, 10);
		if (*p != '\0')
			continue;

		if (rid != wksids[i].rid)
			continue;

		return (&wksids[i]);
	}
	return (NULL);
}
