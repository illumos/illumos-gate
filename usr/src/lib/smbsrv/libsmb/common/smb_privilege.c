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
 *
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 */

/*
 * This module provides the interface to the built-in privilege names
 * and id's. NT privileges are known on the network using strings. Each
 * system assigns locally unique identifiers (LUID) for use within the
 * system. Each built-in privilege also has a display-name, which is a
 * short description of the privilege. The functions here provide an
 * interface to map between LUIDs, names and display names.
 */

#include <string.h>
#include <syslog.h>

#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_privilege.h>

static char *smb_priv_getname(uint32_t id);

/*
 * Table of built-in privilege id's, names and display strings. This
 * table matches the response from an NT4.0 PDC LSARPC service.
 * Requests for values 0 and 1 return STATUS_NO_SUCH_PRIVILEGE.
 *
 * SE_UNSOLICITED_INPUT_NAME/SeUnsolicitedInputPrivilege is defined in
 * winnt.h but doesn't appear in the list reported by the NT4.0 LSA.
 */
static smb_privinfo_t priv_table[] = {
	{  0, "", "", 0 },
	{  1, "", "", 0 },
	{  2, SE_CREATE_TOKEN_NAME, "Create a token object", 0 },
	{  3, SE_ASSIGNPRIMARYTOKEN_NAME, "Replace a process level token", 0 },
	{  4, SE_LOCK_MEMORY_NAME, "Lock pages in memory", 0 },
	{  5, SE_INCREASE_QUOTA_NAME, "Increase quotas", 0 },
	{  6, SE_MACHINE_ACCOUNT_NAME, "Add workstations to domain", 0 },
	{  7, SE_TCB_NAME, "Act as part of the operating system", 0 },
	{  8, SE_SECURITY_NAME, "Manage auditing and security log", 0 },
	{  9, SE_TAKE_OWNERSHIP_NAME,
	    "Take ownership of files or other objects", PF_PRESENTABLE },
	{ 10, SE_LOAD_DRIVER_NAME, "Load and unload device drivers", 0 },
	{ 11, SE_SYSTEM_PROFILE_NAME, "Profile system performance", 0 },
	{ 12, SE_SYSTEMTIME_NAME, "Change the system time", 0 },
	{ 13, SE_PROF_SINGLE_PROCESS_NAME, "Profile single process", 0 },
	{ 14, SE_INC_BASE_PRIORITY_NAME, "Increase scheduling priority", 0 },
	{ 15, SE_CREATE_PAGEFILE_NAME, "Create a pagefile", 0 },
	{ 16, SE_CREATE_PERMANENT_NAME, "Create permanent shared objects", 0 },
	{ 17, SE_BACKUP_NAME, "Back up files and directories",
	    PF_PRESENTABLE },
	{ 18, SE_RESTORE_NAME, "Restore files and directories",
	    PF_PRESENTABLE },
	{ 19, SE_SHUTDOWN_NAME, "Shut down the system", 0 },
	{ 20, SE_DEBUG_NAME, "Debug programs", 0 },
	{ 21, SE_AUDIT_NAME, "Generate security audits", 0 },
	{ 22, SE_SYSTEM_ENVIRONMENT_NAME,
	    "Modify firmware environment values", 0 },
	{ 23, SE_CHANGE_NOTIFY_NAME, "Bypass traverse checking", 0 },
	{ 24, SE_REMOTE_SHUTDOWN_NAME,
	    "Force shutdown from a remote system", 0 },
	{ 25, SE_READ_FILE_NAME,
	    "Bypass ACL for READ access", PF_PRESENTABLE },
	{ 26, SE_WRITE_FILE_NAME,
	    "Bypass ACL for WRITE and DELETE access", PF_PRESENTABLE },
};

/*
 * smb_priv_presentable_num
 *
 * Returns number of presentable privileges
 */
int
smb_priv_presentable_num()
{
	int i, num;

	num = 0;
	for (i = SE_MIN_LUID; i <= SE_MAX_LUID; i++)
		if (priv_table[i].flags == PF_PRESENTABLE)
			num++;

	return (num);
}

/*
 * smb_priv_presentable_ids
 *
 * Returns IDs of presentable privileges
 * Returns 0 in case of invalid parameter and 1 on success.
 */
int
smb_priv_presentable_ids(uint32_t *ids, int num)
{
	int i, j;

	if (ids == NULL || num <= 0)
		return (0);

	for (i = SE_MIN_LUID, j = 0; i <= SE_MAX_LUID; i++)
		if (priv_table[i].flags == PF_PRESENTABLE)
			ids[j++] = priv_table[i].id;

	return (1);
}

/*
 * smb_priv_getbyvalue
 *
 * Return the privilege info for the specified id (low part of the LUID).
 * Returns a null pointer if id is out-of-range.
 */
smb_privinfo_t *
smb_priv_getbyvalue(uint32_t id)
{
	if (id < SE_MIN_LUID || id > SE_MAX_LUID)
		return (0);

	return (&priv_table[id]);
}


/*
 * smb_priv_getbyname
 *
 * Return the privilege info for the specified name. Returns a null
 * pointer if we can't find a matching name in the table.
 */
smb_privinfo_t *
smb_priv_getbyname(char *name)
{
	smb_privinfo_t *entry;
	int i;

	if (name == 0)
		return (0);

	for (i = SE_MIN_LUID; i <= SE_MAX_LUID; ++i) {
		entry = &priv_table[i];

		if (smb_strcasecmp(name, entry->name, 0) == 0)
			return (entry);
	}

	return (0);
}

/*
 * smb_privset_size
 *
 * Returns the memory block size needed to keep a complete
 * set of privileges in a smb_privset_t structure.
 */
int
smb_privset_size()
{
	int pcnt = SE_MAX_LUID - SE_MIN_LUID + 1;

	return (2 * sizeof (uint32_t) +
	    pcnt * sizeof (smb_luid_attrs_t));
}

/*
 * smb_privset_validate
 *
 * Validates the given privilege set structure
 * Returns 1 if the structure is Ok, otherwise returns 0.
 */
int
smb_privset_validate(smb_privset_t *privset)
{
	int count;
	uint32_t i;

	if (privset == 0) {
		return (0);
	}

	count = SE_MAX_LUID - SE_MIN_LUID + 1;

	if (privset->priv_cnt != count) {
		return (0);
	}

	for (i = 0; i < count; i++) {
		if (privset->priv[i].luid.hi_part != 0) {
			return (0);
		}

		if (privset->priv[i].luid.lo_part !=
		    i + SE_MIN_LUID) {
			return (0);
		}
	}

	return (1);
}

/*
 * smb_privset_init
 *
 * initialize all privileges in disable state.
 */
void
smb_privset_init(smb_privset_t *privset)
{
	int count;
	uint32_t i;

	if (privset == 0)
		return;

	count = SE_MAX_LUID - SE_MIN_LUID + 1;

	privset->priv_cnt = count;
	privset->control = 0;
	for (i = 0; i < count; i++) {
		privset->priv[i].luid.hi_part = 0;
		privset->priv[i].luid.lo_part = i + SE_MIN_LUID;
		privset->priv[i].attrs = 0;
	}
}

/*
 * smb_privset_new
 *
 * Allocate memory and initialize all privileges in disable state.
 * Returns pointer to allocated space or NULL if there is not
 * enough memory.
 */
smb_privset_t *
smb_privset_new()
{
	smb_privset_t *privset;

	privset = malloc(smb_privset_size());
	if (privset == NULL)
		return (NULL);

	smb_privset_init(privset);

	return (privset);
}

/*
 * smb_privset_copy
 *
 * Copy privleges information specified by 'src' to the
 * buffer specified by dst.
 */
void
smb_privset_copy(smb_privset_t *dst, smb_privset_t *src)
{
	if (src == 0 || dst == 0)
		return;

	(void) memcpy(dst, src, smb_privset_size());
}

/*
 * smb_privset_merge
 *
 * Enable the privileges that are enabled in src in dst
 */
void
smb_privset_merge(smb_privset_t *dst, smb_privset_t *src)
{
	int i;

	if (src == NULL || dst == NULL)
		return;

	for (i = 0; i < src->priv_cnt; i++) {
		if (src->priv[i].attrs == SE_PRIVILEGE_ENABLED)
			smb_privset_enable(dst, src->priv[i].luid.lo_part);
	}
}

/*
 * smb_privset_free
 *
 * This will free the memory allocated by the 'privset'.
 */
void
smb_privset_free(smb_privset_t *privset)
{
	free(privset);
}

void
smb_privset_enable(smb_privset_t *privset, uint32_t id)
{
	int i;

	if (privset == NULL)
		return;

	for (i = 0; i < privset->priv_cnt; i++) {
		if (privset->priv[i].luid.lo_part == id)
			privset->priv[i].attrs = SE_PRIVILEGE_ENABLED;
	}
}

void
smb_privset_log(smb_privset_t *privset)
{
	smb_luid_t *luid;
	int i, ecnt;

	if (privset == NULL)
		return;

	for (i = 0, ecnt = 0; i < privset->priv_cnt; ++i) {
		if (privset->priv[i].attrs != 0) {
			ecnt++;
		}
	}

	syslog(LOG_DEBUG, "   Privilege Count: %d (Enable=%d)",
	    privset->priv_cnt, ecnt);

	for (i = 0; i < privset->priv_cnt; ++i) {
		if (privset->priv[i].attrs != 0) {
			luid = &privset->priv[i].luid;
			syslog(LOG_DEBUG, "    %s",
			    smb_priv_getname(luid->lo_part));
		}
	}
}

int
smb_privset_query(smb_privset_t *privset, uint32_t id)
{
	int i;

	if (privset == NULL)
		return (0);

	for (i = 0; privset->priv_cnt; i++) {
		if (privset->priv[i].luid.lo_part == id) {
			if (privset->priv[i].attrs == SE_PRIVILEGE_ENABLED)
				return (1);
			else
				return (0);
		}
	}

	return (0);
}

static char *
smb_priv_getname(uint32_t id)
{
	if (id < SE_MIN_LUID || id > SE_MAX_LUID)
		return ("Unknown Privilege");

	return (priv_table[id].name);
}
