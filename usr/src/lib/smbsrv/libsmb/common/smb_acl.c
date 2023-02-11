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
 *
 * Copyright 2023 RackTop Systems, Inc.
 */

/*
 * SMB server interfaces for ACL conversion (smb_acl_...)
 *
 * There are two variants of this interface:
 * This is the library version.  See also:
 * $SRC/uts/common/fs/smbsrv/smb_acl.c
 */

#include <stddef.h>
#include <strings.h>
#include <syslog.h>
#include <assert.h>

#include <smbsrv/smb.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smb_idmap.h>

#define	ACE_ALL_TYPES	0x001F

/*
 * ACE groups within a DACL
 *
 * This is from lower to higher ACE order priority
 */
#define	SMB_AG_START		0
#define	SMB_AG_ALW_INHRT	0
#define	SMB_AG_DNY_INHRT	1
#define	SMB_AG_ALW_DRCT		2
#define	SMB_AG_DNY_DRCT		3
#define	SMB_AG_NUM		4

#define	DEFAULT_DACL_ACENUM	2
acl_t *acl_alloc(enum acl_type);

static idmap_stat smb_fsacl_getsids(smb_idmap_batch_t *, acl_t *);
static acl_t *smb_fsacl_null_empty(boolean_t);
static boolean_t smb_ace_isvalid(smb_ace_t *, int);
static uint16_t smb_ace_len(smb_ace_t *);
static uint32_t smb_ace_mask_g2s(uint32_t);
static uint16_t smb_ace_flags_tozfs(uint8_t);
static uint8_t smb_ace_flags_fromzfs(uint16_t);
static boolean_t smb_ace_wellknown_update(const char *, ace_t *);

smb_acl_t *
smb_acl_alloc(uint8_t revision, uint16_t bsize, uint16_t acecnt)
{
	smb_acl_t *acl;
	int size;

	size = sizeof (smb_acl_t) + (acecnt * sizeof (smb_ace_t));
	if ((acl = malloc(size)) == NULL)
		return (NULL);

	acl->sl_revision = revision;
	acl->sl_bsize = bsize;
	acl->sl_acecnt = acecnt;
	acl->sl_aces = (smb_ace_t *)(acl + 1);

	list_create(&acl->sl_sorted, sizeof (smb_ace_t),
	    offsetof(smb_ace_t, se_sln));
	return (acl);
}

void
smb_acl_free(smb_acl_t *acl)
{
	int i;
	void *ace;

	if (acl == NULL)
		return;

	for (i = 0; i < acl->sl_acecnt; i++)
		smb_sid_free(acl->sl_aces[i].se_sid);

	while ((ace = list_head(&acl->sl_sorted)) != NULL)
		list_remove(&acl->sl_sorted, ace);
	list_destroy(&acl->sl_sorted);
	free(acl);
}

/*
 * smb_acl_len
 *
 * Returns the size of given ACL in bytes. Note that this
 * is not an in-memory size, it's the ACL's size as it would
 * appear on the wire
 */
uint16_t
smb_acl_len(smb_acl_t *acl)
{
	return ((acl) ? acl->sl_bsize : 0);
}

boolean_t
smb_acl_isvalid(smb_acl_t *acl, int which_acl)
{
	int i;

	if (acl->sl_bsize < SMB_ACL_HDRSIZE)
		return (B_FALSE);

	if (acl->sl_revision != ACL_REVISION) {
		/*
		 * we are rejecting ACLs with object-specific ACEs for now
		 */
		return (B_FALSE);
	}

	for (i = 0; i < acl->sl_acecnt; i++) {
		if (!smb_ace_isvalid(&acl->sl_aces[i], which_acl))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * smb_acl_sort
 *
 * Sorts the given ACL in place if it needs to be sorted.
 *
 * The following is an excerpt from MSDN website.
 *
 * Order of ACEs in a DACL
 *
 * For Windows NT versions 4.0 and earlier, the preferred order of ACEs
 * is simple: In a DACL, all access-denied ACEs should precede any
 * access-allowed ACEs.
 *
 * For Windows 2000 or later, the proper order of ACEs is more complicated
 * because of the introduction of object-specific ACEs and automatic
 * inheritance.
 *
 * The following describes the preferred order:
 *
 * To ensure that noninherited ACEs have precedence over inherited ACEs,
 * place all noninherited ACEs in a group before any inherited ACEs. This
 * ordering ensures, for example, that a noninherited access-denied ACE
 * is enforced regardless of any inherited ACE that allows access.
 * Within the groups of noninherited ACEs and inherited ACEs, order ACEs
 * according to ACE type, as the following shows:
 *	. Access-denied ACEs that apply to the object itself
 *	. Access-denied ACEs that apply to a subobject of the
 *	  object, such as a property set or property
 *	. Access-allowed ACEs that apply to the object itself
 *	. Access-allowed ACEs that apply to a subobject of the object
 *
 * So, here is the desired ACE order
 *
 * deny-direct, allow-direct, deny-inherited, allow-inherited
 *
 * Of course, not all ACE types are required in an ACL.
 */
void
smb_acl_sort(smb_acl_t *acl)
{
	list_t ace_grps[SMB_AG_NUM];
	list_t *alist;
	smb_ace_t *ace;
	uint8_t ace_flags;
	int ag, i;

	assert(acl);

	if (acl->sl_acecnt == 0) {
		/*
		 * ACL with no entry is a valid ACL and it means
		 * no access for anybody.
		 */
		return;
	}

	for (i = SMB_AG_START; i < SMB_AG_NUM; i++) {
		list_create(&ace_grps[i], sizeof (smb_ace_t),
		    offsetof(smb_ace_t, se_sln));
	}

	for (i = 0, ace = acl->sl_aces; i < acl->sl_acecnt; ++i, ace++) {
		ace_flags = ace->se_hdr.se_flags;

		switch (ace->se_hdr.se_type) {
		case ACCESS_DENIED_ACE_TYPE:
			ag = (ace_flags & INHERITED_ACE) ?
			    SMB_AG_DNY_INHRT : SMB_AG_DNY_DRCT;
			break;

		case ACCESS_ALLOWED_ACE_TYPE:
			ag = (ace_flags & INHERITED_ACE) ?
			    SMB_AG_ALW_INHRT : SMB_AG_ALW_DRCT;
			break;

		default:
			/*
			 * This is the lowest priority group so we put
			 * evertything unknown here.
			 */
			ag = SMB_AG_ALW_INHRT;
			break;
		}

		/* Add the ACE to the selected group */
		list_insert_tail(&ace_grps[ag], ace);
	}

	/*
	 * start with highest priority ACE group and append
	 * the ACEs to the ACL.
	 */
	for (i = SMB_AG_NUM - 1; i >= SMB_AG_START; i--) {
		alist = &ace_grps[i];
		while ((ace = list_head(alist)) != NULL) {
			list_remove(alist, ace);
			list_insert_tail(&acl->sl_sorted, ace);
		}
		list_destroy(alist);
	}
}

/*
 * Error handling call-back for smb_idmap_batch_getmappings.
 * Would be nice if this could report the path, but that's not
 * passed down here.  For now, use a dtrace fbt probe here.
 */
static void
smb_acl_bgm_error(smb_idmap_batch_t *sib, smb_idmap_t *sim)
{

	if ((sib->sib_flags & SMB_IDMAP_SKIP_ERRS) != 0)
		return;

	if ((sib->sib_flags & SMB_IDMAP_ID2SID) != 0) {
		/*
		 * Note: The ID and type we asked idmap to map
		 * were saved in *sim_id and sim_idtype.
		 */
		uid_t id = (sim->sim_id == NULL) ? (uid_t)-1 : *sim->sim_id;
		syslog(LOG_ERR, "!smb_acl: Can't get SID for "
		    "ID=%u type=%d, status=%d",
		    id, sim->sim_idtype, sim->sim_stat);
	}

	if ((sib->sib_flags & SMB_IDMAP_SID2ID) != 0) {
		syslog(LOG_ERR, "!smb_acl: Can't get ID for "
		    "SID %s-%u, status=%d",
		    sim->sim_domsid, sim->sim_rid, sim->sim_stat);
	}
}

/*
 * smb_acl_from_zfs
 *
 * Converts given ZFS ACL to a Windows ACL.
 *
 * A pointer to allocated memory for the Windows ACL will be
 * returned upon successful conversion.
 */
smb_acl_t *
smb_acl_from_zfs(acl_t *zacl)
{
	ace_t *zace;
	int numaces;
	smb_acl_t *acl;
	smb_ace_t *ace;
	smb_idmap_batch_t sib;
	smb_idmap_t *sim;
	idmap_stat idm_stat;

	idm_stat = smb_idmap_batch_create(&sib, zacl->acl_cnt,
	    SMB_IDMAP_ID2SID);
	if (idm_stat != IDMAP_SUCCESS)
		return (NULL);

	/*
	 * Note that smb_fsacl_getsids sets up references in
	 * sib.sib_maps to the zace->a_who fields that live
	 * until smb_idmap_batch_destroy is called.
	 */
	if (smb_fsacl_getsids(&sib, zacl) != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (NULL);
	}

	acl = smb_acl_alloc(ACL_REVISION, SMB_ACL_HDRSIZE, zacl->acl_cnt);

	sim = sib.sib_maps;
	for (numaces = 0, zace = zacl->acl_aclp;
	    numaces < zacl->acl_cnt;
	    zace++, numaces++, sim++) {
		assert(sim->sim_sid);
		if (sim->sim_sid == NULL) {
			smb_acl_free(acl);
			acl = NULL;
			break;
		}

		ace = &acl->sl_aces[numaces];
		ace->se_hdr.se_type = zace->a_type;
		ace->se_hdr.se_flags = smb_ace_flags_fromzfs(zace->a_flags);
		ace->se_mask = zace->a_access_mask;
		ace->se_sid = smb_sid_dup(sim->sim_sid);
		ace->se_hdr.se_bsize = smb_ace_len(ace);

		acl->sl_bsize += ace->se_hdr.se_bsize;
	}

	smb_idmap_batch_destroy(&sib);
	return (acl);
}

/*
 * smb_acl_to_zfs
 *
 * Converts given Windows ACL to a ZFS ACL.
 *
 * fs_acl will contain a pointer to the created ZFS ACL.
 * The allocated memory should be freed by calling
 * smb_fsacl_free().
 *
 * Since the output parameter, fs_acl, is allocated in this
 * function, the caller has to make sure *fs_acl is NULL which
 * means it's not pointing to any memory.
 */
uint32_t
smb_acl_to_zfs(smb_acl_t *acl, uint32_t flags, int which_acl, acl_t **fs_acl)
{
	char sidstr[SMB_SID_STRSZ];
	smb_ace_t *ace;
	acl_t *zacl;
	ace_t *zace;
	smb_idmap_batch_t sib;
	smb_idmap_t *sim;
	idmap_stat idm_stat;
	int i;

	assert(fs_acl);
	assert(*fs_acl == NULL);

	if (acl && !smb_acl_isvalid(acl, which_acl))
		return (NT_STATUS_INVALID_ACL);

	if ((acl == NULL) || (acl->sl_acecnt == 0)) {
		if (which_acl == SMB_DACL_SECINFO) {
			*fs_acl = smb_fsacl_null_empty(acl == NULL);
		}

		return (NT_STATUS_SUCCESS);
	}

	idm_stat = smb_idmap_batch_create(&sib, acl->sl_acecnt,
	    SMB_IDMAP_SID2ID);
	if (idm_stat != IDMAP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	zacl = smb_fsacl_alloc(acl->sl_acecnt, flags);

	zace = zacl->acl_aclp;
	ace = acl->sl_aces;
	sim = sib.sib_maps;

	for (i = 0; i < acl->sl_acecnt; i++, zace++, ace++, sim++) {
		zace->a_type = ace->se_hdr.se_type & ACE_ALL_TYPES;
		zace->a_access_mask = smb_ace_mask_g2s(ace->se_mask);
		zace->a_flags = smb_ace_flags_tozfs(ace->se_hdr.se_flags);
		zace->a_who = (uid_t)-1;

		smb_sid_tostr(ace->se_sid, sidstr);

		if (!smb_ace_wellknown_update(sidstr, zace)) {
			sim->sim_id = &zace->a_who;
			idm_stat = smb_idmap_batch_getid(sib.sib_idmaph, sim,
			    ace->se_sid, SMB_IDMAP_UNKNOWN);

			if (idm_stat != IDMAP_SUCCESS) {
				smb_fsacl_free(zacl);
				smb_idmap_batch_destroy(&sib);
				return (NT_STATUS_INTERNAL_ERROR);
			}
		}
	}

	idm_stat = smb_idmap_batch_getmappings(&sib, smb_acl_bgm_error);
	if (idm_stat != IDMAP_SUCCESS) {
		smb_fsacl_free(zacl);
		smb_idmap_batch_destroy(&sib);
		return (NT_STATUS_NONE_MAPPED);
	}

	/*
	 * Set the ACEs group flag based on the type of ID returned.
	 */
	zace = zacl->acl_aclp;
	ace = acl->sl_aces;
	sim = sib.sib_maps;
	for (i = 0; i < acl->sl_acecnt; i++, zace++, ace++, sim++) {
		if (zace->a_who == (uid_t)-1)
			continue;

		if (sim->sim_idtype == SMB_IDMAP_GROUP)
			zace->a_flags |= ACE_IDENTIFIER_GROUP;
	}

	smb_idmap_batch_destroy(&sib);

	*fs_acl = zacl;
	return (NT_STATUS_SUCCESS);
}

static boolean_t
smb_ace_wellknown_update(const char *sid, ace_t *zace)
{
	struct {
		char		*sid;
		uint16_t	flags;
	} map[] = {
		{ NT_WORLD_SIDSTR,			ACE_EVERYONE },
		{ NT_BUILTIN_CURRENT_OWNER_SIDSTR,	ACE_OWNER },
		{ NT_BUILTIN_CURRENT_GROUP_SIDSTR,
			(ACE_GROUP | ACE_IDENTIFIER_GROUP) },
	};

	int	i;

	for (i = 0; i < (sizeof (map) / sizeof (map[0])); ++i) {
		if (strcmp(sid, map[i].sid) == 0) {
			zace->a_flags |= map[i].flags;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * smb_fsacl_getsids
 *
 * Batch all the uid/gid in given ZFS ACL to get their corresponding SIDs.
 * Note: sib is type SMB_IDMAP_ID2SID, zacl->acl_cnt entries.
 */
static idmap_stat
smb_fsacl_getsids(smb_idmap_batch_t *sib, acl_t *zacl)
{
	ace_t *zace;
	idmap_stat idm_stat;
	smb_idmap_t *sim;
	uid_t id;
	int i, idtype;

	sim = sib->sib_maps;

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt;
	    zace++, i++, sim++) {
		id = (uid_t)-1;	/* some types do not need id */
		switch (zace->a_flags & ACE_TYPE_FLAGS) {
		case ACE_OWNER:
			idtype = SMB_IDMAP_OWNERAT;
			break;

		case (ACE_GROUP | ACE_IDENTIFIER_GROUP):
			/* owning group */
			idtype = SMB_IDMAP_GROUPAT;
			break;

		case ACE_IDENTIFIER_GROUP:
			/* regular group */
			idtype = SMB_IDMAP_GROUP;
			id = zace->a_who;
			/* for smb_acl_bgm_error ID2SID */
			sim->sim_id = &zace->a_who;
			break;

		case ACE_EVERYONE:
			idtype = SMB_IDMAP_EVERYONE;
			break;

		default:
			/* user entry */
			idtype = SMB_IDMAP_USER;
			id = zace->a_who;
			/* for smb_acl_bgm_error ID2SID */
			sim->sim_id = &zace->a_who;
			break;
		}

		idm_stat = smb_idmap_batch_getsid(sib->sib_idmaph, sim,
		    id, idtype);

		if (idm_stat != IDMAP_SUCCESS) {
			return (idm_stat);
		}
	}

	idm_stat = smb_idmap_batch_getmappings(sib, smb_acl_bgm_error);
	return (idm_stat);
}

/*
 * smb_fsacl_null_empty
 *
 * NULL DACL means everyone full-access
 * Empty DACL means everyone full-deny
 *
 * ZFS ACL must have at least one entry so smb server has
 * to simulate the aforementioned expected behavior by adding
 * an entry in case the requested DACL is null or empty. Adding
 * a everyone full-deny entry has proved to be problematic in
 * tests since a deny entry takes precedence over allow entries.
 * So, instead of adding a everyone full-deny, an owner ACE with
 * owner implicit permissions will be set.
 */
static acl_t *
smb_fsacl_null_empty(boolean_t null)
{
	acl_t *zacl;
	ace_t *zace;

	zacl = smb_fsacl_alloc(1, ACL_AUTO_INHERIT);
	zace = zacl->acl_aclp;

	zace->a_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	if (null) {
		zace->a_access_mask = ACE_ALL_PERMS;
		zace->a_flags = ACE_EVERYONE;
	} else {
		zace->a_access_mask = ACE_READ_ACL | ACE_WRITE_ACL |
		    ACE_READ_ATTRIBUTES;
		zace->a_flags = ACE_OWNER;
	}

	return (zacl);
}

/*
 * FS ACL (acl_t) Functions
 */
acl_t *
smb_fsacl_alloc(int acenum, int flags)
{
	acl_t *acl;

	acl = acl_alloc(ACE_T);
	acl->acl_cnt = acenum;
	if ((acl->acl_aclp = malloc(acl->acl_entry_size * acenum)) == NULL)
		return (NULL);

	acl->acl_flags = flags;
	return (acl);
}

void
smb_fsacl_free(acl_t *acl)
{
	if (acl)
		acl_free(acl);
}

/*
 * ACE Functions
 */

/*
 * This is generic (ACL version 2) vs. object-specific
 * (ACL version 4) ACE types.
 */
boolean_t
smb_ace_is_generic(int type)
{
	switch (type) {
	case ACE_ACCESS_ALLOWED_ACE_TYPE:
	case ACE_ACCESS_DENIED_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_ACE_TYPE:
	case ACE_SYSTEM_ALARM_ACE_TYPE:
	case ACE_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
	case ACE_ACCESS_DENIED_CALLBACK_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
	case ACE_SYSTEM_ALARM_CALLBACK_ACE_TYPE:
		return (B_TRUE);

	default:
		break;
	}

	return (B_FALSE);
}

boolean_t
smb_ace_is_access(int type)
{
	switch (type) {
	case ACE_ACCESS_ALLOWED_ACE_TYPE:
	case ACE_ACCESS_DENIED_ACE_TYPE:
	case ACE_ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
	case ACE_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
	case ACE_ACCESS_DENIED_OBJECT_ACE_TYPE:
	case ACE_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
	case ACE_ACCESS_DENIED_CALLBACK_ACE_TYPE:
	case ACE_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
	case ACE_ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
		return (B_TRUE);

	default:
		break;
	}

	return (B_FALSE);
}

boolean_t
smb_ace_is_audit(int type)
{
	switch (type) {
	case ACE_SYSTEM_AUDIT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
		return (B_TRUE);

	default:
		break;
	}

	return (B_FALSE);
}

/*
 * smb_ace_len
 *
 * Returns the length of the given ACE as it appears in an
 * ACL on the wire (i.e. a flat buffer which contains the SID)
 */
static uint16_t
smb_ace_len(smb_ace_t *ace)
{
	assert(ace);
	assert(ace->se_sid);

	if (ace == NULL)
		return (0);

	return (SMB_ACE_HDRSIZE + sizeof (ace->se_mask) +
	    smb_sid_len(ace->se_sid));
}

/*
 * smb_ace_mask_g2s
 *
 * Converts generic access bits in the given mask (if any)
 * to file specific bits. Generic access masks shouldn't be
 * stored in filesystem ACEs.
 */
static uint32_t
smb_ace_mask_g2s(uint32_t mask)
{
	if (mask & GENERIC_ALL) {
		mask &= ~(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE
		    | GENERIC_EXECUTE);

		mask |= FILE_ALL_ACCESS;
		return (mask);
	}

	if (mask & GENERIC_READ) {
		mask &= ~GENERIC_READ;
		mask |= FILE_GENERIC_READ;
	}

	if (mask & GENERIC_WRITE) {
		mask &= ~GENERIC_WRITE;
		mask |= FILE_GENERIC_WRITE;
	}

	if (mask & GENERIC_EXECUTE) {
		mask &= ~GENERIC_EXECUTE;
		mask |= FILE_GENERIC_EXECUTE;
	}

	return (mask);
}

/*
 * smb_ace_flags_tozfs
 *
 * This function maps the flags which have different values
 * in Windows and Solaris. The ones with the same value are
 * transferred untouched.
 */
static uint16_t
smb_ace_flags_tozfs(uint8_t c_flags)
{
	uint16_t z_flags = 0;

	if (c_flags & SUCCESSFUL_ACCESS_ACE_FLAG)
		z_flags |= ACE_SUCCESSFUL_ACCESS_ACE_FLAG;

	if (c_flags & FAILED_ACCESS_ACE_FLAG)
		z_flags |= ACE_FAILED_ACCESS_ACE_FLAG;

	if (c_flags & INHERITED_ACE)
		z_flags |= ACE_INHERITED_ACE;

	z_flags |= (c_flags & ACE_INHERIT_FLAGS);

	return (z_flags);
}

static uint8_t
smb_ace_flags_fromzfs(uint16_t z_flags)
{
	uint8_t c_flags;

	c_flags = z_flags & ACE_INHERIT_FLAGS;

	if (z_flags & ACE_SUCCESSFUL_ACCESS_ACE_FLAG)
		c_flags |= SUCCESSFUL_ACCESS_ACE_FLAG;

	if (z_flags & ACE_FAILED_ACCESS_ACE_FLAG)
		c_flags |= FAILED_ACCESS_ACE_FLAG;

	if (z_flags & ACE_INHERITED_ACE)
		c_flags |= INHERITED_ACE;

	return (c_flags);
}

static boolean_t
smb_ace_isvalid(smb_ace_t *ace, int which_acl)
{
	uint16_t min_len;

	min_len = sizeof (smb_acehdr_t);

	if (ace->se_hdr.se_bsize < min_len)
		return (B_FALSE);

	if (smb_ace_is_access(ace->se_hdr.se_type) &&
	    (which_acl != SMB_DACL_SECINFO))
		return (B_FALSE);

	if (smb_ace_is_audit(ace->se_hdr.se_type) &&
	    (which_acl != SMB_SACL_SECINFO))
		return (B_FALSE);

	if (smb_ace_is_generic(ace->se_hdr.se_type)) {
		if (!smb_sid_isvalid(ace->se_sid))
			return (B_FALSE);

		min_len += sizeof (ace->se_mask);
		min_len += smb_sid_len(ace->se_sid);

		if (ace->se_hdr.se_bsize < min_len)
			return (B_FALSE);
	}

	/*
	 * object-specific ACE validation will be added later.
	 */
	return (B_TRUE);
}
