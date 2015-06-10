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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/sid.h>
#include <sys/acl.h>
#include <acl/acl_common.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/smb_kproto.h>

#define	ACE_FD_INHERIT_ACE (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE)

#define	ZACE_IS_OWNER(zace) ((zace->a_flags & ACE_TYPE_FLAGS) == ACE_OWNER)
#define	ZACE_IS_OWNGRP(zace) \
	((zace->a_flags & ACE_TYPE_FLAGS) == (ACE_IDENTIFIER_GROUP|ACE_GROUP))

#define	ZACE_IS_USER(zace) \
	(((zace->a_flags & ACE_TYPE_FLAGS) == 0) || (ZACE_IS_OWNER(zace)))
#define	ZACE_IS_GROUP(zace) (zace->a_flags & ACE_IDENTIFIER_GROUP)
#define	ZACE_IS_EVERYONE(zace) (zace->a_flags & ACE_EVERYONE)

#define	ZACE_IS_PROPAGATE(zace) \
	((zace->a_flags & ACE_NO_PROPAGATE_INHERIT_ACE) == 0)

#define	ZACE_IS_CREATOR_OWNER(zace) \
	(ZACE_IS_USER(zace) && (zace->a_who == IDMAP_WK_CREATOR_OWNER_UID))

#define	ZACE_IS_CREATOR_GROUP(zace) \
	(ZACE_IS_GROUP(zace) && (zace->a_who == IDMAP_WK_CREATOR_GROUP_GID))

#define	ZACE_IS_CREATOR(zace) \
	(ZACE_IS_CREATOR_OWNER(zace) || ZACE_IS_CREATOR_GROUP(zace))

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
/*
 * Default ACL:
 *    owner: full access
 *    SYSTEM: full access
 */
#ifdef	_KERNEL
static const ace_t const default_dacl[DEFAULT_DACL_ACENUM] = {
	{ (uid_t)-1, ACE_ALL_PERMS, 0, ACE_ACCESS_ALLOWED_ACE_TYPE },
	{ IDMAP_WK_LOCAL_SYSTEM_GID, ACE_ALL_PERMS, ACE_IDENTIFIER_GROUP,
	    ACE_ACCESS_ALLOWED_ACE_TYPE }
};
#endif	/* _KERNEL */

/*
 * Note:
 *
 * smb_acl_xxx functions work with smb_acl_t which represents the CIFS format
 * smb_fsacl_xxx functions work with acl_t which represents the Solaris native
 * format
 */

static idmap_stat smb_fsacl_getsids(smb_idmap_batch_t *, acl_t *);
static acl_t *smb_fsacl_null_empty(boolean_t);
#ifdef	_KERNEL
static int smb_fsacl_inheritable(acl_t *, int);
static void smb_ace_inherit(ace_t *, ace_t *, int, uid_t, gid_t);
#endif	/* _KERNEL */

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
	acl = kmem_zalloc(size, KM_SLEEP);
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
	int i, size;
	void *ace;

	if (acl == NULL)
		return;

	for (i = 0; i < acl->sl_acecnt; i++)
		smb_sid_free(acl->sl_aces[i].se_sid);

	while ((ace = list_head(&acl->sl_sorted)) != NULL)
		list_remove(&acl->sl_sorted, ace);
	list_destroy(&acl->sl_sorted);

	size = sizeof (smb_acl_t) + (acl->sl_acecnt * sizeof (smb_ace_t));
	kmem_free(acl, size);
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
 * 	. Access-denied ACEs that apply to the object itself
 * 	. Access-denied ACEs that apply to a subobject of the
 *	  object, such as a property set or property
 * 	. Access-allowed ACEs that apply to the object itself
 * 	. Access-allowed ACEs that apply to a subobject of the object
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

	ASSERT(acl);

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
 * smb_acl_from_zfs
 *
 * Converts given ZFS ACL to a Windows ACL.
 *
 * A pointer to allocated memory for the Win ACL will be
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

	if (smb_fsacl_getsids(&sib, zacl) != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (NULL);
	}

	acl = smb_acl_alloc(ACL_REVISION, SMB_ACL_HDRSIZE, zacl->acl_cnt);

	sim = sib.sib_maps;
	for (numaces = 0, zace = zacl->acl_aclp;
	    numaces < zacl->acl_cnt;
	    zace++, numaces++, sim++) {
		ASSERT(sim->sim_sid);
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
	smb_ace_t *ace;
	acl_t *zacl;
	ace_t *zace;
	smb_idmap_batch_t sib;
	smb_idmap_t *sim;
	idmap_stat idm_stat;
	char *sidstr;
	int i;

	ASSERT(fs_acl);
	ASSERT(*fs_acl == NULL);

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

	sidstr = kmem_alloc(SMB_SID_STRSZ, KM_SLEEP);
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
				kmem_free(sidstr, SMB_SID_STRSZ);
				smb_fsacl_free(zacl);
				smb_idmap_batch_destroy(&sib);
				return (NT_STATUS_INTERNAL_ERROR);
			}
		}
	}

	kmem_free(sidstr, SMB_SID_STRSZ);

	idm_stat = smb_idmap_batch_getmappings(&sib);
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
 */
static idmap_stat
smb_fsacl_getsids(smb_idmap_batch_t *sib, acl_t *zacl)
{
	ace_t *zace;
	idmap_stat idm_stat;
	smb_idmap_t *sim;
	uid_t id = (uid_t)-1;
	int i, idtype;

	sim = sib->sib_maps;

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt;
	    zace++, i++, sim++) {
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
			id = zace->a_who;
			idtype = SMB_IDMAP_GROUP;
			break;

		case ACE_EVERYONE:
			idtype = SMB_IDMAP_EVERYONE;
			break;

		default:
			/* user entry */
			id = zace->a_who;
			idtype = SMB_IDMAP_USER;
		}

		idm_stat = smb_idmap_batch_getsid(sib->sib_idmaph, sim,
		    id, idtype);

		if (idm_stat != IDMAP_SUCCESS) {
			return (idm_stat);
		}
	}

	idm_stat = smb_idmap_batch_getmappings(sib);
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
	acl->acl_aclp = kmem_zalloc(acl->acl_entry_size * acenum, KM_SLEEP);
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
 * smb_fsop_aclmerge
 *
 * smb_fsop_aclread/write routines which interact with filesystem
 * work with single ACL. This routine merges given DACL and SACL
 * which might have been created during CIFS to FS conversion into
 * one single ACL.
 */
acl_t *
smb_fsacl_merge(acl_t *dacl, acl_t *sacl)
{
	acl_t *acl;
	int dacl_size;

	ASSERT(dacl);
	ASSERT(sacl);

	acl = smb_fsacl_alloc(dacl->acl_cnt + sacl->acl_cnt, dacl->acl_flags);
	dacl_size = dacl->acl_cnt * dacl->acl_entry_size;
	bcopy(dacl->acl_aclp, acl->acl_aclp, dacl_size);
	bcopy(sacl->acl_aclp, (char *)acl->acl_aclp + dacl_size,
	    sacl->acl_cnt * sacl->acl_entry_size);

	return (acl);
}

/*
 * smb_fsacl_split
 *
 * splits the given ACE_T ACL (zacl) to one or two ACLs (DACL/SACL) based on
 * the 'which_acl' parameter. Note that output dacl/sacl parameters could be
 * NULL even if they're specified in 'which_acl', which means the target
 * doesn't have any access and/or audit ACEs.
 */
void
smb_fsacl_split(acl_t *zacl, acl_t **dacl, acl_t **sacl, int which_acl)
{
	ace_t *zace;
	ace_t *access_ace = NULL;
	ace_t *audit_ace = NULL;
	int naccess, naudit;
	int get_dacl, get_sacl;
	int i;

	*dacl = *sacl = NULL;
	naccess = naudit = 0;
	get_dacl = (which_acl & SMB_DACL_SECINFO);
	get_sacl = (which_acl & SMB_SACL_SECINFO);

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt; zace++, i++) {
		if (get_dacl && smb_ace_is_access(zace->a_type))
			naccess++;
		else if (get_sacl && smb_ace_is_audit(zace->a_type))
			naudit++;
	}

	if (naccess) {
		*dacl = smb_fsacl_alloc(naccess, zacl->acl_flags);
		access_ace = (*dacl)->acl_aclp;
	}

	if (naudit) {
		*sacl = smb_fsacl_alloc(naudit, zacl->acl_flags);
		audit_ace = (*sacl)->acl_aclp;
	}

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt; zace++, i++) {
		if (get_dacl && smb_ace_is_access(zace->a_type)) {
			*access_ace = *zace;
			access_ace++;
		} else if (get_sacl && smb_ace_is_audit(zace->a_type)) {
			*audit_ace = *zace;
			audit_ace++;
		}
	}
}

/*
 * ACE Inheritance Rules
 *
 * The system propagates inheritable ACEs to child objects according to a
 * set of inheritance rules. The system places inherited ACEs in the child's
 * DACL according to the preferred order of ACEs in a DACL. For Windows
 * 2000 or later, the system sets the INHERITED_ACE flag in all inherited ACEs.
 *
 * The following table shows the ACEs inherited by container and noncontainer
 * child objects for different combinations of inheritance flags. These
 * inheritance rules work the same for both DACLs and SACLs.
 *
 * Parent ACE type 			Effect on Child ACL
 * -----------------------		-------------------
 * OBJECT_INHERIT_ACE only 		Noncontainer child objects:
 *					Inherited as an effective ACE.
 *					Container child objects:
 *					Containers inherit an inherit-only ACE
 *					unless the NO_PROPAGATE_INHERIT_ACE bit
 *					flag is also set.
 *
 * CONTAINER_INHERIT_ACE only 		Noncontainer child objects:
 *					No effect on the child object.
 *					Container child objects:
 *				The child object inherits an effective ACE.
 *				The inherited ACE is inheritable unless the
 *				NO_PROPAGATE_INHERIT_ACE bit flag is also set.
 *
 * CONTAINER_INHERIT_ACE and
 * OBJECT_INHERIT_ACE 			Noncontainer child objects:
 *					Inherited as an effective ACE.
 *					Container child objects:
 *				The child object inherits an effective ACE.
 *				The inherited ACE is inheritable unless the
 *				NO_PROPAGATE_INHERIT_ACE bit flag is also set
 *
 * No inheritance flags set 	No effect on child container or noncontainer
 *				objects.
 *
 * If an inherited ACE is an effective ACE for the child object, the system
 * maps any generic rights to the specific rights for the child object.
 * Similarly, the system maps generic SIDs, such as CREATOR_OWNER, to the
 * appropriate SID. If an inherited ACE is an inherit-only ACE, any generic
 * rights or generic SIDs are left unchanged so that they can be mapped
 * appropriately when the ACE is inherited by the next generation of child
 * objects.
 *
 * For a case in which a container object inherits an ACE that is both
 * effective on the container and inheritable by its descendants, the
 * container may inherit two ACEs. This occurs if the inheritable ACE
 * contains generic information. The container inherits an inherit-only
 * ACE containing the generic information and an effective-only ACE in
 * which the generic information has been mapped.
 */

#ifdef	_KERNEL
/*
 * smb_fsacl_inherit
 *
 * Manufacture the inherited ACL from the given ACL considering
 * the new object type (file/dir) specified by 'is_dir'. The
 * returned ACL is used in smb_fsop_create/smb_fsop_mkdir functions.
 * This function implements Windows inheritance rules explained above.
 *
 * Note that the in/out ACLs are ZFS ACLs not Windows ACLs
 */
acl_t *
smb_fsacl_inherit(acl_t *dir_zacl, int is_dir, int which_acl, cred_t *cr)
{
	boolean_t use_default = B_FALSE;
	int num_inheritable = 0;
	int numaces;
	ace_t *dir_zace;
	acl_t *new_zacl;
	ace_t *new_zace;
	ksid_t *owner_sid;
	ksid_t *group_sid;
	uid_t uid;
	gid_t gid;

	owner_sid = crgetsid(cr, KSID_OWNER);
	group_sid = crgetsid(cr, KSID_GROUP);
	ASSERT(owner_sid);
	ASSERT(group_sid);
	uid = owner_sid->ks_id;
	gid = group_sid->ks_id;

	num_inheritable = smb_fsacl_inheritable(dir_zacl, is_dir);

	if (num_inheritable == 0) {
		if (which_acl == SMB_DACL_SECINFO) {
			/* No inheritable access ACEs -> default DACL */
			num_inheritable = DEFAULT_DACL_ACENUM;
			use_default = B_TRUE;
		} else {
			return (NULL);
		}
	}

	new_zacl = smb_fsacl_alloc(num_inheritable, ACL_AUTO_INHERIT);
	new_zace = new_zacl->acl_aclp;

	if (use_default) {
		bcopy(default_dacl, new_zacl->acl_aclp, sizeof (default_dacl));
		new_zace->a_who = uid;
		return (new_zacl);
	}

	for (numaces = 0, dir_zace = dir_zacl->acl_aclp;
	    numaces < dir_zacl->acl_cnt;
	    dir_zace++, numaces++) {
		switch (dir_zace->a_flags & ACE_FD_INHERIT_ACE) {
		case (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE):
			/*
			 * Files inherit an effective ACE.
			 *
			 * Dirs inherit an effective ACE.
			 * The inherited ACE is inheritable unless the
			 * ACE_NO_PROPAGATE_INHERIT_ACE bit flag is also set
			 */
			smb_ace_inherit(dir_zace, new_zace, is_dir, uid, gid);
			new_zace++;

			if (is_dir && ZACE_IS_CREATOR(dir_zace) &&
			    (ZACE_IS_PROPAGATE(dir_zace))) {
				*new_zace = *dir_zace;
				new_zace->a_flags |= (ACE_INHERIT_ONLY_ACE |
				    ACE_INHERITED_ACE);
				new_zace++;
			}
			break;

		case ACE_FILE_INHERIT_ACE:
			/*
			 * Files inherit as an effective ACE.
			 *
			 * Dirs inherit an inherit-only ACE
			 * unless the ACE_NO_PROPAGATE_INHERIT_ACE bit
			 * flag is also set.
			 */
			if (is_dir == 0) {
				smb_ace_inherit(dir_zace, new_zace, is_dir,
				    uid, gid);
				new_zace++;
			} else if (ZACE_IS_PROPAGATE(dir_zace)) {
				*new_zace = *dir_zace;
				new_zace->a_flags |= (ACE_INHERIT_ONLY_ACE |
				    ACE_INHERITED_ACE);
				new_zace++;
			}
			break;

		case ACE_DIRECTORY_INHERIT_ACE:
			/*
			 * No effect on files
			 *
			 * Dirs inherit an effective ACE.
			 * The inherited ACE is inheritable unless the
			 * ACE_NO_PROPAGATE_INHERIT_ACE bit flag is also set.
			 */
			if (is_dir == 0)
				break;

			smb_ace_inherit(dir_zace, new_zace, is_dir, uid, gid);
			new_zace++;

			if (ZACE_IS_CREATOR(dir_zace) &&
			    (ZACE_IS_PROPAGATE(dir_zace))) {
				*new_zace = *dir_zace;
				new_zace->a_flags |= (ACE_INHERIT_ONLY_ACE |
				    ACE_INHERITED_ACE);
				new_zace++;
			}

			break;

		default:
			break;
		}
	}

	return (new_zacl);
}
#endif	/* _KERNEL */

/*
 * smb_fsacl_from_vsa
 *
 * Converts given vsecattr_t structure to a acl_t structure.
 *
 * The allocated memory for retuned acl_t should be freed by
 * calling acl_free().
 */
acl_t *
smb_fsacl_from_vsa(vsecattr_t *vsecattr, acl_type_t acl_type)
{
	int		aclbsize = 0;	/* size of acl list in bytes */
	int		dfaclbsize = 0;	/* size of default acl list in bytes */
	int		numacls;
	acl_t		*acl_info;

	ASSERT(vsecattr);

	acl_info = acl_alloc(acl_type);
	if (acl_info == NULL)
		return (NULL);

	acl_info->acl_flags = 0;

	switch (acl_type) {

	case ACLENT_T:
		numacls = vsecattr->vsa_aclcnt + vsecattr->vsa_dfaclcnt;
		aclbsize = vsecattr->vsa_aclcnt * sizeof (aclent_t);
		dfaclbsize = vsecattr->vsa_dfaclcnt * sizeof (aclent_t);

		acl_info->acl_cnt = numacls;
		acl_info->acl_aclp = kmem_alloc(aclbsize + dfaclbsize,
		    KM_SLEEP);
		(void) memcpy(acl_info->acl_aclp, vsecattr->vsa_aclentp,
		    aclbsize);
		(void) memcpy((char *)acl_info->acl_aclp + aclbsize,
		    vsecattr->vsa_dfaclentp, dfaclbsize);

		if (acl_info->acl_cnt <= MIN_ACL_ENTRIES)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;

		break;

	case ACE_T:
		aclbsize = vsecattr->vsa_aclcnt * sizeof (ace_t);
		acl_info->acl_cnt = vsecattr->vsa_aclcnt;
		acl_info->acl_flags = vsecattr->vsa_aclflags;
		acl_info->acl_aclp = kmem_alloc(aclbsize, KM_SLEEP);
		(void) memcpy(acl_info->acl_aclp, vsecattr->vsa_aclentp,
		    aclbsize);
		if (ace_trivial(acl_info->acl_aclp, acl_info->acl_cnt) == 0)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;

		break;

	default:
		acl_free(acl_info);
		return (NULL);
	}

	if (aclbsize && vsecattr->vsa_aclentp)
		kmem_free(vsecattr->vsa_aclentp, aclbsize);
	if (dfaclbsize && vsecattr->vsa_dfaclentp)
		kmem_free(vsecattr->vsa_dfaclentp, dfaclbsize);

	return (acl_info);
}

/*
 * smb_fsacl_to_vsa
 *
 * Converts given acl_t structure to a vsecattr_t structure.
 *
 * IMPORTANT:
 * Upon successful return the memory allocated for vsa_aclentp
 * should be freed by calling kmem_free(). The size is returned
 * in aclbsize.
 */
int
smb_fsacl_to_vsa(acl_t *acl_info, vsecattr_t *vsecattr, int *aclbsize)
{
	int		error = 0;
	int		numacls;
	aclent_t	*aclp;

	ASSERT(acl_info);
	ASSERT(vsecattr);
	ASSERT(aclbsize);

	bzero(vsecattr, sizeof (vsecattr_t));
	*aclbsize = 0;

	switch (acl_info->acl_type) {
	case ACLENT_T:
		numacls = acl_info->acl_cnt;
		/*
		 * Minimum ACL size is three entries so might as well
		 * bail out here.  Also limit request size to prevent user
		 * from allocating too much kernel memory.  Maximum size
		 * is MAX_ACL_ENTRIES for the ACL part and MAX_ACL_ENTRIES
		 * for the default ACL part.
		 */
		if (numacls < 3 || numacls > (MAX_ACL_ENTRIES * 2)) {
			error = EINVAL;
			break;
		}

		vsecattr->vsa_mask = VSA_ACL;

		vsecattr->vsa_aclcnt = numacls;
		*aclbsize = numacls * sizeof (aclent_t);
		vsecattr->vsa_aclentp = kmem_alloc(*aclbsize, KM_SLEEP);
		(void) memcpy(vsecattr->vsa_aclentp, acl_info->acl_aclp,
		    *aclbsize);

		/* Sort the acl list */
		ksort((caddr_t)vsecattr->vsa_aclentp,
		    vsecattr->vsa_aclcnt, sizeof (aclent_t), cmp2acls);

		/* Break into acl and default acl lists */
		for (numacls = 0, aclp = vsecattr->vsa_aclentp;
		    numacls < vsecattr->vsa_aclcnt;
		    aclp++, numacls++) {
			if (aclp->a_type & ACL_DEFAULT)
				break;
		}

		/* Find where defaults start (if any) */
		if (numacls < vsecattr->vsa_aclcnt) {
			vsecattr->vsa_mask |= VSA_DFACL;
			vsecattr->vsa_dfaclcnt = vsecattr->vsa_aclcnt - numacls;
			vsecattr->vsa_dfaclentp = aclp;
			vsecattr->vsa_aclcnt = numacls;
		}

		/* Adjust if they're all defaults */
		if (vsecattr->vsa_aclcnt == 0) {
			vsecattr->vsa_mask &= ~VSA_ACL;
			vsecattr->vsa_aclentp = NULL;
		}

		/* Only directories can have defaults */
		if (vsecattr->vsa_dfaclcnt &&
		    (acl_info->acl_flags & ACL_IS_DIR)) {
			error = ENOTDIR;
		}

		break;

	case ACE_T:
		if (acl_info->acl_cnt < 1 ||
		    acl_info->acl_cnt > MAX_ACL_ENTRIES) {
			error = EINVAL;
			break;
		}

		vsecattr->vsa_mask = VSA_ACE | VSA_ACE_ACLFLAGS;
		vsecattr->vsa_aclcnt = acl_info->acl_cnt;
		vsecattr->vsa_aclflags = acl_info->acl_flags & ACL_FLAGS_ALL;
		*aclbsize = vsecattr->vsa_aclcnt * sizeof (ace_t);
		vsecattr->vsa_aclentsz = *aclbsize;
		vsecattr->vsa_aclentp = kmem_alloc(*aclbsize, KM_SLEEP);
		(void) memcpy(vsecattr->vsa_aclentp, acl_info->acl_aclp,
		    *aclbsize);

		break;

	default:
		error = EINVAL;
	}

	return (error);
}

#ifdef	_KERNEL
/*
 * smb_fsacl_inheritable
 *
 * Checks to see if there are any inheritable ACEs in the
 * given ZFS ACL. Returns the number of inheritable ACEs.
 *
 * The inherited ACL could be different based on the type of
 * new object (file/dir) specified by 'is_dir'.
 *
 * Note that the input ACL is a ZFS ACL not Windows ACL.
 */
static int
smb_fsacl_inheritable(acl_t *zacl, int is_dir)
{
	int numaces;
	int num_inheritable = 0;
	ace_t *zace;

	if (zacl == NULL)
		return (0);

	for (numaces = 0, zace = zacl->acl_aclp;
	    numaces < zacl->acl_cnt;
	    zace++, numaces++) {
		switch (zace->a_flags & ACE_FD_INHERIT_ACE) {
		case (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE):
			/*
			 * Files inherit an effective ACE.
			 *
			 * Dirs inherit an effective ACE.
			 * The inherited ACE is inheritable unless the
			 * ACE_NO_PROPAGATE_INHERIT_ACE bit flag is also set
			 */
			num_inheritable++;

			if (is_dir && ZACE_IS_CREATOR(zace) &&
			    (ZACE_IS_PROPAGATE(zace))) {
				num_inheritable++;
			}
			break;

		case ACE_FILE_INHERIT_ACE:
			/*
			 * Files inherit as an effective ACE.
			 *
			 * Dirs inherit an inherit-only ACE
			 * unless the ACE_NO_PROPAGATE_INHERIT_ACE bit
			 * flag is also set.
			 */
			if (is_dir == 0)
				num_inheritable++;
			else if (ZACE_IS_PROPAGATE(zace))
				num_inheritable++;
			break;

		case ACE_DIRECTORY_INHERIT_ACE:
			/*
			 * No effect on files
			 *
			 * Dirs inherit an effective ACE.
			 * The inherited ACE is inheritable unless the
			 * ACE_NO_PROPAGATE_INHERIT_ACE bit flag is also set.
			 */
			if (is_dir == 0)
				break;

			num_inheritable++;

			if (ZACE_IS_CREATOR(zace) &&
			    (ZACE_IS_PROPAGATE(zace)))
				num_inheritable++;
			break;

		default:
			break;
		}
	}

	return (num_inheritable);
}
#endif	/* _KERNEL */


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
	ASSERT(ace);
	ASSERT(ace->se_sid);

	if (ace == NULL)
		return (0);

	return (SMB_ACE_HDRSIZE + sizeof (ace->se_mask) +
	    smb_sid_len(ace->se_sid));
}

#ifdef	_KERNEL
static void
smb_ace_inherit(ace_t *dir_zace, ace_t *zace, int is_dir, uid_t uid, gid_t gid)
{
	*zace = *dir_zace;

	/* This is an effective ACE so remove the inherit_only flag */
	zace->a_flags &= ~ACE_INHERIT_ONLY_ACE;
	/* Mark this ACE as inherited */
	zace->a_flags |= ACE_INHERITED_ACE;

	/*
	 * If this is a file or NO_PROPAGATE is set then this inherited
	 * ACE is not inheritable so clear the inheritance flags
	 */
	if (!(is_dir && ZACE_IS_PROPAGATE(dir_zace)))
		zace->a_flags &= ~ACE_INHERIT_FLAGS;

	/*
	 * Replace creator owner/group ACEs with actual owner/group ACEs.
	 * This is a non-inheritable effective ACE.
	 */
	if (ZACE_IS_CREATOR_OWNER(dir_zace)) {
		zace->a_who = uid;
		zace->a_flags &= ~ACE_INHERIT_FLAGS;
	} else if (ZACE_IS_CREATOR_GROUP(dir_zace)) {
		zace->a_who = gid;
		zace->a_flags |= ACE_IDENTIFIER_GROUP;
		zace->a_flags &= ~ACE_INHERIT_FLAGS;
	}
}
#endif	/* _KERNEL */

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
