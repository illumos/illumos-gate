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
 * Platform SDK: Security
 *
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
 * Parent ACE type 				Effect on Child ACL
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

#include <sys/acl.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_idmap.h>

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

static int smb_ace_isvalid(smb_ace_hdr_t *ace, int which_acl);
static int smb_ace_append_generic(smb_acl_t *acl, void *generic_ace);

static int smb_ace_common_add(
    smb_acl_t *acl,
    uint8_t type,
    uint8_t flags,
    uint32_t access_mask,
    nt_sid_t *sid);

static void smb_ace_inherit(ace_t *dir_zace, ace_t *zace, int is_dir);
static uint16_t smb_ace_flags_tozfs(uint8_t c_flags, int isdir);
static uint8_t smb_ace_flags_fromzfs(uint16_t z_flags);
static void smb_acl_init(smb_acl_t *acl, uint16_t size, uint8_t rev);

static int
smb_ace_isvalid(smb_ace_hdr_t *ace, int which_acl)
{
	uint16_t min_len;
	smb_ace_t *p;

	min_len = sizeof (smb_ace_hdr_t);

	if (ace->se_size < min_len)
		return (0);

	if (smb_ace_is_access(ace->se_type) &&
	    (which_acl != SMB_DACL_SECINFO)) {
		return (0);
	}

	if (smb_ace_is_audit(ace->se_type) &&
	    (which_acl != SMB_SACL_SECINFO)) {
		return (0);
	}

	if (smb_ace_is_generic(ace->se_type)) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		p = (smb_ace_t *)ace;

		if (ace->se_size < sizeof (*p))
			return (0);	/* won't handle empty SubAuthority[] */

		if (nt_sid_is_valid(&p->se_sid) == 0)
			return (0);

		min_len += sizeof (p->se_mask);
		min_len += nt_sid_length(&p->se_sid);

		if (ace->se_size < min_len)
			return (0);
	}

	/*
	 * XXX object-specific ACE validation will be added later.
	 */
	return (1);
}

int
smb_acl_isvalid(smb_acl_t *acl, int which_acl)
{
	uint16_t	min_len;
	unsigned char	*scan;
	unsigned char	*scan_end;
	smb_ace_hdr_t	*ace;
	uint16_t	count = 0;

	min_len = sizeof (smb_acl_t);

	if (acl->sl_size < min_len)
		return (0);

	if (acl->sl_revision != ACL_REVISION) {
		/*
		 * XXX we are rejecting ACLs with object-specific ACEs for now
		 */
		return (0);
	}

	scan = (unsigned char *) &acl[0];
	scan_end = scan + acl->sl_size;
	scan = (unsigned char *) &acl[1];	/* skip Acl header */

	while (count < acl->sl_acecnt && scan < scan_end) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		ace = (smb_ace_hdr_t *)scan;

		if (scan + sizeof (smb_ace_hdr_t) >= scan_end)
			return (0);

		if (scan + ace->se_size > scan_end)
			return (0);	/* overflow */

		if (!smb_ace_isvalid(ace, which_acl))
			return (0);

		scan += ace->se_size;
		count++;
	}

	return (1);
}


static void
smb_acl_init(smb_acl_t *acl, uint16_t size, uint8_t rev)
{
	bzero(acl, size);
	acl->sl_revision = rev;
	acl->sl_size = size;
}

uint16_t
smb_acl_len(smb_acl_t *acl)
{
	smb_ace_hdr_t *ace;
	unsigned char *scan_beg;
	unsigned char *scan_end;
	unsigned char *scan;
	uint16_t length;
	uint16_t count;

	scan_beg = (unsigned char *) &acl[0];
	scan_end = scan_beg + acl->sl_size;
	scan = (unsigned char *) &acl[1];
	length   = sizeof (smb_acl_t);
	count    = 0;

	while ((count < acl->sl_acecnt) && (scan < scan_end)) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		ace = (smb_ace_hdr_t *)scan;
		length += ace->se_size;
		scan += ace->se_size;
		count++;
	}

	return (length);
}

/*
 * Append the generic ACE to the ACL. This is used to put any
 * kind of ACE on the ACL so the argument is declared as a void*. We cast it
 * to an ACCESS_ALLOWED_ACE just because there is no sense of a generic ACE.
 */
static int
smb_ace_append_generic(smb_acl_t *acl, void *generic_ace)
{
	smb_ace_t *ace = (smb_ace_t *)generic_ace;
	uint16_t acl_len = smb_acl_len(acl);
	unsigned char *scan = (uchar_t *)acl;

	if ((acl_len + ace->se_header.se_size) > acl->sl_size) {
		/* no room in the acl for this ace */
		return (0);
	}

	/* append the ace to the acl and inc ace count */
	bcopy(ace, &scan[acl_len], ace->se_header.se_size);
	acl->sl_acecnt++;

	return (1);
}

/*
 * Helper for the ACL sort routine
 */
typedef struct smb_ace_entry {
	smb_ace_t	*e_ace;
	list_node_t	e_node;
} smb_ace_entry_t;

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

/*
 * smb_acl_do_sort
 *
 * Sorts the given ACL, acl, and returns the result
 * in a newly allocated memory.
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
 * Of course, not all ACE types are required in an ACL.
 */
static smb_acl_t *
smb_acl_do_sort(smb_acl_t *acl, list_t *ace_grps)
{
	smb_acl_t *sorted_acl;
	smb_ace_entry_t *nae;
	int i;

	sorted_acl = kmem_alloc(acl->sl_size, KM_SLEEP);
	*sorted_acl = *acl;

	/* start with no ACE in the sorted ACL */
	sorted_acl->sl_acecnt = 0;

	/*
	 * start with highest priority ACE group and append
	 * the ACEs to the ACL.
	 */
	for (i = SMB_AG_NUM - 1; i >= SMB_AG_START; i--) {
		nae = list_head(&ace_grps[i]);
		while (nae) {
			if (!smb_ace_append_generic(sorted_acl, nae->e_ace)) {
				kmem_free(sorted_acl, acl->sl_size);
				return (NULL);
			}
			nae = list_next(&ace_grps[i], nae);
		}
	}

	return (sorted_acl);
}

/*
 * smb_acl_need_sort
 *
 * Here is the desired ACE order
 *
 * deny-direct, allow-direct, deny-inherited, allow-inherited
 *
 * If any ace has been encountered which belongs to a group
 * with lower priority of the specified ace_grp then the acl
 * should be sorted.
 */
static int
smb_acl_need_sort(list_t *ace_grps, int ace_grp)
{
	int i;

	for (i = SMB_AG_START; i < ace_grp; i++)
		if (!list_is_empty(&ace_grps[i]))
			return (1);

	return (0);
}

/*
 * smb_acl_sort
 *
 * Returns NULL upon failure.
 * Returns pointer to the passed (original) acl if no sort is required.
 * Returns pointer to a new acl upon successful sort in which case the
 * caller is responsible for freeing the allocated memory.
 */
smb_acl_t *
smb_acl_sort(smb_acl_t *acl)
{
	smb_acl_t *sorted_acl;
	smb_ace_t *ace;
	smb_ace_entry_t *ace_list;
	int ace_list_size;
	list_t ace_grps[SMB_AG_NUM];
	int ag;
	int do_sort = 0;
	uint16_t i;
	uint8_t ace_flags;

	ASSERT(acl);

	if (acl->sl_acecnt == 0) {
		/*
		 * ACL with no entry is a valid ACL and it means
		 * no access for anybody.
		 */
		return (acl);
	}

	for (i = SMB_AG_START; i < SMB_AG_NUM; i++) {
		list_create(&ace_grps[i], sizeof (smb_ace_entry_t),
		    offsetof(smb_ace_entry_t, e_node));
	}

	/*
	 * Allocate the helper entries to group the ACEs based on
	 * the desired priorities.
	 */
	ace_list_size = sizeof (smb_ace_entry_t) * acl->sl_acecnt;
	ace_list = kmem_alloc(ace_list_size, KM_SLEEP);

	for (i = 0; i < acl->sl_acecnt; ++i) {
		ace_list[i].e_ace = smb_ace_get(acl, i);
		ace = ace_list[i].e_ace;
		ASSERT(ace);

		ace_flags = ace->se_header.se_flags;

		switch (ace->se_header.se_type) {
		case ACCESS_DENIED_ACE_TYPE:
			if (ace_flags & INHERITED_ACE) {
				ag = SMB_AG_DNY_INHRT;
				do_sort |= smb_acl_need_sort(ace_grps, ag);
			} else {
				ag = SMB_AG_DNY_DRCT;
				do_sort |= smb_acl_need_sort(ace_grps, ag);
			}
			break;

		case ACCESS_ALLOWED_ACE_TYPE:
			if (ace_flags & INHERITED_ACE) {
				ag = SMB_AG_ALW_INHRT;
			} else {
				ag = SMB_AG_ALW_DRCT;
				do_sort |= smb_acl_need_sort(ace_grps, ag);
			}
			break;

		default:
			/*
			 * This is the lowest priority group so we put
			 * evertything unknown here.
			 */
			ag = SMB_AG_ALW_INHRT;
			break;
		}

		/* Put the element on the appropriate list */
		list_insert_tail(&ace_grps[ag], &ace_list[i]);
	}

	if (do_sort)
		sorted_acl = smb_acl_do_sort(acl, ace_grps);
	else
		sorted_acl = acl;

	for (i = SMB_AG_START; i < SMB_AG_NUM; i++) {
		void *ent;
		list_t *alist = &ace_grps[i];

		while ((ent = list_head(alist)) != NULL)
			list_remove(alist, ent);
		list_destroy(alist);
	}

	kmem_free(ace_list, ace_list_size);

	return (sorted_acl);
}

static int
smb_ace_common_add(
    smb_acl_t *acl,
    uint8_t type,
    uint8_t flags,
    uint32_t access_mask,
    nt_sid_t *sid)
{
	smb_ace_t *ace;
	unsigned char *scan = (unsigned char *) acl;
	uint16_t used = smb_acl_len(acl);
	uint16_t sid_len = nt_sid_length(sid);
	uint16_t size;

	size = sizeof (ace->se_header) + sizeof (ace->se_mask) + sid_len;

	if (size + used > acl->sl_size) {
		/* won't fit */
		return (0);
	}

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	ace = (smb_ace_t *)&scan[used];

	ace->se_header.se_type  = type;
	ace->se_header.se_flags = flags;
	ace->se_header.se_size  = size;
	ace->se_mask = access_mask;
	bcopy(sid, &ace->se_sid, sid_len);

	acl->sl_acecnt++;

	return (1);
}

smb_ace_t *
smb_ace_get(smb_acl_t *acl, uint16_t idx)
{
	smb_ace_t *ace;
	unsigned char *scan_beg = (unsigned char *) &acl[0];
	unsigned char *scan_end = scan_beg + acl->sl_size;
	unsigned char *scan = (unsigned char *) &acl[1];
	uint16_t count = 0;

	if (idx >= acl->sl_acecnt)
		return (NULL);

	while (count <= idx && scan < scan_end) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		ace = (smb_ace_t *)scan;

		if (count == idx) {
			return (ace);
		}

		scan += ace->se_header.se_size;
		count++;
	}

	return (NULL);
}

int
smb_acl_copy(uint16_t buflen, smb_acl_t *dst_acl, smb_acl_t *src_acl)
{
	smb_ace_hdr_t *dst_ace;
	smb_ace_hdr_t *src_ace;
	unsigned char *scan = (unsigned char *) &src_acl[1];
	unsigned char *dest_beg = (unsigned char *) &dst_acl[0];
	unsigned char *dest_end;
	unsigned char *dest = (unsigned char *) &dst_acl[1];
	uint16_t count = 0;
	uint16_t n_bytes;

	n_bytes = smb_acl_len(src_acl);
	if (n_bytes > buflen)
		return (0);

	dest_end = dest_beg + n_bytes;

	dst_acl->sl_revision = src_acl->sl_revision;
	dst_acl->sl_sbz1 = 0;
	dst_acl->sl_size = n_bytes;
	dst_acl->sl_acecnt = 0;
	dst_acl->sl_sbz2 = 0;

	while (count < src_acl->sl_acecnt && dest < dest_end) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		src_ace = (smb_ace_hdr_t *)scan;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		dst_ace = (smb_ace_hdr_t *)dest;
		bcopy(src_ace, dst_ace, src_ace->se_size);
		dest += dst_ace->se_size;
		dst_acl->sl_acecnt++;
		scan += src_ace->se_size;
		count++;
	}

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (dest - dest_beg);
}

/*
 * smb_ace_len
 *
 * Returns the length of an ACE with the given SID
 *
 * struct smb_ace {
 *	smb_ace_hdr_t se_header;
 *	uint32_t se_mask;
 *	nt_sid_t se_sid;
 * };
 */
uint16_t
smb_ace_len(nt_sid_t *sid)
{
	ASSERT(sid);

	return (sizeof (smb_ace_hdr_t)
	    + sizeof (uint32_t) + nt_sid_length(sid));
}

/*
 * smb_ace_mask_g2s
 *
 * Converts generic access bits in the given mask (if any)
 * to file specific bits. Generic access masks shouldn't be
 * stored in filesystem ACEs.
 */
uint32_t
smb_ace_mask_g2s(DWORD mask)
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
 * smb_acl_getsids
 *
 * Batch all the uid/gid in given ZFS ACL to get their corresponding SIDs.
 */
static idmap_stat
smb_acl_getsids(smb_idmap_batch_t *sib, acl_t *zacl, uid_t uid, gid_t gid)
{
	ace_t *zace;
	idmap_stat idm_stat;
	smb_idmap_t *sim;
	uid_t id;
	int i, idtype;

	sim = sib->sib_maps;

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt;
	    zace++, i++, sim++) {
		switch (zace->a_flags & ACE_TYPE_FLAGS) {
		case ACE_OWNER:
			id = uid;
			idtype = SMB_IDMAP_USER;
			break;

		case (ACE_GROUP | ACE_IDENTIFIER_GROUP):
			/* owning group */
			id = gid;
			idtype = SMB_IDMAP_GROUP;
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
 * smb_acl_grow
 *
 * Grow the acl size by given number of bytes in 'grow'
 * Returns pointer to the newly allocated memory.
 */
static smb_acl_t *
smb_acl_grow(smb_acl_t *acl, uint16_t grow)
{
	smb_acl_t *new_acl;
	uint16_t smb_aclsz;

	ASSERT(acl);

	smb_aclsz = acl->sl_size;
	new_acl = kmem_alloc(smb_aclsz + grow, KM_SLEEP);
	(void) memcpy(new_acl, acl, smb_aclsz);
	kmem_free(acl, smb_aclsz);
	new_acl->sl_size = smb_aclsz + grow;

	return (new_acl);
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
smb_acl_from_zfs(acl_t *zacl, uid_t uid, gid_t gid)
{
	ace_t *zace;
	int numaces;
	smb_acl_t *acl;
	uint16_t smb_aclsz;
	smb_idmap_batch_t sib;
	smb_idmap_t *sim;
	idmap_stat idm_stat;
	int status;

	idm_stat = smb_idmap_batch_create(&sib, zacl->acl_cnt,
	    SMB_IDMAP_ID2SID);
	if (idm_stat != IDMAP_SUCCESS)
		return (NULL);

	if (smb_acl_getsids(&sib, zacl, uid, gid) != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (NULL);
	}

	smb_aclsz = sizeof (smb_acl_t);

	acl = kmem_alloc(smb_aclsz, KM_SLEEP);
	smb_acl_init(acl, smb_aclsz, ACL_REVISION);

	sim = sib.sib_maps;
	for (numaces = 0, zace = zacl->acl_aclp;
	    numaces < zacl->acl_cnt;
	    zace++, numaces++, sim++) {
		ASSERT(sim->sim_sid);
		if (sim->sim_sid == NULL) {
			kmem_free(acl, acl->sl_size);
			acl = NULL;
			break;
		}

		/* Make room for this ACE */
		acl = smb_acl_grow(acl, smb_ace_len(sim->sim_sid));

		status = smb_ace_common_add(acl,
		    zace->a_type,
		    smb_ace_flags_fromzfs(zace->a_flags),
		    zace->a_access_mask,
		    sim->sim_sid);

		if (status == 0) {
			kmem_free(acl, acl->sl_size);
			acl = NULL;
			break;
		}
	}

	smb_idmap_batch_destroy(&sib);
	return (acl);
}

/*
 * SID for Everyone group: S-1-1-0.
 */
nt_sid_t everyone_sid = {
	NT_SID_REVISION,
	1,
	NT_SECURITY_WORLD_AUTH,
	{ 0 }
};

/*
 * smb_acl_null_empty
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
acl_t *
smb_acl_null_empty(int null)
{
	acl_t *zacl;
	ace_t *zace;

	zacl = smb_fsop_aclalloc(1, ACL_AUTO_INHERIT);
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
 * smb_acl_to_zfs
 *
 * Converts given Windows ACL to a ZFS ACL.
 *
 * fs_acl will contain a pointer to the created ZFS ACL.
 * The allocated memory should be freed by calling
 * smb_fsop_aclfree().
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
	int i, isdir;

	ASSERT(fs_acl);
	ASSERT(*fs_acl == NULL);

	if (acl && !smb_acl_isvalid(acl, which_acl))
		return (NT_STATUS_INVALID_ACL);

	if ((acl == NULL) || (acl->sl_acecnt == 0)) {
		if (which_acl == SMB_DACL_SECINFO) {
			*fs_acl = smb_acl_null_empty(acl == NULL);
		}

		return (NT_STATUS_SUCCESS);
	}

	idm_stat = smb_idmap_batch_create(&sib, acl->sl_acecnt,
	    SMB_IDMAP_SID2ID);
	if (idm_stat != IDMAP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	isdir = ((flags & ACL_IS_DIR) == ACL_IS_DIR);

	zacl = smb_fsop_aclalloc(acl->sl_acecnt, flags);

	zace = zacl->acl_aclp;
	sim = sib.sib_maps;

	for (i = 0; ace = smb_ace_get(acl, i); i++, zace++, sim++) {
		zace->a_type = ace->se_header.se_type & ACE_ALL_TYPES;
		zace->a_access_mask = smb_ace_mask_g2s(ace->se_mask);
		zace->a_flags = smb_ace_flags_tozfs(ace->se_header.se_flags,
		    isdir);

		if (nt_sid_is_equal(&ace->se_sid, &everyone_sid))
			zace->a_flags |= ACE_EVERYONE;
		else {
			sim->sim_id = &zace->a_who;
			idm_stat = smb_idmap_batch_getid(sib.sib_idmaph, sim,
			    &ace->se_sid, -1);

			if (idm_stat != IDMAP_SUCCESS) {
				smb_fsop_aclfree(zacl);
				smb_idmap_batch_destroy(&sib);
				return (NT_STATUS_INTERNAL_ERROR);
			}
		}
	}

	idm_stat = smb_idmap_batch_getmappings(&sib);
	if (idm_stat != IDMAP_SUCCESS) {
		smb_fsop_aclfree(zacl);
		smb_idmap_batch_destroy(&sib);
		return (NT_STATUS_NONE_MAPPED);
	}

	/*
	 * Set the ACEs group flag based on the type of ID returned.
	 */
	zace = zacl->acl_aclp;
	sim = sib.sib_maps;
	for (i = 0; i < acl->sl_acecnt; i++, zace++, sim++) {
		if (zace->a_flags & ACE_EVERYONE)
			continue;

		if (sim->sim_idtype == SMB_IDMAP_GROUP)
			zace->a_flags |= ACE_IDENTIFIER_GROUP;
	}

	smb_idmap_batch_destroy(&sib);

	*fs_acl = zacl;
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_acl_inheritable
 *
 * Checks to see if there are any inheritable ACEs in the
 * given ZFS ACL. Returns the number of inheritable ACEs.
 *
 * The inherited ACL could be different based on the type of
 * new object (file/dir) specified by 'is_dir'.
 *
 * Note that the input ACL is a ZFS ACL not Windows ACL.
 *
 * Any ACE except creator owner/group:
 *
 *  FI   DI   NP   #F  #D
 * ---- ---- ---- ---- ----
 *  -    -    ?    0    0
 *  X    -    -    1    1
 *  X    -    X    1    0
 *  -    X    -    0    1
 *  -    X    X    0    1
 *  X    X    -    1    1
 *  X    X    X    1    1
 *
 * Creator owner/group ACE:
 *
 *  FI   DI   NP   #F  #D
 * ---- ---- ---- ---- ----
 *  -    -    ?    0    0
 *  X    -    -    1r   1c
 *  X    -    X    1r   0
 *  -    X    -    0    2
 *  -    X    X    0    1r
 *  X    X    -    1r   2
 *  X    X    X    1r   1r
 *
 * Legend:
 *
 *  FI: File Inherit
 *  DI: Dir Inherit
 *  NP: No Propagate
 *  #F: #ACE for a new file
 *  #D: #ACE for a new dir
 *
 *   X: bit is set
 *   -: bit is not set
 *   ?: don't care
 *
 *  1r: one owner/group ACE
 *  1c: one creator owner/group ACE
 */
static int
smb_acl_inheritable(acl_t *zacl, int is_dir)
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

#define	DEFAULT_DACL_ACENUM	2
/*
 * Default ACL:
 *    owner: full access
 *    SYSTEM: full access
 */
static ace_t default_dacl[DEFAULT_DACL_ACENUM] = {
	{ (uid_t)-1, ACE_ALL_PERMS, 0, ACE_ACCESS_ALLOWED_ACE_TYPE },
	{ IDMAP_WK_LOCAL_SYSTEM_GID, ACE_ALL_PERMS, ACE_IDENTIFIER_GROUP,
	    ACE_ACCESS_ALLOWED_ACE_TYPE }
};

/*
 * smb_acl_inherit
 *
 * Manufacture the inherited ACL from the given ACL considering
 * the new object type (file/dir) specified by 'is_dir'. The
 * returned ACL is used in smb_fsop_create/smb_fsop_mkdir functions.
 * This function implements Windows inheritance rules.
 *
 * Note that the in/our ACLs are ZFS ACLs not Windows ACLs
 */
acl_t *
smb_acl_inherit(acl_t *dir_zacl, int is_dir, int which_acl, uid_t owner_uid)
{
	boolean_t use_default = B_FALSE;
	int num_inheritable = 0;
	int numaces;
	ace_t *dir_zace;
	acl_t *new_zacl;
	ace_t *new_zace;

	num_inheritable = smb_acl_inheritable(dir_zacl, is_dir);

	if (num_inheritable == 0) {
		if (which_acl == SMB_DACL_SECINFO) {
			/* No inheritable access ACEs -> default DACL */
			num_inheritable = DEFAULT_DACL_ACENUM;
			use_default = B_TRUE;
		} else {
			return (NULL);
		}
	}

	new_zacl = smb_fsop_aclalloc(num_inheritable, ACL_AUTO_INHERIT);
	new_zace = new_zacl->acl_aclp;

	if (use_default) {
		bcopy(default_dacl, new_zacl->acl_aclp, sizeof (default_dacl));
		new_zace->a_who = owner_uid;
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
			smb_ace_inherit(dir_zace, new_zace, is_dir);
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
				smb_ace_inherit(dir_zace, new_zace, is_dir);
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

			smb_ace_inherit(dir_zace, new_zace, is_dir);
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

static void
smb_ace_inherit(ace_t *dir_zace, ace_t *zace, int is_dir)
{
	*zace = *dir_zace;
	if (!(is_dir && ZACE_IS_PROPAGATE(dir_zace)))
		zace->a_flags &= ~ACE_INHERIT_FLAGS;
	zace->a_flags |= ACE_INHERITED_ACE;

	/*
	 * Replace creator owner/group ACEs with
	 * actual owner/group ACEs.
	 */
	if (ZACE_IS_CREATOR_OWNER(dir_zace)) {
		zace->a_who = (uid_t)-1;
		zace->a_flags |= ACE_OWNER;
	} else if (ZACE_IS_CREATOR_GROUP(dir_zace)) {
		zace->a_who = (uid_t)-1;
		zace->a_flags |= ACE_GROUP;
	}
}

static uint16_t
smb_ace_flags_tozfs(uint8_t c_flags, int isdir)
{
	uint16_t z_flags = 0;

	if (c_flags & SUCCESSFUL_ACCESS_ACE_FLAG)
		z_flags |= ACE_SUCCESSFUL_ACCESS_ACE_FLAG;

	if (c_flags & FAILED_ACCESS_ACE_FLAG)
		z_flags |= ACE_FAILED_ACCESS_ACE_FLAG;

	if (c_flags & INHERITED_ACE)
		z_flags |= ACE_INHERITED_ACE;

	/*
	 * ZFS doesn't like any inheritance flags to be set on a
	 * file's ACE, only directories. Windows doesn't care.
	 */
	if (isdir)
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

/*
 * This is generic (ACL version 2) vs. object-specific
 * (ACL version 4) ACE types.
 */
int
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
		return (1);

	default:
		break;
	}

	return (0);
}

int
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
		return (1);

	default:
		break;
	}

	return (0);
}

int
smb_ace_is_audit(int type)
{
	switch (type) {
	case ACE_SYSTEM_AUDIT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
		return (1);

	default:
		break;
	}

	return (0);
}
