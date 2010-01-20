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

/*
 * The following naming convention is used in function names.
 *
 * If an argument is one or more aclent_t, we use "aent".
 * If an argument is one or more nfsace4, we use "ace4".
 * If an argument is one or more ace_t, we use "acet".
 *
 * If there is an aggregate of the one above...
 *     If it's contained in a vsecattr_t, we prepend "vs_".
 *     If it's contained in an "array" (pointer) and length, we prepend "ln_".
 *
 * Thus, for example, suppose you have a function that converts an
 * array of aclent_t structures into an array of nfsace4 structures,
 * it's name would be "ln_aent_to_ace4".
 */

#include <sys/acl.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/sdt.h>

#define	ACE4_POSIX_SUPPORTED_BITS (ACE4_READ_DATA | \
    ACE4_WRITE_DATA | \
    ACE4_APPEND_DATA | \
    ACE4_EXECUTE | \
    ACE4_READ_ATTRIBUTES | \
    ACE4_READ_ACL | \
    ACE4_WRITE_ACL)

static int ace4vals_compare(const void *, const void *);
static int nfs4_ace4_list_construct(void *, void *, int);
static void nfs4_ace4_list_destroy(void *, void *);
static void ace4_list_free(ace4_list_t *);
static void ace4vals_init(ace4vals_t *, utf8string *);
static void ace4_list_init(ace4_list_t *, int);
static int ln_aent_preprocess(aclent_t *, int,
    int *, o_mode_t *, int *, int *, int *);
static void ace4_make_deny(nfsace4 *, nfsace4 *, int, int, int);
static acemask4 mode_to_ace4_access(o_mode_t, int, int, int, int);
static int ln_aent_to_ace4(aclent_t *, int, nfsace4 **, int *, int, int);
static int ace4_mask_to_mode(acemask4, o_mode_t *, int);
static int ace4_allow_to_mode(acemask4, o_mode_t *, int);
static ace4vals_t *ace4vals_find(nfsace4 *, avl_tree_t *, int *);
static int ace4_to_aent_legal(nfsace4 *, int);
static int ace4vals_to_aent(ace4vals_t *, aclent_t *, ace4_list_t *,
    uid_t, gid_t, int, int);
static int ace4_list_to_aent(ace4_list_t *, aclent_t **, int *, uid_t, gid_t,
    int, int);
static int ln_ace4_to_aent(nfsace4 *ace4, int n, uid_t, gid_t,
    aclent_t **, int *, aclent_t **, int *, int, int);
static int ace4_cmp(nfsace4 *, nfsace4 *);
static int acet_to_ace4(ace_t *, nfsace4 *, int);
static int ace4_to_acet(nfsace4 *, ace_t *, uid_t, gid_t, int);
static int validate_idmapping(utf8string *, uid_t *, int, int);
static int u8s_mapped_to_nobody(utf8string *, uid_t, int);
static void remap_id(uid_t *, int);
static void ace4_mask_to_acet_mask(acemask4, uint32_t *);
static void acet_mask_to_ace4_mask(uint32_t, acemask4 *);
static void ace4_flags_to_acet_flags(aceflag4, uint16_t *);
static void acet_flags_to_ace4_flags(uint16_t, aceflag4 *);

/*
 * The following two functions check and set ACE4_SYNCRONIZE, ACE4_WRITE_OWNER,
 * ACE4_DELETE and ACE4_WRITE_ATTRIBUTES.
 */
static int access_mask_check(nfsace4 *, int, int, int);
static acemask4 access_mask_set(int, int, int, int, int);

static int nfs4_acl_debug = 0;

#define	ACL_SYNCHRONIZE_SET_DENY		0x0000001
#define	ACL_SYNCHRONIZE_SET_ALLOW		0x0000002
#define	ACL_SYNCHRONIZE_ERR_DENY		0x0000004
#define	ACL_SYNCHRONIZE_ERR_ALLOW		0x0000008

#define	ACL_WRITE_OWNER_SET_DENY		0x0000010
#define	ACL_WRITE_OWNER_SET_ALLOW		0x0000020
#define	ACL_WRITE_OWNER_ERR_DENY		0x0000040
#define	ACL_WRITE_OWNER_ERR_ALLOW		0x0000080

#define	ACL_DELETE_SET_DENY			0x0000100
#define	ACL_DELETE_SET_ALLOW			0x0000200
#define	ACL_DELETE_ERR_DENY			0x0000400
#define	ACL_DELETE_ERR_ALLOW			0x0000800

#define	ACL_WRITE_ATTRS_OWNER_SET_DENY		0x0001000
#define	ACL_WRITE_ATTRS_OWNER_SET_ALLOW		0x0002000
#define	ACL_WRITE_ATTRS_OWNER_ERR_DENY		0x0004000
#define	ACL_WRITE_ATTRS_OWNER_ERR_ALLOW		0x0008000

#define	ACL_WRITE_ATTRS_WRITER_SET_DENY		0x0010000
#define	ACL_WRITE_ATTRS_WRITER_SET_ALLOW	0x0020000
#define	ACL_WRITE_ATTRS_WRITER_ERR_DENY		0x0040000
#define	ACL_WRITE_ATTRS_WRITER_ERR_ALLOW	0x0080000

#define	ACL_WRITE_NAMED_WRITER_SET_DENY		0x0100000
#define	ACL_WRITE_NAMED_WRITER_SET_ALLOW	0x0200000
#define	ACL_WRITE_NAMED_WRITER_ERR_DENY		0x0400000
#define	ACL_WRITE_NAMED_WRITER_ERR_ALLOW	0x0800000

#define	ACL_READ_NAMED_READER_SET_DENY		0x1000000
#define	ACL_READ_NAMED_READER_SET_ALLOW		0x2000000
#define	ACL_READ_NAMED_READER_ERR_DENY		0x4000000
#define	ACL_READ_NAMED_READER_ERR_ALLOW		0x8000000

/*
 * What we will send the server upon setting an ACL on our client
 */
static int nfs4_acl_client_produce =
	(ACL_SYNCHRONIZE_SET_ALLOW |
	ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	ACL_WRITE_ATTRS_WRITER_SET_DENY);

/*
 * What we will accept upon getting an ACL on our client
 */
static int nfs4_acl_client_consume =
	(ACL_WRITE_OWNER_ERR_DENY |
	ACL_WRITE_OWNER_ERR_ALLOW |
	ACL_WRITE_ATTRS_OWNER_ERR_DENY |
	ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	ACL_WRITE_ATTRS_WRITER_ERR_ALLOW |
	ACL_WRITE_ATTRS_WRITER_SET_DENY);

/*
 * What we will produce as an ACL on a newly created file
 */
static int nfs4_acl_server_produce =
	(ACL_SYNCHRONIZE_SET_ALLOW |
	ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	ACL_WRITE_ATTRS_WRITER_SET_DENY);

/*
 * What we will accept upon setting an ACL on our server
 */
static int nfs4_acl_server_consume =
	(ACL_SYNCHRONIZE_ERR_DENY |
	ACL_DELETE_ERR_DENY |
	ACL_WRITE_OWNER_ERR_DENY |
	ACL_WRITE_OWNER_ERR_ALLOW |
	ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	ACL_WRITE_ATTRS_OWNER_ERR_DENY |
	ACL_WRITE_ATTRS_WRITER_SET_DENY |
	ACL_WRITE_ATTRS_WRITER_ERR_ALLOW |
	ACL_WRITE_NAMED_WRITER_ERR_DENY |
	ACL_READ_NAMED_READER_ERR_DENY);

static kmem_cache_t *nfs4_ace4vals_cache = NULL;
static kmem_cache_t *nfs4_ace4_list_cache = NULL;

static int
ace4vals_compare(const void *va, const void *vb)
{
	const ace4vals_t *a = va, *b = vb;

	if ((a->key == NULL) && (b->key == NULL))
		return (0);
	else if (a->key == NULL)
		return (-1);
	else if (b->key == NULL)
		return (1);

	return (utf8_compare(a->key, b->key));
}

/*ARGSUSED*/
static int
nfs4_ace4_list_construct(void *voidp, void *arg, int kmem_flags)
{
	ace4_list_t *a4l = voidp;

	avl_create(&a4l->user, ace4vals_compare, sizeof (ace4vals_t),
	    offsetof(ace4vals_t, avl));
	avl_create(&a4l->group, ace4vals_compare, sizeof (ace4vals_t),
	    offsetof(ace4vals_t, avl));
	return (0);
}

/*ARGSUSED*/
static void
nfs4_ace4_list_destroy(void *voidp, void *arg)
{
	ace4_list_t *a4l = voidp;

	avl_destroy(&a4l->user);
	avl_destroy(&a4l->group);
}

void
nfs4_acl_init(void)
{
	nfs4_ace4vals_cache = kmem_cache_create("nfs4_ace4vals_cache",
	    sizeof (ace4vals_t), 0,
	    NULL, NULL,
	    NULL, NULL,
	    NULL,
	    0);
	nfs4_ace4_list_cache = kmem_cache_create("nfs4_ace4_list_cache",
	    sizeof (ace4_list_t), 0,
	    nfs4_ace4_list_construct, nfs4_ace4_list_destroy,
	    NULL, NULL,
	    NULL,
	    0);
}

void
vs_acet_destroy(vsecattr_t *vsp)
{
	if (vsp->vsa_mask != (VSA_ACE | VSA_ACECNT))
		return;

	if ((vsp->vsa_aclentp != NULL) &&
	    (vsp->vsa_aclcnt > 0) &&
	    (vsp->vsa_mask & VSA_ACE) &&
	    (vsp->vsa_mask & VSA_ACECNT))
		kmem_free(vsp->vsa_aclentp,
		    vsp->vsa_aclcnt * sizeof (ace_t));

	vsp->vsa_aclentp = NULL;
	vsp->vsa_aclcnt = 0;
}

void
vs_ace4_destroy(vsecattr_t *vsp)
{
	nfsace4 *ace4;
	int i;

	if (vsp->vsa_mask != (VSA_ACE | VSA_ACECNT))
		return;

	if ((vsp->vsa_aclentp != NULL) &&
	    (vsp->vsa_aclcnt > 0) &&
	    (vsp->vsa_mask & VSA_ACE) &&
	    (vsp->vsa_mask & VSA_ACECNT)) {
		for (i = 0; i < vsp->vsa_aclcnt; i++) {
			ace4 = (nfsace4 *)vsp->vsa_aclentp + i;
			if ((ace4->who.utf8string_len > 0) &&
			    (ace4->who.utf8string_val != NULL))
				kmem_free(ace4->who.utf8string_val,
				    ace4->who.utf8string_len);

			ace4->who.utf8string_val = NULL;
			ace4->who.utf8string_len = 0;
		}

		kmem_free(vsp->vsa_aclentp,
		    vsp->vsa_aclcnt * sizeof (nfsace4));
	}

	vsp->vsa_aclentp = NULL;
	vsp->vsa_aclcnt = 0;
}

void
vs_aent_destroy(vsecattr_t *vsp)
{
	if (vsp->vsa_mask & (VSA_ACE | VSA_ACECNT))
		return;

	if ((vsp->vsa_aclentp != NULL) &&
	    (vsp->vsa_aclcnt > 0) &&
	    (vsp->vsa_mask & VSA_ACL) &&
	    (vsp->vsa_mask & VSA_ACLCNT))
		kmem_free(vsp->vsa_aclentp,
		    vsp->vsa_aclcnt * sizeof (aclent_t));
	if ((vsp->vsa_dfaclentp != NULL) &&
	    (vsp->vsa_dfaclcnt > 0) &&
	    (vsp->vsa_mask & VSA_DFACL) &&
	    (vsp->vsa_mask & VSA_DFACLCNT))
		kmem_free(vsp->vsa_dfaclentp,
		    vsp->vsa_dfaclcnt * sizeof (aclent_t));

	vsp->vsa_aclentp = NULL;
	vsp->vsa_aclcnt = 0;

	vsp->vsa_dfaclentp = NULL;
	vsp->vsa_aclcnt = 0;
}

/*
 * free all data associated with an ace4_list
 */
static void
ace4_list_free(ace4_list_t *a4l)
{
	ace4vals_t *node;
	void *cookie;

	if (a4l == NULL)
		return;

	/* free all nodes, but don't destroy the trees themselves */
	cookie = NULL;
	while ((node = avl_destroy_nodes(&a4l->user, &cookie)) != NULL)
		kmem_cache_free(nfs4_ace4vals_cache, node);
	cookie = NULL;
	while ((node = avl_destroy_nodes(&a4l->group, &cookie)) != NULL)
		kmem_cache_free(nfs4_ace4vals_cache, node);

	/* free the container itself */
	kmem_cache_free(nfs4_ace4_list_cache, a4l);
}

static void
ace4vals_init(ace4vals_t *vals, utf8string *key)
{
	bzero(vals, sizeof (*vals));
	vals->allowed = ACE4_MASK_UNDEFINED;
	vals->denied = ACE4_MASK_UNDEFINED;
	vals->mask = ACE4_MASK_UNDEFINED;
	vals->key = key;
}

static void
ace4_list_init(ace4_list_t *a4l, int dfacl_flag)
{
	ace4vals_init(&a4l->user_obj, NULL);
	ace4vals_init(&a4l->group_obj, NULL);
	ace4vals_init(&a4l->other_obj, NULL);
	a4l->numusers = 0;
	a4l->numgroups = 0;
	a4l->acl_mask = 0;
	a4l->hasmask = 0;
	a4l->state = ace4_unused;
	a4l->seen = 0;
	a4l->dfacl_flag = dfacl_flag;
}

/*
 * Make an initial pass over an array of aclent_t's.  Gather
 * information such as an ACL_MASK (if any), number of users,
 * number of groups, and whether the array needs to be sorted.
 */
static int
ln_aent_preprocess(aclent_t *aclent, int n,
    int *hasmask, o_mode_t *mask,
    int *numuser, int *numgroup, int *needsort)
{
	int error = 0;
	int i;
	int curtype = 0;

	*hasmask = 0;
	*mask = 07;
	*needsort = 0;
	*numuser = 0;
	*numgroup = 0;

	for (i = 0; i < n; i++) {
		if (aclent[i].a_type < curtype)
			*needsort = 1;
		else if (aclent[i].a_type > curtype)
			curtype = aclent[i].a_type;
		if (aclent[i].a_type & USER)
			(*numuser)++;
		if (aclent[i].a_type & (GROUP | GROUP_OBJ))
			(*numgroup)++;
		if (aclent[i].a_type & CLASS_OBJ) {
			if (*hasmask) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_aent_preprocess: multiple CLASS_OBJs "
				    "(masks) found"));
				error = EINVAL;
				goto out;
			} else {
				*hasmask = 1;
				*mask = aclent[i].a_perm;
			}
		}
	}

	if ((! *hasmask) && (*numuser + *numgroup > 1)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ln_aent_preprocess: no CLASS_OBJs "
		    "(masks) found"));
		error = EINVAL;
		goto out;
	}

out:
	return (error);
}

static acemask4
access_mask_set(int haswriteperm, int hasreadperm, int isowner, int isallow,
    int isserver)
{
	acemask4 access_mask = 0;
	int nfs4_acl_produce;
	int synchronize_set = 0, write_owner_set = 0;
	int delete_set = 0, write_attrs_set = 0;
	int read_named_set = 0, write_named_set = 0;

	if (isserver)
		nfs4_acl_produce = nfs4_acl_server_produce;
	else
		nfs4_acl_produce = nfs4_acl_client_produce;

	if (isallow) {
		synchronize_set = ACL_SYNCHRONIZE_SET_ALLOW;
		write_owner_set = ACL_WRITE_OWNER_SET_ALLOW;
		delete_set = ACL_DELETE_SET_ALLOW;
		if (hasreadperm)
			read_named_set = ACL_READ_NAMED_READER_SET_ALLOW;
		if (haswriteperm)
			write_named_set = ACL_WRITE_NAMED_WRITER_SET_ALLOW;
		if (isowner)
			write_attrs_set = ACL_WRITE_ATTRS_OWNER_SET_ALLOW;
		else if (haswriteperm)
			write_attrs_set = ACL_WRITE_ATTRS_WRITER_SET_ALLOW;
	} else {
		synchronize_set = ACL_SYNCHRONIZE_SET_DENY;
		write_owner_set = ACL_WRITE_OWNER_SET_DENY;
		delete_set = ACL_DELETE_SET_DENY;
		if (hasreadperm)
			read_named_set = ACL_READ_NAMED_READER_SET_DENY;
		if (haswriteperm)
			write_named_set = ACL_WRITE_NAMED_WRITER_SET_DENY;
		if (isowner)
			write_attrs_set = ACL_WRITE_ATTRS_OWNER_SET_DENY;
		else if (haswriteperm)
			write_attrs_set = ACL_WRITE_ATTRS_WRITER_SET_DENY;
		else
			/*
			 * If the entity is not the owner and does not
			 * have write permissions ACE4_WRITE_ATTRIBUTES will
			 * always go in the DENY ACE.
			 */
			access_mask |= ACE4_WRITE_ATTRIBUTES;
	}

	if (nfs4_acl_produce & synchronize_set)
		access_mask |= ACE4_SYNCHRONIZE;
	if (nfs4_acl_produce & write_owner_set)
		access_mask |= ACE4_WRITE_OWNER;
	if (nfs4_acl_produce & delete_set)
		access_mask |= ACE4_DELETE;
	if (nfs4_acl_produce & write_attrs_set)
		access_mask |= ACE4_WRITE_ATTRIBUTES;
	if (nfs4_acl_produce & read_named_set)
		access_mask |= ACE4_READ_NAMED_ATTRS;
	if (nfs4_acl_produce & write_named_set)
		access_mask |= ACE4_WRITE_NAMED_ATTRS;

	return (access_mask);
}

/*
 * Given an nfsace4 (presumably an ALLOW entry), make a
 * corresponding DENY entry at the address given.
 */
static void
ace4_make_deny(nfsace4 *allow, nfsace4 *deny, int isdir, int isowner,
    int isserver)
{
	bcopy(allow, deny, sizeof (nfsace4));

	(void) utf8_copy(&allow->who, &deny->who);

	deny->type = ACE4_ACCESS_DENIED_ACE_TYPE;
	deny->access_mask ^= ACE4_POSIX_SUPPORTED_BITS;
	if (isdir)
		deny->access_mask ^= ACE4_DELETE_CHILD;

	deny->access_mask &= ~(ACE4_SYNCHRONIZE | ACE4_WRITE_OWNER |
	    ACE4_DELETE | ACE4_WRITE_ATTRIBUTES | ACE4_READ_NAMED_ATTRS |
	    ACE4_WRITE_NAMED_ATTRS);
	deny->access_mask |= access_mask_set((allow->access_mask &
	    ACE4_WRITE_DATA), (allow->access_mask & ACE4_READ_DATA), isowner,
	    FALSE, isserver);
}

/*
 * Given an o_mode_t, convert it into an access_mask as used
 * by nfsace4, assuming aclent_t -> nfsace4 semantics.
 */
static acemask4
mode_to_ace4_access(o_mode_t mode, int isdir, int isowner, int isallow,
    int isserver)
{
	acemask4 access = 0;
	int haswriteperm = 0;
	int hasreadperm = 0;

	if (isallow) {
		haswriteperm = (mode & 02);
		hasreadperm = (mode & 04);
	} else {
		haswriteperm = !(mode & 02);
		hasreadperm = !(mode & 04);
	}

	/*
	 * The following call takes care of correctly setting the following
	 * mask bits in the access_mask:
	 * ACE4_SYNCHRONIZE, ACE4_WRITE_OWNER, ACE4_DELETE,
	 * ACE4_WRITE_ATTRIBUTES, ACE4_WRITE_NAMED_ATTRS, ACE4_READ_NAMED_ATTRS
	 */
	access = access_mask_set(haswriteperm, hasreadperm, isowner, isallow,
	    isserver);

	if (isallow) {
		access |= ACE4_READ_ACL | ACE4_READ_ATTRIBUTES;
		if (isowner)
			access |= ACE4_WRITE_ACL;
	} else {
		if (! isowner)
			access |= ACE4_WRITE_ACL;
	}

	/* read */
	if (mode & 04) {
		access |= ACE4_READ_DATA;
	}
	/* write */
	if (mode & 02) {
		access |= ACE4_WRITE_DATA |
		    ACE4_APPEND_DATA;
		if (isdir)
			access |= ACE4_DELETE_CHILD;
	}
	/* exec */
	if (mode & 01) {
		access |= ACE4_EXECUTE;
	}

	return (access);
}

/*
 * Convert an array of aclent_t into an array of nfsace4 entries,
 * following POSIX draft -> nfsv4 conversion semantics as outlined in
 * the IETF draft.
 */
static int
ln_aent_to_ace4(aclent_t *aclent, int n, nfsace4 **acepp, int *rescount,
    int isdir, int isserver)
{
	int error = 0;
	o_mode_t mask;
	int numuser, numgroup, needsort;
	int resultsize = 0;
	int i, groupi = 0, skip;
	nfsace4 *acep, *result = NULL;
	int hasmask;

	error = ln_aent_preprocess(aclent, n, &hasmask, &mask,
	    &numuser, &numgroup, &needsort);
	if (error != 0)
		goto out;

	/* allow + deny for each aclent */
	resultsize = n * 2;
	if (hasmask) {
		/*
		 * stick extra deny on the group_obj and on each
		 * user|group for the mask (the group_obj was added
		 * into the count for numgroup)
		 */
		resultsize += numuser + numgroup;
		/* ... and don't count the mask itself */
		resultsize -= 2;
	}

	/* sort the source if necessary */
	if (needsort)
		ksort((caddr_t)aclent, n, sizeof (aclent_t), cmp2acls);

	result = acep = kmem_zalloc(resultsize * sizeof (nfsace4), KM_SLEEP);

	for (i = 0; i < n; i++) {
		/*
		 * don't process CLASS_OBJ (mask); mask was grabbed in
		 * ln_aent_preprocess()
		 */
		if (aclent[i].a_type & CLASS_OBJ)
			continue;

		/* If we need an ACL_MASK emulator, prepend it now */
		if ((hasmask) &&
		    (aclent[i].a_type & (USER | GROUP | GROUP_OBJ))) {
			acep->type = ACE4_ACCESS_DENIED_ACE_TYPE;
			acep->flag = 0;
			if (aclent[i].a_type & GROUP_OBJ) {
				(void) str_to_utf8(ACE4_WHO_GROUP, &acep->who);
				acep->flag |= ACE4_IDENTIFIER_GROUP;
				error = 0;
			} else if (aclent[i].a_type & USER) {
				/*
				 * On the client, we do not allow an ACL with
				 * ACEs containing the UID_UNKNOWN user to be
				 * set.  This is because having UID_UNKNOWN in
				 * an ACE can only come from the user having
				 * done a read-modify-write ACL manipulation
				 * (e.g. setfacl -m or chmod A+) when there
				 * was an ACE with an unmappable group already
				 * present.
				 */
				if (aclent[i].a_id == UID_UNKNOWN &&
				    !isserver) {
					DTRACE_PROBE(
					    nfs4clnt__err__acl__uid__unknown);
					NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
					    "ln_aent_to_ace4: UID_UNKNOWN is "
					    "not allowed in the ACL"));
					error = EACCES;
					goto out;
				}

				error = nfs_idmap_uid_str(aclent[i].a_id,
				    &acep->who, isserver);
			} else {
				/*
				 * Same rule as UID_UNKNOWN (above).
				 */
				if (aclent[i].a_id == GID_UNKNOWN &&
				    !isserver) {
					DTRACE_PROBE(
					    nfs4clnt__err__acl__gid__unknown);
					NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
					    "ln_aent_to_ace4: GID_UNKNOWN is "
					    "not allowed in the ACL"));
					error = EACCES;
					goto out;
				}

				error = nfs_idmap_gid_str(aclent[i].a_id,
				    &acep->who, isserver);
				acep->flag |= ACE4_IDENTIFIER_GROUP;
			}
			if (error != 0) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_aent_to_ace4: idmap translate "
				    "failed with %d", error));
				goto out;
			}
			if (aclent[i].a_type & ACL_DEFAULT) {
				acep->flag |= ACE4_INHERIT_ONLY_ACE |
				    ACE4_FILE_INHERIT_ACE |
				    ACE4_DIRECTORY_INHERIT_ACE;
			}
			/*
			 * Set the access mask for the prepended deny
			 * ace.  To do this, we invert the mask (found
			 * in ln_aent_preprocess()) then convert it to an
			 * DENY ace access_mask.
			 */
			acep->access_mask = mode_to_ace4_access((mask ^ 07),
			    isdir, 0, 0, isserver);
			acep += 1;
		}

		/* handle a_perm -> access_mask */
		acep->access_mask = mode_to_ace4_access(aclent[i].a_perm,
		    isdir, aclent[i].a_type & USER_OBJ, 1, isserver);

		/* emulate a default aclent */
		if (aclent[i].a_type & ACL_DEFAULT) {
			acep->flag |= ACE4_INHERIT_ONLY_ACE |
			    ACE4_FILE_INHERIT_ACE |
			    ACE4_DIRECTORY_INHERIT_ACE;
		}

		/*
		 * handle a_perm and a_id
		 *
		 * this must be done last, since it involves the
		 * corresponding deny aces, which are handled
		 * differently for each different a_type.
		 */
		if (aclent[i].a_type & USER_OBJ) {
			(void) str_to_utf8(ACE4_WHO_OWNER, &acep->who);
			ace4_make_deny(acep, acep + 1, isdir, TRUE, isserver);
			acep += 2;
		} else if (aclent[i].a_type & USER) {
			error = nfs_idmap_uid_str(aclent[i].a_id, &acep->who,
			    isserver);
			if (error != 0) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_aent_to_ace4: uid idmap failed "
				    "with error %d", error));
				goto out;
			}
			ace4_make_deny(acep, acep + 1, isdir, FALSE, isserver);
			acep += 2;
		} else if (aclent[i].a_type & (GROUP_OBJ | GROUP)) {
			if (aclent[i].a_type & GROUP_OBJ) {
				(void) str_to_utf8(ACE4_WHO_GROUP, &acep->who);
				error = 0;
			} else {
				error = nfs_idmap_gid_str(aclent[i].a_id,
				    &acep->who, isserver);
			}
			if (error != 0) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_aent_to_ace4: gid idmap failed "
				    "with error %d", error));
				goto out;
			}
			acep->flag |= ACE4_IDENTIFIER_GROUP;
			/*
			 * Set the corresponding deny for the group ace.
			 *
			 * The deny aces go after all of the groups, unlike
			 * everything else, where they immediately follow
			 * the allow ace.
			 *
			 * We calculate "skip", the number of slots to
			 * skip ahead for the deny ace, here.
			 *
			 * The pattern is:
			 * MD1 A1 MD2 A2 MD3 A3 D1 D2 D3
			 * thus, skip is
			 * (2 * numgroup) - 1 - groupi
			 * (2 * numgroup) to account for MD + A
			 * - 1 to account for the fact that we're on the
			 * access (A), not the mask (MD)
			 * - groupi to account for the fact that we have
			 * passed up groupi number of MD's.
			 */
			skip = (2 * numgroup) - 1 - groupi;
			ace4_make_deny(acep, acep + skip, isdir, FALSE,
			    isserver);
			/*
			 * If we just did the last group, skip acep past
			 * all of the denies; else, just move ahead one.
			 */
			if (++groupi >= numgroup)
				acep += numgroup + 1;
			else
				acep += 1;
		} else if (aclent[i].a_type & OTHER_OBJ) {
			(void) str_to_utf8(ACE4_WHO_EVERYONE, &acep->who);
			ace4_make_deny(acep, acep + 1, isdir, FALSE, isserver);
			acep += 2;
		} else {
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "ln_aent_to_ace4: aclent_t with invalid type: %x",
			    aclent[i].a_type));
			error = EINVAL;
			goto out;
		}
	}

	*acepp = result;
	*rescount = resultsize;

out:

	if (error != 0) {
		if ((result != NULL) && (resultsize > 0)) {
			/* free any embedded "who" strings */
			for (i = 0; i < resultsize; i++) {
				acep = result + i;
				if ((acep->who.utf8string_len > 0) &&
				    (acep->who.utf8string_val != NULL)) {
					kmem_free(acep->who.utf8string_val,
					    acep->who.utf8string_len);
				}
			}

			/* free the nfsace4 block */
			kmem_free(result, resultsize * sizeof (nfsace4));
		}
	}

	return (error);
}

/*
 * Convert a POSIX draft ACL (in a vsecattr_t) to an NFSv4 ACL, following
 * the semantics of the IETF draft, draft-ietf-nfsv4-acl-mapping-01.txt.
 */
int
vs_aent_to_ace4(vsecattr_t *aclentacl, vsecattr_t *vs_ace4,
    int isdir, int isserver)
{
	int error = 0;
	nfsace4 *acebuf = NULL;
	int acecnt = 0;
	nfsace4 *dfacebuf = NULL;
	int dfacecnt = 0;

	/* initialize vs_ace4 in case we can't complete our work */
	vs_ace4->vsa_mask = 0;
	vs_ace4->vsa_aclentp = NULL;
	vs_ace4->vsa_aclcnt = 0;
	vs_ace4->vsa_dfaclentp = NULL;
	vs_ace4->vsa_dfaclcnt = 0;
	vs_ace4->vsa_aclentsz = 0;

	if (! (aclentacl->vsa_mask & (VSA_ACL | VSA_ACLCNT |
	    VSA_DFACL | VSA_DFACLCNT))) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "vs_aent_to_ace4: vsa_mask lacking proper mask"));
		error = EINVAL;
		goto out;
	}

	if ((aclentacl->vsa_aclcnt < 3) &&
	    (aclentacl->vsa_mask & (VSA_ACL | VSA_ACLCNT))) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "vs_aent_to_ace4: too small vsa_aclcnt, %d",
		    aclentacl->vsa_aclcnt));
		error = EINVAL;
		goto out;
	}

	if ((aclentacl->vsa_dfaclcnt != 0) && (aclentacl->vsa_dfaclcnt < 3) &&
	    (aclentacl->vsa_mask & (VSA_DFACL | VSA_DFACLCNT))) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "vs_aent_to_ace4: too small vsa_dfaclcnt, %d",
		    aclentacl->vsa_dfaclcnt));
		error = EINVAL;
		goto out;
	}

	if (aclentacl->vsa_aclcnt > 0) {
		error = ln_aent_to_ace4(aclentacl->vsa_aclentp,
		    aclentacl->vsa_aclcnt, &acebuf, &acecnt, isdir, isserver);
		if (error != 0)
			goto out;
	}
	if (aclentacl->vsa_dfaclcnt > 0) {
		error = ln_aent_to_ace4(aclentacl->vsa_dfaclentp,
		    aclentacl->vsa_dfaclcnt, &dfacebuf, &dfacecnt, isdir,
		    isserver);
		if (error != 0)
			goto out;
	}

	vs_ace4->vsa_aclcnt = acecnt + dfacecnt;
	/* on error, this is freed by vs_ace4_destroy() */
	if (vs_ace4->vsa_aclcnt > 0)
		vs_ace4->vsa_aclentp = kmem_zalloc(vs_ace4->vsa_aclcnt *
		    sizeof (nfsace4), KM_SLEEP);
	/*
	 * When we bcopy the nfsace4's, the result (in vsa_aclentp)
	 * will have its "who.utf8string_val" pointer pointing to the
	 * allocated strings.  Thus, when we free acebuf and dbacebuf,
	 * we don't need to free these strings.
	 */
	if (acecnt > 0)
		bcopy(acebuf, vs_ace4->vsa_aclentp, acecnt * sizeof (nfsace4));
	if (dfacecnt > 0)
		bcopy(dfacebuf, (nfsace4 *) vs_ace4->vsa_aclentp + acecnt,
		    dfacecnt * sizeof (nfsace4));
	vs_ace4->vsa_mask = VSA_ACE | VSA_ACECNT;

out:
	if (error != 0)
		vs_ace4_destroy(vs_ace4);

	if (acebuf != NULL)
		kmem_free(acebuf, acecnt * sizeof (nfsace4));
	if (dfacebuf != NULL)
		kmem_free(dfacebuf, dfacecnt * sizeof (nfsace4));

	return (error);
}

static int
ace4_mask_to_mode(acemask4 mask, o_mode_t *modep, int isdir)
{
	int error = 0;
	o_mode_t mode = 0;
	acemask4 bits, wantbits;

	/* read */
	if (mask & ACE4_READ_DATA)
		mode |= 04;

	/* write */
	wantbits = (ACE4_WRITE_DATA |
	    ACE4_APPEND_DATA);
	if (isdir)
		wantbits |= ACE4_DELETE_CHILD;
	bits = mask & wantbits;
	if (bits != 0) {
		if (bits != wantbits) {
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "ace4_mask_to_mode: bad subset of write flags "
			    "%x", bits));
			error = ENOTSUP;
			goto out;
		}
		mode |= 02;
	}

	/* exec */
	if (mask & ACE4_EXECUTE) {
		mode |= 01;
	}

	*modep = mode;

out:
	return (error);
}

static int
ace4_allow_to_mode(acemask4 mask, o_mode_t *modep, int isdir)
{
	/* ACE4_READ_ACL and ACE4_READ_ATTRIBUTES must both be set */
	if ((mask & (ACE4_READ_ACL | ACE4_READ_ATTRIBUTES)) !=
	    (ACE4_READ_ACL | ACE4_READ_ATTRIBUTES)) {
		return (ENOTSUP);
	}

	return (ace4_mask_to_mode(mask, modep, isdir));
}

/*
 * Find or create an ace4vals holder for a given id and avl tree.
 *
 * Note that only one thread will ever touch these avl trees, so
 * there is no need for locking.
 */
static ace4vals_t *
ace4vals_find(nfsace4 *ace4, avl_tree_t *avl, int *num)
{
	ace4vals_t key, *rc;
	avl_index_t where;

	key.key = &ace4->who;
	rc = avl_find(avl, &key, &where);
	if (rc != NULL)
		return (rc);

	/* this memory is freed by ln_ace4_to_aent()->ace4_list_free() */
	rc = kmem_cache_alloc(nfs4_ace4vals_cache, KM_SLEEP);
	ace4vals_init(rc, &ace4->who);
	avl_insert(avl, rc, where);
	(*num)++;

	return (rc);
}

static int
access_mask_check(nfsace4 *ace4p, int mask_bit, int isserver, int isowner)
{
	int set_deny, err_deny;
	int set_allow, err_allow;
	int nfs4_acl_consume;
	int haswriteperm, hasreadperm;

	if (ace4p->type == ACE4_ACCESS_DENIED_ACE_TYPE) {
		haswriteperm = (ace4p->access_mask & ACE4_WRITE_DATA) ? 0 : 1;
		hasreadperm = (ace4p->access_mask & ACE4_READ_DATA) ? 0 : 1;
	} else {
		haswriteperm = (ace4p->access_mask & ACE4_WRITE_DATA) ? 1 : 0;
		hasreadperm = (ace4p->access_mask & ACE4_READ_DATA) ? 1 : 0;
	}

	if (isserver)
		nfs4_acl_consume = nfs4_acl_server_consume;
	else
		nfs4_acl_consume = nfs4_acl_client_consume;

	if (mask_bit == ACE4_SYNCHRONIZE) {
		set_deny = ACL_SYNCHRONIZE_SET_DENY;
		err_deny =  ACL_SYNCHRONIZE_ERR_DENY;
		set_allow = ACL_SYNCHRONIZE_SET_ALLOW;
		err_allow = ACL_SYNCHRONIZE_ERR_ALLOW;
	} else if (mask_bit == ACE4_WRITE_OWNER) {
		set_deny = ACL_WRITE_OWNER_SET_DENY;
		err_deny =  ACL_WRITE_OWNER_ERR_DENY;
		set_allow = ACL_WRITE_OWNER_SET_ALLOW;
		err_allow = ACL_WRITE_OWNER_ERR_ALLOW;
	} else if (mask_bit == ACE4_DELETE) {
		set_deny = ACL_DELETE_SET_DENY;
		err_deny =  ACL_DELETE_ERR_DENY;
		set_allow = ACL_DELETE_SET_ALLOW;
		err_allow = ACL_DELETE_ERR_ALLOW;
	} else if (mask_bit == ACE4_WRITE_ATTRIBUTES) {
		if (isowner) {
			set_deny = ACL_WRITE_ATTRS_OWNER_SET_DENY;
			err_deny =  ACL_WRITE_ATTRS_OWNER_ERR_DENY;
			set_allow = ACL_WRITE_ATTRS_OWNER_SET_ALLOW;
			err_allow = ACL_WRITE_ATTRS_OWNER_ERR_ALLOW;
		} else if (haswriteperm) {
			set_deny = ACL_WRITE_ATTRS_WRITER_SET_DENY;
			err_deny =  ACL_WRITE_ATTRS_WRITER_ERR_DENY;
			set_allow = ACL_WRITE_ATTRS_WRITER_SET_ALLOW;
			err_allow = ACL_WRITE_ATTRS_WRITER_ERR_ALLOW;
		} else {
			if ((ace4p->access_mask & mask_bit) &&
			    (ace4p->type & ACE4_ACCESS_ALLOWED_ACE_TYPE)) {
				return (ENOTSUP);
			}
			return (0);
		}
	} else if (mask_bit == ACE4_READ_NAMED_ATTRS) {
		if (!hasreadperm)
			return (0);

		set_deny = ACL_READ_NAMED_READER_SET_DENY;
		err_deny = ACL_READ_NAMED_READER_ERR_DENY;
		set_allow = ACL_READ_NAMED_READER_SET_ALLOW;
		err_allow = ACL_READ_NAMED_READER_ERR_ALLOW;
	} else if (mask_bit == ACE4_WRITE_NAMED_ATTRS) {
		if (!haswriteperm)
			return (0);

		set_deny = ACL_WRITE_NAMED_WRITER_SET_DENY;
		err_deny = ACL_WRITE_NAMED_WRITER_ERR_DENY;
		set_allow = ACL_WRITE_NAMED_WRITER_SET_ALLOW;
		err_allow = ACL_WRITE_NAMED_WRITER_ERR_ALLOW;
	} else
		return (EINVAL);

	if (ace4p->type == ACE4_ACCESS_DENIED_ACE_TYPE) {
		if (nfs4_acl_consume & set_deny) {
			if (!(ace4p->access_mask & mask_bit)) {
				return (ENOTSUP);
			}
		} else if (nfs4_acl_consume & err_deny) {
			if (ace4p->access_mask & mask_bit) {
				return (ENOTSUP);
			}
		}
	} else {
		/* ACE4_ACCESS_ALLOWED_ACE_TYPE */
		if (nfs4_acl_consume & set_allow) {
			if (!(ace4p->access_mask & mask_bit)) {
				return (ENOTSUP);
			}
		} else if (nfs4_acl_consume & err_allow) {
			if (ace4p->access_mask & mask_bit) {
				return (ENOTSUP);
			}
		}
	}
	return (0);
}

static int
ace4_to_aent_legal(nfsace4 *ace4p, int isserver)
{
	int error = 0;
	int isowner;

	/* check for NULL who string */
	if (ace4p->who.utf8string_val == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_aent_legal: NULL who string"));
		error = EINVAL;
		goto out;
	}

	/* only ALLOW or DENY */
	if ((ace4p->type != ACE4_ACCESS_ALLOWED_ACE_TYPE) &&
	    (ace4p->type != ACE4_ACCESS_DENIED_ACE_TYPE)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_aent_legal: neither allow nor deny"));
		error = ENOTSUP;
		goto out;
	}

	/* check for invalid flags */
	if (ace4p->flag & ~(ACE4_VALID_FLAG_BITS)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_aent_legal: invalid flags: %x", ace4p->flag));
		error = EINVAL;
		goto out;
	}

	/* some flags are illegal */
	if (ace4p->flag & (ACE4_SUCCESSFUL_ACCESS_ACE_FLAG |
	    ACE4_FAILED_ACCESS_ACE_FLAG |
	    ACE4_NO_PROPAGATE_INHERIT_ACE)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_aent_legal: illegal flags: %x", ace4p->flag));
		error = ENOTSUP;
		goto out;
	}

	/* check for invalid masks */
	if (ace4p->access_mask & ~(ACE4_VALID_MASK_BITS)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_aent_legal: invalid mask: %x",
		    ace4p->access_mask));
		error = EINVAL;
		goto out;
	}

	if ((ace4p->who.utf8string_len == 6) &&
	    (bcmp(ACE4_WHO_OWNER, ace4p->who.utf8string_val, 6) == 0)) {
		isowner = 1;
	} else {
		isowner = 0;
	}

	error = access_mask_check(ace4p, ACE4_SYNCHRONIZE, isserver, isowner);
	if (error)
		goto out;

	error = access_mask_check(ace4p, ACE4_WRITE_OWNER, isserver, isowner);
	if (error)
		goto out;

	error = access_mask_check(ace4p, ACE4_DELETE, isserver, isowner);
	if (error)
		goto out;

	error = access_mask_check(ace4p, ACE4_WRITE_ATTRIBUTES, isserver,
	    isowner);
	if (error)
		goto out;

	error = access_mask_check(ace4p, ACE4_READ_NAMED_ATTRS, isserver,
	    isowner);
	if (error)
		goto out;

	error = access_mask_check(ace4p, ACE4_WRITE_NAMED_ATTRS, isserver,
	    isowner);
	if (error)
		goto out;

	/* more detailed checking of masks */
	if (ace4p->type == ACE4_ACCESS_ALLOWED_ACE_TYPE) {
		if (! (ace4p->access_mask & ACE4_READ_ATTRIBUTES)) {
			error = ENOTSUP;
			goto out;
		}
		if ((ace4p->access_mask & ACE4_WRITE_DATA) &&
		    (! (ace4p->access_mask & ACE4_APPEND_DATA))) {
			error = ENOTSUP;
			goto out;
		}
		if ((! (ace4p->access_mask & ACE4_WRITE_DATA)) &&
		    (ace4p->access_mask & ACE4_APPEND_DATA)) {
			error = ENOTSUP;
			goto out;
		}
	}

	/* ACL enforcement */
	if ((ace4p->access_mask & ACE4_READ_ACL) &&
	    (ace4p->type != ACE4_ACCESS_ALLOWED_ACE_TYPE)) {
		error = ENOTSUP;
		goto out;
	}
	if (ace4p->access_mask & ACE4_WRITE_ACL) {
		if ((ace4p->type == ACE4_ACCESS_DENIED_ACE_TYPE) &&
		    (isowner)) {
			error = ENOTSUP;
			goto out;
		}
		if ((ace4p->type == ACE4_ACCESS_ALLOWED_ACE_TYPE) &&
		    (! isowner)) {
			error = ENOTSUP;
			goto out;
		}
	}

out:
	return (error);
}

static int
ace4vals_to_aent(ace4vals_t *vals, aclent_t *dest, ace4_list_t *list,
    uid_t owner, gid_t group, int isdir, int isserver)
{
	int error;
	acemask4 flips = ACE4_POSIX_SUPPORTED_BITS;

	if (isdir)
		flips |= ACE4_DELETE_CHILD;
	if (vals->allowed != (vals->denied ^ flips)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4vals_to_aent: mis-matched allow/deny pair: %x/%x",
		    vals->allowed, vals->denied));
		error = ENOTSUP;
		goto out;
	}
	if ((list->hasmask) && (list->acl_mask != vals->mask) &&
	    (vals->aent_type & (USER | GROUP | GROUP_OBJ))) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4vals_to_aent: entry is missing mask"));
		error = ENOTSUP;
		goto out;
	}
	error = ace4_allow_to_mode(vals->allowed, &dest->a_perm, isdir);
	if (error != 0)
		goto out;
	dest->a_type = vals->aent_type;
	if (dest->a_type & (USER | GROUP)) {
		if (dest->a_type & USER)
			error = nfs_idmap_str_uid(vals->key, &dest->a_id,
			    isserver);
		else
			error = nfs_idmap_str_gid(vals->key, &dest->a_id,
			    isserver);
		if (error != 0) {
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "ace4vals_to_aent: idmap failed with %d", error));
			if (isserver && (error == EPERM))
				error = NFS4ERR_BADOWNER;
			goto out;
		}

		error = validate_idmapping(vals->key, &dest->a_id,
		    (dest->a_type & USER ? 1 : 0), isserver);
		if (error != 0) {
			goto out;
		}
	} else if (dest->a_type & USER_OBJ) {
		dest->a_id = owner;
	} else if (dest->a_type & GROUP_OBJ) {
		dest->a_id = group;
	} else if (dest->a_type & OTHER_OBJ) {
		dest->a_id = 0;
	} else {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4vals_to_aent: dest->a_type invalid: %x "
		    "(internal error)", dest->a_type));
		error = EINVAL;
		goto out;
	}

out:
	return (error);
}

static int
ace4_list_to_aent(ace4_list_t *list, aclent_t **aclentp, int *aclcnt,
    uid_t owner, gid_t group, int isdir, int isserver)
{
	int error = 0;
	aclent_t *aent, *result = NULL;
	ace4vals_t *vals;
	int resultcount;

	if ((list->seen & (USER_OBJ | GROUP_OBJ | OTHER_OBJ)) !=
	    (USER_OBJ | GROUP_OBJ | OTHER_OBJ)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_list_to_aent: required aclent_t entites missing"));
		error = ENOTSUP;
		goto out;
	}
	if ((! list->hasmask) && (list->numusers + list->numgroups > 0)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_list_to_aent: CLASS_OBJ (mask) missing"));
		error = ENOTSUP;
		goto out;
	}

	resultcount = 3 + list->numusers + list->numgroups;
	/*
	 * This must be the same condition as below, when we add the CLASS_OBJ
	 * (aka ACL mask)
	 */
	if ((list->hasmask) || (! list->dfacl_flag))
		resultcount += 1;

	result = aent = kmem_alloc(resultcount * sizeof (aclent_t), KM_SLEEP);

	/* USER_OBJ */
	ASSERT(list->user_obj.aent_type & USER_OBJ);
	error = ace4vals_to_aent(&list->user_obj, aent, list, owner, group,
	    isdir, isserver);

	if (error != 0)
		goto out;
	++aent;
	/* USER */
	vals = NULL;
	for (vals = avl_first(&list->user); vals != NULL;
	    vals = AVL_NEXT(&list->user, vals)) {
		ASSERT(vals->aent_type & USER);
		error = ace4vals_to_aent(vals, aent, list, owner, group,
		    isdir, isserver);
		if (error != 0)
			goto out;
		++aent;
	}
	/* GROUP_OBJ */
	ASSERT(list->group_obj.aent_type & GROUP_OBJ);
	error = ace4vals_to_aent(&list->group_obj, aent, list, owner, group,
	    isdir, isserver);
	if (error != 0)
		goto out;
	++aent;
	/* GROUP */
	vals = NULL;
	for (vals = avl_first(&list->group); vals != NULL;
	    vals = AVL_NEXT(&list->group, vals)) {
		ASSERT(vals->aent_type & GROUP);
		error = ace4vals_to_aent(vals, aent, list, owner, group,
		    isdir, isserver);
		if (error != 0)
			goto out;
		++aent;
	}
	/*
	 * CLASS_OBJ (aka ACL_MASK)
	 *
	 * An ACL_MASK is not fabricated if the ACL is a default ACL.
	 * This is to follow UFS's behavior.
	 */
	if ((list->hasmask) || (! list->dfacl_flag)) {
		if (list->hasmask) {
			acemask4 flips = ACE4_POSIX_SUPPORTED_BITS;
			if (isdir)
				flips |= ACE4_DELETE_CHILD;
			error = ace4_mask_to_mode(list->acl_mask ^ flips,
			    &aent->a_perm, isdir);
			if (error != 0)
				goto out;
		} else {
			/* fabricate the ACL_MASK from the group permissions */
			error = ace4_mask_to_mode(list->group_obj.allowed,
			    &aent->a_perm, isdir);
			if (error != 0)
				goto out;
		}
		aent->a_id = 0;
		aent->a_type = CLASS_OBJ | list->dfacl_flag;
		++aent;
	}
	/* OTHER_OBJ */
	ASSERT(list->other_obj.aent_type & OTHER_OBJ);
	error = ace4vals_to_aent(&list->other_obj, aent, list, owner, group,
	    isdir, isserver);
	if (error != 0)
		goto out;
	++aent;

	*aclentp = result;
	*aclcnt = resultcount;

out:
	if (error != 0) {
		if (result != NULL)
			kmem_free(result, resultcount * sizeof (aclent_t));
	}

	return (error);
}

/*
 * Convert a list of nfsace4 entries to equivalent regular and default
 * aclent_t lists.  Return error (ENOTSUP) when conversion is not possible.
 */
static int
ln_ace4_to_aent(nfsace4 *ace4, int n,
    uid_t owner, gid_t group,
    aclent_t **aclentp, int *aclcnt,
    aclent_t **dfaclentp, int *dfaclcnt,
    int isdir, int isserver)
{
	int error = 0;
	nfsace4 *ace4p;
	acemask4 bits;
	int i;
	ace4_list_t *normacl = NULL, *dfacl = NULL, *acl;
	ace4vals_t *vals;

	*aclentp = NULL;
	*aclcnt = 0;
	*dfaclentp = NULL;
	*dfaclcnt = 0;

	/* we need at least user_obj, group_obj, and other_obj */
	if (n < 6) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ln_ace4_to_aent: too few nfsace4 entries: %d", n));
		error = ENOTSUP;
		goto out;
	}
	if (ace4 == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ln_ace4_to_aent: NULL source"));
		error = EINVAL;
		goto out;
	}

	normacl = kmem_cache_alloc(nfs4_ace4_list_cache, KM_SLEEP);
	ace4_list_init(normacl, 0);
	dfacl = kmem_cache_alloc(nfs4_ace4_list_cache, KM_SLEEP);
	ace4_list_init(dfacl, ACL_DEFAULT);

	/* process every nfsace4... */
	for (i = 0; i < n; i++) {
		ace4p = &ace4[i];

		/* rule out certain cases quickly */
		error = ace4_to_aent_legal(ace4p, isserver);
		if (error != 0)
			goto out;

		/*
		 * Turn off these bits in order to not have to worry about
		 * them when doing the checks for compliments.
		 */
		ace4p->access_mask &= ~(ACE4_WRITE_OWNER | ACE4_DELETE |
		    ACE4_SYNCHRONIZE | ACE4_WRITE_ATTRIBUTES |
		    ACE4_READ_NAMED_ATTRS | ACE4_WRITE_NAMED_ATTRS);

		/* see if this should be a regular or default acl */
		bits = ace4p->flag &
		    (ACE4_INHERIT_ONLY_ACE |
		    ACE4_FILE_INHERIT_ACE |
		    ACE4_DIRECTORY_INHERIT_ACE);
		if (bits != 0) {
			/* all or nothing on these inherit bits */
			if (bits != (ACE4_INHERIT_ONLY_ACE |
			    ACE4_FILE_INHERIT_ACE |
			    ACE4_DIRECTORY_INHERIT_ACE)) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: bad inherit flags "
				    "%x", bits));
				error = ENOTSUP;
				goto out;
			}
			acl = dfacl;
		} else {
			acl = normacl;
		}

		if ((ace4p->who.utf8string_len == 6) &&
		    (bcmp(ACE4_WHO_OWNER,
		    ace4p->who.utf8string_val, 6) == 0)) {
			if (acl->state > ace4_user_obj) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: OWNER@ found "
				    "out of order"));
				error = ENOTSUP;
				goto out;
			}
			acl->state = ace4_user_obj;
			acl->seen |= USER_OBJ;
			vals = &acl->user_obj;
			vals->aent_type = USER_OBJ | acl->dfacl_flag;
		} else if ((ace4p->who.utf8string_len == 9) &&
		    (bcmp(ACE4_WHO_EVERYONE, ace4p->who.utf8string_val, 9)
		    == 0)) {
			acl->state = ace4_other_obj;
			acl->seen |= OTHER_OBJ;
			vals = &acl->other_obj;
			vals->aent_type = OTHER_OBJ | acl->dfacl_flag;
		} else if ((ace4p->who.utf8string_len == 6) &&
		    (bcmp(ACE4_WHO_GROUP, ace4p->who.utf8string_val, 6) == 0)) {
			if (acl->state > ace4_group) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: group entry found "
				    "out of order"));
				error = ENOTSUP;
				goto out;
			}
			acl->seen |= GROUP_OBJ;
			vals = &acl->group_obj;
			vals->aent_type = GROUP_OBJ | acl->dfacl_flag;
			acl->state = ace4_group;
		} else if (ace4p->flag & ACE4_IDENTIFIER_GROUP) {
			if (acl->state > ace4_group) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: group entry found "
				    "out of order"));
				error = ENOTSUP;
				goto out;
			}
			acl->seen |= GROUP;
			vals = ace4vals_find(ace4p, &acl->group,
			    &acl->numgroups);
			vals->aent_type = GROUP | acl->dfacl_flag;
			acl->state = ace4_group;
		} else {
			if (acl->state > ace4_user) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: user entry found "
				    "out of order"));
				error = ENOTSUP;
				goto out;
			}
			acl->state = ace4_user;
			acl->seen |= USER;
			vals = ace4vals_find(ace4p, &acl->user,
			    &acl->numusers);
			vals->aent_type = USER | acl->dfacl_flag;
		}
		ASSERT(acl->state > ace4_unused);

		if (ace4p->type == ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			/* no more than one allowed per aclent_t */
			if (vals->allowed != ACE4_MASK_UNDEFINED) {
				NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
				    "ln_ace4_to_aent: too many ALLOWs "
				    "for one entity"));
				error = ENOTSUP;
				goto out;
			}
			vals->allowed = ace4p->access_mask;
		} else {
			/*
			 * it's a DENY; if there was a previous DENY, it
			 * must have been an ACL_MASK.
			 */
			if (vals->denied != ACE4_MASK_UNDEFINED) {
				/* ACL_MASK is for USER and GROUP only */
				if ((acl->state != ace4_user) &&
				    (acl->state != ace4_group)) {
					NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
					    "ln_ace4_to_aent: ACL_MASK-like "
					    "DENY found on non-user/non-group "
					    "entity"));
					error = ENOTSUP;
					goto out;
				}

				if (! acl->hasmask) {
					acl->hasmask = 1;
					acl->acl_mask = vals->denied;
				/* check for mismatched ACL_MASK emulations */
				} else if (acl->acl_mask != vals->denied) {
					NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
					    "ln_ace4_to_aent: ACL_MASK "
					    "mismatch"));
					error = ENOTSUP;
					goto out;
				}
				vals->mask = vals->denied;
			}
			vals->denied = ace4p->access_mask;
		}
	}

	/* done collating; produce the aclent_t lists */
	if (normacl->state != ace4_unused) {
		error = ace4_list_to_aent(normacl, aclentp, aclcnt,
		    owner, group, isdir, isserver);
		if (error != 0)
			goto out;
	}
	if (dfacl->state != ace4_unused) {
		error = ace4_list_to_aent(dfacl, dfaclentp, dfaclcnt,
		    owner, group, isdir, isserver);
		if (error != 0)
			goto out;
	}

out:
	if (normacl != NULL)
		ace4_list_free(normacl);
	if (dfacl != NULL)
		ace4_list_free(dfacl);

	return (error);
}

/*
 * Convert an NFSv4 ACL (in a vsecattr_t) to a POSIX draft ACL, following
 * the semantics of NFSv4_to_POSIX.html.  Contact fsh-group@sun.com to
 * obtain this document.
 */
int
vs_ace4_to_aent(vsecattr_t *vs_ace4, vsecattr_t *vs_aent,
    uid_t owner, gid_t group, int isdir, int isserver)
{
	int error = 0;

	error = ln_ace4_to_aent(vs_ace4->vsa_aclentp, vs_ace4->vsa_aclcnt,
	    owner, group,
	    (aclent_t **)&vs_aent->vsa_aclentp, &vs_aent->vsa_aclcnt,
	    (aclent_t **)&vs_aent->vsa_dfaclentp, &vs_aent->vsa_dfaclcnt,
	    isdir, isserver);
	if (error != 0)
		goto out;

	vs_aent->vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT;
	if ((vs_aent->vsa_aclcnt == 0) && (vs_aent->vsa_dfaclcnt == 0)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "vs_ace4_to_aent: neither ACL nor default ACL found"));
		error = ENOTSUP;
		goto out;
	}

out:
	if (error != 0) {
		if (vs_aent != NULL)
			vs_aent_destroy(vs_aent);
	}

	return (error);
}

/*
 * compare two ace4 acls
 */

static int
ace4_cmp(nfsace4 *a, nfsace4 *b)
{
	if (a->type < b->type)
		return (-1);
	if (a->type > b->type)
		return (1);
	if (a->flag < b->flag)
		return (-1);
	if (a->flag > b->flag)
		return (1);
	if (a->access_mask < b->access_mask)
		return (-1);
	if (a->access_mask > b->access_mask)
		return (1);
	return (utf8_compare(&a->who, &b->who));
}

int
ln_ace4_cmp(nfsace4 *a, nfsace4* b, int n)
{
	int rc;
	int i;

	for (i = 0; i < n; i++) {
		rc = ace4_cmp(a + i, b + i);
		if (rc != 0)
			return (rc);
	}
	return (0);
}

/*
 * Convert an ace_t to an nfsace4; the primary difference being
 * strings versus integer uid/gids.
 */
static int
acet_to_ace4(ace_t *ace, nfsace4 *nfsace4, int isserver)
{
	int error = 0;

	if (ace == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "acet_to_ace4: NULL source"));
		error = EINVAL;
		goto out;
	}
	if (nfsace4 == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "acet_to_ace4: NULL destination"));
		error = EINVAL;
		goto out;
	}

	switch (ace->a_type) {
	case ACE_ACCESS_ALLOWED_ACE_TYPE:
		nfsace4->type = ACE4_ACCESS_ALLOWED_ACE_TYPE;
		break;
	case ACE_ACCESS_DENIED_ACE_TYPE:
		nfsace4->type = ACE4_ACCESS_DENIED_ACE_TYPE;
		break;
	default:
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "acet_to_ace4: unsupported type: %x", ace->a_type));
		error = ENOTSUP;
		break;
	}
	if (error != 0)
		goto out;

	acet_mask_to_ace4_mask(ace->a_access_mask, &nfsace4->access_mask);
	acet_flags_to_ace4_flags(ace->a_flags, &nfsace4->flag);

	if (ace->a_flags & ACE_GROUP) {
		nfsace4->flag |= ACE4_IDENTIFIER_GROUP;
		(void) str_to_utf8(ACE4_WHO_GROUP, &nfsace4->who);
	} else if (ace->a_flags & ACE_IDENTIFIER_GROUP) {
		nfsace4->flag |= ACE4_IDENTIFIER_GROUP;
		/*
		 * On the client, we do not allow an ACL with ACEs containing
		 * the "unknown"/GID_UNKNOWN group to be set.  This is because
		 * it having GID_UNKNOWN in an ACE can only come from
		 * the user having done a read-modify-write ACL manipulation
		 * (e.g. setfacl -m or chmod A+) when there was an ACE with
		 * an unmappable group already present.
		 */
		if (ace->a_who == GID_UNKNOWN && !isserver) {
			DTRACE_PROBE(nfs4clnt__err__acl__gid__unknown);
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "acet_to_ace4: GID_UNKNOWN is not allowed in "
			    "the ACL"));
			error = EACCES;
			goto out;
		}
		error = nfs_idmap_gid_str(ace->a_who, &nfsace4->who, isserver);
		if (error != 0)
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "acet_to_ace4: idmap failed with %d", error));
	} else if (ace->a_flags & ACE_OWNER) {
		(void) str_to_utf8(ACE4_WHO_OWNER, &nfsace4->who);
	} else if (ace->a_flags & ACE_EVERYONE) {
		(void) str_to_utf8(ACE4_WHO_EVERYONE, &nfsace4->who);
	} else {
		/*
		 * Same rule as GID_UNKNOWN (above).
		 */
		if (ace->a_who == UID_UNKNOWN && !isserver) {
			DTRACE_PROBE(nfs4clnt__err__acl__uid__unknown);
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "acet_to_ace4: UID_UNKNOWN is not allowed in "
			    "the ACL"));
			error = EACCES;
			goto out;
		}
		error = nfs_idmap_uid_str(ace->a_who, &nfsace4->who, isserver);
		if (error != 0)
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "acet_to_ace4: idmap failed with %d", error));
	}

out:
	return (error);
}

/*
 * Convert an nfsace4 to an ace_t, the primary difference being
 * integer uid/gids versus strings.
 */
static int
ace4_to_acet(nfsace4 *nfsace4, ace_t *ace, uid_t owner, gid_t group,
    int isserver)
{
	int error = 0;

	if (nfsace4 == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: NULL source"));
		return (EINVAL);
	}
	if (ace == NULL) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: NULL destination"));
		return (EINVAL);
	}

	switch (nfsace4->type) {
	case ACE4_ACCESS_ALLOWED_ACE_TYPE:
		ace->a_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
		break;
	case ACE4_ACCESS_DENIED_ACE_TYPE:
		ace->a_type = ACE_ACCESS_DENIED_ACE_TYPE;
		break;
	default:
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: unsupported type: %x", nfsace4->type));
		error = ENOTSUP;
		break;
	}
	if (error != 0)
		goto out;

	if (nfsace4->flag & ~(ACE4_VALID_FLAG_BITS)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: invalid flags: %x", nfsace4->flag));
		error = EINVAL;
		goto out;
	}

	/* check for invalid masks */
	if (nfsace4->access_mask & ~(ACE4_VALID_MASK_BITS)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: invalid mask: %x", nfsace4->access_mask));
		error = EINVAL;
		goto out;
	}

	ace4_mask_to_acet_mask(nfsace4->access_mask, &ace->a_access_mask);

	if (nfsace4->flag & ~ACE_NFSV4_SUP_FLAGS) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "ace4_to_acet: unsupported flags: %x", nfsace4->flag));
		error = ENOTSUP;
		goto out;
	}
	ace4_flags_to_acet_flags(nfsace4->flag, &ace->a_flags);

	if ((nfsace4->who.utf8string_len == 6) &&
	    (bcmp(ACE4_WHO_GROUP,
	    nfsace4->who.utf8string_val, 6)) == 0) {
		ace->a_who = group;
		ace->a_flags |= ACE_GROUP | ACE_IDENTIFIER_GROUP;
	} else if ((nfsace4->who.utf8string_len == 6) &&
	    (bcmp(ACE4_WHO_OWNER,
	    nfsace4->who.utf8string_val, 6) == 0)) {
		ace->a_flags |= ACE_OWNER;
		ace->a_who = owner;
	} else if ((nfsace4->who.utf8string_len == 9) &&
	    (bcmp(ACE4_WHO_EVERYONE,
	    nfsace4->who.utf8string_val, 9) == 0)) {
		ace->a_flags |= ACE_EVERYONE;
		ace->a_who = 0;
	} else if (nfsace4->flag & ACE4_IDENTIFIER_GROUP) {
		ace->a_flags |= ACE_IDENTIFIER_GROUP;
		error = nfs_idmap_str_gid(&nfsace4->who,
		    &ace->a_who, isserver);
		if (error != 0) {
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "ace4_to_acet: idmap failed with %d",
			    error));
			if (isserver && (error == EPERM))
				error = NFS4ERR_BADOWNER;
			goto out;
		}
		error = validate_idmapping(&nfsace4->who,
		    &ace->a_who, FALSE, isserver);
		if (error != 0)
			goto out;
	} else {
		error = nfs_idmap_str_uid(&nfsace4->who,
		    &ace->a_who, isserver);
		if (error != 0) {
			NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
			    "ace4_to_acet: idmap failed with %d",
			    error));
			if (isserver && (error == EPERM))
				error = NFS4ERR_BADOWNER;
			goto out;
		}
		error = validate_idmapping(&nfsace4->who,
		    &ace->a_who, TRUE, isserver);
		if (error != 0)
			goto out;
	}

out:
	return (error);
}

static void
ace4_mask_to_acet_mask(acemask4 ace4_mask, uint32_t *acet_mask)
{
	*acet_mask = 0;

	if (ace4_mask & ACE4_READ_DATA)
		*acet_mask |= ACE_READ_DATA;
	if (ace4_mask & ACE4_WRITE_DATA)
		*acet_mask |= ACE_WRITE_DATA;
	if (ace4_mask & ACE4_APPEND_DATA)
		*acet_mask |= ACE_APPEND_DATA;
	if (ace4_mask & ACE4_READ_NAMED_ATTRS)
		*acet_mask |= ACE_READ_NAMED_ATTRS;
	if (ace4_mask & ACE4_WRITE_NAMED_ATTRS)
		*acet_mask |= ACE_WRITE_NAMED_ATTRS;
	if (ace4_mask & ACE4_EXECUTE)
		*acet_mask |= ACE_EXECUTE;
	if (ace4_mask & ACE4_DELETE_CHILD)
		*acet_mask |= ACE_DELETE_CHILD;
	if (ace4_mask & ACE4_READ_ATTRIBUTES)
		*acet_mask |= ACE_READ_ATTRIBUTES;
	if (ace4_mask & ACE4_WRITE_ATTRIBUTES)
		*acet_mask |= ACE_WRITE_ATTRIBUTES;
	if (ace4_mask & ACE4_DELETE)
		*acet_mask |= ACE_DELETE;
	if (ace4_mask & ACE4_READ_ACL)
		*acet_mask |= ACE_READ_ACL;
	if (ace4_mask & ACE4_WRITE_ACL)
		*acet_mask |= ACE_WRITE_ACL;
	if (ace4_mask & ACE4_WRITE_OWNER)
		*acet_mask |= ACE_WRITE_OWNER;
	if (ace4_mask & ACE4_SYNCHRONIZE)
		*acet_mask |= ACE_SYNCHRONIZE;
}

static void
acet_mask_to_ace4_mask(uint32_t acet_mask, acemask4 *ace4_mask)
{
	*ace4_mask = 0;

	if (acet_mask & ACE_READ_DATA)
		*ace4_mask |= ACE4_READ_DATA;
	if (acet_mask & ACE_WRITE_DATA)
		*ace4_mask |= ACE4_WRITE_DATA;
	if (acet_mask & ACE_APPEND_DATA)
		*ace4_mask |= ACE_APPEND_DATA;
	if (acet_mask & ACE4_READ_NAMED_ATTRS)
		*ace4_mask |= ACE_READ_NAMED_ATTRS;
	if (acet_mask & ACE_WRITE_NAMED_ATTRS)
		*ace4_mask |= ACE4_WRITE_NAMED_ATTRS;
	if (acet_mask & ACE_EXECUTE)
		*ace4_mask |= ACE4_EXECUTE;
	if (acet_mask & ACE_DELETE_CHILD)
		*ace4_mask |= ACE4_DELETE_CHILD;
	if (acet_mask & ACE_READ_ATTRIBUTES)
		*ace4_mask |= ACE4_READ_ATTRIBUTES;
	if (acet_mask & ACE_WRITE_ATTRIBUTES)
		*ace4_mask |= ACE4_WRITE_ATTRIBUTES;
	if (acet_mask & ACE_DELETE)
		*ace4_mask |= ACE4_DELETE;
	if (acet_mask & ACE_READ_ACL)
		*ace4_mask |= ACE4_READ_ACL;
	if (acet_mask & ACE_WRITE_ACL)
		*ace4_mask |= ACE4_WRITE_ACL;
	if (acet_mask & ACE_WRITE_OWNER)
		*ace4_mask |= ACE4_WRITE_OWNER;
	if (acet_mask & ACE_SYNCHRONIZE)
		*ace4_mask |= ACE4_SYNCHRONIZE;
}

static void
ace4_flags_to_acet_flags(aceflag4 ace4_flags, uint16_t *acet_flags)
{
	*acet_flags = 0;

	if (ace4_flags & ACE4_FILE_INHERIT_ACE)
		*acet_flags |= ACE_FILE_INHERIT_ACE;
	if (ace4_flags & ACE4_DIRECTORY_INHERIT_ACE)
		*acet_flags |= ACE_DIRECTORY_INHERIT_ACE;
	if (ace4_flags & ACE4_NO_PROPAGATE_INHERIT_ACE)
		*acet_flags |= ACE_NO_PROPAGATE_INHERIT_ACE;
	if (ace4_flags & ACE4_INHERIT_ONLY_ACE)
		*acet_flags |= ACE_INHERIT_ONLY_ACE;
	if (ace4_flags & ACE4_SUCCESSFUL_ACCESS_ACE_FLAG)
		*acet_flags |= ACE_SUCCESSFUL_ACCESS_ACE_FLAG;
	if (ace4_flags & ACE4_FAILED_ACCESS_ACE_FLAG)
		*acet_flags |= ACE_FAILED_ACCESS_ACE_FLAG;
	/* ACE_IDENTIFIER_GROUP is handled in ace4_to_acet() */
}

static void
acet_flags_to_ace4_flags(uint16_t acet_flags, aceflag4 *ace4_flags)
{
	*ace4_flags = 0;

	if (acet_flags & ACE_FILE_INHERIT_ACE)
		*ace4_flags |= ACE4_FILE_INHERIT_ACE;
	if (acet_flags & ACE_DIRECTORY_INHERIT_ACE)
		*ace4_flags |= ACE4_DIRECTORY_INHERIT_ACE;
	if (acet_flags & ACE_NO_PROPAGATE_INHERIT_ACE)
		*ace4_flags |= ACE4_NO_PROPAGATE_INHERIT_ACE;
	if (acet_flags & ACE_INHERIT_ONLY_ACE)
		*ace4_flags |= ACE4_INHERIT_ONLY_ACE;
	if (acet_flags & ACE_SUCCESSFUL_ACCESS_ACE_FLAG)
		*ace4_flags |= ACE4_SUCCESSFUL_ACCESS_ACE_FLAG;
	if (acet_flags & ACE_FAILED_ACCESS_ACE_FLAG)
		*ace4_flags |= ACE4_FAILED_ACCESS_ACE_FLAG;
	/* ACE4_IDENTIFIER_GROUP is handled in acet_to_ace4() */
}

int
vs_ace4_to_acet(vsecattr_t *vs_ace4, vsecattr_t *vs_acet,
    uid_t owner, gid_t group, int isserver)
{
	int error;
	int i;

	if ((vs_ace4->vsa_mask & (VSA_ACE | VSA_ACECNT)) !=
	    (VSA_ACE | VSA_ACECNT))
		return (EINVAL);
	if (vs_ace4->vsa_aclcnt < 0)
		return (EINVAL);
	if ((vs_ace4->vsa_aclcnt == 0) || (vs_ace4->vsa_aclentp == NULL))
		return (0);

	if (vs_ace4->vsa_aclcnt > 0) {
		vs_acet->vsa_aclentp = kmem_alloc(vs_ace4->vsa_aclcnt *
		    sizeof (ace_t), KM_SLEEP);
		vs_acet->vsa_aclentsz = vs_ace4->vsa_aclcnt * sizeof (ace_t);
	} else
		vs_acet->vsa_aclentp = NULL;
	vs_acet->vsa_aclcnt = vs_ace4->vsa_aclcnt;
	vs_acet->vsa_mask = VSA_ACE | VSA_ACECNT;

	for (i = 0; i < vs_ace4->vsa_aclcnt; i++) {
		error = ace4_to_acet((nfsace4 *)(vs_ace4->vsa_aclentp) + i,
		    (ace_t *)(vs_acet->vsa_aclentp) + i, owner, group,
		    isserver);
		if (error != 0)
			goto out;
	}

out:
	if (error != 0)
		vs_acet_destroy(vs_acet);

	return (error);
}

int
vs_acet_to_ace4(vsecattr_t *vs_acet, vsecattr_t *vs_ace4,
    int isserver)
{
	int error = 0;
	int i;

	if (! (vs_acet->vsa_mask & VSA_ACE)) {
		NFS4_DEBUG(nfs4_acl_debug, (CE_NOTE,
		    "vs_acet_to_ace4: VSA_ACE missing from mask"));
		return (EINVAL);
	}

	if (vs_acet->vsa_aclcnt > 0)
		vs_ace4->vsa_aclentp = kmem_zalloc(vs_acet->vsa_aclcnt *
		    sizeof (nfsace4), KM_SLEEP);
	else
		vs_ace4->vsa_aclentp = NULL;
	vs_ace4->vsa_aclcnt = vs_acet->vsa_aclcnt;
	vs_ace4->vsa_mask = VSA_ACE | VSA_ACECNT;

	for (i = 0; i < vs_acet->vsa_aclcnt; i++) {
		error = acet_to_ace4((ace_t *)(vs_acet->vsa_aclentp) + i,
		    (nfsace4 *)(vs_ace4->vsa_aclentp) + i, isserver);
		if (error != 0)
			goto out;
	}

out:
	if (error != 0)
		vs_ace4_destroy(vs_ace4);

	return (error);
}

void
nfs4_acl_fill_cache(rnode4_t *rp, vsecattr_t *vsap)
{
	size_t aclsize;
	vsecattr_t *rvsap;
	nfsace4 *tmp_ace4, *ace4;
	int i;

	mutex_enter(&rp->r_statelock);
	if (rp->r_secattr != NULL)
		rvsap = rp->r_secattr;
	else {
		rvsap = kmem_zalloc(sizeof (*rvsap), KM_NOSLEEP);
		if (rvsap == NULL) {
			mutex_exit(&rp->r_statelock);
			return;
		}
		rp->r_secattr = rvsap;
	}

	if (vsap->vsa_mask & VSA_ACE) {
		if (rvsap->vsa_aclentp != NULL) {
			if (rvsap->vsa_aclcnt != vsap->vsa_aclcnt) {
				vs_ace4_destroy(rvsap);
				rvsap->vsa_aclentp = NULL;
			} else {
				/*
				 * The counts are equal so we don't have to
				 * destroy the acl entries because we'd only
				 * have to re-allocate them, but we do have to
				 * destroy all of the who utf8strings.
				 * The acl that we are now filling the cache
				 * with may have the same amount of entries as
				 * what is currently cached, but those entries
				 * may not be the same.
				 */
				ace4 = (nfsace4 *) rvsap->vsa_aclentp;
				for (i = 0; i < rvsap->vsa_aclcnt; i++) {
					if (ace4[i].who.utf8string_val != NULL)
						kmem_free(
						    ace4[i].who.utf8string_val,
						    ace4[i].who.utf8string_len);
				}
			}
		}
		if (vsap->vsa_aclcnt > 0) {
			aclsize = vsap->vsa_aclcnt * sizeof (nfsace4);

			if (rvsap->vsa_aclentp == NULL) {
				rvsap->vsa_aclentp = kmem_alloc(aclsize,
				    KM_SLEEP);
			}

			bcopy(vsap->vsa_aclentp, rvsap->vsa_aclentp, aclsize);

			tmp_ace4 = (nfsace4 *) vsap->vsa_aclentp;
			ace4 = (nfsace4 *) rvsap->vsa_aclentp;
			for (i = 0; i < vsap->vsa_aclcnt; i++) {
				(void) utf8_copy(&tmp_ace4[i].who,
				    &ace4[i].who);
			}
		}
		rvsap->vsa_aclcnt = vsap->vsa_aclcnt;
		rvsap->vsa_mask |= VSA_ACE | VSA_ACECNT;
	}
	if (vsap->vsa_mask & VSA_ACECNT) {
		if (rvsap->vsa_aclentp != NULL) {
			/*
			 * If the caller requested to only cache the
			 * count, get rid of the acl whether or not the
			 * counts are equal because it may be invalid.
			 */
			if (vsap->vsa_mask == VSA_ACECNT ||
			    rvsap->vsa_aclcnt != vsap->vsa_aclcnt) {
				vs_ace4_destroy(rvsap);
				rvsap->vsa_aclentp = NULL;
				rvsap->vsa_mask &= ~VSA_ACE;
			}
		}
		rvsap->vsa_aclcnt = vsap->vsa_aclcnt;
		rvsap->vsa_mask |= VSA_ACECNT;
	}
	mutex_exit(&rp->r_statelock);
}

/*
 * This should ONLY be called on the ACL cache (rnode4_t.r_secattr).  The cache
 * is stored as a nfsv4 acl meaning the vsecattr_t.vsa_aclentp is a list of
 * nfsace4 entries and vsecattr_t.vsa_dfaclentp is NULL or not populated.
 */
void
nfs4_acl_free_cache(vsecattr_t *vsap)
{
	if (vsap == NULL)
		return;

	if (vsap->vsa_aclentp != NULL)
		vs_ace4_destroy(vsap);

	kmem_free(vsap, sizeof (*vsap));
	vsap = NULL;
}

static int
validate_idmapping(utf8string *orig_who, uid_t *mapped_id, int isuser,
	int isserver)
{
	if (u8s_mapped_to_nobody(orig_who, *mapped_id, isuser)) {
		if (isserver) {
			char	*who = NULL;
			uint_t	len = 0;
			/* SERVER */
			/*
			 * This code path gets executed on the server
			 * in the case that we are setting an ACL.
			 *
			 * We silently got our who value (who@domain)
			 * mapped to "nobody" (possibly because the
			 * nfsmapid daemon was unresponsive).
			 * We NEVER want to silently map the user or
			 * group to "nobody" as this could end up
			 * wrongly giving access to user or group
			 * "nobody" rather than the entity it was
			 * meant for.
			 */
			who = utf8_to_str(orig_who, &len, NULL);
			DTRACE_PROBE1(nfs4__acl__nobody, char *, who);
			if (who != NULL)
				kmem_free(who, len);
			return (NFS4ERR_BADOWNER);
		} else {
			char	*who = NULL;
			uint_t	len = 0;
			/* CLIENT */
			/*
			 * This code path gets executed on the client
			 * when we are getting an ACL.
			 *
			 * We do not want to silently map user or group to
			 * "nobody" because of the semantics that an ACL
			 * modification interface (i.e. - setfacl -m, chmod A+)
			 * may use to modify an ACL (i.e. - get the ACL
			 * then use it as a basis for setting the
			 * modified ACL).  Therefore, change the mapping.
			 */
			who = utf8_to_str(orig_who, &len, NULL);
			DTRACE_PROBE1(nfs4__acl__nobody, char *, who);
			if (who != NULL)
				kmem_free(who, len);

			/*
			 * Re-mapped from UID_NOBODY/GID_NOBODY
			 * to UID_UNKNOWN/GID_UNKNOWN and return.
			 */
			remap_id(mapped_id, isuser);
			return (0);
		}
	}
	return (0);
}
/*
 * Returns 1 if the who, utf8string was mapped to UID_NOBODY or GID_NOBODY.
 * Returns 0 if the who, utf8string was mapped correctly.
 */
static int
u8s_mapped_to_nobody(utf8string *orig_who, uid_t mapped_id, int isuser)
{
	if (orig_who->utf8string_len == 6 &&
	    bcmp("nobody", orig_who->utf8string_val, 6) == 0)
		return (0);

	if (isuser)
		return (mapped_id == UID_NOBODY);

	return (mapped_id == GID_NOBODY);
}

/*
 * This function is used in the case that the utf8string passed over the wire
 * was mapped to UID_NOBODY or GID_NOBODY and we will remap the id to
 * to the appropriate mapping.  That is UID_UNKNOWN or GID_UNKNOWN.
 */
static void
remap_id(uid_t *id, int isuser)
{
	if (isuser)
		*id = UID_UNKNOWN;

	*id = GID_UNKNOWN;
}
