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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include <locale.h>
#include <aclutils.h>
#include <acl_common.h>
#include <sys/avl.h>

#define	offsetof(s, m)	((size_t)(&(((s *)0)->m)))

#define	ACL_PATH	0
#define	ACL_FD		1

#define	ACE_POSIX_SUPPORTED_BITS (ACE_READ_DATA | \
    ACE_WRITE_DATA | ACE_APPEND_DATA | ACE_EXECUTE | \
    ACE_READ_ATTRIBUTES | ACE_READ_ACL | ACE_WRITE_ACL)


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


#define	ACE_VALID_MASK_BITS (\
    ACE_READ_DATA | \
    ACE_LIST_DIRECTORY | \
    ACE_WRITE_DATA | \
    ACE_ADD_FILE | \
    ACE_APPEND_DATA | \
    ACE_ADD_SUBDIRECTORY | \
    ACE_READ_NAMED_ATTRS | \
    ACE_WRITE_NAMED_ATTRS | \
    ACE_EXECUTE | \
    ACE_DELETE_CHILD | \
    ACE_READ_ATTRIBUTES | \
    ACE_WRITE_ATTRIBUTES | \
    ACE_DELETE | \
    ACE_READ_ACL | \
    ACE_WRITE_ACL | \
    ACE_WRITE_OWNER | \
    ACE_SYNCHRONIZE)

#define	ACE_MASK_UNDEFINED			0x80000000

#define	ACE_VALID_FLAG_BITS (ACE_FILE_INHERIT_ACE | \
    ACE_DIRECTORY_INHERIT_ACE | \
    ACE_NO_PROPAGATE_INHERIT_ACE | ACE_INHERIT_ONLY_ACE | \
    ACE_SUCCESSFUL_ACCESS_ACE_FLAG | ACE_FAILED_ACCESS_ACE_FLAG | \
    ACE_IDENTIFIER_GROUP | ACE_OWNER | ACE_GROUP | ACE_EVERYONE)

/*
 * ACL conversion helpers
 */

typedef enum {
	ace_unused,
	ace_user_obj,
	ace_user,
	ace_group, /* includes GROUP and GROUP_OBJ */
	ace_other_obj
} ace_to_aent_state_t;

typedef struct acevals {
	uid_t key;
	avl_node_t avl;
	uint32_t mask;
	uint32_t allowed;
	uint32_t denied;
	int aent_type;
} acevals_t;

typedef struct ace_list {
	acevals_t user_obj;
	avl_tree_t user;
	int numusers;
	acevals_t group_obj;
	avl_tree_t group;
	int numgroups;
	acevals_t other_obj;
	uint32_t acl_mask;
	int hasmask;
	int dfacl_flag;
	ace_to_aent_state_t state;
	int seen; /* bitmask of all aclent_t a_type values seen */
} ace_list_t;

typedef union {
	const char *file;
	int  fd;
} acl_inp;

acl_t *
acl_alloc(enum acl_type type)
{
	acl_t *aclp;

	aclp = malloc(sizeof (acl_t));

	if (aclp == NULL)
		return (NULL);

	aclp->acl_aclp = NULL;
	aclp->acl_cnt = 0;

	switch (type) {
	case ACE_T:
		aclp->acl_type = ACE_T;
		aclp->acl_entry_size = sizeof (ace_t);
		break;
	case ACLENT_T:
		aclp->acl_type = ACLENT_T;
		aclp->acl_entry_size = sizeof (aclent_t);
		break;
	default:
		acl_free(aclp);
		aclp = NULL;
	}
	return (aclp);
}

/*
 * Free acl_t structure
 */
void
acl_free(acl_t *aclp)
{
	if (aclp == NULL)
		return;

	if (aclp->acl_aclp)
		free(aclp->acl_aclp);
	free(aclp);
}

/*
 * Determine whether a file has a trivial ACL
 * returns: 	0 = trivial
 *		1 = nontrivial
 *		<0 some other system failure, such as ENOENT or EPERM
 */
int
acl_trivial(const char *filename)
{
	int acl_flavor;
	int aclcnt;
	int cntcmd;
	int val = 0;
	ace_t *acep;

	acl_flavor = pathconf(filename, _PC_ACL_ENABLED);

	if (acl_flavor == _ACL_ACE_ENABLED)
		cntcmd = ACE_GETACLCNT;
	else
		cntcmd = GETACLCNT;

	aclcnt = acl(filename, cntcmd, 0, NULL);
	if (aclcnt > 0) {
		if (acl_flavor == _ACL_ACE_ENABLED) {
			acep = malloc(sizeof (ace_t) * aclcnt);
			if (acep == NULL)
				return (-1);
			if (acl(filename, ACE_GETACL,
			    aclcnt, acep) < 0) {
				free(acep);
				return (-1);
			}

			val = ace_trivial(acep, aclcnt);
			free(acep);

		} else if (aclcnt > MIN_ACL_ENTRIES)
			val = 1;
	}
	return (val);
}

static uint32_t
access_mask_set(int haswriteperm, int hasreadperm, int isowner, int isallow)
{
	uint32_t access_mask = 0;
	int acl_produce;
	int synchronize_set = 0, write_owner_set = 0;
	int delete_set = 0, write_attrs_set = 0;
	int read_named_set = 0, write_named_set = 0;

	acl_produce = (ACL_SYNCHRONIZE_SET_ALLOW |
	    ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	    ACL_WRITE_ATTRS_WRITER_SET_DENY);

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
			 * have write permissions ACE_WRITE_ATTRIBUTES will
			 * always go in the DENY ACE.
			 */
			access_mask |= ACE_WRITE_ATTRIBUTES;
	}

	if (acl_produce & synchronize_set)
		access_mask |= ACE_SYNCHRONIZE;
	if (acl_produce & write_owner_set)
		access_mask |= ACE_WRITE_OWNER;
	if (acl_produce & delete_set)
		access_mask |= ACE_DELETE;
	if (acl_produce & write_attrs_set)
		access_mask |= ACE_WRITE_ATTRIBUTES;
	if (acl_produce & read_named_set)
		access_mask |= ACE_READ_NAMED_ATTRS;
	if (acl_produce & write_named_set)
		access_mask |= ACE_WRITE_NAMED_ATTRS;

	return (access_mask);
}

/*
 * Given an mode_t, convert it into an access_mask as used
 * by nfsace, assuming aclent_t -> nfsace semantics.
 */
static uint32_t
mode_to_ace_access(mode_t mode, int isdir, int isowner, int isallow)
{
	uint32_t access = 0;
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
	 * ACE_SYNCHRONIZE, ACE_WRITE_OWNER, ACE_DELETE,
	 * ACE_WRITE_ATTRIBUTES, ACE_WRITE_NAMED_ATTRS, ACE_READ_NAMED_ATTRS
	 */
	access = access_mask_set(haswriteperm, hasreadperm, isowner, isallow);

	if (isallow) {
		access |= ACE_READ_ACL | ACE_READ_ATTRIBUTES;
		if (isowner)
			access |= ACE_WRITE_ACL;
	} else {
		if (! isowner)
			access |= ACE_WRITE_ACL;
	}

	/* read */
	if (mode & 04) {
		access |= ACE_READ_DATA;
	}
	/* write */
	if (mode & 02) {
		access |= ACE_WRITE_DATA |
		    ACE_APPEND_DATA;
		if (isdir)
			access |= ACE_DELETE_CHILD;
	}
	/* exec */
	if (mode & 01) {
		access |= ACE_EXECUTE;
	}

	return (access);
}

/*
 * Given an nfsace (presumably an ALLOW entry), make a
 * corresponding DENY entry at the address given.
 */
static void
ace_make_deny(ace_t *allow, ace_t *deny, int isdir, int isowner)
{
	(void) memcpy(deny, allow, sizeof (ace_t));

	deny->a_who = allow->a_who;

	deny->a_type = ACE_ACCESS_DENIED_ACE_TYPE;
	deny->a_access_mask ^= ACE_POSIX_SUPPORTED_BITS;
	if (isdir)
		deny->a_access_mask ^= ACE_DELETE_CHILD;

	deny->a_access_mask &= ~(ACE_SYNCHRONIZE | ACE_WRITE_OWNER |
	    ACE_DELETE | ACE_WRITE_ATTRIBUTES | ACE_READ_NAMED_ATTRS |
	    ACE_WRITE_NAMED_ATTRS);
	deny->a_access_mask |= access_mask_set((allow->a_access_mask &
	    ACE_WRITE_DATA), (allow->a_access_mask & ACE_READ_DATA), isowner,
	    B_FALSE);
}
/*
 * Make an initial pass over an array of aclent_t's.  Gather
 * information such as an ACL_MASK (if any), number of users,
 * number of groups, and whether the array needs to be sorted.
 */
static int
ln_aent_preprocess(aclent_t *aclent, int n,
    int *hasmask, mode_t *mask,
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
				error = EINVAL;
				goto out;
			} else {
				*hasmask = 1;
				*mask = aclent[i].a_perm;
			}
		}
	}

	if ((! *hasmask) && (*numuser + *numgroup > 1)) {
		error = EINVAL;
		goto out;
	}

out:
	return (error);
}

/*
 * Convert an array of aclent_t into an array of nfsace entries,
 * following POSIX draft -> nfsv4 conversion semantics as outlined in
 * the IETF draft.
 */
static int
ln_aent_to_ace(aclent_t *aclent, int n, ace_t **acepp, int *rescount, int isdir)
{
	int error = 0;
	mode_t mask;
	int numuser, numgroup, needsort;
	int resultsize = 0;
	int i, groupi = 0, skip;
	ace_t *acep, *result = NULL;
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

	result = acep = calloc(1, resultsize * sizeof (ace_t));
	if (result == NULL)
		goto out;

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
			acep->a_type = ACE_ACCESS_DENIED_ACE_TYPE;
			acep->a_flags = 0;
			if (aclent[i].a_type & GROUP_OBJ) {
				acep->a_who = -1;
				acep->a_flags |=
				    (ACE_IDENTIFIER_GROUP|ACE_GROUP);
			} else if (aclent[i].a_type & USER) {
				acep->a_who = aclent[i].a_id;
			} else {
				acep->a_who = aclent[i].a_id;
				acep->a_flags |= ACE_IDENTIFIER_GROUP;
			}
			if (aclent[i].a_type & ACL_DEFAULT) {
				acep->a_flags |= ACE_INHERIT_ONLY_ACE |
				    ACE_FILE_INHERIT_ACE |
				    ACE_DIRECTORY_INHERIT_ACE;
			}
			/*
			 * Set the access mask for the prepended deny
			 * ace.  To do this, we invert the mask (found
			 * in ln_aent_preprocess()) then convert it to an
			 * DENY ace access_mask.
			 */
			acep->a_access_mask = mode_to_ace_access((mask ^ 07),
			    isdir, 0, 0);
			acep += 1;
		}

		/* handle a_perm -> access_mask */
		acep->a_access_mask = mode_to_ace_access(aclent[i].a_perm,
		    isdir, aclent[i].a_type & USER_OBJ, 1);

		/* emulate a default aclent */
		if (aclent[i].a_type & ACL_DEFAULT) {
			acep->a_flags |= ACE_INHERIT_ONLY_ACE |
			    ACE_FILE_INHERIT_ACE |
			    ACE_DIRECTORY_INHERIT_ACE;
		}

		/*
		 * handle a_perm and a_id
		 *
		 * this must be done last, since it involves the
		 * corresponding deny aces, which are handled
		 * differently for each different a_type.
		 */
		if (aclent[i].a_type & USER_OBJ) {
			acep->a_who = -1;
			acep->a_flags |= ACE_OWNER;
			ace_make_deny(acep, acep + 1, isdir, B_TRUE);
			acep += 2;
		} else if (aclent[i].a_type & USER) {
			acep->a_who = aclent[i].a_id;
			ace_make_deny(acep, acep + 1, isdir, B_FALSE);
			acep += 2;
		} else if (aclent[i].a_type & (GROUP_OBJ | GROUP)) {
			if (aclent[i].a_type & GROUP_OBJ) {
				acep->a_who = -1;
				acep->a_flags |= ACE_GROUP;
			} else {
				acep->a_who = aclent[i].a_id;
			}
			acep->a_flags |= ACE_IDENTIFIER_GROUP;
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
			ace_make_deny(acep, acep + skip, isdir, B_FALSE);
			/*
			 * If we just did the last group, skip acep past
			 * all of the denies; else, just move ahead one.
			 */
			if (++groupi >= numgroup)
				acep += numgroup + 1;
			else
				acep += 1;
		} else if (aclent[i].a_type & OTHER_OBJ) {
			acep->a_who = -1;
			acep->a_flags |= ACE_EVERYONE;
			ace_make_deny(acep, acep + 1, isdir, B_FALSE);
			acep += 2;
		} else {
			error = EINVAL;
			goto out;
		}
	}

	*acepp = result;
	*rescount = resultsize;

out:
	if (error != 0) {
		if ((result != NULL) && (resultsize > 0)) {
			free(result);
		}
	}

	return (error);
}

static int
convert_aent_to_ace(aclent_t *aclentp, int aclcnt, int isdir,
    ace_t **retacep, int *retacecnt)
{
	ace_t *acep;
	ace_t *dfacep;
	int acecnt = 0;
	int dfacecnt = 0;
	int dfaclstart = 0;
	int dfaclcnt = 0;
	aclent_t *aclp;
	int i;
	int error;

	ksort((caddr_t)aclentp, aclcnt, sizeof (aclent_t), cmp2acls);

	for (i = 0, aclp = aclentp; i < aclcnt; aclp++, i++) {
		if (aclp->a_type & ACL_DEFAULT)
			break;
	}

	if (i < aclcnt) {
		dfaclstart = i;
		dfaclcnt = aclcnt - i;
	}

	if (dfaclcnt && isdir == 0) {
		return (-1);
	}

	error = ln_aent_to_ace(aclentp, i,  &acep, &acecnt, isdir);
	if (error)
		return (-1);

	if (dfaclcnt) {
		error = ln_aent_to_ace(&aclentp[dfaclstart], dfaclcnt,
		    &dfacep, &dfacecnt, isdir);
		if (error) {
			if (acep) {
				free(acep);
			}
			return (-1);
		}
	}

	if (dfacecnt != 0) {
		acep = realloc(acep, sizeof (ace_t) * (acecnt + dfacecnt));
		if (acep == NULL)
			return (-1);
		if (dfaclcnt) {
			(void) memcpy(acep + acecnt, dfacep,
			    sizeof (ace_t) * dfacecnt);
		}
	}
	if (dfaclcnt)
		free(dfacep);

	*retacecnt = acecnt + dfacecnt;
	*retacep = acep;
	return (0);
}

static void
acevals_init(acevals_t *vals, uid_t key)
{
	bzero(vals, sizeof (*vals));
	vals->allowed = ACE_MASK_UNDEFINED;
	vals->denied = ACE_MASK_UNDEFINED;
	vals->mask = ACE_MASK_UNDEFINED;
	vals->key = key;
}

static void
ace_list_init(ace_list_t *al, int dfacl_flag)
{
	acevals_init(&al->user_obj, NULL);
	acevals_init(&al->group_obj, NULL);
	acevals_init(&al->other_obj, NULL);
	al->numusers = 0;
	al->numgroups = 0;
	al->acl_mask = 0;
	al->hasmask = 0;
	al->state = ace_unused;
	al->seen = 0;
	al->dfacl_flag = dfacl_flag;
}

/*
 * Find or create an acevals holder for a given id and avl tree.
 *
 * Note that only one thread will ever touch these avl trees, so
 * there is no need for locking.
 */
static acevals_t *
acevals_find(ace_t *ace, avl_tree_t *avl, int *num)
{
	acevals_t key, *rc;
	avl_index_t where;

	key.key = ace->a_who;
	rc = avl_find(avl, &key, &where);
	if (rc != NULL)
		return (rc);

	/* this memory is freed by ln_ace_to_aent()->ace_list_free() */
	rc = calloc(1, sizeof (acevals_t));
	if (rc == NULL)
		return (rc);
	acevals_init(rc, ace->a_who);
	avl_insert(avl, rc, where);
	(*num)++;

	return (rc);
}

static int
access_mask_check(ace_t *acep, int mask_bit, int isowner)
{
	int set_deny, err_deny;
	int set_allow, err_allow;
	int acl_consume;
	int haswriteperm, hasreadperm;

	if (acep->a_type == ACE_ACCESS_DENIED_ACE_TYPE) {
		haswriteperm = (acep->a_access_mask & ACE_WRITE_DATA) ? 0 : 1;
		hasreadperm = (acep->a_access_mask & ACE_READ_DATA) ? 0 : 1;
	} else {
		haswriteperm = (acep->a_access_mask & ACE_WRITE_DATA) ? 1 : 0;
		hasreadperm = (acep->a_access_mask & ACE_READ_DATA) ? 1 : 0;
	}

	acl_consume = (ACL_SYNCHRONIZE_ERR_DENY |
	    ACL_DELETE_ERR_DENY |
	    ACL_WRITE_OWNER_ERR_DENY |
	    ACL_WRITE_OWNER_ERR_ALLOW |
	    ACL_WRITE_ATTRS_OWNER_SET_ALLOW |
	    ACL_WRITE_ATTRS_OWNER_ERR_DENY |
	    ACL_WRITE_ATTRS_WRITER_SET_DENY |
	    ACL_WRITE_ATTRS_WRITER_ERR_ALLOW |
	    ACL_WRITE_NAMED_WRITER_ERR_DENY |
	    ACL_READ_NAMED_READER_ERR_DENY);

	if (mask_bit == ACE_SYNCHRONIZE) {
		set_deny = ACL_SYNCHRONIZE_SET_DENY;
		err_deny =  ACL_SYNCHRONIZE_ERR_DENY;
		set_allow = ACL_SYNCHRONIZE_SET_ALLOW;
		err_allow = ACL_SYNCHRONIZE_ERR_ALLOW;
	} else if (mask_bit == ACE_WRITE_OWNER) {
		set_deny = ACL_WRITE_OWNER_SET_DENY;
		err_deny =  ACL_WRITE_OWNER_ERR_DENY;
		set_allow = ACL_WRITE_OWNER_SET_ALLOW;
		err_allow = ACL_WRITE_OWNER_ERR_ALLOW;
	} else if (mask_bit == ACE_DELETE) {
		set_deny = ACL_DELETE_SET_DENY;
		err_deny =  ACL_DELETE_ERR_DENY;
		set_allow = ACL_DELETE_SET_ALLOW;
		err_allow = ACL_DELETE_ERR_ALLOW;
	} else if (mask_bit == ACE_WRITE_ATTRIBUTES) {
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
			if ((acep->a_access_mask & mask_bit) &&
			    (acep->a_type & ACE_ACCESS_ALLOWED_ACE_TYPE)) {
				return (ENOTSUP);
			}
			return (0);
		}
	} else if (mask_bit == ACE_READ_NAMED_ATTRS) {
		if (!hasreadperm)
			return (0);

		set_deny = ACL_READ_NAMED_READER_SET_DENY;
		err_deny = ACL_READ_NAMED_READER_ERR_DENY;
		set_allow = ACL_READ_NAMED_READER_SET_ALLOW;
		err_allow = ACL_READ_NAMED_READER_ERR_ALLOW;
	} else if (mask_bit == ACE_WRITE_NAMED_ATTRS) {
		if (!haswriteperm)
			return (0);

		set_deny = ACL_WRITE_NAMED_WRITER_SET_DENY;
		err_deny = ACL_WRITE_NAMED_WRITER_ERR_DENY;
		set_allow = ACL_WRITE_NAMED_WRITER_SET_ALLOW;
		err_allow = ACL_WRITE_NAMED_WRITER_ERR_ALLOW;
	} else {
		return (EINVAL);
	}

	if (acep->a_type == ACE_ACCESS_DENIED_ACE_TYPE) {
		if (acl_consume & set_deny) {
			if (!(acep->a_access_mask & mask_bit)) {
				return (ENOTSUP);
			}
		} else if (acl_consume & err_deny) {
			if (acep->a_access_mask & mask_bit) {
				return (ENOTSUP);
			}
		}
	} else {
		/* ACE_ACCESS_ALLOWED_ACE_TYPE */
		if (acl_consume & set_allow) {
			if (!(acep->a_access_mask & mask_bit)) {
				return (ENOTSUP);
			}
		} else if (acl_consume & err_allow) {
			if (acep->a_access_mask & mask_bit) {
				return (ENOTSUP);
			}
		}
	}
	return (0);
}

static int
ace_to_aent_legal(ace_t *acep)
{
	int error = 0;
	int isowner;

	/* only ALLOW or DENY */
	if ((acep->a_type != ACE_ACCESS_ALLOWED_ACE_TYPE) &&
	    (acep->a_type != ACE_ACCESS_DENIED_ACE_TYPE)) {
		error = ENOTSUP;
		goto out;
	}

	/* check for invalid flags */
	if (acep->a_flags & ~(ACE_VALID_FLAG_BITS)) {
		error = EINVAL;
		goto out;
	}

	/* some flags are illegal */
	if (acep->a_flags & (ACE_SUCCESSFUL_ACCESS_ACE_FLAG |
	    ACE_FAILED_ACCESS_ACE_FLAG |
	    ACE_NO_PROPAGATE_INHERIT_ACE)) {
		error = ENOTSUP;
		goto out;
	}

	/* check for invalid masks */
	if (acep->a_access_mask & ~(ACE_VALID_MASK_BITS)) {
		error = EINVAL;
		goto out;
	}

	if ((acep->a_flags & ACE_OWNER)) {
		isowner = 1;
	} else {
		isowner = 0;
	}

	error = access_mask_check(acep, ACE_SYNCHRONIZE, isowner);
	if (error)
		goto out;

	error = access_mask_check(acep, ACE_WRITE_OWNER, isowner);
	if (error)
		goto out;

	error = access_mask_check(acep, ACE_DELETE, isowner);
	if (error)
		goto out;

	error = access_mask_check(acep, ACE_WRITE_ATTRIBUTES, isowner);
	if (error)
		goto out;

	error = access_mask_check(acep, ACE_READ_NAMED_ATTRS, isowner);
	if (error)
		goto out;

	error = access_mask_check(acep, ACE_WRITE_NAMED_ATTRS, isowner);
	if (error)
		goto out;

	/* more detailed checking of masks */
	if (acep->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) {
		if (! (acep->a_access_mask & ACE_READ_ATTRIBUTES)) {
			error = ENOTSUP;
			goto out;
		}
		if ((acep->a_access_mask & ACE_WRITE_DATA) &&
		    (! (acep->a_access_mask & ACE_APPEND_DATA))) {
			error = ENOTSUP;
			goto out;
		}
		if ((! (acep->a_access_mask & ACE_WRITE_DATA)) &&
		    (acep->a_access_mask & ACE_APPEND_DATA)) {
			error = ENOTSUP;
			goto out;
		}
	}

	/* ACL enforcement */
	if ((acep->a_access_mask & ACE_READ_ACL) &&
	    (acep->a_type != ACE_ACCESS_ALLOWED_ACE_TYPE)) {
		error = ENOTSUP;
		goto out;
	}
	if (acep->a_access_mask & ACE_WRITE_ACL) {
		if ((acep->a_type == ACE_ACCESS_DENIED_ACE_TYPE) &&
		    (isowner)) {
			error = ENOTSUP;
			goto out;
		}
		if ((acep->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) &&
		    (! isowner)) {
			error = ENOTSUP;
			goto out;
		}
	}

out:
	return (error);
}

static int
ace_mask_to_mode(uint32_t  mask, o_mode_t *modep, int isdir)
{
	int error = 0;
	o_mode_t mode = 0;
	uint32_t bits, wantbits;

	/* read */
	if (mask & ACE_READ_DATA)
		mode |= 04;

	/* write */
	wantbits = (ACE_WRITE_DATA | ACE_APPEND_DATA);
	if (isdir)
		wantbits |= ACE_DELETE_CHILD;
	bits = mask & wantbits;
	if (bits != 0) {
		if (bits != wantbits) {
			error = ENOTSUP;
			goto out;
		}
		mode |= 02;
	}

	/* exec */
	if (mask & ACE_EXECUTE) {
		mode |= 01;
	}

	*modep = mode;

out:
	return (error);
}

static int
ace_allow_to_mode(uint32_t mask, o_mode_t *modep, int isdir)
{
	/* ACE_READ_ACL and ACE_READ_ATTRIBUTES must both be set */
	if ((mask & (ACE_READ_ACL | ACE_READ_ATTRIBUTES)) !=
	    (ACE_READ_ACL | ACE_READ_ATTRIBUTES)) {
		return (ENOTSUP);
	}

	return (ace_mask_to_mode(mask, modep, isdir));
}

static int
acevals_to_aent(acevals_t *vals, aclent_t *dest, ace_list_t *list,
    uid_t owner, gid_t group, int isdir)
{
	int error;
	uint32_t  flips = ACE_POSIX_SUPPORTED_BITS;

	if (isdir)
		flips |= ACE_DELETE_CHILD;
	if (vals->allowed != (vals->denied ^ flips)) {
		error = ENOTSUP;
		goto out;
	}
	if ((list->hasmask) && (list->acl_mask != vals->mask) &&
	    (vals->aent_type & (USER | GROUP | GROUP_OBJ))) {
		error = ENOTSUP;
		goto out;
	}
	error = ace_allow_to_mode(vals->allowed, &dest->a_perm, isdir);
	if (error != 0)
		goto out;
	dest->a_type = vals->aent_type;
	if (dest->a_type & (USER | GROUP)) {
		dest->a_id = vals->key;
	} else if (dest->a_type & USER_OBJ) {
		dest->a_id = owner;
	} else if (dest->a_type & GROUP_OBJ) {
		dest->a_id = group;
	} else if (dest->a_type & OTHER_OBJ) {
		dest->a_id = 0;
	} else {
		error = EINVAL;
		goto out;
	}

out:
	return (error);
}

static int
ace_list_to_aent(ace_list_t *list, aclent_t **aclentp, int *aclcnt,
    uid_t owner, gid_t group, int isdir)
{
	int error = 0;
	aclent_t *aent, *result = NULL;
	acevals_t *vals;
	int resultcount;

	if ((list->seen & (USER_OBJ | GROUP_OBJ | OTHER_OBJ)) !=
	    (USER_OBJ | GROUP_OBJ | OTHER_OBJ)) {
		error = ENOTSUP;
		goto out;
	}
	if ((! list->hasmask) && (list->numusers + list->numgroups > 0)) {
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

	result = aent = calloc(1, resultcount * sizeof (aclent_t));

	if (result == NULL) {
		error = ENOMEM;
		goto out;
	}

	/* USER_OBJ */
	if (!(list->user_obj.aent_type & USER_OBJ)) {
		error = EINVAL;
		goto out;
	}

	error = acevals_to_aent(&list->user_obj, aent, list, owner, group,
	    isdir);

	if (error != 0)
		goto out;
	++aent;
	/* USER */
	vals = NULL;
	for (vals = avl_first(&list->user); vals != NULL;
	    vals = AVL_NEXT(&list->user, vals)) {
		if (!(vals->aent_type & USER)) {
			error = EINVAL;
			goto out;
		}
		error = acevals_to_aent(vals, aent, list, owner, group,
		    isdir);
		if (error != 0)
			goto out;
		++aent;
	}
	/* GROUP_OBJ */
	if (!(list->group_obj.aent_type & GROUP_OBJ)) {
		error = EINVAL;
		goto out;
	}
	error = acevals_to_aent(&list->group_obj, aent, list, owner, group,
	    isdir);
	if (error != 0)
		goto out;
	++aent;
	/* GROUP */
	vals = NULL;
	for (vals = avl_first(&list->group); vals != NULL;
	    vals = AVL_NEXT(&list->group, vals)) {
		if (!(vals->aent_type & GROUP)) {
			error = EINVAL;
			goto out;
		}
		error = acevals_to_aent(vals, aent, list, owner, group,
		    isdir);
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
			uint32_t flips = ACE_POSIX_SUPPORTED_BITS;
			if (isdir)
				flips |= ACE_DELETE_CHILD;
			error = ace_mask_to_mode(list->acl_mask ^ flips,
			    &aent->a_perm, isdir);
			if (error != 0)
				goto out;
		} else {
			/* fabricate the ACL_MASK from the group permissions */
			error = ace_mask_to_mode(list->group_obj.allowed,
			    &aent->a_perm, isdir);
			if (error != 0)
				goto out;
		}
		aent->a_id = 0;
		aent->a_type = CLASS_OBJ | list->dfacl_flag;
		++aent;
	}
	/* OTHER_OBJ */
	if (!(list->other_obj.aent_type & OTHER_OBJ)) {
		error = EINVAL;
		goto out;
	}
	error = acevals_to_aent(&list->other_obj, aent, list, owner, group,
	    isdir);
	if (error != 0)
		goto out;
	++aent;

	*aclentp = result;
	*aclcnt = resultcount;

out:
	if (error != 0) {
		if (result != NULL)
			free(result);
	}

	return (error);
}

/*
 * free all data associated with an ace_list
 */
static void
ace_list_free(ace_list_t *al)
{
	acevals_t *node;
	void *cookie;

	if (al == NULL)
		return;

	cookie = NULL;
	while ((node = avl_destroy_nodes(&al->user, &cookie)) != NULL)
		free(node);
	cookie = NULL;
	while ((node = avl_destroy_nodes(&al->group, &cookie)) != NULL)
		free(node);

	avl_destroy(&al->user);
	avl_destroy(&al->group);

	/* free the container itself */
	free(al);
}

static int
acevals_compare(const void *va, const void *vb)
{
	const acevals_t *a = va, *b = vb;

	if (a->key == b->key)
		return (0);

	if (a->key > b->key)
		return (1);

	else
		return (-1);
}

/*
 * Convert a list of ace_t entries to equivalent regular and default
 * aclent_t lists.  Return error (ENOTSUP) when conversion is not possible.
 */
static int
ln_ace_to_aent(ace_t *ace, int n, uid_t owner, gid_t group,
    aclent_t **aclentp, int *aclcnt, aclent_t **dfaclentp, int *dfaclcnt,
    int isdir)
{
	int error = 0;
	ace_t *acep;
	uint32_t bits;
	int i;
	ace_list_t *normacl = NULL, *dfacl = NULL, *acl;
	acevals_t *vals;

	*aclentp = NULL;
	*aclcnt = 0;
	*dfaclentp = NULL;
	*dfaclcnt = 0;

	/* we need at least user_obj, group_obj, and other_obj */
	if (n < 6) {
		error = ENOTSUP;
		goto out;
	}
	if (ace == NULL) {
		error = EINVAL;
		goto out;
	}

	normacl = calloc(1, sizeof (ace_list_t));

	if (normacl == NULL) {
		error = errno;
		goto out;
	}

	avl_create(&normacl->user, acevals_compare, sizeof (acevals_t),
	    offsetof(acevals_t, avl));
	avl_create(&normacl->group, acevals_compare, sizeof (acevals_t),
	    offsetof(acevals_t, avl));

	ace_list_init(normacl, 0);

	dfacl = calloc(1, sizeof (ace_list_t));
	if (dfacl == NULL) {
		error = errno;
		goto out;
	}
	avl_create(&dfacl->user, acevals_compare, sizeof (acevals_t),
	    offsetof(acevals_t, avl));
	avl_create(&dfacl->group, acevals_compare, sizeof (acevals_t),
	    offsetof(acevals_t, avl));
	ace_list_init(dfacl, ACL_DEFAULT);

	/* process every ace_t... */
	for (i = 0; i < n; i++) {
		acep = &ace[i];

		/* rule out certain cases quickly */
		error = ace_to_aent_legal(acep);
		if (error != 0)
			goto out;

		/*
		 * Turn off these bits in order to not have to worry about
		 * them when doing the checks for compliments.
		 */
		acep->a_access_mask &= ~(ACE_WRITE_OWNER | ACE_DELETE |
		    ACE_SYNCHRONIZE | ACE_WRITE_ATTRIBUTES |
		    ACE_READ_NAMED_ATTRS | ACE_WRITE_NAMED_ATTRS);

		/* see if this should be a regular or default acl */
		bits = acep->a_flags &
		    (ACE_INHERIT_ONLY_ACE |
		    ACE_FILE_INHERIT_ACE |
		    ACE_DIRECTORY_INHERIT_ACE);
		if (bits != 0) {
			/* all or nothing on these inherit bits */
			if (bits != (ACE_INHERIT_ONLY_ACE |
			    ACE_FILE_INHERIT_ACE |
			    ACE_DIRECTORY_INHERIT_ACE)) {
				error = ENOTSUP;
				goto out;
			}
			acl = dfacl;
		} else {
			acl = normacl;
		}

		if ((acep->a_flags & ACE_OWNER)) {
			if (acl->state > ace_user_obj) {
				error = ENOTSUP;
				goto out;
			}
			acl->state = ace_user_obj;
			acl->seen |= USER_OBJ;
			vals = &acl->user_obj;
			vals->aent_type = USER_OBJ | acl->dfacl_flag;
		} else if ((acep->a_flags & ACE_EVERYONE)) {
			acl->state = ace_other_obj;
			acl->seen |= OTHER_OBJ;
			vals = &acl->other_obj;
			vals->aent_type = OTHER_OBJ | acl->dfacl_flag;
		} else if (acep->a_flags & ACE_IDENTIFIER_GROUP) {
			if (acl->state > ace_group) {
				error = ENOTSUP;
				goto out;
			}
			if ((acep->a_flags & ACE_GROUP)) {
				acl->seen |= GROUP_OBJ;
				vals = &acl->group_obj;
				vals->aent_type = GROUP_OBJ | acl->dfacl_flag;
			} else {
				acl->seen |= GROUP;
				vals = acevals_find(acep, &acl->group,
				    &acl->numgroups);
				if (vals == NULL) {
					error = ENOMEM;
					goto out;
				}
				vals->aent_type = GROUP | acl->dfacl_flag;
			}
			acl->state = ace_group;
		} else {
			if (acl->state > ace_user) {
				error = ENOTSUP;
				goto out;
			}
			acl->state = ace_user;
			acl->seen |= USER;
			vals = acevals_find(acep, &acl->user,
			    &acl->numusers);
			if (vals == NULL) {
				error = ENOMEM;
				goto out;
			}
			vals->aent_type = USER | acl->dfacl_flag;
		}

		if (!(acl->state > ace_unused)) {
			error = EINVAL;
			goto out;
		}

		if (acep->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) {
			/* no more than one allowed per aclent_t */
			if (vals->allowed != ACE_MASK_UNDEFINED) {
				error = ENOTSUP;
				goto out;
			}
			vals->allowed = acep->a_access_mask;
		} else {
			/*
			 * it's a DENY; if there was a previous DENY, it
			 * must have been an ACL_MASK.
			 */
			if (vals->denied != ACE_MASK_UNDEFINED) {
				/* ACL_MASK is for USER and GROUP only */
				if ((acl->state != ace_user) &&
				    (acl->state != ace_group)) {
					error = ENOTSUP;
					goto out;
				}

				if (! acl->hasmask) {
					acl->hasmask = 1;
					acl->acl_mask = vals->denied;
				/* check for mismatched ACL_MASK emulations */
				} else if (acl->acl_mask != vals->denied) {
					error = ENOTSUP;
					goto out;
				}
				vals->mask = vals->denied;
			}
			vals->denied = acep->a_access_mask;
		}
	}

	/* done collating; produce the aclent_t lists */
	if (normacl->state != ace_unused) {
		error = ace_list_to_aent(normacl, aclentp, aclcnt,
		    owner, group, isdir);
		if (error != 0) {
			goto out;
		}
	}
	if (dfacl->state != ace_unused) {
		error = ace_list_to_aent(dfacl, dfaclentp, dfaclcnt,
		    owner, group, isdir);
		if (error != 0) {
			goto out;
		}
	}

out:
	if (normacl != NULL)
		ace_list_free(normacl);
	if (dfacl != NULL)
		ace_list_free(dfacl);

	return (error);
}

static int
convert_ace_to_aent(ace_t *acebufp, int acecnt, int isdir,
    uid_t owner, gid_t group, aclent_t **retaclentp, int *retaclcnt)
{
	int error;
	aclent_t *aclentp, *dfaclentp;
	int aclcnt, dfaclcnt;

	error = ln_ace_to_aent(acebufp, acecnt, owner, group,
	    &aclentp, &aclcnt, &dfaclentp, &dfaclcnt, isdir);

	if (error)
		return (error);


	if (dfaclcnt != 0) {
		/*
		 * Slap aclentp and dfaclentp into a single array.
		 */
		aclentp = realloc(aclentp, (sizeof (aclent_t) * aclcnt) +
		    (sizeof (aclent_t) * dfaclcnt));
		if (aclentp != NULL) {
			(void) memcpy(aclentp + aclcnt,
			    dfaclentp, sizeof (aclent_t) * dfaclcnt);
		} else {
			error = -1;
		}
	}

	if (aclentp) {
		*retaclentp = aclentp;
		*retaclcnt = aclcnt + dfaclcnt;
	}

	if (dfaclentp)
		free(dfaclentp);

	return (error);
}

static int
cacl_get(acl_inp inp, int get_flag, int type, acl_t **aclp)
{
	const char *fname;
	int fd;
	int ace_acl = 0;
	int error;
	int getcmd, cntcmd;
	acl_t *acl_info;
	int	save_errno;
	int	stat_error;
	struct stat64 statbuf;

	*aclp = NULL;
	if (type == ACL_PATH) {
		fname = inp.file;
		ace_acl = pathconf(fname, _PC_ACL_ENABLED);
	} else {
		fd = inp.fd;
		ace_acl = fpathconf(fd, _PC_ACL_ENABLED);
	}

	/*
	 * if acl's aren't supported then
	 * send it through the old GETACL interface
	 */
	if (ace_acl == 0 || ace_acl == -1) {
		ace_acl = _ACL_ACLENT_ENABLED;
	}

	if (ace_acl & _ACL_ACE_ENABLED) {
		cntcmd = ACE_GETACLCNT;
		getcmd = ACE_GETACL;
		acl_info = acl_alloc(ACE_T);
	} else {
		cntcmd = GETACLCNT;
		getcmd = GETACL;
		acl_info = acl_alloc(ACLENT_T);
	}

	if (acl_info == NULL)
		return (-1);

	if (type == ACL_PATH) {
		acl_info->acl_cnt = acl(fname, cntcmd, 0, NULL);
	} else {
		acl_info->acl_cnt = facl(fd, cntcmd, 0, NULL);
	}

	save_errno = errno;
	if (acl_info->acl_cnt < 0) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}

	if (acl_info->acl_cnt == 0) {
		acl_free(acl_info);
		errno = save_errno;
		return (0);
	}

	acl_info->acl_aclp =
	    malloc(acl_info->acl_cnt * acl_info->acl_entry_size);
	save_errno = errno;

	if (acl_info->acl_aclp == NULL) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}

	if (type == ACL_PATH) {
		stat_error = stat64(fname, &statbuf);
		error = acl(fname, getcmd, acl_info->acl_cnt,
		    acl_info->acl_aclp);
	} else {
		stat_error = fstat64(fd, &statbuf);
		error = facl(fd, getcmd, acl_info->acl_cnt,
		    acl_info->acl_aclp);
	}

	save_errno = errno;
	if (error == -1) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}


	if (stat_error == 0) {
		acl_info->acl_flags =
		    (S_ISDIR(statbuf.st_mode) ? ACL_IS_DIR : 0);
	} else
		acl_info->acl_flags = 0;

	switch (acl_info->acl_type) {
	case ACLENT_T:
		if (acl_info->acl_cnt <= MIN_ACL_ENTRIES)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;
		break;
	case ACE_T:
		if (ace_trivial(acl_info->acl_aclp, acl_info->acl_cnt) == 0)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;
		break;
	default:
		errno = EINVAL;
		acl_free(acl_info);
		return (-1);
	}

	if ((acl_info->acl_flags & ACL_IS_TRIVIAL) &&
	    (get_flag & ACL_NO_TRIVIAL)) {
		acl_free(acl_info);
		errno = 0;
		return (0);
	}

	*aclp = acl_info;
	return (0);
}

/*
 * return -1 on failure, otherwise the number of acl
 * entries is returned
 */
int
acl_get(const char *path, int get_flag, acl_t **aclp)
{
	acl_inp acl_inp;
	acl_inp.file = path;

	return (cacl_get(acl_inp, get_flag, ACL_PATH, aclp));
}

int
facl_get(int fd, int get_flag, acl_t **aclp)
{

	acl_inp acl_inp;
	acl_inp.fd = fd;

	return (cacl_get(acl_inp, get_flag, ACL_FD, aclp));
}

static int
acl_translate(acl_t *aclp, int target_flavor, int isdir, uid_t owner,
    gid_t group)
{
	int aclcnt;
	void *acldata;
	int error;

	/*
	 * See if we need to translate
	 */
	if ((target_flavor == _ACL_ACE_ENABLED && aclp->acl_type == ACE_T) ||
	    (target_flavor == _ACL_ACLENT_ENABLED &&
	    aclp->acl_type == ACLENT_T))
		return (0);

	if (target_flavor == -1)
		return (-1);

	if (target_flavor ==  _ACL_ACE_ENABLED &&
	    aclp->acl_type == ACLENT_T) {
		error = convert_aent_to_ace(aclp->acl_aclp,
		    aclp->acl_cnt, isdir, (ace_t **)&acldata, &aclcnt);
		if (error) {
			errno = error;
			return (-1);
		}
	} else if (target_flavor == _ACL_ACLENT_ENABLED &&
	    aclp->acl_type == ACE_T) {
		error = convert_ace_to_aent(aclp->acl_aclp, aclp->acl_cnt,
		    isdir, owner, group, (aclent_t **)&acldata, &aclcnt);
		if (error) {
			errno = error;
			return (-1);
		}
	} else {
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * replace old acl with newly translated acl
	 */
	free(aclp->acl_aclp);
	aclp->acl_aclp = acldata;
	aclp->acl_cnt = aclcnt;
	aclp->acl_type = (target_flavor == _ACL_ACE_ENABLED) ? ACE_T : ACLENT_T;
	return (0);
}

/*
 * Set an ACL, translates acl to ace_t when appropriate.
 */
static int
cacl_set(acl_inp *acl_inp, acl_t *aclp, int type)
{
	int error = 0;
	int acl_flavor_target;
	struct stat64 statbuf;
	int stat_error;
	int isdir;


	if (type == ACL_PATH) {
		stat_error = stat64(acl_inp->file, &statbuf);
		if (stat_error)
			return (-1);
		acl_flavor_target = pathconf(acl_inp->file, _PC_ACL_ENABLED);
	} else {
		stat_error = fstat64(acl_inp->fd, &statbuf);
		if (stat_error)
			return (-1);
		acl_flavor_target = fpathconf(acl_inp->fd, _PC_ACL_ENABLED);
	}

	/*
	 * If target returns an error or 0 from pathconf call then
	 * fall back to UFS/POSIX Draft interface.
	 * In the case of 0 we will then fail in either acl(2) or
	 * acl_translate().  We could erroneously get 0 back from
	 * a file system that is using fs_pathconf() and not answering
	 * the _PC_ACL_ENABLED question itself.
	 */
	if (acl_flavor_target == 0 || acl_flavor_target == -1)
		acl_flavor_target = _ACL_ACLENT_ENABLED;

	isdir = S_ISDIR(statbuf.st_mode);

	if ((error = acl_translate(aclp, acl_flavor_target, isdir,
	    statbuf.st_uid, statbuf.st_gid)) != 0) {
		return (error);
	}

	if (type == ACL_PATH) {
		error = acl(acl_inp->file,
		    (aclp->acl_type == ACE_T) ? ACE_SETACL : SETACL,
		    aclp->acl_cnt, aclp->acl_aclp);
	} else {
		error = facl(acl_inp->fd,
		    (aclp->acl_type == ACE_T) ? ACE_SETACL : SETACL,
		    aclp->acl_cnt, aclp->acl_aclp);
	}

	return (error);
}

int
acl_set(const char *path, acl_t *aclp)
{
	acl_inp acl_inp;

	acl_inp.file = path;

	return (cacl_set(&acl_inp, aclp, ACL_PATH));
}

int
facl_set(int fd, acl_t *aclp)
{
	acl_inp acl_inp;

	acl_inp.fd = fd;

	return (cacl_set(&acl_inp, aclp, ACL_FD));
}

int
acl_cnt(acl_t *aclp)
{
	return (aclp->acl_cnt);
}

int
acl_type(acl_t *aclp)
{
	return (aclp->acl_type);
}

acl_t *
acl_dup(acl_t *aclp)
{
	acl_t *newaclp;

	newaclp = acl_alloc(aclp->acl_type);
	if (newaclp == NULL)
		return (NULL);

	newaclp->acl_aclp = malloc(aclp->acl_entry_size * aclp->acl_cnt);
	if (newaclp->acl_aclp == NULL) {
		acl_free(newaclp);
		return (NULL);
	}

	(void) memcpy(newaclp->acl_aclp,
	    aclp->acl_aclp, aclp->acl_entry_size * aclp->acl_cnt);
	newaclp->acl_cnt = aclp->acl_cnt;

	return (newaclp);
}

int
acl_flags(acl_t *aclp)
{
	return (aclp->acl_flags);
}

void *
acl_data(acl_t *aclp)
{
	return (aclp->acl_aclp);
}

/*
 * Remove an ACL from a file and create a trivial ACL based
 * off of the mode argument.  After acl has been set owner/group
 * are updated to match owner,group arguments
 */
int
acl_strip(const char *file, uid_t owner, gid_t group, mode_t mode)
{
	int	error = 0;
	aclent_t min_acl[MIN_ACL_ENTRIES];
	ace_t	min_ace_acl[6];	/* owner, group, everyone + complement denies */
	int	acl_flavor;
	int	aclcnt;

	acl_flavor = pathconf(file, _PC_ACL_ENABLED);

	/*
	 * force it through aclent flavor when file system doesn't
	 * understand question
	 */
	if (acl_flavor == 0 || acl_flavor == -1)
		acl_flavor = _ACL_ACLENT_ENABLED;

	if (acl_flavor & _ACL_ACLENT_ENABLED) {
		min_acl[0].a_type = USER_OBJ;
		min_acl[0].a_id   = owner;
		min_acl[0].a_perm = ((mode & 0700) >> 6);
		min_acl[1].a_type = GROUP_OBJ;
		min_acl[1].a_id   = group;
		min_acl[1].a_perm = ((mode & 0070) >> 3);
		min_acl[2].a_type = CLASS_OBJ;
		min_acl[2].a_id   = (uid_t)-1;
		min_acl[2].a_perm = ((mode & 0070) >> 3);
		min_acl[3].a_type = OTHER_OBJ;
		min_acl[3].a_id   = (uid_t)-1;
		min_acl[3].a_perm = (mode & 0007);
		aclcnt = 4;
		error = acl(file, SETACL, aclcnt, min_acl);
	} else if (acl_flavor & _ACL_ACE_ENABLED) {
		(void) memcpy(min_ace_acl, trivial_acl, sizeof (ace_t) * 6);

		/*
		 * Make aces match request mode
		 */
		adjust_ace_pair(&min_ace_acl[0], (mode & 0700) >> 6);
		adjust_ace_pair(&min_ace_acl[2], (mode & 0070) >> 3);
		adjust_ace_pair(&min_ace_acl[4], mode & 0007);

		error = acl(file, ACE_SETACL, 6, min_ace_acl);
	} else {
		errno = EINVAL;
		error = 1;
	}

	if (error == 0)
		error = chown(file, owner, group);
	return (error);
}

static int
ace_match(void *entry1, void *entry2)
{
	ace_t *p1 = (ace_t *)entry1;
	ace_t *p2 = (ace_t *)entry2;
	ace_t ace1, ace2;

	ace1 = *p1;
	ace2 = *p2;

	/*
	 * Need to fixup who field for abstrations for
	 * accurate comparison, since field is undefined.
	 */
	if (ace1.a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE))
		ace1.a_who = -1;
	if (ace2.a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE))
		ace2.a_who = -1;
	return (memcmp(&ace1, &ace2, sizeof (ace_t)));
}

static int
aclent_match(void *entry1, void *entry2)
{
	aclent_t *aclent1 = (aclent_t *)entry1;
	aclent_t *aclent2 = (aclent_t *)entry2;

	return (memcmp(aclent1, aclent2, sizeof (aclent_t)));
}

/*
 * Find acl entries in acl that correspond to removeacl.  Search
 * is started from slot.  The flag argument indicates whether to
 * remove all matches or just the first match.
 */
int
acl_removeentries(acl_t *acl, acl_t *removeacl, int start_slot, int flag)
{
	int i, j;
	int match;
	int (*acl_match)(void *acl1, void *acl2);
	void *acl_entry, *remove_entry;
	void *start;
	int found = 0;

	if (flag != ACL_REMOVE_ALL && flag != ACL_REMOVE_FIRST)
		flag = ACL_REMOVE_FIRST;

	if (acl == NULL || removeacl == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (acl->acl_type != removeacl->acl_type)
		return (EACL_DIFF_TYPE);

	if (acl->acl_type == ACLENT_T)
		acl_match = aclent_match;
	else
		acl_match = ace_match;

	for (i = 0, remove_entry = removeacl->acl_aclp;
	    i != removeacl->acl_cnt; i++) {

		j = 0;
		acl_entry = (char *)acl->acl_aclp +
		    (acl->acl_entry_size * start_slot);
		for (;;) {
			match = acl_match(acl_entry, remove_entry);
			if (match == 0)  {
				found++;
				start = (char *)acl_entry +
				    acl->acl_entry_size;
				(void) memmove(acl_entry, start,
				    acl->acl_entry_size *
				    acl->acl_cnt-- - (j + 1));

				if (flag == ACL_REMOVE_FIRST)
					break;
				/*
				 * List has changed, restart search from
				 * beginning.
				 */
				acl_entry = acl->acl_aclp;
				j = 0;
				continue;
			}
			acl_entry = ((char *)acl_entry + acl->acl_entry_size);
			if (++j >= acl->acl_cnt) {
				break;
			}
		}
	}

	return ((found == 0) ? EACL_NO_ACL_ENTRY : 0);
}

/*
 * Replace entires entries in acl1 with the corresponding entries
 * in newentries.  The where argument specifies where to begin
 * the replacement.  If the where argument is 1 greater than the
 * number of acl entries in acl1 then they are appended.  If the
 * where argument is 2+ greater than the number of acl entries then
 * EACL_INVALID_SLOT is returned.
 */
int
acl_modifyentries(acl_t *acl1, acl_t *newentries, int where)
{

	int slot;
	int slots_needed;
	int slots_left;
	int newsize;

	if (acl1 == NULL || newentries == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (where < 0 || where >= acl1->acl_cnt)
		return (EACL_INVALID_SLOT);

	if (acl1->acl_type != newentries->acl_type)
		return (EACL_DIFF_TYPE);

	slot = where;

	slots_left = acl1->acl_cnt - slot + 1;
	if (slots_left < newentries->acl_cnt) {
		slots_needed = newentries->acl_cnt - slots_left;
		newsize = (acl1->acl_entry_size * acl1->acl_cnt) +
		    (acl1->acl_entry_size * slots_needed);
		acl1->acl_aclp = realloc(acl1->acl_aclp, newsize);
		if (acl1->acl_aclp == NULL)
			return (-1);
	}
	(void) memcpy((char *)acl1->acl_aclp + (acl1->acl_entry_size * slot),
	    newentries->acl_aclp,
	    newentries->acl_entry_size * newentries->acl_cnt);

	/*
	 * Did ACL grow?
	 */

	if ((slot + newentries->acl_cnt) > acl1->acl_cnt) {
		acl1->acl_cnt = slot + newentries->acl_cnt;
	}

	return (0);
}

/*
 * Add acl2 entries into acl1.  The where argument specifies where
 * to add the entries.
 */
int
acl_addentries(acl_t *acl1, acl_t *acl2, int where)
{

	int newsize;
	int len;
	void *start;
	void *to;

	if (acl1 == NULL || acl2 == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (acl1->acl_type != acl2->acl_type)
		return (EACL_DIFF_TYPE);

	/*
	 * allow where to specify 1 past last slot for an append operation
	 * but anything greater is an error.
	 */
	if (where < 0 || where > acl1->acl_cnt)
		return (EACL_INVALID_SLOT);

	newsize = (acl2->acl_entry_size * acl2->acl_cnt) +
	    (acl1->acl_entry_size * acl1->acl_cnt);
	acl1->acl_aclp = realloc(acl1->acl_aclp, newsize);
	if (acl1->acl_aclp == NULL)
		return (-1);

	/*
	 * first push down entries where new ones will be inserted
	 */

	to = (void *)((char *)acl1->acl_aclp +
	    ((where + acl2->acl_cnt) * acl1->acl_entry_size));

	start = (void *)((char *)acl1->acl_aclp +
	    where * acl1->acl_entry_size);

	if (where < acl1->acl_cnt) {
		len = (acl1->acl_cnt - where) * acl1->acl_entry_size;
		(void) memmove(to, start, len);
	}

	/*
	 * now stick in new entries.
	 */

	(void) memmove(start, acl2->acl_aclp,
	    acl2->acl_cnt * acl2->acl_entry_size);

	acl1->acl_cnt += acl2->acl_cnt;
	return (0);
}

/*
 * return text for an ACL error.
 */
char *
acl_strerror(int errnum)
{
	switch (errnum) {
	case EACL_GRP_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one group or default group entry"));
	case EACL_USER_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one user or default user entry"));
	case EACL_OTHER_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one other entry"));
	case EACL_CLASS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one mask entry"));
	case EACL_DUPLICATE_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate user or group entries"));
	case EACL_MISS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Missing user/group owner, other, mask entry"));
	case EACL_MEM_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Memory error"));
	case EACL_ENTRY_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Unrecognized entry type"));
	case EACL_INHERIT_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid inheritance flags"));
	case EACL_FLAGS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Unrecognized entry flags"));
	case EACL_PERM_MASK_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL permissions"));
	case EACL_COUNT_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL count"));
	case EACL_INVALID_SLOT:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL entry number specified"));
	case EACL_NO_ACL_ENTRY:
		return (dgettext(TEXT_DOMAIN,
		    "ACL entry doesn't exist"));
	case EACL_DIFF_TYPE:
		return (dgettext(TEXT_DOMAIN,
		    "ACL type's are different"));
	case EACL_INVALID_USER_GROUP:
		return (dgettext(TEXT_DOMAIN, "Invalid user or group"));
	case EACL_INVALID_STR:
		return (dgettext(TEXT_DOMAIN, "ACL string is invalid"));
	case EACL_FIELD_NOT_BLANK:
		return (dgettext(TEXT_DOMAIN, "Field expected to be blank"));
	case EACL_INVALID_ACCESS_TYPE:
		return (dgettext(TEXT_DOMAIN, "Invalid access type"));
	case EACL_UNKNOWN_DATA:
		return (dgettext(TEXT_DOMAIN, "Unrecognized entry"));
	case EACL_MISSING_FIELDS:
		return (dgettext(TEXT_DOMAIN,
		    "ACL specification missing required fields"));
	case EACL_INHERIT_NOTDIR:
		return (dgettext(TEXT_DOMAIN,
		    "Inheritance flags are only allowed on directories"));
	case -1:
		return (strerror(errno));
	default:
		errno = EINVAL;
		return (dgettext(TEXT_DOMAIN, "Unknown error"));
	}
}

extern int yyinteractive;

/* PRINTFLIKE1 */
void
acl_error(const char *fmt, ...)
{
	va_list va;

	if (yyinteractive == 0)
		return;

	va_start(va, fmt);
	(void) vfprintf(stderr, fmt, va);
	va_end(va);
}
