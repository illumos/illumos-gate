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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

/*
 * aclcheck(): check validity of an ACL
 *	A valid ACL is defined as follows:
 *	There must be exactly one USER_OBJ, GROUP_OBJ, and OTHER_OBJ entry.
 *	If there are any USER entries, then the user id must be unique.
 *	If there are any GROUP entries, then the group id must be unique.
 *	If there are any GROUP or USER entries, there must be exactly one
 *	CLASS_OBJ entry.
 *	The same rules apply to default ACL entries.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <aclutils.h>

struct entry {
	int	count;
	uid_t	*id;
};

struct entry_stat {
	struct entry	user_obj;
	struct entry	user;
	struct entry	group_obj;
	struct entry	group;
	struct entry	other_obj;
	struct entry	class_obj;
	struct entry	def_user_obj;
	struct entry	def_user;
	struct entry	def_group_obj;
	struct entry	def_group;
	struct entry	def_other_obj;
	struct entry	def_class_obj;
};

static void free_mem(struct entry_stat *);
static int check_dup(int, uid_t *, uid_t, struct entry_stat *);

static int
aclent_aclcheck(aclent_t *aclbufp, int nentries,  int *which, int isdir)
{
	struct entry_stat	tally;
	aclent_t		*aclentp;
	uid_t			**idp;
	int			cnt;

	*which = -1;
	memset(&tally, '\0', sizeof (tally));

	for (aclentp = aclbufp; nentries > 0; nentries--, aclentp++) {
		switch (aclentp->a_type) {
		case USER_OBJ:
			/* check uniqueness */
			if (tally.user_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_USER_ERROR);
			}
			tally.user_obj.count = 1;
			break;

		case GROUP_OBJ:
			/* check uniqueness */
			if (tally.group_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_GRP_ERROR);
			}
			tally.group_obj.count = 1;
			break;

		case OTHER_OBJ:
			/* check uniqueness */
			if (tally.other_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_OTHER_ERROR);
			}
			tally.other_obj.count = 1;
			break;

		case CLASS_OBJ:
			/* check uniqueness */
			if (tally.class_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_CLASS_ERROR);
			}
			tally.class_obj.count = 1;
			break;

		case USER:
		case GROUP:
		case DEF_USER:
		case DEF_GROUP:
			/* check duplicate */
			if (aclentp->a_type == DEF_USER) {
				cnt = (tally.def_user.count)++;
				idp = &(tally.def_user.id);
			} else if (aclentp->a_type == DEF_GROUP) {
				cnt = (tally.def_group.count)++;
				idp = &(tally.def_group.id);
			} else if (aclentp->a_type == USER) {
				cnt = (tally.user.count)++;
				idp = &(tally.user.id);
			} else {
				cnt = (tally.group.count)++;
				idp = &(tally.group.id);
			}

			if (cnt == 0) {
				*idp = calloc(nentries, sizeof (uid_t));
				if (*idp == NULL)
					return (EACL_MEM_ERROR);
			} else {
				if (check_dup(cnt, *idp, aclentp->a_id,
				    &tally) == -1) {
					*which = (int)(aclentp - aclbufp);
					return (EACL_DUPLICATE_ERROR);
				}
			}
			(*idp)[cnt] = aclentp->a_id;
			break;

		case DEF_USER_OBJ:
			/* check uniqueness */
			if (tally.def_user_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_USER_ERROR);
			}
			tally.def_user_obj.count = 1;
			break;

		case DEF_GROUP_OBJ:
			/* check uniqueness */
			if (tally.def_group_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_GRP_ERROR);
			}
			tally.def_group_obj.count = 1;
			break;

		case DEF_OTHER_OBJ:
			/* check uniqueness */
			if (tally.def_other_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_OTHER_ERROR);
			}
			tally.def_other_obj.count = 1;
			break;

		case DEF_CLASS_OBJ:
			/* check uniqueness */
			if (tally.def_class_obj.count > 0) {
				*which = (int)(aclentp - aclbufp);
				(void) free_mem(&tally);
				errno = EINVAL;
				return (EACL_CLASS_ERROR);
			}
			tally.def_class_obj.count = 1;
			break;

		default:
			(void) free_mem(&tally);
			errno = EINVAL;
			*which = (int)(aclentp - aclbufp);
			return (EACL_ENTRY_ERROR);
		}
	}
	/* If there are group or user entries, there must be one class entry */
	if (tally.user.count > 0 || tally.group.count > 0)
		if (tally.class_obj.count != 1) {
			(void) free_mem(&tally);
			errno = EINVAL;
			return (EACL_MISS_ERROR);
		}
	/* same is true for default entries */
	if (tally.def_user.count > 0 || tally.def_group.count > 0)
		if (tally.def_class_obj.count != 1) {
			(void) free_mem(&tally);
			errno = EINVAL;
			return (EACL_MISS_ERROR);
		}

	/* there must be exactly one user_obj, group_obj, and other_obj entry */
	if (tally.user_obj.count != 1 ||
	    tally.group_obj.count != 1 ||
	    tally.other_obj.count != 1) {
		(void) free_mem(&tally);
		errno = EINVAL;
		return (EACL_MISS_ERROR);
	}

	/* has default? same rules apply to default entries */
	if (tally.def_user.count > 0 || tally.def_user_obj.count > 0 ||
	    tally.def_group.count > 0 || tally.def_group_obj.count > 0 ||
	    tally.def_class_obj.count > 0 || tally.def_other_obj.count > 0) {

		/*
		 * Can't have default ACL's on non-directories
		 */
		if (isdir == 0) {
			(void) free_mem(&tally);
			errno = EINVAL;
			return (EACL_INHERIT_NOTDIR);
		}

		if (tally.def_user_obj.count != 1 ||
		    tally.def_group_obj.count != 1 ||
		    tally.def_other_obj.count != 1) {
			(void) free_mem(&tally);
			errno = EINVAL;
			return (EACL_MISS_ERROR);
		}
	}

	(void) free_mem(&tally);
	return (0);
}

int
aclcheck(aclent_t *aclbufp, int nentries, int *which)
{
	return (aclent_aclcheck(aclbufp, nentries, which, 1));
}


static void
free_mem(struct entry_stat *tallyp)
{
	if ((tallyp->user).count > 0)
		free((tallyp->user).id);
	if ((tallyp->group).count > 0)
		free((tallyp->group).id);
	if ((tallyp->def_user).count > 0)
		free((tallyp->def_user).id);
	if ((tallyp->def_group).count > 0)
		free((tallyp->def_group).id);
}

static int
check_dup(int count, uid_t *ids, uid_t newid, struct entry_stat *tallyp)
{
	int	i;

	for (i = 0; i < count; i++) {
		if (ids[i] == newid) {
			errno = EINVAL;
			(void) free_mem(tallyp);
			return (-1);
		}
	}
	return (0);
}

#define	IFLAGS	(ACE_FILE_INHERIT_ACE|ACE_DIRECTORY_INHERIT_ACE| \
    ACE_NO_PROPAGATE_INHERIT_ACE|ACE_INHERIT_ONLY_ACE)

static int
ace_aclcheck(acl_t *aclp, int isdir)
{
	ace_t 	*acep;
	int 	i;
	int	error = 0;

	/*
	 * step through all valid flags.
	 */

	if (aclp->acl_cnt <= 0 || aclp->acl_cnt > MAX_ACL_ENTRIES)
		return (EACL_COUNT_ERROR);

	for (i = 0, acep = aclp->acl_aclp;
	    i != aclp->acl_cnt && error == 0; i++, acep++) {
		switch (acep->a_flags & 0xf040) {
		case 0:
		case ACE_OWNER:
		case ACE_EVERYONE:
		case ACE_IDENTIFIER_GROUP:
		case ACE_GROUP|ACE_IDENTIFIER_GROUP:
			break;
		default:
			errno = EINVAL;
			return (EACL_FLAGS_ERROR);
		}

		/*
		 * INHERIT_ONLY/NO_PROPAGATE need a to INHERIT_FILE
		 * or INHERIT_DIR also
		 */
		if (acep->a_flags &
		    (ACE_INHERIT_ONLY_ACE|ACE_NO_PROPAGATE_INHERIT_ACE)) {
			if ((acep->a_flags & (ACE_FILE_INHERIT_ACE|
			    ACE_DIRECTORY_INHERIT_ACE)) == 0) {
				errno = EINVAL;
				return (EACL_INHERIT_ERROR);
			}
			break;
		}

		switch (acep->a_type) {
		case ACE_ACCESS_ALLOWED_ACE_TYPE:
		case ACE_ACCESS_DENIED_ACE_TYPE:
		case ACE_SYSTEM_AUDIT_ACE_TYPE:
		case ACE_SYSTEM_ALARM_ACE_TYPE:
			break;
		default:
			errno = EINVAL;
			return (EACL_ENTRY_ERROR);
		}
		if (acep->a_access_mask > ACE_ALL_PERMS) {
			errno = EINVAL;
			return (EACL_PERM_MASK_ERROR);
		}
	}

	return (0);
}

int
acl_check(acl_t *aclp, int flag)
{
	int error;
	int where;

	switch (aclp->acl_type) {
	case ACLENT_T:
		error = aclent_aclcheck(aclp->acl_aclp, aclp->acl_cnt,
		    &where, flag);
		break;
	case ACE_T:
		error = ace_aclcheck(aclp, flag);
		break;
	default:
		errno = EINVAL;
		error = EACL_ENTRY_ERROR;
	}
	return (error);
}
