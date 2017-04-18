/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/sunddi.h>
#include <sys/pathname.h>
#include <sys/acl.h>
#include <acl/acl_common.h>
#include <sys/lx_acl.h>


typedef struct {
	uint16_t lpaxe_tag;
	uint16_t lpaxe_perm;
	uint32_t lpaxe_id;
} lx_posix_acl_xattr_entry_t;

typedef struct {
	uint32_t			lpaxh_version;
	lx_posix_acl_xattr_entry_t	lpaxh_entries[];
} lx_posix_acl_xattr_header_t;

#define	LX_POSIX_ACL_XATTR_VERSION	0x0002

/* e_tag entry in struct posix_acl_entry */
#define	LX_ACL_USER_OBJ		0x01	/* USER_OBJ	*/
#define	LX_ACL_USER		0x02	/* USER		*/
#define	LX_ACL_GROUP_OBJ	0x04	/* GROUP_OBJ	*/
#define	LX_ACL_GROUP		0x08	/* GROUP	*/
#define	LX_ACL_MASK		0x10	/* CLASS_OBJ	*/
#define	LX_ACL_OTHER		0x20	/* OTHER_OBJ	*/


static int
lx_acl_from_xattr(enum lx_acl_type atype, void *xattr, uint_t xlen,
    acl_t **aclpp)
{
	lx_posix_acl_xattr_header_t *head = xattr;
	lx_posix_acl_xattr_entry_t *entry;
	int err = 0;
	uint_t count, sz = xlen;
	const uint_t mask = (atype == LX_ACL_DEFAULT) ? ACL_DEFAULT : 0;
	acl_t *acl;
	aclent_t *acle;

	if (xattr == NULL) {
		/* Handle zero-length set operations */
		acl = acl_alloc(ACLENT_T);
		*aclpp = acl;
		return (0);
	}

	if (xlen < sizeof (*head)) {
		return (EINVAL);
	} else if (head->lpaxh_version != LX_POSIX_ACL_XATTR_VERSION) {
		return (EOPNOTSUPP);
	}

	sz -= sizeof (lx_posix_acl_xattr_header_t);
	if (sz % sizeof (lx_posix_acl_xattr_entry_t) != 0) {
		return (EINVAL);
	}
	count = sz / sizeof (lx_posix_acl_xattr_entry_t);

	acl = acl_alloc(ACLENT_T);
	if (count == 0) {
		*aclpp = acl;
		return (0);
	}

	acle = kmem_alloc(count * sizeof (aclent_t), KM_SLEEP);
	acl->acl_cnt = count;
	acl->acl_aclp = acle;
	entry = head->lpaxh_entries;
	for (uint_t i = 0; i < count && err == 0; i++, entry++, acle++) {
		switch (entry->lpaxe_tag) {
		case LX_ACL_USER_OBJ:
		case LX_ACL_GROUP_OBJ:
		case LX_ACL_OTHER:
		case LX_ACL_MASK:
			break;
		case LX_ACL_USER:
		case LX_ACL_GROUP:
			if (entry->lpaxe_id > MAXUID) {
				err = EINVAL;
			}
			break;
		default:
			err = EINVAL;
			break;
		}
		acle->a_id = entry->lpaxe_id | mask;
		acle->a_type = entry->lpaxe_tag;
		acle->a_perm = entry->lpaxe_perm;
	}
	if (err != 0) {
		acl_free(acl);
		return (err);
	}

	*aclpp = acl;
	return (0);
}

/* ARGSUSED */
int
lx_acl_setxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t len)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	acl_t *acl = NULL;
	cred_t *cr = CRED();
	int err;

	if (vp->v_type == VLNK) {
		return (ENOTSUP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (EACCES);
	}

	/*
	 * Copyin and verify the input, even through there is little to be done
	 * with the result.
	 */
	if ((err = lx_acl_from_xattr(atype, data, len, &acl)) != 0) {
		return (err);
	}

	/*
	 * Because systemd has decided to scope-creep its way into a position
	 * of moribund domination over all things system software, there exist
	 * work-arounds which are required to address its numerous bugs and
	 * shortcomings.  One such case involves the FreeIPA installer needing
	 * to perform setfacl(3) on /run/systemd/ask-password.
	 *
	 * Between the fact that meaningful ACL translation can be challenging
	 * and that the path in question resides on tmpfs (which doesn't yet
	 * support ACLs at all on illumos), faked success is the only palatable
	 * course of action for now.  Atonement will follow.
	 *
	 * See also: https://bugzilla.redhat.com/show_bug.cgi?id=1322167
	 */
	err = ENOTSUP;
	if (crgetuid(cr) == 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if (vnodetopath(NULL, vp, path, MAXPATHLEN, cr) == 0 &&
		    strncmp(path, "/run/systemd/", 13) == 0) {
			/* Saccharin-sweet fake success */
			err = 0;
		}
		kmem_free(path, MAXPATHLEN);
	}
	acl_free(acl);

	return (err);
}

/* ARGSUSED */
int
lx_acl_getxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t slen,
    ssize_t *solen)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	vsecattr_t vsattr;
	int err;

	if (vp->v_type == VLNK) {
		return (ENOTSUP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (ENODATA);
	}

	bzero(&vsattr, sizeof (vsattr));
	vsattr.vsa_mask = VSA_ACECNT;
	if ((err = VOP_GETSECATTR(vp, &vsattr, 0, CRED(), NULL)) != 0) {
		err = (err == ENOENT) ? ENODATA : err;
		return (err);
	}

	return (ENODATA);
}

/* ARGSUSED */
int
lx_acl_removexattr(vnode_t *vp, enum lx_acl_type atype)
{
	return (ENODATA);
}

/* ARGSUSED */
int
lx_acl_listxattr(vnode_t *vp, uio_t *uio)
{
	return (0);
}
