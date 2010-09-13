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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/filio.h>
#include <sys/acl.h>
#include <sys/cmn_err.h>
#include <acl/acl_common.h>

#include <sys/unistd.h>
#include <sys/debug.h>
#include <fs/fs_subr.h>

static int cacl(int cmd, int nentries, void *aclbufp,
    vnode_t *vp, int *rv);

/*
 * Get/Set ACL of a file.
 */
int
acl(const char *fname, int cmd, int nentries, void *aclbufp)
{
	struct vnode *vp;
	int error;
	int rv = 0;
	int estale_retry = 0;

	/* Sanity check arguments */
	if (fname == NULL)
		return (set_errno(EINVAL));
lookup:
	error = lookupname((char *)fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (error) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}

	error = cacl(cmd, nentries, aclbufp, vp, &rv);
	VN_RELE(vp);
	if (error) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}
	return (rv);
}

/*
 * Get/Set ACL of a file with facl system call.
 */
int
facl(int fdes, int cmd, int nentries, void *aclbufp)
{
	file_t *fp;
	int error;
	int rv = 0;

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (fp->f_flag & FREVOKED) {
		releasef(fdes);
		return (set_errno(EBADF));
	}

	error = cacl(cmd, nentries, aclbufp, fp->f_vnode, &rv);
	releasef(fdes);

	if (error)
		return (set_errno(error));
	return (rv);
}


/*
 * Common code for acl() and facl().
 */
static int
cacl(int cmd, int nentries, void *aclbufp, vnode_t *vp, int *rv)
{
	int		error;
	int		aclbsize;	/* size of acl list in bytes */
	int		dfaclbsize;	/* size of default acl list in bytes */
	int		numacls;
	caddr_t		uaddrp;
	aclent_t	*aclp, *aaclp;
	vsecattr_t	vsecattr;
	size_t		entry_size;

	ASSERT(vp);

	bzero(&vsecattr, sizeof (vsecattr_t));

	switch (cmd) {

	case ACE_GETACLCNT:
	case GETACLCNT:
		if (cmd == GETACLCNT) {
			entry_size = sizeof (aclent_t);
			vsecattr.vsa_mask = VSA_ACLCNT | VSA_DFACLCNT;
		} else {
			entry_size = sizeof (ace_t);
			vsecattr.vsa_mask = VSA_ACECNT;
		}
		if (error = VOP_GETSECATTR(vp, &vsecattr, 0, CRED(), NULL))
			return (error);
		*rv = vsecattr.vsa_aclcnt + vsecattr.vsa_dfaclcnt;
		if (vsecattr.vsa_aclcnt && vsecattr.vsa_aclentp) {
			kmem_free(vsecattr.vsa_aclentp,
			    vsecattr.vsa_aclcnt * entry_size);
		}
		if (vsecattr.vsa_dfaclcnt && vsecattr.vsa_dfaclentp) {
			kmem_free(vsecattr.vsa_dfaclentp,
			    vsecattr.vsa_dfaclcnt * entry_size);
		}
		break;
	case GETACL:
		/*
		 * Minimum ACL size is three entries so might as well
		 * bail out here.
		 */
		if (nentries < 3)
			return (EINVAL);
		/*
		 * NULL output buffer is also a pretty easy bail out.
		 */
		if (aclbufp == NULL)
			return (EFAULT);
		vsecattr.vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL |
		    VSA_DFACLCNT;
		if (error = VOP_GETSECATTR(vp, &vsecattr, 0, CRED(), NULL))
			return (error);
		/* Check user's buffer is big enough */
		numacls = vsecattr.vsa_aclcnt + vsecattr.vsa_dfaclcnt;
		aclbsize = vsecattr.vsa_aclcnt * sizeof (aclent_t);
		dfaclbsize = vsecattr.vsa_dfaclcnt * sizeof (aclent_t);
		if (numacls > nentries) {
			error = ENOSPC;
			goto errout;
		}
		/* Sort the acl & default acl lists */
		if (vsecattr.vsa_aclcnt > 1)
			ksort((caddr_t)vsecattr.vsa_aclentp,
			    vsecattr.vsa_aclcnt, sizeof (aclent_t), cmp2acls);
		if (vsecattr.vsa_dfaclcnt > 1)
			ksort((caddr_t)vsecattr.vsa_dfaclentp,
			    vsecattr.vsa_dfaclcnt, sizeof (aclent_t), cmp2acls);
		/* Copy out acl's */
		uaddrp = (caddr_t)aclbufp;
		if (aclbsize > 0) {	/* bug #1262490 */
			if (copyout(vsecattr.vsa_aclentp, uaddrp, aclbsize)) {
				error = EFAULT;
				goto errout;
			}
		}
		/* Copy out default acl's */
		if (dfaclbsize > 0) {
			uaddrp += aclbsize;
			if (copyout(vsecattr.vsa_dfaclentp,
			    uaddrp, dfaclbsize)) {
				error = EFAULT;
				goto errout;
			}
		}
		*rv = numacls;
		if (vsecattr.vsa_aclcnt) {
			kmem_free(vsecattr.vsa_aclentp,
			    vsecattr.vsa_aclcnt * sizeof (aclent_t));
		}
		if (vsecattr.vsa_dfaclcnt) {
			kmem_free(vsecattr.vsa_dfaclentp,
			    vsecattr.vsa_dfaclcnt * sizeof (aclent_t));
		}
		break;

	case ACE_GETACL:
		if (aclbufp == NULL)
			return (EFAULT);

		vsecattr.vsa_mask = VSA_ACE | VSA_ACECNT;
		if (error = VOP_GETSECATTR(vp, &vsecattr, 0, CRED(), NULL))
			return (error);

		aclbsize = vsecattr.vsa_aclcnt * sizeof (ace_t);
		if (vsecattr.vsa_aclcnt > nentries) {
			error = ENOSPC;
			goto errout;
		}

		if (aclbsize > 0) {
			if ((error = copyout(vsecattr.vsa_aclentp,
			    aclbufp, aclbsize)) != 0) {
				goto errout;
			}
		}

		*rv = vsecattr.vsa_aclcnt;
		if (vsecattr.vsa_aclcnt) {
			kmem_free(vsecattr.vsa_aclentp, vsecattr.vsa_aclentsz);
		}
		break;

	case SETACL:
		/*
		 * Minimum ACL size is three entries so might as well
		 * bail out here.  Also limit request size to prevent user
		 * from allocating too much kernel memory.  Maximum size
		 * is MAX_ACL_ENTRIES for the ACL part and MAX_ACL_ENTRIES
		 * for the default ACL part. (bug 4058667)
		 */
		if (nentries < 3 || nentries > (MAX_ACL_ENTRIES * 2))
			return (EINVAL);
		/*
		 * NULL output buffer is also an easy bail out.
		 */
		if (aclbufp == NULL)
			return (EFAULT);
		vsecattr.vsa_mask = VSA_ACL;
		aclbsize = nentries * sizeof (aclent_t);
		vsecattr.vsa_aclentp = kmem_alloc(aclbsize, KM_SLEEP);
		aaclp = vsecattr.vsa_aclentp;
		vsecattr.vsa_aclcnt = nentries;
		uaddrp = (caddr_t)aclbufp;
		if (copyin(uaddrp, vsecattr.vsa_aclentp, aclbsize)) {
			kmem_free(aaclp, aclbsize);
			return (EFAULT);
		}
		/* Sort the acl list */
		ksort((caddr_t)vsecattr.vsa_aclentp,
		    vsecattr.vsa_aclcnt, sizeof (aclent_t), cmp2acls);

		/* Break into acl and default acl lists */
		for (numacls = 0, aclp = vsecattr.vsa_aclentp;
		    numacls < vsecattr.vsa_aclcnt;
		    aclp++, numacls++) {
			if (aclp->a_type & ACL_DEFAULT)
				break;
		}

		/* Find where defaults start (if any) */
		if (numacls < vsecattr.vsa_aclcnt) {
			vsecattr.vsa_mask |= VSA_DFACL;
			vsecattr.vsa_dfaclcnt = nentries - numacls;
			vsecattr.vsa_dfaclentp = aclp;
			vsecattr.vsa_aclcnt = numacls;
		}
		/* Adjust if they're all defaults */
		if (vsecattr.vsa_aclcnt == 0) {
			vsecattr.vsa_mask &= ~VSA_ACL;
			vsecattr.vsa_aclentp = NULL;
		}
		/* Only directories can have defaults */
		if (vsecattr.vsa_dfaclcnt && vp->v_type != VDIR) {
			kmem_free(aaclp, aclbsize);
			return (ENOTDIR);
		}
		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
		if (error = VOP_SETSECATTR(vp, &vsecattr, 0, CRED(), NULL)) {
			kmem_free(aaclp, aclbsize);
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			return (error);
		}

		/*
		 * Should return 0 upon success according to the man page
		 * and SVR4 semantics. (Bug #1214399: SETACL returns wrong rc)
		 */
		*rv = 0;
		kmem_free(aaclp, aclbsize);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		break;

	case ACE_SETACL:
		if (nentries < 1 || nentries > MAX_ACL_ENTRIES)
			return (EINVAL);

		if (aclbufp == NULL)
			return (EFAULT);

		vsecattr.vsa_mask = VSA_ACE;
		aclbsize = nentries * sizeof (ace_t);
		vsecattr.vsa_aclentp = kmem_alloc(aclbsize, KM_SLEEP);
		aaclp = vsecattr.vsa_aclentp;
		vsecattr.vsa_aclcnt = nentries;
		vsecattr.vsa_aclentsz = aclbsize;
		uaddrp = (caddr_t)aclbufp;
		if (copyin(uaddrp, vsecattr.vsa_aclentp, aclbsize)) {
			kmem_free(aaclp, aclbsize);
			return (EFAULT);
		}
		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
		if (error = VOP_SETSECATTR(vp, &vsecattr, 0, CRED(), NULL)) {
			kmem_free(aaclp, aclbsize);
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			return (error);
		}
		*rv = 0;
		kmem_free(aaclp, aclbsize);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		break;

	default:
		return (EINVAL);
	}

	return (0);

errout:
	if (aclbsize && vsecattr.vsa_aclentp)
		kmem_free(vsecattr.vsa_aclentp, aclbsize);
	if (dfaclbsize && vsecattr.vsa_dfaclentp)
		kmem_free(vsecattr.vsa_dfaclentp, dfaclbsize);
	return (error);
}
