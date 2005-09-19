/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/tiuser.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/unistd.h>
#include <sys/vmsystm.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/pathconf.h>
#include <sys/dnlc.h>
#include <sys/acl.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/xdr.h>
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode.h>
#include <nfs/nfs_acl.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>

#include <fs/fs_subr.h>

/*
 * The order and contents of this structure must be kept in sync with that of
 * aclreqcnt_v2_tmpl in nfs_stats.c
 */
char *aclnames_v2[] = {
	"null", "getacl", "setacl", "getattr", "access", "getxattrdir"
};

/*
 * This table maps from NFS protocol number into call type.
 * Zero means a "Lookup" type call
 * One  means a "Read" type call
 * Two  means a "Write" type call
 * This is used to select a default time-out.
 */
uchar_t acl_call_type_v2[] = {
	0, 0, 1, 0, 0, 0
};

/*
 * Similar table, but to determine which timer to use
 * (only real reads and writes!)
 */
uchar_t acl_timer_type_v2[] = {
	0, 0, 0, 0, 0, 0
};

/*
 * This table maps from acl operation into a call type
 * for the semisoft mount option.
 * Zero means do not repeat operation.
 * One  means repeat.
 */
uchar_t acl_ss_call_type_v2[] = {
	0, 0, 1, 0, 0, 0
};

static int nfs_acl_dup_cache(vsecattr_t *, vsecattr_t *);
static void nfs_acl_dup_res(rnode_t *, vsecattr_t *);

/* ARGSUSED */
int
acl_getacl2(vnode_t *vp, vsecattr_t *vsp, int flag, cred_t *cr)
{
	int error;
	GETACL2args args;
	GETACL2res res;
	int doqueue;
	vattr_t va;
	rnode_t *rp;
	failinfo_t fi;
	hrtime_t t;

	rp = VTOR(vp);
	if (rp->r_secattr != NULL) {
		error = nfs_validate_caches(vp, cr);
		if (error)
			return (error);
		mutex_enter(&rp->r_statelock);
		if (rp->r_secattr != NULL) {
			if (nfs_acl_dup_cache(vsp, rp->r_secattr)) {
				mutex_exit(&rp->r_statelock);
				return (0);
			}
		}
		mutex_exit(&rp->r_statelock);
	}

	args.mask = vsp->vsa_mask;
	args.fh = *VTOFH(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fh;
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	res.resok.acl.vsa_aclentp = NULL;
	res.resok.acl.vsa_dfaclentp = NULL;

	doqueue = 1;

	t = gethrtime();

	error = acl2call(VTOMI(vp), ACLPROC2_GETACL,
	    xdr_GETACL2args, (caddr_t)&args,
	    xdr_GETACL2res, (caddr_t)&res, cr,
	    &doqueue, &res.status, 0, &fi);

	if (error)
		return (error);

	error = geterrno(res.status);
	if (!error) {
		(void) nfs_cache_fattr(vp, &res.resok.attr, &va, t, cr);
		nfs_acl_dup_res(rp, &res.resok.acl);
		*vsp = res.resok.acl;
	} else {
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

/* ARGSUSED */
int
acl_setacl2(vnode_t *vp, vsecattr_t *vsp, int flag, cred_t *cr)
{
	int error;
	SETACL2args args;
	SETACL2res res;
	int doqueue;
	vattr_t va;
	rnode_t *rp;
	hrtime_t t;

	args.fh = *VTOFH(vp);
	args.acl = *vsp;

	doqueue = 1;

	t = gethrtime();

	error = acl2call(VTOMI(vp), ACLPROC2_SETACL,
	    xdr_SETACL2args, (caddr_t)&args,
	    xdr_SETACL2res, (caddr_t)&res, cr,
	    &doqueue, &res.status, 0, NULL);

	/*
	 * On success, adding the arguments to setsecattr into the cache have
	 * not proven adequate.  On error, we cannot depend on cache.
	 * Simply flush the cache to force the next getsecattr
	 * to go over the wire.
	 */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	if (rp->r_secattr != NULL) {
		nfs_acl_free(rp->r_secattr);
		rp->r_secattr = NULL;
	}
	mutex_exit(&rp->r_statelock);

	if (error)
		return (error);

	error = geterrno(res.status);
	if (!error) {
		(void) nfs_cache_fattr(vp, &res.resok.attr, &va, t, cr);
	} else {
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

int
acl_getattr2_otw(vnode_t *vp, vattr_t *vap, cred_t *cr)
{
	int error;
	GETATTR2args args;
	GETATTR2res res;
	int doqueue;
	failinfo_t fi;
	hrtime_t t;

	args.fh = *VTOFH(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fh;
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	doqueue = 1;

	t = gethrtime();

	error = acl2call(VTOMI(vp), ACLPROC2_GETATTR,
	    xdr_GETATTR2args, (caddr_t)&args,
	    xdr_GETATTR2res, (caddr_t)&res, cr,
	    &doqueue, &res.status, 0, &fi);

	if (error)
		return (error);
	error = geterrno(res.status);

	if (!error) {
		error = nfs_cache_fattr(vp, &res.resok.attr, vap, t, cr);
	} else {
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

/* ARGSUSED */
int
acl_access2(vnode_t *vp, int mode, int flags, cred_t *cr)
{
	int error;
	ACCESS2args args;
	ACCESS2res res;
	int doqueue;
	uint32 acc;
	rnode_t *rp;
	cred_t *cred, *ncr, *ncrfree = NULL;
	vattr_t va;
	failinfo_t fi;
	nfs_access_type_t cacc;
	hrtime_t t;

	acc = 0;
	if (mode & VREAD)
		acc |= ACCESS2_READ;
	if (mode & VWRITE) {
		if (vn_is_readonly(vp) && !IS_DEVVP(vp))
			return (EROFS);
		if (vp->v_type == VDIR)
			acc |= ACCESS2_DELETE;
		acc |= ACCESS2_MODIFY | ACCESS2_EXTEND;
	}
	if (mode & VEXEC) {
		if (vp->v_type == VDIR)
			acc |= ACCESS2_LOOKUP;
		else
			acc |= ACCESS2_EXECUTE;
	}

	rp = VTOR(vp);
	if (vp->v_type == VDIR) {
		args.access = ACCESS2_READ | ACCESS2_DELETE | ACCESS2_MODIFY |
		    ACCESS2_EXTEND | ACCESS2_LOOKUP;
	} else {
		args.access = ACCESS2_READ | ACCESS2_MODIFY | ACCESS2_EXTEND |
		    ACCESS2_EXECUTE;
	}
	args.fh = *VTOFH(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fh;
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	cred = cr;
	/*
	 * ncr and ncrfree both initially
	 * point to the memory area returned
	 * by crnetadjust();
	 * ncrfree not NULL when exiting means
	 * that we need to release it
	 */
	ncr = crnetadjust(cred);
	ncrfree = ncr;

tryagain:
	if (rp->r_acache != NULL) {
		cacc = nfs_access_check(rp, acc, cr);
		if (cacc == NFS_ACCESS_ALLOWED) {
			if (ncrfree != NULL)
				crfree(ncrfree);
			return (0);
		}
		if (cacc == NFS_ACCESS_DENIED) {
			/*
			 * If the cred can be adjusted, try again
			 * with the new cred.
			 */
			if (ncr != NULL) {
				cred = ncr;
				ncr = NULL;
				goto tryagain;
			}
			if (ncrfree != NULL)
				crfree(ncrfree);
			return (EACCES);
		}
	}

	doqueue = 1;

	t = gethrtime();

	error = acl2call(VTOMI(vp), ACLPROC2_ACCESS,
	    xdr_ACCESS2args, (caddr_t)&args,
	    xdr_ACCESS2res, (caddr_t)&res, cred,
	    &doqueue, &res.status, 0, &fi);

	if (error) {
		if (ncrfree != NULL)
			crfree(ncrfree);
		return (error);
	}

	error = geterrno(res.status);
	if (!error) {
		(void) nfs_cache_fattr(vp, &res.resok.attr, &va, t, cr);
		nfs_access_cache(rp, args.access, res.resok.access, cred);
		/*
		 * we just cached results with cred; if cred is the
		 * adjusted credentials from crnetadjust, we do not want
		 * to release them before exiting: hence setting ncrfree
		 * to NULL
		 */
		if (cred != cr)
			ncrfree = NULL;
		if ((acc & res.resok.access) != acc) {
			/*
			 * If the cred can be adjusted, try again
			 * with the new cred.
			 */
			if (ncr != NULL) {
				cred = ncr;
				ncr = NULL;
				goto tryagain;
			}
			error = EACCES;
		}
	} else {
		PURGE_STALE_FH(error, vp, cr);
	}

	if (ncrfree != NULL)
		crfree(ncrfree);

	return (error);
}

static int xattr_lookup_neg_cache = 1;

/*
 * Look up a hidden attribute directory over the wire; the vnode
 * we start with could be a file or directory.  We have to be
 * tricky in recording the name in the rnode r_path - we use the
 * magic name XATTR_RPATH and rely on code in failover_lookup() to
 * detect this and use this routine to do the same lookup on
 * remapping.  DNLC is easier: slashes are legal, so we use
 * XATTR_DIR_NAME as UFS does.
 */
int
acl_getxattrdir2(vnode_t *vp, vnode_t **vpp, bool_t create, cred_t *cr,
	int rfscall_flags)
{
	int error;
	GETXATTRDIR2args args;
	GETXATTRDIR2res res;
	int doqueue;
	failinfo_t fi;
	hrtime_t t;

	args.fh = *VTOFH(vp);
	args.create = create;

	fi.vp = vp;
	fi.fhp = NULL;		/* no need to update, filehandle not copied */
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	doqueue = 1;

	t = gethrtime();

	error = acl2call(VTOMI(vp), ACLPROC2_GETXATTRDIR,
	    xdr_GETXATTRDIR2args, (caddr_t)&args,
	    xdr_GETXATTRDIR2res, (caddr_t)&res, cr,
	    &doqueue, &res.status, rfscall_flags, &fi);

	if (!error) {
		error = geterrno(res.status);
		if (!error) {
			*vpp = makenfsnode(&res.resok.fh, &res.resok.attr,
			    vp->v_vfsp, t, cr, VTOR(vp)->r_path, XATTR_RPATH);
			mutex_enter(&(*vpp)->v_lock);
			(*vpp)->v_flag |= V_XATTRDIR;
			mutex_exit(&(*vpp)->v_lock);
			if (!(rfscall_flags & RFSCALL_SOFT))
				dnlc_update(vp, XATTR_DIR_NAME, *vpp);
		} else {
			PURGE_STALE_FH(error, vp, cr);
			if (error == ENOENT && xattr_lookup_neg_cache)
				dnlc_enter(vp, XATTR_DIR_NAME, DNLC_NO_VNODE);
		}
	}
	return (error);
}

/*
 * The order and contents of this structure must be kept in sync with that of
 * aclreqcnt_v3_tmpl in nfs_stats.c
 */
char *aclnames_v3[] = {
	"null", "getacl", "setacl", "getxattrdir"
};

/*
 * This table maps from NFS protocol number into call type.
 * Zero means a "Lookup" type call
 * One  means a "Read" type call
 * Two  means a "Write" type call
 * This is used to select a default time-out.
 */
uchar_t acl_call_type_v3[] = {
	0, 0, 1, 0
};

/*
 * This table maps from acl operation into a call type
 * for the semisoft mount option.
 * Zero means do not repeat operation.
 * One  means repeat.
 */
uchar_t acl_ss_call_type_v3[] = {
	0, 0, 1, 0
};

/*
 * Similar table, but to determine which timer to use
 * (only real reads and writes!)
 */
uchar_t acl_timer_type_v3[] = {
	0, 0, 0, 0
};

/* ARGSUSED */
int
acl_getacl3(vnode_t *vp, vsecattr_t *vsp, int flag, cred_t *cr)
{
	int error;
	GETACL3args args;
	GETACL3res res;
	int doqueue;
	rnode_t *rp;
	failinfo_t fi;
	hrtime_t t;

	rp = VTOR(vp);
	if (rp->r_secattr != NULL) {
		error = nfs3_validate_caches(vp, cr);
		if (error)
			return (error);
		mutex_enter(&rp->r_statelock);
		if (rp->r_secattr != NULL) {
			if (nfs_acl_dup_cache(vsp, rp->r_secattr)) {
				mutex_exit(&rp->r_statelock);
				return (0);
			}
		}
		mutex_exit(&rp->r_statelock);
	}

	args.mask = vsp->vsa_mask;
	args.fh = *VTOFH3(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fh;
	fi.copyproc = nfs3copyfh;
	fi.lookupproc = nfs3lookup;
	fi.xattrdirproc = acl_getxattrdir3;

	res.resok.acl.vsa_aclentp = NULL;
	res.resok.acl.vsa_dfaclentp = NULL;

	doqueue = 1;

	t = gethrtime();

	error = acl3call(VTOMI(vp), ACLPROC3_GETACL,
	    xdr_GETACL3args, (caddr_t)&args,
	    xdr_GETACL3res, (caddr_t)&res, cr,
	    &doqueue, &res.status, 0, &fi);

	if (error)
		return (error);

	error = geterrno3(res.status);

	if (!error) {
		nfs3_cache_post_op_attr(vp, &res.resok.attr, t, cr);
		nfs_acl_dup_res(rp, &res.resok.acl);
		*vsp = res.resok.acl;
	} else {
		nfs3_cache_post_op_attr(vp, &res.resfail.attr, t, cr);
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

/* ARGSUSED */
int
acl_setacl3(vnode_t *vp, vsecattr_t *vsp, int flag, cred_t *cr)
{
	int error;
	SETACL3args args;
	SETACL3res res;
	rnode_t *rp;
	int doqueue;
	hrtime_t t;

	args.fh = *VTOFH3(vp);
	args.acl = *vsp;

	doqueue = 1;

	t = gethrtime();

	error = acl3call(VTOMI(vp), ACLPROC3_SETACL,
	    xdr_SETACL3args, (caddr_t)&args,
	    xdr_SETACL3res, (caddr_t)&res, cr,
	    &doqueue, &res.status, 0, NULL);

	/*
	 * On success, adding the arguments to setsecattr into the cache have
	 * not proven adequate.  On error, we cannot depend on cache.
	 * Simply flush the cache to force the next getsecattr
	 * to go over the wire.
	 */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	if (rp->r_secattr != NULL) {
		nfs_acl_free(rp->r_secattr);
		rp->r_secattr = NULL;
	}
	mutex_exit(&rp->r_statelock);

	if (error)
		return (error);

	error = geterrno3(res.status);
	if (!error) {
		nfs3_cache_post_op_attr(vp, &res.resok.attr, t, cr);
	} else {
		nfs3_cache_post_op_attr(vp, &res.resfail.attr, t, cr);
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

int
acl_getxattrdir3(vnode_t *vp, vnode_t **vpp, bool_t create, cred_t *cr,
	int rfscall_flags)
{
	int error;
	GETXATTRDIR3args args;
	GETXATTRDIR3res res;
	int doqueue;
	struct vattr vattr;
	vnode_t *nvp;
	failinfo_t fi;
	hrtime_t t;

	args.fh = *VTOFH3(vp);
	args.create = create;

	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fh;
	fi.copyproc = nfs3copyfh;
	fi.lookupproc = nfs3lookup;
	fi.xattrdirproc = acl_getxattrdir3;

	doqueue = 1;

	t = gethrtime();

	error = acl3call(VTOMI(vp), ACLPROC3_GETXATTRDIR,
	    xdr_GETXATTRDIR3args, (caddr_t)&args,
	    xdr_GETXATTRDIR3res, (caddr_t)&res, cr,
	    &doqueue, &res.status, rfscall_flags, &fi);

	if (error)
		return (error);

	error = geterrno3(res.status);
	if (!error) {
		if (res.resok.attr.attributes) {
			nvp = makenfs3node(&res.resok.fh,
			    &res.resok.attr.attr,
			    vp->v_vfsp, t, cr, VTOR(vp)->r_path, XATTR_RPATH);
		} else {
			nvp = makenfs3node(&res.resok.fh, NULL,
			    vp->v_vfsp, t, cr, VTOR(vp)->r_path, XATTR_RPATH);
			if (nvp->v_type == VNON) {
				vattr.va_mask = AT_TYPE;
				error = nfs3getattr(nvp, &vattr, cr);
				if (error) {
					VN_RELE(nvp);
					return (error);
				}
				nvp->v_type = vattr.va_type;
			}
		}
		mutex_enter(&nvp->v_lock);
		nvp->v_flag |= V_XATTRDIR;
		mutex_exit(&nvp->v_lock);
		if (!(rfscall_flags & RFSCALL_SOFT))
			dnlc_update(vp, XATTR_DIR_NAME, nvp);
		*vpp = nvp;
	} else {
		PURGE_STALE_FH(error, vp, cr);
		if (error == ENOENT && xattr_lookup_neg_cache)
			dnlc_enter(vp, XATTR_DIR_NAME, DNLC_NO_VNODE);
	}

	return (error);
}

void
nfs_acl_free(vsecattr_t *vsp)
{

	if (vsp->vsa_aclentp != NULL) {
		kmem_free(vsp->vsa_aclentp, vsp->vsa_aclcnt *
		    sizeof (aclent_t));
	}
	if (vsp->vsa_dfaclentp != NULL) {
		kmem_free(vsp->vsa_dfaclentp, vsp->vsa_dfaclcnt *
		    sizeof (aclent_t));
	}
	kmem_free(vsp, sizeof (*vsp));
}

static int
nfs_acl_dup_cache(vsecattr_t *vsp, vsecattr_t *rvsp)
{
	size_t aclsize;

	if ((rvsp->vsa_mask & vsp->vsa_mask) != vsp->vsa_mask)
		return (0);

	if (vsp->vsa_mask & VSA_ACL) {
		ASSERT(rvsp->vsa_mask & VSA_ACLCNT);
		aclsize = rvsp->vsa_aclcnt * sizeof (aclent_t);
		vsp->vsa_aclentp = kmem_alloc(aclsize, KM_SLEEP);
		bcopy(rvsp->vsa_aclentp, vsp->vsa_aclentp, aclsize);
	}
	if (vsp->vsa_mask & VSA_ACLCNT)
		vsp->vsa_aclcnt = rvsp->vsa_aclcnt;
	if (vsp->vsa_mask & VSA_DFACL) {
		ASSERT(rvsp->vsa_mask & VSA_DFACLCNT);
		aclsize = rvsp->vsa_dfaclcnt * sizeof (aclent_t);
		vsp->vsa_dfaclentp = kmem_alloc(aclsize, KM_SLEEP);
		bcopy(rvsp->vsa_dfaclentp, vsp->vsa_dfaclentp, aclsize);
	}
	if (vsp->vsa_mask & VSA_DFACLCNT)
		vsp->vsa_dfaclcnt = rvsp->vsa_dfaclcnt;

	return (1);
}

static void
nfs_acl_dup_res_impl(kmutex_t *statelock, vsecattr_t **rspp, vsecattr_t *vsp)
{
	size_t aclsize;
	vsecattr_t *rvsp;

	mutex_enter(statelock);
	if (*rspp != NULL)
		rvsp = *rspp;
	else {
		rvsp = kmem_zalloc(sizeof (*rvsp), KM_NOSLEEP);
		if (rvsp == NULL) {
			mutex_exit(statelock);
			return;
		}
		*rspp = rvsp;
	}

	if (vsp->vsa_mask & VSA_ACL) {
		if (rvsp->vsa_aclentp != NULL &&
		    rvsp->vsa_aclcnt != vsp->vsa_aclcnt) {
			aclsize = rvsp->vsa_aclcnt * sizeof (aclent_t);
			kmem_free(rvsp->vsa_aclentp, aclsize);
			rvsp->vsa_aclentp = NULL;
		}
		if (vsp->vsa_aclcnt > 0) {
			aclsize = vsp->vsa_aclcnt * sizeof (aclent_t);
			if (rvsp->vsa_aclentp == NULL) {
				rvsp->vsa_aclentp = kmem_alloc(aclsize,
				    KM_SLEEP);
			}
			bcopy(vsp->vsa_aclentp, rvsp->vsa_aclentp, aclsize);
		}
		rvsp->vsa_aclcnt = vsp->vsa_aclcnt;
		rvsp->vsa_mask |= VSA_ACL | VSA_ACLCNT;
	}
	if (vsp->vsa_mask & VSA_ACLCNT) {
		if (rvsp->vsa_aclentp != NULL &&
		    rvsp->vsa_aclcnt != vsp->vsa_aclcnt) {
			aclsize = rvsp->vsa_aclcnt * sizeof (aclent_t);
			kmem_free(rvsp->vsa_aclentp, aclsize);
			rvsp->vsa_aclentp = NULL;
			rvsp->vsa_mask &= ~VSA_ACL;
		}
		rvsp->vsa_aclcnt = vsp->vsa_aclcnt;
		rvsp->vsa_mask |= VSA_ACLCNT;
	}
	if (vsp->vsa_mask & VSA_DFACL) {
		if (rvsp->vsa_dfaclentp != NULL &&
		    rvsp->vsa_dfaclcnt != vsp->vsa_dfaclcnt) {
			aclsize = rvsp->vsa_dfaclcnt * sizeof (aclent_t);
			kmem_free(rvsp->vsa_dfaclentp, aclsize);
			rvsp->vsa_dfaclentp = NULL;
		}
		if (vsp->vsa_dfaclcnt > 0) {
			aclsize = vsp->vsa_dfaclcnt * sizeof (aclent_t);
			if (rvsp->vsa_dfaclentp == NULL) {
				rvsp->vsa_dfaclentp = kmem_alloc(aclsize,
				    KM_SLEEP);
			}
			bcopy(vsp->vsa_dfaclentp, rvsp->vsa_dfaclentp, aclsize);
		}
		rvsp->vsa_dfaclcnt = vsp->vsa_dfaclcnt;
		rvsp->vsa_mask |= VSA_DFACL | VSA_DFACLCNT;
	}
	if (vsp->vsa_mask & VSA_DFACLCNT) {
		if (rvsp->vsa_dfaclentp != NULL &&
		    rvsp->vsa_dfaclcnt != vsp->vsa_dfaclcnt) {
			aclsize = rvsp->vsa_dfaclcnt * sizeof (aclent_t);
			kmem_free(rvsp->vsa_dfaclentp, aclsize);
			rvsp->vsa_dfaclentp = NULL;
			rvsp->vsa_mask &= ~VSA_DFACL;
		}
		rvsp->vsa_dfaclcnt = vsp->vsa_dfaclcnt;
		rvsp->vsa_mask |= VSA_DFACLCNT;
	}
	mutex_exit(statelock);
}

static void
nfs_acl_dup_res(rnode_t *rp, vsecattr_t *vsp)
{
	nfs_acl_dup_res_impl(&rp->r_statelock, &rp->r_secattr, vsp);
}
