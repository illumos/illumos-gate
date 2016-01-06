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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <sys/param.h>
#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/var.h>
#include <sys/utsname.h>
#include <sys/utssys.h>
#include <sys/ustat.h>
#include <sys/statvfs.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/pathname.h>
#include <sys/modctl.h>
#include <sys/fs/snode.h>
#include <sys/sunldi_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/ddipropdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/modctl.h>
#include <sys/flock.h>
#include <sys/share.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <util/qsort.h>
#include <sys/zone.h>

/*
 * utssys()
 */
static int		uts_fusers(char *, int, intptr_t);
static int		_statvfs64_by_dev(dev_t, struct statvfs64 *);

#if defined(_ILP32) || defined(_SYSCALL32_IMPL)

static int utssys_uname32(caddr_t, rval_t *);
static int utssys_ustat32(dev_t, struct ustat32 *);

int64_t
utssys32(void *buf, int arg, int type, void *outbp)
{
	int error;
	rval_t rv;

	rv.r_vals = 0;

	switch (type) {
	case UTS_UNAME:
		/*
		 * This is an obsolete way to get the utsname structure
		 * (it only gives you the first 8 characters of each field!)
		 * uname(2) is the preferred and better interface.
		 */
		error = utssys_uname32(buf, &rv);
		break;
	case UTS_USTAT:
		error = utssys_ustat32(expldev((dev32_t)arg), buf);
		break;
	case UTS_FUSERS:
		error = uts_fusers(buf, arg, (intptr_t)outbp);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error == 0 ? rv.r_vals : (int64_t)set_errno(error));
}

static int
utssys_uname32(caddr_t buf, rval_t *rvp)
{
	if (copyout(utsname.sysname, buf, 8))
		return (EFAULT);
	buf += 8;
	if (subyte(buf, 0) < 0)
		return (EFAULT);
	buf++;
	if (copyout(uts_nodename(), buf, 8))
		return (EFAULT);
	buf += 8;
	if (subyte(buf, 0) < 0)
		return (EFAULT);
	buf++;
	if (copyout(utsname.release, buf, 8))
		return (EFAULT);
	buf += 8;
	if (subyte(buf, 0) < 0)
		return (EFAULT);
	buf++;
	if (copyout(utsname.version, buf, 8))
		return (EFAULT);
	buf += 8;
	if (subyte(buf, 0) < 0)
		return (EFAULT);
	buf++;
	if (copyout(utsname.machine, buf, 8))
		return (EFAULT);
	buf += 8;
	if (subyte(buf, 0) < 0)
		return (EFAULT);
	rvp->r_val1 = 1;
	return (0);
}

static int
utssys_ustat32(dev_t dev, struct ustat32 *cbuf)
{
	struct ustat32 ust32;
	struct statvfs64 stvfs;
	fsblkcnt64_t	fsbc64;
	char *cp, *cp2;
	int i, error;

	if ((error = _statvfs64_by_dev(dev, &stvfs)) != 0)
		return (error);

	fsbc64 = stvfs.f_bfree * (stvfs.f_frsize / 512);
	/*
	 * Check to see if the number of free blocks can be expressed
	 * in 31 bits or whether the number of free files is more than
	 * can be expressed in 32 bits and is not -1 (UINT64_MAX).  NFS
	 * Version 2 does not support the number of free files and
	 * hence will return -1.  -1, when translated from a 32 bit
	 * quantity to an unsigned 64 bit quantity, turns into UINT64_MAX.
	 */
	if (fsbc64 > INT32_MAX ||
	    (stvfs.f_ffree > UINT32_MAX && stvfs.f_ffree != UINT64_MAX))
		return (EOVERFLOW);

	ust32.f_tfree = (daddr32_t)fsbc64;
	ust32.f_tinode = (ino32_t)stvfs.f_ffree;

	cp = stvfs.f_fstr;
	cp2 = ust32.f_fname;
	i = 0;
	while (i++ < sizeof (ust32.f_fname))
		if (*cp != '\0')
			*cp2++ = *cp++;
		else
			*cp2++ = '\0';
	while (*cp != '\0' &&
	    (i++ < sizeof (stvfs.f_fstr) - sizeof (ust32.f_fpack)))
		cp++;
	(void) strncpy(ust32.f_fpack, cp + 1, sizeof (ust32.f_fpack));

	if (copyout(&ust32, cbuf, sizeof (ust32)))
		return (EFAULT);
	return (0);
}

#endif	/* _ILP32 || _SYSCALL32_IMPL */

#ifdef _LP64

static int uts_ustat64(dev_t, struct ustat *);

int64_t
utssys64(void *buf, long arg, int type, void *outbp)
{
	int error;
	rval_t rv;

	rv.r_vals = 0;

	switch (type) {
	case UTS_USTAT:
		error = uts_ustat64((dev_t)arg, buf);
		break;
	case UTS_FUSERS:
		error = uts_fusers(buf, (int)arg, (intptr_t)outbp);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error == 0 ? rv.r_vals : (int64_t)set_errno(error));
}

static int
uts_ustat64(dev_t dev, struct ustat *cbuf)
{
	struct ustat ust;
	struct statvfs64 stvfs;
	fsblkcnt64_t	fsbc64;
	char *cp, *cp2;
	int i, error;

	if ((error = _statvfs64_by_dev(dev, &stvfs)) != 0)
		return (error);

	fsbc64 = stvfs.f_bfree * (stvfs.f_frsize / 512);
	ust.f_tfree = (daddr_t)fsbc64;
	ust.f_tinode = (ino_t)stvfs.f_ffree;

	cp = stvfs.f_fstr;
	cp2 = ust.f_fname;
	i = 0;
	while (i++ < sizeof (ust.f_fname))
		if (*cp != '\0')
			*cp2++ = *cp++;
		else
			*cp2++ = '\0';
	while (*cp != '\0' &&
	    (i++ < sizeof (stvfs.f_fstr) - sizeof (ust.f_fpack)))
		cp++;
	(void) strncpy(ust.f_fpack, cp + 1, sizeof (ust.f_fpack));

	if (copyout(&ust, cbuf, sizeof (ust)))
		return (EFAULT);
	return (0);
}

#endif	/* _LP64 */

/*
 * Utility routine for the ustat implementations.
 * (If it wasn't for the 'find-by-dev_t' semantic of ustat(2), we could push
 * this all out into userland, sigh.)
 */
static int
_statvfs64_by_dev(dev_t dev, struct statvfs64 *svp)
{
	vfs_t *vfsp;
	int error;

	if ((vfsp = vfs_dev2vfsp(dev)) == NULL) {
		/*
		 * See if it's the root of our zone.
		 */
		vfsp = curproc->p_zone->zone_rootvp->v_vfsp;
		if (vfsp->vfs_dev == dev) {
			VFS_HOLD(vfsp);
		} else {
			vfsp = NULL;
		}
	}
	if (vfsp == NULL)
		return (EINVAL);
	error = VFS_STATVFS(vfsp, svp);
	VFS_RELE(vfsp);
	return (error);
}

/*
 * Check if this pid has an NBMAND lock or share reservation
 * on this vp. llp is a snapshoted list of all NBMAND locks
 * set by this pid. Return 1 if there is an NBMAND lock else
 * return 0.
 */
static int
proc_has_nbmand_on_vp(vnode_t *vp, pid_t pid, locklist_t *llp)
{
	/*
	 * Any NBMAND lock held by the process on this vp?
	 */
	while (llp) {
		if (llp->ll_vp == vp) {
			return (1);
		}
		llp = llp->ll_next;
	}
	/*
	 * Any NBMAND share reservation on the vp for this process?
	 */
	return (proc_has_nbmand_share_on_vp(vp, pid));
}

static fu_data_t *
dofusers(vnode_t *fvp, int flags)
{
	fu_data_t	*fu_data;
	proc_t		*prp;
	vfs_t		*cvfsp;
	pid_t		npids, pidx, *pidlist;
	int		v_proc = v.v_proc;	/* max # of procs */
	int		pcnt = 0;
	int		contained = (flags & F_CONTAINED);
	int		nbmandonly = (flags & F_NBMANDLIST);
	int		dip_usage = (flags & F_DEVINFO);
	int		fvp_isdev = vn_matchops(fvp, spec_getvnodeops());
	zone_t *zone = curproc->p_zone;
	int inglobal = INGLOBALZONE(curproc);

	/* get a pointer to the file system containing this vnode */
	cvfsp = fvp->v_vfsp;
	ASSERT(cvfsp);

	/* allocate the data structure to return our results in */
	fu_data = kmem_alloc(fu_data_size(v_proc), KM_SLEEP);
	fu_data->fud_user_max = v_proc;
	fu_data->fud_user_count = 0;

	/* get a snapshot of all the pids we're going to check out */
	pidlist = kmem_alloc(v_proc * sizeof (pid_t), KM_SLEEP);
	mutex_enter(&pidlock);
	for (npids = 0, prp = practive; prp != NULL; prp = prp->p_next) {
		if (inglobal || prp->p_zone == zone)
			pidlist[npids++] = prp->p_pid;
	}
	mutex_exit(&pidlock);

	/* grab each process and check its file usage */
	for (pidx = 0; pidx < npids; pidx++) {
		locklist_t	*llp = NULL;
		uf_info_t	*fip;
		vnode_t		*vp;
		user_t		*up;
		sess_t		*sp;
		uid_t		uid;
		pid_t		pid = pidlist[pidx];
		int		i, use_flag = 0;

		/*
		 * grab prp->p_lock using sprlock()
		 * if sprlock() fails the process does not exists anymore
		 */
		prp = sprlock(pid);
		if (prp == NULL)
			continue;

		/* get the processes credential info in case we need it */
		mutex_enter(&prp->p_crlock);
		uid = crgetruid(prp->p_cred);
		mutex_exit(&prp->p_crlock);

		/*
		 * it's safe to drop p_lock here because we
		 * called sprlock() before and it set the SPRLOCK
		 * flag for the process so it won't go away.
		 */
		mutex_exit(&prp->p_lock);

		/*
		 * now we want to walk a processes open file descriptors
		 * to do this we need to grab the fip->fi_lock.  (you
		 * can't hold p_lock when grabbing the fip->fi_lock.)
		 */
		fip = P_FINFO(prp);
		mutex_enter(&fip->fi_lock);

		/*
		 * Snapshot nbmand locks for pid
		 */
		llp = flk_active_nbmand_locks(prp->p_pid);
		for (i = 0; i < fip->fi_nfiles; i++) {
			uf_entry_t	*ufp;
			file_t		*fp;

			UF_ENTER(ufp, fip, i);
			if (((fp = ufp->uf_file) == NULL) ||
			    ((vp = fp->f_vnode) == NULL)) {
				UF_EXIT(ufp);
				continue;
			}

			/*
			 * if the target file (fvp) is not a device
			 * and corrosponds to the root of a filesystem
			 * (cvfsp), then check if it contains the file
			 * is use by this process (vp).
			 */
			if (contained && (vp->v_vfsp == cvfsp))
				use_flag |= F_OPEN;

			/*
			 * if the target file (fvp) is not a device,
			 * then check if it matches the file in use
			 * by this process (vp).
			 */
			if (!fvp_isdev && VN_CMP(fvp, vp))
				use_flag |= F_OPEN;

			/*
			 * if the target file (fvp) is a device,
			 * then check if the current file in use
			 * by this process (vp) maps to the same device
			 * minor node.
			 */
			if (fvp_isdev &&
			    vn_matchops(vp, spec_getvnodeops()) &&
			    (fvp->v_rdev == vp->v_rdev))
				use_flag |= F_OPEN;

			/*
			 * if the target file (fvp) is a device,
			 * and we're checking for device instance
			 * usage, then check if the current file in use
			 * by this process (vp) maps to the same device
			 * instance.
			 */
			if (dip_usage &&
			    vn_matchops(vp, spec_getvnodeops()) &&
			    (VTOCS(fvp)->s_dip == VTOCS(vp)->s_dip))
				use_flag |= F_OPEN;

			/*
			 * if the current file in use by this process (vp)
			 * doesn't match what we're looking for, move on
			 * to the next file in the process.
			 */
			if ((use_flag & F_OPEN) == 0) {
				UF_EXIT(ufp);
				continue;
			}

			if (proc_has_nbmand_on_vp(vp, prp->p_pid, llp)) {
				/* A nbmand found so we're done.  */
				use_flag |= F_NBM;
				UF_EXIT(ufp);
				break;
			}
			UF_EXIT(ufp);
		}
		if (llp)
			flk_free_locklist(llp);

		mutex_exit(&fip->fi_lock);

		/*
		 * If nbmand usage tracking is desired and no nbmand was
		 * found for this process, then no need to do further
		 * usage tracking for this process.
		 */
		if (nbmandonly && (!(use_flag & F_NBM))) {
			/*
			 * grab the process lock again, clear the SPRLOCK
			 * flag, release the process, and continue.
			 */
			mutex_enter(&prp->p_lock);
			sprunlock(prp);
			continue;
		}

		/*
		 * All other types of usage.
		 * For the next few checks we need to hold p_lock.
		 */
		mutex_enter(&prp->p_lock);
		up = PTOU(prp);
		if (fvp_isdev) {
			/*
			 * if the target file (fvp) is a device
			 * then check if it matches the processes tty
			 *
			 * we grab s_lock to protect ourselves against
			 * freectty() freeing the vnode out from under us.
			 */
			sp = prp->p_sessp;
			mutex_enter(&sp->s_lock);
			vp = prp->p_sessp->s_vp;
			if (vp != NULL) {
				if (fvp->v_rdev == vp->v_rdev)
					use_flag |= F_TTY;

				if (dip_usage &&
				    (VTOCS(fvp)->s_dip == VTOCS(vp)->s_dip))
					use_flag |= F_TTY;
			}
			mutex_exit(&sp->s_lock);
		} else {
			/* check the processes current working directory */
			if (up->u_cdir &&
			    (VN_CMP(fvp, up->u_cdir) ||
			    (contained && (up->u_cdir->v_vfsp == cvfsp))))
				use_flag |= F_CDIR;

			/* check the processes root directory */
			if (up->u_rdir &&
			    (VN_CMP(fvp, up->u_rdir) ||
			    (contained && (up->u_rdir->v_vfsp == cvfsp))))
				use_flag |= F_RDIR;

			/* check the program text vnode */
			if (prp->p_exec &&
			    (VN_CMP(fvp, prp->p_exec) ||
			    (contained && (prp->p_exec->v_vfsp == cvfsp))))
				use_flag |= F_TEXT;
		}

		/* Now we can drop p_lock again */
		mutex_exit(&prp->p_lock);

		/*
		 * now we want to walk a processes memory mappings.
		 * to do this we need to grab the prp->p_as lock.  (you
		 * can't hold p_lock when grabbing the prp->p_as lock.)
		 */
		if (prp->p_as != &kas) {
			struct seg	*seg;
			struct as	*as = prp->p_as;

			AS_LOCK_ENTER(as, RW_READER);
			for (seg = AS_SEGFIRST(as); seg;
			    seg = AS_SEGNEXT(as, seg)) {
				/*
				 * if we can't get a backing vnode for this
				 * segment then skip it
				 */
				vp = NULL;
				if ((SEGOP_GETVP(seg, seg->s_base, &vp)) ||
				    (vp == NULL))
					continue;

				/*
				 * if the target file (fvp) is not a device
				 * and corrosponds to the root of a filesystem
				 * (cvfsp), then check if it contains the
				 * vnode backing this segment (vp).
				 */
				if (contained && (vp->v_vfsp == cvfsp)) {
					use_flag |= F_MAP;
					break;
				}

				/*
				 * if the target file (fvp) is not a device,
				 * check if it matches the the vnode backing
				 * this segment (vp).
				 */
				if (!fvp_isdev && VN_CMP(fvp, vp)) {
					use_flag |= F_MAP;
					break;
				}

				/*
				 * if the target file (fvp) isn't a device,
				 * or the the vnode backing this segment (vp)
				 * isn't a device then continue.
				 */
				if (!fvp_isdev ||
				    !vn_matchops(vp, spec_getvnodeops()))
					continue;

				/*
				 * check if the vnode backing this segment
				 * (vp) maps to the same device minor node
				 * as the target device (fvp)
				 */
				if (fvp->v_rdev == vp->v_rdev) {
					use_flag |= F_MAP;
					break;
				}

				/*
				 * if we're checking for device instance
				 * usage, then check if the vnode backing
				 * this segment (vp) maps to the same device
				 * instance as the target device (fvp).
				 */
				if (dip_usage &&
				    (VTOCS(fvp)->s_dip == VTOCS(vp)->s_dip)) {
					use_flag |= F_MAP;
					break;
				}
			}
			AS_LOCK_EXIT(as);
		}

		if (use_flag) {
			ASSERT(pcnt < fu_data->fud_user_max);
			fu_data->fud_user[pcnt].fu_flags = use_flag;
			fu_data->fud_user[pcnt].fu_pid = pid;
			fu_data->fud_user[pcnt].fu_uid = uid;
			pcnt++;
		}

		/*
		 * grab the process lock again, clear the SPRLOCK
		 * flag, release the process, and continue.
		 */
		mutex_enter(&prp->p_lock);
		sprunlock(prp);
	}

	kmem_free(pidlist, v_proc * sizeof (pid_t));

	fu_data->fud_user_count = pcnt;
	return (fu_data);
}

typedef struct dofkusers_arg {
	vnode_t		*fvp;
	int		flags;
	int		*error;
	fu_data_t	*fu_data;
} dofkusers_arg_t;

static int
dofkusers_walker(const ldi_usage_t *ldi_usage, void *arg)
{
	dofkusers_arg_t	*dofkusers_arg = (dofkusers_arg_t *)arg;

	vnode_t		*fvp = dofkusers_arg->fvp;
	int		flags = dofkusers_arg->flags;
	int		*error = dofkusers_arg->error;
	fu_data_t	*fu_data = dofkusers_arg->fu_data;

	modid_t		modid;
	minor_t		minor;
	int		instance;
	int		dip_usage = (flags & F_DEVINFO);

	ASSERT(*error == 0);
	ASSERT(vn_matchops(fvp, spec_getvnodeops()));

	/*
	 * check if the dev_t of the target device matches the dev_t
	 * of the device we're trying to find usage info for.
	 */
	if (fvp->v_rdev != ldi_usage->tgt_devt) {

		/*
		 * if the dev_ts don't match and we're not trying
		 * to find usage information for device instances
		 * then return
		 */
		if (!dip_usage)
			return (LDI_USAGE_CONTINUE);


		/*
		 * we're trying to find usage information for an
		 * device instance instead of just a minor node.
		 *
		 * check if the dip for the target device matches the
		 * dip of the device we're trying to find usage info for.
		 */
		if (VTOCS(fvp)->s_dip != ldi_usage->tgt_dip)
			return (LDI_USAGE_CONTINUE);
	}

	if (fu_data->fud_user_count >= fu_data->fud_user_max) {
		*error = E2BIG;
		return (LDI_USAGE_TERMINATE);
	}

	/* get the device vnode user information */
	modid = ldi_usage->src_modid;
	ASSERT(modid != -1);

	minor = instance = -1;
	if (ldi_usage->src_dip != NULL) {
		instance = DEVI(ldi_usage->src_dip)->devi_instance;
	}
	if (ldi_usage->src_devt != DDI_DEV_T_NONE) {
		minor = getminor(ldi_usage->src_devt);
	}

	/* set the device vnode user information */
	fu_data->fud_user[fu_data->fud_user_count].fu_flags = F_KERNEL;
	fu_data->fud_user[fu_data->fud_user_count].fu_modid = modid;
	fu_data->fud_user[fu_data->fud_user_count].fu_instance = instance;
	fu_data->fud_user[fu_data->fud_user_count].fu_minor = minor;

	fu_data->fud_user_count++;

	return (LDI_USAGE_CONTINUE);
}

int
f_user_cmp(const void *arg1, const void *arg2)
{
	f_user_t *f_user1 = (f_user_t *)arg1;
	f_user_t *f_user2 = (f_user_t *)arg2;

	/*
	 * we should only be called for f_user_t entires that represent
	 * a kernel file consumer
	 */
	ASSERT(f_user1->fu_flags & F_KERNEL);
	ASSERT(f_user2->fu_flags & F_KERNEL);

	if (f_user1->fu_modid != f_user2->fu_modid)
		return ((f_user1->fu_modid < f_user2->fu_modid) ? -1 : 1);

	if (f_user1->fu_instance != f_user2->fu_instance)
		return ((f_user1->fu_instance < f_user2->fu_instance) ? -1 : 1);

	if (f_user1->fu_minor != f_user2->fu_minor)
		return ((f_user1->fu_minor < f_user2->fu_minor) ? -1 : 1);

	return (0);
}

static fu_data_t *
dofkusers(vnode_t *fvp, int flags, int *error)
{
	dofkusers_arg_t	dofkusers_arg;
	fu_data_t	*fu_data;
	int		user_max, i;

	/*
	 * we only keep track of kernel device consumers, so if the
	 * target vnode isn't a device then there's nothing to do here
	 */
	if (!vn_matchops(fvp, spec_getvnodeops()))
		return (NULL);

	/* allocate the data structure to return our results in */
	user_max = ldi_usage_count();
	fu_data = kmem_alloc(fu_data_size(user_max), KM_SLEEP);
	fu_data->fud_user_max = user_max;
	fu_data->fud_user_count = 0;

	/* invoke the callback to collect device usage information */
	dofkusers_arg.fvp = fvp;
	dofkusers_arg.flags = flags;
	dofkusers_arg.error = error;
	dofkusers_arg.fu_data = fu_data;
	ldi_usage_walker(&dofkusers_arg, dofkusers_walker);

	/* check for errors */
	if (*error != 0)
		return (fu_data);

	/* if there aren't any file consumers then return */
	if (fu_data->fud_user_count == 0)
		return (fu_data);

	/*
	 * since we ignore the spec_type of the target we're trying to
	 * access it's possible that we could have duplicates entries in
	 * the list of consumers.
	 *
	 * we don't want to check for duplicate in the callback because
	 * we're holding locks in the ldi when the callback is invoked.
	 *
	 * so here we need to go through the array of file consumers
	 * and remove duplicate entries.
	 */

	/* first sort the array of file consumers */
	qsort((caddr_t)fu_data->fud_user, fu_data->fud_user_count,
	    sizeof (f_user_t), f_user_cmp);

	/* then remove any duplicate entires */
	i = 1;
	while (i < fu_data->fud_user_count) {

		if (f_user_cmp(&fu_data->fud_user[i],
		    &fu_data->fud_user[i - 1]) != 0) {
			/*
			 * the current element is unique, move onto
			 * the next one
			 */
			i++;
			continue;
		}

		/*
		 * this entry is a duplicate so if it's not the last
		 * entry in the array then remove it.
		 */
		fu_data->fud_user_count--;
		if (i == fu_data->fud_user_count)
			break;

		bcopy(&fu_data->fud_user[i + 1], &fu_data->fud_user[i],
		    sizeof (f_user_t) * (fu_data->fud_user_count - i));
	}

	return (fu_data);
}

/*
 * Determine the ways in which processes and the kernel are using a named
 * file or mounted file system (path).  Normally return 0.  In case of an
 * error appropriate errno will be returned.
 *
 * Upon success, uts_fusers will also copyout the file usage information
 * in the form of an array of f_user_t's that are contained within an
 * fu_data_t pointed to by userbp.
 */
static int
uts_fusers(char *path, int flags, intptr_t userbp)
{
	fu_data_t	*fu_data = NULL, *fuk_data = NULL;
	fu_data_t	fu_header;
	vnode_t		*fvp = NULL;
	size_t		bcount;
	int		error = 0;
	int		total_max, total_out;
	int		contained = (flags & F_CONTAINED);
	int		dip_usage = (flags & F_DEVINFO);
	int		fvp_isdev;


	/* figure out how man f_user_t's we can safetly copy out */
	if (copyin((const void *)userbp, &total_max, sizeof (total_max)))
		return (EFAULT);

	/*
	 * check if we only want a count of how many kernel device
	 * consumers exist
	 */
	if (flags & F_KINFO_COUNT) {
		fu_header.fud_user_max = total_max;
		fu_header.fud_user_count = ldi_usage_count();
		bcount = fu_data_size(0);
		if (copyout(&fu_header, (void *)userbp, bcount))
			return (EFAULT);
		return (0);
	}

	/* get the vnode for the file we want to look up usage for */
	error = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &fvp);
	if (error != 0)
		return (error);
	ASSERT(fvp);
	fvp_isdev = vn_matchops(fvp, spec_getvnodeops());

	/*
	 * if we want to report usage for all files contained within a
	 * file system then the target file better correspond to the
	 * root node of a mounted file system, or the root of a zone.
	 */
	if (contained && !(fvp->v_flag & VROOT) &&
	    fvp != curproc->p_zone->zone_rootvp) {
		error = EINVAL;
		goto out;
	}

	/*
	 * if we want to report usage for all files contained within a
	 * file system then the target file better not be a device.
	 */
	if (contained && fvp_isdev) {
		error = EINVAL;
		goto out;
	}

	/*
	 * if we want to report usage for a device instance then the
	 * target file better corrospond to a device
	 */
	if (dip_usage && !fvp_isdev) {
		error = EINVAL;
		goto out;
	}

	/*
	 * if the target vnode isn't a device and it has a reference count
	 * of one then no one else is going to have it open so we don't
	 * have any work to do.
	 */
	if (!fvp_isdev && (fvp->v_count == 1)) {
		goto out;
	}

	/* look up usage information for this vnode */
	fu_data = dofusers(fvp, flags);
	fuk_data = dofkusers(fvp, flags, &error);
	if (error != 0)
		goto out;

	/* get a count of the number of f_user_t's we need to copy out */
	total_out = 0;
	if (fu_data)
		total_out += fu_data->fud_user_count;
	if (fuk_data)
		total_out += fuk_data->fud_user_count;

	/* check if there is enough space to copyout all results */
	if (total_out > total_max) {
		error = E2BIG;
		goto out;
	}

	/* copyout file usage info counts */
	fu_header.fud_user_max = total_max;
	fu_header.fud_user_count = total_out;
	bcount = fu_data_size(0);
	if (copyout(&fu_header, (void *)userbp, bcount)) {
		error = EFAULT;
		goto out;
	}

	/* copyout userland process file usage info */
	if ((fu_data != NULL) && (fu_data->fud_user_count > 0)) {
		userbp += bcount;
		bcount = fu_data->fud_user_count * sizeof (f_user_t);
		if (copyout(fu_data->fud_user, (void *)userbp, bcount)) {
			error = EFAULT;
			goto out;
		}
	}

	/* copyout kernel file usage info */
	if ((fuk_data != NULL) && (fuk_data->fud_user_count > 0)) {
		userbp += bcount;
		bcount = fuk_data->fud_user_count * sizeof (f_user_t);
		if (copyout(fuk_data->fud_user, (void *)userbp, bcount)) {
			error = EFAULT;
			goto out;
		}
	}

out:
	/* release the vnode that we were looking up usage for */
	VN_RELE(fvp);

	/* release any allocated memory */
	if (fu_data)
		kmem_free(fu_data, fu_data_size(fu_data->fud_user_max));
	if (fuk_data)
		kmem_free(fuk_data, fu_data_size(fuk_data->fud_user_max));

	return (error);
}
