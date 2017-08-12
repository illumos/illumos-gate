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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#if 0 // XXX

#include <sys/user.h>
#include <sys/vm.h>
#include <sys/conf.h>
#include <sys/class.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/autoconf.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/instance.h>
#include <sys/modhash.h>
#include <sys/dacf.h>
#include <ipp/ipp.h>
#include <sys/strsubr.h>
#include <sys/kcpc.h>
#include <sys/brand.h>
#include <sys/cpc_pcbe.h>
#include <sys/kstat.h>
#include <sys/socketvar.h>
#include <sys/kiconv.h>

#endif // XXX

#include <libfksmbfs.h>

/*
 * Install a filesystem.
 */
/*ARGSUSED1*/
int
fake_installfs(vfsdef_t *def)
{
	struct vfssw *vswp;
	char *fsname = def->name;
	int fstype;	/* index into vfssw[] and vsanchor_fstype[] */
	int allocated;
	int err;

	if (def->def_version != VFSDEF_VERSION) {
		cmn_err(CE_WARN, "file system '%s' version mismatch", fsname);
		return (ENXIO);
	}

	allocated = 0;

	WLOCK_VFSSW();
	if ((vswp = vfs_getvfsswbyname(fsname)) == NULL) {
		if ((vswp = allocate_vfssw(fsname)) == NULL) {
			WUNLOCK_VFSSW();
			/*
			 * See 1095689.  If this message appears, then
			 * we either need to make the vfssw table bigger
			 * statically, or make it grow dynamically.
			 */
			cmn_err(CE_WARN, "no room for '%s' in vfssw!", fsname);
			return (ENXIO);
		}
		allocated = 1;
	}
	ASSERT(vswp != NULL);

	fstype = vswp - vfssw;	/* Pointer arithmetic to get the fstype */

	/* Turn on everything by default *except* VSW_STATS */
	vswp->vsw_flag = def->flags & ~(VSW_STATS);

	if (def->flags & VSW_HASPROTO) {
		vfs_mergeopttbl(&vfs_mntopts, def->optproto,
		    &vswp->vsw_optproto);
	} else {
		vfs_copyopttbl(&vfs_mntopts, &vswp->vsw_optproto);
	}

	if (def->flags & VSW_CANRWRO) {
		/*
		 * This obviously implies VSW_CANREMOUNT.
		 */
		vswp->vsw_flag |= VSW_CANREMOUNT;
	}

	/* vopstats ... */

	if (def->init == NULL)
		err = EFAULT;
	else
		err = (*(def->init))(fstype, fsname);

	if (err != 0) {
		if (allocated) {
			kmem_free(vswp->vsw_name, strlen(vswp->vsw_name)+1);
			vswp->vsw_name = "";
		}
		vswp->vsw_flag = 0;
		vswp->vsw_init = NULL;
	}

	vfs_unrefvfssw(vswp);
	WUNLOCK_VFSSW();

	/* ... vopstats */

	return (err);
}

int fake_removefs_allowed = 1;

/*
 * Remove a filesystem
 */
int
fake_removefs(vfsdef_t *def)
{
	struct vfssw *vswp;

	if (fake_removefs_allowed == 0)
		return (EBUSY);

	WLOCK_VFSSW();
	if ((vswp = vfs_getvfsswbyname(def->name)) == NULL) {
		WUNLOCK_VFSSW();
		cmn_err(CE_WARN, "fake_removefs: %s not in vfssw",
			def->name);
		return (EINVAL);
	}
	if (vswp->vsw_count != 1) {
		vfs_unrefvfssw(vswp);
		WUNLOCK_VFSSW();
		return (EBUSY);
	}

	/*
	 * A mounted filesystem could still have vsw_count = 0
	 * so we must check whether anyone is actually using our ops
	 */
	if (vfs_opsinuse(&vswp->vsw_vfsops)) {
		vfs_unrefvfssw(vswp);
		WUNLOCK_VFSSW();
		return (EBUSY);
	}

	vfs_freeopttbl(&vswp->vsw_optproto);
	vswp->vsw_optproto.mo_count = 0;

	vswp->vsw_flag = 0;
	vswp->vsw_init = NULL;
	vfs_unrefvfssw(vswp);
	WUNLOCK_VFSSW();
	return (0);
}
