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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/vm.h>
#include <sys/conf.h>
#include <sys/class.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/autoconf.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/instance.h>
#include <sys/modhash.h>
#include <sys/dacf.h>
#include <sys/debug.h>
#include <ipp/ipp.h>
#include <sys/strsubr.h>
#include <sys/kcpc.h>
#include <sys/brand.h>
#include <sys/cpc_pcbe.h>
#include <sys/kstat.h>
#include <sys/socketvar.h>
#include <sys/kiconv.h>

extern int moddebug;

extern struct cb_ops no_cb_ops;
extern struct dev_ops nodev_ops;
extern struct dev_ops mod_nodev_ops;

extern struct modctl *mod_getctl(struct modlinkage *);
extern int errsys(), nodev(), nulldev();

extern int findmodbyname(char *);
extern int mod_getsysnum(char *);

extern struct execsw execsw[];

/*
 * Define dev_ops for unused devopsp entry.
 */
struct dev_ops mod_nodev_ops = {
	DEVO_REV,		/* devo_rev	*/
	0,			/* refcnt	*/
	ddi_no_info,		/* info */
	nulldev,		/* identify	*/
	nulldev,		/* probe	*/
	ddifail,		/* attach	*/
	nodev,			/* detach	*/
	nulldev,		/* reset	*/
	&no_cb_ops,		/* character/block driver operations */
	(struct bus_ops *)0	/* bus operations for nexus drivers */
};

/*
 * Define mod_ops for each supported module type
 */

/*
 * Null operations; used for uninitialized and "misc" modules.
 */
static int mod_null(struct modldrv *, struct modlinkage *);
static int mod_infonull(void *, struct modlinkage *, int *);

struct mod_ops mod_miscops = {
	mod_null, mod_null, mod_infonull
};

/* CPU Modules */
struct mod_ops mod_cpuops = {
	mod_null, mod_null, mod_infonull
};

/*
 * Cryptographic Modules
 */
struct mod_ops mod_cryptoops = {
	mod_null, mod_null, mod_infonull
};

/*
 * IP Policy Modules
 */
static int mod_installipp(struct modlipp *, struct modlinkage *);
static int mod_removeipp(struct modlipp *, struct modlinkage *);
static int mod_infoipp(struct modlipp *, struct modlinkage *, int *);

struct mod_ops mod_ippops = {
	mod_installipp, mod_removeipp, mod_infoipp
};

/*
 * Device drivers
 */
static int mod_infodrv(struct modldrv *, struct modlinkage *, int *);
static int mod_installdrv(struct modldrv *, struct modlinkage *);
static int mod_removedrv(struct modldrv *, struct modlinkage *);

struct mod_ops mod_driverops = {
	mod_installdrv, mod_removedrv, mod_infodrv
};

/*
 * System calls (new interface)
 */
static int mod_infosys(struct modlsys *, struct modlinkage *, int *);
static int mod_installsys(struct modlsys *, struct modlinkage *);
static int mod_removesys(struct modlsys *, struct modlinkage *);

struct mod_ops mod_syscallops = {
	mod_installsys, mod_removesys, mod_infosys
};

#ifdef _SYSCALL32_IMPL
/*
 * 32-bit system calls in 64-bit kernel
 */
static int mod_infosys32(struct modlsys *, struct modlinkage *, int *);
static int mod_installsys32(struct modlsys *, struct modlinkage *);
static int mod_removesys32(struct modlsys *, struct modlinkage *);

struct mod_ops mod_syscallops32 = {
	mod_installsys32, mod_removesys32, mod_infosys32
};
#endif	/* _SYSCALL32_IMPL */

/*
 * Filesystems
 */
static int mod_infofs(struct modlfs *, struct modlinkage *, int *);
static int mod_installfs(struct modlfs *, struct modlinkage *);
static int mod_removefs(struct modlfs *, struct modlinkage *);

struct mod_ops mod_fsops = {
	mod_installfs, mod_removefs, mod_infofs
};

/*
 * Streams modules.
 */
static int mod_infostrmod(struct modlstrmod *, struct modlinkage *, int *);
static int mod_installstrmod(struct modlstrmod *, struct modlinkage *);
static int mod_removestrmod(struct modlstrmod *, struct modlinkage *);

struct mod_ops mod_strmodops = {
	mod_installstrmod, mod_removestrmod, mod_infostrmod
};

/*
 * Socket modules.
 */
static int mod_infosockmod(struct modlsockmod *, struct modlinkage *, int *);
static int mod_installsockmod(struct modlsockmod *, struct modlinkage *);
static int mod_removesockmod(struct modlsockmod *, struct modlinkage *);

struct mod_ops mod_sockmodops = {
	mod_installsockmod, mod_removesockmod, mod_infosockmod
};

/*
 * Scheduling classes.
 */
static int mod_infosched(struct modlsched *, struct modlinkage *, int *);
static int mod_installsched(struct modlsched *, struct modlinkage *);
static int mod_removesched(struct modlsched *, struct modlinkage *);

struct mod_ops mod_schedops = {
	mod_installsched, mod_removesched, mod_infosched
};

/*
 * Exec file type (like ELF, ...).
 */
static int mod_infoexec(struct modlexec *, struct modlinkage *, int *);
static int mod_installexec(struct modlexec *, struct modlinkage *);
static int mod_removeexec(struct modlexec *, struct modlinkage *);

struct mod_ops mod_execops = {
	mod_installexec, mod_removeexec, mod_infoexec
};

/*
 * Dacf (Dynamic Autoconfiguration) modules.
 */
static int mod_infodacf(struct modldacf *, struct modlinkage *, int *);
static int mod_installdacf(struct modldacf *, struct modlinkage *);
static int mod_removedacf(struct modldacf *, struct modlinkage *);

struct mod_ops mod_dacfops = {
	mod_installdacf, mod_removedacf, mod_infodacf
};

/*
 * PCBE (Performance Counter BackEnd) modules.
 */
static int mod_installpcbe(struct modlpcbe *, struct modlinkage *);
static int mod_removepcbe(struct modlpcbe *, struct modlinkage *);

struct mod_ops mod_pcbeops = {
	mod_installpcbe, mod_removepcbe, mod_infonull
};

/*
 * Brand modules.
 */
static int mod_installbrand(struct modlbrand *, struct modlinkage *);
static int mod_removebrand(struct modlbrand *, struct modlinkage *);

struct mod_ops mod_brandops = {
	mod_installbrand, mod_removebrand, mod_infonull
};

/*
 * kiconv modules.
 */
static int mod_installkiconv(struct modlkiconv *, struct modlinkage *);
static int mod_removekiconv(struct modlkiconv *, struct modlinkage *);

struct mod_ops mod_kiconvops = {
	mod_installkiconv, mod_removekiconv, mod_infonull
};

static struct sysent *mod_getsysent(struct modlinkage *, struct sysent *);

static char uninstall_err[] = "Cannot uninstall %s; not installed";

/*
 * Debugging support
 */
#define	DRV_DBG		MODDEBUG_LOADMSG2

/*PRINTFLIKE2*/
static void mod_dprintf(int flag, const char *format, ...) __KPRINTFLIKE(2);

static void
mod_dprintf(int flag, const char *format, ...)
{
	va_list alist;

	if ((moddebug & flag) != 0) {
		va_start(alist, format);
		(void) vprintf(format, alist);
		va_end(alist);
	}
}

/*
 * Install a module.
 * (This routine is in the Solaris SPARC DDI/DKI)
 */
int
mod_install(struct modlinkage *modlp)
{
	int retval = -1;	/* No linkage structures */
	struct modlmisc **linkpp;
	struct modlmisc **linkpp1;

	if (modlp->ml_rev != MODREV_1) {
		printf("mod_install:  modlinkage structure is not MODREV_1\n");
		return (EINVAL);
	}
	linkpp = (struct modlmisc **)&modlp->ml_linkage[0];

	while (*linkpp != NULL) {
		if ((retval = MODL_INSTALL(*linkpp, modlp)) != 0) {
			linkpp1 = (struct modlmisc **)&modlp->ml_linkage[0];

			while (linkpp1 != linkpp) {
				MODL_REMOVE(*linkpp1, modlp); /* clean up */
				linkpp1++;
			}
			break;
		}
		linkpp++;
	}
	return (retval);
}

static char *reins_err =
	"Could not reinstall %s\nReboot to correct the problem";

/*
 * Remove a module.  This is called by the module wrapper routine.
 * (This routine is in the Solaris SPARC DDI/DKI)
 */
int
mod_remove(struct modlinkage *modlp)
{
	int retval = 0;
	struct modlmisc **linkpp, *last_linkp;

	linkpp = (struct modlmisc **)&modlp->ml_linkage[0];

	while (*linkpp != NULL) {
		if ((retval = MODL_REMOVE(*linkpp, modlp)) != 0) {
			last_linkp = *linkpp;
			linkpp = (struct modlmisc **)&modlp->ml_linkage[0];
			while (*linkpp != last_linkp) {
				if (MODL_INSTALL(*linkpp, modlp) != 0) {
					cmn_err(CE_WARN, reins_err,
					    (*linkpp)->misc_linkinfo);
					break;
				}
				linkpp++;
			}
			break;
		}
		linkpp++;
	}
	return (retval);
}

/*
 * Get module status.
 * (This routine is in the Solaris SPARC DDI/DKI)
 */
int
mod_info(struct modlinkage *modlp, struct modinfo *modinfop)
{
	int i;
	int retval = 0;
	struct modspecific_info *msip;
	struct modlmisc **linkpp;

	modinfop->mi_rev = modlp->ml_rev;

	linkpp = (struct modlmisc **)modlp->ml_linkage;
	msip = &modinfop->mi_msinfo[0];

	for (i = 0; i < MODMAXLINK; i++) {
		if (*linkpp == NULL) {
			msip->msi_linkinfo[0] = '\0';
		} else {
			(void) strncpy(msip->msi_linkinfo,
			    (*linkpp)->misc_linkinfo, MODMAXLINKINFOLEN);
			retval = MODL_INFO(*linkpp, modlp, &msip->msi_p0);
			if (retval != 0)
				break;
			linkpp++;
		}
		msip++;
	}

	if (modinfop->mi_info == MI_INFO_LINKAGE) {
		/*
		 * Slight kludge used to extract the address of the
		 * modlinkage structure from the module (just after
		 * loading a module for the very first time)
		 */
		modinfop->mi_base = (void *)modlp;
	}

	if (retval == 0)
		return (1);
	return (0);
}

/*
 * Get module name.
 */
const char *
mod_modname(struct modlinkage *modlp)
{
	struct modctl	*mcp;

	if ((mcp = mod_getctl(modlp)) == NULL)
		return (NULL);

	return (mcp->mod_modname);
}

/*
 * Null operation; return 0.
 */
/*ARGSUSED*/
static int
mod_null(struct modldrv *modl, struct modlinkage *modlp)
{
	return (0);
}

/*
 * Status for User modules.
 */
/*ARGSUSED*/
static int
mod_infonull(void *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = -1;		/* for modinfo display */
	return (0);
}

/*
 * Driver status info
 */
/*ARGSUSED*/
static int
mod_infodrv(struct modldrv *modl, struct modlinkage *modlp, int *p0)
{
	struct modctl *mcp;
	char *mod_name;

	if ((mcp = mod_getctl(modlp)) == NULL) {
		*p0 = -1;
		return (0);	/* driver is not yet installed */
	}

	mod_name = mcp->mod_modname;

	*p0 = ddi_name_to_major(mod_name);
	return (0);
}

/*
 * Manage dacf (device autoconfiguration) modules
 */

/*ARGSUSED*/
static int
mod_infodacf(struct modldacf *modl, struct modlinkage *modlp, int *p0)
{
	if (mod_getctl(modlp) == NULL) {
		*p0 = -1;
		return (0);	/* module is not yet installed */
	}

	*p0 = 0;
	return (0);
}

static int
mod_installdacf(struct modldacf *modl, struct modlinkage *modlp)
{
	struct modctl	*mcp;

	if ((mcp = mod_getctl(modlp)) == NULL)
		return (EINVAL);
	return (dacf_module_register(mcp->mod_modname, modl->dacf_dacfsw));
}

/*ARGSUSED*/
static int
mod_removedacf(struct modldacf *modl, struct modlinkage *modlp)
{
	struct modctl	*mcp;

	if ((mcp = mod_getctl(modlp)) == NULL)
		return (EINVAL);
	return (dacf_module_unregister(mcp->mod_modname));
}

/*
 * Manage PCBE (Performance Counter BackEnd) modules.
 */
/*ARGSUSED*/
static int
mod_installpcbe(struct modlpcbe *modl, struct modlinkage *modlp)
{
	if (modl->pcbe_ops->pcbe_ver != PCBE_VER_1) {
		cmn_err(CE_WARN, "pcbe '%s' version mismatch",
		    modl->pcbe_linkinfo);
		return (EINVAL);
	}

	kcpc_register_pcbe(modl->pcbe_ops);
	return (0);
}

/*
 * PCBEs may not be unloaded. It would make CPC locking too complex, and since
 * PCBEs are loaded once and used for life, there is no harm done in leaving
 * them in the system.
 */
/*ARGSUSED*/
static int
mod_removepcbe(struct modlpcbe *modl, struct modlinkage *modlp)
{
	return (EBUSY);
}

/*
 * Manage BrandZ modules.
 */
/*ARGSUSED*/
static int
mod_installbrand(struct modlbrand *modl, struct modlinkage *modlp)
{
	return (brand_register(modl->brand_branddef));
}

/*ARGSUSED*/
static int
mod_removebrand(struct modlbrand *modl, struct modlinkage *modlp)
{
	return (brand_unregister(modl->brand_branddef));
}

/*
 * Install a new driver
 */
static int
mod_installdrv(struct modldrv *modl, struct modlinkage *modlp)
{
	struct modctl *mcp;
	struct dev_ops *ops;
	char *modname;
	major_t major;
	struct dev_ops *dp;
	struct devnames *dnp;
	struct streamtab *str;
	cdevsw_impl_t *cdp;
	uint_t sqtype;
	uint_t qflag;
	uint_t flag;
	int err = 0;

	/* sanity check module */
	if ((mcp = mod_getctl(modlp)) == NULL) {
		cmn_err(CE_WARN, "mod_install: bad module linkage data");
		err = ENXIO;
		goto done;
	}
	modname = mcp->mod_modname;

	/* Sanity check modname */
	if ((major = ddi_name_to_major(modname)) == DDI_MAJOR_T_NONE) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "mod_installdrv: no major number for %s", modname);
#endif
		err = ENXIO;
		goto done;
	}

	/* Verify MP safety flag */
	ops = modl->drv_dev_ops;
	if (ops->devo_bus_ops == NULL && ops->devo_cb_ops != NULL &&
	    !(ops->devo_cb_ops->cb_flag & D_MP)) {
		cmn_err(CE_WARN,
		    "mod_installdrv: MT-unsafe driver '%s' rejected", modname);
		err = ENXIO;
		goto done;
	}


	/* Is bus_map_fault signature correct (version 8 and higher)? */
	if (ops->devo_bus_ops != NULL &&
	    ops->devo_bus_ops->bus_map_fault != NULL &&
	    ops->devo_bus_ops->bus_map_fault != i_ddi_map_fault &&
	    ops->devo_bus_ops->busops_rev < BUSO_REV_8) {

		cmn_err(CE_WARN,
		    "mod_installdrv: busops' revision of '%s' is too low"
		    " (must be at least 8)", modname);
		err = ENXIO;
		goto done;
	}


	/* Make sure the driver is uninstalled */
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dp = devopsp[major];

	if (dnp->dn_flags & (DN_DRIVER_REMOVED|DN_DRIVER_INACTIVE)) {
#ifdef DEBUG
		cmn_err(CE_CONT,
		    "mod_installdrv: driver %s not installed", modname);
#endif
		err = ENXIO;
		goto unlock;
	}

	if (dp != &nodev_ops && dp != &mod_nodev_ops) {
		cmn_err(CE_WARN,
		    "mod_installdrv: driver already installed %s", modname);
		err = EALREADY;
		goto unlock;
	}

	devopsp[major] = ops; /* setup devopsp */

	if ((str = STREAMSTAB(major)) != NULL) {	/* streams driver */
		flag = CBFLAG(major);
		if ((err = devflg_to_qflag(str, flag, &qflag, &sqtype)) != 0)
			goto unlock;
		cdp = &devimpl[major];
		ASSERT(cdp->d_str == NULL);
		cdp->d_str = str;
		cdp->d_qflag = qflag | QISDRV;
		cdp->d_sqtype = sqtype;
	}

	if (ops->devo_bus_ops == NULL)
		dnp->dn_flags |= DN_LEAF_DRIVER;

unlock:
	UNLOCK_DEV_OPS(&dnp->dn_lock);
done:
	return (err);
}

static int
mod_removedrv(struct modldrv *modl, struct modlinkage *modlp)
{
	struct modctl *mcp;
	struct dev_ops *ops;
	struct devnames *dnp;
	struct dev_ops *dp;
	major_t major;
	char *modname;
	extern kthread_id_t mod_aul_thread;
	struct streamtab *str;
	cdevsw_impl_t *cdp;
	int err = 0;

	/* Don't auto unload modules on if moddebug flag is set */
	if ((moddebug & MODDEBUG_NOAUL_DRV) && (mod_aul_thread == curthread)) {
		err = EBUSY;
		goto done;
	}

	/* Verify modname has a driver major */
	mcp = mod_getctl(modlp);
	ASSERT(mcp != NULL);
	modname = mcp->mod_modname;

	if ((major = ddi_name_to_major(modname)) == -1) {
		cmn_err(CE_WARN, uninstall_err, modname);
		err = EINVAL;
		goto done;
	}

	ops = modl->drv_dev_ops;
	dnp = &(devnamesp[major]);
	LOCK_DEV_OPS(&(dnp->dn_lock));

	dp = devopsp[major];

	if (dp != ops)  {
		cmn_err(CE_NOTE, "mod_removedrv: mismatched driver for %s",
		    modname);
		err = EBUSY;
		goto unlock;
	}

	/*
	 * A driver is not unloadable if its dev_ops are held
	 */
	if (!DRV_UNLOADABLE(dp)) {
		mod_dprintf(DRV_DBG, "Cannot unload device driver <%s>,"
		    " refcnt %d\n", modname, dp->devo_refcnt);
		err = EBUSY;
		goto unlock;
	}

	/*
	 * OK to unload.
	 */
	if ((str = STREAMSTAB(major)) != NULL) {	/* streams driver */
		cdp = &devimpl[major];
		ASSERT(cdp->d_str == str);
		cdp->d_str = NULL;

		/* check for reference to per-dev syncq */
		if (cdp->d_dmp != NULL) {
			rele_dm(cdp->d_dmp);
			cdp->d_dmp = NULL;
		}
	}

	devopsp[major] = &mod_nodev_ops;
	dnp->dn_flags &= ~(DN_DRIVER_HELD|DN_NO_AUTODETACH);

unlock:
	UNLOCK_DEV_OPS(&(dnp->dn_lock));
done:
	return (err);
}

/*
 * System call subroutines
 */

/*
 * Compute system call number for given sysent and sysent table
 */
static int
mod_infosysnum(struct modlinkage *modlp, struct sysent table[])
{
	struct sysent *sysp;

	if ((sysp = mod_getsysent(modlp, table)) == NULL)
		return (-1);
	return ((int)(sysp - table));
}

/*
 * Put a loadable system call entry into a sysent table.
 */
static int
mod_installsys_sysent(
	struct modlsys		*modl,
	struct modlinkage	*modlp,
	struct sysent		table[])
{
	struct sysent *sysp;
	struct sysent *mp;

#ifdef DEBUG
	/*
	 * Before we even play with the sysent table, sanity check the
	 * incoming flags to make sure the entry is valid
	 */
	switch (modl->sys_sysent->sy_flags & SE_RVAL_MASK) {
	case SE_32RVAL1:
		/* only r_val1 returned */
	case SE_32RVAL1 | SE_32RVAL2:
		/* r_val1 and r_val2 returned */
	case SE_64RVAL:
		/* 64-bit rval returned */
		break;
	default:
		cmn_err(CE_WARN, "loadable syscall: %p: bad rval flags %x",
		    (void *)modl, modl->sys_sysent->sy_flags);
		return (ENOSYS);
	}
#endif
	if ((sysp = mod_getsysent(modlp, table)) == NULL)
		return (ENOSPC);

	/*
	 * We should only block here until the reader in syscall gives
	 * up the lock.  Multiple writers are prevented in the mod layer.
	 */
	rw_enter(sysp->sy_lock, RW_WRITER);
	mp = modl->sys_sysent;
	sysp->sy_narg = mp->sy_narg;
	sysp->sy_call = mp->sy_call;

	/*
	 * clear the old call method flag, and get the new one from the module.
	 */
	sysp->sy_flags &= ~SE_ARGC;
	sysp->sy_flags |= SE_LOADED |
	    (mp->sy_flags & (SE_ARGC | SE_NOUNLOAD | SE_RVAL_MASK));

	/*
	 * If the syscall doesn't need or want unloading, it can avoid
	 * the locking overhead on each entry.  Convert the sysent to a
	 * normal non-loadable entry in that case.
	 */
	if (mp->sy_flags & SE_NOUNLOAD) {
		if (mp->sy_flags & SE_ARGC) {
			sysp->sy_callc = (int64_t (*)())mp->sy_call;
		} else {
			sysp->sy_callc = syscall_ap;
		}
		sysp->sy_flags &= ~SE_LOADABLE;
	}
	rw_exit(sysp->sy_lock);
	return (0);
}

/*
 * Remove a loadable system call entry from a sysent table.
 */
static int
mod_removesys_sysent(
	struct modlsys		*modl,
	struct modlinkage	*modlp,
	struct sysent		table[])
{
	struct sysent	*sysp;

	if ((sysp = mod_getsysent(modlp, table)) == NULL ||
	    (sysp->sy_flags & (SE_LOADABLE | SE_NOUNLOAD)) == 0 ||
	    sysp->sy_call != modl->sys_sysent->sy_call) {

		struct modctl *mcp = mod_getctl(modlp);
		char *modname = mcp->mod_modname;

		cmn_err(CE_WARN, uninstall_err, modname);
		return (EINVAL);
	}

	/* If we can't get the write lock, we can't unlink from the system */

	if (!(moddebug & MODDEBUG_NOAUL_SYS) &&
	    rw_tryenter(sysp->sy_lock, RW_WRITER)) {
		/*
		 * Check the flags to be sure the syscall is still
		 * (un)loadable.
		 * If SE_NOUNLOAD is set, SE_LOADABLE will not be.
		 */
		if ((sysp->sy_flags & (SE_LOADED | SE_LOADABLE)) ==
		    (SE_LOADED | SE_LOADABLE)) {
			sysp->sy_flags &= ~SE_LOADED;
			sysp->sy_callc = loadable_syscall;
			sysp->sy_call = (int (*)())nosys;
			rw_exit(sysp->sy_lock);
			return (0);
		}
		rw_exit(sysp->sy_lock);
	}
	return (EBUSY);
}

/*
 * System call status info
 */
/*ARGSUSED*/
static int
mod_infosys(struct modlsys *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = mod_infosysnum(modlp, sysent);
	return (0);
}

/*
 * Link a system call into the system by setting the proper sysent entry.
 * Called from the module's _init routine.
 */
static int
mod_installsys(struct modlsys *modl, struct modlinkage *modlp)
{
	return (mod_installsys_sysent(modl, modlp, sysent));
}

/*
 * Unlink a system call from the system.
 * Called from a modules _fini routine.
 */
static int
mod_removesys(struct modlsys *modl, struct modlinkage *modlp)
{
	return (mod_removesys_sysent(modl, modlp, sysent));
}

#ifdef _SYSCALL32_IMPL

/*
 * 32-bit system call status info
 */
/*ARGSUSED*/
static int
mod_infosys32(struct modlsys *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = mod_infosysnum(modlp, sysent32);
	return (0);
}

/*
 * Link the 32-bit syscall into the system by setting the proper sysent entry.
 * Also called from the module's _init routine.
 */
static int
mod_installsys32(struct modlsys *modl, struct modlinkage *modlp)
{
	return (mod_installsys_sysent(modl, modlp, sysent32));
}

/*
 * Unlink the 32-bit flavor of a system call from the system.
 * Also called from a module's _fini routine.
 */
static int
mod_removesys32(struct modlsys *modl, struct modlinkage *modlp)
{
	return (mod_removesys_sysent(modl, modlp, sysent32));
}

#endif	/* _SYSCALL32_IMPL */

/*
 * Filesystem status info
 */
/*ARGSUSED*/
static int
mod_infofs(struct modlfs *modl, struct modlinkage *modlp, int *p0)
{
	struct vfssw *vswp;

	RLOCK_VFSSW();
	if ((vswp = vfs_getvfsswbyname(modl->fs_vfsdef->name)) == NULL)
		*p0 = -1;
	else {
		*p0 = vswp - vfssw;
		vfs_unrefvfssw(vswp);
	}
	RUNLOCK_VFSSW();
	return (0);
}

/*
 * Install a filesystem.
 */
/*ARGSUSED1*/
static int
mod_installfs(struct modlfs *modl, struct modlinkage *modlp)
{
	struct vfssw *vswp;
	struct modctl *mcp;
	char *fsname;
	char ksname[KSTAT_STRLEN + 1];
	int fstype;	/* index into vfssw[] and vsanchor_fstype[] */
	int allocated;
	int err;
	int vsw_stats_enabled;
	/* Not for public consumption so these aren't in a header file */
	extern int	vopstats_enabled;
	extern vopstats_t **vopstats_fstype;
	extern kstat_t *new_vskstat(char *, vopstats_t *);
	extern void initialize_vopstats(vopstats_t *);

	if (modl->fs_vfsdef->def_version == VFSDEF_VERSION) {
		/* Version matched */
		fsname = modl->fs_vfsdef->name;
	} else {
		if ((modl->fs_vfsdef->def_version > 0) &&
		    (modl->fs_vfsdef->def_version < VFSDEF_VERSION)) {
			/* Older VFSDEF_VERSION */
			fsname = modl->fs_vfsdef->name;
		} else if ((mcp = mod_getctl(modlp)) != NULL) {
			/* Pre-VFSDEF_VERSION */
			fsname = mcp->mod_modname;
		} else {
			/* If all else fails... */
			fsname = "<unknown file system type>";
		}

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
	vswp->vsw_flag = modl->fs_vfsdef->flags & ~(VSW_STATS);

	if (modl->fs_vfsdef->flags & VSW_HASPROTO) {
		vfs_mergeopttbl(&vfs_mntopts, modl->fs_vfsdef->optproto,
		    &vswp->vsw_optproto);
	} else {
		vfs_copyopttbl(&vfs_mntopts, &vswp->vsw_optproto);
	}

	if (modl->fs_vfsdef->flags & VSW_CANRWRO) {
		/*
		 * This obviously implies VSW_CANREMOUNT.
		 */
		vswp->vsw_flag |= VSW_CANREMOUNT;
	}

	/*
	 * If stats are enabled system wide and for this fstype, then
	 * set the VSW_STATS flag in the proper vfssw[] table entry.
	 */
	if (vopstats_enabled && modl->fs_vfsdef->flags & VSW_STATS) {
		vswp->vsw_flag |= VSW_STATS;
	}

	if (modl->fs_vfsdef->init == NULL)
		err = EFAULT;
	else
		err = (*(modl->fs_vfsdef->init))(fstype, fsname);

	if (err != 0) {
		if (allocated) {
			kmem_free(vswp->vsw_name, strlen(vswp->vsw_name)+1);
			vswp->vsw_name = "";
		}
		vswp->vsw_flag = 0;
		vswp->vsw_init = NULL;
	}

	/* We don't want to hold the vfssw[] write lock over a kmem_alloc() */
	vsw_stats_enabled = vswp->vsw_flag & VSW_STATS;

	vfs_unrefvfssw(vswp);
	WUNLOCK_VFSSW();

	/* If everything is on, set up the per-fstype vopstats */
	if (vsw_stats_enabled && vopstats_enabled &&
	    vopstats_fstype && vopstats_fstype[fstype] == NULL) {
		(void) strlcpy(ksname, VOPSTATS_STR, sizeof (ksname));
		(void) strlcat(ksname, vfssw[fstype].vsw_name, sizeof (ksname));
		vopstats_fstype[fstype] =
		    kmem_alloc(sizeof (vopstats_t), KM_SLEEP);
		initialize_vopstats(vopstats_fstype[fstype]);
		(void) new_vskstat(ksname, vopstats_fstype[fstype]);
	}
	return (err);
}

/*
 * Remove a filesystem
 */
static int
mod_removefs(struct modlfs *modl, struct modlinkage *modlp)
{
	struct vfssw *vswp;
	struct modctl *mcp;
	char *modname;

	if (moddebug & MODDEBUG_NOAUL_FS)
		return (EBUSY);

	WLOCK_VFSSW();
	if ((vswp = vfs_getvfsswbyname(modl->fs_vfsdef->name)) == NULL) {
		mcp = mod_getctl(modlp);
		ASSERT(mcp != NULL);
		modname = mcp->mod_modname;
		WUNLOCK_VFSSW();
		cmn_err(CE_WARN, uninstall_err, modname);
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

/*
 * Get status of a streams module.
 */
/*ARGSUSED*/
static int
mod_infostrmod(struct modlstrmod *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = -1;	/* no useful info */
	return (0);
}


/*
 * Install a streams module.
 */
/*ARGSUSED*/
static int
mod_installstrmod(struct modlstrmod *modl, struct modlinkage *modlp)
{
	struct fmodsw *fp = modl->strmod_fmodsw;

	if (!(fp->f_flag & D_MP)) {
		cmn_err(CE_WARN, "mod_install: MT-unsafe strmod '%s' rejected",
		    fp->f_name);
		return (ENXIO);
	}

	return (fmodsw_register(fp->f_name, fp->f_str, fp->f_flag));
}

/*
 * Remove a streams module.
 */
/*ARGSUSED*/
static int
mod_removestrmod(struct modlstrmod *modl, struct modlinkage *modlp)
{
	if (moddebug & MODDEBUG_NOAUL_STR)
		return (EBUSY);

	return (fmodsw_unregister(modl->strmod_fmodsw->f_name));
}

/*
 * Get status of a socket module.
 */
/*ARGSUSED*/
static int
mod_infosockmod(struct modlsockmod *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = -1;	/* no useful info */
	return (0);
}

/*
 * Install a socket module.
 */
/*ARGSUSED*/
static int
mod_installsockmod(struct modlsockmod *modl, struct modlinkage *modlp)
{
	struct modctl *mcp;
	char *mod_name;

	mcp = mod_getctl(modlp);
	ASSERT(mcp != NULL);
	mod_name = mcp->mod_modname;
	if (strcmp(mod_name, modl->sockmod_reg_info->smod_name) != 0) {
#ifdef DEBUG
		cmn_err(CE_CONT, "mod_installsockmod: different names"
		    " %s != %s \n", mod_name,
		    modl->sockmod_reg_info->smod_name);
#endif
		return (EINVAL);
	}

	/*
	 * Register module.
	 */
	return (smod_register(modl->sockmod_reg_info));
}

/*
 * Remove a socket module.
 */
/*ARGSUSED*/
static int
mod_removesockmod(struct modlsockmod *modl, struct modlinkage *modlp)
{
	/*
	 * unregister from the global socket creation table
	 * check the refcnt in the lookup table
	 */
	return (smod_unregister(modl->sockmod_reg_info->smod_name));
}

/*
 * Get status of a scheduling class module.
 */
/*ARGSUSED1*/
static int
mod_infosched(struct modlsched *modl, struct modlinkage *modlp, int *p0)
{
	int	status;
	auto id_t	cid;

	status = getcidbyname(modl->sched_class->cl_name, &cid);

	if (status != 0)
		*p0 = -1;
	else
		*p0 = cid;

	return (0);
}

/*
 * Install a scheduling class module.
 */
/*ARGSUSED1*/
static int
mod_installsched(struct modlsched *modl, struct modlinkage *modlp)
{
	sclass_t *clp;
	int status;
	id_t cid;

	/*
	 * See if module is already installed.
	 */
	mutex_enter(&class_lock);
	status = alloc_cid(modl->sched_class->cl_name, &cid);
	mutex_exit(&class_lock);
	ASSERT(status == 0);
	clp = &sclass[cid];
	rw_enter(clp->cl_lock, RW_WRITER);
	if (SCHED_INSTALLED(clp)) {
		printf("scheduling class %s is already installed\n",
		    modl->sched_class->cl_name);
		rw_exit(clp->cl_lock);
		return (EBUSY);		/* it's already there */
	}

	clp->cl_init = modl->sched_class->cl_init;
	clp->cl_funcs = modl->sched_class->cl_funcs;
	modl->sched_class = clp;
	disp_add(clp);
	loaded_classes++;		/* for priocntl system call */
	rw_exit(clp->cl_lock);
	return (0);
}

/*
 * Remove a scheduling class module.
 *
 * we only null out the init func and the class functions because
 * once a class has been loaded it has that slot in the class
 * array until the next reboot. We don't decrement loaded_classes
 * because this keeps count of the number of classes that have
 * been loaded for this session. It will have to be this way until
 * we implement the class array as a linked list and do true
 * dynamic allocation.
 */
static int
mod_removesched(struct modlsched *modl, struct modlinkage *modlp)
{
	int status;
	sclass_t *clp;
	struct modctl *mcp;
	char *modname;
	id_t cid;

	status = getcidbyname(modl->sched_class->cl_name, &cid);
	if (status != 0) {
		mcp = mod_getctl(modlp);
		ASSERT(mcp != NULL);
		modname = mcp->mod_modname;
		cmn_err(CE_WARN, uninstall_err, modname);
		return (EINVAL);
	}
	clp = &sclass[cid];
	if (moddebug & MODDEBUG_NOAUL_SCHED ||
	    !rw_tryenter(clp->cl_lock, RW_WRITER))
		return (EBUSY);

	clp->cl_init = NULL;
	clp->cl_funcs = NULL;
	rw_exit(clp->cl_lock);
	return (0);
}

/*
 * Get status of an exec module.
 */
/*ARGSUSED1*/
static int
mod_infoexec(struct modlexec *modl, struct modlinkage *modlp, int *p0)
{
	struct execsw *eswp;

	if ((eswp = findexecsw(modl->exec_execsw->exec_magic)) == NULL)
		*p0 = -1;
	else
		*p0 = eswp - execsw;

	return (0);
}

/*
 * Install an exec module.
 */
static int
mod_installexec(struct modlexec *modl, struct modlinkage *modlp)
{
	struct execsw *eswp;
	struct modctl *mcp;
	char *modname;
	char *magic;
	size_t magic_size;

	/*
	 * See if execsw entry is already allocated.  Can't use findexectype()
	 * because we may get a recursive call to here.
	 */

	if ((eswp = findexecsw(modl->exec_execsw->exec_magic)) == NULL) {
		mcp = mod_getctl(modlp);
		ASSERT(mcp != NULL);
		modname = mcp->mod_modname;
		magic = modl->exec_execsw->exec_magic;
		magic_size = modl->exec_execsw->exec_maglen;
		if ((eswp = allocate_execsw(modname, magic, magic_size)) ==
		    NULL) {
			printf("no unused entries in 'execsw'\n");
			return (ENOSPC);
		}
	}
	if (eswp->exec_func != NULL) {
		printf("exec type %x is already installed\n",
		    *eswp->exec_magic);
			return (EBUSY);		 /* it's already there! */
	}

	rw_enter(eswp->exec_lock, RW_WRITER);
	eswp->exec_func = modl->exec_execsw->exec_func;
	eswp->exec_core = modl->exec_execsw->exec_core;
	rw_exit(eswp->exec_lock);

	return (0);
}

/*
 * Remove an exec module.
 */
static int
mod_removeexec(struct modlexec *modl, struct modlinkage *modlp)
{
	struct execsw *eswp;
	struct modctl *mcp;
	char *modname;

	eswp = findexecsw(modl->exec_execsw->exec_magic);
	if (eswp == NULL) {
		mcp = mod_getctl(modlp);
		ASSERT(mcp != NULL);
		modname = mcp->mod_modname;
		cmn_err(CE_WARN, uninstall_err, modname);
		return (EINVAL);
	}
	if (moddebug & MODDEBUG_NOAUL_EXEC ||
	    !rw_tryenter(eswp->exec_lock, RW_WRITER))
		return (EBUSY);
	eswp->exec_func = NULL;
	eswp->exec_core = NULL;
	rw_exit(eswp->exec_lock);
	return (0);
}

/*
 * Find a free sysent entry or check if the specified one is free.
 */
static struct sysent *
mod_getsysent(struct modlinkage *modlp, struct sysent *se)
{
	int sysnum;
	struct modctl *mcp;
	char *mod_name;

	if ((mcp = mod_getctl(modlp)) == NULL) {
		/*
		 * This happens when we're looking up the module
		 * pointer as part of a stub installation.  So
		 * there's no need to whine at this point.
		 */
		return (NULL);
	}

	mod_name = mcp->mod_modname;

	if ((sysnum = mod_getsysnum(mod_name)) == -1) {
		cmn_err(CE_WARN, "system call missing from bind file");
		return (NULL);
	}

	if (sysnum > 0 && sysnum < NSYSCALL &&
	    (se[sysnum].sy_flags & (SE_LOADABLE | SE_NOUNLOAD)))
		return (se + sysnum);

	cmn_err(CE_WARN, "system call entry %d is already in use", sysnum);
	return (NULL);
}

/*
 * IP Policy Modules.
 */
/*ARGSUSED*/
static int
mod_infoipp(struct modlipp *modl, struct modlinkage *modlp, int *p0)
{
	struct modctl *mcp = mod_getctl(modlp);
	ipp_mod_id_t mid;

	if (mcp == NULL) {
		*p0 = -1;
		return (0);	/* module is not yet installed */
	}

	mid = ipp_mod_lookup(mcp->mod_modname);

	*p0 = mid;
	return (0);
}

static int
mod_installipp(struct modlipp *modl, struct modlinkage *modlp)
{
	struct modctl *mcp = mod_getctl(modlp);

	ASSERT(mcp != NULL);
	return (ipp_mod_register(mcp->mod_modname, modl->ipp_ops));
}

/*ARGSUSED*/
static int
mod_removeipp(struct modlipp *modl, struct modlinkage *modlp)
{
	struct modctl *mcp = mod_getctl(modlp);
	extern kthread_id_t mod_aul_thread;
	ipp_mod_id_t mid;

	ASSERT(mcp != NULL);

	if ((moddebug & MODDEBUG_NOAUL_IPP) && (mod_aul_thread == curthread))
		return (EBUSY);

	mid = ipp_mod_lookup(mcp->mod_modname);
	ASSERT(mid != IPP_MOD_INVAL);

	return (ipp_mod_unregister(mid));
}

/*
 * Manage kiconv modules.
 */
/*ARGSUSED*/
static int
mod_installkiconv(struct modlkiconv *modl, struct modlinkage *modlp)
{
	return (kiconv_register_module(modl->kiconv_moddef));
}

/*ARGSUSED*/
static int
mod_removekiconv(struct modlkiconv *modl, struct modlinkage *modlp)
{
	return (kiconv_unregister_module(modl->kiconv_moddef));
}
