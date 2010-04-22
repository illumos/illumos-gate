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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * modctl system call for loadable module support.
 */

#include <sys/param.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/time.h>
#include <sys/reboot.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/kmem.h>
#include <sys/sysconf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/bootconf.h>
#include <sys/dc_ki.h>
#include <sys/cladm.h>
#include <sys/dtrace.h>
#include <sys/kdi.h>

#include <sys/devpolicy.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/devops.h>
#include <sys/autoconf.h>
#include <sys/hwconf.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/sysmacros.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <sys/instance.h>
#include <sys/modhash.h>
#include <sys/modhash_impl.h>
#include <sys/dacf_impl.h>
#include <sys/vfs.h>
#include <sys/pathname.h>
#include <sys/console.h>
#include <sys/policy.h>
#include <ipp/ipp_impl.h>
#include <sys/fs/dv_node.h>
#include <sys/strsubr.h>
#include <sys/fs/sdev_impl.h>

static int		mod_circdep(struct modctl *);
static int		modinfo(modid_t, struct modinfo *);

static void		mod_uninstall_all(void);
static int		mod_getinfo(struct modctl *, struct modinfo *);
static struct modctl	*allocate_modp(const char *, const char *);

static int		mod_load(struct modctl *, int);
static void		mod_unload(struct modctl *);
static int		modinstall(struct modctl *);
static int		moduninstall(struct modctl *);

static struct modctl	*mod_hold_by_name_common(struct modctl *, const char *);
static struct modctl	*mod_hold_next_by_id(modid_t);
static struct modctl	*mod_hold_loaded_mod(struct modctl *, char *, int *);
static struct modctl	*mod_hold_installed_mod(char *, int, int, int *);

static void		mod_release(struct modctl *);
static void		mod_make_requisite(struct modctl *, struct modctl *);
static int		mod_install_requisites(struct modctl *);
static void		check_esc_sequences(char *, char *);
static struct modctl	*mod_hold_by_name_requisite(struct modctl *, char *);

/*
 * module loading thread control structure. Calls to kobj_load_module()() are
 * handled off to a separate thead using this structure.
 */
struct loadmt {
	ksema_t		sema;
	struct modctl	*mp;
	int		usepath;
	kthread_t	*owner;
	int		retval;
};

static void	modload_thread(struct loadmt *);

kcondvar_t	mod_cv;
kcondvar_t	mod_uninstall_cv;	/* Communication between swapper */
					/* and the uninstall daemon. */
kmutex_t	mod_lock;		/* protects &modules insert linkage, */
					/* mod_busy, mod_want, and mod_ref. */
					/* blocking operations while holding */
					/* mod_lock should be avoided */
kmutex_t	mod_uninstall_lock;	/* protects mod_uninstall_cv */
kthread_id_t	mod_aul_thread;

int		modunload_wait;
kmutex_t	modunload_wait_mutex;
kcondvar_t	modunload_wait_cv;
int		modunload_active_count;
int		modunload_disable_count;

int	isminiroot;		/* set if running as miniroot */
int	modrootloaded;		/* set after root driver and fs are loaded */
int	moddebug = 0x0;		/* debug flags for module writers */
int	swaploaded;		/* set after swap driver and fs are loaded */
int	bop_io_quiesced = 0;	/* set when BOP I/O can no longer be used */
int	last_module_id;
clock_t	mod_uninstall_interval = 0;
int	mod_uninstall_pass_max = 6;
int	mod_uninstall_ref_zero;	/* # modules that went mod_ref == 0 */
int	mod_uninstall_pass_exc;	/* mod_uninstall_all left new stuff */

int	ddi_modclose_unload = 1;	/* 0 -> just decrement reference */

int	devcnt_incr	= 256;		/* allow for additional drivers */
int	devcnt_min	= 512;		/* and always at least this number */

struct devnames *devnamesp;
struct devnames orphanlist;

krwlock_t	devinfo_tree_lock;	/* obsolete, to be removed */

#define	MAJBINDFILE "/etc/name_to_major"
#define	SYSBINDFILE "/etc/name_to_sysnum"

static char	majbind[] = MAJBINDFILE;
static char	sysbind[] = SYSBINDFILE;
static uint_t	mod_autounload_key;	/* for module autounload detection */

extern int obpdebug;

#define	DEBUGGER_PRESENT	((boothowto & RB_DEBUG) || (obpdebug != 0))

static int minorperm_loaded = 0;

void
mod_setup(void)
{
	struct sysent *callp;
	int callnum, exectype;
	int	num_devs;
	int	i;

	/*
	 * Initialize the list of loaded driver dev_ops.
	 * XXX - This must be done before reading the system file so that
	 * forceloads of drivers will work.
	 */
	num_devs = read_binding_file(majbind, mb_hashtab, make_mbind);
	/*
	 * Since read_binding_file is common code, it doesn't enforce that all
	 * of the binding file entries have major numbers <= MAXMAJ32.	Thus,
	 * ensure that we don't allocate some massive amount of space due to a
	 * bad entry.  We can't have major numbers bigger than MAXMAJ32
	 * until file system support for larger major numbers exists.
	 */

	/*
	 * Leave space for expansion, but not more than L_MAXMAJ32
	 */
	devcnt = MIN(num_devs + devcnt_incr, L_MAXMAJ32);
	devcnt = MAX(devcnt, devcnt_min);
	devopsp = kmem_alloc(devcnt * sizeof (struct dev_ops *), KM_SLEEP);
	for (i = 0; i < devcnt; i++)
		devopsp[i] = &mod_nodev_ops;

	init_devnamesp(devcnt);

	/*
	 * Sync up with the work that the stand-alone linker has already done.
	 */
	(void) kobj_sync();

	if (boothowto & RB_DEBUG)
		kdi_dvec_modavail();

	make_aliases(mb_hashtab);

	/*
	 * Initialize streams device implementation structures.
	 */
	devimpl = kmem_zalloc(devcnt * sizeof (cdevsw_impl_t), KM_SLEEP);

	/*
	 * If the cl_bootstrap module is present,
	 * we should be configured as a cluster. Loading this module
	 * will set "cluster_bootflags" to non-zero.
	 */
	(void) modload("misc", "cl_bootstrap");

	(void) read_binding_file(sysbind, sb_hashtab, make_mbind);
	init_syscallnames(NSYSCALL);

	/*
	 * Start up dynamic autoconfiguration framework (dacf).
	 */
	mod_hash_init();
	dacf_init();

	/*
	 * Start up IP policy framework (ipp).
	 */
	ipp_init();

	/*
	 * Allocate loadable native system call locks.
	 */
	for (callnum = 0, callp = sysent; callnum < NSYSCALL;
	    callnum++, callp++) {
		if (LOADABLE_SYSCALL(callp)) {
			if (mod_getsysname(callnum) != NULL) {
				callp->sy_lock =
				    kobj_zalloc(sizeof (krwlock_t), KM_SLEEP);
				rw_init(callp->sy_lock, NULL, RW_DEFAULT, NULL);
			} else {
				callp->sy_flags &= ~SE_LOADABLE;
				callp->sy_callc = nosys;
			}
#ifdef DEBUG
		} else {
			/*
			 * Do some sanity checks on the sysent table
			 */
			switch (callp->sy_flags & SE_RVAL_MASK) {
			case SE_32RVAL1:
				/* only r_val1 returned */
			case SE_32RVAL1 | SE_32RVAL2:
				/* r_val1 and r_val2 returned */
			case SE_64RVAL:
				/* 64-bit rval returned */
				break;
			default:
				cmn_err(CE_WARN, "sysent[%d]: bad flags %x",
				    callnum, callp->sy_flags);
			}
#endif
		}
	}

#ifdef _SYSCALL32_IMPL
	/*
	 * Allocate loadable system call locks for 32-bit compat syscalls
	 */
	for (callnum = 0, callp = sysent32; callnum < NSYSCALL;
	    callnum++, callp++) {
		if (LOADABLE_SYSCALL(callp)) {
			if (mod_getsysname(callnum) != NULL) {
				callp->sy_lock =
				    kobj_zalloc(sizeof (krwlock_t), KM_SLEEP);
				rw_init(callp->sy_lock, NULL, RW_DEFAULT, NULL);
			} else {
				callp->sy_flags &= ~SE_LOADABLE;
				callp->sy_callc = nosys;
			}
#ifdef DEBUG
		} else {
			/*
			 * Do some sanity checks on the sysent table
			 */
			switch (callp->sy_flags & SE_RVAL_MASK) {
			case SE_32RVAL1:
				/* only r_val1 returned */
			case SE_32RVAL1 | SE_32RVAL2:
				/* r_val1 and r_val2 returned */
			case SE_64RVAL:
				/* 64-bit rval returned */
				break;
			default:
				cmn_err(CE_WARN, "sysent32[%d]: bad flags %x",
				    callnum, callp->sy_flags);
				goto skip;
			}

			/*
			 * Cross-check the native and compatibility tables.
			 */
			if (callp->sy_callc == nosys ||
			    sysent[callnum].sy_callc == nosys)
				continue;
			/*
			 * If only one or the other slot is loadable, then
			 * there's an error -- they should match!
			 */
			if ((callp->sy_callc == loadable_syscall) ^
			    (sysent[callnum].sy_callc == loadable_syscall)) {
				cmn_err(CE_WARN, "sysent[%d] loadable?",
				    callnum);
			}
			/*
			 * This is more of a heuristic test -- if the
			 * system call returns two values in the 32-bit
			 * world, it should probably return two 32-bit
			 * values in the 64-bit world too.
			 */
			if (((callp->sy_flags & SE_32RVAL2) == 0) ^
			    ((sysent[callnum].sy_flags & SE_32RVAL2) == 0)) {
				cmn_err(CE_WARN, "sysent[%d] rval2 mismatch!",
				    callnum);
			}
skip:;
#endif	/* DEBUG */
		}
	}
#endif	/* _SYSCALL32_IMPL */

	/*
	 * Allocate loadable exec locks.  (Assumes all execs are loadable)
	 */
	for (exectype = 0; exectype < nexectype; exectype++) {
		execsw[exectype].exec_lock =
		    kobj_zalloc(sizeof (krwlock_t), KM_SLEEP);
		rw_init(execsw[exectype].exec_lock, NULL, RW_DEFAULT, NULL);
	}

	read_class_file();

	/* init thread specific structure for mod_uninstall_all */
	tsd_create(&mod_autounload_key, NULL);
}

static int
modctl_modload(int use_path, char *filename, int *rvp)
{
	struct modctl *modp;
	int retval = 0;
	char *filenamep;
	int modid;

	filenamep = kmem_zalloc(MOD_MAXPATH, KM_SLEEP);

	if (copyinstr(filename, filenamep, MOD_MAXPATH, 0)) {
		retval = EFAULT;
		goto out;
	}

	filenamep[MOD_MAXPATH - 1] = 0;
	modp = mod_hold_installed_mod(filenamep, use_path, 0, &retval);

	if (modp == NULL)
		goto out;

	modp->mod_loadflags |= MOD_NOAUTOUNLOAD;
	modid = modp->mod_id;
	mod_release_mod(modp);
	CPU_STATS_ADDQ(CPU, sys, modload, 1);
	if (rvp != NULL && copyout(&modid, rvp, sizeof (modid)) != 0)
		retval = EFAULT;
out:
	kmem_free(filenamep, MOD_MAXPATH);

	return (retval);
}

static int
modctl_modunload(modid_t id)
{
	int rval = 0;

	if (id == 0) {
#ifdef DEBUG
		/*
		 * Turn on mod_uninstall_daemon
		 */
		if (mod_uninstall_interval == 0) {
			mod_uninstall_interval = 60;
			modreap();
			return (rval);
		}
#endif
		mod_uninstall_all();
	} else {
		rval = modunload(id);
	}
	return (rval);
}

static int
modctl_modinfo(modid_t id, struct modinfo *umodi)
{
	int retval;
	struct modinfo modi;
#if defined(_SYSCALL32_IMPL)
	int nobase;
	struct modinfo32 modi32;
#endif

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(umodi, &modi, sizeof (struct modinfo)) != 0)
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		bzero(&modi, sizeof (modi));
		if (copyin(umodi, &modi32, sizeof (struct modinfo32)) != 0)
			return (EFAULT);
		modi.mi_info = modi32.mi_info;
		modi.mi_id = modi32.mi_id;
		modi.mi_nextid = modi32.mi_nextid;
		nobase = modi.mi_info & MI_INFO_NOBASE;
	}
#endif
	/*
	 * This flag is -only- for the kernels use.
	 */
	modi.mi_info &= ~MI_INFO_LINKAGE;

	retval = modinfo(id, &modi);
	if (retval)
		return (retval);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&modi, umodi, sizeof (struct modinfo)) != 0)
			retval = EFAULT;
#ifdef _SYSCALL32_IMPL
	} else {
		int i;

		if (!nobase && (uintptr_t)modi.mi_base > UINT32_MAX)
			return (EOVERFLOW);

		modi32.mi_info = modi.mi_info;
		modi32.mi_state = modi.mi_state;
		modi32.mi_id = modi.mi_id;
		modi32.mi_nextid = modi.mi_nextid;
		modi32.mi_base = (caddr32_t)(uintptr_t)modi.mi_base;
		modi32.mi_size = modi.mi_size;
		modi32.mi_rev = modi.mi_rev;
		modi32.mi_loadcnt = modi.mi_loadcnt;
		bcopy(modi.mi_name, modi32.mi_name, sizeof (modi32.mi_name));
		for (i = 0; i < MODMAXLINK32; i++) {
			modi32.mi_msinfo[i].msi_p0 = modi.mi_msinfo[i].msi_p0;
			bcopy(modi.mi_msinfo[i].msi_linkinfo,
			    modi32.mi_msinfo[i].msi_linkinfo,
			    sizeof (modi32.mi_msinfo[0].msi_linkinfo));
		}
		if (copyout(&modi32, umodi, sizeof (struct modinfo32)) != 0)
			retval = EFAULT;
#endif
	}

	return (retval);
}

/*
 * Return the last major number in the range of permissible major numbers.
 */
/*ARGSUSED*/
static int
modctl_modreserve(modid_t id, int *data)
{
	if (copyout(&devcnt, data, sizeof (devcnt)) != 0)
		return (EFAULT);
	return (0);
}

/* Add/Remove driver and binding aliases */
static int
modctl_update_driver_aliases(int add, int *data)
{
	struct modconfig	mc;
	int			i, n, rv = 0;
	struct aliases		alias;
	struct aliases		*ap;
	char			name[MAXMODCONFNAME];
	char			cname[MAXMODCONFNAME];
	char			*drvname;
	int			resid;
	struct alias_info {
		char	*alias_name;
		int	alias_resid;
	} *aliases, *aip;

	bzero(&mc, sizeof (struct modconfig));
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(data, &mc, sizeof (struct modconfig)) != 0)
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		struct modconfig32 modc32;
		if (copyin(data, &modc32, sizeof (struct modconfig32)) != 0)
			return (EFAULT);
		else {
			bcopy(modc32.drvname, mc.drvname,
			    sizeof (modc32.drvname));
			bcopy(modc32.drvclass, mc.drvclass,
			    sizeof (modc32.drvclass));
			mc.major = modc32.major;
			mc.flags = modc32.flags;
			mc.num_aliases = modc32.num_aliases;
			mc.ap = (struct aliases *)(uintptr_t)modc32.ap;
		}
	}
#endif

	/*
	 * If the driver is already in the mb_hashtab, and the name given
	 * doesn't match that driver's name, fail.  Otherwise, pass, since
	 * we may be adding aliases.
	 */
	drvname = mod_major_to_name(mc.major);
	if ((drvname != NULL) && strcmp(drvname, mc.drvname) != 0)
		return (EINVAL);

	/*
	 * Precede alias removal by unbinding as many devices as possible.
	 */
	if (add == 0) {
		(void) i_ddi_unload_drvconf(mc.major);
		i_ddi_unbind_devs(mc.major);
	}

	/*
	 * Add/remove each supplied driver alias to/from mb_hashtab
	 */
	ap = mc.ap;
	if (mc.num_aliases > 0)
		aliases = kmem_zalloc(
		    mc.num_aliases * sizeof (struct alias_info), KM_SLEEP);
	aip = aliases;
	for (i = 0; i < mc.num_aliases; i++) {
		bzero(&alias, sizeof (struct aliases));
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(ap, &alias, sizeof (struct aliases)) != 0) {
				rv = EFAULT;
				goto error;
			}
			if (alias.a_len > MAXMODCONFNAME) {
				rv = EINVAL;
				goto error;
			}
			if (copyin(alias.a_name, name, alias.a_len) != 0) {
				rv = EFAULT;
				goto error;
			}
			if (name[alias.a_len - 1] != '\0') {
				rv = EINVAL;
				goto error;
			}
		}
#ifdef _SYSCALL32_IMPL
		else {
			struct aliases32 al32;
			bzero(&al32, sizeof (struct aliases32));
			if (copyin(ap, &al32, sizeof (struct aliases32)) != 0) {
				rv = EFAULT;
				goto error;
			}
			if (al32.a_len > MAXMODCONFNAME) {
				rv = EINVAL;
				goto error;
			}
			if (copyin((void *)(uintptr_t)al32.a_name,
			    name, al32.a_len) != 0) {
				rv = EFAULT;
				goto error;
			}
			if (name[al32.a_len - 1] != '\0') {
				rv = EINVAL;
				goto error;
			}
			alias.a_next = (void *)(uintptr_t)al32.a_next;
		}
#endif
		check_esc_sequences(name, cname);
		aip->alias_name = strdup(cname);
		ap = alias.a_next;
		aip++;
	}

	if (add == 0) {
		ap = mc.ap;
		resid = 0;
		aip = aliases;
		/* attempt to unbind all devices bound to each alias */
		for (i = 0; i < mc.num_aliases; i++) {
			n = i_ddi_unbind_devs_by_alias(
			    mc.major, aip->alias_name);
			resid += n;
			aip->alias_resid = n;
		}

		/*
		 * If some device bound to an alias remains in use,
		 * and override wasn't specified, no change is made to
		 * the binding state and we fail the operation.
		 */
		if (resid > 0 && ((mc.flags & MOD_UNBIND_OVERRIDE) == 0)) {
			rv = EBUSY;
			goto error;
		}

		/*
		 * No device remains bound of any of the aliases,
		 * or force was requested.  Mark each alias as
		 * inactive via delete_mbind so no future binds
		 * to this alias take place and that a new
		 * binding can be established.
		 */
		aip = aliases;
		for (i = 0; i < mc.num_aliases; i++) {
			if (moddebug & MODDEBUG_BINDING)
				cmn_err(CE_CONT, "Removing binding for %s "
				    "(%d active references)\n",
				    aip->alias_name, aip->alias_resid);
			delete_mbind(aip->alias_name, mb_hashtab);
			aip++;
		}
		rv = 0;
	} else {
		aip = aliases;
		for (i = 0; i < mc.num_aliases; i++) {
			if (moddebug & MODDEBUG_BINDING)
				cmn_err(CE_NOTE, "Adding binding for '%s'\n",
				    aip->alias_name);
			(void) make_mbind(aip->alias_name,
			    mc.major, NULL, mb_hashtab);
			aip++;
		}
		/*
		 * Try to establish an mbinding for mc.drvname, and add it to
		 * devnames. Add class if any after establishing the major
		 * number.
		 */
		(void) make_mbind(mc.drvname, mc.major, NULL, mb_hashtab);
		if ((rv = make_devname(mc.drvname, mc.major,
		    (mc.flags & MOD_ADDMAJBIND_UPDATE) ?
		    DN_DRIVER_INACTIVE : 0)) != 0) {
			goto error;
		}

		if (mc.drvclass[0] != '\0')
			add_class(mc.drvname, mc.drvclass);
		if ((mc.flags & MOD_ADDMAJBIND_UPDATE) == 0) {
			(void) i_ddi_load_drvconf(mc.major);
		}
	}

	/*
	 * Ensure that all nodes are bound to the most appropriate driver
	 * possible, attempting demotion and rebind when a more appropriate
	 * driver now exists.  But not when adding a driver update-only.
	 */
	if ((add == 0) || ((mc.flags & MOD_ADDMAJBIND_UPDATE) == 0)) {
		i_ddi_bind_devs();
		i_ddi_di_cache_invalidate();
	}

error:
	if (mc.num_aliases > 0) {
		aip = aliases;
		for (i = 0; i < mc.num_aliases; i++) {
			if (aip->alias_name != NULL)
				strfree(aip->alias_name);
			aip++;
		}
		kmem_free(aliases, mc.num_aliases * sizeof (struct alias_info));
	}
	return (rv);
}

static int
modctl_add_driver_aliases(int *data)
{
	return (modctl_update_driver_aliases(1, data));
}

static int
modctl_remove_driver_aliases(int *data)
{
	return (modctl_update_driver_aliases(0, data));
}

static int
modctl_rem_major(major_t major)
{
	struct devnames *dnp;

	if (major >= devcnt)
		return (EINVAL);

	/* mark devnames as removed */
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (dnp->dn_name == NULL ||
	    (dnp->dn_flags & (DN_DRIVER_REMOVED | DN_TAKEN_GETUDEV))) {
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (EINVAL);
	}
	dnp->dn_flags |= DN_DRIVER_REMOVED;
	pm_driver_removed(major);
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	(void) i_ddi_unload_drvconf(major);
	i_ddi_unbind_devs(major);
	i_ddi_bind_devs();
	i_ddi_di_cache_invalidate();

	/* purge all the bindings to this driver */
	purge_mbind(major, mb_hashtab);
	return (0);
}

static struct vfs *
path_to_vfs(char *name)
{
	vnode_t *vp;
	struct vfs *vfsp;

	if (lookupname(name, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp))
		return (NULL);

	vfsp = vp->v_vfsp;
	VN_RELE(vp);
	return (vfsp);
}

static int
new_vfs_in_modpath()
{
	static int n_modpath = 0;
	static char *modpath_copy;
	static struct pathvfs {
		char *path;
		struct vfs *vfsp;
	} *pathvfs;

	int i, new_vfs = 0;
	char *tmp, *tmp1;
	struct vfs *vfsp;

	if (n_modpath != 0) {
		for (i = 0; i < n_modpath; i++) {
			vfsp = path_to_vfs(pathvfs[i].path);
			if (vfsp != pathvfs[i].vfsp) {
				pathvfs[i].vfsp = vfsp;
				if (vfsp)
					new_vfs = 1;
			}
		}
		return (new_vfs);
	}

	/*
	 * First call, initialize the pathvfs structure
	 */
	modpath_copy = i_ddi_strdup(default_path, KM_SLEEP);
	tmp = modpath_copy;
	n_modpath = 1;
	tmp1 = strchr(tmp, ' ');
	while (tmp1) {
		*tmp1 = '\0';
		n_modpath++;
		tmp = tmp1 + 1;
		tmp1 = strchr(tmp, ' ');
	}

	pathvfs = kmem_zalloc(n_modpath * sizeof (struct pathvfs), KM_SLEEP);
	tmp = modpath_copy;
	for (i = 0; i < n_modpath; i++) {
		pathvfs[i].path = tmp;
		vfsp = path_to_vfs(tmp);
		pathvfs[i].vfsp = vfsp;
		tmp += strlen(tmp) + 1;
	}
	return (1);	/* always reread driver.conf the first time */
}

static int
modctl_load_drvconf(major_t major, int flags)
{
	int ret;

	/*
	 * devfsadm -u - read all new driver.conf files
	 * and bind and configure devices for new drivers.
	 */
	if (flags & MOD_LOADDRVCONF_RECONF) {
		(void) i_ddi_load_drvconf(DDI_MAJOR_T_NONE);
		i_ddi_bind_devs();
		i_ddi_di_cache_invalidate();
		return (0);
	}

	/*
	 * update_drv <drv> - reload driver.conf for the specified driver
	 */
	if (major != DDI_MAJOR_T_NONE) {
		ret = i_ddi_load_drvconf(major);
		if (ret == 0)
			i_ddi_bind_devs();
		return (ret);
	}

	/*
	 * We are invoked to rescan new driver.conf files. It is
	 * only necessary if a new file system was mounted in the
	 * module_path. Because rescanning driver.conf files can
	 * take some time on older platforms (sun4m), the following
	 * code skips unnecessary driver.conf rescans to optimize
	 * boot performance.
	 */
	if (new_vfs_in_modpath()) {
		(void) i_ddi_load_drvconf(DDI_MAJOR_T_NONE);
		/*
		 * If we are still initializing io subsystem,
		 * load drivers with ddi-forceattach property
		 */
		if (!i_ddi_io_initialized())
			i_ddi_forceattach_drivers();
	}
	return (0);
}

/*
 * Unload driver.conf file and follow up by attempting
 * to rebind devices to more appropriate driver.
 */
static int
modctl_unload_drvconf(major_t major)
{
	int ret;

	if (major >= devcnt)
		return (EINVAL);

	ret = i_ddi_unload_drvconf(major);
	if (ret != 0)
		return (ret);
	(void) i_ddi_unbind_devs(major);
	i_ddi_bind_devs();

	return (0);
}

static void
check_esc_sequences(char *str, char *cstr)
{
	int i;
	size_t len;
	char *p;

	len = strlen(str);
	for (i = 0; i < len; i++, str++, cstr++) {
		if (*str != '\\') {
			*cstr = *str;
		} else {
			p = str + 1;
			/*
			 * we only handle octal escape sequences for SPACE
			 */
			if (*p++ == '0' && *p++ == '4' && *p == '0') {
				*cstr = ' ';
				str += 3;
			} else {
				*cstr = *str;
			}
		}
	}
	*cstr = 0;
}

static int
modctl_getmodpathlen(int *data)
{
	int len;
	len = strlen(default_path);
	if (copyout(&len, data, sizeof (len)) != 0)
		return (EFAULT);
	return (0);
}

static int
modctl_getmodpath(char *data)
{
	if (copyout(default_path, data, strlen(default_path) + 1) != 0)
		return (EFAULT);
	return (0);
}

static int
modctl_read_sysbinding_file(void)
{
	(void) read_binding_file(sysbind, sb_hashtab, make_mbind);
	return (0);
}

static int
modctl_getmaj(char *uname, uint_t ulen, int *umajorp)
{
	char name[256];
	int retval;
	major_t major;

	if (ulen == 0)
		return (EINVAL);
	if ((retval = copyinstr(uname, name,
	    (ulen < 256) ? ulen : 256, 0)) != 0)
		return (retval);
	if ((major = mod_name_to_major(name)) == DDI_MAJOR_T_NONE)
		return (ENODEV);
	if (copyout(&major, umajorp, sizeof (major_t)) != 0)
		return (EFAULT);
	return (0);
}

static char **
convert_constraint_string(char *constraints, size_t len)
{
	int	i;
	int	n;
	char	*p;
	char	**array;

	ASSERT(constraints != NULL);
	ASSERT(len > 0);

	for (i = 0, p = constraints; strlen(p) > 0; i++, p += strlen(p) + 1)
		;

	n = i;

	if (n == 0) {
		kmem_free(constraints, len);
		return (NULL);
	}

	array = kmem_alloc((n + 1) * sizeof (char *), KM_SLEEP);

	for (i = 0, p = constraints; i < n; i++, p += strlen(p) + 1) {
		array[i] = i_ddi_strdup(p, KM_SLEEP);
	}
	array[n] = NULL;

	kmem_free(constraints, len);

	return (array);
}
/*ARGSUSED*/
static int
modctl_retire(char *path, char *uconstraints, size_t ulen)
{
	char	*pathbuf;
	char	*devpath;
	size_t	pathsz;
	int	retval;
	char	*constraints;
	char	**cons_array;

	if (path == NULL)
		return (EINVAL);

	if ((uconstraints == NULL) ^ (ulen == 0))
		return (EINVAL);

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	retval = copyinstr(path, pathbuf, MAXPATHLEN, &pathsz);
	if (retval != 0) {
		kmem_free(pathbuf, MAXPATHLEN);
		return (retval);
	}
	devpath = i_ddi_strdup(pathbuf, KM_SLEEP);
	kmem_free(pathbuf, MAXPATHLEN);

	/*
	 * First check if the device is already retired.
	 * If it is, then persist the retire anyway, just in case the retire
	 * store has got out of sync with the boot archive.
	 */
	if (e_ddi_device_retired(devpath)) {
		cmn_err(CE_NOTE, "Device: already retired: %s", devpath);
		(void) e_ddi_retire_persist(devpath);
		kmem_free(devpath, strlen(devpath) + 1);
		return (0);
	}

	cons_array = NULL;
	if (uconstraints) {
		constraints = kmem_alloc(ulen, KM_SLEEP);
		if (copyin(uconstraints, constraints, ulen)) {
			kmem_free(constraints, ulen);
			kmem_free(devpath, strlen(devpath) + 1);
			return (EFAULT);
		}
		cons_array = convert_constraint_string(constraints, ulen);
	}

	/*
	 * Try to retire the device first. The following
	 * routine will return an error only if the device
	 * is not retireable i.e. retire constraints forbid
	 * a retire. A return of success from this routine
	 * indicates that device is retireable.
	 */
	retval = e_ddi_retire_device(devpath, cons_array);
	if (retval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "constraints forbid retire: %s", devpath);
		kmem_free(devpath, strlen(devpath) + 1);
		return (ENOTSUP);
	}

	/*
	 * Ok, the retire succeeded. Persist the retire.
	 * If retiring a nexus, we need to only persist the
	 * nexus retire. Any children of a retired nexus
	 * are automatically covered by the retire store
	 * code.
	 */
	retval = e_ddi_retire_persist(devpath);
	if (retval != 0) {
		cmn_err(CE_WARN, "Failed to persist device retire: error %d: "
		    "%s", retval, devpath);
		kmem_free(devpath, strlen(devpath) + 1);
		return (retval);
	}
	if (moddebug & MODDEBUG_RETIRE)
		cmn_err(CE_NOTE, "Persisted retire of device: %s", devpath);

	kmem_free(devpath, strlen(devpath) + 1);
	return (0);
}

static int
modctl_is_retired(char *path, int *statep)
{
	char	*pathbuf;
	char	*devpath;
	size_t	pathsz;
	int	error;
	int	status;

	if (path == NULL || statep == NULL)
		return (EINVAL);

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	error = copyinstr(path, pathbuf, MAXPATHLEN, &pathsz);
	if (error != 0) {
		kmem_free(pathbuf, MAXPATHLEN);
		return (error);
	}
	devpath = i_ddi_strdup(pathbuf, KM_SLEEP);
	kmem_free(pathbuf, MAXPATHLEN);

	if (e_ddi_device_retired(devpath))
		status = 1;
	else
		status = 0;
	kmem_free(devpath, strlen(devpath) + 1);

	return (copyout(&status, statep, sizeof (status)) ? EFAULT : 0);
}

static int
modctl_unretire(char *path)
{
	char	*pathbuf;
	char	*devpath;
	size_t	pathsz;
	int	retired;
	int	retval;

	if (path == NULL)
		return (EINVAL);

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	retval = copyinstr(path, pathbuf, MAXPATHLEN, &pathsz);
	if (retval != 0) {
		kmem_free(pathbuf, MAXPATHLEN);
		return (retval);
	}
	devpath = i_ddi_strdup(pathbuf, KM_SLEEP);
	kmem_free(pathbuf, MAXPATHLEN);

	/*
	 * We check if a device is retired (first) before
	 * unpersisting the retire, because we use the
	 * retire store to determine if a device is retired.
	 * If we unpersist first, the device will always appear
	 * to be unretired. For the rationale behind unpersisting
	 * a device that is not retired, see the next comment.
	 */
	retired = e_ddi_device_retired(devpath);

	/*
	 * We call unpersist unconditionally because the lookup
	 * for retired devices (e_ddi_device_retired()), skips "bypassed"
	 * devices. We still want to be able remove "bypassed" entries
	 * from the persistent store, so we unpersist unconditionally
	 * i.e. whether or not the entry is found on a lookup.
	 *
	 * e_ddi_retire_unpersist() returns 1 if it found and cleared
	 * an entry from the retire store or 0 otherwise.
	 */
	if (e_ddi_retire_unpersist(devpath))
		if (moddebug & MODDEBUG_RETIRE) {
			cmn_err(CE_NOTE, "Unpersisted retire of device: %s",
			    devpath);
		}

	/*
	 * Check if the device is already unretired. If so,
	 * the unretire becomes a NOP
	 */
	if (!retired) {
		cmn_err(CE_NOTE, "Not retired: %s", devpath);
		kmem_free(devpath, strlen(devpath) + 1);
		return (0);
	}

	retval = e_ddi_unretire_device(devpath);
	if (retval != 0) {
		cmn_err(CE_WARN, "cannot unretire device: error %d, path %s\n",
		    retval, devpath);
	}

	kmem_free(devpath, strlen(devpath) + 1);

	return (retval);
}

static int
modctl_getname(char *uname, uint_t ulen, int *umajorp)
{
	char *name;
	major_t major;

	if (copyin(umajorp, &major, sizeof (major)) != 0)
		return (EFAULT);
	if ((name = mod_major_to_name(major)) == NULL)
		return (ENODEV);
	if ((strlen(name) + 1) > ulen)
		return (ENOSPC);
	return (copyoutstr(name, uname, ulen, NULL));
}

static int
modctl_devt2instance(dev_t dev, int *uinstancep)
{
	int	instance;

	if ((instance = dev_to_instance(dev)) == -1)
		return (EINVAL);

	return (copyout(&instance, uinstancep, sizeof (int)));
}

/*
 * Return the sizeof of the device id.
 */
static int
modctl_sizeof_devid(dev_t dev, uint_t *len)
{
	uint_t		sz;
	ddi_devid_t	devid;

	/* get device id */
	if (ddi_lyr_get_devid(dev, &devid) == DDI_FAILURE)
		return (EINVAL);

	sz = ddi_devid_sizeof(devid);
	ddi_devid_free(devid);

	/* copyout device id size */
	if (copyout(&sz, len, sizeof (sz)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Return a copy of the device id.
 */
static int
modctl_get_devid(dev_t dev, uint_t len, ddi_devid_t udevid)
{
	uint_t		sz;
	ddi_devid_t	devid;
	int		err = 0;

	/* get device id */
	if (ddi_lyr_get_devid(dev, &devid) == DDI_FAILURE)
		return (EINVAL);

	sz = ddi_devid_sizeof(devid);

	/* Error if device id is larger than space allocated */
	if (sz > len) {
		ddi_devid_free(devid);
		return (ENOSPC);
	}

	/* copy out device id */
	if (copyout(devid, udevid, sz) != 0)
		err = EFAULT;
	ddi_devid_free(devid);
	return (err);
}

/*
 * return the /devices paths associated with the specified devid and
 * minor name.
 */
/*ARGSUSED*/
static int
modctl_devid2paths(ddi_devid_t udevid, char *uminor_name, uint_t flag,
	size_t *ulensp, char *upaths)
{
	ddi_devid_t	devid = NULL;
	int		devid_len;
	char		*minor_name = NULL;
	dev_info_t	*dip = NULL;
	int		circ;
	struct ddi_minor_data	*dmdp;
	char		*path = NULL;
	int		ulens;
	int		lens;
	int		len;
	dev_t		*devlist = NULL;
	int		ndevs;
	int		i;
	int		ret = 0;

	/*
	 * If upaths is NULL then we are only computing the amount of space
	 * needed to hold the paths and returning the value in *ulensp. If we
	 * are copying out paths then we get the amount of space allocated by
	 * the caller. If the actual space needed for paths is larger, or
	 * things are changing out from under us, then we return EAGAIN.
	 */
	if (upaths) {
		if (ulensp == NULL)
			return (EINVAL);
		if (copyin(ulensp, &ulens, sizeof (ulens)) != 0)
			return (EFAULT);
	}

	/*
	 * copyin enough of the devid to determine the length then
	 * reallocate and copy in the entire devid.
	 */
	devid_len = ddi_devid_sizeof(NULL);
	devid = kmem_alloc(devid_len, KM_SLEEP);
	if (copyin(udevid, devid, devid_len)) {
		ret = EFAULT;
		goto out;
	}
	len = devid_len;
	devid_len = ddi_devid_sizeof(devid);
	kmem_free(devid, len);
	devid = kmem_alloc(devid_len, KM_SLEEP);
	if (copyin(udevid, devid, devid_len)) {
		ret = EFAULT;
		goto out;
	}

	/* copyin the minor name if specified. */
	minor_name = uminor_name;
	if ((minor_name != DEVID_MINOR_NAME_ALL) &&
	    (minor_name != DEVID_MINOR_NAME_ALL_CHR) &&
	    (minor_name != DEVID_MINOR_NAME_ALL_BLK)) {
		minor_name = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (copyinstr(uminor_name, minor_name, MAXPATHLEN, 0)) {
			ret = EFAULT;
			goto out;
		}
	}

	/*
	 * Use existing function to resolve the devid into a devlist.
	 *
	 * NOTE: there is a loss of spectype information in the current
	 * ddi_lyr_devid_to_devlist implementation. We work around this by not
	 * passing down DEVID_MINOR_NAME_ALL here, but reproducing all minor
	 * node forms in the loop processing the devlist below. It would be
	 * best if at some point the use of this interface here was replaced
	 * with a path oriented call.
	 */
	if (ddi_lyr_devid_to_devlist(devid,
	    (minor_name == DEVID_MINOR_NAME_ALL) ?
	    DEVID_MINOR_NAME_ALL_CHR : minor_name,
	    &ndevs, &devlist) != DDI_SUCCESS) {
		ret = EINVAL;
		goto out;
	}

	/*
	 * loop over the devlist, converting each devt to a path and doing
	 * a copyout of the path and computation of the amount of space
	 * needed to hold all the paths
	 */
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	for (i = 0, lens = 0; i < ndevs; i++) {

		/* find the dip associated with the dev_t */
		if ((dip = e_ddi_hold_devi_by_dev(devlist[i], 0)) == NULL)
			continue;

		/* loop over all the minor nodes, skipping ones we don't want */
		ndi_devi_enter(dip, &circ);
		for (dmdp = DEVI(dip)->devi_minor; dmdp; dmdp = dmdp->next) {
			if ((dmdp->ddm_dev != devlist[i]) ||
			    (dmdp->type != DDM_MINOR))
				continue;

			if ((minor_name != DEVID_MINOR_NAME_ALL) &&
			    (minor_name != DEVID_MINOR_NAME_ALL_CHR) &&
			    (minor_name != DEVID_MINOR_NAME_ALL_BLK) &&
			    strcmp(minor_name, dmdp->ddm_name))
				continue;
			else {
				if ((minor_name == DEVID_MINOR_NAME_ALL_CHR) &&
				    (dmdp->ddm_spec_type != S_IFCHR))
					continue;
				if ((minor_name == DEVID_MINOR_NAME_ALL_BLK) &&
				    (dmdp->ddm_spec_type != S_IFBLK))
					continue;
			}

			(void) ddi_pathname_minor(dmdp, path);
			len = strlen(path) + 1;
			*(path + len) = '\0';	/* set double termination */
			lens += len;

			/* copyout the path with double terminations */
			if (upaths) {
				if (lens > ulens) {
					ret = EAGAIN;
					goto out;
				}
				if (copyout(path, upaths, len + 1)) {
					ret = EFAULT;
					goto out;
				}
				upaths += len;
			}
		}
		ndi_devi_exit(dip, circ);
		ddi_release_devi(dip);
		dip = NULL;
	}
	lens++;		/* add one for double termination */

	/* copy out the amount of space needed to hold the paths */
	if (ulensp && copyout(&lens, ulensp, sizeof (lens))) {
		ret = EFAULT;
		goto out;
	}
	ret = 0;

out:	if (dip) {
		ndi_devi_exit(dip, circ);
		ddi_release_devi(dip);
	}
	if (path)
		kmem_free(path, MAXPATHLEN);
	if (devlist)
		ddi_lyr_free_devlist(devlist, ndevs);
	if (minor_name &&
	    (minor_name != DEVID_MINOR_NAME_ALL) &&
	    (minor_name != DEVID_MINOR_NAME_ALL_CHR) &&
	    (minor_name != DEVID_MINOR_NAME_ALL_BLK))
		kmem_free(minor_name, MAXPATHLEN);
	if (devid)
		kmem_free(devid, devid_len);
	return (ret);
}

/*
 * Return the size of the minor name.
 */
static int
modctl_sizeof_minorname(dev_t dev, int spectype, uint_t *len)
{
	uint_t	sz;
	char	*name;

	/* get the minor name */
	if (ddi_lyr_get_minor_name(dev, spectype, &name) == DDI_FAILURE)
		return (EINVAL);

	sz = strlen(name) + 1;
	kmem_free(name, sz);

	/* copy out the size of the minor name */
	if (copyout(&sz, len, sizeof (sz)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Return the minor name.
 */
static int
modctl_get_minorname(dev_t dev, int spectype, uint_t len, char *uname)
{
	uint_t	sz;
	char	*name;
	int	err = 0;

	/* get the minor name */
	if (ddi_lyr_get_minor_name(dev, spectype, &name) == DDI_FAILURE)
		return (EINVAL);

	sz = strlen(name) + 1;

	/* Error if the minor name is larger than the space allocated */
	if (sz > len) {
		kmem_free(name, sz);
		return (ENOSPC);
	}

	/* copy out the minor name */
	if (copyout(name, uname, sz) != 0)
		err = EFAULT;
	kmem_free(name, sz);
	return (err);
}

/*
 * Return the size of the (dev_t,spectype) devfspath name.
 */
static int
modctl_devfspath_len(dev_t dev, int spectype, uint_t *len)
{
	uint_t	sz;
	char	*name;

	/* get the path name */
	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (ddi_dev_pathname(dev, spectype, name) == DDI_FAILURE) {
		kmem_free(name, MAXPATHLEN);
		return (EINVAL);
	}

	sz = strlen(name) + 1;
	kmem_free(name, MAXPATHLEN);

	/* copy out the size of the path name */
	if (copyout(&sz, len, sizeof (sz)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Return the (dev_t,spectype) devfspath name.
 */
static int
modctl_devfspath(dev_t dev, int spectype, uint_t len, char *uname)
{
	uint_t	sz;
	char	*name;
	int	err = 0;

	/* get the path name */
	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (ddi_dev_pathname(dev, spectype, name) == DDI_FAILURE) {
		kmem_free(name, MAXPATHLEN);
		return (EINVAL);
	}

	sz = strlen(name) + 1;

	/* Error if the path name is larger than the space allocated */
	if (sz > len) {
		kmem_free(name, MAXPATHLEN);
		return (ENOSPC);
	}

	/* copy out the path name */
	if (copyout(name, uname, sz) != 0)
		err = EFAULT;
	kmem_free(name, MAXPATHLEN);
	return (err);
}

/*
 * Return the size of the (major,instance) devfspath name.
 */
static int
modctl_devfspath_mi_len(major_t major, int instance, uint_t *len)
{
	uint_t	sz;
	char	*name;

	/* get the path name */
	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (e_ddi_majorinstance_to_path(major, instance, name) != DDI_SUCCESS) {
		kmem_free(name, MAXPATHLEN);
		return (EINVAL);
	}

	sz = strlen(name) + 1;
	kmem_free(name, MAXPATHLEN);

	/* copy out the size of the path name */
	if (copyout(&sz, len, sizeof (sz)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Return the (major_instance) devfspath name.
 * NOTE: e_ddi_majorinstance_to_path does not require the device to attach to
 * return a path - it uses the instance tree.
 */
static int
modctl_devfspath_mi(major_t major, int instance, uint_t len, char *uname)
{
	uint_t	sz;
	char	*name;
	int	err = 0;

	/* get the path name */
	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (e_ddi_majorinstance_to_path(major, instance, name) != DDI_SUCCESS) {
		kmem_free(name, MAXPATHLEN);
		return (EINVAL);
	}

	sz = strlen(name) + 1;

	/* Error if the path name is larger than the space allocated */
	if (sz > len) {
		kmem_free(name, MAXPATHLEN);
		return (ENOSPC);
	}

	/* copy out the path name */
	if (copyout(name, uname, sz) != 0)
		err = EFAULT;
	kmem_free(name, MAXPATHLEN);
	return (err);
}

static int
modctl_get_fbname(char *path)
{
	extern dev_t fbdev;
	char *pathname = NULL;
	int rval = 0;

	/* make sure fbdev is set before we plunge in */
	if (fbdev == NODEV)
		return (ENODEV);

	pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if ((rval = ddi_dev_pathname(fbdev, S_IFCHR,
	    pathname)) == DDI_SUCCESS) {
		if (copyout(pathname, path, strlen(pathname)+1) != 0) {
			rval = EFAULT;
		}
	}
	kmem_free(pathname, MAXPATHLEN);
	return (rval);
}

/*
 * modctl_reread_dacf()
 *	Reread the dacf rules database from the named binding file.
 *	If NULL is specified, pass along the NULL, it means 'use the default'.
 */
static int
modctl_reread_dacf(char *path)
{
	int rval = 0;
	char *filename, *filenamep;

	filename = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	if (path == NULL) {
		filenamep = NULL;
	} else {
		if (copyinstr(path, filename, MAXPATHLEN, 0) != 0) {
			rval = EFAULT;
			goto out;
		}
		filenamep = filename;
		filenamep[MAXPATHLEN - 1] = '\0';
	}

	rval = read_dacf_binding_file(filenamep);
out:
	kmem_free(filename, MAXPATHLEN);
	return (rval);
}

/*ARGSUSED*/
static int
modctl_modevents(int subcmd, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uint_t flag)
{
	int error = 0;
	char *filenamep;

	switch (subcmd) {

	case MODEVENTS_FLUSH:
		/* flush all currently queued events */
		log_sysevent_flushq(subcmd, flag);
		break;

	case MODEVENTS_SET_DOOR_UPCALL_FILENAME:
		/*
		 * bind door_upcall to filename
		 * this should only be done once per invocation
		 * of the event daemon.
		 */

		filenamep = kmem_zalloc(MOD_MAXPATH, KM_SLEEP);

		if (copyinstr((char *)a2, filenamep, MOD_MAXPATH, 0)) {
			error = EFAULT;
		} else {
			error = log_sysevent_filename(filenamep);
		}
		kmem_free(filenamep, MOD_MAXPATH);
		break;

	case MODEVENTS_GETDATA:
		error = log_sysevent_copyout_data((sysevent_id_t *)a2,
		    (size_t)a3, (caddr_t)a4);
		break;

	case MODEVENTS_FREEDATA:
		error = log_sysevent_free_data((sysevent_id_t *)a2);
		break;
	case MODEVENTS_POST_EVENT:
		error = log_usr_sysevent((sysevent_t *)a2, (uint32_t)a3,
		    (sysevent_id_t *)a4);
		break;
	case MODEVENTS_REGISTER_EVENT:
		error = log_sysevent_register((char *)a2, (char *)a3,
		    (se_pubsub_t *)a4);
		break;
	default:
		error = EINVAL;
	}

	return (error);
}

static void
free_mperm(mperm_t *mp)
{
	int len;

	if (mp->mp_minorname) {
		len = strlen(mp->mp_minorname) + 1;
		kmem_free(mp->mp_minorname, len);
	}
	kmem_free(mp, sizeof (mperm_t));
}

#define	MP_NO_DRV_ERR	\
	"/etc/minor_perm: no driver for %s\n"

#define	MP_EMPTY_MINOR	\
	"/etc/minor_perm: empty minor name for driver %s\n"

#define	MP_NO_MINOR	\
	"/etc/minor_perm: no minor matching %s for driver %s\n"

/*
 * Remove mperm entry with matching minorname
 */
static void
rem_minorperm(major_t major, char *drvname, mperm_t *mp, int is_clone)
{
	mperm_t **mp_head;
	mperm_t *freemp = NULL;
	struct devnames *dnp = &devnamesp[major];
	mperm_t **wildmp;

	ASSERT(mp->mp_minorname && strlen(mp->mp_minorname) > 0);

	LOCK_DEV_OPS(&dnp->dn_lock);
	if (strcmp(mp->mp_minorname, "*") == 0) {
		wildmp = ((is_clone == 0) ?
		    &dnp->dn_mperm_wild : &dnp->dn_mperm_clone);
		if (*wildmp)
			freemp = *wildmp;
		*wildmp = NULL;
	} else {
		mp_head = &dnp->dn_mperm;
		while (*mp_head) {
			if (strcmp((*mp_head)->mp_minorname,
			    mp->mp_minorname) != 0) {
				mp_head = &(*mp_head)->mp_next;
				continue;
			}
			/* remove the entry */
			freemp = *mp_head;
			*mp_head = freemp->mp_next;
			break;
		}
	}
	if (freemp) {
		if (moddebug & MODDEBUG_MINORPERM) {
			cmn_err(CE_CONT, "< %s %s 0%o %d %d\n",
			    drvname, freemp->mp_minorname,
			    freemp->mp_mode & 0777,
			    freemp->mp_uid, freemp->mp_gid);
		}
		free_mperm(freemp);
	} else {
		if (moddebug & MODDEBUG_MINORPERM) {
			cmn_err(CE_CONT, MP_NO_MINOR,
			    drvname, mp->mp_minorname);
		}
	}

	UNLOCK_DEV_OPS(&dnp->dn_lock);
}

/*
 * Add minor perm entry
 */
static void
add_minorperm(major_t major, char *drvname, mperm_t *mp, int is_clone)
{
	mperm_t **mp_head;
	mperm_t *freemp = NULL;
	struct devnames *dnp = &devnamesp[major];
	mperm_t **wildmp;

	ASSERT(mp->mp_minorname && strlen(mp->mp_minorname) > 0);

	/*
	 * Note that update_drv replace semantics require
	 * replacing matching entries with the new permissions.
	 */
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (strcmp(mp->mp_minorname, "*") == 0) {
		wildmp = ((is_clone == 0) ?
		    &dnp->dn_mperm_wild : &dnp->dn_mperm_clone);
		if (*wildmp)
			freemp = *wildmp;
		*wildmp = mp;
	} else {
		mperm_t *p, *v = NULL;
		for (p = dnp->dn_mperm; p; v = p, p = p->mp_next) {
			if (strcmp(p->mp_minorname, mp->mp_minorname) == 0) {
				if (v == NULL)
					dnp->dn_mperm = mp;
				else
					v->mp_next = mp;
				mp->mp_next = p->mp_next;
				freemp = p;
				goto replaced;
			}
		}
		if (p == NULL) {
			mp_head = &dnp->dn_mperm;
			if (*mp_head == NULL) {
				*mp_head = mp;
			} else {
				mp->mp_next = *mp_head;
				*mp_head = mp;
			}
		}
	}
replaced:
	if (freemp) {
		if (moddebug & MODDEBUG_MINORPERM) {
			cmn_err(CE_CONT, "< %s %s 0%o %d %d\n",
			    drvname, freemp->mp_minorname,
			    freemp->mp_mode & 0777,
			    freemp->mp_uid, freemp->mp_gid);
		}
		free_mperm(freemp);
	}
	if (moddebug & MODDEBUG_MINORPERM) {
		cmn_err(CE_CONT, "> %s %s 0%o %d %d\n",
		    drvname, mp->mp_minorname, mp->mp_mode & 0777,
		    mp->mp_uid, mp->mp_gid);
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);
}


static int
process_minorperm(int cmd, nvlist_t *nvl)
{
	char *minor;
	major_t major;
	mperm_t *mp;
	nvpair_t *nvp;
	char *name;
	int is_clone;
	major_t minmaj;

	ASSERT(cmd == MODLOADMINORPERM ||
	    cmd == MODADDMINORPERM || cmd == MODREMMINORPERM);

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);

		is_clone = 0;
		(void) nvpair_value_string(nvp, &minor);
		major = ddi_name_to_major(name);
		if (major != DDI_MAJOR_T_NONE) {
			mp = kmem_zalloc(sizeof (*mp), KM_SLEEP);
			if (minor == NULL || strlen(minor) == 0) {
				if (moddebug & MODDEBUG_MINORPERM) {
					cmn_err(CE_CONT, MP_EMPTY_MINOR, name);
				}
				minor = "*";
			}

			/*
			 * The minor name of a node using the clone
			 * driver must be the driver name.  To avoid
			 * multiple searches, we map entries in the form
			 * clone:<driver> to <driver>:*.  This also allows us
			 * to filter out some of the litter in /etc/minor_perm.
			 * Minor perm alias entries where the name is not
			 * the driver kept on the clone list itself.
			 * This all seems very fragile as a driver could
			 * be introduced with an existing alias name.
			 */
			if (strcmp(name, "clone") == 0) {
				minmaj = ddi_name_to_major(minor);
				if (minmaj != DDI_MAJOR_T_NONE) {
					if (moddebug & MODDEBUG_MINORPERM) {
						cmn_err(CE_CONT,
						    "mapping %s:%s to %s:*\n",
						    name, minor, minor);
					}
					major = minmaj;
					name = minor;
					minor = "*";
					is_clone = 1;
				}
			}

			if (mp) {
				mp->mp_minorname =
				    i_ddi_strdup(minor, KM_SLEEP);
			}
		} else {
			mp = NULL;
			if (moddebug & MODDEBUG_MINORPERM) {
				cmn_err(CE_CONT, MP_NO_DRV_ERR, name);
			}
		}

		/* mode */
		nvp = nvlist_next_nvpair(nvl, nvp);
		ASSERT(strcmp(nvpair_name(nvp), "mode") == 0);
		if (mp)
			(void) nvpair_value_int32(nvp, (int *)&mp->mp_mode);
		/* uid */
		nvp = nvlist_next_nvpair(nvl, nvp);
		ASSERT(strcmp(nvpair_name(nvp), "uid") == 0);
		if (mp)
			(void) nvpair_value_uint32(nvp, &mp->mp_uid);
		/* gid */
		nvp = nvlist_next_nvpair(nvl, nvp);
		ASSERT(strcmp(nvpair_name(nvp), "gid") == 0);
		if (mp) {
			(void) nvpair_value_uint32(nvp, &mp->mp_gid);

			if (cmd == MODREMMINORPERM) {
				rem_minorperm(major, name, mp, is_clone);
				free_mperm(mp);
			} else {
				add_minorperm(major, name, mp, is_clone);
			}
		}
	}

	if (cmd == MODLOADMINORPERM)
		minorperm_loaded = 1;

	/*
	 * Reset permissions of cached dv_nodes
	 */
	(void) devfs_reset_perm(DV_RESET_PERM);

	return (0);
}

static int
modctl_minorperm(int cmd, char *usrbuf, size_t buflen)
{
	int error;
	nvlist_t *nvl;
	char *buf = kmem_alloc(buflen, KM_SLEEP);

	if ((error = ddi_copyin(usrbuf, buf, buflen, 0)) != 0) {
		kmem_free(buf, buflen);
		return (error);
	}

	error = nvlist_unpack(buf, buflen, &nvl, KM_SLEEP);
	kmem_free(buf, buflen);
	if (error)
		return (error);

	error = process_minorperm(cmd, nvl);
	nvlist_free(nvl);
	return (error);
}

struct walk_args {
	char		*wa_drvname;
	list_t		wa_pathlist;
};

struct path_elem {
	char		*pe_dir;
	char		*pe_nodename;
	list_node_t	pe_node;
	int		pe_dirlen;
};

/*ARGSUSED*/
static int
modctl_inst_walker(const char *path, in_node_t *np, in_drv_t *dp, void *arg)
{
	struct walk_args *wargs = (struct walk_args *)arg;
	struct path_elem *pe;
	char *nodename;

	/*
	 * Search may be restricted to a single driver in the case of rem_drv
	 */
	if (wargs->wa_drvname &&
	    strcmp(dp->ind_driver_name, wargs->wa_drvname) != 0)
		return (INST_WALK_CONTINUE);

	pe = kmem_zalloc(sizeof (*pe), KM_SLEEP);
	pe->pe_dir = i_ddi_strdup((char *)path, KM_SLEEP);
	pe->pe_dirlen = strlen(pe->pe_dir) + 1;
	ASSERT(strrchr(pe->pe_dir, '/') != NULL);
	nodename = strrchr(pe->pe_dir, '/');
	*nodename++ = 0;
	pe->pe_nodename = nodename;
	list_insert_tail(&wargs->wa_pathlist, pe);

	return (INST_WALK_CONTINUE);
}

/*
 * /devices attribute nodes clean-up optionally performed
 * when removing a driver (rem_drv -C).
 *
 * Removing attribute nodes allows a machine to be reprovisioned
 * without the side-effect of inadvertently picking up stale
 * device node ownership or permissions.
 *
 * Preserving attributes (not performing cleanup) allows devices
 * attribute changes to be preserved across upgrades, as
 * upgrade rather heavy-handedly does a rem_drv/add_drv cycle.
 */
static int
modctl_remdrv_cleanup(const char *u_drvname)
{
	struct walk_args *wargs;
	struct path_elem *pe;
	char *drvname;
	int err, rval = 0;

	drvname = kmem_alloc(MAXMODCONFNAME, KM_SLEEP);
	if ((err = copyinstr(u_drvname, drvname, MAXMODCONFNAME, 0))) {
		kmem_free(drvname, MAXMODCONFNAME);
		return (err);
	}

	/*
	 * First go through the instance database.  For each
	 * instance of a device bound to the driver being
	 * removed, remove any underlying devfs attribute nodes.
	 *
	 * This is a two-step process.	First we go through
	 * the instance data itself, constructing a list of
	 * the nodes discovered.  The second step is then
	 * to find and remove any devfs attribute nodes
	 * for the instances discovered in the first step.
	 * The two-step process avoids any difficulties
	 * which could arise by holding the instance data
	 * lock with simultaneous devfs operations.
	 */
	wargs = kmem_zalloc(sizeof (*wargs), KM_SLEEP);

	wargs->wa_drvname = drvname;
	list_create(&wargs->wa_pathlist,
	    sizeof (struct path_elem), offsetof(struct path_elem, pe_node));

	(void) e_ddi_walk_instances(modctl_inst_walker, (void *)wargs);

	for (pe = list_head(&wargs->wa_pathlist); pe != NULL;
	    pe = list_next(&wargs->wa_pathlist, pe)) {
		err = devfs_remdrv_cleanup((const char *)pe->pe_dir,
		    (const char *)pe->pe_nodename);
		if (rval == 0)
			rval = err;
	}

	while ((pe = list_head(&wargs->wa_pathlist)) != NULL) {
		list_remove(&wargs->wa_pathlist, pe);
		kmem_free(pe->pe_dir, pe->pe_dirlen);
		kmem_free(pe, sizeof (*pe));
	}
	kmem_free(wargs, sizeof (*wargs));

	/*
	 * Pseudo nodes aren't recorded in the instance database
	 * so any such nodes need to be handled separately.
	 */
	err = devfs_remdrv_cleanup("pseudo", (const char *)drvname);
	if (rval == 0)
		rval = err;

	kmem_free(drvname, MAXMODCONFNAME);
	return (rval);
}

/*
 * Perform a cleanup of non-existent /devices attribute nodes,
 * similar to rem_drv -C, but for all drivers/devices.
 * This is also optional, performed as part of devfsadm -C.
 */
void
dev_devices_cleanup()
{
	struct walk_args *wargs;
	struct path_elem *pe;
	dev_info_t *devi;
	char *path;
	int err;

	/*
	 * It's expected that all drivers have been loaded and
	 * module unloading disabled while performing cleanup.
	 */
	ASSERT(modunload_disable_count > 0);

	wargs = kmem_zalloc(sizeof (*wargs), KM_SLEEP);
	wargs->wa_drvname = NULL;
	list_create(&wargs->wa_pathlist,
	    sizeof (struct path_elem), offsetof(struct path_elem, pe_node));

	(void) e_ddi_walk_instances(modctl_inst_walker, (void *)wargs);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	for (pe = list_head(&wargs->wa_pathlist); pe != NULL;
	    pe = list_next(&wargs->wa_pathlist, pe)) {
		(void) snprintf(path, MAXPATHLEN, "%s/%s",
		    pe->pe_dir, pe->pe_nodename);
		devi = e_ddi_hold_devi_by_path(path, 0);
		if (devi != NULL) {
			ddi_release_devi(devi);
		} else {
			err = devfs_remdrv_cleanup((const char *)pe->pe_dir,
			    (const char *)pe->pe_nodename);
			if (err) {
				cmn_err(CE_CONT,
				    "devfs: %s: clean-up error %d\n",
				    path, err);
			}
		}
	}

	while ((pe = list_head(&wargs->wa_pathlist)) != NULL) {
		list_remove(&wargs->wa_pathlist, pe);
		kmem_free(pe->pe_dir, pe->pe_dirlen);
		kmem_free(pe, sizeof (*pe));
	}
	kmem_free(wargs, sizeof (*wargs));
	kmem_free(path, MAXPATHLEN);
}

static int
modctl_allocpriv(const char *name)
{
	char *pstr = kmem_alloc(PRIVNAME_MAX, KM_SLEEP);
	int error;

	if ((error = copyinstr(name, pstr, PRIVNAME_MAX, 0))) {
		kmem_free(pstr, PRIVNAME_MAX);
		return (error);
	}
	error = priv_getbyname(pstr, PRIV_ALLOC);
	if (error < 0)
		error = -error;
	else
		error = 0;
	kmem_free(pstr, PRIVNAME_MAX);
	return (error);
}

static int
modctl_devexists(const char *upath, int pathlen)
{
	char	*path;
	int	ret;

	/*
	 * copy in the path, including the terminating null
	 */
	pathlen++;
	if (pathlen <= 1 || pathlen > MAXPATHLEN)
		return (EINVAL);
	path = kmem_zalloc(pathlen + 1, KM_SLEEP);
	if ((ret = copyinstr(upath, path, pathlen, NULL)) == 0) {
		ret = sdev_modctl_devexists(path);
	}

	kmem_free(path, pathlen + 1);
	return (ret);
}

static int
modctl_devreaddir(const char *udir, int udirlen,
    char *upaths, int64_t *ulensp)
{
	char	*paths = NULL;
	char	**dirlist = NULL;
	char	*dir;
	int64_t	ulens;
	int64_t	lens;
	int	i, n;
	int	ret = 0;
	char	*p;
	int	npaths;
	int	npaths_alloc;

	/*
	 * If upaths is NULL then we are only computing the amount of space
	 * needed to return the paths, with the value returned in *ulensp. If we
	 * are copying out paths then we get the amount of space allocated by
	 * the caller. If the actual space needed for paths is larger, or
	 * things are changing out from under us, then we return EAGAIN.
	 */
	if (upaths) {
		if (ulensp == NULL)
			return (EINVAL);
		if (copyin(ulensp, &ulens, sizeof (ulens)) != 0)
			return (EFAULT);
	}

	/*
	 * copyin the /dev path including terminating null
	 */
	udirlen++;
	if (udirlen <= 1 || udirlen > MAXPATHLEN)
		return (EINVAL);
	dir = kmem_zalloc(udirlen + 1, KM_SLEEP);
	if ((ret = copyinstr(udir, dir, udirlen, NULL)) != 0)
		goto err;

	if ((ret = sdev_modctl_readdir(dir, &dirlist,
	    &npaths, &npaths_alloc, 0)) != 0) {
		ASSERT(dirlist == NULL);
		goto err;
	}

	lens = 0;
	for (i = 0; i < npaths; i++) {
		lens += strlen(dirlist[i]) + 1;
	}
	lens++;		/* add one for double termination */

	if (upaths) {
		if (lens > ulens) {
			ret = EAGAIN;
			goto out;
		}

		paths = kmem_alloc(lens, KM_SLEEP);

		p = paths;
		for (i = 0; i < npaths; i++) {
			n = strlen(dirlist[i]) + 1;
			bcopy(dirlist[i], p, n);
			p += n;
		}
		*p = 0;

		if (copyout(paths, upaths, lens)) {
			ret = EFAULT;
			goto err;
		}
	}

out:
	/* copy out the amount of space needed to hold the paths */
	if (copyout(&lens, ulensp, sizeof (lens)))
		ret = EFAULT;

err:
	if (dirlist)
		sdev_modctl_readdir_free(dirlist, npaths, npaths_alloc);
	if (paths)
		kmem_free(paths, lens);
	kmem_free(dir, udirlen + 1);
	return (ret);
}

static int
modctl_devemptydir(const char *udir, int udirlen, int *uempty)
{
	char	*dir;
	int	ret;
	char	**dirlist = NULL;
	int	npaths;
	int	npaths_alloc;
	int	empty;

	/*
	 * copyin the /dev path including terminating null
	 */
	udirlen++;
	if (udirlen <= 1 || udirlen > MAXPATHLEN)
		return (EINVAL);
	dir = kmem_zalloc(udirlen + 1, KM_SLEEP);
	if ((ret = copyinstr(udir, dir, udirlen, NULL)) != 0)
		goto err;

	if ((ret = sdev_modctl_readdir(dir, &dirlist,
	    &npaths, &npaths_alloc, 1)) != 0) {
		goto err;
	}

	empty = npaths ? 0 : 1;
	if (copyout(&empty, uempty, sizeof (empty)))
		ret = EFAULT;

err:
	if (dirlist)
		sdev_modctl_readdir_free(dirlist, npaths, npaths_alloc);
	kmem_free(dir, udirlen + 1);
	return (ret);
}

static int
modctl_hp(int subcmd, const char *path, char *cn_name, uintptr_t arg,
    uintptr_t rval)
{
	int error = 0;
	size_t pathsz, namesz;
	char *devpath, *cn_name_str;

	if (path == NULL)
		return (EINVAL);

	devpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	error = copyinstr(path, devpath, MAXPATHLEN, &pathsz);
	if (error != 0) {
		kmem_free(devpath, MAXPATHLEN);
		return (EFAULT);
	}

	cn_name_str = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	error = copyinstr(cn_name, cn_name_str, MAXNAMELEN, &namesz);
	if (error != 0) {
		kmem_free(devpath, MAXPATHLEN);
		kmem_free(cn_name_str, MAXNAMELEN);

		return (EFAULT);
	}

	switch (subcmd) {
	case MODHPOPS_CHANGE_STATE:
		error = ddihp_modctl(DDI_HPOP_CN_CHANGE_STATE, devpath,
		    cn_name_str, arg, NULL);
		break;
	case MODHPOPS_CREATE_PORT:
		/* Create an empty PORT */
		error = ddihp_modctl(DDI_HPOP_CN_CREATE_PORT, devpath,
		    cn_name_str, NULL, NULL);
		break;
	case MODHPOPS_REMOVE_PORT:
		/* Remove an empty PORT */
		error = ddihp_modctl(DDI_HPOP_CN_REMOVE_PORT, devpath,
		    cn_name_str, NULL, NULL);
		break;
	case MODHPOPS_BUS_GET:
		error = ddihp_modctl(DDI_HPOP_CN_GET_PROPERTY, devpath,
		    cn_name_str, arg, rval);
		break;
	case MODHPOPS_BUS_SET:
		error = ddihp_modctl(DDI_HPOP_CN_SET_PROPERTY, devpath,
		    cn_name_str, arg, rval);
		break;
	default:
		error = ENOTSUP;
		break;
	}

	kmem_free(devpath, MAXPATHLEN);
	kmem_free(cn_name_str, MAXNAMELEN);

	return (error);
}

int
modctl_moddevname(int subcmd, uintptr_t a1, uintptr_t a2)
{
	int error = 0;

	switch (subcmd) {
	case MODDEVNAME_LOOKUPDOOR:
		error = devname_filename_register((char *)a1);
		break;
	case MODDEVNAME_PROFILE:
		error = devname_profile_update((char *)a1, (size_t)a2);
		break;
	case MODDEVNAME_RECONFIG:
		i_ddi_set_reconfig();
		break;
	case MODDEVNAME_SYSAVAIL:
		i_ddi_set_sysavail();
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*ARGSUSED5*/
int
modctl(int cmd, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5)
{
	int	error = EINVAL;
	dev_t	dev;

	if (secpolicy_modctl(CRED(), cmd) != 0)
		return (set_errno(EPERM));

	switch (cmd) {
	case MODLOAD:		/* load a module */
		error = modctl_modload((int)a1, (char *)a2, (int *)a3);
		break;

	case MODUNLOAD:		/* unload a module */
		error = modctl_modunload((modid_t)a1);
		break;

	case MODINFO:		/* get module status */
		error = modctl_modinfo((modid_t)a1, (struct modinfo *)a2);
		break;

	case MODRESERVED:	/* get last major number in range */
		error = modctl_modreserve((modid_t)a1, (int *)a2);
		break;

	case MODSETMINIROOT:	/* we are running in miniroot */
		isminiroot = 1;
		error = 0;
		break;

	case MODADDMAJBIND:	/* add major / driver alias bindings */
		error = modctl_add_driver_aliases((int *)a2);
		break;

	case MODGETPATHLEN:	/* get modpath length */
		error = modctl_getmodpathlen((int *)a2);
		break;

	case MODGETPATH:	/* get modpath */
		error = modctl_getmodpath((char *)a2);
		break;

	case MODREADSYSBIND:	/* read system call binding file */
		error = modctl_read_sysbinding_file();
		break;

	case MODGETMAJBIND:	/* get major number for named device */
		error = modctl_getmaj((char *)a1, (uint_t)a2, (int *)a3);
		break;

	case MODGETNAME:	/* get name of device given major number */
		error = modctl_getname((char *)a1, (uint_t)a2, (int *)a3);
		break;

	case MODDEVT2INSTANCE:
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			dev = (dev_t)a1;
		}
#ifdef _SYSCALL32_IMPL
		else {
			dev = expldev(a1);
		}
#endif
		error = modctl_devt2instance(dev, (int *)a2);
		break;

	case MODSIZEOF_DEVID:	/* sizeof device id of device given dev_t */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			dev = (dev_t)a1;
		}
#ifdef _SYSCALL32_IMPL
		else {
			dev = expldev(a1);
		}
#endif
		error = modctl_sizeof_devid(dev, (uint_t *)a2);
		break;

	case MODGETDEVID:	/* get device id of device given dev_t */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			dev = (dev_t)a1;
		}
#ifdef _SYSCALL32_IMPL
		else {
			dev = expldev(a1);
		}
#endif
		error = modctl_get_devid(dev, (uint_t)a2, (ddi_devid_t)a3);
		break;

	case MODSIZEOF_MINORNAME:	/* sizeof minor nm (dev_t,spectype) */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			error = modctl_sizeof_minorname((dev_t)a1, (int)a2,
			    (uint_t *)a3);
		}
#ifdef _SYSCALL32_IMPL
		else {
			error = modctl_sizeof_minorname(expldev(a1), (int)a2,
			    (uint_t *)a3);
		}

#endif
		break;

	case MODGETMINORNAME:		/* get minor name of (dev_t,spectype) */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			error = modctl_get_minorname((dev_t)a1, (int)a2,
			    (uint_t)a3, (char *)a4);
		}
#ifdef _SYSCALL32_IMPL
		else {
			error = modctl_get_minorname(expldev(a1), (int)a2,
			    (uint_t)a3, (char *)a4);
		}
#endif
		break;

	case MODGETDEVFSPATH_LEN:	/* sizeof path nm of (dev_t,spectype) */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			error = modctl_devfspath_len((dev_t)a1, (int)a2,
			    (uint_t *)a3);
		}
#ifdef _SYSCALL32_IMPL
		else {
			error = modctl_devfspath_len(expldev(a1), (int)a2,
			    (uint_t *)a3);
		}

#endif
		break;

	case MODGETDEVFSPATH:		/* get path name of (dev_t,spec) type */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			error = modctl_devfspath((dev_t)a1, (int)a2,
			    (uint_t)a3, (char *)a4);
		}
#ifdef _SYSCALL32_IMPL
		else {
			error = modctl_devfspath(expldev(a1), (int)a2,
			    (uint_t)a3, (char *)a4);
		}
#endif
		break;

	case MODGETDEVFSPATH_MI_LEN:	/* sizeof path nm of (major,instance) */
		error = modctl_devfspath_mi_len((major_t)a1, (int)a2,
		    (uint_t *)a3);
		break;

	case MODGETDEVFSPATH_MI:	/* get path name of (major,instance) */
		error = modctl_devfspath_mi((major_t)a1, (int)a2,
		    (uint_t)a3, (char *)a4);
		break;


	case MODEVENTS:
		error = modctl_modevents((int)a1, a2, a3, a4, (uint_t)a5);
		break;

	case MODGETFBNAME:	/* get the framebuffer name */
		error = modctl_get_fbname((char *)a1);
		break;

	case MODREREADDACF:	/* reread dacf rule database from given file */
		error = modctl_reread_dacf((char *)a1);
		break;

	case MODLOADDRVCONF:	/* load driver.conf file for major */
		error = modctl_load_drvconf((major_t)a1, (int)a2);
		break;

	case MODUNLOADDRVCONF:	/* unload driver.conf file for major */
		error = modctl_unload_drvconf((major_t)a1);
		break;

	case MODREMMAJBIND:	/* remove a major binding */
		error = modctl_rem_major((major_t)a1);
		break;

	case MODREMDRVALIAS:	/* remove a major/alias binding */
		error = modctl_remove_driver_aliases((int *)a2);
		break;

	case MODDEVID2PATHS:	/* get paths given devid */
		error = modctl_devid2paths((ddi_devid_t)a1, (char *)a2,
		    (uint_t)a3, (size_t *)a4, (char *)a5);
		break;

	case MODSETDEVPOLICY:	/* establish device policy */
		error = devpolicy_load((int)a1, (size_t)a2, (devplcysys_t *)a3);
		break;

	case MODGETDEVPOLICY:	/* get device policy */
		error = devpolicy_get((int *)a1, (size_t)a2,
		    (devplcysys_t *)a3);
		break;

	case MODALLOCPRIV:
		error = modctl_allocpriv((const char *)a1);
		break;

	case MODGETDEVPOLICYBYNAME:
		error = devpolicy_getbyname((size_t)a1,
		    (devplcysys_t *)a2, (char *)a3);
		break;

	case MODLOADMINORPERM:
	case MODADDMINORPERM:
	case MODREMMINORPERM:
		error = modctl_minorperm(cmd, (char *)a1, (size_t)a2);
		break;

	case MODREMDRVCLEANUP:
		error = modctl_remdrv_cleanup((const char *)a1);
		break;

	case MODDEVEXISTS:	/* non-reconfiguring /dev lookup */
		error = modctl_devexists((const char *)a1, (size_t)a2);
		break;

	case MODDEVREADDIR:	/* non-reconfiguring /dev readdir */
		error = modctl_devreaddir((const char *)a1, (size_t)a2,
		    (char *)a3, (int64_t *)a4);
		break;

	case MODDEVEMPTYDIR:	/* non-reconfiguring /dev emptydir */
		error = modctl_devemptydir((const char *)a1, (size_t)a2,
		    (int *)a3);
		break;

	case MODDEVNAME:
		error = modctl_moddevname((int)a1, a2, a3);
		break;

	case MODRETIRE:	/* retire device named by physpath a1 */
		error = modctl_retire((char *)a1, (char *)a2, (size_t)a3);
		break;

	case MODISRETIRED:  /* check if a device is retired. */
		error = modctl_is_retired((char *)a1, (int *)a2);
		break;

	case MODUNRETIRE:	/* unretire device named by physpath a1 */
		error = modctl_unretire((char *)a1);
		break;

	case MODHPOPS:	/* hotplug operations */
		/* device named by physpath a2 and Connection name a3 */
		error = modctl_hp((int)a1, (char *)a2, (char *)a3, a4, a5);
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error ? set_errno(error) : 0);
}

/*
 * Calls to kobj_load_module()() are handled off to this routine in a
 * separate thread.
 */
static void
modload_thread(struct loadmt *ltp)
{
	/* load the module and signal the creator of this thread */
	kmutex_t	cpr_lk;
	callb_cpr_t	cpr_i;

	mutex_init(&cpr_lk, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_i, &cpr_lk, callb_generic_cpr, "modload");
	/* borrow the devi lock from thread which invoked us */
	pm_borrow_lock(ltp->owner);
	ltp->retval = kobj_load_module(ltp->mp, ltp->usepath);
	pm_return_lock();
	sema_v(&ltp->sema);
	mutex_enter(&cpr_lk);
	CALLB_CPR_EXIT(&cpr_i);
	mutex_destroy(&cpr_lk);
	thread_exit();
}

/*
 * load a module, adding a reference if caller specifies rmodp.  If rmodp
 * is specified then an errno is returned, otherwise a module index is
 * returned (-1 on error).
 */
static int
modrload(const char *subdir, const char *filename, struct modctl **rmodp)
{
	struct modctl *modp;
	size_t size;
	char *fullname;
	int retval = EINVAL;
	int id = -1;

	if (rmodp)
		*rmodp = NULL;			/* avoid garbage */

	if (subdir != NULL) {
		/*
		 * refuse / in filename to prevent "../" escapes.
		 */
		if (strchr(filename, '/') != NULL)
			return (rmodp ? retval : id);

		/*
		 * allocate enough space for <subdir>/<filename><NULL>
		 */
		size = strlen(subdir) + strlen(filename) + 2;
		fullname = kmem_zalloc(size, KM_SLEEP);
		(void) sprintf(fullname, "%s/%s", subdir, filename);
	} else {
		fullname = (char *)filename;
	}

	modp = mod_hold_installed_mod(fullname, 1, 0, &retval);
	if (modp != NULL) {
		id = modp->mod_id;
		if (rmodp) {
			/* add mod_ref and return *rmodp */
			mutex_enter(&mod_lock);
			modp->mod_ref++;
			mutex_exit(&mod_lock);
			*rmodp = modp;
		}
		mod_release_mod(modp);
		CPU_STATS_ADDQ(CPU, sys, modload, 1);
	}

done:	if (subdir != NULL)
		kmem_free(fullname, size);
	return (rmodp ? retval : id);
}

/*
 * This is the primary kernel interface to load a module. It loads and
 * installs the named module.  It does not hold mod_ref of the module, so
 * a module unload attempt can occur at any time - it is up to the
 * _fini/mod_remove implementation to determine if unload will succeed.
 */
int
modload(const char *subdir, const char *filename)
{
	return (modrload(subdir, filename, NULL));
}

/*
 * Load a module using a series of qualified names from most specific to least
 * specific, e.g. for subdir "foo", p1 "bar", p2 "baz", we might try:
 *			Value returned in *chosen
 * foo/bar.baz.1.2.3	3
 * foo/bar.baz.1.2	2
 * foo/bar.baz.1	1
 * foo/bar.baz		0
 *
 * Return the module ID on success; -1 if no module was loaded.  On success
 * and if 'chosen' is not NULL we also return the number of suffices that
 * were in the module we chose to load.
 */
int
modload_qualified(const char *subdir, const char *p1,
    const char *p2, const char *delim, uint_t suffv[], int suffc, int *chosen)
{
	char path[MOD_MAXPATH];
	size_t n, resid = sizeof (path);
	char *p = path;

	char **dotv;
	int i, rc, id;
	modctl_t *mp;

	if (p2 != NULL)
		n = snprintf(p, resid, "%s/%s%s%s", subdir, p1, delim, p2);
	else
		n = snprintf(p, resid, "%s/%s", subdir, p1);

	if (n >= resid)
		return (-1);

	p += n;
	resid -= n;
	dotv = kmem_alloc(sizeof (char *) * (suffc + 1), KM_SLEEP);

	for (i = 0; i < suffc; i++) {
		dotv[i] = p;
		n = snprintf(p, resid, "%s%u", delim, suffv[i]);

		if (n >= resid) {
			kmem_free(dotv, sizeof (char *) * (suffc + 1));
			return (-1);
		}

		p += n;
		resid -= n;
	}

	dotv[suffc] = p;

	for (i = suffc; i >= 0; i--) {
		dotv[i][0] = '\0';
		mp = mod_hold_installed_mod(path, 1, 1, &rc);

		if (mp != NULL) {
			kmem_free(dotv, sizeof (char *) * (suffc + 1));
			id = mp->mod_id;
			mod_release_mod(mp);
			if (chosen != NULL)
				*chosen = i;
			return (id);
		}
	}

	kmem_free(dotv, sizeof (char *) * (suffc + 1));
	return (-1);
}

/*
 * Load a module.
 */
int
modloadonly(const char *subdir, const char *filename)
{
	struct modctl *modp;
	char *fullname;
	size_t size;
	int id, retval;

	if (subdir != NULL) {
		/*
		 * allocate enough space for <subdir>/<filename><NULL>
		 */
		size = strlen(subdir) + strlen(filename) + 2;
		fullname = kmem_zalloc(size, KM_SLEEP);
		(void) sprintf(fullname, "%s/%s", subdir, filename);
	} else {
		fullname = (char *)filename;
	}

	modp = mod_hold_loaded_mod(NULL, fullname, &retval);
	if (modp) {
		id = modp->mod_id;
		mod_release_mod(modp);
	}

	if (subdir != NULL)
		kmem_free(fullname, size);

	if (retval == 0)
		return (id);
	return (-1);
}

/*
 * Try to uninstall and unload a module, removing a reference if caller
 * specifies rmodp.
 */
static int
modunrload(modid_t id, struct modctl **rmodp, int unload)
{
	struct modctl	*modp;
	int		retval;

	if (rmodp)
		*rmodp = NULL;			/* avoid garbage */

	if ((modp = mod_hold_by_id((modid_t)id)) == NULL)
		return (EINVAL);

	if (rmodp) {
		mutex_enter(&mod_lock);
		modp->mod_ref--;
		if (modp->mod_ref == 0)
			mod_uninstall_ref_zero++;
		mutex_exit(&mod_lock);
		*rmodp = modp;
	}

	if (unload) {
		retval = moduninstall(modp);
		if (retval == 0) {
			mod_unload(modp);
			CPU_STATS_ADDQ(CPU, sys, modunload, 1);
		} else if (retval == EALREADY)
			retval = 0;	/* already unloaded, not an error */
	} else
		retval = 0;

	mod_release_mod(modp);
	return (retval);
}

/*
 * Uninstall and unload a module.
 */
int
modunload(modid_t id)
{
	int		retval;

	/* synchronize with any active modunload_disable() */
	modunload_begin();
	if (ddi_root_node())
		(void) devfs_clean(ddi_root_node(), NULL, 0);
	retval = modunrload(id, NULL, 1);
	modunload_end();
	return (retval);
}

/*
 * Return status of a loaded module.
 */
static int
modinfo(modid_t id, struct modinfo *modinfop)
{
	struct modctl	*modp;
	modid_t		mid;
	int		i;

	mid = modinfop->mi_id;
	if (modinfop->mi_info & MI_INFO_ALL) {
		while ((modp = mod_hold_next_by_id(mid++)) != NULL) {
			if ((modinfop->mi_info & MI_INFO_CNT) ||
			    modp->mod_installed)
				break;
			mod_release_mod(modp);
		}
		if (modp == NULL)
			return (EINVAL);
	} else {
		modp = mod_hold_by_id(id);
		if (modp == NULL)
			return (EINVAL);
		if (!(modinfop->mi_info & MI_INFO_CNT) &&
		    (modp->mod_installed == 0)) {
			mod_release_mod(modp);
			return (EINVAL);
		}
	}

	modinfop->mi_rev = 0;
	modinfop->mi_state = 0;
	for (i = 0; i < MODMAXLINK; i++) {
		modinfop->mi_msinfo[i].msi_p0 = -1;
		modinfop->mi_msinfo[i].msi_linkinfo[0] = 0;
	}
	if (modp->mod_loaded) {
		modinfop->mi_state = MI_LOADED;
		kobj_getmodinfo(modp->mod_mp, modinfop);
	}
	if (modp->mod_installed) {
		modinfop->mi_state |= MI_INSTALLED;

		(void) mod_getinfo(modp, modinfop);
	}

	modinfop->mi_id = modp->mod_id;
	modinfop->mi_loadcnt = modp->mod_loadcnt;
	(void) strcpy(modinfop->mi_name, modp->mod_modname);

	mod_release_mod(modp);
	return (0);
}

static char mod_stub_err[] = "mod_hold_stub: Couldn't load stub module %s";
static char no_err[] = "No error function for weak stub %s";

/*
 * used by the stubs themselves to load and hold a module.
 * Returns  0 if the module is successfully held;
 *	    the stub needs to call mod_release_stub().
 *	    -1 if the stub should just call the err_fcn.
 * Note that this code is stretched out so that we avoid subroutine calls
 * and optimize for the most likely case.  That is, the case where the
 * module is loaded and installed and not held.  In that case we just inc
 * the mod_ref count and continue.
 */
int
mod_hold_stub(struct mod_stub_info *stub)
{
	struct modctl *mp;
	struct mod_modinfo *mip;

	mip = stub->mods_modinfo;

	mutex_enter(&mod_lock);

	/* we do mod_hold_by_modctl inline for speed */

mod_check_again:
	if ((mp = mip->mp) != NULL) {
		if (mp->mod_busy == 0) {
			if (mp->mod_installed) {
				/* increment the reference count */
				mp->mod_ref++;
				ASSERT(mp->mod_ref && mp->mod_installed);
				mutex_exit(&mod_lock);
				return (0);
			} else {
				mp->mod_busy = 1;
				mp->mod_inprogress_thread =
				    (curthread == NULL ?
				    (kthread_id_t)-1 : curthread);
			}
		} else {
			/*
			 * wait one time and then go see if someone
			 * else has resolved the stub (set mip->mp).
			 */
			if (mod_hold_by_modctl(mp,
			    MOD_WAIT_ONCE | MOD_LOCK_HELD))
				goto mod_check_again;

			/*
			 * what we have now may have been unloaded!, in
			 * that case, mip->mp will be NULL, we'll hit this
			 * module and load again..
			 */
			cmn_err(CE_PANIC, "mod_hold_stub should have blocked");
		}
		mutex_exit(&mod_lock);
	} else {
		/* first time we've hit this module */
		mutex_exit(&mod_lock);
		mp = mod_hold_by_name(mip->modm_module_name);
		mip->mp = mp;
	}

	/*
	 * If we are here, it means that the following conditions
	 * are satisfied.
	 *
	 * mip->mp != NULL
	 * this thread has set the mp->mod_busy = 1
	 * mp->mod_installed = 0
	 *
	 */
	ASSERT(mp != NULL);
	ASSERT(mp->mod_busy == 1);

	if (mp->mod_installed == 0) {
		/* Module not loaded, if weak stub don't load it */
		if (stub->mods_flag & MODS_WEAK) {
			if (stub->mods_errfcn == NULL) {
				mod_release_mod(mp);
				cmn_err(CE_PANIC, no_err,
				    mip->modm_module_name);
			}
		} else {
			/* Not a weak stub so load the module */

			if (mod_load(mp, 1) != 0 || modinstall(mp) != 0) {
				/*
				 * If mod_load() was successful
				 * and modinstall() failed, then
				 * unload the module.
				 */
				if (mp->mod_loaded)
					mod_unload(mp);

				mod_release_mod(mp);
				if (stub->mods_errfcn == NULL) {
					cmn_err(CE_PANIC, mod_stub_err,
					    mip->modm_module_name);
				} else {
					return (-1);
				}
			}
		}
	}

	/*
	 * At this point module is held and loaded. Release
	 * the mod_busy and mod_inprogress_thread before
	 * returning. We actually call mod_release() here so
	 * that if another stub wants to access this module,
	 * it can do so. mod_ref is incremented before mod_release()
	 * is called to prevent someone else from snatching the
	 * module from this thread.
	 */
	mutex_enter(&mod_lock);
	mp->mod_ref++;
	ASSERT(mp->mod_ref &&
	    (mp->mod_loaded || (stub->mods_flag & MODS_WEAK)));
	mod_release(mp);
	mutex_exit(&mod_lock);
	return (0);
}

void
mod_release_stub(struct mod_stub_info *stub)
{
	struct modctl *mp = stub->mods_modinfo->mp;

	/* inline mod_release_mod */
	mutex_enter(&mod_lock);
	ASSERT(mp->mod_ref &&
	    (mp->mod_loaded || (stub->mods_flag & MODS_WEAK)));
	mp->mod_ref--;
	if (mp->mod_ref == 0)
		mod_uninstall_ref_zero++;
	if (mp->mod_want) {
		mp->mod_want = 0;
		cv_broadcast(&mod_cv);
	}
	mutex_exit(&mod_lock);
}

static struct modctl *
mod_hold_loaded_mod(struct modctl *dep, char *filename, int *status)
{
	struct modctl *modp;
	int retval;

	/*
	 * Hold the module.
	 */
	modp = mod_hold_by_name_requisite(dep, filename);
	if (modp) {
		retval = mod_load(modp, 1);
		if (retval != 0) {
			mod_release_mod(modp);
			modp = NULL;
		}
		*status = retval;
	} else {
		*status = ENOSPC;
	}

	/*
	 * if dep is not NULL, clear the module dependency information.
	 * This information is set in mod_hold_by_name_common().
	 */
	if (dep != NULL && dep->mod_requisite_loading != NULL) {
		ASSERT(dep->mod_busy);
		dep->mod_requisite_loading = NULL;
	}

	return (modp);
}

/*
 * hold, load, and install the named module
 */
static struct modctl *
mod_hold_installed_mod(char *name, int usepath, int forcecheck, int *r)
{
	struct modctl *modp;
	int retval;

	/*
	 * Verify that that module in question actually exists on disk
	 * before allocation of module structure by mod_hold_by_name.
	 */
	if (modrootloaded && swaploaded || forcecheck) {
		if (!kobj_path_exists(name, usepath)) {
			*r = ENOENT;
			return (NULL);
		}
	}

	/*
	 * Hold the module.
	 */
	modp = mod_hold_by_name(name);
	if (modp) {
		retval = mod_load(modp, usepath);
		if (retval != 0) {
			mod_release_mod(modp);
			modp = NULL;
			*r = retval;
		} else {
			if ((*r = modinstall(modp)) != 0) {
				/*
				 * We loaded it, but failed to _init() it.
				 * Be kind to developers -- force it
				 * out of memory now so that the next
				 * attempt to use the module will cause
				 * a reload.  See 1093793.
				 */
				mod_unload(modp);
				mod_release_mod(modp);
				modp = NULL;
			}
		}
	} else {
		*r = ENOSPC;
	}
	return (modp);
}

static char mod_excl_msg[] =
	"module %s(%s) is EXCLUDED and will not be loaded\n";
static char mod_init_msg[] = "loadmodule:%s(%s): _init() error %d\n";

/*
 * This routine is needed for dependencies.  Users specify dependencies
 * by declaring a character array initialized to filenames of dependents.
 * So the code that handles dependents deals with filenames (and not
 * module names) because that's all it has.  We load by filename and once
 * we've loaded a file we can get the module name.
 * Unfortunately there isn't a single unified filename/modulename namespace.
 * C'est la vie.
 *
 * We allow the name being looked up to be prepended by an optional
 * subdirectory e.g. we can lookup (NULL, "fs/ufs") or ("fs", "ufs")
 */
struct modctl *
mod_find_by_filename(char *subdir, char *filename)
{
	struct modctl	*mp;
	size_t		sublen;

	ASSERT(!MUTEX_HELD(&mod_lock));
	if (subdir != NULL)
		sublen = strlen(subdir);
	else
		sublen = 0;

	mutex_enter(&mod_lock);
	mp = &modules;
	do {
		if (sublen) {
			char *mod_filename = mp->mod_filename;

			if (strncmp(subdir, mod_filename, sublen) == 0 &&
			    mod_filename[sublen] == '/' &&
			    strcmp(filename, &mod_filename[sublen + 1]) == 0) {
				mutex_exit(&mod_lock);
				return (mp);
			}
		} else if (strcmp(filename, mp->mod_filename) == 0) {
			mutex_exit(&mod_lock);
			return (mp);
		}
	} while ((mp = mp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (NULL);
}

/*
 * Check for circular dependencies.  This is called from do_dependents()
 * in kobj.c.  If we are the thread already loading this module, then
 * we're trying to load a dependent that we're already loading which
 * means the user specified circular dependencies.
 */
static int
mod_circdep(struct modctl *modp)
{
	struct modctl	*rmod;

	ASSERT(MUTEX_HELD(&mod_lock));

	/*
	 * Check the mod_inprogress_thread first.
	 * mod_inprogress_thread is used in mod_hold_stub()
	 * directly to improve performance.
	 */
	if (modp->mod_inprogress_thread == curthread)
		return (1);

	/*
	 * Check the module circular dependencies.
	 */
	for (rmod = modp; rmod != NULL; rmod = rmod->mod_requisite_loading) {
		/*
		 * Check if there is a module circular dependency.
		 */
		if (rmod->mod_requisite_loading == modp)
			return (1);
	}
	return (0);
}

static int
mod_getinfo(struct modctl *modp, struct modinfo *modinfop)
{
	int (*func)(struct modinfo *);
	int retval;

	ASSERT(modp->mod_busy);

	/* primary modules don't do getinfo */
	if (modp->mod_prim)
		return (0);

	func = (int (*)(struct modinfo *))kobj_lookup(modp->mod_mp, "_info");

	if (kobj_addrcheck(modp->mod_mp, (caddr_t)func)) {
		cmn_err(CE_WARN, "_info() not defined properly in %s",
		    modp->mod_filename);
		/*
		 * The semantics of mod_info(9F) are that 0 is failure
		 * and non-zero is success.
		 */
		retval = 0;
	} else
		retval = (*func)(modinfop);	/* call _info() function */

	if (moddebug & MODDEBUG_USERDEBUG)
		printf("Returned from _info, retval = %x\n", retval);

	return (retval);
}

static void
modadd(struct modctl *mp)
{
	ASSERT(MUTEX_HELD(&mod_lock));

	mp->mod_id = last_module_id++;
	mp->mod_next = &modules;
	mp->mod_prev = modules.mod_prev;
	modules.mod_prev->mod_next = mp;
	modules.mod_prev = mp;
}

/*ARGSUSED*/
static struct modctl *
allocate_modp(const char *filename, const char *modname)
{
	struct modctl *mp;

	mp = kobj_zalloc(sizeof (*mp), KM_SLEEP);
	mp->mod_modname = kobj_zalloc(strlen(modname) + 1, KM_SLEEP);
	(void) strcpy(mp->mod_modname, modname);
	return (mp);
}

/*
 * Get the value of a symbol.  This is a wrapper routine that
 * calls kobj_getsymvalue().  kobj_getsymvalue() may go away but this
 * wrapper will prevent callers from noticing.
 */
uintptr_t
modgetsymvalue(char *name, int kernelonly)
{
	return (kobj_getsymvalue(name, kernelonly));
}

/*
 * Get the symbol nearest an address.  This is a wrapper routine that
 * calls kobj_getsymname().  kobj_getsymname() may go away but this
 * wrapper will prevent callers from noticing.
 */
char *
modgetsymname(uintptr_t value, ulong_t *offset)
{
	return (kobj_getsymname(value, offset));
}

/*
 * Lookup a symbol in a specified module.  These are wrapper routines that
 * call kobj_lookup().	kobj_lookup() may go away but these wrappers will
 * prevent callers from noticing.
 */
uintptr_t
modlookup(const char *modname, const char *symname)
{
	struct modctl *modp;
	uintptr_t val;

	if ((modp = mod_hold_by_name(modname)) == NULL)
		return (0);
	val = kobj_lookup(modp->mod_mp, symname);
	mod_release_mod(modp);
	return (val);
}

uintptr_t
modlookup_by_modctl(modctl_t *modp, const char *symname)
{
	ASSERT(modp->mod_ref > 0 || modp->mod_busy);

	return (kobj_lookup(modp->mod_mp, symname));
}

/*
 * Ask the user for the name of the system file and the default path
 * for modules.
 */
void
mod_askparams()
{
	static char s0[64];
	intptr_t fd;

	if ((fd = kobj_open(systemfile)) != -1L)
		kobj_close(fd);
	else
		systemfile = NULL;

	/*CONSTANTCONDITION*/
	while (1) {
		printf("Name of system file [%s]:  ",
		    systemfile ? systemfile : "/dev/null");

		console_gets(s0, sizeof (s0));

		if (s0[0] == '\0')
			break;
		else if (strcmp(s0, "/dev/null") == 0) {
			systemfile = NULL;
			break;
		} else {
			if ((fd = kobj_open(s0)) != -1L) {
				kobj_close(fd);
				systemfile = s0;
				break;
			}
		}
		printf("can't find file %s\n", s0);
	}
}

static char loading_msg[] = "loading '%s' id %d\n";
static char load_msg[] = "load '%s' id %d loaded @ 0x%p/0x%p size %d/%d\n";

/*
 * Common code for loading a module (but not installing it).
 * Handoff the task of module loading to a separate thread
 * with a large stack if possible, since this code may recurse a few times.
 * Return zero if there are no errors or an errno value.
 */
static int
mod_load(struct modctl *mp, int usepath)
{
	int		retval;
	struct modinfo	*modinfop = NULL;
	struct loadmt	lt;

	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy);

	if (mp->mod_loaded)
		return (0);

	if (mod_sysctl(SYS_CHECK_EXCLUDE, mp->mod_modname) != 0 ||
	    mod_sysctl(SYS_CHECK_EXCLUDE, mp->mod_filename) != 0) {
		if (moddebug & MODDEBUG_LOADMSG) {
			printf(mod_excl_msg, mp->mod_filename,
			    mp->mod_modname);
		}
		return (ENXIO);
	}
	if (moddebug & MODDEBUG_LOADMSG2)
		printf(loading_msg, mp->mod_filename, mp->mod_id);

	if (curthread != &t0) {
		lt.mp = mp;
		lt.usepath = usepath;
		lt.owner = curthread;
		sema_init(&lt.sema, 0, NULL, SEMA_DEFAULT, NULL);

		/* create thread to hand of call to */
		(void) thread_create(NULL, DEFAULTSTKSZ * 2,
		    modload_thread, &lt, 0, &p0, TS_RUN, maxclsyspri);

		/* wait for thread to complete kobj_load_module */
		sema_p(&lt.sema);

		sema_destroy(&lt.sema);
		retval = lt.retval;
	} else
		retval = kobj_load_module(mp, usepath);

	if (mp->mod_mp) {
		ASSERT(retval == 0);
		mp->mod_loaded = 1;
		mp->mod_loadcnt++;
		if (moddebug & MODDEBUG_LOADMSG) {
			printf(load_msg, mp->mod_filename, mp->mod_id,
			    (void *)((struct module *)mp->mod_mp)->text,
			    (void *)((struct module *)mp->mod_mp)->data,
			    ((struct module *)mp->mod_mp)->text_size,
			    ((struct module *)mp->mod_mp)->data_size);
		}

		/*
		 * XXX - There should be a better way to get this.
		 */
		modinfop = kmem_zalloc(sizeof (struct modinfo), KM_SLEEP);
		modinfop->mi_info = MI_INFO_LINKAGE;
		if (mod_getinfo(mp, modinfop) == 0)
			mp->mod_linkage = NULL;
		else {
			mp->mod_linkage = (void *)modinfop->mi_base;
			ASSERT(mp->mod_linkage->ml_rev == MODREV_1);
		}

		/*
		 * DCS: bootstrapping code. If the driver is loaded
		 * before root mount, it is assumed that the driver
		 * may be used before mounting root. In order to
		 * access mappings of global to local minor no.'s
		 * during installation/open of the driver, we load
		 * them into memory here while the BOP_interfaces
		 * are still up.
		 */
		if ((cluster_bootflags & CLUSTER_BOOTED) && !modrootloaded) {
			retval = clboot_modload(mp);
		}

		kmem_free(modinfop, sizeof (struct modinfo));
		(void) mod_sysctl(SYS_SET_MVAR, (void *)mp);
		retval = install_stubs_by_name(mp, mp->mod_modname);

		/*
		 * Now that the module is loaded, we need to give DTrace
		 * a chance to notify its providers.  This is done via
		 * the dtrace_modload function pointer.
		 */
		if (strcmp(mp->mod_modname, "dtrace") != 0) {
			struct modctl *dmp = mod_hold_by_name("dtrace");

			if (dmp != NULL && dtrace_modload != NULL)
				(*dtrace_modload)(mp);

			mod_release_mod(dmp);
		}

	} else {
		/*
		 * If load failed then we need to release any requisites
		 * that we had established.
		 */
		ASSERT(retval);
		mod_release_requisites(mp);

		if (moddebug & MODDEBUG_ERRMSG)
			printf("error loading '%s', error %d\n",
			    mp->mod_filename, retval);
	}
	return (retval);
}

static char unload_msg[] = "unloading %s, module id %d, loadcnt %d.\n";

static void
mod_unload(struct modctl *mp)
{
	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy);
	ASSERT((mp->mod_loaded && (mp->mod_installed == 0)) &&
	    ((mp->mod_prim == 0) && (mp->mod_ref >= 0)));

	if (moddebug & MODDEBUG_LOADMSG)
		printf(unload_msg, mp->mod_modname,
		    mp->mod_id, mp->mod_loadcnt);

	/*
	 * If mod_ref is not zero, it means some modules might still refer
	 * to this module. Then you can't unload this module right now.
	 * Instead, set 1 to mod_delay_unload to notify the system of
	 * unloading this module later when it's not required any more.
	 */
	if (mp->mod_ref > 0) {
		mp->mod_delay_unload = 1;
		if (moddebug & MODDEBUG_LOADMSG2) {
			printf("module %s not unloaded,"
			    " non-zero reference count (%d)",
			    mp->mod_modname, mp->mod_ref);
		}
		return;
	}

	if (((mp->mod_loaded == 0) || mp->mod_installed) ||
	    (mp->mod_ref || mp->mod_prim)) {
		/*
		 * A DEBUG kernel would ASSERT panic above, the code is broken
		 * if we get this warning.
		 */
		cmn_err(CE_WARN, "mod_unload: %s in incorrect state: %d %d %d",
		    mp->mod_filename, mp->mod_installed, mp->mod_loaded,
		    mp->mod_ref);
		return;
	}

	/* reset stub functions to call the binder again */
	reset_stubs(mp);

	/*
	 * mark module as unloaded before the modctl structure is freed.
	 * This is required not to reuse the modctl structure before
	 * the module is marked as unloaded.
	 */
	mp->mod_loaded = 0;
	mp->mod_linkage = NULL;

	/* free the memory */
	kobj_unload_module(mp);

	if (mp->mod_delay_unload) {
		mp->mod_delay_unload = 0;
		if (moddebug & MODDEBUG_LOADMSG2) {
			printf("deferred unload of module %s"
			    " (id %d) successful",
			    mp->mod_modname, mp->mod_id);
		}
	}

	/* release hold on requisites */
	mod_release_requisites(mp);

	/*
	 * Now that the module is gone, we need to give DTrace a chance to
	 * remove any probes that it may have had in the module.  This is
	 * done via the dtrace_modunload function pointer.
	 */
	if (strcmp(mp->mod_modname, "dtrace") != 0) {
		struct modctl *dmp = mod_hold_by_name("dtrace");

		if (dmp != NULL && dtrace_modunload != NULL)
			(*dtrace_modunload)(mp);

		mod_release_mod(dmp);
	}
}

static int
modinstall(struct modctl *mp)
{
	int val;
	int (*func)(void);

	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy && mp->mod_loaded);

	if (mp->mod_installed)
		return (0);
	/*
	 * If mod_delay_unload is on, it means the system chose the deferred
	 * unload for this module. Then you can't install this module until
	 * it's unloaded from the system.
	 */
	if (mp->mod_delay_unload)
		return (ENXIO);

	if (moddebug & MODDEBUG_LOADMSG)
		printf("installing %s, module id %d.\n",
		    mp->mod_modname, mp->mod_id);

	ASSERT(mp->mod_mp != NULL);
	if (mod_install_requisites(mp) != 0) {
		/*
		 * Note that we can't call mod_unload(mp) here since
		 * if modinstall() was called by mod_install_requisites(),
		 * we won't be able to hold the dependent modules
		 * (otherwise there would be a deadlock).
		 */
		return (ENXIO);
	}

	if (moddebug & MODDEBUG_ERRMSG) {
		printf("init '%s' id %d loaded @ 0x%p/0x%p size %lu/%lu\n",
		    mp->mod_filename, mp->mod_id,
		    (void *)((struct module *)mp->mod_mp)->text,
		    (void *)((struct module *)mp->mod_mp)->data,
		    ((struct module *)mp->mod_mp)->text_size,
		    ((struct module *)mp->mod_mp)->data_size);
	}

	func = (int (*)())kobj_lookup(mp->mod_mp, "_init");

	if (kobj_addrcheck(mp->mod_mp, (caddr_t)func)) {
		cmn_err(CE_WARN, "_init() not defined properly in %s",
		    mp->mod_filename);
		return (EFAULT);
	}

	if (moddebug & MODDEBUG_USERDEBUG) {
		printf("breakpoint before calling %s:_init()\n",
		    mp->mod_modname);
		if (DEBUGGER_PRESENT)
			debug_enter("_init");
	}

	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy && mp->mod_loaded);
	val = (*func)();		/* call _init */

	if (moddebug & MODDEBUG_USERDEBUG)
		printf("Returned from _init, val = %x\n", val);

	if (val == 0) {
		/*
		 * Set the MODS_INSTALLED flag to enable this module
		 * being called now.
		 */
		install_stubs(mp);
		mp->mod_installed = 1;
	} else if (moddebug & MODDEBUG_ERRMSG)
		printf(mod_init_msg, mp->mod_filename, mp->mod_modname, val);

	return (val);
}

int	detach_driver_unconfig = 0;

static int
detach_driver(char *name)
{
	major_t major;
	int error;

	/*
	 * If being called from mod_uninstall_all() then the appropriate
	 * driver detaches (leaf only) have already been done.
	 */
	if (mod_in_autounload())
		return (0);

	major = ddi_name_to_major(name);
	if (major == DDI_MAJOR_T_NONE)
		return (0);

	error = ndi_devi_unconfig_driver(ddi_root_node(),
	    NDI_DETACH_DRIVER | detach_driver_unconfig, major);
	return (error == NDI_SUCCESS ? 0 : -1);
}

static char finiret_msg[] = "Returned from _fini for %s, status = %x\n";

static int
moduninstall(struct modctl *mp)
{
	int status = 0;
	int (*func)(void);

	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy);

	/*
	 * Verify that we need to do something and can uninstall the module.
	 *
	 * If we should not uninstall the module or if the module is not in
	 * the correct state to start an uninstall we return EBUSY to prevent
	 * us from progressing to mod_unload.  If the module has already been
	 * uninstalled and unloaded we return EALREADY.
	 */
	if (mp->mod_prim || mp->mod_ref || mp->mod_nenabled != 0)
		return (EBUSY);
	if ((mp->mod_installed == 0) || (mp->mod_loaded == 0))
		return (EALREADY);

	/*
	 * To avoid devinfo / module deadlock we must release this module
	 * prior to initiating the detach_driver, otherwise the detach_driver
	 * might deadlock on a devinfo node held by another thread
	 * coming top down and involving the module we have locked.
	 *
	 * When we regrab the module we must reverify that it is OK
	 * to proceed with the uninstall operation.
	 */
	mod_release_mod(mp);
	status = detach_driver(mp->mod_modname);
	(void) mod_hold_by_modctl(mp, MOD_WAIT_FOREVER | MOD_LOCK_NOT_HELD);

	/* check detach status and reverify state with lock */
	mutex_enter(&mod_lock);
	if ((status != 0) || mp->mod_prim || mp->mod_ref) {
		mutex_exit(&mod_lock);
		return (EBUSY);
	}
	if ((mp->mod_installed == 0) || (mp->mod_loaded == 0)) {
		mutex_exit(&mod_lock);
		return (EALREADY);
	}
	mutex_exit(&mod_lock);

	if (moddebug & MODDEBUG_LOADMSG2)
		printf("uninstalling %s\n", mp->mod_modname);

	/*
	 * lookup _fini, return EBUSY if not defined.
	 *
	 * The MODDEBUG_FINI_EBUSY is usefull in resolving leaks in
	 * detach(9E) - it allows bufctl addresses to be resolved.
	 */
	func = (int (*)())kobj_lookup(mp->mod_mp, "_fini");
	if ((func == NULL) || (mp->mod_loadflags & MOD_NOUNLOAD) ||
	    (moddebug & MODDEBUG_FINI_EBUSY))
		return (EBUSY);

	/* verify that _fini is in this module */
	if (kobj_addrcheck(mp->mod_mp, (caddr_t)func)) {
		cmn_err(CE_WARN, "_fini() not defined properly in %s",
		    mp->mod_filename);
		return (EFAULT);
	}

	/* call _fini() */
	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(mp->mod_busy && mp->mod_loaded && mp->mod_installed);

	status = (*func)();

	if (status == 0) {
		/* _fini returned success, the module is no longer installed */
		if (moddebug & MODDEBUG_LOADMSG)
			printf("uninstalled %s\n", mp->mod_modname);

		/*
		 * Even though we only set mod_installed to zero here, a zero
		 * return value means we are committed to a code path were
		 * mod_loaded will also end up as zero - we have no other
		 * way to get the module data and bss back to the pre _init
		 * state except a reload. To ensure this, after return,
		 * mod_busy must stay set until mod_loaded is cleared.
		 */
		mp->mod_installed = 0;

		/*
		 * Clear the MODS_INSTALLED flag not to call functions
		 * in the module directly from now on.
		 */
		uninstall_stubs(mp);
	} else {
		if (moddebug & MODDEBUG_USERDEBUG)
			printf(finiret_msg, mp->mod_filename, status);
		/*
		 * By definition _fini is only allowed to return EBUSY or the
		 * result of mod_remove (EBUSY or EINVAL).  In the off chance
		 * that a driver returns EALREADY we convert this to EINVAL
		 * since to our caller EALREADY means module was already
		 * removed.
		 */
		if (status == EALREADY)
			status = EINVAL;
	}

	return (status);
}

/*
 * Uninstall all modules.
 */
static void
mod_uninstall_all(void)
{
	struct modctl	*mp;
	int		pass;
	modid_t		modid;

	/* synchronize with any active modunload_disable() */
	modunload_begin();

	/* mark this thread as doing autounloading */
	(void) tsd_set(mod_autounload_key, (void *)1);

	(void) devfs_clean(ddi_root_node(), NULL, 0);
	(void) ndi_devi_unconfig(ddi_root_node(), NDI_AUTODETACH);

	/*
	 * Loop up to max times if we keep producing unreferenced modules.
	 * A new unreferenced module is an opportunity to unload.
	 */
	for (pass = 0; pass < mod_uninstall_pass_max; pass++) {

		/* zero count of modules that go unreferenced during pass */
		mod_uninstall_ref_zero = 0;

		modid = 0;
		while ((mp = mod_hold_next_by_id(modid)) != NULL) {
			modid = mp->mod_id;

			/*
			 * Skip modules with the MOD_NOAUTOUNLOAD flag set
			 */
			if (mp->mod_loadflags & MOD_NOAUTOUNLOAD) {
				mod_release_mod(mp);
				continue;
			}

			if (moduninstall(mp) == 0) {
				mod_unload(mp);
				CPU_STATS_ADDQ(CPU, sys, modunload, 1);
			}
			mod_release_mod(mp);
		}

		/* break if no modules went unreferenced during pass */
		if (mod_uninstall_ref_zero == 0)
			break;
	}
	if (pass >= mod_uninstall_pass_max)
		mod_uninstall_pass_exc++;

	(void) tsd_set(mod_autounload_key, NULL);
	modunload_end();
}

/* wait for unloads that have begun before registering disable */
void
modunload_disable(void)
{
	mutex_enter(&modunload_wait_mutex);
	while (modunload_active_count) {
		modunload_wait++;
		cv_wait(&modunload_wait_cv, &modunload_wait_mutex);
		modunload_wait--;
	}
	modunload_disable_count++;
	mutex_exit(&modunload_wait_mutex);
}

/* mark end of disable and signal waiters */
void
modunload_enable(void)
{
	mutex_enter(&modunload_wait_mutex);
	modunload_disable_count--;
	if ((modunload_disable_count == 0) && modunload_wait)
		cv_broadcast(&modunload_wait_cv);
	mutex_exit(&modunload_wait_mutex);
}

/* wait for disables to complete before begining unload */
void
modunload_begin()
{
	mutex_enter(&modunload_wait_mutex);
	while (modunload_disable_count) {
		modunload_wait++;
		cv_wait(&modunload_wait_cv, &modunload_wait_mutex);
		modunload_wait--;
	}
	modunload_active_count++;
	mutex_exit(&modunload_wait_mutex);
}

/* mark end of unload and signal waiters */
void
modunload_end()
{
	mutex_enter(&modunload_wait_mutex);
	modunload_active_count--;
	if ((modunload_active_count == 0) && modunload_wait)
		cv_broadcast(&modunload_wait_cv);
	mutex_exit(&modunload_wait_mutex);
}

void
mod_uninstall_daemon(void)
{
	callb_cpr_t	cprinfo;
	clock_t		ticks;

	mod_aul_thread = curthread;

	CALLB_CPR_INIT(&cprinfo, &mod_uninstall_lock, callb_generic_cpr, "mud");
	for (;;) {
		mutex_enter(&mod_uninstall_lock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * In DEBUG kernels, unheld drivers are uninstalled periodically
		 * every mod_uninstall_interval seconds.  Periodic uninstall can
		 * be disabled by setting mod_uninstall_interval to 0 which is
		 * the default for a non-DEBUG kernel.
		 */
		if (mod_uninstall_interval) {
			ticks = drv_usectohz(mod_uninstall_interval * 1000000);
			(void) cv_reltimedwait(&mod_uninstall_cv,
			    &mod_uninstall_lock, ticks, TR_CLOCK_TICK);
		} else {
			cv_wait(&mod_uninstall_cv, &mod_uninstall_lock);
		}
		/*
		 * The whole daemon is safe for CPR except we don't want
		 * the daemon to run if FREEZE is issued and this daemon
		 * wakes up from the cv_wait above. In this case, it'll be
		 * blocked in CALLB_CPR_SAFE_END until THAW is issued.
		 *
		 * The reason of calling CALLB_CPR_SAFE_BEGIN twice is that
		 * mod_uninstall_lock is used to protect cprinfo and
		 * CALLB_CPR_SAFE_BEGIN assumes that this lock is held when
		 * called.
		 */
		CALLB_CPR_SAFE_END(&cprinfo, &mod_uninstall_lock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		mutex_exit(&mod_uninstall_lock);
		if ((modunload_disable_count == 0) &&
		    ((moddebug & MODDEBUG_NOAUTOUNLOAD) == 0)) {
			mod_uninstall_all();
		}
	}
}

/*
 * Unload all uninstalled modules.
 */
void
modreap(void)
{
	mutex_enter(&mod_uninstall_lock);
	cv_broadcast(&mod_uninstall_cv);
	mutex_exit(&mod_uninstall_lock);
}

/*
 * Hold the specified module. This is the module holding primitive.
 *
 * If MOD_LOCK_HELD then the caller already holds the mod_lock.
 *
 * Return values:
 *	 0 ==> the module is held
 *	 1 ==> the module is not held and the MOD_WAIT_ONCE caller needs
 *		to determine how to retry.
 */
int
mod_hold_by_modctl(struct modctl *mp, int f)
{
	ASSERT((f & (MOD_WAIT_ONCE | MOD_WAIT_FOREVER)) &&
	    ((f & (MOD_WAIT_ONCE | MOD_WAIT_FOREVER)) !=
	    (MOD_WAIT_ONCE | MOD_WAIT_FOREVER)));
	ASSERT((f & (MOD_LOCK_HELD | MOD_LOCK_NOT_HELD)) &&
	    ((f & (MOD_LOCK_HELD | MOD_LOCK_NOT_HELD)) !=
	    (MOD_LOCK_HELD | MOD_LOCK_NOT_HELD)));
	ASSERT((f & MOD_LOCK_NOT_HELD) || MUTEX_HELD(&mod_lock));

	if (f & MOD_LOCK_NOT_HELD)
		mutex_enter(&mod_lock);

	while (mp->mod_busy) {
		mp->mod_want = 1;
		cv_wait(&mod_cv, &mod_lock);
		/*
		 * Module may be unloaded by daemon.
		 * Nevertheless, modctl structure is still in linked list
		 * (i.e., off &modules), not freed!
		 * Caller is not supposed to assume "mp" is valid, but there
		 * is no reasonable way to detect this but using
		 * mp->mod_modinfo->mp == NULL check (follow the back pointer)
		 *   (or similar check depending on calling context)
		 * DON'T free modctl structure, it will be very very
		 * problematic.
		 */
		if (f & MOD_WAIT_ONCE) {
			if (f & MOD_LOCK_NOT_HELD)
				mutex_exit(&mod_lock);
			return (1);	/* caller decides how to retry */
		}
	}

	mp->mod_busy = 1;
	mp->mod_inprogress_thread =
	    (curthread == NULL ? (kthread_id_t)-1 : curthread);

	if (f & MOD_LOCK_NOT_HELD)
		mutex_exit(&mod_lock);
	return (0);
}

static struct modctl *
mod_hold_by_name_common(struct modctl *dep, const char *filename)
{
	const char	*modname;
	struct modctl	*mp;
	char		*curname, *newname;
	int		found = 0;

	mutex_enter(&mod_lock);

	if ((modname = strrchr(filename, '/')) == NULL)
		modname = filename;
	else
		modname++;

	mp = &modules;
	do {
		if (strcmp(modname, mp->mod_modname) == 0) {
			found = 1;
			break;
		}
	} while ((mp = mp->mod_next) != &modules);

	if (found == 0) {
		mp = allocate_modp(filename, modname);
		modadd(mp);
	}

	/*
	 * if dep is not NULL, set the mp in mod_requisite_loading for
	 * the module circular dependency check. This field is used in
	 * mod_circdep(), but it's cleard in mod_hold_loaded_mod().
	 */
	if (dep != NULL) {
		ASSERT(dep->mod_busy && dep->mod_requisite_loading == NULL);
		dep->mod_requisite_loading = mp;
	}

	/*
	 * If the module was held, then it must be us who has it held.
	 */
	if (mod_circdep(mp))
		mp = NULL;
	else {
		(void) mod_hold_by_modctl(mp, MOD_WAIT_FOREVER | MOD_LOCK_HELD);

		/*
		 * If the name hadn't been set or has changed, allocate
		 * space and set it.  Free space used by previous name.
		 *
		 * Do not change the name of primary modules, for primary
		 * modules the mod_filename was allocated in standalone mode:
		 * it is illegal to kobj_alloc in standalone mode and kobj_free
		 * in non-standalone mode.
		 */
		curname = mp->mod_filename;
		if (curname == NULL ||
		    ((mp->mod_prim == 0) &&
		    (curname != filename) &&
		    (modname != filename) &&
		    (strcmp(curname, filename) != 0))) {
			newname = kobj_zalloc(strlen(filename) + 1, KM_SLEEP);
			(void) strcpy(newname, filename);
			mp->mod_filename = newname;
			if (curname != NULL)
				kobj_free(curname, strlen(curname) + 1);
		}
	}

	mutex_exit(&mod_lock);
	if (mp && moddebug & MODDEBUG_LOADMSG2)
		printf("Holding %s\n", mp->mod_filename);
	if (mp == NULL && moddebug & MODDEBUG_LOADMSG2)
		printf("circular dependency loading %s\n", filename);
	return (mp);
}

static struct modctl *
mod_hold_by_name_requisite(struct modctl *dep, char *filename)
{
	return (mod_hold_by_name_common(dep, filename));
}

struct modctl *
mod_hold_by_name(const char *filename)
{
	return (mod_hold_by_name_common(NULL, filename));
}

struct modctl *
mod_hold_by_id(modid_t modid)
{
	struct modctl	*mp;
	int		found = 0;

	mutex_enter(&mod_lock);
	mp = &modules;
	do {
		if (mp->mod_id == modid) {
			found = 1;
			break;
		}
	} while ((mp = mp->mod_next) != &modules);

	if ((found == 0) || mod_circdep(mp))
		mp = NULL;
	else
		(void) mod_hold_by_modctl(mp, MOD_WAIT_FOREVER | MOD_LOCK_HELD);

	mutex_exit(&mod_lock);
	return (mp);
}

static struct modctl *
mod_hold_next_by_id(modid_t modid)
{
	struct modctl	*mp;
	int		found = 0;

	if (modid < -1)
		return (NULL);

	mutex_enter(&mod_lock);

	mp = &modules;
	do {
		if (mp->mod_id > modid) {
			found = 1;
			break;
		}
	} while ((mp = mp->mod_next) != &modules);

	if ((found == 0) || mod_circdep(mp))
		mp = NULL;
	else
		(void) mod_hold_by_modctl(mp, MOD_WAIT_FOREVER | MOD_LOCK_HELD);

	mutex_exit(&mod_lock);
	return (mp);
}

static void
mod_release(struct modctl *mp)
{
	ASSERT(MUTEX_HELD(&mod_lock));
	ASSERT(mp->mod_busy);

	mp->mod_busy = 0;
	mp->mod_inprogress_thread = NULL;
	if (mp->mod_want) {
		mp->mod_want = 0;
		cv_broadcast(&mod_cv);
	}
}

void
mod_release_mod(struct modctl *mp)
{
	if (moddebug & MODDEBUG_LOADMSG2)
		printf("Releasing %s\n", mp->mod_filename);
	mutex_enter(&mod_lock);
	mod_release(mp);
	mutex_exit(&mod_lock);
}

modid_t
mod_name_to_modid(char *filename)
{
	char		*modname;
	struct modctl	*mp;

	mutex_enter(&mod_lock);

	if ((modname = strrchr(filename, '/')) == NULL)
		modname = filename;
	else
		modname++;

	mp = &modules;
	do {
		if (strcmp(modname, mp->mod_modname) == 0) {
			mutex_exit(&mod_lock);
			return (mp->mod_id);
		}
	} while ((mp = mp->mod_next) != &modules);

	mutex_exit(&mod_lock);
	return (-1);
}


int
mod_remove_by_name(char *name)
{
	struct modctl *mp;
	int retval;

	mp = mod_hold_by_name(name);

	if (mp == NULL)
		return (EINVAL);

	if (mp->mod_loadflags & MOD_NOAUTOUNLOAD) {
		/*
		 * Do not unload forceloaded modules
		 */
		mod_release_mod(mp);
		return (0);
	}

	if ((retval = moduninstall(mp)) == 0) {
		mod_unload(mp);
		CPU_STATS_ADDQ(CPU, sys, modunload, 1);
	} else if (retval == EALREADY)
		retval = 0;		/* already unloaded, not an error */
	mod_release_mod(mp);
	return (retval);
}

/*
 * Record that module "dep" is dependent on module "on_mod."
 */
static void
mod_make_requisite(struct modctl *dependent, struct modctl *on_mod)
{
	struct modctl_list **pmlnp;	/* previous next pointer */
	struct modctl_list *mlp;
	struct modctl_list *new;

	ASSERT(dependent->mod_busy && on_mod->mod_busy);
	mutex_enter(&mod_lock);

	/*
	 * Search dependent's requisite list to see if on_mod is recorded.
	 * List is ordered by id.
	 */
	for (pmlnp = &dependent->mod_requisites, mlp = *pmlnp;
	    mlp; pmlnp = &mlp->modl_next, mlp = *pmlnp)
		if (mlp->modl_modp->mod_id >= on_mod->mod_id)
			break;

	/* Create and insert if not already recorded */
	if ((mlp == NULL) || (mlp->modl_modp->mod_id != on_mod->mod_id)) {
		new = kobj_zalloc(sizeof (*new), KM_SLEEP);
		new->modl_modp = on_mod;
		new->modl_next = mlp;
		*pmlnp = new;

		/*
		 * Increment the mod_ref count in our new requisite module.
		 * This is what keeps a module that has other modules
		 * which are dependent on it from being uninstalled and
		 * unloaded. "on_mod"'s mod_ref count decremented in
		 * mod_release_requisites when the "dependent" module
		 * unload is complete.	"on_mod" must be loaded, but may not
		 * yet be installed.
		 */
		on_mod->mod_ref++;
		ASSERT(on_mod->mod_ref && on_mod->mod_loaded);
	}

	mutex_exit(&mod_lock);
}

/*
 * release the hold associated with mod_make_requisite mod_ref++
 * as part of unload.
 */
void
mod_release_requisites(struct modctl *modp)
{
	struct modctl_list *modl;
	struct modctl_list *next;
	struct modctl *req;
	struct modctl_list *start = NULL, *mod_garbage;

	ASSERT(!quiesce_active);
	ASSERT(modp->mod_busy);
	ASSERT(MUTEX_NOT_HELD(&mod_lock));

	mutex_enter(&mod_lock);		/* needed for manipulation of req */
	for (modl = modp->mod_requisites; modl; modl = next) {
		next = modl->modl_next;
		req = modl->modl_modp;
		ASSERT(req->mod_ref >= 1 && req->mod_loaded);
		req->mod_ref--;
		if (req->mod_ref == 0)
			mod_uninstall_ref_zero++;

		/*
		 * Check if the module has to be unloaded or not.
		 */
		if (req->mod_ref == 0 && req->mod_delay_unload) {
			struct modctl_list *new;
			/*
			 * Allocate the modclt_list holding the garbage
			 * module which should be unloaded later.
			 */
			new = kobj_zalloc(sizeof (struct modctl_list),
			    KM_SLEEP);
			new->modl_modp = req;

			if (start == NULL)
				mod_garbage = start = new;
			else {
				mod_garbage->modl_next = new;
				mod_garbage = new;
			}
		}

		/* free the list as we go */
		kobj_free(modl, sizeof (*modl));
	}
	modp->mod_requisites = NULL;
	mutex_exit(&mod_lock);

	/*
	 * Unload the garbage modules.
	 */
	for (mod_garbage = start; mod_garbage != NULL; /* nothing */) {
		struct modctl_list *old = mod_garbage;
		struct modctl *mp = mod_garbage->modl_modp;
		ASSERT(mp != NULL);

		/*
		 * Hold this module until it's unloaded completely.
		 */
		(void) mod_hold_by_modctl(mp,
		    MOD_WAIT_FOREVER | MOD_LOCK_NOT_HELD);
		/*
		 * Check if the module is not unloaded yet and nobody requires
		 * the module. If it's unloaded already or somebody still
		 * requires the module, don't unload it now.
		 */
		if (mp->mod_loaded && mp->mod_ref == 0)
			mod_unload(mp);
		ASSERT((mp->mod_loaded == 0 && mp->mod_delay_unload == 0) ||
		    (mp->mod_ref > 0));
		mod_release_mod(mp);

		mod_garbage = mod_garbage->modl_next;
		kobj_free(old, sizeof (struct modctl_list));
	}
}

/*
 * Process dependency of the module represented by "dep" on the
 * module named by "on."
 *
 * Called from kobj_do_dependents() to load a module "on" on which
 * "dep" depends.
 */
struct modctl *
mod_load_requisite(struct modctl *dep, char *on)
{
	struct modctl *on_mod;
	int retval;

	if ((on_mod = mod_hold_loaded_mod(dep, on, &retval)) != NULL) {
		mod_make_requisite(dep, on_mod);
	} else if (moddebug & MODDEBUG_ERRMSG) {
		printf("error processing %s on which module %s depends\n",
		    on, dep->mod_modname);
	}
	return (on_mod);
}

static int
mod_install_requisites(struct modctl *modp)
{
	struct modctl_list *modl;
	struct modctl *req;
	int status = 0;

	ASSERT(MUTEX_NOT_HELD(&mod_lock));
	ASSERT(modp->mod_busy);

	for (modl = modp->mod_requisites; modl; modl = modl->modl_next) {
		req = modl->modl_modp;
		(void) mod_hold_by_modctl(req,
		    MOD_WAIT_FOREVER | MOD_LOCK_NOT_HELD);
		status = modinstall(req);
		mod_release_mod(req);

		if (status != 0)
			break;
	}
	return (status);
}

/*
 * returns 1 if this thread is doing autounload, 0 otherwise.
 * see mod_uninstall_all.
 */
int
mod_in_autounload()
{
	return ((int)(uintptr_t)tsd_get(mod_autounload_key));
}

/*
 * gmatch adapted from libc, stripping the wchar stuff
 */
#define	popchar(p, c)	{ \
		c = *p++; \
		if (c == 0) { \
			return (0); \
		} \
	}

int
gmatch(const char *s, const char *p)
{
	int c, sc;
	int ok, lc, notflag;

	sc = *s++;
	c = *p++;
	if (c == 0)
		return (sc == c);	/* nothing matches nothing */

	switch (c) {
	case '\\':
		/* skip to quoted character */
		popchar(p, c);
		/*FALLTHRU*/

	default:
		/* straight comparison */
		if (c != sc)
			return (0);
		/*FALLTHRU*/

	case '?':
		/* first char matches, move to remainder */
		return (sc != '\0' ? gmatch(s, p) : 0);


	case '*':
		while (*p == '*')
			p++;

		/* * matches everything */
		if (*p == 0)
			return (1);

		/* undo skip at the beginning & iterate over substrings */
		--s;
		while (*s) {
			if (gmatch(s, p))
				return (1);
			s++;
		}
		return (0);

	case '[':
		/* match any char within [] */
		if (sc == 0)
			return (0);

		ok = lc = notflag = 0;

		if (*p == '!') {
			notflag = 1;
			p++;
		}
		popchar(p, c);

		do {
			if (c == '-' && lc && *p != ']') {
				/* test sc against range [c1-c2] */
				popchar(p, c);
				if (c == '\\') {
					popchar(p, c);
				}

				if (notflag) {
					/* return 0 on mismatch */
					if (lc <= sc && sc <= c)
						return (0);
					ok++;
				} else if (lc <= sc && sc <= c) {
					ok++;
				}
				/* keep going, may get a match next */
			} else if (c == '\\') {
				/* skip to quoted character */
				popchar(p, c);
			}
			lc = c;
			if (notflag) {
				if (sc == lc)
					return (0);
				ok++;
			} else if (sc == lc) {
				ok++;
			}
			popchar(p, c);
		} while (c != ']');

		/* recurse on remainder of string */
		return (ok ? gmatch(s, p) : 0);
	}
	/*NOTREACHED*/
}


/*
 * Get default perm for device from /etc/minor_perm. Return 0 if match found.
 *
 * Pure wild-carded patterns are handled separately so the ordering of
 * these patterns doesn't matter.  We're still dependent on ordering
 * however as the first matching entry is the one returned.
 * Not ideal but all existing examples and usage do imply this
 * ordering implicitly.
 *
 * Drivers using the clone driver are always good for some entertainment.
 * Clone nodes under pseudo have the form clone@0:<driver>.  Some minor
 * perm entries have the form clone:<driver>, others use <driver>:*
 * Examples are clone:llc1 vs. llc2:*, for example.
 *
 * Minor perms in the clone:<driver> form are mapped to the drivers's
 * mperm list, not the clone driver, as wildcard entries for clone
 * reference only.  In other words, a clone wildcard will match
 * references for clone@0:<driver> but never <driver>@<minor>.
 *
 * Additional minor perms in the standard form are also supported,
 * for mixed usage, ie a node with an entry clone:<driver> could
 * provide further entries <driver>:<minor>.
 *
 * Finally, some uses of clone use an alias as the minor name rather
 * than the driver name, with the alias as the minor perm entry.
 * This case is handled by attaching the driver to bring its
 * minor list into existence, then discover the alias via DDI_ALIAS.
 * The clone device's minor perm list can then be searched for
 * that alias.
 */

static int
dev_alias_minorperm(dev_info_t *dip, char *minor_name, mperm_t *rmp)
{
	major_t			major;
	struct devnames		*dnp;
	mperm_t			*mp;
	char			*alias = NULL;
	dev_info_t		*cdevi;
	int			circ;
	struct ddi_minor_data	*dmd;

	major = ddi_name_to_major(minor_name);

	ASSERT(dip == clone_dip);
	ASSERT(major != DDI_MAJOR_T_NONE);

	/*
	 * Attach the driver named by the minor node, then
	 * search its first instance's minor list for an
	 * alias node.
	 */
	if (ddi_hold_installed_driver(major) == NULL)
		return (1);

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);

	if ((cdevi = dnp->dn_head) != NULL) {
		ndi_devi_enter(cdevi, &circ);
		for (dmd = DEVI(cdevi)->devi_minor; dmd; dmd = dmd->next) {
			if (dmd->type == DDM_ALIAS) {
				alias = i_ddi_strdup(dmd->ddm_name, KM_SLEEP);
				break;
			}
		}
		ndi_devi_exit(cdevi, circ);
	}

	UNLOCK_DEV_OPS(&dnp->dn_lock);
	ddi_rele_driver(major);

	if (alias == NULL) {
		if (moddebug & MODDEBUG_MINORPERM)
			cmn_err(CE_CONT, "dev_minorperm: "
			    "no alias for %s\n", minor_name);
		return (1);
	}

	major = ddi_driver_major(clone_dip);
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);

	/*
	 * Go through the clone driver's mperm list looking
	 * for a match for the specified alias.
	 */
	for (mp = dnp->dn_mperm; mp; mp = mp->mp_next) {
		if (strcmp(alias, mp->mp_minorname) == 0) {
			break;
		}
	}

	if (mp) {
		if (moddebug & MODDEBUG_MP_MATCH) {
			cmn_err(CE_CONT,
			    "minor perm defaults: %s %s 0%o %d %d (aliased)\n",
			    minor_name, alias, mp->mp_mode,
			    mp->mp_uid, mp->mp_gid);
		}
		rmp->mp_uid = mp->mp_uid;
		rmp->mp_gid = mp->mp_gid;
		rmp->mp_mode = mp->mp_mode;
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	kmem_free(alias, strlen(alias)+1);

	return (mp == NULL);
}

int
dev_minorperm(dev_info_t *dip, char *name, mperm_t *rmp)
{
	major_t major;
	char *minor_name;
	struct devnames *dnp;
	mperm_t *mp;
	int is_clone = 0;

	if (!minorperm_loaded) {
		if (moddebug & MODDEBUG_MINORPERM)
			cmn_err(CE_CONT,
			    "%s: minor perm not yet loaded\n", name);
		return (1);
	}

	minor_name = strchr(name, ':');
	if (minor_name == NULL)
		return (1);
	minor_name++;

	/*
	 * If it's the clone driver, search the driver as named
	 * by the minor.  All clone minor perm entries other than
	 * alias nodes are actually installed on the real driver's list.
	 */
	if (dip == clone_dip) {
		major = ddi_name_to_major(minor_name);
		if (major == DDI_MAJOR_T_NONE) {
			if (moddebug & MODDEBUG_MINORPERM)
				cmn_err(CE_CONT, "dev_minorperm: "
				    "%s: no such driver\n", minor_name);
			return (1);
		}
		is_clone = 1;
	} else {
		major = ddi_driver_major(dip);
		ASSERT(major != DDI_MAJOR_T_NONE);
	}

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);

	/*
	 * Go through the driver's mperm list looking for
	 * a match for the specified minor.  If there's
	 * no matching pattern, use the wild card.
	 * Defer to the clone wild for clone if specified,
	 * otherwise fall back to the normal form.
	 */
	for (mp = dnp->dn_mperm; mp; mp = mp->mp_next) {
		if (gmatch(minor_name, mp->mp_minorname) != 0) {
			break;
		}
	}
	if (mp == NULL) {
		if (is_clone)
			mp = dnp->dn_mperm_clone;
		if (mp == NULL)
			mp = dnp->dn_mperm_wild;
	}

	if (mp) {
		if (moddebug & MODDEBUG_MP_MATCH) {
			cmn_err(CE_CONT,
			    "minor perm defaults: %s %s 0%o %d %d\n",
			    name, mp->mp_minorname, mp->mp_mode,
			    mp->mp_uid, mp->mp_gid);
		}
		rmp->mp_uid = mp->mp_uid;
		rmp->mp_gid = mp->mp_gid;
		rmp->mp_mode = mp->mp_mode;
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	/*
	 * If no match can be found for a clone node,
	 * search for a possible match for an alias.
	 * One such example is /dev/ptmx -> /devices/pseudo/clone@0:ptm,
	 * with minor perm entry clone:ptmx.
	 */
	if (mp == NULL && is_clone) {
		return (dev_alias_minorperm(dip, minor_name, rmp));
	}

	return (mp == NULL);
}

/*
 * dynamicaly reference load a dl module/library, returning handle
 */
/*ARGSUSED*/
ddi_modhandle_t
ddi_modopen(const char *modname, int mode, int *errnop)
{
	char		*subdir;
	char		*mod;
	int		subdirlen;
	struct modctl	*hmodp = NULL;
	int		retval = EINVAL;

	ASSERT(modname && (mode == KRTLD_MODE_FIRST));
	if ((modname == NULL) || (mode != KRTLD_MODE_FIRST))
		goto out;

	/* find last '/' in modname */
	mod = strrchr(modname, '/');

	if (mod) {
		/* for subdir string without modification to argument */
		mod++;
		subdirlen = mod - modname;
		subdir = kmem_alloc(subdirlen, KM_SLEEP);
		(void) strlcpy(subdir, modname, subdirlen);
	} else {
		subdirlen = 0;
		subdir = "misc";
		mod = (char *)modname;
	}

	/* reference load with errno return value */
	retval = modrload(subdir, mod, &hmodp);

	if (subdirlen)
		kmem_free(subdir, subdirlen);

out:	if (errnop)
		*errnop = retval;

	if (moddebug & MODDEBUG_DDI_MOD)
		printf("ddi_modopen %s mode %x: %s %p %d\n",
		    modname ? modname : "<unknown>", mode,
		    hmodp ? hmodp->mod_filename : "<unknown>",
		    (void *)hmodp, retval);

	return ((ddi_modhandle_t)hmodp);
}

/* lookup "name" in open dl module/library */
void *
ddi_modsym(ddi_modhandle_t h, const char *name, int *errnop)
{
	struct modctl	*hmodp = (struct modctl *)h;
	void		*f;
	int		retval;

	ASSERT(hmodp && name && hmodp->mod_installed && (hmodp->mod_ref >= 1));
	if ((hmodp == NULL) || (name == NULL) ||
	    (hmodp->mod_installed == 0) || (hmodp->mod_ref < 1)) {
		f = NULL;
		retval = EINVAL;
	} else {
		f = (void *)kobj_lookup(hmodp->mod_mp, (char *)name);
		if (f)
			retval = 0;
		else
			retval = ENOTSUP;
	}

	if (moddebug & MODDEBUG_DDI_MOD)
		printf("ddi_modsym in %s of %s: %d %p\n",
		    hmodp ? hmodp->mod_modname : "<unknown>",
		    name ? name : "<unknown>", retval, f);

	if (errnop)
		*errnop = retval;
	return (f);
}

/* dynamic (un)reference unload of an open dl module/library */
int
ddi_modclose(ddi_modhandle_t h)
{
	struct modctl	*hmodp = (struct modctl *)h;
	struct modctl	*modp = NULL;
	int		retval;

	ASSERT(hmodp && hmodp->mod_installed && (hmodp->mod_ref >= 1));
	if ((hmodp == NULL) ||
	    (hmodp->mod_installed == 0) || (hmodp->mod_ref < 1)) {
		retval = EINVAL;
		goto out;
	}

	retval = modunrload(hmodp->mod_id, &modp, ddi_modclose_unload);
	if (retval == EBUSY)
		retval = 0;	/* EBUSY is not an error */

	if (retval == 0) {
		ASSERT(hmodp == modp);
		if (hmodp != modp)
			retval = EINVAL;
	}

out:	if (moddebug & MODDEBUG_DDI_MOD)
		printf("ddi_modclose %s: %d\n",
		    hmodp ? hmodp->mod_modname : "<unknown>", retval);

	return (retval);
}
