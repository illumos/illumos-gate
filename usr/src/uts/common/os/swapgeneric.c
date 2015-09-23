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
 * Copyright (c) 1982, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Configure root, swap and dump devices.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/reboot.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/mount.h>
#include <sys/kobj.h>
#include <sys/bootconf.h>
#include <sys/sysconf.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/debug.h>
#include <sys/fs/snode.h>
#include <fs/fs_subr.h>
#include <sys/socket.h>
#include <net/if.h>

#include <sys/mkdev.h>
#include <sys/cmn_err.h>
#include <sys/console.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/hwconf.h>
#include <sys/dc_ki.h>
#include <sys/promif.h>
#include <sys/bootprops.h>

/*
 * Local routines
 */
static int preload_module(struct sysparam *, void *);
static struct vfssw *getfstype(char *, char *, size_t);
static int getphysdev(char *, char *, size_t);
static int load_bootpath_drivers(char *bootpath);
static int load_boot_driver(char *drv);
static int load_boot_platform_modules(char *drv);
static dev_info_t *path_to_devinfo(char *path);
static boolean_t netboot_over_ib(char *bootpath);
static boolean_t netboot_over_iscsi(void);

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "root and swap configuration"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

extern ib_boot_prop_t *iscsiboot_prop;
/*
 * Configure root file system.
 */
int
rootconf(void)
{
	int		error;
	struct vfssw	*vsw;
	extern void pm_init(void);
	int ret = -1;
	BMDPRINTF(("rootconf: fstype %s\n", rootfs.bo_fstype));
	BMDPRINTF(("rootconf: name %s\n", rootfs.bo_name));
	BMDPRINTF(("rootconf: flags 0x%x\n", rootfs.bo_flags));
	BMDPRINTF(("rootconf: obp_bootpath %s\n", obp_bootpath));

	/*
	 * Install cluster modules that were only loaded during
	 * loadrootmodules().
	 */
	if (error = clboot_rootconf())
		return (error);

	if (root_is_svm) {
		(void) strncpy(rootfs.bo_name, obp_bootpath, BO_MAXOBJNAME);

		BMDPRINTF(("rootconf: svm: rootfs name %s\n", rootfs.bo_name));
		BMDPRINTF(("rootconf: svm: svm name %s\n", svm_bootpath));
	}

	/*
	 * Run _init on the root filesystem (we already loaded it
	 * but we've been waiting until now to _init it) which will
	 * have the side-effect of running vsw_init() on this vfs.
	 * Because all the nfs filesystems are lumped into one
	 * module we need to special case it.
	 */
	if (strncmp(rootfs.bo_fstype, "nfs", 3) == 0) {
		if (modload("fs", "nfs") == -1) {
			cmn_err(CE_CONT, "Cannot initialize %s filesystem\n",
			    rootfs.bo_fstype);
			return (ENXIO);
		}
	} else {
		if (modload("fs", rootfs.bo_fstype) == -1) {
			cmn_err(CE_CONT, "Cannot initialize %s filesystem\n",
			    rootfs.bo_fstype);
			return (ENXIO);
		}
	}
	RLOCK_VFSSW();
	vsw = vfs_getvfsswbyname(rootfs.bo_fstype);
	RUNLOCK_VFSSW();
	if (vsw == NULL) {
		cmn_err(CE_CONT, "Cannot find %s filesystem\n",
		    rootfs.bo_fstype);
		return (ENXIO);
	}
	VFS_INIT(rootvfs, &vsw->vsw_vfsops, (caddr_t)0);
	VFS_HOLD(rootvfs);

	if (root_is_svm) {
		rootvfs->vfs_flag |= VFS_RDONLY;
	}

	/*
	 * This pm-releated call has to occur before root is mounted since we
	 * need to power up all devices.  It is placed after VFS_INIT() such
	 * that opening a device via ddi_lyr_ interface just before root has
	 * been mounted would work.
	 */
	pm_init();

	if (netboot && iscsiboot_prop) {
		cmn_err(CE_WARN, "NFS boot and iSCSI boot"
		    " shouldn't happen in the same time");
		return (EINVAL);
	}

	if (netboot || iscsiboot_prop) {
		ret = strplumb();
		if (ret != 0) {
			cmn_err(CE_WARN, "Cannot plumb network device %d", ret);
			return (EFAULT);
		}
	}

	if ((ret == 0) && iscsiboot_prop) {
		ret = modload("drv", "iscsi");
		/* -1 indicates fail */
		if (ret == -1) {
			cmn_err(CE_WARN, "Failed to load iscsi module");
			iscsi_boot_prop_free();
			return (EINVAL);
		} else {
			if (!i_ddi_attach_pseudo_node("iscsi")) {
				cmn_err(CE_WARN,
				    "Failed to attach iscsi driver");
				iscsi_boot_prop_free();
				return (ENODEV);
			}
		}
	}

	/*
	 * ufs_mountroot() ends up calling getrootdev()
	 * (below) which actually triggers the _init, identify,
	 * probe and attach of the drivers that make up root device
	 * bush; these are also quietly waiting in memory.
	 */
	BMDPRINTF(("rootconf: calling VFS_MOUNTROOT %s\n", rootfs.bo_fstype));

	error = VFS_MOUNTROOT(rootvfs, ROOT_INIT);
	vfs_unrefvfssw(vsw);
	rootdev = rootvfs->vfs_dev;

	if (error)
		cmn_err(CE_CONT, "Cannot mount root on %s fstype %s\n",
		    rootfs.bo_name, rootfs.bo_fstype);
	else
		cmn_err(CE_CONT, "?root on %s fstype %s\n",
		    rootfs.bo_name, rootfs.bo_fstype);
	return (error);
}

/*
 * Remount root on an SVM mirror root device
 * Only supported on UFS filesystems at present
 */
int
svm_rootconf(void)
{
	int	error;
	extern int ufs_remountroot(struct vfs *vfsp);

	ASSERT(root_is_svm == 1);

	if (strcmp(rootfs.bo_fstype, "ufs") != 0) {
		cmn_err(CE_CONT, "Mounting root on %s with filesystem "
		    "type %s is not supported\n",
		    rootfs.bo_name, rootfs.bo_fstype);
		return (EINVAL);
	}

	(void) strncpy(rootfs.bo_name, svm_bootpath, BO_MAXOBJNAME);

	BMDPRINTF(("svm_rootconf: rootfs %s\n", rootfs.bo_name));

	error = ufs_remountroot(rootvfs);

	if (error) {
		cmn_err(CE_CONT, "Cannot remount root on %s fstype %s\n",
		    rootfs.bo_name, rootfs.bo_fstype);
	} else {
		cmn_err(CE_CONT, "?root remounted on %s fstype %s\n",
		    rootfs.bo_name, rootfs.bo_fstype);
	}
	return (error);
}

/*
 * Under the assumption that our root file system is on a
 * disk partition, get the dev_t of the partition in question.
 *
 * By now, boot has faithfully loaded all our modules into memory, and
 * we've taken over resource management.  Before we go any further, we
 * have to fire up the device drivers and stuff we need to mount the
 * root filesystem.  That's what we do here.  Fingers crossed.
 */
dev_t
getrootdev(void)
{
	dev_t	d;

	d = ddi_pathname_to_dev_t(rootfs.bo_name);
	if ((d == NODEV) && (iscsiboot_prop != NULL)) {
		/* Give it another try with the 'disk' path */
		get_iscsi_bootpath_phy(rootfs.bo_name);
		d = ddi_pathname_to_dev_t(rootfs.bo_name);
	}
	if (d == NODEV)
		cmn_err(CE_CONT, "Cannot assemble drivers for root %s\n",
		    rootfs.bo_name);
	return (d);
}

/*
 * If booted with ASKNAME, prompt on the console for a filesystem
 * name and return it.
 */
void
getfsname(char *askfor, char *name, size_t namelen)
{
	if (boothowto & RB_ASKNAME) {
		printf("%s name: ", askfor);
		console_gets(name, namelen);
	}
}

/*ARGSUSED1*/
static int
preload_module(struct sysparam *sysp, void *p)
{
	static char *wmesg = "forceload of %s failed";
	char *name;

	name = sysp->sys_ptr;
	BMDPRINTF(("preload_module: %s\n", name));
	if (modloadonly(NULL, name) < 0)
		cmn_err(CE_WARN, wmesg, name);
	return (0);
}

/*
 * We want to load all the modules needed to mount the root filesystem,
 * so that when we start the ball rolling in 'getrootdev', every module
 * should already be in memory, just waiting to be init-ed.
 */

int
loadrootmodules(void)
{
	struct vfssw	*vsw;
	char		*this;
	char		*name;
	int		err;
	int		i, proplen;
	extern char	*impl_module_list[];
	extern char	*platform_module_list[];

	/* Make sure that the PROM's devinfo tree has been created */
	ASSERT(ddi_root_node());

	BMDPRINTF(("loadrootmodules: fstype %s\n", rootfs.bo_fstype));
	BMDPRINTF(("loadrootmodules: name %s\n", rootfs.bo_name));
	BMDPRINTF(("loadrootmodules: flags 0x%x\n", rootfs.bo_flags));

	/*
	 * zzz We need to honor what's in rootfs if it's not null.
	 * non-null means use what's there.  This way we can
	 * change rootfs with /etc/system AND with tunetool.
	 */
	if (root_is_svm) {
		/* user replaced rootdev, record obp_bootpath */
		obp_bootpath[0] = '\0';
		(void) getphysdev("root", obp_bootpath, BO_MAXOBJNAME);
		BMDPRINTF(("loadrootmodules: obp_bootpath %s\n", obp_bootpath));
	} else {
		/*
		 * Get the root fstype and root device path from boot.
		 */
		rootfs.bo_fstype[0] = '\0';
		rootfs.bo_name[0] = '\0';
	}

	/*
	 * This lookup will result in modloadonly-ing the root
	 * filesystem module - it gets _init-ed in rootconf()
	 */
	if ((vsw = getfstype("root", rootfs.bo_fstype, BO_MAXFSNAME)) == NULL)
		return (ENXIO);	/* in case we have no file system types */

	(void) strcpy(rootfs.bo_fstype, vsw->vsw_name);

	vfs_unrefvfssw(vsw);

	/*
	 * Load the favored drivers of the implementation.
	 * e.g. 'sbus' and possibly 'zs' (even).
	 *
	 * Called whilst boot is still loaded (because boot does
	 * the i/o for us), and DDI services are unavailable.
	 */
	BMDPRINTF(("loadrootmodules: impl_module_list\n"));
	for (i = 0; (this = impl_module_list[i]) != NULL; i++) {
		if ((err = load_boot_driver(this)) != 0) {
			cmn_err(CE_WARN, "Cannot load drv/%s", this);
			return (err);
		}
	}
	/*
	 * Now load the platform modules (if any)
	 */
	BMDPRINTF(("loadrootmodules: platform_module_list\n"));
	for (i = 0; (this = platform_module_list[i]) != NULL; i++) {
		if ((err = load_boot_platform_modules(this)) != 0) {
			cmn_err(CE_WARN, "Cannot load drv/%s", this);
			return (err);
		}
	}

loop:
	(void) getphysdev("root", rootfs.bo_name, BO_MAXOBJNAME);
	/*
	 * Given a physical pathname, load the correct set of driver
	 * modules into memory, including all possible parents.
	 *
	 * NB: The code sets the variable 'name' for error reporting.
	 */
	err = 0;
	BMDPRINTF(("loadrootmodules: rootfs %s\n", rootfs.bo_name));
	if (root_is_svm == 0) {
		BMDPRINTF(("loadrootmodules: rootfs %s\n", rootfs.bo_name));
		name = rootfs.bo_name;
		err = load_bootpath_drivers(rootfs.bo_name);
	}

	/*
	 * Load driver modules in obp_bootpath, this is always
	 * required for mountroot to succeed. obp_bootpath is
	 * is set if rootdev is set via /etc/system, which is
	 * the case if booting of a SVM/VxVM mirror.
	 */
	if ((err == 0) && obp_bootpath[0] != '\0') {
		BMDPRINTF(("loadrootmodules: obp_bootpath %s\n", obp_bootpath));
		name = obp_bootpath;
		err = load_bootpath_drivers(obp_bootpath);
	}

	if (err != 0) {
		cmn_err(CE_CONT, "Cannot load drivers for %s\n", name);
		goto out;
	}

	/*
	 * Check to see if the booter performed DHCP configuration
	 * ("bootp-response" boot property exists). If so, then before
	 * bootops disappears we need to save the value of this property
	 * such that the userland dhcpagent can adopt the DHCP management
	 * of our primary network interface.
	 */
	proplen = BOP_GETPROPLEN(bootops, "bootp-response");
	if (proplen > 0) {
		dhcack = kmem_zalloc(proplen, KM_SLEEP);
		if (BOP_GETPROP(bootops, "bootp-response", dhcack) == -1) {
			cmn_err(CE_WARN, "BOP_GETPROP of  "
			    "\"bootp-response\" failed\n");
			kmem_free(dhcack, dhcacklen);
			dhcack = NULL;
			goto out;
		}
		dhcacklen = proplen;

		/*
		 * Fetch the "netdev-path" boot property (if it exists), and
		 * stash it for later use by sysinfo(SI_DHCP_CACHE, ...).
		 */
		proplen = BOP_GETPROPLEN(bootops, "netdev-path");
		if (proplen > 0) {
			netdev_path = kmem_zalloc(proplen, KM_SLEEP);
			if (BOP_GETPROP(bootops, "netdev-path",
			    (uchar_t *)netdev_path) == -1) {
				cmn_err(CE_WARN, "BOP_GETPROP of  "
				    "\"netdev-path\" failed\n");
				kmem_free(netdev_path, proplen);
				goto out;
			}
		}
	}

	/*
	 * Preload (load-only, no init) all modules which
	 * were added to the /etc/system file with the
	 * FORCELOAD keyword.
	 */
	BMDPRINTF(("loadrootmodules: preload_module\n"));
	(void) mod_sysctl_type(MOD_FORCELOAD, preload_module, NULL);

	/*
	 * If we booted otw then load in the plumbing
	 * routine now while we still can. If we didn't
	 * boot otw then we will load strplumb in main().
	 *
	 * NFS is actually a set of modules, the core routines,
	 * a diskless helper module, rpcmod, and the tli interface.  Load
	 * them now while we still can.
	 *
	 * Because we glomb all versions of nfs into a single module
	 * we check based on the initial string "nfs".
	 *
	 * XXX: A better test for this is to see if device_type
	 * XXX: from the PROM is "network".
	 */

	if (strncmp(rootfs.bo_fstype, "nfs", 3) == 0) {
		++netboot;

		/*
		 * Preload (load-only, no init) the dacf module. We cannot
		 * init the module because one of its requisite modules is
		 * dld whose _init function will call taskq_create(), which
		 * will panic the system at this point.
		 */
		if ((err = modloadonly("dacf", "net_dacf")) < 0)  {
			cmn_err(CE_CONT, "Cannot load dacf/net_dacf\n");
			goto out;
		}
		if ((err = modload("misc", "tlimod")) < 0)  {
			cmn_err(CE_CONT, "Cannot load misc/tlimod\n");
			goto out;
		}
		if ((err = modload("strmod", "rpcmod")) < 0)  {
			cmn_err(CE_CONT, "Cannot load strmod/rpcmod\n");
			goto out;
		}
		if ((err = modload("misc", "nfs_dlboot")) < 0)  {
			cmn_err(CE_CONT, "Cannot load misc/nfs_dlboot\n");
			goto out;
		}
		if ((err = modload("mac", "mac_ether")) < 0)  {
			cmn_err(CE_CONT, "Cannot load mac/mac_ether\n");
			goto out;
		}
		if ((err = modload("misc", "strplumb")) < 0)  {
			cmn_err(CE_CONT, "Cannot load misc/strplumb\n");
			goto out;
		}
		if ((err = strplumb_load()) < 0) {
			goto out;
		}
	}
	if (netboot_over_iscsi() == B_TRUE) {
		/* iscsi boot */
		if ((err = modloadonly("dacf", "net_dacf")) < 0) {
			cmn_err(CE_CONT, "Cannot load dacf/net_dacf\n");
			goto out;
		}
		if ((err = modload("misc", "tlimod")) < 0) {
			cmn_err(CE_CONT, "Cannot load misc/tlimod\n");
			goto out;
		}
		if ((err = modload("mac", "mac_ether")) < 0) {
			cmn_err(CE_CONT, "Cannot load mac/mac_ether\n");
			goto out;
		}
		if ((err = modloadonly("drv", "iscsi")) < 0) {
			cmn_err(CE_CONT, "Cannot load drv/iscsi\n");
			goto out;
		}
		if ((err = modloadonly("drv", "ssd")) < 0) {
			cmn_err(CE_CONT, "Cannot load drv/ssd\n");
			goto out;
		}
		if ((err = modloadonly("drv", "sd")) < 0) {
			cmn_err(CE_CONT, "Cannot load drv/sd\n");
			goto out;
		}
		if ((err = modload("misc", "strplumb")) < 0) {
			cmn_err(CE_CONT, "Cannot load misc/strplumb\n");
			goto out;
		}
		if ((err = strplumb_load()) < 0) {
			goto out;
		}
	}
	/*
	 * Preload modules needed for booting as a cluster.
	 */
	err = clboot_loadrootmodules();

out:
	if (err != 0 && (boothowto & RB_ASKNAME))
		goto loop;

	return (err);
}

static int
get_bootpath_prop(char *bootpath)
{
	if (root_is_ramdisk) {
		if (BOP_GETPROP(bootops, "bootarchive", bootpath) == -1)
			return (-1);
		(void) strlcat(bootpath, ":a", BO_MAXOBJNAME);
	} else {
		/*
		 * Look for the 1275 compliant name 'bootpath' first,
		 * but make certain it has a non-NULL value as well.
		 */
		if ((BOP_GETPROP(bootops, "bootpath", bootpath) == -1) ||
		    strlen(bootpath) == 0) {
			if (BOP_GETPROP(bootops,
			    "boot-path", bootpath) == -1)
				return (-1);
		}
		if (memcmp(bootpath, BP_ISCSI_DISK,
		    strlen(BP_ISCSI_DISK)) == 0) {
			/* iscsi boot */
			get_iscsi_bootpath_vhci(bootpath);
		}
	}
	return (0);
}

static int
get_fstype_prop(char *fstype)
{
	char *prop = (root_is_ramdisk) ? "archive-fstype" : "fstype";

	return (BOP_GETPROP(bootops, prop, fstype));
}

/*
 * Get the name of the root or swap filesystem type, and return
 * the corresponding entry in the vfs switch.
 *
 * If we're not asking the user, and we're trying to find the
 * root filesystem type, we ask boot for the filesystem
 * type that it came from and use that.  Similarly, if we're
 * trying to find the swap filesystem, we try and derive it from
 * the root filesystem type.
 *
 * If we are booting via NFS we currently have these options:
 *	nfs -	dynamically choose NFS V2. V3, or V4 (default)
 *	nfs2 -	force NFS V2
 *	nfs3 -	force NFS V3
 *	nfs4 -	force NFS V4
 * Because we need to maintain backward compatibility with the naming
 * convention that the NFS V2 filesystem name is "nfs" (see vfs_conf.c)
 * we need to map "nfs" => "nfsdyn" and "nfs2" => "nfs".  The dynamic
 * nfs module will map the type back to either "nfs", "nfs3", or "nfs4".
 * This is only for root filesystems, all other uses will expect
 * that "nfs" == NFS V2.
 *
 * If the filesystem isn't already loaded, vfs_getvfssw() will load
 * it for us, but if (at the time we call it) modrootloaded is
 * still not set, it won't run the filesystems _init routine (and
 * implicitly it won't run the filesystems vsw_init() entry either).
 * We do that explicitly in rootconf().
 */
static struct vfssw *
getfstype(char *askfor, char *fsname, size_t fsnamelen)
{
	struct vfssw *vsw;
	static char defaultfs[BO_MAXFSNAME];
	int root = 0;

	if (strcmp(askfor, "root") == 0) {
		(void) get_fstype_prop(defaultfs);
		root++;
	} else {
		(void) strcpy(defaultfs, "swapfs");
	}

	if (boothowto & RB_ASKNAME) {
		for (*fsname = '\0'; *fsname == '\0'; *fsname = '\0') {
			printf("%s filesystem type [%s]: ", askfor, defaultfs);
			console_gets(fsname, fsnamelen);
			if (*fsname == '\0')
				(void) strcpy(fsname, defaultfs);
			if (root) {
				if (strcmp(fsname, "nfs2") == 0)
					(void) strcpy(fsname, "nfs");
				else if (strcmp(fsname, "nfs") == 0)
					(void) strcpy(fsname, "nfsdyn");
			}
			if ((vsw = vfs_getvfssw(fsname)) != NULL)
				return (vsw);
			printf("Unknown filesystem type '%s'\n", fsname);
		}
	} else if (*fsname == '\0') {
		fsname = defaultfs;
	}
	if (*fsname == '\0') {
		return (NULL);
	}

	if (root) {
		if (strcmp(fsname, "nfs2") == 0)
			(void) strcpy(fsname, "nfs");
		else if (strcmp(fsname, "nfs") == 0)
			(void) strcpy(fsname, "nfsdyn");
	}

	return (vfs_getvfssw(fsname));
}


/*
 * Get a physical device name, and maybe load and attach
 * the driver.
 *
 * XXX	Need better checking of whether or not a device
 *	actually exists if the user typed in a pathname.
 *
 * XXX	Are we sure we want to expose users to this sort
 *	of physical namespace gobbledygook (now there's
 *	a word to conjure with..)
 *
 * XXX	Note that on an OBP machine, we can easily ask the
 *	prom and pretty-print some plausible set of bootable
 *	devices.  We can also user the prom to verify any
 *	such device.  Later tim.. later.
 */
static int
getphysdev(char *askfor, char *name, size_t namelen)
{
	static char fmt[] = "Enter physical name of %s device\n[%s]: ";
	dev_t dev;
	static char defaultpath[BO_MAXOBJNAME];

	/*
	 * Establish 'default' values - we get the root device from
	 * boot, and we infer the swap device is the same but with
	 * a 'b' on the end instead of an 'a'.  A first stab at
	 * ease-of-use ..
	 */
	if (strcmp(askfor, "root") == 0) {
		if (get_bootpath_prop(defaultpath) == -1)
			boothowto |= RB_ASKNAME | RB_VERBOSE;
	} else {
		(void) strcpy(defaultpath, rootfs.bo_name);
		defaultpath[strlen(defaultpath) - 1] = 'b';
	}

retry:
	if (boothowto & RB_ASKNAME) {
		printf(fmt, askfor, defaultpath);
		console_gets(name, namelen);
	}
	if (*name == '\0')
		(void) strcpy(name, defaultpath);

	if (strcmp(askfor, "swap") == 0)   {

		/*
		 * Try to load and install the swap device driver.
		 */
		dev = ddi_pathname_to_dev_t(name);

		if (dev == (dev_t)-1)  {
			printf("Not a supported device for swap.\n");
			boothowto |= RB_ASKNAME | RB_VERBOSE;
			goto retry;
		}

		/*
		 * Ensure that we're not trying to swap on the floppy.
		 */
		if (strncmp(ddi_major_to_name(getmajor(dev)), "fd", 2) == 0) {
			printf("Too dangerous to swap on the floppy\n");
			if (boothowto & RB_ASKNAME)
				goto retry;
			return (-1);
		}
	}

	return (0);
}


/*
 * Load a driver needed to boot.
 */
static int
load_boot_driver(char *drv)
{
	char		*drvname;
	major_t		major;
#ifdef	sparc
	struct devnames *dnp;
	ddi_prop_t	*propp;
	char		*module;
	char		*dir, *mf;
	int		plen;
	int		mlen;
#endif	/* sparc */

	if ((major = ddi_name_to_major(drv)) == DDI_MAJOR_T_NONE) {
		cmn_err(CE_CONT, "%s: no major number\n", drv);
		return (-1);
	}
	/*
	 * resolve aliases
	 */
	drvname = ddi_major_to_name(major);

#ifdef	DEBUG
	if (strcmp(drv, drvname) == 0) {
		BMDPRINTF(("load_boot_driver: %s\n", drv));
	} else {
		BMDPRINTF(("load_boot_driver: %s -> %s\n", drv, drvname));
	}
#endif	/* DEBUG */

	if (modloadonly("drv", drvname) == -1) {
		cmn_err(CE_CONT, "%s: cannot load driver\n", drvname);
		return (-1);
	}

#ifdef	sparc
	/*
	 * NOTE: this can be removed when newboot-sparc is delivered.
	 *
	 * Check to see if the driver had a 'ddi-forceload' global driver.conf
	 * property to identify additional modules that need to be loaded.
	 * The driver still needs to use ddi_modopen() to open these modules,
	 * but the 'ddi-forceload' property allows the modules to be loaded
	 * into memory prior to lights-out, so that driver ddi_modopen()
	 * calls during lights-out (when mounting root) will work correctly.
	 * Use of 'ddi-forceload' is only required for drivers involved in
	 * getting root mounted.
	 */
	dnp = &devnamesp[major];
	if (dnp->dn_global_prop_ptr && dnp->dn_global_prop_ptr->prop_list &&
	    ((propp = i_ddi_prop_search(DDI_DEV_T_ANY,
	    "ddi-forceload", DDI_PROP_TYPE_STRING,
	    &dnp->dn_global_prop_ptr->prop_list)) != NULL)) {

		module = (char *)propp->prop_val;
		plen = propp->prop_len;
		while (plen > 0) {
			mlen = strlen(module);
			mf = strrchr(module, '/');
			if (mf) {
				dir = module;
				*mf++ = '\0';		/* '/' -> '\0' */
			} else {
				dir = "misc";
				mf = module;
			}
			if (modloadonly(dir, mf) == -1)
				cmn_err(CE_CONT,
				    "misc/%s: can't load module\n", mf);
			if (mf != module)
				*(mf - 1) = '/';	/* '\0' -> '/' */

			module += mlen + 1;
			plen -= mlen + 1;
		}
	}
#endif	/* sparc */

	return (0);
}


/*
 * For a given instance, load that driver and its parents
 */
static int
load_parent_drivers(dev_info_t *dip, char *path)
{
	int	rval = 0;
	major_t	major = DDI_MAJOR_T_NONE;
	char	*drv;
	char	*p;

	while (dip) {
		/* check for path-oriented alias */
		if (path)
			major = ddi_name_to_major(path);
		else
			major = DDI_MAJOR_T_NONE;

		if (major != DDI_MAJOR_T_NONE)
			drv = ddi_major_to_name(major);
		else
			drv = ddi_binding_name(dip);

		if (load_boot_driver(drv) != 0)
			rval = -1;

		dip = ddi_get_parent(dip);
		if (path) {
			p = strrchr(path, '/');
			if (p)
				*p = 0;
		}
	}

	return (rval);
}


/*
 * For a given path to a boot device,
 * load that driver and all its parents.
 */
static int
load_bootpath_drivers(char *bootpath)
{
	dev_info_t	*dip;
	char		*pathcopy;
	int		pathcopy_len;
	int		rval;
	char		*p;
	int		proplen;
	char		iscsi_network_path[BO_MAXOBJNAME];

	if (bootpath == NULL || *bootpath == 0)
		return (-1);

	BMDPRINTF(("load_bootpath_drivers: %s\n", bootpath));
#ifdef _OBP
	if (netboot_over_iscsi()) {
		/* iscsi boot */
		if (root_is_ramdisk) {
			if (modloadonly("drv", "ramdisk") < 0)
				return (-1);
		}
		proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_NETWORK_BOOTPATH);
		if (proplen > 0) {
			if (BOP_GETPROP(bootops, BP_ISCSI_NETWORK_BOOTPATH,
			    iscsi_network_path) > 0) {
				p = strchr(iscsi_network_path, ':');
				if (p != NULL) {
					*p = '\0';
				}
				pathcopy = i_ddi_strdup(iscsi_network_path,
				    KM_SLEEP);
				pathcopy_len = strlen(pathcopy) + 1;
			} else {
				return (-1);
			}
		} else {
			return (-1);
		}
	} else {
#endif
		pathcopy = i_ddi_strdup(bootpath, KM_SLEEP);
		pathcopy_len = strlen(pathcopy) + 1;
#ifdef _OBP
	}
#endif
	dip = path_to_devinfo(pathcopy);

#if defined(__i386) || defined(__amd64)
	/*
	 * i386 does not provide stub nodes for all boot devices,
	 * but we should be able to find the node for the parent,
	 * and the leaf of the boot path should be the driver name,
	 * which we go ahead and load here.
	 */
	if (dip == NULL) {
		char	*leaf;

		/*
		 * Find last slash to build the full path to the
		 * parent of the leaf boot device
		 */
		p = strrchr(pathcopy, '/');
		*p++ = 0;

		/*
		 * Now isolate the driver name of the leaf device
		 */
		leaf = p;
		p = strchr(leaf, '@');
		*p = 0;

		BMDPRINTF(("load_bootpath_drivers: parent=%s leaf=%s\n",
		    bootpath, leaf));

		dip = path_to_devinfo(pathcopy);
		if (leaf) {
			rval = load_boot_driver(leaf, NULL);
			if (rval == -1) {
				kmem_free(pathcopy, pathcopy_len);
				return (NULL);
			}
		}
	}
#endif

	if (dip == NULL) {
		cmn_err(CE_WARN, "can't bind driver for boot path <%s>",
		    bootpath);
		kmem_free(pathcopy, pathcopy_len);
		return (NULL);
	}

	/*
	 * Load IP over IB driver when netbooting over IB.
	 * As per IB 1275 binding, IP over IB is represented as
	 * service on the top of the HCA node. So, there is no
	 * PROM node and generic framework cannot pre-load
	 * IP over IB driver based on the bootpath. The following
	 * code preloads IP over IB driver when doing netboot over
	 * InfiniBand.
	 */
	if (netboot_over_ib(bootpath) &&
	    modloadonly("drv", "ibp") == -1) {
		cmn_err(CE_CONT, "ibp: cannot load platform driver\n");
		kmem_free(pathcopy, pathcopy_len);
		return (NULL);
	}

	/*
	 * The PROM node for hubs have incomplete compatible
	 * properties and therefore do not bind to the hubd driver.
	 * As a result load_bootpath_drivers() loads the usb_mid driver
	 * for hub nodes rather than the hubd driver. This causes
	 * mountroot failures when booting off USB storage. To prevent
	 * this, if we are booting via USB hubs, we preload the hubd driver.
	 */
	if (strstr(bootpath, "/hub@") && modloadonly("drv", "hubd") == -1) {
		cmn_err(CE_WARN, "bootpath contains a USB hub, "
		    "but cannot load hubd driver");
	}

	/* get rid of minor node at end of copy (if not already done above) */
	p = strrchr(pathcopy, '/');
	if (p) {
		p = strchr(p, ':');
		if (p)
			*p = 0;
	}

	rval = load_parent_drivers(dip, pathcopy);
	kmem_free(pathcopy, pathcopy_len);
	return (rval);
}




/*
 * Load drivers required for a platform
 * Since all hardware nodes should be available in the device
 * tree, walk the per-driver list and load the parents of
 * each node found. If not a hardware node, try to load it.
 * Pseudo nexus is already loaded.
 */
static int
load_boot_platform_modules(char *drv)
{
	major_t	major;
	dev_info_t *dip;
	char	*drvname;
	int	rval = 0;

	if ((major = ddi_name_to_major(drv)) == DDI_MAJOR_T_NONE) {
		cmn_err(CE_CONT, "%s: no major number\n", drv);
		return (-1);
	}

	/*
	 * resolve aliases
	 */
	drvname = ddi_major_to_name(major);
	if ((major = ddi_name_to_major(drvname)) == DDI_MAJOR_T_NONE)
		return (-1);

#ifdef	DEBUG
	if (strcmp(drv, drvname) == 0) {
		BMDPRINTF(("load_boot_platform_modules: %s\n", drv));
	} else {
		BMDPRINTF(("load_boot_platform_modules: %s -> %s\n",
		    drv, drvname));
	}
#endif	/* DEBUG */

	dip = devnamesp[major].dn_head;
	if (dip == NULL) {
		/* pseudo node, not-enumerated, needs to be loaded */
		if (modloadonly("drv", drvname) == -1) {
			cmn_err(CE_CONT, "%s: cannot load platform driver\n",
			    drvname);
			rval = -1;
		}
	} else {
		while (dip) {
			if (load_parent_drivers(dip, NULL) != 0)
				rval = -1;
			dip = ddi_get_next(dip);
		}
	}

	return (rval);
}


/*
 * i_find_node: Internal routine used by path_to_devinfo
 * to locate a given nodeid in the device tree.
 */
struct i_path_findnode {
	pnode_t nodeid;
	dev_info_t *dip;
};

static int
i_path_find_node(dev_info_t *dev, void *arg)
{
	struct i_path_findnode *f = (struct i_path_findnode *)arg;


	if (ddi_get_nodeid(dev) == (int)f->nodeid) {
		f->dip = dev;
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * Return the devinfo node to a boot device
 */
static dev_info_t *
path_to_devinfo(char *path)
{
	struct i_path_findnode fn;
	extern dev_info_t *top_devinfo;

	/*
	 * Get the nodeid of the given pathname, if such a mapping exists.
	 */
	fn.dip = NULL;
	fn.nodeid = prom_finddevice(path);
	if (fn.nodeid != OBP_BADNODE) {
		/*
		 * Find the nodeid in our copy of the device tree and return
		 * whatever name we used to bind this node to a driver.
		 */
		ddi_walk_devs(top_devinfo, i_path_find_node, (void *)(&fn));
	}

#ifdef	DEBUG
	/*
	 * If we're bound to something other than the nodename,
	 * note that in the message buffer and system log.
	 */
	if (fn.dip) {
		char *p, *q;

		p = ddi_binding_name(fn.dip);
		q = ddi_node_name(fn.dip);
		if (p && q && (strcmp(p, q) != 0)) {
			BMDPRINTF(("path_to_devinfo: %s bound to %s\n",
			    path, p));
		}
	}
#endif	/* DEBUG */

	return (fn.dip);
}

/*
 * This routine returns B_TRUE if the bootpath corresponds to
 * IP over IB driver.
 *
 * The format of the bootpath for the IP over IB looks like
 * /pci@1f,700000/pci@1/ib@0:port=1,pkey=8001,protocol=ip
 *
 * The minor node portion "port=1,pkey=8001,protocol=ip" represents
 * IP over IB driver.
 */
static boolean_t
netboot_over_ib(char *bootpath)
{

	char		*temp;
	boolean_t	ret = B_FALSE;
	pnode_t		node = prom_finddevice(bootpath);
	int		len;
	char		devicetype[OBP_MAXDRVNAME];

	/* Is this IB node ? */
	if (node == OBP_BADNODE || node == OBP_NONODE) {
		return (B_FALSE);
	}
	len = prom_getproplen(node, OBP_DEVICETYPE);
	if (len <= 1 || len >= OBP_MAXDRVNAME)
		return (B_FALSE);

	(void) prom_getprop(node, OBP_DEVICETYPE, (caddr_t)devicetype);

	if (strncmp("ib", devicetype, 2) == 0) {
		/* Check for proper IP over IB string */
		if ((temp = strstr(bootpath, ":port=")) != NULL) {
			if ((temp = strstr(temp, ",pkey=")) != NULL)
				if ((temp = strstr(temp,
				    ",protocol=ip")) != NULL) {
					ret = B_TRUE;
				}
		}
	}
	return (ret);
}

static boolean_t
netboot_over_iscsi(void)
{
	int proplen;
	boolean_t	ret = B_FALSE;
	char	bootpath[OBP_MAXPATHLEN];

	proplen = BOP_GETPROPLEN(bootops, BP_BOOTPATH);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_BOOTPATH, bootpath) > 0) {
			if (memcmp(bootpath, BP_ISCSI_DISK,
			    strlen(BP_ISCSI_DISK)) == 0) {
				ret = B_TRUE;
			}
		}
	}
	return (ret);
}
