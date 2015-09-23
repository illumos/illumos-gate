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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/callb.h>
#include <sys/fs/ufs_inode.h>
#include <vm/anon.h>
#include <sys/fs/swapnode.h>	/* for swapfs_minfree */
#include <sys/kmem.h>
#include <sys/cpr.h>
#include <sys/conf.h>
#include <sys/machclock.h>

/*
 * CPR miscellaneous support routines
 */
#define	cpr_open(path, mode,  vpp)	(vn_open(path, UIO_SYSSPACE, \
		mode, 0600, vpp, CRCREAT, 0))
#define	cpr_rdwr(rw, vp, basep, cnt)	(vn_rdwr(rw, vp,  (caddr_t)(basep), \
		cnt, 0LL, UIO_SYSSPACE, 0, (rlim64_t)MAXOFF_T, CRED(), \
		(ssize_t *)NULL))

extern void clkset(time_t);
extern cpu_t *i_cpr_bootcpu(void);
extern caddr_t i_cpr_map_setup(void);
extern void i_cpr_free_memory_resources(void);

extern kmutex_t cpr_slock;
extern size_t cpr_buf_size;
extern char *cpr_buf;
extern size_t cpr_pagedata_size;
extern char *cpr_pagedata;
extern int cpr_bufs_allocated;
extern int cpr_bitmaps_allocated;

#if defined(__sparc)
static struct cprconfig cprconfig;
static int cprconfig_loaded = 0;
static int cpr_statefile_ok(vnode_t *, int);
static int cpr_p_online(cpu_t *, int);
static void cpr_save_mp_state(void);
#endif

int cpr_is_ufs(struct vfs *);
int cpr_is_zfs(struct vfs *);

char cpr_default_path[] = CPR_DEFAULT;

#define	COMPRESS_PERCENT 40	/* approx compression ratio in percent */
#define	SIZE_RATE	115	/* increase size by 15% */
#define	INTEGRAL	100	/* for integer math */


/*
 * cmn_err() followed by a 1/4 second delay; this gives the
 * logging service a chance to flush messages and helps avoid
 * intermixing output from prom_printf().
 */
/*PRINTFLIKE2*/
void
cpr_err(int ce, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vcmn_err(ce, fmt, adx);
	va_end(adx);
	drv_usecwait(MICROSEC >> 2);
}


int
cpr_init(int fcn)
{
	/*
	 * Allow only one suspend/resume process.
	 */
	if (mutex_tryenter(&cpr_slock) == 0)
		return (EBUSY);

	CPR->c_flags = 0;
	CPR->c_substate = 0;
	CPR->c_cprboot_magic = 0;
	CPR->c_alloc_cnt = 0;

	CPR->c_fcn = fcn;
	if (fcn == AD_CPR_REUSABLE)
		CPR->c_flags |= C_REUSABLE;
	else
		CPR->c_flags |= C_SUSPENDING;
	if (fcn == AD_SUSPEND_TO_RAM || fcn == DEV_SUSPEND_TO_RAM) {
		return (0);
	}
#if defined(__sparc)
	if (fcn != AD_CPR_NOCOMPRESS && fcn != AD_CPR_TESTNOZ)
		CPR->c_flags |= C_COMPRESSING;
	/*
	 * reserve CPR_MAXCONTIG virtual pages for cpr_dump()
	 */
	CPR->c_mapping_area = i_cpr_map_setup();
	if (CPR->c_mapping_area == 0) {		/* no space in kernelmap */
		cpr_err(CE_CONT, "Unable to alloc from kernelmap.\n");
		mutex_exit(&cpr_slock);
		return (EAGAIN);
	}
	if (cpr_debug & CPR_DEBUG3)
		cpr_err(CE_CONT, "Reserved virtual range from 0x%p for writing "
		    "kas\n", (void *)CPR->c_mapping_area);
#endif

	return (0);
}

/*
 * This routine releases any resources used during the checkpoint.
 */
void
cpr_done(void)
{
	cpr_stat_cleanup();
	i_cpr_bitmap_cleanup();

	/*
	 * Free pages used by cpr buffers.
	 */
	if (cpr_buf) {
		kmem_free(cpr_buf, cpr_buf_size);
		cpr_buf = NULL;
	}
	if (cpr_pagedata) {
		kmem_free(cpr_pagedata, cpr_pagedata_size);
		cpr_pagedata = NULL;
	}

	i_cpr_free_memory_resources();
	mutex_exit(&cpr_slock);
	cpr_err(CE_CONT, "System has been resumed.\n");
}


#if defined(__sparc)
/*
 * reads config data into cprconfig
 */
static int
cpr_get_config(void)
{
	static char config_path[] = CPR_CONFIG;
	struct cprconfig *cf = &cprconfig;
	struct vnode *vp;
	char *fmt;
	int err;

	if (cprconfig_loaded)
		return (0);

	fmt = "cannot %s config file \"%s\", error %d\n";
	if (err = vn_open(config_path, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0)) {
		cpr_err(CE_CONT, fmt, "open", config_path, err);
		return (err);
	}

	err = cpr_rdwr(UIO_READ, vp, cf, sizeof (*cf));
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	if (err) {
		cpr_err(CE_CONT, fmt, "read", config_path, err);
		return (err);
	}

	if (cf->cf_magic == CPR_CONFIG_MAGIC)
		cprconfig_loaded = 1;
	else {
		cpr_err(CE_CONT, "invalid config file \"%s\", "
		    "rerun pmconfig(1M)\n", config_path);
		err = EINVAL;
	}

	return (err);
}


/*
 * concat fs and path fields of the cprconfig structure;
 * returns pointer to the base of static data
 */
static char *
cpr_cprconfig_to_path(void)
{
	static char full_path[MAXNAMELEN];
	struct cprconfig *cf = &cprconfig;
	char *ptr;

	/*
	 * build /fs/path without extra '/'
	 */
	(void) strcpy(full_path, cf->cf_fs);
	if (strcmp(cf->cf_fs, "/"))
		(void) strcat(full_path, "/");
	ptr = cf->cf_path;
	if (*ptr == '/')
		ptr++;
	(void) strcat(full_path, ptr);
	return (full_path);
}


/*
 * Verify that the information in the configuration file regarding the
 * location for the statefile is still valid, depending on cf_type.
 * for CFT_UFS, cf_fs must still be a mounted filesystem, it must be
 *	mounted on the same device as when pmconfig was last run,
 *	and the translation of that device to a node in the prom's
 *	device tree must be the same as when pmconfig was last run.
 * for CFT_SPEC and CFT_ZVOL, cf_path must be the path to a block
 *      special file, it must have no file system mounted on it,
 *	and the translation of that device to a node in the prom's
 *	device tree must be the same as when pmconfig was last run.
 */
static int
cpr_verify_statefile_path(void)
{
	struct cprconfig *cf = &cprconfig;
	static const char long_name[] = "Statefile pathname is too long.\n";
	static const char lookup_fmt[] = "Lookup failed for "
	    "cpr statefile device %s.\n";
	static const char path_chg_fmt[] = "Device path for statefile "
	    "has changed from %s to %s.\t%s\n";
	static const char rerun[] = "Please rerun pmconfig(1m).";
	struct vfs *vfsp = NULL, *vfsp_save = rootvfs;
	ufsvfs_t *ufsvfsp = (ufsvfs_t *)rootvfs->vfs_data;
	ufsvfs_t *ufsvfsp_save = ufsvfsp;
	int error;
	struct vnode *vp;
	char *slash, *tail, *longest;
	char *errstr;
	int found = 0;
	union {
		char un_devpath[OBP_MAXPATHLEN];
		char un_sfpath[MAXNAMELEN];
	} un;
#define	devpath	un.un_devpath
#define	sfpath	un.un_sfpath

	ASSERT(cprconfig_loaded);
	/*
	 * We need not worry about locking or the timing of releasing
	 * the vnode, since we are single-threaded now.
	 */

	switch (cf->cf_type) {
	case CFT_SPEC:
		error = i_devname_to_promname(cf->cf_devfs, devpath,
		    OBP_MAXPATHLEN);
		if (error || strcmp(devpath, cf->cf_dev_prom)) {
			cpr_err(CE_CONT, path_chg_fmt,
			    cf->cf_dev_prom, devpath, rerun);
			return (error);
		}
		/*FALLTHROUGH*/
	case CFT_ZVOL:
		if (strlen(cf->cf_path) > sizeof (sfpath)) {
			cpr_err(CE_CONT, long_name);
			return (ENAMETOOLONG);
		}
		if ((error = lookupname(cf->cf_devfs,
		    UIO_SYSSPACE, FOLLOW, NULLVPP, &vp)) != 0) {
			cpr_err(CE_CONT, lookup_fmt, cf->cf_devfs);
			return (error);
		}
		if (vp->v_type != VBLK)
			errstr = "statefile must be a block device";
		else if (vfs_devismounted(vp->v_rdev))
			errstr = "statefile device must not "
			    "have a file system mounted on it";
		else if (IS_SWAPVP(vp))
			errstr = "statefile device must not "
			    "be configured as swap file";
		else
			errstr = NULL;

		VN_RELE(vp);
		if (errstr) {
			cpr_err(CE_CONT, "%s.\n", errstr);
			return (ENOTSUP);
		}

		return (error);
	case CFT_UFS:
		break;		/* don't indent all the original code */
	default:
		cpr_err(CE_PANIC, "invalid cf_type");
	}

	/*
	 * The original code for UFS statefile
	 */
	if (strlen(cf->cf_fs) + strlen(cf->cf_path) + 2 > sizeof (sfpath)) {
		cpr_err(CE_CONT, long_name);
		return (ENAMETOOLONG);
	}

	bzero(sfpath, sizeof (sfpath));
	(void) strcpy(sfpath, cpr_cprconfig_to_path());

	if (*sfpath != '/') {
		cpr_err(CE_CONT, "Statefile pathname %s "
		    "must begin with a /\n", sfpath);
		return (EINVAL);
	}

	/*
	 * Find the longest prefix of the statefile pathname which
	 * is the mountpoint of a filesystem.  This string must
	 * match the cf_fs field we read from the config file.  Other-
	 * wise the user has changed things without running pmconfig.
	 */
	tail = longest = sfpath + 1;	/* pt beyond the leading "/" */
	while ((slash = strchr(tail, '/')) != NULL) {
		*slash = '\0';	  /* temporarily terminate the string */
		if ((error = lookupname(sfpath,
		    UIO_SYSSPACE, FOLLOW, NULLVPP, &vp)) != 0) {
			*slash = '/';
			cpr_err(CE_CONT, "A directory in the "
			    "statefile path %s was not found.\n", sfpath);
			VN_RELE(vp);

			return (error);
		}

		vfs_list_read_lock();
		vfsp = rootvfs;
		do {
			ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
			if (ufsvfsp != NULL && ufsvfsp->vfs_root == vp) {
				found = 1;
				break;
			}
			vfsp = vfsp->vfs_next;
		} while (vfsp != rootvfs);
		vfs_list_unlock();

		/*
		 * If we have found a filesystem mounted on the current
		 * path prefix, remember the end of the string in
		 * "longest".  If it happens to be the the exact fs
		 * saved in the configuration file, save the current
		 * ufsvfsp so we can make additional checks further down.
		 */
		if (found) {
			longest = slash;
			if (strcmp(cf->cf_fs, sfpath) == 0) {
				ufsvfsp_save = ufsvfsp;
				vfsp_save = vfsp;
			}
			found = 0;
		}

		VN_RELE(vp);
		*slash = '/';
		tail = slash + 1;
	}
	*longest = '\0';
	if (cpr_is_ufs(vfsp_save) == 0 || strcmp(cf->cf_fs, sfpath)) {
		cpr_err(CE_CONT, "Filesystem containing "
		    "the statefile when pmconfig was run (%s) has "
		    "changed to %s. %s\n", cf->cf_fs, sfpath, rerun);
		return (EINVAL);
	}

	if ((error = lookupname(cf->cf_devfs,
	    UIO_SYSSPACE, FOLLOW, NULLVPP, &vp)) != 0) {
		cpr_err(CE_CONT, lookup_fmt, cf->cf_devfs);
		return (error);
	}

	if (ufsvfsp_save->vfs_devvp->v_rdev != vp->v_rdev) {
		cpr_err(CE_CONT, "Filesystem containing "
		    "statefile no longer mounted on device %s. "
		    "See power.conf(4).", cf->cf_devfs);
		VN_RELE(vp);
		return (ENXIO);
	}
	VN_RELE(vp);

	error = i_devname_to_promname(cf->cf_devfs, devpath, OBP_MAXPATHLEN);
	if (error || strcmp(devpath, cf->cf_dev_prom)) {
		cpr_err(CE_CONT, path_chg_fmt,
		    cf->cf_dev_prom, devpath, rerun);
		return (error);
	}

	return (0);
}

/*
 * Make sure that the statefile can be used as a block special statefile
 * (meaning that is exists and has nothing mounted on it)
 * Returns errno if not a valid statefile.
 */
int
cpr_check_spec_statefile(void)
{
	int err;

	if (err = cpr_get_config())
		return (err);
	ASSERT(cprconfig.cf_type == CFT_SPEC ||
	    cprconfig.cf_type == CFT_ZVOL);

	if (cprconfig.cf_devfs == NULL)
		return (ENXIO);

	return (cpr_verify_statefile_path());

}

int
cpr_alloc_statefile(int alloc_retry)
{
	register int rc = 0;
	char *str;

	/*
	 * Statefile size validation. If checkpoint the first time, disk blocks
	 * allocation will be done; otherwise, just do file size check.
	 * if statefile allocation is being retried, C_VP will be inited
	 */
	if (alloc_retry) {
		str = "\n-->Retrying statefile allocation...";
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG7))
			prom_printf(str);
		if (C_VP->v_type != VBLK)
			(void) VOP_DUMPCTL(C_VP, DUMP_FREE, NULL, NULL);
	} else {
		/*
		 * Open an exiting file for writing, the state file needs to be
		 * pre-allocated since we can't and don't want to do allocation
		 * during checkpoint (too much of the OS is disabled).
		 *    - do a preliminary size checking here, if it is too small,
		 *	allocate more space internally and retry.
		 *    - check the vp to make sure it's the right type.
		 */
		char *path = cpr_build_statefile_path();

		if (path == NULL)
			return (ENXIO);
		else if (rc = cpr_verify_statefile_path())
			return (rc);

		if (rc = vn_open(path, UIO_SYSSPACE,
		    FCREAT|FWRITE, 0600, &C_VP, CRCREAT, 0)) {
			cpr_err(CE_WARN, "cannot open statefile %s", path);
			return (rc);
		}
	}

	/*
	 * Only ufs and block special statefiles supported
	 */
	if (C_VP->v_type != VREG && C_VP->v_type != VBLK) {
		cpr_err(CE_CONT,
		    "Statefile must be regular file or block special file.");
		return (EACCES);
	}

	if (rc = cpr_statefile_ok(C_VP, alloc_retry))
		return (rc);

	if (C_VP->v_type != VBLK) {
		/*
		 * sync out the fs change due to the statefile reservation.
		 */
		(void) VFS_SYNC(C_VP->v_vfsp, 0, CRED());

		/*
		 * Validate disk blocks allocation for the state file.
		 * Ask the file system prepare itself for the dump operation.
		 */
		if (rc = VOP_DUMPCTL(C_VP, DUMP_ALLOC, NULL, NULL)) {
			cpr_err(CE_CONT, "Error allocating "
			    "blocks for cpr statefile.");
			return (rc);
		}
	}
	return (0);
}


/*
 * Lookup device size and return available space in bytes.
 * NOTE: Since prop_op(9E) can't tell the difference between a character
 * and a block reference, it is ok to ask for "Size" instead of "Nblocks".
 */
size_t
cpr_get_devsize(dev_t dev)
{
	size_t bytes = 0;

	bytes = cdev_Size(dev);
	if (bytes == 0)
		bytes = cdev_size(dev);

	if (bytes > CPR_SPEC_OFFSET)
		bytes -= CPR_SPEC_OFFSET;
	else
		bytes = 0;

	return (bytes);
}


/*
 * increase statefile size
 */
static int
cpr_grow_statefile(vnode_t *vp, u_longlong_t newsize)
{
	extern uchar_t cpr_pagecopy[];
	struct inode *ip = VTOI(vp);
	u_longlong_t offset;
	int error, increase;
	ssize_t resid;

	rw_enter(&ip->i_contents, RW_READER);
	increase = (ip->i_size < newsize);
	offset = ip->i_size;
	rw_exit(&ip->i_contents);

	if (increase == 0)
		return (0);

	/*
	 * write to each logical block to reserve disk space
	 */
	error = 0;
	cpr_pagecopy[0] = '1';
	for (; offset < newsize; offset += ip->i_fs->fs_bsize) {
		if (error = vn_rdwr(UIO_WRITE, vp, (caddr_t)cpr_pagecopy,
		    ip->i_fs->fs_bsize, (offset_t)offset, UIO_SYSSPACE, 0,
		    (rlim64_t)MAXOFF_T, CRED(), &resid)) {
			if (error == ENOSPC) {
				cpr_err(CE_WARN, "error %d while reserving "
				    "disk space for statefile %s\n"
				    "wanted %lld bytes, file is %lld short",
				    error, cpr_cprconfig_to_path(),
				    newsize, newsize - offset);
			}
			break;
		}
	}
	return (error);
}


/*
 * do a simple estimate of the space needed to hold the statefile
 * taking compression into account, but be fairly conservative
 * so we have a better chance of completing; when dump fails,
 * the retry cost is fairly high.
 *
 * Do disk blocks allocation for the state file if no space has
 * been allocated yet. Since the state file will not be removed,
 * allocation should only be done once.
 */
static int
cpr_statefile_ok(vnode_t *vp, int alloc_retry)
{
	extern size_t cpr_bitmap_size;
	struct inode *ip = VTOI(vp);
	const int UCOMP_RATE = 20; /* comp. ratio*10 for user pages */
	u_longlong_t size, isize, ksize, raw_data;
	char *str, *est_fmt;
	size_t space;
	int error;

	/*
	 * number of pages short for swapping.
	 */
	STAT->cs_nosw_pages = k_anoninfo.ani_mem_resv;
	if (STAT->cs_nosw_pages < 0)
		STAT->cs_nosw_pages = 0;

	str = "cpr_statefile_ok:";

	CPR_DEBUG(CPR_DEBUG9, "Phys swap: max=%lu resv=%lu\n",
	    k_anoninfo.ani_max, k_anoninfo.ani_phys_resv);
	CPR_DEBUG(CPR_DEBUG9, "Mem swap: max=%ld resv=%lu\n",
	    MAX(availrmem - swapfs_minfree, 0),
	    k_anoninfo.ani_mem_resv);
	CPR_DEBUG(CPR_DEBUG9, "Total available swap: %ld\n",
	    CURRENT_TOTAL_AVAILABLE_SWAP);

	/*
	 * try increasing filesize by 15%
	 */
	if (alloc_retry) {
		/*
		 * block device doesn't get any bigger
		 */
		if (vp->v_type == VBLK) {
			if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6))
				prom_printf(
				    "Retry statefile on special file\n");
			return (ENOMEM);
		} else {
			rw_enter(&ip->i_contents, RW_READER);
			size = (ip->i_size * SIZE_RATE) / INTEGRAL;
			rw_exit(&ip->i_contents);
		}
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6))
			prom_printf("Retry statefile size = %lld\n", size);
	} else {
		u_longlong_t cpd_size;
		pgcnt_t npages, nback;
		int ndvram;

		ndvram = 0;
		(void) callb_execute_class(CB_CL_CPR_FB,
		    (int)(uintptr_t)&ndvram);
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6))
			prom_printf("ndvram size = %d\n", ndvram);

		/*
		 * estimate 1 cpd_t for every (CPR_MAXCONTIG / 2) pages
		 */
		npages = cpr_count_kpages(REGULAR_BITMAP, cpr_nobit);
		cpd_size = sizeof (cpd_t) * (npages / (CPR_MAXCONTIG / 2));
		raw_data = cpd_size + cpr_bitmap_size;
		ksize = ndvram + mmu_ptob(npages);

		est_fmt = "%s estimated size with "
		    "%scompression %lld, ksize %lld\n";
		nback = mmu_ptob(STAT->cs_nosw_pages);
		if (CPR->c_flags & C_COMPRESSING) {
			size = ((ksize * COMPRESS_PERCENT) / INTEGRAL) +
			    raw_data + ((nback * 10) / UCOMP_RATE);
			CPR_DEBUG(CPR_DEBUG1, est_fmt, str, "", size, ksize);
		} else {
			size = ksize + raw_data + nback;
			CPR_DEBUG(CPR_DEBUG1, est_fmt, str, "no ",
			    size, ksize);
		}
	}

	/*
	 * All this is much simpler for a block device
	 */
	if (vp->v_type == VBLK) {
		space = cpr_get_devsize(vp->v_rdev);
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6))
			prom_printf("statefile dev size %lu\n", space);

		/*
		 * Export the estimated filesize info, this value will be
		 * compared before dumping out the statefile in the case of
		 * no compression.
		 */
		STAT->cs_est_statefsz = size;
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6))
			prom_printf("%s Estimated statefile size %llu, "
			    "space %lu\n", str, size, space);
		if (size > space) {
			cpr_err(CE_CONT, "Statefile partition too small.");
			return (ENOMEM);
		}
		return (0);
	} else {
		if (CPR->c_alloc_cnt++ > C_MAX_ALLOC_RETRY) {
			cpr_err(CE_CONT, "Statefile allocation retry failed\n");
			return (ENOMEM);
		}

		/*
		 * Estimate space needed for the state file.
		 *
		 * State file size in bytes:
		 * 	kernel size + non-cache pte seg +
		 *	bitmap size + cpr state file headers size
		 * (round up to fs->fs_bsize)
		 */
		size = blkroundup(ip->i_fs, size);

		/*
		 * Export the estimated filesize info, this value will be
		 * compared before dumping out the statefile in the case of
		 * no compression.
		 */
		STAT->cs_est_statefsz = size;
		error = cpr_grow_statefile(vp, size);
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6)) {
			rw_enter(&ip->i_contents, RW_READER);
			isize = ip->i_size;
			rw_exit(&ip->i_contents);
			prom_printf("%s Estimated statefile size %lld, "
			    "i_size %lld\n", str, size, isize);
		}

		return (error);
	}
}


void
cpr_statef_close(void)
{
	if (C_VP) {
		if (!cpr_reusable_mode)
			(void) VOP_DUMPCTL(C_VP, DUMP_FREE, NULL, NULL);
		(void) VOP_CLOSE(C_VP, FWRITE, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(C_VP);
		C_VP = 0;
	}
}


/*
 * open cpr default file and display error
 */
int
cpr_open_deffile(int mode, vnode_t **vpp)
{
	int error;

	if (error = cpr_open(cpr_default_path, mode, vpp))
		cpr_err(CE_CONT, "cannot open \"%s\", error %d\n",
		    cpr_default_path, error);
	return (error);
}


/*
 * write cdef_t to disk.  This contains the original values of prom
 * properties that we modify.  We fill in the magic number of the file
 * here as a signal to the booter code that the state file is valid.
 * Be sure the file gets synced, since we may be shutting down the OS.
 */
int
cpr_write_deffile(cdef_t *cdef)
{
	struct vnode *vp;
	char *str;
	int rc;

	if (rc = cpr_open_deffile(FCREAT|FWRITE, &vp))
		return (rc);

	if (rc = cpr_rdwr(UIO_WRITE, vp, cdef, sizeof (*cdef)))
		str = "write";
	else if (rc = VOP_FSYNC(vp, FSYNC, CRED(), NULL))
		str = "fsync";
	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);

	if (rc) {
		cpr_err(CE_WARN, "%s error %d, file \"%s\"",
		    str, rc, cpr_default_path);
	}
	return (rc);
}

/*
 * Clear the magic number in the defaults file.  This tells the booter
 * program that the state file is not current and thus prevents
 * any attempt to restore from an obsolete state file.
 */
void
cpr_clear_definfo(void)
{
	struct vnode *vp;
	cmini_t mini;

	if ((CPR->c_cprboot_magic != CPR_DEFAULT_MAGIC) ||
	    cpr_open_deffile(FCREAT|FWRITE, &vp))
		return;
	mini.magic = mini.reusable = 0;
	(void) cpr_rdwr(UIO_WRITE, vp, &mini, sizeof (mini));
	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
}

/*
 * If the cpr default file is invalid, then we must not be in reusable mode
 * if it is valid, it tells us our mode
 */
int
cpr_get_reusable_mode(void)
{
	struct vnode *vp;
	cmini_t mini;
	int rc;

	if (cpr_open(cpr_default_path, FREAD, &vp))
		return (0);

	rc = cpr_rdwr(UIO_READ, vp, &mini, sizeof (mini));
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	if (rc == 0 && mini.magic == CPR_DEFAULT_MAGIC)
		return (mini.reusable);

	return (0);
}
#endif

/*
 * clock/time related routines
 */
static time_t   cpr_time_stamp;


void
cpr_tod_get(cpr_time_t *ctp)
{
	timestruc_t ts;

	mutex_enter(&tod_lock);
	ts = TODOP_GET(tod_ops);
	mutex_exit(&tod_lock);
	ctp->tv_sec = (time32_t)ts.tv_sec;
	ctp->tv_nsec = (int32_t)ts.tv_nsec;
}

void
cpr_tod_status_set(int tod_flag)
{
	mutex_enter(&tod_lock);
	tod_status_set(tod_flag);
	mutex_exit(&tod_lock);
}

void
cpr_save_time(void)
{
	cpr_time_stamp = gethrestime_sec();
}

/*
 * correct time based on saved time stamp or hardware clock
 */
void
cpr_restore_time(void)
{
	clkset(cpr_time_stamp);
}

#if defined(__sparc)
/*
 * CPU ONLINE/OFFLINE CODE
 */
int
cpr_mp_offline(void)
{
	cpu_t *cp, *bootcpu;
	int rc = 0;
	int brought_up_boot = 0;

	/*
	 * Do nothing for UP.
	 */
	if (ncpus == 1)
		return (0);

	mutex_enter(&cpu_lock);

	cpr_save_mp_state();

	bootcpu = i_cpr_bootcpu();
	if (!CPU_ACTIVE(bootcpu)) {
		if ((rc = cpr_p_online(bootcpu, CPU_CPR_ONLINE))) {
			mutex_exit(&cpu_lock);
			return (rc);
		}
		brought_up_boot = 1;
	}

	cp = cpu_list;
	do {
		if (cp == bootcpu)
			continue;
		if (cp->cpu_flags & CPU_OFFLINE)
			continue;
		if ((rc = cpr_p_online(cp, CPU_CPR_OFFLINE))) {
			mutex_exit(&cpu_lock);
			return (rc);
		}
	} while ((cp = cp->cpu_next) != cpu_list);
	if (brought_up_boot && (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG6)))
		prom_printf("changed cpu %p to state %d\n",
		    (void *)bootcpu, CPU_CPR_ONLINE);
	mutex_exit(&cpu_lock);

	return (rc);
}

int
cpr_mp_online(void)
{
	cpu_t *cp, *bootcpu = CPU;
	int rc = 0;

	/*
	 * Do nothing for UP.
	 */
	if (ncpus == 1)
		return (0);

	/*
	 * cpr_save_mp_state() sets CPU_CPR_ONLINE in cpu_cpr_flags
	 * to indicate a cpu was online at the time of cpr_suspend();
	 * now restart those cpus that were marked as CPU_CPR_ONLINE
	 * and actually are offline.
	 */
	mutex_enter(&cpu_lock);
	for (cp = bootcpu->cpu_next; cp != bootcpu; cp = cp->cpu_next) {
		/*
		 * Clear the CPU_FROZEN flag in all cases.
		 */
		cp->cpu_flags &= ~CPU_FROZEN;

		if (CPU_CPR_IS_OFFLINE(cp))
			continue;
		if (CPU_ACTIVE(cp))
			continue;
		if ((rc = cpr_p_online(cp, CPU_CPR_ONLINE))) {
			mutex_exit(&cpu_lock);
			return (rc);
		}
	}

	/*
	 * turn off the boot cpu if it was offlined
	 */
	if (CPU_CPR_IS_OFFLINE(bootcpu)) {
		if ((rc = cpr_p_online(bootcpu, CPU_CPR_OFFLINE))) {
			mutex_exit(&cpu_lock);
			return (rc);
		}
	}
	mutex_exit(&cpu_lock);
	return (0);
}

static void
cpr_save_mp_state(void)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_list;
	do {
		cp->cpu_cpr_flags &= ~CPU_CPR_ONLINE;
		if (CPU_ACTIVE(cp))
			CPU_SET_CPR_FLAGS(cp, CPU_CPR_ONLINE);
	} while ((cp = cp->cpu_next) != cpu_list);
}

/*
 * change cpu to online/offline
 */
static int
cpr_p_online(cpu_t *cp, int state)
{
	int rc;

	ASSERT(MUTEX_HELD(&cpu_lock));

	switch (state) {
	case CPU_CPR_ONLINE:
		rc = cpu_online(cp);
		break;
	case CPU_CPR_OFFLINE:
		rc = cpu_offline(cp, CPU_FORCED);
		break;
	}
	if (rc) {
		cpr_err(CE_WARN, "Failed to change processor %d to "
		    "state %d, (errno %d)", cp->cpu_id, state, rc);
	}
	return (rc);
}

/*
 * Construct the pathname of the state file and return a pointer to
 * caller.  Read the config file to get the mount point of the
 * filesystem and the pathname within fs.
 */
char *
cpr_build_statefile_path(void)
{
	struct cprconfig *cf = &cprconfig;

	if (cpr_get_config())
		return (NULL);

	switch (cf->cf_type) {
	case CFT_UFS:
		if (strlen(cf->cf_path) + strlen(cf->cf_fs) >= MAXNAMELEN - 1) {
			cpr_err(CE_CONT, "Statefile path is too long.\n");
			return (NULL);
		}
		return (cpr_cprconfig_to_path());
	case CFT_ZVOL:
		/*FALLTHROUGH*/
	case CFT_SPEC:
		return (cf->cf_devfs);
	default:
		cpr_err(CE_PANIC, "invalid statefile type");
		/*NOTREACHED*/
		return (NULL);
	}
}

int
cpr_statefile_is_spec(void)
{
	if (cpr_get_config())
		return (0);
	return (cprconfig.cf_type == CFT_SPEC);
}

char *
cpr_get_statefile_prom_path(void)
{
	struct cprconfig *cf = &cprconfig;

	ASSERT(cprconfig_loaded);
	ASSERT(cf->cf_magic == CPR_CONFIG_MAGIC);
	ASSERT(cf->cf_type == CFT_SPEC || cf->cf_type == CFT_ZVOL);
	return (cf->cf_dev_prom);
}


/*
 * XXX The following routines need to be in the vfs source code.
 */

int
cpr_is_ufs(struct vfs *vfsp)
{
	char *fsname;

	fsname = vfssw[vfsp->vfs_fstype].vsw_name;
	return (strcmp(fsname, "ufs") == 0);
}

int
cpr_is_zfs(struct vfs *vfsp)
{
	char *fsname;

	fsname = vfssw[vfsp->vfs_fstype].vsw_name;
	return (strcmp(fsname, "zfs") == 0);
}

/*
 * This is a list of file systems that are allowed to be writeable when a
 * reusable statefile checkpoint is taken.  They must not have any state that
 * cannot be restored to consistency by simply rebooting using the checkpoint.
 * (In contrast to ufs and pcfs which have disk state that could get
 * out of sync with the in-kernel data).
 */
int
cpr_reusable_mount_check(void)
{
	struct vfs *vfsp;
	char *fsname;
	char **cpp;
	static char *cpr_writeok_fss[] = {
		"autofs", "devfs", "fd", "lofs", "mntfs", "namefs", "nfs",
		"proc", "tmpfs", "ctfs", "objfs", "dev", NULL
	};

	vfs_list_read_lock();
	vfsp = rootvfs;
	do {
		if (vfsp->vfs_flag & VFS_RDONLY) {
			vfsp = vfsp->vfs_next;
			continue;
		}
		fsname = vfssw[vfsp->vfs_fstype].vsw_name;
		for (cpp = cpr_writeok_fss; *cpp; cpp++) {
			if (strcmp(fsname, *cpp) == 0)
				break;
		}
		/*
		 * if the inner loop reached the NULL terminator,
		 * the current fs-type does not match any OK-type
		 */
		if (*cpp == NULL) {
			cpr_err(CE_CONT, "a filesystem of type %s is "
			    "mounted read/write.\nReusable statefile requires "
			    "no writeable filesystem of this type be mounted\n",
			    fsname);
			vfs_list_unlock();
			return (EINVAL);
		}
		vfsp = vfsp->vfs_next;
	} while (vfsp != rootvfs);
	vfs_list_unlock();
	return (0);
}

/*
 * return statefile offset in DEV_BSIZE units
 */
int
cpr_statefile_offset(void)
{
	return (cprconfig.cf_type != CFT_UFS ? btod(CPR_SPEC_OFFSET) : 0);
}

/*
 * Force a fresh read of the cprinfo per uadmin 3 call
 */
void
cpr_forget_cprconfig(void)
{
	cprconfig_loaded = 0;
}
#endif
