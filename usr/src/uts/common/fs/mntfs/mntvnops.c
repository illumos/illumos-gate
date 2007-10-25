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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/atomic.h>
#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/fs/mntdata.h>
#include <fs/fs_subr.h>
#include <sys/vmsystm.h>
#include <vm/seg_vn.h>

#define	MNTROOTINO	2

static mntnode_t *mntgetnode(vnode_t *);

vnodeops_t *mntvnodeops;
extern void vfs_mnttab_readop(void);

/*
 * Design of kernel mnttab accounting.
 *
 * To support whitespace in mount names, we implement an ioctl
 * (MNTIOC_GETMNTENT) which allows a programmatic interface to the data in
 * /etc/mnttab.  The libc functions getmntent() and getextmntent() are built
 * atop this interface.
 *
 * To minimize the amount of memory used in the kernel, we keep all the
 * necessary information in the user's address space.  Large server
 * configurations can have /etc/mnttab files in excess of 64k.
 *
 * To support both vanilla read() calls as well as ioctl() calls, we have two
 * different snapshots of the kernel data structures, mnt_read and mnt_ioctl.
 * These snapshots include the base location in user memory, the number of
 * mounts in the snapshot, and any metadata associated with it.  The metadata is
 * used only to support the ioctl() interface, and is a series of extmnttab
 * structures.  When the user issues an ioctl(), we simply copyout a pointer to
 * that structure, and the rest is handled in userland.
 */

/*
 * NOTE: The following variable enables the generation of the "dev=xxx"
 * in the option string for a mounted file system.  Really this should
 * be gotten rid of altogether, but for the sake of backwards compatibility
 * we had to leave it in.  It is defined as a 32-bit device number.  This
 * means that when 64-bit device numbers are in use, if either the major or
 * minor part of the device number will not fit in a 16 bit quantity, the
 * "dev=" will be set to NODEV (0x7fffffff).  See PSARC 1999/566 and
 * 1999/131 for details.  The cmpldev() function used to generate the 32-bit
 * device number handles this check and assigns the proper value.
 */
int mntfs_enabledev = 1;	/* enable old "dev=xxx" option */

static int
mntfs_devsize(struct vfs *vfsp)
{
	dev32_t odev;

	(void) cmpldev(&odev, vfsp->vfs_dev);
	return (snprintf(NULL, 0, "dev=%x", odev));
}

static int
mntfs_devprint(struct vfs *vfsp, char *buf)
{
	dev32_t odev;

	(void) cmpldev(&odev, vfsp->vfs_dev);
	return (snprintf(buf, MAX_MNTOPT_STR, "dev=%x", odev));
}

static int
mntfs_optsize(struct vfs *vfsp)
{
	int i, size = 0;
	mntopt_t *mop;

	for (i = 0; i < vfsp->vfs_mntopts.mo_count; i++) {
		mop = &vfsp->vfs_mntopts.mo_list[i];
		if (mop->mo_flags & MO_NODISPLAY)
			continue;
		if (mop->mo_flags & MO_SET) {
			if (size)
				size++; /* space for comma */
			size += strlen(mop->mo_name);
			/*
			 * count option value if there is one
			 */
			if (mop->mo_arg != NULL) {
				size += strlen(mop->mo_arg) + 1;
			}
		}
	}
	if (vfsp->vfs_zone != NULL && vfsp->vfs_zone != global_zone) {
		/*
		 * Add space for "zone=<zone_name>" if required.
		 */
		if (size)
			size++;	/* space for comma */
		size += sizeof ("zone=") - 1;
		size += strlen(vfsp->vfs_zone->zone_name);
	}
	if (mntfs_enabledev) {
		if (size != 0)
			size++; /* space for comma */
		size += mntfs_devsize(vfsp);
	}
	if (size == 0)
		size = strlen("-");
	return (size);
}

static int
mntfs_optprint(struct vfs *vfsp, char *buf)
{
	int i, optinbuf = 0;
	mntopt_t *mop;
	char *origbuf = buf;

	for (i = 0; i < vfsp->vfs_mntopts.mo_count; i++) {
		mop = &vfsp->vfs_mntopts.mo_list[i];
		if (mop->mo_flags & MO_NODISPLAY)
			continue;
		if (mop->mo_flags & MO_SET) {
			if (optinbuf)
				*buf++ = ',';
			else
				optinbuf = 1;
			buf += snprintf(buf, MAX_MNTOPT_STR,
				"%s", mop->mo_name);
			/*
			 * print option value if there is one
			 */
			if (mop->mo_arg != NULL) {
				buf += snprintf(buf, MAX_MNTOPT_STR, "=%s",
					mop->mo_arg);
			}
		}
	}
	if (vfsp->vfs_zone != NULL && vfsp->vfs_zone != global_zone) {
		if (optinbuf)
			*buf++ = ',';
		else
			optinbuf = 1;
		buf += snprintf(buf, MAX_MNTOPT_STR, "zone=%s",
		    vfsp->vfs_zone->zone_name);
	}
	if (mntfs_enabledev) {
		if (optinbuf++)
			*buf++ = ',';
		buf += mntfs_devprint(vfsp, buf);
	}
	if (!optinbuf) {
		buf += snprintf(buf, MAX_MNTOPT_STR, "-");
	}
	return (buf - origbuf);
}

static size_t
mntfs_vfs_len(vfs_t *vfsp, zone_t *zone)
{
	size_t size = 0;
	const char *resource, *mntpt;

	mntpt = refstr_value(vfsp->vfs_mntpt);
	if (mntpt != NULL && mntpt[0] != '\0') {
		size += strlen(ZONE_PATH_TRANSLATE(mntpt, zone)) + 1;
	} else {
		size += strlen("-") + 1;
	}

	resource = refstr_value(vfsp->vfs_resource);
	if (resource != NULL && resource[0] != '\0') {
		if (resource[0] != '/') {
			size += strlen(resource) + 1;
		} else if (!ZONE_PATH_VISIBLE(resource, zone)) {
			/*
			 * Same as the zone's view of the mount point.
			 */
			size += strlen(ZONE_PATH_TRANSLATE(mntpt, zone)) + 1;
		} else {
			size += strlen(ZONE_PATH_TRANSLATE(resource, zone)) + 1;
		}
	} else {
		size += strlen("-") + 1;
	}
	size += strlen(vfssw[vfsp->vfs_fstype].vsw_name) + 1;
	size += mntfs_optsize(vfsp);
	size += snprintf(NULL, 0, "\t%ld\n", vfsp->vfs_mtime);
	return (size);
}

static void
mntfs_zonerootvfs(zone_t *zone, vfs_t *rootvfsp)
{
	/*
	 * Basically copy over the real vfs_t on which the root vnode is
	 * located, changing its mountpoint and resource to match those of
	 * the zone's rootpath.
	 */
	*rootvfsp = *zone->zone_rootvp->v_vfsp;
	rootvfsp->vfs_mntpt = refstr_alloc(zone->zone_rootpath);
	rootvfsp->vfs_resource = rootvfsp->vfs_mntpt;
}

static size_t
mntfs_zone_len(uint_t *nent_ptr, zone_t *zone, int showhidden)
{
	struct vfs *zonelist;
	struct vfs *vfsp;
	size_t size = 0;
	uint_t cnt = 0;

	ASSERT(zone->zone_rootpath != NULL);

	/*
	 * If the zone has a root entry, it will be the first in the list.  If
	 * it doesn't, we conjure one up.
	 */
	vfsp = zonelist = zone->zone_vfslist;
	if (zonelist == NULL ||
	    strcmp(refstr_value(vfsp->vfs_mntpt), zone->zone_rootpath) != 0) {
		vfs_t tvfs;
		/*
		 * The root of the zone is not a mount point.  The vfs we want
		 * to report is that of the zone's root vnode.
		 */
		ASSERT(zone != global_zone);
		mntfs_zonerootvfs(zone, &tvfs);
		size += mntfs_vfs_len(&tvfs, zone);
		refstr_rele(tvfs.vfs_mntpt);
		cnt++;
	}
	if (zonelist == NULL)
		goto out;
	do {
		/*
		 * Skip mounts that should not show up in mnttab
		 */
		if (!showhidden && (vfsp->vfs_flag & VFS_NOMNTTAB)) {
			vfsp = vfsp->vfs_zone_next;
			continue;
		}
		cnt++;
		size += mntfs_vfs_len(vfsp, zone);
		vfsp = vfsp->vfs_zone_next;
	} while (vfsp != zonelist);
out:
	*nent_ptr = cnt;
	return (size);
}

static size_t
mntfs_global_len(uint_t *nent_ptr, int showhidden)
{
	struct vfs *vfsp;
	size_t size = 0;
	uint_t cnt = 0;

	vfsp = rootvfs;
	do {
		/*
		 * Skip mounts that should not show up in mnttab
		 */
		if (!showhidden && (vfsp->vfs_flag & VFS_NOMNTTAB)) {
			vfsp = vfsp->vfs_next;
			continue;
		}
		cnt++;
		size += mntfs_vfs_len(vfsp, global_zone);
		vfsp = vfsp->vfs_next;
	} while (vfsp != rootvfs);
	*nent_ptr = cnt;
	return (size);
}

static void
mntfs_vfs_generate(vfs_t *vfsp, zone_t *zone, struct extmnttab *tab,
    char **basep, int forread)
{
	const char *resource, *mntpt;
	char *cp = *basep;

	mntpt = refstr_value(vfsp->vfs_mntpt);
	resource = refstr_value(vfsp->vfs_resource);

	if (tab)
		tab->mnt_special = cp;
	if (resource != NULL && resource[0] != '\0') {
		if (resource[0] != '/') {
			cp += snprintf(cp, MAXPATHLEN, "%s", resource);
		} else if (!ZONE_PATH_VISIBLE(resource, zone)) {
			/*
			 * Use the mount point as the resource.
			 */
			cp += snprintf(cp, MAXPATHLEN, "%s",
			    ZONE_PATH_TRANSLATE(mntpt, zone));
		} else {
			cp += snprintf(cp, MAXPATHLEN, "%s",
			    ZONE_PATH_TRANSLATE(resource, zone));
		}
	} else {
		cp += snprintf(cp, MAXPATHLEN, "-");
	}
	*cp++ = forread ? '\t' : '\0';

	if (tab)
		tab->mnt_mountp = cp;
	if (mntpt != NULL && mntpt[0] != '\0') {
		/*
		 * We know the mount point is visible from within the zone,
		 * otherwise it wouldn't be on the zone's vfs list.
		 */
		cp += snprintf(cp, MAXPATHLEN, "%s",
		    ZONE_PATH_TRANSLATE(mntpt, zone));
	} else {
		cp += snprintf(cp, MAXPATHLEN, "-");
	}
	*cp++ = forread ? '\t' : '\0';

	if (tab)
		tab->mnt_fstype = cp;
	cp += snprintf(cp, MAXPATHLEN, "%s",
	    vfssw[vfsp->vfs_fstype].vsw_name);
	*cp++ = forread ? '\t' : '\0';

	if (tab)
		tab->mnt_mntopts = cp;
	cp += mntfs_optprint(vfsp, cp);
	*cp++ = forread ? '\t' : '\0';

	if (tab)
		tab->mnt_time = cp;
	cp += snprintf(cp, MAX_MNTOPT_STR, "%ld", vfsp->vfs_mtime);
	*cp++ = forread ? '\n' : '\0';

	if (tab) {
		tab->mnt_major = getmajor(vfsp->vfs_dev);
		tab->mnt_minor = getminor(vfsp->vfs_dev);
	}

	*basep = cp;
}

static void
mntfs_zone_generate(zone_t *zone, int showhidden, struct extmnttab *tab,
    char *basep, int forread)
{
	vfs_t *zonelist;
	vfs_t *vfsp;
	char *cp = basep;

	/*
	 * If the zone has a root entry, it will be the first in the list.  If
	 * it doesn't, we conjure one up.
	 */
	vfsp = zonelist = zone->zone_vfslist;
	if (zonelist == NULL ||
	    strcmp(refstr_value(vfsp->vfs_mntpt), zone->zone_rootpath) != 0) {
		vfs_t tvfs;
		/*
		 * The root of the zone is not a mount point.  The vfs we want
		 * to report is that of the zone's root vnode.
		 */
		ASSERT(zone != global_zone);
		mntfs_zonerootvfs(zone, &tvfs);
		mntfs_vfs_generate(&tvfs, zone, tab, &cp, forread);
		refstr_rele(tvfs.vfs_mntpt);
		if (tab)
			tab++;
	}
	if (zonelist == NULL)
		return;
	do {
		/*
		 * Skip mounts that should not show up in mnttab
		 */
		if (!showhidden && (vfsp->vfs_flag & VFS_NOMNTTAB)) {
			vfsp = vfsp->vfs_zone_next;
			continue;
		}
		mntfs_vfs_generate(vfsp, zone, tab, &cp, forread);
		if (tab)
			tab++;
		vfsp = vfsp->vfs_zone_next;
	} while (vfsp != zonelist);
}

static void
mntfs_global_generate(int showhidden, struct extmnttab *tab, char *basep,
    int forread)
{
	vfs_t *vfsp;
	char *cp = basep;

	vfsp = rootvfs;
	do {
		/*
		 * Skip mounts that should not show up in mnttab
		 */
		if (!showhidden && vfsp->vfs_flag & VFS_NOMNTTAB) {
			vfsp = vfsp->vfs_next;
			continue;
		}
		mntfs_vfs_generate(vfsp, global_zone, tab, &cp, forread);
		if (tab)
			tab++;
		vfsp = vfsp->vfs_next;
	} while (vfsp != rootvfs);
}

static char *
mntfs_mapin(char *base, size_t size)
{
	size_t rlen = roundup(size, PAGESIZE);
	struct as *as = curproc->p_as;
	char *addr;

	as_rangelock(as);
	map_addr(&addr, rlen, 0, 1, 0);
	if (addr == NULL || as_map(as, addr, rlen, segvn_create, zfod_argsp)) {
		as_rangeunlock(as);
		return (NULL);
	}
	as_rangeunlock(as);
	if (copyout(base, addr, size)) {
		(void) as_unmap(as, addr, rlen);
		return (NULL);
	}
	return (addr);
}

static void
mntfs_freesnap(mntsnap_t *snap)
{
	if (snap->mnts_text != NULL)
		(void) as_unmap(curproc->p_as, snap->mnts_text,
			roundup(snap->mnts_textsize, PAGESIZE));
	snap->mnts_textsize = snap->mnts_count = 0;
	if (snap->mnts_metadata != NULL)
		(void) as_unmap(curproc->p_as, snap->mnts_metadata,
			roundup(snap->mnts_metasize, PAGESIZE));
	snap->mnts_metasize = 0;
}

#ifdef _SYSCALL32_IMPL

typedef struct extmnttab32 {
	uint32_t	mnt_special;
	uint32_t	mnt_mountp;
	uint32_t	mnt_fstype;
	uint32_t	mnt_mntopts;
	uint32_t	mnt_time;
	uint_t		mnt_major;
	uint_t		mnt_minor;
} extmnttab32_t;

#endif

/*
 * Snapshot the latest version of the kernel mounted resource information
 *
 * There are two types of snapshots: one destined for reading, and one destined
 * for ioctl().  The difference is that the ioctl() interface is delimited by
 * NULLs, while the read() interface is delimited by tabs and newlines.
 */
/* ARGSUSED */
static int
mntfs_snapshot(mntnode_t *mnp, int forread, int datamodel)
{
	size_t size;
	timespec_t lastmodt;
	mntdata_t *mntdata = MTOD(mnp);
	zone_t *zone = mntdata->mnt_zone;
	boolean_t global_view = (MTOD(mnp)->mnt_zone == global_zone);
	boolean_t showhidden = ((mnp->mnt_flags & MNT_SHOWHIDDEN) != 0);
	struct extmnttab *metadata_baseaddr;
	char *text_baseaddr;
	int i;
	mntsnap_t *snap;

	if (forread)
		snap = &mnp->mnt_read;
	else
		snap = &mnp->mnt_ioctl;

	vfs_list_read_lock();
	/*
	 * Check if the mnttab info has changed since the last snapshot
	 */
	vfs_mnttab_modtime(&lastmodt);
	if (snap->mnts_count &&
	    lastmodt.tv_sec == snap->mnts_time.tv_sec &&
	    lastmodt.tv_nsec == snap->mnts_time.tv_nsec) {
		vfs_list_unlock();
		return (0);
	}


	if (snap->mnts_count != 0)
		mntfs_freesnap(snap);
	if (global_view)
		size = mntfs_global_len(&snap->mnts_count, showhidden);
	else
		size = mntfs_zone_len(&snap->mnts_count, zone, showhidden);
	ASSERT(size != 0);

	if (!forread)
		metadata_baseaddr = kmem_alloc(
		    snap->mnts_count * sizeof (struct extmnttab), KM_SLEEP);
	else
		metadata_baseaddr = NULL;

	text_baseaddr = kmem_alloc(size, KM_SLEEP);

	if (global_view)
		mntfs_global_generate(showhidden, metadata_baseaddr,
		    text_baseaddr, forread);
	else
		mntfs_zone_generate(zone, showhidden,
		    metadata_baseaddr, text_baseaddr, forread);

	vfs_mnttab_modtime(&snap->mnts_time);
	vfs_list_unlock();

	snap->mnts_text = mntfs_mapin(text_baseaddr, size);
	snap->mnts_textsize = size;
	kmem_free(text_baseaddr, size);

	/*
	 * The pointers in the metadata refer to addreesses in the range
	 * [base_addr, base_addr + size].  Now that we have mapped the text into
	 * the user's address space, we have to convert these addresses into the
	 * new (user) range.  We also handle the conversion for 32-bit and
	 * 32-bit applications here.
	 */
	if (!forread) {
		struct extmnttab *tab;
#ifdef _SYSCALL32_IMPL
		struct extmnttab32 *tab32;

		if (datamodel == DATAMODEL_ILP32) {
			tab = (struct extmnttab *)metadata_baseaddr;
			tab32 = (struct extmnttab32 *)metadata_baseaddr;

			for (i = 0; i < snap->mnts_count; i++) {
				tab32[i].mnt_special =
				    (uintptr_t)snap->mnts_text +
				    (tab[i].mnt_special - text_baseaddr);
				tab32[i].mnt_mountp =
				    (uintptr_t)snap->mnts_text +
				    (tab[i].mnt_mountp - text_baseaddr);
				tab32[i].mnt_fstype =
				    (uintptr_t)snap->mnts_text +
				    (tab[i].mnt_fstype - text_baseaddr);
				tab32[i].mnt_mntopts =
				    (uintptr_t)snap->mnts_text +
				    (tab[i].mnt_mntopts - text_baseaddr);
				tab32[i].mnt_time = (uintptr_t)snap->mnts_text +
				    (tab[i].mnt_time - text_baseaddr);
				tab32[i].mnt_major = tab[i].mnt_major;
				tab32[i].mnt_minor = tab[i].mnt_minor;
			}

			snap->mnts_metasize =
			    snap->mnts_count * sizeof (struct extmnttab32);
			snap->mnts_metadata = mntfs_mapin(
			    (char *)metadata_baseaddr,
			    snap->mnts_metasize);

		} else {
#endif
			tab = (struct extmnttab *)metadata_baseaddr;
			for (i = 0; i < snap->mnts_count; i++) {
				tab[i].mnt_special = snap->mnts_text +
				    (tab[i].mnt_special - text_baseaddr);
				tab[i].mnt_mountp = snap->mnts_text +
				    (tab[i].mnt_mountp - text_baseaddr);
				tab[i].mnt_fstype = snap->mnts_text +
				    (tab[i].mnt_fstype - text_baseaddr);
				tab[i].mnt_mntopts = snap->mnts_text +
				    (tab[i].mnt_mntopts - text_baseaddr);
				tab[i].mnt_time = snap->mnts_text +
				    (tab[i].mnt_time - text_baseaddr);
			}

			snap->mnts_metasize =
			    snap->mnts_count * sizeof (struct extmnttab);
			snap->mnts_metadata = mntfs_mapin(
			    (char *)metadata_baseaddr, snap->mnts_metasize);
#ifdef _SYSCALL32_IMPL
		}
#endif

		kmem_free(metadata_baseaddr,
		    snap->mnts_count * sizeof (struct extmnttab));
	}

	mntdata->mnt_size = size;

	if (snap->mnts_text == NULL ||
	    (!forread && snap->mnts_metadata == NULL)) {
		mntfs_freesnap(snap);
		return (ENOMEM);
	}
	vfs_mnttab_readop();
	return (0);
}

/*
 * Public function to convert vfs_mntopts into a string.
 * A buffer of sufficient size is allocated, which is returned via bufp,
 * and whose length is returned via lenp.
 */
void
mntfs_getmntopts(struct vfs *vfsp, char **bufp, size_t *lenp)
{
	size_t len;
	char *buf;

	vfs_list_read_lock();

	len = mntfs_optsize(vfsp) + 1;
	buf = kmem_alloc(len, KM_NOSLEEP);
	if (buf == NULL) {
		*bufp = NULL;
		vfs_list_unlock();
		return;
	}
	buf[len - 1] = '\0';
	(void) mntfs_optprint(vfsp, buf);
	ASSERT(buf[len - 1] == '\0');

	vfs_list_unlock();
	*bufp = buf;
	*lenp = len;
}


/* ARGSUSED */
static int
mntopen(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t *vp = *vpp;
	mntnode_t *nmnp;

	/*
	 * Not allowed to open for writing, return error.
	 */
	if (flag & FWRITE)
		return (EPERM);
	/*
	 * Create a new mnt/vnode for each open, this will give us a handle to
	 * hang the snapshot on.
	 */
	nmnp = mntgetnode(vp);

	*vpp = MTOV(nmnp);
	atomic_add_32(&MTOD(nmnp)->mnt_nopen, 1);
	VN_RELE(vp);
	return (0);
}

/* ARGSUSED */
static int
mntclose(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);

	/* Clean up any locks or shares held by the current process */
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	if (count > 1)
		return (0);
	if (vp->v_count == 1) {
		mntfs_freesnap(&mnp->mnt_read);
		mntfs_freesnap(&mnp->mnt_ioctl);
		atomic_add_32(&MTOD(mnp)->mnt_nopen, -1);
	}
	return (0);
}

/* ARGSUSED */
static int
mntread(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cred, caller_context_t *ct)
{
	int error = 0;
	off_t off = uio->uio_offset;
	size_t len = uio->uio_resid;
	mntnode_t *mnp = VTOM(vp);
	char *buf;
	mntsnap_t *snap = &mnp->mnt_read;
	int datamodel;

	if (off == (off_t)0 || snap->mnts_count == 0) {
		/*
		 * It is assumed that any kernel callers wishing
		 * to read mnttab will be using extmnttab entries
		 * and not extmnttab32 entries, whether or not
		 * the kernel is LP64 or ILP32.  Thus, force the
		 * datamodel that mntfs_snapshot uses to be
		 * DATAMODEL_LP64.
		 */
		if (uio->uio_segflg == UIO_SYSSPACE)
			datamodel = DATAMODEL_LP64;
		else
			datamodel = get_udatamodel();
		if ((error = mntfs_snapshot(mnp, 1, datamodel)) != 0)
			return (error);
	}
	if ((size_t)(off + len) > snap->mnts_textsize)
		len = snap->mnts_textsize - off;

	if (off < 0 || len > snap->mnts_textsize)
		return (EFAULT);

	if (len == 0)
		return (0);

	/*
	 * The mnttab image is stored in the user's address space,
	 * so we have to copy it into the kernel from userland,
	 * then copy it back out to the specified address.
	 */
	buf = kmem_alloc(len, KM_SLEEP);
	if (copyin(snap->mnts_text + off, buf, len))
		error = EFAULT;
	else {
		error = uiomove(buf, len, UIO_READ, uio);
	}
	kmem_free(buf, len);
	vfs_mnttab_readop();
	return (error);
}


static int
mntgetattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);
	int error;
	vnode_t *rvp;
	extern timespec_t vfs_mnttab_ctime;
	mntdata_t *mntdata = MTOD(VTOM(vp));
	mntsnap_t *snap = mnp->mnt_read.mnts_count ?
	    &mnp->mnt_read : &mnp->mnt_ioctl;

	/*
	 * Return all the attributes.  Should be refined
	 * so that it returns only those asked for.
	 * Most of this is complete fakery anyway.
	 */
	rvp = mnp->mnt_mountvp;
	/*
	 * Attributes are same as underlying file with modifications
	 */
	if (error = VOP_GETATTR(rvp, vap, flags, cr, ct))
		return (error);

	/*
	 * We always look like a regular file
	 */
	vap->va_type = VREG;
	/*
	 * mode should basically be read only
	 */
	vap->va_mode &= 07444;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_blksize = DEV_BSIZE;
	vap->va_rdev = 0;
	vap->va_seq = 0;
	/*
	 * Set nlink to the number of open vnodes for mnttab info
	 * plus one for existing.
	 */
	vap->va_nlink = mntdata->mnt_nopen + 1;
	/*
	 * If we haven't taken a snapshot yet, set the
	 * size to the size of the latest snapshot.
	 */
	vap->va_size = snap->mnts_textsize ? snap->mnts_textsize :
	    mntdata->mnt_size;
	/*
	 * Fetch mtime from the vfs mnttab timestamp
	 */
	vap->va_ctime = vfs_mnttab_ctime;
	vfs_list_read_lock();
	vfs_mnttab_modtime(&vap->va_mtime);
	vap->va_atime = vap->va_mtime;
	vfs_list_unlock();
	/*
	 * Nodeid is always ROOTINO;
	 */
	vap->va_nodeid = (ino64_t)MNTROOTINO;
	vap->va_nblocks = btod(vap->va_size);
	return (0);
}


static int
mntaccess(vnode_t *vp, int mode, int flags, cred_t *cr,
	caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);

	if (mode & (VWRITE|VEXEC))
		return (EROFS);

	/*
	 * Do access check on the underlying directory vnode.
	 */
	return (VOP_ACCESS(mnp->mnt_mountvp, mode, flags, cr, ct));
}


/*
 * New /mntfs vnode required; allocate it and fill in most of the fields.
 */
static mntnode_t *
mntgetnode(vnode_t *dp)
{
	mntnode_t *mnp;
	vnode_t *vp;

	mnp = kmem_zalloc(sizeof (mntnode_t), KM_SLEEP);
	mnp->mnt_vnode = vn_alloc(KM_SLEEP);
	mnp->mnt_mountvp = VTOM(dp)->mnt_mountvp;
	vp = MTOV(mnp);
	vp->v_flag = VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vn_setops(vp, mntvnodeops);
	vp->v_vfsp = dp->v_vfsp;
	vp->v_type = VREG;
	vp->v_data = (caddr_t)mnp;

	return (mnp);
}

/*
 * Free the storage obtained from mntgetnode().
 */
static void
mntfreenode(mntnode_t *mnp)
{
	vnode_t *vp = MTOV(mnp);

	vn_invalid(vp);
	vn_free(vp);
	kmem_free(mnp, sizeof (*mnp));
}


/* ARGSUSED */
static int
mntfsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static void
mntinactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);

	mntfreenode(mnp);
}

/* ARGSUSED */
static int
mntseek(vnode_t *vp, offset_t ooff, offset_t *noffp,
	caller_context_t *ct)
{
	if (*noffp == 0)
		VTOM(vp)->mnt_offset = 0;

	return (0);
}

/*
 * Return the answer requested to poll().
 * POLLRDBAND will return when the mtime of the mnttab
 * information is newer than the latest one read for this open.
 */
/* ARGSUSED */
static int
mntpoll(vnode_t *vp, short ev, int any, short *revp, pollhead_t **phpp,
	caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);
	mntsnap_t *snap = &mnp->mnt_read;

	if (mnp->mnt_ioctl.mnts_time.tv_sec > snap->mnts_time.tv_sec ||
	    (mnp->mnt_ioctl.mnts_time.tv_sec == snap->mnts_time.tv_sec &&
	    mnp->mnt_ioctl.mnts_time.tv_nsec > snap->mnts_time.tv_nsec))
		snap = &mnp->mnt_ioctl;

	*revp = 0;
	*phpp = (pollhead_t *)NULL;
	if (ev & POLLIN)
		*revp |= POLLIN;

	if (ev & POLLRDNORM)
		*revp |= POLLRDNORM;

	if (ev & POLLRDBAND) {
		vfs_mnttab_poll(&snap->mnts_time, phpp);
		if (*phpp == (pollhead_t *)NULL)
			*revp |= POLLRDBAND;
	}
	if (*revp || *phpp != NULL || any) {
		return (0);
	}
	/*
	 * If someone is polling an unsupported poll events (e.g.
	 * POLLOUT, POLLPRI, etc.), just return POLLERR revents.
	 * That way we will ensure that we don't return a 0
	 * revents with a NULL pollhead pointer.
	 */
	*revp = POLLERR;
	return (0);
}
/* ARGSUSED */
static int
mntioctl(struct vnode *vp, int cmd, intptr_t arg, int flag,
	cred_t *cr, int *rvalp, caller_context_t *ct)
{
	uint_t *up = (uint_t *)arg;
	mntnode_t *mnp = VTOM(vp);
	mntsnap_t *snap = &mnp->mnt_ioctl;
	int error;

	error = 0;
	switch (cmd) {

	case MNTIOC_NMNTS: {		/* get no. of mounted resources */
		if (snap->mnts_count == 0) {
			if ((error =
			    mntfs_snapshot(mnp, 0, flag & DATAMODEL_MASK)) != 0)
				return (error);
		}
		if (suword32(up, snap->mnts_count) != 0)
			error = EFAULT;
		break;
	}

	case MNTIOC_GETDEVLIST: {	/* get mounted device major/minor nos */
		uint_t *devlist;
		int i;
		size_t len;

		if (snap->mnts_count == 0) {
			if ((error =
			    mntfs_snapshot(mnp, 0, flag & DATAMODEL_MASK)) != 0)
				return (error);
		}

		len = 2 * snap->mnts_count * sizeof (uint_t);
		devlist = kmem_alloc(len, KM_SLEEP);
		for (i = 0; i < snap->mnts_count; i++) {

#ifdef _SYSCALL32_IMPL
			if ((flag & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				struct extmnttab32 tab;

				if ((error = xcopyin(snap->mnts_text +
				    i * sizeof (struct extmnttab32), &tab,
				    sizeof (tab))) != 0)
					break;

				devlist[i*2] = tab.mnt_major;
				devlist[i*2+1] = tab.mnt_minor;
			} else {
#endif
				struct extmnttab tab;

				if ((error = xcopyin(snap->mnts_text +
				    i * sizeof (struct extmnttab), &tab,
				    sizeof (tab))) != 0)
					break;

				devlist[i*2] = tab.mnt_major;
				devlist[i*2+1] = tab.mnt_minor;
#ifdef _SYSCALL32_IMPL
			}
#endif
		}

		if (error == 0)
			error = xcopyout(devlist, up, len);
		kmem_free(devlist, len);
		break;
	}

	case MNTIOC_SETTAG:		/* set tag on mounted file system */
	case MNTIOC_CLRTAG:		/* clear tag on mounted file system */
	{
		struct mnttagdesc *dp = (struct mnttagdesc *)arg;
		STRUCT_DECL(mnttagdesc, tagdesc);
		char *cptr;
		uint32_t major, minor;
		char tagbuf[MAX_MNTOPT_TAG];
		char *pbuf;
		size_t len;
		uint_t start = 0;
		mntdata_t *mntdata = MTOD(mnp);
		zone_t *zone = mntdata->mnt_zone;

		STRUCT_INIT(tagdesc, flag & DATAMODEL_MASK);
		if (copyin(dp, STRUCT_BUF(tagdesc), STRUCT_SIZE(tagdesc))) {
			error = EFAULT;
			break;
		}
		pbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (zone != global_zone) {
			(void) strcpy(pbuf, zone->zone_rootpath);
			/* truncate "/" and nul */
			start = zone->zone_rootpathlen - 2;
			ASSERT(pbuf[start] == '/');
		}
		cptr = STRUCT_FGETP(tagdesc, mtd_mntpt);
		error = copyinstr(cptr, pbuf + start, MAXPATHLEN - start, &len);
		if (error) {
			kmem_free(pbuf, MAXPATHLEN);
			break;
		}
		if (start != 0 && pbuf[start] != '/') {
			kmem_free(pbuf, MAXPATHLEN);
			error = EINVAL;
			break;
		}
		cptr = STRUCT_FGETP(tagdesc, mtd_tag);
		if ((error = copyinstr(cptr, tagbuf, MAX_MNTOPT_TAG, &len))) {
			kmem_free(pbuf, MAXPATHLEN);
			break;
		}
		major = STRUCT_FGET(tagdesc, mtd_major);
		minor = STRUCT_FGET(tagdesc, mtd_minor);
		if (cmd == MNTIOC_SETTAG)
			error = vfs_settag(major, minor, pbuf, tagbuf, cr);
		else
			error = vfs_clrtag(major, minor, pbuf, tagbuf, cr);
		kmem_free(pbuf, MAXPATHLEN);
		break;
	}

	case MNTIOC_SHOWHIDDEN:
	{
		mutex_enter(&vp->v_lock);
		mnp->mnt_flags |= MNT_SHOWHIDDEN;
		mutex_exit(&vp->v_lock);
		break;
	}

	case MNTIOC_GETMNTENT:
	{
		size_t idx;
		uintptr_t addr;

		idx = mnp->mnt_offset;
		if (snap->mnts_count == 0 || idx == 0) {
			if ((error =
			    mntfs_snapshot(mnp, 0, flag & DATAMODEL_MASK)) != 0)
				return (error);
		}
		/*
		 * If the next index is beyond the end of the current mnttab,
		 * return EOF
		 */
		if (idx >= snap->mnts_count) {
			*rvalp = 1;
			return (0);
		}

#ifdef _SYSCALL32_IMPL
		if ((flag & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			addr = (uintptr_t)(snap->mnts_metadata + idx *
			    sizeof (struct extmnttab32));
			error = suword32((void *)arg, addr);
		} else {
#endif
			addr = (uintptr_t)(snap->mnts_metadata + idx *
			    sizeof (struct extmnttab));
			error = sulword((void *)arg, addr);
#ifdef _SYSCALL32_IMPL
		}
#endif

		if (error != 0)
			return (error);

		mnp->mnt_offset++;
		break;
	}

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * /mntfs vnode operations vector
 */
const fs_operation_def_t mnt_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = mntopen },
	VOPNAME_CLOSE,		{ .vop_close = mntclose },
	VOPNAME_READ,		{ .vop_read = mntread },
	VOPNAME_IOCTL,		{ .vop_ioctl = mntioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = mntgetattr },
	VOPNAME_ACCESS,		{ .vop_access = mntaccess },
	VOPNAME_FSYNC,		{ .vop_fsync = mntfsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = mntinactive },
	VOPNAME_SEEK,		{ .vop_seek = mntseek },
	VOPNAME_POLL,		{ .vop_poll = mntpoll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};
