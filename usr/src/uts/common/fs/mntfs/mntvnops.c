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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/time.h>
#include <sys/ksynch.h>
#include <sys/sdt.h>

#define	MNTROOTINO	2

static mntnode_t *mntgetnode(vnode_t *);

vnodeops_t *mntvnodeops;
extern void vfs_mnttab_readop(void);

/*
 * Design of kernel mnttab accounting.
 *
 * mntfs provides two methods of reading the in-kernel mnttab, i.e. the state of
 * the mounted resources: the read-only file /etc/mnttab, and a collection of
 * ioctl() commands. Most of these interfaces are public and are described in
 * mnttab(4). Three private ioctl() commands, MNTIOC_GETMNTENT,
 * MNTIOC_GETEXTMNTENT and MNTIOC_GETMNTANY, provide for the getmntent(3C)
 * family of functions, allowing them to support white space in mount names.
 *
 * A significant feature of mntfs is that it provides a file descriptor with a
 * snapshot once it begins to consume mnttab data. Thus, as the process
 * continues to consume data, its view of the in-kernel mnttab does not change
 * even if resources are mounted or unmounted. The intent is to ensure that
 * processes are guaranteed to read self-consistent data even as the system
 * changes.
 *
 * The snapshot is implemented by a "database", unique to each zone, that
 * comprises a linked list of mntelem_ts. The database is identified by
 * zone_mntfs_db and is protected by zone_mntfs_db_lock. Each element contains
 * the text entry in /etc/mnttab for a mounted resource, i.e. a vfs_t, and is
 * marked with its time of "birth", i.e. creation. An element is "killed", and
 * marked with its time of death, when it is found to be out of date, e.g. when
 * the corresponding resource has been unmounted.
 *
 * When a process performs the first read() or ioctl() for a file descriptor for
 * /etc/mnttab, the database is updated by a call to mntfs_snapshot() to ensure
 * that an element exists for each currently mounted resource. Following this,
 * the current time is written into a snapshot structure, a mntsnap_t, embedded
 * in the descriptor's mntnode_t.
 *
 * mntfs is able to enumerate the /etc/mnttab entries corresponding to a
 * particular file descriptor by searching the database for entries that were
 * born before the appropriate snapshot and that either are still alive or died
 * after the snapshot was created. Consumers use the iterator function
 * mntfs_get_next_elem() to identify the next suitable element in the database.
 *
 * Each snapshot has a hold on its corresponding database elements, effected by
 * a per-element reference count. At last close(), a snapshot is destroyed in
 * mntfs_freesnap() by releasing all of its holds; an element is destroyed if
 * its reference count becomes zero. Therefore the database never exists unless
 * there is at least one active consumer of /etc/mnttab.
 *
 * getmntent(3C) et al. "do not open, close or rewind the file." This implies
 * that getmntent() and read() must be able to operate without interaction on
 * the same file descriptor; this is accomplished by the use of separate
 * mntsnap_ts for both read() and ioctl().
 *
 * mntfs observes the following lock-ordering:
 *
 *	mnp->mnt_contents -> vfslist -> zonep->zone_mntfs_db_lock
 *
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

extern void vfs_mono_time(timespec_t *);
enum { MNTFS_FIRST, MNTFS_SECOND, MNTFS_NEITHER };

/*
 * Determine whether a field within a line from /etc/mnttab contains actual
 * content or simply the marker string "-". This never applies to the time,
 * therefore the delimiter must be a tab.
 */
#define	MNTFS_REAL_FIELD(x)	(*(x) != '-' || *((x) + 1) != '\t')

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

/* Identify which, if either, of two supplied timespec structs is newer. */
static int
mntfs_newest(timespec_t *a, timespec_t *b)
{
	if (a->tv_sec == b->tv_sec &&
	    a->tv_nsec == b->tv_nsec) {
		return (MNTFS_NEITHER);
	} else if (b->tv_sec > a->tv_sec ||
	    (b->tv_sec == a->tv_sec &&
	    b->tv_nsec > a->tv_nsec)) {
		return (MNTFS_SECOND);
	} else {
		return (MNTFS_FIRST);
	}
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

void
mntfs_populate_text(vfs_t *vfsp, zone_t *zonep, mntelem_t *elemp)
{
	struct extmnttab *tabp = &elemp->mnte_tab;
	const char *resource, *mntpt;
	char *cp = elemp->mnte_text;
	mntpt = refstr_value(vfsp->vfs_mntpt);
	resource = refstr_value(vfsp->vfs_resource);

	tabp->mnt_special = 0;
	if (resource != NULL && resource[0] != '\0') {
		if (resource[0] != '/') {
			cp += snprintf(cp, MAXPATHLEN, "%s\t", resource);
		} else if (!ZONE_PATH_VISIBLE(resource, zonep)) {
			/*
			 * Use the mount point as the resource.
			 */
			cp += snprintf(cp, MAXPATHLEN, "%s\t",
			    ZONE_PATH_TRANSLATE(mntpt, zonep));
		} else {
			cp += snprintf(cp, MAXPATHLEN, "%s\t",
			    ZONE_PATH_TRANSLATE(resource, zonep));
		}
	} else {
		cp += snprintf(cp, MAXPATHLEN, "-\t");
	}

	tabp->mnt_mountp = (char *)(cp - elemp->mnte_text);
	if (mntpt != NULL && mntpt[0] != '\0') {
		/*
		 * We know the mount point is visible from within the zone,
		 * otherwise it wouldn't be on the zone's vfs list.
		 */
		cp += snprintf(cp, MAXPATHLEN, "%s\t",
		    ZONE_PATH_TRANSLATE(mntpt, zonep));
	} else {
		cp += snprintf(cp, MAXPATHLEN, "-\t");
	}

	tabp->mnt_fstype = (char *)(cp - elemp->mnte_text);
	cp += snprintf(cp, MAXPATHLEN, "%s\t",
	    vfssw[vfsp->vfs_fstype].vsw_name);

	tabp->mnt_mntopts = (char *)(cp - elemp->mnte_text);
	cp += mntfs_optprint(vfsp, cp);
	*cp++ = '\t';

	tabp->mnt_time = (char *)(cp - elemp->mnte_text);
	cp += snprintf(cp, MAX_MNTOPT_STR, "%ld", vfsp->vfs_mtime);
	*cp++ = '\n'; /* over-write snprintf's trailing null-byte */

	tabp->mnt_major = getmajor(vfsp->vfs_dev);
	tabp->mnt_minor = getminor(vfsp->vfs_dev);

	elemp->mnte_text_size = cp - elemp->mnte_text;
	elemp->mnte_vfs_ctime = vfsp->vfs_hrctime;
	elemp->mnte_hidden = vfsp->vfs_flag & VFS_NOMNTTAB;
}

/* Determine the length of the /etc/mnttab entry for this vfs_t. */
static size_t
mntfs_text_len(vfs_t *vfsp, zone_t *zone)
{
	size_t size = 0;
	const char *resource, *mntpt;
	size_t mntsize;

	mntpt = refstr_value(vfsp->vfs_mntpt);
	if (mntpt != NULL && mntpt[0] != '\0') {
		mntsize = strlen(ZONE_PATH_TRANSLATE(mntpt, zone)) + 1;
	} else {
		mntsize = 2;	/* "-\t" */
	}
	size += mntsize;

	resource = refstr_value(vfsp->vfs_resource);
	if (resource != NULL && resource[0] != '\0') {
		if (resource[0] != '/') {
			size += strlen(resource) + 1;
		} else if (!ZONE_PATH_VISIBLE(resource, zone)) {
			/*
			 * Same as the zone's view of the mount point.
			 */
			size += mntsize;
		} else {
			size += strlen(ZONE_PATH_TRANSLATE(resource, zone)) + 1;
		}
	} else {
		size += 2;	/* "-\t" */
	}
	size += strlen(vfssw[vfsp->vfs_fstype].vsw_name) + 1;
	size += mntfs_optsize(vfsp);
	size += snprintf(NULL, 0, "\t%ld\n", vfsp->vfs_mtime);
	return (size);
}

/* Destroy the resources associated with a snapshot element. */
static void
mntfs_destroy_elem(mntelem_t *elemp)
{
	kmem_free(elemp->mnte_text, elemp->mnte_text_size);
	kmem_free(elemp, sizeof (mntelem_t));
}

/*
 * Return 1 if the given snapshot is in the range of the given element; return
 * 0 otherwise.
 */
static int
mntfs_elem_in_range(mntsnap_t *snapp, mntelem_t *elemp)
{
	timespec_t	*stimep = &snapp->mnts_time;
	timespec_t	*btimep = &elemp->mnte_birth;
	timespec_t	*dtimep = &elemp->mnte_death;

	/*
	 * If a snapshot is in range of an element then the snapshot must have
	 * been created after the birth of the element, and either the element
	 * is still alive or it died after the snapshot was created.
	 */
	if (mntfs_newest(btimep, stimep) == MNTFS_SECOND &&
	    (MNTFS_ELEM_IS_ALIVE(elemp) ||
	    mntfs_newest(stimep, dtimep) == MNTFS_SECOND))
		return (1);
	else
		return (0);
}

/*
 * Return the next valid database element, after the one provided, for a given
 * snapshot; return NULL if none exists. The caller must hold the zone's
 * database lock as a reader before calling this function.
 */
static mntelem_t *
mntfs_get_next_elem(mntsnap_t *snapp, mntelem_t *elemp)
{
	int show_hidden = snapp->mnts_flags & MNTS_SHOWHIDDEN;

	do {
		elemp = elemp->mnte_next;
	} while (elemp &&
	    (!mntfs_elem_in_range(snapp, elemp) ||
	    (!show_hidden && elemp->mnte_hidden)));
	return (elemp);
}

/*
 * This function frees the resources associated with a mntsnap_t. It walks
 * through the database, decrementing the reference count of any element that
 * satisfies the snapshot. If the reference count of an element becomes zero
 * then it is removed from the database.
 */
static void
mntfs_freesnap(mntnode_t *mnp, mntsnap_t *snapp)
{
	zone_t *zonep = MTOD(mnp)->mnt_zone_ref.zref_zone;
	krwlock_t *dblockp = &zonep->zone_mntfs_db_lock;
	mntelem_t **elempp = &zonep->zone_mntfs_db;
	mntelem_t *elemp;
	int show_hidden = snapp->mnts_flags & MNTS_SHOWHIDDEN;
	size_t number_decremented = 0;

	ASSERT(RW_WRITE_HELD(&mnp->mnt_contents));

	/* Ignore an uninitialised snapshot. */
	if (snapp->mnts_nmnts == 0)
		return;

	/* Drop the holds on any matching database elements. */
	rw_enter(dblockp, RW_WRITER);
	while ((elemp = *elempp) != NULL) {
		if (mntfs_elem_in_range(snapp, elemp) &&
		    (!elemp->mnte_hidden || show_hidden) &&
		    ++number_decremented && --elemp->mnte_refcnt == 0) {
			if ((*elempp = elemp->mnte_next) != NULL)
				(*elempp)->mnte_prev = elemp->mnte_prev;
			mntfs_destroy_elem(elemp);
		} else {
			elempp = &elemp->mnte_next;
		}
	}
	rw_exit(dblockp);
	ASSERT(number_decremented == snapp->mnts_nmnts);

	/* Clear the snapshot data. */
	bzero(snapp, sizeof (mntsnap_t));
}

/* Insert the new database element newp after the existing element prevp. */
static void
mntfs_insert_after(mntelem_t *newp, mntelem_t *prevp)
{
	newp->mnte_prev = prevp;
	newp->mnte_next = prevp->mnte_next;
	prevp->mnte_next = newp;
	if (newp->mnte_next != NULL)
		newp->mnte_next->mnte_prev = newp;
}

/* Create and return a copy of a given database element. */
static mntelem_t *
mntfs_copy(mntelem_t *origp)
{
	mntelem_t *copyp;

	copyp = kmem_zalloc(sizeof (mntelem_t), KM_SLEEP);
	copyp->mnte_vfs_ctime = origp->mnte_vfs_ctime;
	copyp->mnte_text_size = origp->mnte_text_size;
	copyp->mnte_text = kmem_alloc(copyp->mnte_text_size, KM_SLEEP);
	bcopy(origp->mnte_text, copyp->mnte_text, copyp->mnte_text_size);
	copyp->mnte_tab = origp->mnte_tab;
	copyp->mnte_hidden = origp->mnte_hidden;

	return (copyp);
}

/*
 * Compare two database elements and determine whether or not the vfs_t payload
 * data of each are the same. Return 1 if so and 0 otherwise.
 */
static int
mntfs_is_same_element(mntelem_t *a, mntelem_t *b)
{
	if (a->mnte_hidden == b->mnte_hidden &&
	    a->mnte_text_size == b->mnte_text_size &&
	    bcmp(a->mnte_text, b->mnte_text, a->mnte_text_size) == 0 &&
	    bcmp(&a->mnte_tab, &b->mnte_tab, sizeof (struct extmnttab)) == 0)
		return (1);
	else
		return (0);
}

/*
 * mntfs_snapshot() updates the database, creating it if necessary, so that it
 * accurately reflects the state of the in-kernel mnttab. It also increments
 * the reference count on all database elements that correspond to currently-
 * mounted resources. Finally, it initialises the appropriate snapshot
 * structure.
 *
 * Each vfs_t is given a high-resolution time stamp, for the benefit of mntfs,
 * when it is inserted into the in-kernel mnttab. This time stamp is copied into
 * the corresponding database element when it is created, allowing the element
 * and the vfs_t to be identified as a pair. It is possible that some file
 * systems may make unadvertised changes to, for example, a resource's mount
 * options. Therefore, in order to determine whether a database element is an
 * up-to-date representation of a given vfs_t, it is compared with a temporary
 * element generated for this purpose. Although less efficient, this is safer
 * than implementing an mtime for a vfs_t.
 *
 * Some mounted resources are marked as "hidden" with a VFS_NOMNTTAB flag. These
 * are considered invisible unless the user has already set the MNT_SHOWHIDDEN
 * flag in the vnode using the MNTIOC_SHOWHIDDEN ioctl.
 */
static void
mntfs_snapshot(mntnode_t *mnp, mntsnap_t *snapp)
{
	mntdata_t	*mnd = MTOD(mnp);
	zone_t		*zonep = mnd->mnt_zone_ref.zref_zone;
	int		is_global_zone = (zonep == global_zone);
	int		show_hidden = mnp->mnt_flags & MNT_SHOWHIDDEN;
	vfs_t		*vfsp, *firstvfsp, *lastvfsp;
	vfs_t		dummyvfs;
	vfs_t		*dummyvfsp = NULL;
	krwlock_t	*dblockp = &zonep->zone_mntfs_db_lock;
	mntelem_t	**headpp = &zonep->zone_mntfs_db;
	mntelem_t	*elemp;
	mntelem_t	*prevp = NULL;
	int		order;
	mntelem_t	*tempelemp;
	mntelem_t	*newp;
	mntelem_t	*firstp = NULL;
	size_t		nmnts = 0;
	size_t		total_text_size = 0;
	size_t		normal_text_size = 0;
	int		insert_before;
	timespec_t	last_mtime;
	size_t		entry_length, new_entry_length;


	ASSERT(RW_WRITE_HELD(&mnp->mnt_contents));
	vfs_list_read_lock();
	vfs_mnttab_modtime(&last_mtime);

	/*
	 * If this snapshot already exists then we must have been asked to
	 * rewind the file, i.e. discard the snapshot and create a new one in
	 * its place. In this case we first see if the in-kernel mnttab has
	 * advertised a change; if not then we simply reinitialise the metadata.
	 */
	if (snapp->mnts_nmnts) {
		if (mntfs_newest(&last_mtime, &snapp->mnts_last_mtime) ==
		    MNTFS_NEITHER) {
			/*
			 * An unchanged mtime is no guarantee that the
			 * in-kernel mnttab is unchanged; for example, a
			 * concurrent remount may be between calls to
			 * vfs_setmntopt_nolock() and vfs_mnttab_modtimeupd().
			 * It follows that the database may have changed, and
			 * in particular that some elements in this snapshot
			 * may have been killed by another call to
			 * mntfs_snapshot(). It is therefore not merely
			 * unnecessary to update the snapshot's time but in
			 * fact dangerous; it needs to be left alone.
			 */
			snapp->mnts_next = snapp->mnts_first;
			snapp->mnts_flags &= ~MNTS_REWIND;
			snapp->mnts_foffset = snapp->mnts_ieoffset = 0;
			vfs_list_unlock();
			return;
		} else {
			mntfs_freesnap(mnp, snapp);
		}
	}

	/*
	 * Create a temporary database element. For each vfs_t, the temporary
	 * element will be populated with the corresponding text. If the vfs_t
	 * does not have a corresponding element within the database, or if
	 * there is such an element but it is stale, a copy of the temporary
	 * element is inserted into the database at the appropriate location.
	 */
	tempelemp = kmem_alloc(sizeof (mntelem_t), KM_SLEEP);
	entry_length = MNT_LINE_MAX;
	tempelemp->mnte_text = kmem_alloc(entry_length, KM_SLEEP);

	/* Find the first and last vfs_t for the given zone. */
	if (is_global_zone) {
		firstvfsp = rootvfs;
		lastvfsp = firstvfsp->vfs_prev;
	} else {
		firstvfsp = zonep->zone_vfslist;
		/*
		 * If there isn't already a vfs_t for root then we create a
		 * dummy which will be used as the head of the list (which will
		 * therefore no longer be circular).
		 */
		if (firstvfsp == NULL ||
		    strcmp(refstr_value(firstvfsp->vfs_mntpt),
		    zonep->zone_rootpath) != 0) {
			/*
			 * The zone's vfs_ts will have mount points relative to
			 * the zone's root path. The vfs_t for the zone's
			 * root file system would therefore have a mount point
			 * equal to the zone's root path. Since the zone's root
			 * path isn't a mount point, we copy the vfs_t of the
			 * zone's root vnode, and provide it with a fake mount
			 * and resource. However, if the zone's root is a
			 * zfs dataset, use the dataset name as the resource.
			 *
			 * Note that by cloning another vfs_t we also acquire
			 * its high-resolution ctime. This might appear to
			 * violate the requirement that the ctimes in the list
			 * of vfs_ts are unique and monotonically increasing;
			 * this is not the case. The dummy vfs_t appears in only
			 * a non-global zone's vfs_t list, where the cloned
			 * vfs_t would not ordinarily be visible; the ctimes are
			 * therefore unique. The zone's root path must be
			 * available before the zone boots, and so its root
			 * vnode's vfs_t's ctime must be lower than those of any
			 * resources subsequently mounted by the zone. The
			 * ctimes are therefore monotonically increasing.
			 */
			dummyvfs = *zonep->zone_rootvp->v_vfsp;
			dummyvfs.vfs_mntpt = refstr_alloc(zonep->zone_rootpath);
			if (strcmp(vfssw[dummyvfs.vfs_fstype].vsw_name, "zfs")
			    != 0)
				dummyvfs.vfs_resource = dummyvfs.vfs_mntpt;
			dummyvfsp = &dummyvfs;
			if (firstvfsp == NULL) {
				lastvfsp = dummyvfsp;
			} else {
				lastvfsp = firstvfsp->vfs_zone_prev;
				dummyvfsp->vfs_zone_next = firstvfsp;
			}
			firstvfsp = dummyvfsp;
		} else {
			lastvfsp = firstvfsp->vfs_zone_prev;
		}
	}

	/*
	 * Now walk through all the vfs_ts for this zone. For each one, find the
	 * corresponding database element, creating it first if necessary, and
	 * increment its reference count.
	 */
	rw_enter(dblockp, RW_WRITER);
	elemp = zonep->zone_mntfs_db;
	/* CSTYLED */
	for (vfsp = firstvfsp;;
	    vfsp = is_global_zone ? vfsp->vfs_next : vfsp->vfs_zone_next) {
		DTRACE_PROBE1(new__vfs, vfs_t *, vfsp);
		/* Consider only visible entries. */
		if ((vfsp->vfs_flag & VFS_NOMNTTAB) == 0 || show_hidden) {
			/*
			 * Walk through the existing database looking for either
			 * an element that matches the current vfs_t, or for the
			 * correct place in which to insert a new element.
			 */
			insert_before = 0;
			for (; elemp; prevp = elemp, elemp = elemp->mnte_next) {
				DTRACE_PROBE1(considering__elem, mntelem_t *,
				    elemp);

				/* Compare the vfs_t with the element. */
				order = mntfs_newest(&elemp->mnte_vfs_ctime,
				    &vfsp->vfs_hrctime);

				/*
				 * If we encounter a database element newer than
				 * this vfs_t then we've stepped over a gap
				 * where the element for this vfs_t must be
				 * inserted.
				 */
				if (order == MNTFS_FIRST) {
					insert_before = 1;
					break;
				}

				/* Dead elements no longer interest us. */
				if (MNTFS_ELEM_IS_DEAD(elemp))
					continue;

				/*
				 * If the time stamps are the same then the
				 * element is potential match for the vfs_t,
				 * although it may later prove to be stale.
				 */
				if (order == MNTFS_NEITHER)
					break;

				/*
				 * This element must be older than the vfs_t.
				 * It must, therefore, correspond to a vfs_t
				 * that has been unmounted. Since the element is
				 * still alive, we kill it if it is visible.
				 */
				if (!elemp->mnte_hidden || show_hidden)
					vfs_mono_time(&elemp->mnte_death);
			}
			DTRACE_PROBE2(possible__match, vfs_t *, vfsp,
			    mntelem_t *, elemp);

			/* Create a new database element if required. */
			new_entry_length = mntfs_text_len(vfsp, zonep);
			if (new_entry_length > entry_length) {
				kmem_free(tempelemp->mnte_text, entry_length);
				tempelemp->mnte_text =
				    kmem_alloc(new_entry_length, KM_SLEEP);
				entry_length = new_entry_length;
			}
			mntfs_populate_text(vfsp, zonep, tempelemp);
			ASSERT(tempelemp->mnte_text_size == new_entry_length);
			if (elemp == NULL) {
				/*
				 * We ran off the end of the database. Insert a
				 * new element at the end.
				 */
				newp = mntfs_copy(tempelemp);
				vfs_mono_time(&newp->mnte_birth);
				if (prevp) {
					mntfs_insert_after(newp, prevp);
				} else {
					newp->mnte_next = NULL;
					newp->mnte_prev = NULL;
					ASSERT(*headpp == NULL);
					*headpp = newp;
				}
				elemp = newp;
			} else if (insert_before) {
				/*
				 * Insert a new element before the current one.
				 */
				newp = mntfs_copy(tempelemp);
				vfs_mono_time(&newp->mnte_birth);
				if (prevp) {
					mntfs_insert_after(newp, prevp);
				} else {
					newp->mnte_next = elemp;
					newp->mnte_prev = NULL;
					elemp->mnte_prev = newp;
					ASSERT(*headpp == elemp);
					*headpp = newp;
				}
				elemp = newp;
			} else if (!mntfs_is_same_element(elemp, tempelemp)) {
				/*
				 * The element corresponds to the vfs_t, but the
				 * vfs_t has changed; it must have been
				 * remounted. Kill the old element and insert a
				 * new one after it.
				 */
				vfs_mono_time(&elemp->mnte_death);
				newp = mntfs_copy(tempelemp);
				vfs_mono_time(&newp->mnte_birth);
				mntfs_insert_after(newp, elemp);
				elemp = newp;
			}

			/* We've found the corresponding element. Hold it. */
			DTRACE_PROBE1(incrementing, mntelem_t *, elemp);
			elemp->mnte_refcnt++;

			/*
			 * Update the parameters used to initialise the
			 * snapshot.
			 */
			nmnts++;
			total_text_size += elemp->mnte_text_size;
			if (!elemp->mnte_hidden)
				normal_text_size += elemp->mnte_text_size;
			if (!firstp)
				firstp = elemp;

			prevp = elemp;
			elemp = elemp->mnte_next;
		}

		if (vfsp == lastvfsp)
			break;
	}

	/*
	 * Any remaining visible database elements that are still alive must be
	 * killed now, because their corresponding vfs_ts must have been
	 * unmounted.
	 */
	for (; elemp; elemp = elemp->mnte_next) {
		if (MNTFS_ELEM_IS_ALIVE(elemp) &&
		    (!elemp->mnte_hidden || show_hidden))
			vfs_mono_time(&elemp->mnte_death);
	}

	/* Initialise the snapshot. */
	vfs_mono_time(&snapp->mnts_time);
	snapp->mnts_last_mtime = last_mtime;
	snapp->mnts_first = snapp->mnts_next = firstp;
	snapp->mnts_flags = show_hidden ? MNTS_SHOWHIDDEN : 0;
	snapp->mnts_nmnts = nmnts;
	snapp->mnts_text_size = total_text_size;
	snapp->mnts_foffset = snapp->mnts_ieoffset = 0;

	/*
	 * Record /etc/mnttab's current size and mtime for possible future use
	 * by mntgetattr().
	 */
	mnd->mnt_size = normal_text_size;
	mnd->mnt_mtime = last_mtime;
	if (show_hidden) {
		mnd->mnt_hidden_size = total_text_size;
		mnd->mnt_hidden_mtime = last_mtime;
	}

	/* Clean up. */
	rw_exit(dblockp);
	vfs_list_unlock();
	if (dummyvfsp != NULL)
		refstr_rele(dummyvfsp->vfs_mntpt);
	kmem_free(tempelemp->mnte_text, entry_length);
	kmem_free(tempelemp, sizeof (mntelem_t));
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
	atomic_inc_32(&MTOD(nmnp)->mnt_nopen);
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
		rw_enter(&mnp->mnt_contents, RW_WRITER);
		mntfs_freesnap(mnp, &mnp->mnt_read);
		mntfs_freesnap(mnp, &mnp->mnt_ioctl);
		rw_exit(&mnp->mnt_contents);
		atomic_dec_32(&MTOD(mnp)->mnt_nopen);
	}
	return (0);
}

/* ARGSUSED */
static int
mntread(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cred, caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);
	zone_t *zonep = MTOD(mnp)->mnt_zone_ref.zref_zone;
	mntsnap_t *snapp = &mnp->mnt_read;
	off_t off = uio->uio_offset;
	size_t len = uio->uio_resid;
	char *bufferp;
	size_t available, copylen;
	size_t written = 0;
	mntelem_t *elemp;
	krwlock_t *dblockp = &zonep->zone_mntfs_db_lock;
	int error = 0;
	off_t	ieoffset;

	rw_enter(&mnp->mnt_contents, RW_WRITER);
	if (snapp->mnts_nmnts == 0 || (off == (off_t)0))
		mntfs_snapshot(mnp, snapp);

	if ((size_t)(off + len) > snapp->mnts_text_size)
		len = snapp->mnts_text_size - off;

	if (off < 0 || len > snapp->mnts_text_size) {
		rw_exit(&mnp->mnt_contents);
		return (EFAULT);
	}

	if (len == 0) {
		rw_exit(&mnp->mnt_contents);
		return (0);
	}

	/*
	 * For the file offset provided, locate the corresponding database
	 * element and calculate the corresponding offset within its text. If
	 * the file offset is the same as that reached during the last read(2)
	 * then use the saved element and intra-element offset.
	 */
	rw_enter(dblockp, RW_READER);
	if (off == 0 || (off == snapp->mnts_foffset)) {
		elemp = snapp->mnts_next;
		ieoffset = snapp->mnts_ieoffset;
	} else {
		off_t total_off;
		/*
		 * Find the element corresponding to the requested file offset
		 * by walking through the database and summing the text sizes
		 * of the individual elements. If the requested file offset is
		 * greater than that reached on the last visit then we can start
		 * at the last seen element; otherwise, we have to start at the
		 * beginning.
		 */
		if (off > snapp->mnts_foffset) {
			elemp = snapp->mnts_next;
			total_off = snapp->mnts_foffset - snapp->mnts_ieoffset;
		} else {
			elemp = snapp->mnts_first;
			total_off = 0;
		}
		while (off > total_off + elemp->mnte_text_size) {
			total_off += elemp->mnte_text_size;
			elemp = mntfs_get_next_elem(snapp, elemp);
			ASSERT(elemp != NULL);
		}
		/* Calculate the intra-element offset. */
		if (off > total_off)
			ieoffset = off - total_off;
		else
			ieoffset = 0;
	}

	/*
	 * Create a buffer and populate it with the text from successive
	 * database elements until it is full.
	 */
	bufferp = kmem_alloc(len, KM_SLEEP);
	while (written < len) {
		available = elemp->mnte_text_size - ieoffset;
		copylen = MIN(len - written, available);
		bcopy(elemp->mnte_text + ieoffset, bufferp + written, copylen);
		written += copylen;
		if (copylen == available) {
			elemp = mntfs_get_next_elem(snapp, elemp);
			ASSERT(elemp != NULL || written == len);
			ieoffset = 0;
		} else {
			ieoffset += copylen;
		}
	}
	rw_exit(dblockp);

	/*
	 * Write the populated buffer, update the snapshot's state if
	 * successful and then advertise our read.
	 */
	error = uiomove(bufferp, len, UIO_READ, uio);
	if (error == 0) {
		snapp->mnts_next = elemp;
		snapp->mnts_foffset = off + len;
		snapp->mnts_ieoffset = ieoffset;
	}
	vfs_mnttab_readop();
	rw_exit(&mnp->mnt_contents);

	/* Clean up. */
	kmem_free(bufferp, len);
	return (error);
}

static int
mntgetattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int mask = vap->va_mask;
	int error;
	mntnode_t *mnp = VTOM(vp);
	timespec_t mtime, old_mtime;
	size_t size, old_size;
	mntdata_t *mntdata = MTOD(VTOM(vp));
	mntsnap_t *rsnapp, *isnapp;
	extern timespec_t vfs_mnttab_ctime;


	/* AT_MODE, AT_UID and AT_GID are derived from the underlying file. */
	if (mask & AT_MODE|AT_UID|AT_GID) {
		if (error = VOP_GETATTR(mnp->mnt_mountvp, vap, flags, cr, ct))
			return (error);
	}

	/*
	 * There are some minor subtleties in the determination of
	 * /etc/mnttab's size and mtime. We wish to avoid any condition in
	 * which, in the vicinity of a change to the in-kernel mnttab, we
	 * return an old value for one but a new value for the other. We cannot
	 * simply hold vfslist for the entire calculation because we might need
	 * to call mntfs_snapshot(), which calls vfs_list_read_lock().
	 */
	if (mask & AT_SIZE|AT_NBLOCKS) {
		rw_enter(&mnp->mnt_contents, RW_WRITER);

		vfs_list_read_lock();
		vfs_mnttab_modtime(&mtime);
		if (mnp->mnt_flags & MNT_SHOWHIDDEN) {
			old_mtime = mntdata->mnt_hidden_mtime;
			old_size = mntdata->mnt_hidden_size;
		} else {
			old_mtime = mntdata->mnt_mtime;
			old_size = mntdata->mnt_size;
		}
		vfs_list_unlock();

		rsnapp = &mnp->mnt_read;
		isnapp = &mnp->mnt_ioctl;
		if (rsnapp->mnts_nmnts || isnapp->mnts_nmnts) {
			/*
			 * The mntnode already has at least one snapshot from
			 * which to take the size; the user will understand from
			 * mnttab(4) that the current size of the in-kernel
			 * mnttab is irrelevant.
			 */
			size = rsnapp->mnts_nmnts ? rsnapp->mnts_text_size :
			    isnapp->mnts_text_size;
		} else if (mntfs_newest(&mtime, &old_mtime) == MNTFS_NEITHER) {
			/*
			 * There is no existing valid snapshot but the in-kernel
			 * mnttab has not changed since the time that the last
			 * one was generated. Use the old file size; note that
			 * it is guaranteed to be consistent with mtime, which
			 * may be returned to the user later.
			 */
			size = old_size;
		} else {
			/*
			 * There is no snapshot and the in-kernel mnttab has
			 * changed since the last one was created. We generate a
			 * new snapshot which we use for not only the size but
			 * also the mtime, thereby ensuring that the two are
			 * consistent.
			 */
			mntfs_snapshot(mnp, rsnapp);
			size = rsnapp->mnts_text_size;
			mtime = rsnapp->mnts_last_mtime;
			mntfs_freesnap(mnp, rsnapp);
		}

		rw_exit(&mnp->mnt_contents);
	} else if (mask & AT_ATIME|AT_MTIME) {
		vfs_list_read_lock();
		vfs_mnttab_modtime(&mtime);
		vfs_list_unlock();
	}

	/* Always look like a regular file. */
	if (mask & AT_TYPE)
		vap->va_type = VREG;
	/* Mode should basically be read only. */
	if (mask & AT_MODE)
		vap->va_mode &= 07444;
	if (mask & AT_FSID)
		vap->va_fsid = vp->v_vfsp->vfs_dev;
	/* Nodeid is always ROOTINO. */
	if (mask & AT_NODEID)
		vap->va_nodeid = (ino64_t)MNTROOTINO;
	/*
	 * Set nlink to the number of open vnodes for mnttab info
	 * plus one for existing.
	 */
	if (mask & AT_NLINK)
		vap->va_nlink = mntdata->mnt_nopen + 1;
	if (mask & AT_SIZE)
		vap->va_size = size;
	if (mask & AT_ATIME)
		vap->va_atime = mtime;
	if (mask & AT_MTIME)
		vap->va_mtime = mtime;
	if (mask & AT_CTIME)
		vap->va_ctime = vfs_mnttab_ctime;
	if (mask & AT_RDEV)
		vap->va_rdev = 0;
	if (mask & AT_BLKSIZE)
		vap->va_blksize = DEV_BSIZE;
	if (mask & AT_NBLOCKS)
		vap->va_nblocks = btod(size);
	if (mask & AT_SEQ)
		vap->va_seq = 0;

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
	rw_init(&mnp->mnt_contents, NULL, RW_DEFAULT, NULL);
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

	rw_destroy(&mnp->mnt_contents);
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

/*
 * lseek(2) is supported only to rewind the file by resetmnttab(3C). Rewinding
 * has a special meaning for /etc/mnttab: it forces mntfs to refresh the
 * snapshot at the next ioctl().
 *
 * mnttab(4) explains that "the snapshot...is taken any time a read(2) is
 * performed at offset 0". We therefore ignore the read snapshot here.
 */
/* ARGSUSED */
static int
mntseek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	mntnode_t *mnp = VTOM(vp);

	if (*noffp == 0) {
		rw_enter(&mnp->mnt_contents, RW_WRITER);
		mnp->mnt_ioctl.mnts_flags |= MNTS_REWIND;
		rw_exit(&mnp->mnt_contents);
	}

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
	mntsnap_t *snapp;

	rw_enter(&mnp->mnt_contents, RW_READER);
	if (mntfs_newest(&mnp->mnt_ioctl.mnts_last_mtime,
	    &mnp->mnt_read.mnts_last_mtime) == MNTFS_FIRST)
		snapp = &mnp->mnt_ioctl;
	else
		snapp = &mnp->mnt_read;

	*revp = 0;
	*phpp = (pollhead_t *)NULL;
	if (ev & POLLIN)
		*revp |= POLLIN;

	if (ev & POLLRDNORM)
		*revp |= POLLRDNORM;

	if (ev & POLLRDBAND) {
		vfs_mnttab_poll(&snapp->mnts_last_mtime, phpp);
		if (*phpp == (pollhead_t *)NULL)
			*revp |= POLLRDBAND;
	}
	rw_exit(&mnp->mnt_contents);

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

/*
 * mntfs_same_word() returns 1 if two words are the same in the context of
 * MNTIOC_GETMNTANY and 0 otherwise.
 *
 * worda is a memory address that lies somewhere in the buffer bufa; it cannot
 * be NULL since this is used to indicate to getmntany(3C) that the user does
 * not wish to match a particular field. The text to which worda points is
 * supplied by the user; if it is not null-terminated then it cannot match.
 *
 * Buffer bufb contains a line from /etc/mnttab, in which the fields are
 * delimited by tab or new-line characters. offb is the offset of the second
 * word within this buffer.
 *
 * mntfs_same_word() returns 1 if the words are the same and 0 otherwise.
 */
int
mntfs_same_word(char *worda, char *bufa, size_t sizea, off_t offb, char *bufb,
    size_t sizeb)
{
	char *wordb = bufb + offb;
	int bytes_remaining;

	ASSERT(worda != NULL);

	bytes_remaining = MIN(((bufa + sizea) - worda),
	    ((bufb + sizeb) - wordb));
	while (bytes_remaining && *worda == *wordb) {
		worda++;
		wordb++;
		bytes_remaining--;
	}
	if (bytes_remaining &&
	    *worda == '\0' && (*wordb == '\t' || *wordb == '\n'))
		return (1);
	else
		return (0);
}

/*
 * mntfs_special_info_string() returns which, if either, of VBLK or VCHR
 * corresponds to a supplied path. If the path is a special device then the
 * function optionally sets the major and minor numbers.
 */
vtype_t
mntfs_special_info_string(char *path, uint_t *major, uint_t *minor, cred_t *cr)
{
	vattr_t vattr;
	vnode_t *vp;
	vtype_t type;
	int error;

	if (path == NULL || *path != '/' ||
	    lookupnameat(path + 1, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp, rootdir))
		return (0);

	vattr.va_mask = AT_TYPE | AT_RDEV;
	error = VOP_GETATTR(vp, &vattr, ATTR_REAL, cr, NULL);
	VN_RELE(vp);

	if (error == 0 && ((type = vattr.va_type) == VBLK || type == VCHR)) {
		if (major && minor) {
			*major = getmajor(vattr.va_rdev);
			*minor = getminor(vattr.va_rdev);
		}
		return (type);
	} else {
		return (0);
	}
}

/*
 * mntfs_special_info_element() extracts the name of the mounted resource
 * for a given element and copies it into a null-terminated string, which it
 * then passes to mntfs_special_info_string().
 */
vtype_t
mntfs_special_info_element(mntelem_t *elemp, cred_t *cr)
{
	char *newpath;
	vtype_t type;

	newpath = kmem_alloc(elemp->mnte_text_size, KM_SLEEP);
	bcopy(elemp->mnte_text, newpath, (off_t)(elemp->mnte_tab.mnt_mountp));
	*(newpath + (off_t)elemp->mnte_tab.mnt_mountp - 1) = '\0';
	type = mntfs_special_info_string(newpath, NULL, NULL, cr);
	kmem_free(newpath, elemp->mnte_text_size);

	return (type);
}

/*
 * Convert an address that points to a byte within a user buffer into an
 * address that points to the corresponding offset within a kernel buffer. If
 * the user address is NULL then make no conversion. If the address does not
 * lie within the buffer then reset it to NULL.
 */
char *
mntfs_import_addr(char *uaddr, char *ubufp, char *kbufp, size_t bufsize)
{
	if (uaddr < ubufp || uaddr >= ubufp + bufsize)
		return (NULL);
	else
		return (kbufp + (uaddr - ubufp));
}

/*
 * These 32-bit versions are to support STRUCT_DECL(9F) etc. in
 * mntfs_copyout_element() and mntioctl().
 */
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

typedef struct mnttab32 {
	uint32_t	mnt_special;
	uint32_t	mnt_mountp;
	uint32_t	mnt_fstype;
	uint32_t	mnt_mntopts;
	uint32_t	mnt_time;
} mnttab32_t;

struct mntentbuf32 {
	uint32_t	mbuf_emp;
	uint_t		mbuf_bufsize;
	uint32_t	mbuf_buf;
};
#endif

/*
 * mntfs_copyout_element() is common code for the MNTIOC_GETMNTENT,
 * MNTIOC_GETEXTMNTENT and MNTIOC_GETMNTANY ioctls. Having identifed the
 * database element desired by the user, this function copies out the text and
 * the pointers to the relevant userland addresses. It returns 0 on success
 * and non-zero otherwise.
 */
int
mntfs_copyout_elem(mntelem_t *elemp, struct extmnttab *uemp,
    char *ubufp, int cmd, int datamodel)
{
		STRUCT_DECL(extmnttab, ktab);
		char *dbbufp = elemp->mnte_text;
		size_t dbbufsize = elemp->mnte_text_size;
		struct extmnttab *dbtabp = &elemp->mnte_tab;
		size_t ssize;
		char *kbufp;
		int error = 0;


		/*
		 * We create a struct extmnttab within the kernel of the size
		 * determined by the user's data model. We then populate its
		 * fields by combining the start address of the text buffer
		 * supplied by the user, ubufp, with the offsets stored for
		 * this database element within dbtabp, a pointer to a struct
		 * extmnttab.
		 *
		 * Note that if the corresponding field is "-" this signifies
		 * no real content, and we set the address to NULL. This does
		 * not apply to mnt_time.
		 */
		STRUCT_INIT(ktab, datamodel);
		STRUCT_FSETP(ktab, mnt_special,
		    MNTFS_REAL_FIELD(dbbufp) ? ubufp : NULL);
		STRUCT_FSETP(ktab, mnt_mountp,
		    MNTFS_REAL_FIELD(dbbufp + (off_t)dbtabp->mnt_mountp) ?
		    ubufp + (off_t)dbtabp->mnt_mountp : NULL);
		STRUCT_FSETP(ktab, mnt_fstype,
		    MNTFS_REAL_FIELD(dbbufp + (off_t)dbtabp->mnt_fstype) ?
		    ubufp + (off_t)dbtabp->mnt_fstype : NULL);
		STRUCT_FSETP(ktab, mnt_mntopts,
		    MNTFS_REAL_FIELD(dbbufp + (off_t)dbtabp->mnt_mntopts) ?
		    ubufp + (off_t)dbtabp->mnt_mntopts : NULL);
		STRUCT_FSETP(ktab, mnt_time,
		    ubufp + (off_t)dbtabp->mnt_time);
		if (cmd == MNTIOC_GETEXTMNTENT) {
			STRUCT_FSETP(ktab, mnt_major, dbtabp->mnt_major);
			STRUCT_FSETP(ktab, mnt_minor, dbtabp->mnt_minor);
			ssize = SIZEOF_STRUCT(extmnttab, datamodel);
		} else {
			ssize = SIZEOF_STRUCT(mnttab, datamodel);
		}
		if (copyout(STRUCT_BUF(ktab), uemp, ssize))
			return (EFAULT);

		/*
		 * We create a text buffer in the kernel into which we copy the
		 * /etc/mnttab entry for this element. We change the tab and
		 * new-line delimiters to null bytes before copying out the
		 * buffer.
		 */
		kbufp = kmem_alloc(dbbufsize, KM_SLEEP);
		bcopy(elemp->mnte_text, kbufp, dbbufsize);
		*(kbufp + (off_t)dbtabp->mnt_mountp - 1) =
		    *(kbufp + (off_t)dbtabp->mnt_fstype - 1) =
		    *(kbufp + (off_t)dbtabp->mnt_mntopts - 1) =
		    *(kbufp + (off_t)dbtabp->mnt_time - 1) =
		    *(kbufp + dbbufsize - 1) = '\0';
		if (copyout(kbufp, ubufp, dbbufsize))
			error = EFAULT;

		kmem_free(kbufp, dbbufsize);
		return (error);
}

/* ARGSUSED */
static int
mntioctl(struct vnode *vp, int cmd, intptr_t arg, int flag, cred_t *cr,
    int *rvalp, caller_context_t *ct)
{
	uint_t *up = (uint_t *)arg;
	mntnode_t *mnp = VTOM(vp);
	mntsnap_t *snapp = &mnp->mnt_ioctl;
	int error = 0;
	zone_t *zonep = MTOD(mnp)->mnt_zone_ref.zref_zone;
	krwlock_t *dblockp = &zonep->zone_mntfs_db_lock;
	model_t datamodel = flag & DATAMODEL_MASK;

	switch (cmd) {

	case MNTIOC_NMNTS:  		/* get no. of mounted resources */
	{
		rw_enter(&mnp->mnt_contents, RW_READER);
		if (snapp->mnts_nmnts == 0 ||
		    (snapp->mnts_flags & MNTS_REWIND)) {
			if (!rw_tryupgrade(&mnp->mnt_contents)) {
				rw_exit(&mnp->mnt_contents);
				rw_enter(&mnp->mnt_contents, RW_WRITER);
			}
			if (snapp->mnts_nmnts == 0 ||
			    (snapp->mnts_flags & MNTS_REWIND))
				mntfs_snapshot(mnp, snapp);
		}
		rw_exit(&mnp->mnt_contents);

		if (suword32(up, snapp->mnts_nmnts) != 0)
			error = EFAULT;
		break;
	}

	case MNTIOC_GETDEVLIST:  	/* get mounted device major/minor nos */
	{
		size_t len;
		uint_t *devlist;
		mntelem_t *elemp;
		int i = 0;

		rw_enter(&mnp->mnt_contents, RW_READER);
		if (snapp->mnts_nmnts == 0 ||
		    (snapp->mnts_flags & MNTS_REWIND)) {
			if (!rw_tryupgrade(&mnp->mnt_contents)) {
				rw_exit(&mnp->mnt_contents);
				rw_enter(&mnp->mnt_contents, RW_WRITER);
			}
			if (snapp->mnts_nmnts == 0 ||
			    (snapp->mnts_flags & MNTS_REWIND))
				mntfs_snapshot(mnp, snapp);
			rw_downgrade(&mnp->mnt_contents);
		}

		/* Create a local buffer to hold the device numbers. */
		len = 2 * snapp->mnts_nmnts * sizeof (uint_t);
		devlist = kmem_alloc(len, KM_SLEEP);

		/*
		 * Walk the database elements for this snapshot and add their
		 * major and minor numbers.
		 */
		rw_enter(dblockp, RW_READER);
		for (elemp = snapp->mnts_first; elemp;
		    elemp = mntfs_get_next_elem(snapp, elemp)) {
				devlist[2 * i] = elemp->mnte_tab.mnt_major;
				devlist[2 * i + 1] = elemp->mnte_tab.mnt_minor;
				i++;
		}
		rw_exit(dblockp);
		ASSERT(i == snapp->mnts_nmnts);
		rw_exit(&mnp->mnt_contents);

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
		zone_t *zone = mntdata->mnt_zone_ref.zref_zone;

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
		rw_enter(&mnp->mnt_contents, RW_WRITER);
		mnp->mnt_flags |= MNT_SHOWHIDDEN;
		rw_exit(&mnp->mnt_contents);
		break;
	}

	case MNTIOC_GETMNTANY:
	{
		STRUCT_DECL(mntentbuf, embuf);	/* Our copy of user's embuf */
		STRUCT_DECL(extmnttab, ktab);	/* Out copy of user's emp */
		struct extmnttab *uemp;		/* uaddr of user's emp */
		char *ubufp;			/* uaddr of user's text buf */
		size_t ubufsize;		/* size of the above */
		struct extmnttab preftab;	/* our version of user's emp */
		char *prefbuf;			/* our copy of user's text */
		mntelem_t *elemp;		/* a database element */
		struct extmnttab *dbtabp;	/* element's extmnttab */
		char *dbbufp;			/* element's text buf */
		size_t dbbufsize;		/* size of the above */
		vtype_t type;			/* type, if any, of special */


		/*
		 * embuf is a struct embuf within the kernel. We copy into it
		 * the struct embuf supplied by the user.
		 */
		STRUCT_INIT(embuf, datamodel);
		if (copyin((void *) arg, STRUCT_BUF(embuf),
		    STRUCT_SIZE(embuf))) {
			error = EFAULT;
			break;
		}
		uemp = STRUCT_FGETP(embuf, mbuf_emp);
		ubufp = STRUCT_FGETP(embuf, mbuf_buf);
		ubufsize = STRUCT_FGET(embuf, mbuf_bufsize);

		/*
		 * Check that the text buffer offered by the user is the
		 * agreed size.
		 */
		if (ubufsize != MNT_LINE_MAX) {
			error = EINVAL;
			break;
		}

		/* Copy the user-supplied entry into a local buffer. */
		prefbuf = kmem_alloc(MNT_LINE_MAX, KM_SLEEP);
		if (copyin(ubufp, prefbuf, MNT_LINE_MAX)) {
			kmem_free(prefbuf, MNT_LINE_MAX);
			error = EFAULT;
			break;
		}

		/* Ensure that any string within it is null-terminated. */
		*(prefbuf + MNT_LINE_MAX - 1) = 0;

		/* Copy in the user-supplied mpref */
		STRUCT_INIT(ktab, datamodel);
		if (copyin(uemp, STRUCT_BUF(ktab),
		    SIZEOF_STRUCT(mnttab, datamodel))) {
			kmem_free(prefbuf, MNT_LINE_MAX);
			error = EFAULT;
			break;
		}

		/*
		 * Copy the members of the user's pref struct into a local
		 * struct. The pointers need to be offset and verified to
		 * ensure that they lie within the bounds of the buffer.
		 */
		preftab.mnt_special = mntfs_import_addr(STRUCT_FGETP(ktab,
		    mnt_special), ubufp, prefbuf, MNT_LINE_MAX);
		preftab.mnt_mountp = mntfs_import_addr(STRUCT_FGETP(ktab,
		    mnt_mountp), ubufp, prefbuf, MNT_LINE_MAX);
		preftab.mnt_fstype = mntfs_import_addr(STRUCT_FGETP(ktab,
		    mnt_fstype), ubufp, prefbuf, MNT_LINE_MAX);
		preftab.mnt_mntopts = mntfs_import_addr(STRUCT_FGETP(ktab,
		    mnt_mntopts), ubufp, prefbuf, MNT_LINE_MAX);
		preftab.mnt_time = mntfs_import_addr(STRUCT_FGETP(ktab,
		    mnt_time), ubufp, prefbuf, MNT_LINE_MAX);

		/*
		 * If the user specifies a mounted resource that is a special
		 * device then we capture its mode and major and minor numbers;
		 * cf. the block comment below.
		 */
		type = mntfs_special_info_string(preftab.mnt_special,
		    &preftab.mnt_major, &preftab.mnt_minor, cr);

		rw_enter(&mnp->mnt_contents, RW_WRITER);
		if (snapp->mnts_nmnts == 0 ||
		    (snapp->mnts_flags & MNTS_REWIND))
			mntfs_snapshot(mnp, snapp);

		/*
		 * This is the core functionality that implements getmntany().
		 * We walk through the mntfs database until we find an element
		 * matching the user's preferences that are contained in
		 * preftab. Typically, this means checking that the text
		 * matches. However, the mounted resource is special: if the
		 * user is looking for a special device then we must find a
		 * database element with the same major and minor numbers and
		 * the same type, i.e. VBLK or VCHR. The type is not recorded
		 * in the element because it cannot be inferred from the vfs_t.
		 * We therefore check the type of suitable candidates via
		 * mntfs_special_info_element(); since this calls into the
		 * underlying file system we make sure to drop the database lock
		 * first.
		 */
		elemp = snapp->mnts_next;
		rw_enter(dblockp, RW_READER);
		for (;;) {
			for (; elemp; elemp = mntfs_get_next_elem(snapp,
			    elemp)) {
				dbtabp = &elemp->mnte_tab;
				dbbufp = elemp->mnte_text;
				dbbufsize = elemp->mnte_text_size;

				if (((type &&
				    dbtabp->mnt_major == preftab.mnt_major &&
				    dbtabp->mnt_minor == preftab.mnt_minor &&
				    MNTFS_REAL_FIELD(dbbufp)) ||
				    (!type && (!preftab.mnt_special ||
				    mntfs_same_word(preftab.mnt_special,
				    prefbuf, MNT_LINE_MAX, (off_t)0, dbbufp,
				    dbbufsize)))) &&

				    (!preftab.mnt_mountp || mntfs_same_word(
				    preftab.mnt_mountp, prefbuf, MNT_LINE_MAX,
				    (off_t)dbtabp->mnt_mountp, dbbufp,
				    dbbufsize)) &&

				    (!preftab.mnt_fstype || mntfs_same_word(
				    preftab.mnt_fstype, prefbuf, MNT_LINE_MAX,
				    (off_t)dbtabp->mnt_fstype, dbbufp,
				    dbbufsize)) &&

				    (!preftab.mnt_mntopts || mntfs_same_word(
				    preftab.mnt_mntopts, prefbuf, MNT_LINE_MAX,
				    (off_t)dbtabp->mnt_mntopts, dbbufp,
				    dbbufsize)) &&

				    (!preftab.mnt_time || mntfs_same_word(
				    preftab.mnt_time, prefbuf, MNT_LINE_MAX,
				    (off_t)dbtabp->mnt_time, dbbufp,
				    dbbufsize)))
					break;
			}
			rw_exit(dblockp);

			if (elemp == NULL || type == 0 ||
			    type == mntfs_special_info_element(elemp, cr))
				break;

			rw_enter(dblockp, RW_READER);
			elemp = mntfs_get_next_elem(snapp, elemp);
		}

		kmem_free(prefbuf, MNT_LINE_MAX);

		/* If we failed to find a match then return EOF. */
		if (elemp == NULL) {
			rw_exit(&mnp->mnt_contents);
			*rvalp = MNTFS_EOF;
			break;
		}

		/*
		 * Check that the text buffer offered by the user will be large
		 * enough to accommodate the text for this entry.
		 */
		if (elemp->mnte_text_size > MNT_LINE_MAX) {
			rw_exit(&mnp->mnt_contents);
			*rvalp = MNTFS_TOOLONG;
			break;
		}

		/*
		 * Populate the user's struct mnttab and text buffer using the
		 * element's contents.
		 */
		if (mntfs_copyout_elem(elemp, uemp, ubufp, cmd, datamodel)) {
			error = EFAULT;
		} else {
			rw_enter(dblockp, RW_READER);
			elemp = mntfs_get_next_elem(snapp, elemp);
			rw_exit(dblockp);
			snapp->mnts_next = elemp;
		}
		rw_exit(&mnp->mnt_contents);
		break;
	}

	case MNTIOC_GETMNTENT:
	case MNTIOC_GETEXTMNTENT:
	{
		STRUCT_DECL(mntentbuf, embuf);	/* Our copy of user's embuf */
		struct extmnttab *uemp;		/* uaddr of user's emp */
		char *ubufp;			/* uaddr of user's text buf */
		size_t ubufsize;		/* size of the above */
		mntelem_t *elemp;		/* a database element */


		rw_enter(&mnp->mnt_contents, RW_WRITER);
		if (snapp->mnts_nmnts == 0 ||
		    (snapp->mnts_flags & MNTS_REWIND))
			mntfs_snapshot(mnp, snapp);
		if ((elemp = snapp->mnts_next) == NULL) {
			rw_exit(&mnp->mnt_contents);
			*rvalp = MNTFS_EOF;
			break;
		}

		/*
		 * embuf is a struct embuf within the kernel. We copy into it
		 * the struct embuf supplied by the user.
		 */
		STRUCT_INIT(embuf, datamodel);
		if (copyin((void *) arg, STRUCT_BUF(embuf),
		    STRUCT_SIZE(embuf))) {
			rw_exit(&mnp->mnt_contents);
			error = EFAULT;
			break;
		}
		uemp = STRUCT_FGETP(embuf, mbuf_emp);
		ubufp = STRUCT_FGETP(embuf, mbuf_buf);
		ubufsize = STRUCT_FGET(embuf, mbuf_bufsize);

		/*
		 * Check that the text buffer offered by the user will be large
		 * enough to accommodate the text for this entry.
		 */
		if (elemp->mnte_text_size > ubufsize) {
			rw_exit(&mnp->mnt_contents);
			*rvalp = MNTFS_TOOLONG;
			break;
		}

		/*
		 * Populate the user's struct mnttab and text buffer using the
		 * element's contents.
		 */
		if (mntfs_copyout_elem(elemp, uemp, ubufp, cmd, datamodel)) {
			error = EFAULT;
		} else {
			rw_enter(dblockp, RW_READER);
			elemp = mntfs_get_next_elem(snapp, elemp);
			rw_exit(dblockp);
			snapp->mnts_next = elemp;
		}
		rw_exit(&mnp->mnt_contents);
		break;
	}

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * mntfs provides a new vnode for each open(2). Two vnodes will represent the
 * same instance of /etc/mnttab if they share the same (zone-specific) vfs.
 */
/* ARGSUSED */
int
mntcmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	return (vp1 != NULL && vp2 != NULL && vp1->v_vfsp == vp2->v_vfsp);
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
	VOPNAME_CMP,		{ .vop_cmp = mntcmp },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};
