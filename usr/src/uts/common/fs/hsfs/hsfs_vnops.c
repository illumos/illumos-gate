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
 * Vnode operations for the High Sierra filesystem
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/fbuf.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/dkio.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/page.h>
#include <sys/swap.h>
#include <sys/avl.h>
#include <sys/sunldi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>

/*
 * For struct modlinkage
 */
#include <sys/modctl.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include <fs/fs_subr.h>

/* # of contiguous requests to detect sequential access pattern */
static int seq_contig_requests = 2;

/*
 * This is the max number os taskq threads that will be created
 * if required. Since we are using a Dynamic TaskQ by default only
 * one thread is created initially.
 *
 * NOTE: In the usual hsfs use case this per fs instance number
 * of taskq threads should not place any undue load on a system.
 * Even on an unusual system with say 100 CDROM drives, 800 threads
 * will not be created unless all the drives are loaded and all
 * of them are saturated with I/O at the same time! If there is at
 * all a complaint of system load due to such an unusual case it
 * should be easy enough to change to one per-machine Dynamic TaskQ
 * for all hsfs mounts with a nthreads of say 32.
 */
static int hsfs_taskq_nthreads = 8;	/* # of taskq threads per fs */

/* Min count of adjacent bufs that will avoid buf coalescing */
static int hsched_coalesce_min = 2;

/*
 * Kmem caches for heavily used small allocations. Using these kmem
 * caches provides a factor of 3 reduction in system time and greatly
 * aids overall throughput esp. on SPARC.
 */
struct kmem_cache *hio_cache;
struct kmem_cache *hio_info_cache;

/*
 * This tunable allows us to ignore inode numbers from rrip-1.12.
 * In this case, we fall back to our default inode algorithm.
 */
extern int use_rrip_inodes;

/*
 * Free behind logic from UFS to tame our thirst for
 * the page cache.
 * See usr/src/uts/common/fs/ufs/ufs_vnops.c for more
 * explanation.
 */
static int	freebehind = 1;
static int	smallfile = 0;
static int	cache_read_ahead = 0;
static u_offset_t smallfile64 = 32 * 1024;
#define	SMALLFILE1_D 1000
#define	SMALLFILE2_D 10
static u_offset_t smallfile1 = 32 * 1024;
static u_offset_t smallfile2 = 32 * 1024;
static clock_t smallfile_update = 0; /* when to recompute */
static uint_t smallfile1_d = SMALLFILE1_D;
static uint_t smallfile2_d = SMALLFILE2_D;

static int hsched_deadline_compare(const void *x1, const void *x2);
static int hsched_offset_compare(const void *x1, const void *x2);
static void hsched_enqueue_io(struct hsfs *fsp, struct hio *hsio, int ra);
int hsched_invoke_strategy(struct hsfs *fsp);

/* ARGSUSED */
static int
hsfs_fsync(vnode_t *cp,
	int syncflag,
	cred_t *cred,
	caller_context_t *ct)
{
	return (0);
}


/*ARGSUSED*/
static int
hsfs_read(struct vnode *vp,
	struct uio *uiop,
	int ioflag,
	struct cred *cred,
	struct caller_context *ct)
{
	caddr_t base;
	offset_t diff;
	int error;
	struct hsnode *hp;
	uint_t filesize;
	int dofree;

	hp = VTOH(vp);
	/*
	 * if vp is of type VDIR, make sure dirent
	 * is filled up with all info (because of ptbl)
	 */
	if (vp->v_type == VDIR) {
		if (hp->hs_dirent.ext_size == 0)
			hs_filldirent(vp, &hp->hs_dirent);
	}
	filesize = hp->hs_dirent.ext_size;

	/* Sanity checks. */
	if (uiop->uio_resid == 0 ||		/* No data wanted. */
	    uiop->uio_loffset > HS_MAXFILEOFF ||	/* Offset too big. */
	    uiop->uio_loffset >= filesize)	/* Past EOF. */
		return (0);

	do {
		/*
		 * We want to ask for only the "right" amount of data.
		 * In this case that means:-
		 *
		 * We can't get data from beyond our EOF. If asked,
		 * we will give a short read.
		 *
		 * segmap_getmapflt returns buffers of MAXBSIZE bytes.
		 * These buffers are always MAXBSIZE aligned.
		 * If our starting offset is not MAXBSIZE aligned,
		 * we can only ask for less than MAXBSIZE bytes.
		 *
		 * If our requested offset and length are such that
		 * they belong in different MAXBSIZE aligned slots
		 * then we'll be making more than one call on
		 * segmap_getmapflt.
		 *
		 * This diagram shows the variables we use and their
		 * relationships.
		 *
		 * |<-----MAXBSIZE----->|
		 * +--------------------------...+
		 * |.....mapon->|<--n-->|....*...|EOF
		 * +--------------------------...+
		 * uio_loffset->|
		 * uio_resid....|<---------->|
		 * diff.........|<-------------->|
		 *
		 * So, in this case our offset is not aligned
		 * and our request takes us outside of the
		 * MAXBSIZE window. We will break this up into
		 * two segmap_getmapflt calls.
		 */
		size_t nbytes;
		offset_t mapon;
		size_t n;
		uint_t flags;

		mapon = uiop->uio_loffset & MAXBOFFSET;
		diff = filesize - uiop->uio_loffset;
		nbytes = (size_t)MIN(MAXBSIZE - mapon, uiop->uio_resid);
		n = MIN(diff, nbytes);
		if (n <= 0) {
			/* EOF or request satisfied. */
			return (0);
		}

		/*
		 * Freebehind computation taken from:
		 * usr/src/uts/common/fs/ufs/ufs_vnops.c
		 */
		if (drv_hztousec(ddi_get_lbolt()) >= smallfile_update) {
			uint64_t percpufreeb;
			if (smallfile1_d == 0) smallfile1_d = SMALLFILE1_D;
			if (smallfile2_d == 0) smallfile2_d = SMALLFILE2_D;
			percpufreeb = ptob((uint64_t)freemem) / ncpus_online;
			smallfile1 = percpufreeb / smallfile1_d;
			smallfile2 = percpufreeb / smallfile2_d;
			smallfile1 = MAX(smallfile1, smallfile);
			smallfile1 = MAX(smallfile1, smallfile64);
			smallfile2 = MAX(smallfile1, smallfile2);
			smallfile_update = drv_hztousec(ddi_get_lbolt())
			    + 1000000;
		}

		dofree = freebehind &&
		    hp->hs_prev_offset == uiop->uio_loffset &&
		    hp->hs_ra_bytes > 0;

		base = segmap_getmapflt(segkmap, vp,
		    (u_offset_t)uiop->uio_loffset, n, 1, S_READ);

		error = uiomove(base + mapon, n, UIO_READ, uiop);

		if (error == 0) {
			/*
			 * if read a whole block, or read to eof,
			 *  won't need this buffer again soon.
			 */
			if (n + mapon == MAXBSIZE ||
			    uiop->uio_loffset == filesize)
				flags = SM_DONTNEED;
			else
				flags = 0;

			if (dofree) {
				flags = SM_FREE | SM_ASYNC;
				if ((cache_read_ahead == 0) &&
				    uiop->uio_loffset > smallfile2)
					flags |=  SM_DONTNEED;
			}

			error = segmap_release(segkmap, base, flags);
		} else
			(void) segmap_release(segkmap, base, 0);
	} while (error == 0 && uiop->uio_resid > 0);

	return (error);
}

/*ARGSUSED2*/
static int
hsfs_getattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct hsnode *hp;
	struct vfs *vfsp;
	struct hsfs *fsp;

	hp = VTOH(vp);
	fsp = VFS_TO_HSFS(vp->v_vfsp);
	vfsp = vp->v_vfsp;

	if ((hp->hs_dirent.ext_size == 0) && (vp->v_type == VDIR)) {
		hs_filldirent(vp, &hp->hs_dirent);
	}
	vap->va_type = IFTOVT(hp->hs_dirent.mode);
	vap->va_mode = hp->hs_dirent.mode;
	vap->va_uid = hp->hs_dirent.uid;
	vap->va_gid = hp->hs_dirent.gid;

	vap->va_fsid = vfsp->vfs_dev;
	vap->va_nodeid = (ino64_t)hp->hs_nodeid;
	vap->va_nlink = hp->hs_dirent.nlink;
	vap->va_size =	(offset_t)hp->hs_dirent.ext_size;

	vap->va_atime.tv_sec = hp->hs_dirent.adate.tv_sec;
	vap->va_atime.tv_nsec = hp->hs_dirent.adate.tv_usec*1000;
	vap->va_mtime.tv_sec = hp->hs_dirent.mdate.tv_sec;
	vap->va_mtime.tv_nsec = hp->hs_dirent.mdate.tv_usec*1000;
	vap->va_ctime.tv_sec = hp->hs_dirent.cdate.tv_sec;
	vap->va_ctime.tv_nsec = hp->hs_dirent.cdate.tv_usec*1000;
	if (vp->v_type == VCHR || vp->v_type == VBLK)
		vap->va_rdev = hp->hs_dirent.r_dev;
	else
		vap->va_rdev = 0;
	vap->va_blksize = vfsp->vfs_bsize;
	/* no. of blocks = no. of data blocks + no. of xar blocks */
	vap->va_nblocks = (fsblkcnt64_t)howmany(vap->va_size + (u_longlong_t)
	    (hp->hs_dirent.xar_len << fsp->hsfs_vol.lbn_shift), DEV_BSIZE);
	vap->va_seq = hp->hs_seq;
	return (0);
}

/*ARGSUSED*/
static int
hsfs_readlink(struct vnode *vp,
	struct uio *uiop,
	struct cred *cred,
	caller_context_t *ct)
{
	struct hsnode *hp;

	if (vp->v_type != VLNK)
		return (EINVAL);

	hp = VTOH(vp);

	if (hp->hs_dirent.sym_link == (char *)NULL)
		return (ENOENT);

	return (uiomove(hp->hs_dirent.sym_link,
	    (size_t)MIN(hp->hs_dirent.ext_size,
	    uiop->uio_resid), UIO_READ, uiop));
}

/*ARGSUSED*/
static void
hsfs_inactive(struct vnode *vp,
	struct cred *cred,
	caller_context_t *ct)
{
	struct hsnode *hp;
	struct hsfs *fsp;

	int nopage;

	hp = VTOH(vp);
	fsp = VFS_TO_HSFS(vp->v_vfsp);
	/*
	 * Note: acquiring and holding v_lock for quite a while
	 * here serializes on the vnode; this is unfortunate, but
	 * likely not to overly impact performance, as the underlying
	 * device (CDROM drive) is quite slow.
	 */
	rw_enter(&fsp->hsfs_hash_lock, RW_WRITER);
	mutex_enter(&hp->hs_contents_lock);
	mutex_enter(&vp->v_lock);

	if (vp->v_count < 1) {
		panic("hsfs_inactive: v_count < 1");
		/*NOTREACHED*/
	}

	if (vp->v_count > 1 || (hp->hs_flags & HREF) == 0) {
		vp->v_count--;	/* release hold from vn_rele */
		mutex_exit(&vp->v_lock);
		mutex_exit(&hp->hs_contents_lock);
		rw_exit(&fsp->hsfs_hash_lock);
		return;
	}
	vp->v_count--;	/* release hold from vn_rele */
	if (vp->v_count == 0) {
		/*
		 * Free the hsnode.
		 * If there are no pages associated with the
		 * hsnode, give it back to the kmem_cache,
		 * else put at the end of this file system's
		 * internal free list.
		 */
		nopage = !vn_has_cached_data(vp);
		hp->hs_flags = 0;
		/*
		 * exit these locks now, since hs_freenode may
		 * kmem_free the hsnode and embedded vnode
		 */
		mutex_exit(&vp->v_lock);
		mutex_exit(&hp->hs_contents_lock);
		hs_freenode(vp, fsp, nopage);
	} else {
		mutex_exit(&vp->v_lock);
		mutex_exit(&hp->hs_contents_lock);
	}
	rw_exit(&fsp->hsfs_hash_lock);
}


/*ARGSUSED*/
static int
hsfs_lookup(
	struct vnode *dvp,
	char *nm,
	struct vnode **vpp,
	struct pathname *pnp,
	int flags,
	struct vnode *rdir,
	struct cred *cred,
	caller_context_t *ct,
	int *direntflags,
	pathname_t *realpnp)
{
	int error;
	int namelen = (int)strlen(nm);

	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * If we're looking for ourself, life is simple.
	 */
	if (namelen == 1 && *nm == '.') {
		if (error = hs_access(dvp, (mode_t)VEXEC, cred))
			return (error);
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	return (hs_dirlook(dvp, nm, namelen, vpp, cred));
}


/*ARGSUSED*/
static int
hsfs_readdir(
	struct vnode		*vp,
	struct uio		*uiop,
	struct cred		*cred,
	int			*eofp,
	caller_context_t	*ct,
	int			flags)
{
	struct hsnode	*dhp;
	struct hsfs	*fsp;
	struct hs_direntry hd;
	struct dirent64	*nd;
	int		error;
	uint_t		offset;		/* real offset in directory */
	uint_t		dirsiz;		/* real size of directory */
	uchar_t		*blkp;
	int		hdlen;		/* length of hs directory entry */
	long		ndlen;		/* length of dirent entry */
	int		bytes_wanted;
	size_t		bufsize;	/* size of dirent buffer */
	char		*outbuf;	/* ptr to dirent buffer */
	char		*dname;
	int		dnamelen;
	size_t		dname_size;
	struct fbuf	*fbp;
	uint_t		last_offset;	/* last index into current dir block */
	ino64_t		dirino;	/* temporary storage before storing in dirent */
	off_t		diroff;

	dhp = VTOH(vp);
	fsp = VFS_TO_HSFS(vp->v_vfsp);
	if (dhp->hs_dirent.ext_size == 0)
		hs_filldirent(vp, &dhp->hs_dirent);
	dirsiz = dhp->hs_dirent.ext_size;
	if (uiop->uio_loffset >= dirsiz) {	/* at or beyond EOF */
		if (eofp)
			*eofp = 1;
		return (0);
	}
	ASSERT(uiop->uio_loffset <= HS_MAXFILEOFF);
	offset = uiop->uio_loffset;

	dname_size = fsp->hsfs_namemax + 1;	/* 1 for the ending NUL */
	dname = kmem_alloc(dname_size, KM_SLEEP);
	bufsize = uiop->uio_resid + sizeof (struct dirent64);

	outbuf = kmem_alloc(bufsize, KM_SLEEP);
	nd = (struct dirent64 *)outbuf;

	while (offset < dirsiz) {
		bytes_wanted = MIN(MAXBSIZE, dirsiz - (offset & MAXBMASK));

		error = fbread(vp, (offset_t)(offset & MAXBMASK),
		    (unsigned int)bytes_wanted, S_READ, &fbp);
		if (error)
			goto done;

		blkp = (uchar_t *)fbp->fb_addr;
		last_offset = (offset & MAXBMASK) + fbp->fb_count;

#define	rel_offset(offset) ((offset) & MAXBOFFSET)	/* index into blkp */

		while (offset < last_offset) {
			/*
			 * Very similar validation code is found in
			 * process_dirblock(), hsfs_node.c.
			 * For an explanation, see there.
			 * It may make sense for the future to
			 * "consolidate" the code in hs_parsedir(),
			 * process_dirblock() and hsfs_readdir() into
			 * a single utility function.
			 */
			hdlen = (int)((uchar_t)
			    HDE_DIR_LEN(&blkp[rel_offset(offset)]));
			if (hdlen < HDE_ROOT_DIR_REC_SIZE ||
			    offset + hdlen > last_offset) {
				/*
				 * advance to next sector boundary
				 */
				offset = roundup(offset + 1, HS_SECTOR_SIZE);
				if (hdlen)
					hs_log_bogus_disk_warning(fsp,
					    HSFS_ERR_TRAILING_JUNK, 0);

				continue;
			}

			bzero(&hd, sizeof (hd));

			/*
			 * Just ignore invalid directory entries.
			 * XXX - maybe hs_parsedir() will detect EXISTENCE bit
			 */
			if (!hs_parsedir(fsp, &blkp[rel_offset(offset)],
			    &hd, dname, &dnamelen, last_offset - offset)) {
				/*
				 * Determine if there is enough room
				 */
				ndlen = (long)DIRENT64_RECLEN((dnamelen));

				if ((ndlen + ((char *)nd - outbuf)) >
				    uiop->uio_resid) {
					fbrelse(fbp, S_READ);
					goto done; /* output buffer full */
				}

				diroff = offset + hdlen;
				/*
				 * If the media carries rrip-v1.12 or newer,
				 * and we trust the inodes from the rrip data
				 * (use_rrip_inodes != 0), use that data. If the
				 * media has been created by a recent mkisofs
				 * version, we may trust all numbers in the
				 * starting extent number; otherwise, we cannot
				 * do this for zero sized files and symlinks,
				 * because if we did we'd end up mapping all of
				 * them to the same node. We use HS_DUMMY_INO
				 * in this case and make sure that we will not
				 * map all files to the same meta data.
				 */
				if (hd.inode != 0 && use_rrip_inodes) {
					dirino = hd.inode;
				} else if ((hd.ext_size == 0 ||
				    hd.sym_link != (char *)NULL) &&
				    (fsp->hsfs_flags & HSFSMNT_INODE) == 0) {
					dirino = HS_DUMMY_INO;
				} else {
					dirino = hd.ext_lbn;
				}

				/* strncpy(9f) will zero uninitialized bytes */

				ASSERT(strlen(dname) + 1 <=
				    DIRENT64_NAMELEN(ndlen));
				(void) strncpy(nd->d_name, dname,
				    DIRENT64_NAMELEN(ndlen));
				nd->d_reclen = (ushort_t)ndlen;
				nd->d_off = (offset_t)diroff;
				nd->d_ino = dirino;
				nd = (struct dirent64 *)((char *)nd + ndlen);

				/*
				 * free up space allocated for symlink
				 */
				if (hd.sym_link != (char *)NULL) {
					kmem_free(hd.sym_link,
					    (size_t)(hd.ext_size+1));
					hd.sym_link = (char *)NULL;
				}
			}
			offset += hdlen;
		}
		fbrelse(fbp, S_READ);
	}

	/*
	 * Got here for one of the following reasons:
	 *	1) outbuf is full (error == 0)
	 *	2) end of directory reached (error == 0)
	 *	3) error reading directory sector (error != 0)
	 *	4) directory entry crosses sector boundary (error == 0)
	 *
	 * If any directory entries have been copied, don't report
	 * case 4.  Instead, return the valid directory entries.
	 *
	 * If no entries have been copied, report the error.
	 * If case 4, this will be indistiguishable from EOF.
	 */
done:
	ndlen = ((char *)nd - outbuf);
	if (ndlen != 0) {
		error = uiomove(outbuf, (size_t)ndlen, UIO_READ, uiop);
		uiop->uio_loffset = offset;
	}
	kmem_free(dname, dname_size);
	kmem_free(outbuf, bufsize);
	if (eofp && error == 0)
		*eofp = (uiop->uio_loffset >= dirsiz);
	return (error);
}

/*ARGSUSED2*/
static int
hsfs_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct hsnode *hp;
	struct hsfid *fid;

	if (fidp->fid_len < (sizeof (*fid) - sizeof (fid->hf_len))) {
		fidp->fid_len = sizeof (*fid) - sizeof (fid->hf_len);
		return (ENOSPC);
	}

	fid = (struct hsfid *)fidp;
	fid->hf_len = sizeof (*fid) - sizeof (fid->hf_len);
	hp = VTOH(vp);
	mutex_enter(&hp->hs_contents_lock);
	fid->hf_dir_lbn = hp->hs_dir_lbn;
	fid->hf_dir_off = (ushort_t)hp->hs_dir_off;
	fid->hf_ino = hp->hs_nodeid;
	mutex_exit(&hp->hs_contents_lock);
	return (0);
}

/*ARGSUSED*/
static int
hsfs_open(struct vnode **vpp,
	int flag,
	struct cred *cred,
	caller_context_t *ct)
{
	return (0);
}

/*ARGSUSED*/
static int
hsfs_close(
	struct vnode *vp,
	int flag,
	int count,
	offset_t offset,
	struct cred *cred,
	caller_context_t *ct)
{
	(void) cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*ARGSUSED2*/
static int
hsfs_access(struct vnode *vp,
	int mode,
	int flags,
	cred_t *cred,
	caller_context_t *ct)
{
	return (hs_access(vp, (mode_t)mode, cred));
}

/*
 * the seek time of a CD-ROM is very slow, and data transfer
 * rate is even worse (max. 150K per sec).  The design
 * decision is to reduce access to cd-rom as much as possible,
 * and to transfer a sizable block (read-ahead) of data at a time.
 * UFS style of read ahead one block at a time is not appropriate,
 * and is not supported
 */

/*
 * KLUSTSIZE should be a multiple of PAGESIZE and <= MAXPHYS.
 */
#define	KLUSTSIZE	(56 * 1024)
/* we don't support read ahead */
int hsfs_lostpage;	/* no. of times we lost original page */

/*
 * Used to prevent biodone() from releasing buf resources that
 * we didn't allocate in quite the usual way.
 */
/*ARGSUSED*/
int
hsfs_iodone(struct buf *bp)
{
	sema_v(&bp->b_io);
	return (0);
}

/*
 * The taskq thread that invokes the scheduling function to ensure
 * that all readaheads are complete and cleans up the associated
 * memory and releases the page lock.
 */
void
hsfs_ra_task(void *arg)
{
	struct hio_info *info = arg;
	uint_t count;
	struct buf *wbuf;

	ASSERT(info->pp != NULL);

	for (count = 0; count < info->bufsused; count++) {
		wbuf = &(info->bufs[count]);

		DTRACE_PROBE1(hsfs_io_wait_ra, struct buf *, wbuf);
		while (sema_tryp(&(info->sema[count])) == 0) {
			if (hsched_invoke_strategy(info->fsp)) {
				sema_p(&(info->sema[count]));
				break;
			}
		}
		sema_destroy(&(info->sema[count]));
		DTRACE_PROBE1(hsfs_io_done_ra, struct buf *, wbuf);
		biofini(&(info->bufs[count]));
	}
	for (count = 0; count < info->bufsused; count++) {
		if (info->vas[count] != NULL) {
			ppmapout(info->vas[count]);
		}
	}
	kmem_free(info->vas, info->bufcnt * sizeof (caddr_t));
	kmem_free(info->bufs, info->bufcnt * sizeof (struct buf));
	kmem_free(info->sema, info->bufcnt * sizeof (ksema_t));

	pvn_read_done(info->pp, 0);
	kmem_cache_free(hio_info_cache, info);
}

/*
 * Submit asynchronous readahead requests to the I/O scheduler
 * depending on the number of pages to read ahead. These requests
 * are asynchronous to the calling thread but I/O requests issued
 * subsequently by other threads with higher LBNs must wait for
 * these readaheads to complete since we have a single ordered
 * I/O pipeline. Thus these readaheads are semi-asynchronous.
 * A TaskQ handles waiting for the readaheads to complete.
 *
 * This function is mostly a copy of hsfs_getapage but somewhat
 * simpler. A readahead request is aborted if page allocation
 * fails.
 */
/*ARGSUSED*/
static int
hsfs_getpage_ra(
	struct vnode *vp,
	u_offset_t off,
	struct seg *seg,
	caddr_t addr,
	struct hsnode *hp,
	struct hsfs *fsp,
	int	xarsiz,
	offset_t	bof,
	int	chunk_lbn_count,
	int	chunk_data_bytes)
{
	struct buf *bufs;
	caddr_t *vas;
	caddr_t va;
	struct page *pp, *searchp, *lastp;
	struct vnode *devvp;
	ulong_t	byte_offset;
	size_t	io_len_tmp;
	uint_t	io_off, io_len;
	uint_t	xlen;
	uint_t	filsiz;
	uint_t	secsize;
	uint_t	bufcnt;
	uint_t	bufsused;
	uint_t	count;
	uint_t	io_end;
	uint_t	which_chunk_lbn;
	uint_t	offset_lbn;
	uint_t	offset_extra;
	offset_t	offset_bytes;
	uint_t	remaining_bytes;
	uint_t	extension;
	int	remainder;	/* must be signed */
	diskaddr_t driver_block;
	u_offset_t io_off_tmp;
	ksema_t	*fio_done;
	struct hio_info *info;
	size_t len;

	ASSERT(fsp->hqueue != NULL);

	if (addr >= seg->s_base + seg->s_size) {
		return (-1);
	}

	devvp = fsp->hsfs_devvp;
	secsize = fsp->hsfs_vol.lbn_size;  /* bytes per logical block */

	/* file data size */
	filsiz = hp->hs_dirent.ext_size;

	if (off >= filsiz)
		return (0);

	extension = 0;
	pp = NULL;

	extension += hp->hs_ra_bytes;

	/*
	 * Some CD writers (e.g. Kodak Photo CD writers)
	 * create CDs in TAO mode and reserve tracks that
	 * are not completely written. Some sectors remain
	 * unreadable for this reason and give I/O errors.
	 * Also, there's no point in reading sectors
	 * we'll never look at.  So, if we're asked to go
	 * beyond the end of a file, truncate to the length
	 * of that file.
	 *
	 * Additionally, this behaviour is required by section
	 * 6.4.5 of ISO 9660:1988(E).
	 */
	len = MIN(extension ? extension : PAGESIZE, filsiz - off);

	/* A little paranoia */
	if (len <= 0)
		return (-1);

	/*
	 * After all that, make sure we're asking for things in units
	 * that bdev_strategy() will understand (see bug 4202551).
	 */
	len = roundup(len, DEV_BSIZE);

	pp = pvn_read_kluster(vp, off, seg, addr, &io_off_tmp,
	    &io_len_tmp, off, len, 1);

	if (pp == NULL) {
		hp->hs_num_contig = 0;
		hp->hs_ra_bytes = 0;
		hp->hs_prev_offset = 0;
		return (-1);
	}

	io_off = (uint_t)io_off_tmp;
	io_len = (uint_t)io_len_tmp;

	/* check for truncation */
	/*
	 * xxx Clean up and return EIO instead?
	 * xxx Ought to go to u_offset_t for everything, but we
	 * xxx call lots of things that want uint_t arguments.
	 */
	ASSERT(io_off == io_off_tmp);

	/*
	 * get enough buffers for worst-case scenario
	 * (i.e., no coalescing possible).
	 */
	bufcnt = (len + secsize - 1) / secsize;
	bufs = kmem_alloc(bufcnt * sizeof (struct buf), KM_SLEEP);
	vas = kmem_alloc(bufcnt * sizeof (caddr_t), KM_SLEEP);

	/*
	 * Allocate a array of semaphores since we are doing I/O
	 * scheduling.
	 */
	fio_done = kmem_alloc(bufcnt * sizeof (ksema_t), KM_SLEEP);

	/*
	 * If our filesize is not an integer multiple of PAGESIZE,
	 * we zero that part of the last page that's between EOF and
	 * the PAGESIZE boundary.
	 */
	xlen = io_len & PAGEOFFSET;
	if (xlen != 0)
		pagezero(pp->p_prev, xlen, PAGESIZE - xlen);

	DTRACE_PROBE2(hsfs_readahead, struct vnode *, vp, uint_t, io_len);

	va = NULL;
	lastp = NULL;
	searchp = pp;
	io_end = io_off + io_len;
	for (count = 0, byte_offset = io_off;
	    byte_offset < io_end;
	    count++) {
		ASSERT(count < bufcnt);

		bioinit(&bufs[count]);
		bufs[count].b_edev = devvp->v_rdev;
		bufs[count].b_dev = cmpdev(devvp->v_rdev);
		bufs[count].b_flags = B_NOCACHE|B_BUSY|B_READ;
		bufs[count].b_iodone = hsfs_iodone;
		bufs[count].b_vp = vp;
		bufs[count].b_file = vp;

		/* Compute disk address for interleaving. */

		/* considered without skips */
		which_chunk_lbn = byte_offset / chunk_data_bytes;

		/* factor in skips */
		offset_lbn = which_chunk_lbn * chunk_lbn_count;

		/* convert to physical byte offset for lbn */
		offset_bytes = LBN_TO_BYTE(offset_lbn, vp->v_vfsp);

		/* don't forget offset into lbn */
		offset_extra = byte_offset % chunk_data_bytes;

		/* get virtual block number for driver */
		driver_block = lbtodb(bof + xarsiz
		    + offset_bytes + offset_extra);

		if (lastp != searchp) {
			/* this branch taken first time through loop */
			va = vas[count] = ppmapin(searchp, PROT_WRITE,
			    (caddr_t)-1);
			/* ppmapin() guarantees not to return NULL */
		} else {
			vas[count] = NULL;
		}

		bufs[count].b_un.b_addr = va + byte_offset % PAGESIZE;
		bufs[count].b_offset =
		    (offset_t)(byte_offset - io_off + off);

		/*
		 * We specifically use the b_lblkno member here
		 * as even in the 32 bit world driver_block can
		 * get very large in line with the ISO9660 spec.
		 */

		bufs[count].b_lblkno = driver_block;

		remaining_bytes = ((which_chunk_lbn + 1) * chunk_data_bytes)
		    - byte_offset;

		/*
		 * remaining_bytes can't be zero, as we derived
		 * which_chunk_lbn directly from byte_offset.
		 */
		if ((remaining_bytes + byte_offset) < (off + len)) {
			/* coalesce-read the rest of the chunk */
			bufs[count].b_bcount = remaining_bytes;
		} else {
			/* get the final bits */
			bufs[count].b_bcount = off + len - byte_offset;
		}

		remainder = PAGESIZE - (byte_offset % PAGESIZE);
		if (bufs[count].b_bcount > remainder) {
			bufs[count].b_bcount = remainder;
		}

		bufs[count].b_bufsize = bufs[count].b_bcount;
		if (((offset_t)byte_offset + bufs[count].b_bcount) >
		    HS_MAXFILEOFF) {
			break;
		}
		byte_offset += bufs[count].b_bcount;

		/*
		 * We are scheduling I/O so we need to enqueue
		 * requests rather than calling bdev_strategy
		 * here. A later invocation of the scheduling
		 * function will take care of doing the actual
		 * I/O as it selects requests from the queue as
		 * per the scheduling logic.
		 */
		struct hio *hsio = kmem_cache_alloc(hio_cache,
		    KM_SLEEP);

		sema_init(&fio_done[count], 0, NULL,
		    SEMA_DEFAULT, NULL);
		hsio->bp = &bufs[count];
		hsio->sema = &fio_done[count];
		hsio->io_lblkno = bufs[count].b_lblkno;
		hsio->nblocks = howmany(hsio->bp->b_bcount,
		    DEV_BSIZE);

		/* used for deadline */
		hsio->io_timestamp = drv_hztousec(ddi_get_lbolt());

		/* for I/O coalescing */
		hsio->contig_chain = NULL;
		hsched_enqueue_io(fsp, hsio, 1);

		lwp_stat_update(LWP_STAT_INBLK, 1);
		lastp = searchp;
		if ((remainder - bufs[count].b_bcount) < 1) {
			searchp = searchp->p_next;
		}
	}

	bufsused = count;
	info = kmem_cache_alloc(hio_info_cache, KM_SLEEP);
	info->bufs = bufs;
	info->vas = vas;
	info->sema = fio_done;
	info->bufsused = bufsused;
	info->bufcnt = bufcnt;
	info->fsp = fsp;
	info->pp = pp;

	(void) taskq_dispatch(fsp->hqueue->ra_task,
	    hsfs_ra_task, info, KM_SLEEP);
	/*
	 * The I/O locked pages are unlocked in our taskq thread.
	 */
	return (0);
}

/*
 * Each file may have a different interleaving on disk.  This makes
 * things somewhat interesting.  The gist is that there are some
 * number of contiguous data sectors, followed by some other number
 * of contiguous skip sectors.  The sum of those two sets of sectors
 * defines the interleave size.  Unfortunately, it means that we generally
 * can't simply read N sectors starting at a given offset to satisfy
 * any given request.
 *
 * What we do is get the relevant memory pages via pvn_read_kluster(),
 * then stride through the interleaves, setting up a buf for each
 * sector that needs to be brought in.  Instead of kmem_alloc'ing
 * space for the sectors, though, we just point at the appropriate
 * spot in the relevant page for each of them.  This saves us a bunch
 * of copying.
 *
 * NOTICE: The code below in hsfs_getapage is mostly same as the code
 *         in hsfs_getpage_ra above (with some omissions). If you are
 *         making any change to this function, please also look at
 *         hsfs_getpage_ra.
 */
/*ARGSUSED*/
static int
hsfs_getapage(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	uint_t *protp,
	struct page *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cred)
{
	struct hsnode *hp;
	struct hsfs *fsp;
	int	err;
	struct buf *bufs;
	caddr_t *vas;
	caddr_t va;
	struct page *pp, *searchp, *lastp;
	page_t	*pagefound;
	offset_t	bof;
	struct vnode *devvp;
	ulong_t	byte_offset;
	size_t	io_len_tmp;
	uint_t	io_off, io_len;
	uint_t	xlen;
	uint_t	filsiz;
	uint_t	secsize;
	uint_t	bufcnt;
	uint_t	bufsused;
	uint_t	count;
	uint_t	io_end;
	uint_t	which_chunk_lbn;
	uint_t	offset_lbn;
	uint_t	offset_extra;
	offset_t	offset_bytes;
	uint_t	remaining_bytes;
	uint_t	extension;
	int	remainder;	/* must be signed */
	int	chunk_lbn_count;
	int	chunk_data_bytes;
	int	xarsiz;
	diskaddr_t driver_block;
	u_offset_t io_off_tmp;
	ksema_t *fio_done;
	int	calcdone;

	/*
	 * We don't support asynchronous operation at the moment, so
	 * just pretend we did it.  If the pages are ever actually
	 * needed, they'll get brought in then.
	 */
	if (pl == NULL)
		return (0);

	hp = VTOH(vp);
	fsp = VFS_TO_HSFS(vp->v_vfsp);
	devvp = fsp->hsfs_devvp;
	secsize = fsp->hsfs_vol.lbn_size;  /* bytes per logical block */

	/* file data size */
	filsiz = hp->hs_dirent.ext_size;

	/* disk addr for start of file */
	bof = LBN_TO_BYTE((offset_t)hp->hs_dirent.ext_lbn, vp->v_vfsp);

	/* xarsiz byte must be skipped for data */
	xarsiz = hp->hs_dirent.xar_len << fsp->hsfs_vol.lbn_shift;

	/* how many logical blocks in an interleave (data+skip) */
	chunk_lbn_count = hp->hs_dirent.intlf_sz + hp->hs_dirent.intlf_sk;

	if (chunk_lbn_count == 0) {
		chunk_lbn_count = 1;
	}

	/*
	 * Convert interleaving size into bytes.  The zero case
	 * (no interleaving) optimization is handled as a side-
	 * effect of the read-ahead logic.
	 */
	if (hp->hs_dirent.intlf_sz == 0) {
		chunk_data_bytes = LBN_TO_BYTE(1, vp->v_vfsp);
		/*
		 * Optimization: If our pagesize is a multiple of LBN
		 * bytes, we can avoid breaking up a page into individual
		 * lbn-sized requests.
		 */
		if (PAGESIZE % chunk_data_bytes == 0) {
			chunk_lbn_count = BYTE_TO_LBN(PAGESIZE, vp->v_vfsp);
			chunk_data_bytes = PAGESIZE;
		}
	} else {
		chunk_data_bytes =
		    LBN_TO_BYTE(hp->hs_dirent.intlf_sz, vp->v_vfsp);
	}

reread:
	err = 0;
	pagefound = 0;
	calcdone = 0;

	/*
	 * Do some read-ahead.  This mostly saves us a bit of
	 * system cpu time more than anything else when doing
	 * sequential reads.  At some point, could do the
	 * read-ahead asynchronously which might gain us something
	 * on wall time, but it seems unlikely....
	 *
	 * We do the easy case here, which is to read through
	 * the end of the chunk, minus whatever's at the end that
	 * won't exactly fill a page.
	 */
	if (hp->hs_ra_bytes > 0 && chunk_data_bytes != PAGESIZE) {
		which_chunk_lbn = (off + len) / chunk_data_bytes;
		extension = ((which_chunk_lbn + 1) * chunk_data_bytes) - off;
		extension -= (extension % PAGESIZE);
	} else {
		extension = roundup(len, PAGESIZE);
	}

	atomic_inc_64(&fsp->total_pages_requested);

	pp = NULL;
again:
	/* search for page in buffer */
	if ((pagefound = page_exists(vp, off)) == 0) {
		/*
		 * Need to really do disk IO to get the page.
		 */
		if (!calcdone) {
			extension += hp->hs_ra_bytes;

			/*
			 * Some cd writers don't write sectors that aren't
			 * used. Also, there's no point in reading sectors
			 * we'll never look at.  So, if we're asked to go
			 * beyond the end of a file, truncate to the length
			 * of that file.
			 *
			 * Additionally, this behaviour is required by section
			 * 6.4.5 of ISO 9660:1988(E).
			 */
			len = MIN(extension ? extension : PAGESIZE,
			    filsiz - off);

			/* A little paranoia. */
			ASSERT(len > 0);

			/*
			 * After all that, make sure we're asking for things
			 * in units that bdev_strategy() will understand
			 * (see bug 4202551).
			 */
			len = roundup(len, DEV_BSIZE);
			calcdone = 1;
		}

		pp = pvn_read_kluster(vp, off, seg, addr, &io_off_tmp,
		    &io_len_tmp, off, len, 0);

		if (pp == NULL) {
			/*
			 * Pressure on memory, roll back readahead
			 */
			hp->hs_num_contig = 0;
			hp->hs_ra_bytes = 0;
			hp->hs_prev_offset = 0;
			goto again;
		}

		io_off = (uint_t)io_off_tmp;
		io_len = (uint_t)io_len_tmp;

		/* check for truncation */
		/*
		 * xxx Clean up and return EIO instead?
		 * xxx Ought to go to u_offset_t for everything, but we
		 * xxx call lots of things that want uint_t arguments.
		 */
		ASSERT(io_off == io_off_tmp);

		/*
		 * get enough buffers for worst-case scenario
		 * (i.e., no coalescing possible).
		 */
		bufcnt = (len + secsize - 1) / secsize;
		bufs = kmem_zalloc(bufcnt * sizeof (struct buf), KM_SLEEP);
		vas = kmem_alloc(bufcnt * sizeof (caddr_t), KM_SLEEP);

		/*
		 * Allocate a array of semaphores if we are doing I/O
		 * scheduling.
		 */
		if (fsp->hqueue != NULL)
			fio_done = kmem_alloc(bufcnt * sizeof (ksema_t),
			    KM_SLEEP);
		for (count = 0; count < bufcnt; count++) {
			bioinit(&bufs[count]);
			bufs[count].b_edev = devvp->v_rdev;
			bufs[count].b_dev = cmpdev(devvp->v_rdev);
			bufs[count].b_flags = B_NOCACHE|B_BUSY|B_READ;
			bufs[count].b_iodone = hsfs_iodone;
			bufs[count].b_vp = vp;
			bufs[count].b_file = vp;
		}

		/*
		 * If our filesize is not an integer multiple of PAGESIZE,
		 * we zero that part of the last page that's between EOF and
		 * the PAGESIZE boundary.
		 */
		xlen = io_len & PAGEOFFSET;
		if (xlen != 0)
			pagezero(pp->p_prev, xlen, PAGESIZE - xlen);

		va = NULL;
		lastp = NULL;
		searchp = pp;
		io_end = io_off + io_len;
		for (count = 0, byte_offset = io_off;
		    byte_offset < io_end; count++) {
			ASSERT(count < bufcnt);

			/* Compute disk address for interleaving. */

			/* considered without skips */
			which_chunk_lbn = byte_offset / chunk_data_bytes;

			/* factor in skips */
			offset_lbn = which_chunk_lbn * chunk_lbn_count;

			/* convert to physical byte offset for lbn */
			offset_bytes = LBN_TO_BYTE(offset_lbn, vp->v_vfsp);

			/* don't forget offset into lbn */
			offset_extra = byte_offset % chunk_data_bytes;

			/* get virtual block number for driver */
			driver_block =
			    lbtodb(bof + xarsiz + offset_bytes + offset_extra);

			if (lastp != searchp) {
				/* this branch taken first time through loop */
				va = vas[count] =
				    ppmapin(searchp, PROT_WRITE, (caddr_t)-1);
				/* ppmapin() guarantees not to return NULL */
			} else {
				vas[count] = NULL;
			}

			bufs[count].b_un.b_addr = va + byte_offset % PAGESIZE;
			bufs[count].b_offset =
			    (offset_t)(byte_offset - io_off + off);

			/*
			 * We specifically use the b_lblkno member here
			 * as even in the 32 bit world driver_block can
			 * get very large in line with the ISO9660 spec.
			 */

			bufs[count].b_lblkno = driver_block;

			remaining_bytes =
			    ((which_chunk_lbn + 1) * chunk_data_bytes)
			    - byte_offset;

			/*
			 * remaining_bytes can't be zero, as we derived
			 * which_chunk_lbn directly from byte_offset.
			 */
			if ((remaining_bytes + byte_offset) < (off + len)) {
				/* coalesce-read the rest of the chunk */
				bufs[count].b_bcount = remaining_bytes;
			} else {
				/* get the final bits */
				bufs[count].b_bcount = off + len - byte_offset;
			}

			/*
			 * It would be nice to do multiple pages'
			 * worth at once here when the opportunity
			 * arises, as that has been shown to improve
			 * our wall time.  However, to do that
			 * requires that we use the pageio subsystem,
			 * which doesn't mix well with what we're
			 * already using here.  We can't use pageio
			 * all the time, because that subsystem
			 * assumes that a page is stored in N
			 * contiguous blocks on the device.
			 * Interleaving violates that assumption.
			 *
			 * Update: This is now not so big a problem
			 * because of the I/O scheduler sitting below
			 * that can re-order and coalesce I/O requests.
			 */

			remainder = PAGESIZE - (byte_offset % PAGESIZE);
			if (bufs[count].b_bcount > remainder) {
				bufs[count].b_bcount = remainder;
			}

			bufs[count].b_bufsize = bufs[count].b_bcount;
			if (((offset_t)byte_offset + bufs[count].b_bcount) >
			    HS_MAXFILEOFF) {
				break;
			}
			byte_offset += bufs[count].b_bcount;

			if (fsp->hqueue == NULL) {
				(void) bdev_strategy(&bufs[count]);

			} else {
				/*
				 * We are scheduling I/O so we need to enqueue
				 * requests rather than calling bdev_strategy
				 * here. A later invocation of the scheduling
				 * function will take care of doing the actual
				 * I/O as it selects requests from the queue as
				 * per the scheduling logic.
				 */
				struct hio *hsio = kmem_cache_alloc(hio_cache,
				    KM_SLEEP);

				sema_init(&fio_done[count], 0, NULL,
				    SEMA_DEFAULT, NULL);
				hsio->bp = &bufs[count];
				hsio->sema = &fio_done[count];
				hsio->io_lblkno = bufs[count].b_lblkno;
				hsio->nblocks = howmany(hsio->bp->b_bcount,
				    DEV_BSIZE);

				/* used for deadline */
				hsio->io_timestamp =
				    drv_hztousec(ddi_get_lbolt());

				/* for I/O coalescing */
				hsio->contig_chain = NULL;
				hsched_enqueue_io(fsp, hsio, 0);
			}

			lwp_stat_update(LWP_STAT_INBLK, 1);
			lastp = searchp;
			if ((remainder - bufs[count].b_bcount) < 1) {
				searchp = searchp->p_next;
			}
		}

		bufsused = count;
		/* Now wait for everything to come in */
		if (fsp->hqueue == NULL) {
			for (count = 0; count < bufsused; count++) {
				if (err == 0) {
					err = biowait(&bufs[count]);
				} else
					(void) biowait(&bufs[count]);
			}
		} else {
			for (count = 0; count < bufsused; count++) {
				struct buf *wbuf;

				/*
				 * Invoke scheduling function till our buf
				 * is processed. In doing this it might
				 * process bufs enqueued by other threads
				 * which is good.
				 */
				wbuf = &bufs[count];
				DTRACE_PROBE1(hsfs_io_wait, struct buf *, wbuf);
				while (sema_tryp(&fio_done[count]) == 0) {
					/*
					 * hsched_invoke_strategy will return 1
					 * if the I/O queue is empty. This means
					 * that there is another thread who has
					 * issued our buf and is waiting. So we
					 * just block instead of spinning.
					 */
					if (hsched_invoke_strategy(fsp)) {
						sema_p(&fio_done[count]);
						break;
					}
				}
				sema_destroy(&fio_done[count]);
				DTRACE_PROBE1(hsfs_io_done, struct buf *, wbuf);

				if (err == 0) {
					err = geterror(wbuf);
				}
			}
			kmem_free(fio_done, bufcnt * sizeof (ksema_t));
		}

		/* Don't leak resources */
		for (count = 0; count < bufcnt; count++) {
			biofini(&bufs[count]);
			if (count < bufsused && vas[count] != NULL) {
				ppmapout(vas[count]);
			}
		}

		kmem_free(vas, bufcnt * sizeof (caddr_t));
		kmem_free(bufs, bufcnt * sizeof (struct buf));
	}

	if (err) {
		pvn_read_done(pp, B_ERROR);
		return (err);
	}

	/*
	 * Lock the requested page, and the one after it if possible.
	 * Don't bother if our caller hasn't given us a place to stash
	 * the page pointers, since otherwise we'd lock pages that would
	 * never get unlocked.
	 */
	if (pagefound) {
		int index;
		ulong_t soff;

		/*
		 * Make sure it's in memory before we say it's here.
		 */
		if ((pp = page_lookup(vp, off, SE_SHARED)) == NULL) {
			hsfs_lostpage++;
			goto reread;
		}

		pl[0] = pp;
		index = 1;
		atomic_inc_64(&fsp->cache_read_pages);

		/*
		 * Try to lock the next page, if it exists, without
		 * blocking.
		 */
		plsz -= PAGESIZE;
		/* LINTED (plsz is unsigned) */
		for (soff = off + PAGESIZE; plsz > 0;
		    soff += PAGESIZE, plsz -= PAGESIZE) {
			pp = page_lookup_nowait(vp, (u_offset_t)soff,
			    SE_SHARED);
			if (pp == NULL)
				break;
			pl[index++] = pp;
		}
		pl[index] = NULL;

		/*
		 * Schedule a semi-asynchronous readahead if we are
		 * accessing the last cached page for the current
		 * file.
		 *
		 * Doing this here means that readaheads will be
		 * issued only if cache-hits occur. This is an advantage
		 * since cache-hits would mean that readahead is giving
		 * the desired benefit. If cache-hits do not occur there
		 * is no point in reading ahead of time - the system
		 * is loaded anyway.
		 */
		if (fsp->hqueue != NULL &&
		    hp->hs_prev_offset - off == PAGESIZE &&
		    hp->hs_prev_offset < filsiz &&
		    hp->hs_ra_bytes > 0 &&
		    !page_exists(vp, hp->hs_prev_offset)) {
			(void) hsfs_getpage_ra(vp, hp->hs_prev_offset, seg,
			    addr + PAGESIZE, hp, fsp, xarsiz, bof,
			    chunk_lbn_count, chunk_data_bytes);
		}

		return (0);
	}

	if (pp != NULL) {
		pvn_plist_init(pp, pl, plsz, off, io_len, rw);
	}

	return (err);
}

/*ARGSUSED*/
static int
hsfs_getpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	uint_t *protp,
	struct page *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cred,
	caller_context_t *ct)
{
	int err;
	uint_t filsiz;
	struct hsfs *fsp;
	struct hsnode *hp;

	fsp = VFS_TO_HSFS(vp->v_vfsp);
	hp = VTOH(vp);

	/* does not support write */
	if (rw == S_WRITE) {
		return (EROFS);
	}

	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}

	ASSERT(off <= HS_MAXFILEOFF);

	/*
	 * Determine file data size for EOF check.
	 */
	filsiz = hp->hs_dirent.ext_size;
	if ((off + len) > (offset_t)(filsiz + PAGEOFFSET) && seg != segkmap)
		return (EFAULT);	/* beyond EOF */

	/*
	 * Async Read-ahead computation.
	 * This attempts to detect sequential access pattern and
	 * enables reading extra pages ahead of time.
	 */
	if (fsp->hqueue != NULL) {
		/*
		 * This check for sequential access also takes into
		 * account segmap weirdness when reading in chunks
		 * less than the segmap size of 8K.
		 */
		if (hp->hs_prev_offset == off || (off <
		    hp->hs_prev_offset && off + MAX(len, PAGESIZE)
		    >= hp->hs_prev_offset)) {
			if (hp->hs_num_contig <
			    (seq_contig_requests - 1)) {
				hp->hs_num_contig++;

			} else {
				/*
				 * We increase readahead quantum till
				 * a predefined max. max_readahead_bytes
				 * is a multiple of PAGESIZE.
				 */
				if (hp->hs_ra_bytes <
				    fsp->hqueue->max_ra_bytes) {
					hp->hs_ra_bytes += PAGESIZE;
				}
			}
		} else {
			/*
			 * Not contiguous so reduce read ahead counters.
			 */
			if (hp->hs_ra_bytes > 0)
				hp->hs_ra_bytes -= PAGESIZE;

			if (hp->hs_ra_bytes <= 0) {
				hp->hs_ra_bytes = 0;
				if (hp->hs_num_contig > 0)
					hp->hs_num_contig--;
			}
		}
		/*
		 * Length must be rounded up to page boundary.
		 * since we read in units of pages.
		 */
		hp->hs_prev_offset = off + roundup(len, PAGESIZE);
		DTRACE_PROBE1(hsfs_compute_ra, struct hsnode *, hp);
	}
	if (protp != NULL)
		*protp = PROT_ALL;

	if (len <= PAGESIZE)
		err = hsfs_getapage(vp, (u_offset_t)off, len, protp, pl, plsz,
		    seg, addr, rw, cred);
	else
		err = pvn_getpages(hsfs_getapage, vp, off, len, protp,
		    pl, plsz, seg, addr, rw, cred);

	return (err);
}



/*
 * This function should never be called. We need to have it to pass
 * it as an argument to other functions.
 */
/*ARGSUSED*/
int
hsfs_putapage(
	vnode_t		*vp,
	page_t		*pp,
	u_offset_t	*offp,
	size_t		*lenp,
	int		flags,
	cred_t		*cr)
{
	/* should never happen - just destroy it */
	cmn_err(CE_NOTE, "hsfs_putapage: dirty HSFS page");
	pvn_write_done(pp, B_ERROR | B_WRITE | B_INVAL | B_FORCE | flags);
	return (0);
}


/*
 * The only flags we support are B_INVAL, B_FREE and B_DONTNEED.
 * B_INVAL is set by:
 *
 *	1) the MC_SYNC command of memcntl(2) to support the MS_INVALIDATE flag.
 *	2) the MC_ADVISE command of memcntl(2) with the MADV_DONTNEED advice
 *	   which translates to an MC_SYNC with the MS_INVALIDATE flag.
 *
 * The B_FREE (as well as the B_DONTNEED) flag is set when the
 * MADV_SEQUENTIAL advice has been used. VOP_PUTPAGE is invoked
 * from SEGVN to release pages behind a pagefault.
 */
/*ARGSUSED*/
static int
hsfs_putpage(
	struct vnode		*vp,
	offset_t		off,
	size_t			len,
	int			flags,
	struct cred		*cr,
	caller_context_t	*ct)
{
	int error = 0;

	if (vp->v_count == 0) {
		panic("hsfs_putpage: bad v_count");
		/*NOTREACHED*/
	}

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	ASSERT(off <= HS_MAXFILEOFF);

	if (!vn_has_cached_data(vp))	/* no pages mapped */
		return (0);

	if (len == 0) {		/* from 'off' to EOF */
		error = pvn_vplist_dirty(vp, off, hsfs_putapage, flags, cr);
	} else {
		offset_t end_off = off + len;
		offset_t file_size = VTOH(vp)->hs_dirent.ext_size;
		offset_t io_off;

		file_size = (file_size + PAGESIZE - 1) & PAGEMASK;
		if (end_off > file_size)
			end_off = file_size;

		for (io_off = off; io_off < end_off; io_off += PAGESIZE) {
			page_t *pp;

			/*
			 * We insist on getting the page only if we are
			 * about to invalidate, free or write it and
			 * the B_ASYNC flag is not set.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL)
				continue;

			/*
			 * Normally pvn_getdirty() should return 0, which
			 * impies that it has done the job for us.
			 * The shouldn't-happen scenario is when it returns 1.
			 * This means that the page has been modified and
			 * needs to be put back.
			 * Since we can't write on a CD, we fake a failed
			 * I/O and force pvn_write_done() to destroy the page.
			 */
			if (pvn_getdirty(pp, flags) == 1) {
				cmn_err(CE_NOTE,
				    "hsfs_putpage: dirty HSFS page");
				pvn_write_done(pp, flags |
				    B_ERROR | B_WRITE | B_INVAL | B_FORCE);
			}
		}
	}
	return (error);
}


/*ARGSUSED*/
static int
hsfs_map(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	int error;

	/* VFS_RECORD(vp->v_vfsp, VS_MAP, VS_CALL); */

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (prot & PROT_WRITE)
		return (ENOSYS);

	if (off > HS_MAXFILEOFF || off < 0 ||
	    (off + len) < 0 || (off + len) > HS_MAXFILEOFF)
		return (ENXIO);

	if (vp->v_type != VREG) {
		return (ENODEV);
	}

	/*
	 * If file is being locked, disallow mapping.
	 */
	if (vn_has_mandatory_locks(vp, VTOH(vp)->hs_dirent.mode))
		return (EAGAIN);

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.cred = cred;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);
	return (error);
}

/* ARGSUSED */
static int
hsfs_addmap(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct hsnode *hp;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	hp = VTOH(vp);
	mutex_enter(&hp->hs_contents_lock);
	hp->hs_mapcnt += btopr(len);
	mutex_exit(&hp->hs_contents_lock);
	return (0);
}

/*ARGSUSED*/
static int
hsfs_delmap(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct hsnode *hp;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	hp = VTOH(vp);
	mutex_enter(&hp->hs_contents_lock);
	hp->hs_mapcnt -= btopr(len);	/* Count released mappings */
	ASSERT(hp->hs_mapcnt >= 0);
	mutex_exit(&hp->hs_contents_lock);
	return (0);
}

/* ARGSUSED */
static int
hsfs_seek(
	struct vnode *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED */
static int
hsfs_frlock(
	struct vnode *vp,
	int cmd,
	struct flock64 *bfp,
	int flag,
	offset_t offset,
	struct flk_callback *flk_cbp,
	cred_t *cr,
	caller_context_t *ct)
{
	struct hsnode *hp = VTOH(vp);

	/*
	 * If the file is being mapped, disallow fs_frlock.
	 * We are not holding the hs_contents_lock while checking
	 * hs_mapcnt because the current locking strategy drops all
	 * locks before calling fs_frlock.
	 * So, hs_mapcnt could change before we enter fs_frlock making
	 * it meaningless to have held hs_contents_lock in the first place.
	 */
	if (hp->hs_mapcnt > 0 && MANDLOCK(vp, hp->hs_dirent.mode))
		return (EAGAIN);

	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

static int
hsched_deadline_compare(const void *x1, const void *x2)
{
	const struct hio *h1 = x1;
	const struct hio *h2 = x2;

	if (h1->io_timestamp < h2->io_timestamp)
		return (-1);
	if (h1->io_timestamp > h2->io_timestamp)
		return (1);

	if (h1->io_lblkno < h2->io_lblkno)
		return (-1);
	if (h1->io_lblkno > h2->io_lblkno)
		return (1);

	if (h1 < h2)
		return (-1);
	if (h1 > h2)
		return (1);

	return (0);
}

static int
hsched_offset_compare(const void *x1, const void *x2)
{
	const struct hio *h1 = x1;
	const struct hio *h2 = x2;

	if (h1->io_lblkno < h2->io_lblkno)
		return (-1);
	if (h1->io_lblkno > h2->io_lblkno)
		return (1);

	if (h1 < h2)
		return (-1);
	if (h1 > h2)
		return (1);

	return (0);
}

void
hsched_init_caches(void)
{
	hio_cache = kmem_cache_create("hsfs_hio_cache",
	    sizeof (struct hio), 0, NULL,
	    NULL, NULL, NULL, NULL, 0);

	hio_info_cache = kmem_cache_create("hsfs_hio_info_cache",
	    sizeof (struct hio_info), 0, NULL,
	    NULL, NULL, NULL, NULL, 0);
}

void
hsched_fini_caches(void)
{
	kmem_cache_destroy(hio_cache);
	kmem_cache_destroy(hio_info_cache);
}

/*
 * Initialize I/O scheduling structures. This is called via hsfs_mount
 */
void
hsched_init(struct hsfs *fsp, int fsid, struct modlinkage *modlinkage)
{
	struct hsfs_queue *hqueue = fsp->hqueue;
	struct vnode *vp = fsp->hsfs_devvp;

	/* TaskQ name of the form: hsched_task_ + stringof(int) */
	char namebuf[23];
	int error, err;
	struct dk_cinfo info;
	ldi_handle_t lh;
	ldi_ident_t li;

	/*
	 * Default maxtransfer = 16k chunk
	 */
	hqueue->dev_maxtransfer = 16384;

	/*
	 * Try to fetch the maximum device transfer size. This is used to
	 * ensure that a coalesced block does not exceed the maxtransfer.
	 */
	err  = ldi_ident_from_mod(modlinkage, &li);
	if (err) {
		cmn_err(CE_NOTE, "hsched_init: Querying device failed");
		cmn_err(CE_NOTE, "hsched_init: ldi_ident_from_mod err=%d\n",
		    err);
		goto set_ra;
	}

	err = ldi_open_by_dev(&(vp->v_rdev), OTYP_CHR, FREAD, CRED(), &lh, li);
	ldi_ident_release(li);
	if (err) {
		cmn_err(CE_NOTE, "hsched_init: Querying device failed");
		cmn_err(CE_NOTE, "hsched_init: ldi_open err=%d\n", err);
		goto set_ra;
	}

	error = ldi_ioctl(lh, DKIOCINFO, (intptr_t)&info, FKIOCTL,
	    CRED(), &err);
	err = ldi_close(lh, FREAD, CRED());
	if (err) {
		cmn_err(CE_NOTE, "hsched_init: Querying device failed");
		cmn_err(CE_NOTE, "hsched_init: ldi_close err=%d\n", err);
	}

	if (error == 0) {
		hqueue->dev_maxtransfer = ldbtob(info.dki_maxtransfer);
	}

set_ra:
	/*
	 * Max size of data to read ahead for sequential access pattern.
	 * Conservative to avoid letting the underlying CD drive to spin
	 * down, in case the application is reading slowly.
	 * We read ahead upto a max of 4 pages.
	 */
	hqueue->max_ra_bytes = PAGESIZE * 8;

	mutex_init(&(hqueue->hsfs_queue_lock), NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&(hqueue->strategy_lock), NULL, MUTEX_DEFAULT, NULL);
	avl_create(&(hqueue->read_tree), hsched_offset_compare,
	    sizeof (struct hio), offsetof(struct hio, io_offset_node));
	avl_create(&(hqueue->deadline_tree), hsched_deadline_compare,
	    sizeof (struct hio), offsetof(struct hio, io_deadline_node));

	(void) snprintf(namebuf, sizeof (namebuf), "hsched_task_%d", fsid);
	hqueue->ra_task = taskq_create(namebuf, hsfs_taskq_nthreads,
	    minclsyspri + 2, 1, 104857600 / PAGESIZE, TASKQ_DYNAMIC);

	hqueue->next = NULL;
	hqueue->nbuf = kmem_zalloc(sizeof (struct buf), KM_SLEEP);
}

void
hsched_fini(struct hsfs_queue *hqueue)
{
	if (hqueue != NULL) {
		/*
		 * Remove the sentinel if there was one.
		 */
		if (hqueue->next != NULL) {
			avl_remove(&hqueue->read_tree, hqueue->next);
			kmem_cache_free(hio_cache, hqueue->next);
		}
		avl_destroy(&(hqueue->read_tree));
		avl_destroy(&(hqueue->deadline_tree));
		mutex_destroy(&(hqueue->hsfs_queue_lock));
		mutex_destroy(&(hqueue->strategy_lock));

		/*
		 * If there are any existing readahead threads running
		 * taskq_destroy will wait for them to finish.
		 */
		taskq_destroy(hqueue->ra_task);
		kmem_free(hqueue->nbuf, sizeof (struct buf));
	}
}

/*
 * Determine if two I/O requests are adjacent to each other so
 * that they can coalesced.
 */
#define	IS_ADJACENT(io, nio) \
	(((io)->io_lblkno + (io)->nblocks == (nio)->io_lblkno) && \
	(io)->bp->b_edev == (nio)->bp->b_edev)

/*
 * This performs the actual I/O scheduling logic. We use the Circular
 * Look algorithm here. Sort the I/O requests in ascending order of
 * logical block number and process them starting with the lowest
 * numbered block and progressing towards higher block numbers in the
 * queue. Once there are no more higher numbered blocks, start again
 * with the lowest one. This is good for CD/DVD as you keep moving
 * the head in one direction along the outward spiral track and avoid
 * too many seeks as much as possible. The re-ordering also allows
 * us to coalesce adjacent requests into one larger request.
 * This is thus essentially a 1-way Elevator with front merging.
 *
 * In addition each read request here has a deadline and will be
 * processed out of turn if the deadline (500ms) expires.
 *
 * This function is necessarily serialized via hqueue->strategy_lock.
 * This function sits just below hsfs_getapage and processes all read
 * requests orginating from that function.
 */
int
hsched_invoke_strategy(struct hsfs *fsp)
{
	struct hsfs_queue *hqueue;
	struct buf *nbuf;
	struct hio *fio, *nio, *tio, *prev, *last;
	size_t bsize, soffset, offset, data;
	int bioret, bufcount;
	struct vnode *fvp;
	ksema_t *io_done;
	caddr_t iodata;

	hqueue = fsp->hqueue;
	mutex_enter(&hqueue->strategy_lock);
	mutex_enter(&hqueue->hsfs_queue_lock);

	/*
	 * Check for Deadline expiration first
	 */
	fio = avl_first(&hqueue->deadline_tree);

	/*
	 * Paranoid check for empty I/O queue. Both deadline
	 * and read trees contain same data sorted in different
	 * ways. So empty deadline tree = empty read tree.
	 */
	if (fio == NULL) {
		/*
		 * Remove the sentinel if there was one.
		 */
		if (hqueue->next != NULL) {
			avl_remove(&hqueue->read_tree, hqueue->next);
			kmem_cache_free(hio_cache, hqueue->next);
			hqueue->next = NULL;
		}
		mutex_exit(&hqueue->hsfs_queue_lock);
		mutex_exit(&hqueue->strategy_lock);
		return (1);
	}

	if (drv_hztousec(ddi_get_lbolt()) - fio->io_timestamp
	    < HSFS_READ_DEADLINE) {
		/*
		 * Apply standard scheduling logic. This uses the
		 * C-LOOK approach. Process I/O requests in ascending
		 * order of logical block address till no subsequent
		 * higher numbered block request remains. Then start
		 * again from the lowest numbered block in the queue.
		 *
		 * We do this cheaply here by means of a sentinel.
		 * The last processed I/O structure from the previous
		 * invocation of this func, is left dangling in the
		 * read_tree so that we can easily scan to the next
		 * higher numbered request and remove the sentinel.
		 */
		fio = NULL;
		if (hqueue->next != NULL) {
			fio = AVL_NEXT(&hqueue->read_tree, hqueue->next);
			avl_remove(&hqueue->read_tree, hqueue->next);
			kmem_cache_free(hio_cache, hqueue->next);
			hqueue->next = NULL;
		}
		if (fio == NULL) {
			fio = avl_first(&hqueue->read_tree);
		}
	} else if (hqueue->next != NULL) {
		DTRACE_PROBE1(hsfs_deadline_expiry, struct hio *, fio);

		avl_remove(&hqueue->read_tree, hqueue->next);
		kmem_cache_free(hio_cache, hqueue->next);
		hqueue->next = NULL;
	}

	/*
	 * In addition we try to coalesce contiguous
	 * requests into one bigger request.
	 */
	bufcount = 1;
	bsize = ldbtob(fio->nblocks);
	fvp = fio->bp->b_file;
	nio = AVL_NEXT(&hqueue->read_tree, fio);
	tio = fio;
	while (nio != NULL && IS_ADJACENT(tio, nio) &&
	    bsize < hqueue->dev_maxtransfer) {
		avl_remove(&hqueue->deadline_tree, tio);
		avl_remove(&hqueue->read_tree, tio);
		tio->contig_chain = nio;
		bsize += ldbtob(nio->nblocks);
		prev = tio;
		tio = nio;

		/*
		 * This check is required to detect the case where
		 * we are merging adjacent buffers belonging to
		 * different files. fvp is used to set the b_file
		 * parameter in the coalesced buf. b_file is used
		 * by DTrace so we do not want DTrace to accrue
		 * requests to two different files to any one file.
		 */
		if (fvp && tio->bp->b_file != fvp) {
			fvp = NULL;
		}

		nio = AVL_NEXT(&hqueue->read_tree, nio);
		bufcount++;
	}

	/*
	 * tio is not removed from the read_tree as it serves as a sentinel
	 * to cheaply allow us to scan to the next higher numbered I/O
	 * request.
	 */
	hqueue->next = tio;
	avl_remove(&hqueue->deadline_tree, tio);
	mutex_exit(&hqueue->hsfs_queue_lock);
	DTRACE_PROBE3(hsfs_io_dequeued, struct hio *, fio, int, bufcount,
	    size_t, bsize);

	/*
	 * The benefit of coalescing occurs if the the savings in I/O outweighs
	 * the cost of doing the additional work below.
	 * It was observed that coalescing 2 buffers results in diminishing
	 * returns, so we do coalescing if we have >2 adjacent bufs.
	 */
	if (bufcount > hsched_coalesce_min) {
		/*
		 * We have coalesced blocks. First allocate mem and buf for
		 * the entire coalesced chunk.
		 * Since we are guaranteed single-threaded here we pre-allocate
		 * one buf at mount time and that is re-used every time. This
		 * is a synthesized buf structure that uses kmem_alloced chunk.
		 * Not quite a normal buf attached to pages.
		 */
		fsp->coalesced_bytes += bsize;
		nbuf = hqueue->nbuf;
		bioinit(nbuf);
		nbuf->b_edev = fio->bp->b_edev;
		nbuf->b_dev = fio->bp->b_dev;
		nbuf->b_flags = fio->bp->b_flags;
		nbuf->b_iodone = fio->bp->b_iodone;
		iodata = kmem_alloc(bsize, KM_SLEEP);
		nbuf->b_un.b_addr = iodata;
		nbuf->b_lblkno = fio->bp->b_lblkno;
		nbuf->b_vp = fvp;
		nbuf->b_file = fvp;
		nbuf->b_bcount = bsize;
		nbuf->b_bufsize = bsize;

		DTRACE_PROBE3(hsfs_coalesced_io_start, struct hio *, fio, int,
		    bufcount, size_t, bsize);

		/*
		 * Perform I/O for the coalesced block.
		 */
		(void) bdev_strategy(nbuf);

		/*
		 * Duplicate the last IO node to leave the sentinel alone.
		 * The sentinel is freed in the next invocation of this
		 * function.
		 */
		prev->contig_chain = kmem_cache_alloc(hio_cache, KM_SLEEP);
		prev->contig_chain->bp = tio->bp;
		prev->contig_chain->sema = tio->sema;
		tio = prev->contig_chain;
		tio->contig_chain = NULL;
		soffset = ldbtob(fio->bp->b_lblkno);
		nio = fio;

		bioret = biowait(nbuf);
		data = bsize - nbuf->b_resid;
		biofini(nbuf);
		mutex_exit(&hqueue->strategy_lock);

		/*
		 * We use the b_resid parameter to detect how much
		 * data was succesfully transferred. We will signal
		 * a success to all the fully retrieved actual bufs
		 * before coalescing, rest is signaled as error,
		 * if any.
		 */
		tio = nio;
		DTRACE_PROBE3(hsfs_coalesced_io_done, struct hio *, nio,
		    int, bioret, size_t, data);

		/*
		 * Copy data and signal success to all the bufs
		 * which can be fully satisfied from b_resid.
		 */
		while (nio != NULL && data >= nio->bp->b_bcount) {
			offset = ldbtob(nio->bp->b_lblkno) - soffset;
			bcopy(iodata + offset, nio->bp->b_un.b_addr,
			    nio->bp->b_bcount);
			data -= nio->bp->b_bcount;
			bioerror(nio->bp, 0);
			biodone(nio->bp);
			sema_v(nio->sema);
			tio = nio;
			nio = nio->contig_chain;
			kmem_cache_free(hio_cache, tio);
		}

		/*
		 * Signal error to all the leftover bufs (if any)
		 * after b_resid data is exhausted.
		 */
		while (nio != NULL) {
			nio->bp->b_resid = nio->bp->b_bcount - data;
			bzero(nio->bp->b_un.b_addr + data, nio->bp->b_resid);
			bioerror(nio->bp, bioret);
			biodone(nio->bp);
			sema_v(nio->sema);
			tio = nio;
			nio = nio->contig_chain;
			kmem_cache_free(hio_cache, tio);
			data = 0;
		}
		kmem_free(iodata, bsize);
	} else {

		nbuf = tio->bp;
		io_done = tio->sema;
		nio = fio;
		last = tio;

		while (nio != NULL) {
			(void) bdev_strategy(nio->bp);
			nio = nio->contig_chain;
		}
		nio = fio;
		mutex_exit(&hqueue->strategy_lock);

		while (nio != NULL) {
			if (nio == last) {
				(void) biowait(nbuf);
				sema_v(io_done);
				break;
				/* sentinel last not freed. See above. */
			} else {
				(void) biowait(nio->bp);
				sema_v(nio->sema);
			}
			tio = nio;
			nio = nio->contig_chain;
			kmem_cache_free(hio_cache, tio);
		}
	}
	return (0);
}

/*
 * Insert an I/O request in the I/O scheduler's pipeline
 * Using AVL tree makes it easy to reorder the I/O request
 * based on logical block number.
 */
static void
hsched_enqueue_io(struct hsfs *fsp, struct hio *hsio, int ra)
{
	struct hsfs_queue *hqueue = fsp->hqueue;

	mutex_enter(&hqueue->hsfs_queue_lock);

	fsp->physical_read_bytes += hsio->bp->b_bcount;
	if (ra)
		fsp->readahead_bytes += hsio->bp->b_bcount;

	avl_add(&hqueue->deadline_tree, hsio);
	avl_add(&hqueue->read_tree, hsio);

	DTRACE_PROBE3(hsfs_io_enqueued, struct hio *, hsio,
	    struct hsfs_queue *, hqueue, int, ra);

	mutex_exit(&hqueue->hsfs_queue_lock);
}

/* ARGSUSED */
static int
hsfs_pathconf(struct vnode *vp,
	int cmd,
	ulong_t *valp,
	struct cred *cr,
	caller_context_t *ct)
{
	struct hsfs	*fsp;

	int		error = 0;

	switch (cmd) {

	case _PC_NAME_MAX:
		fsp = VFS_TO_HSFS(vp->v_vfsp);
		*valp = fsp->hsfs_namemax;
		break;

	case _PC_FILESIZEBITS:
		*valp = 33;	/* Without multi extent support: 4 GB - 2k */
		break;

	case _PC_TIMESTAMP_RESOLUTION:
		/*
		 * HSFS keeps, at best, 1/100 second timestamp resolution.
		 */
		*valp = 10000000L;
		break;

	default:
		error = fs_pathconf(vp, cmd, valp, cr, ct);
		break;
	}

	return (error);
}



const fs_operation_def_t hsfs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = hsfs_open },
	VOPNAME_CLOSE,		{ .vop_close = hsfs_close },
	VOPNAME_READ,		{ .vop_read = hsfs_read },
	VOPNAME_GETATTR,	{ .vop_getattr = hsfs_getattr },
	VOPNAME_ACCESS,		{ .vop_access = hsfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = hsfs_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = hsfs_readdir },
	VOPNAME_READLINK,	{ .vop_readlink = hsfs_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = hsfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = hsfs_inactive },
	VOPNAME_FID,		{ .vop_fid = hsfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = hsfs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = hsfs_frlock },
	VOPNAME_GETPAGE,	{ .vop_getpage = hsfs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = hsfs_putpage },
	VOPNAME_MAP,		{ .vop_map = hsfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = hsfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = hsfs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = hsfs_pathconf },
	NULL,			NULL
};

struct vnodeops *hsfs_vnodeops;
