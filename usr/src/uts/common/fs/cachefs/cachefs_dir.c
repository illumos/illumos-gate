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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/dirent.h>
#include <sys/fbuf.h>
#include <rpc/types.h>
#include <vm/seg.h>
#include <vm/faultcode.h>
#include <vm/hat.h>
#include <vm/seg_map.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dir.h>
#include <sys/fs/cachefs_log.h>

/* forward declarations */
static int cachefs_dir_getentrys(struct cnode *, u_offset_t, u_offset_t *,
    uint_t *, uint_t, caddr_t, int *);
static int cachefs_dir_stuff(cnode_t *dcp, uint_t count, caddr_t buf,
    vnode_t *frontvp, u_offset_t *offsetp, u_offset_t *fsizep);
static int cachefs_dir_extend(cnode_t *, u_offset_t *, int incr_frontblks);
static int cachefs_dir_fill_common(cnode_t *dcp, cred_t *cr,
    vnode_t *frontvp, vnode_t *backvp, u_offset_t *frontsize);
static int cachefs_dir_complete(fscache_t *fscp, vnode_t *backvp,
    vnode_t *frontvp, cred_t *cr, int acltoo);



/*
 * cachefs_dir_look() called mainly by lookup (and create), looks up the cached
 * directory for an entry and returns the information there. If the directory
 * entry doesn't exist return ENOENT, if it is incomplete, return EINVAL.
 * Should only call this routine if the dir is populated.
 * Returns ENOTDIR if dir gets nuked because of front file problems.
 */
int
cachefs_dir_look(cnode_t *dcp, char *nm, fid_t *cookiep, uint_t *flagp,
    u_offset_t *d_offsetp, cfs_cid_t *cidp)
{
	int error;
	struct vattr va;
	u_offset_t blockoff = 0LL;
	uint_t offset = 0; /* offset inside the block of size MAXBSIZE */
	vnode_t *dvp;
	struct fscache *fscp = C_TO_FSCACHE(dcp);
	cachefscache_t *cachep = fscp->fs_cache;
	int nmlen;
	struct fbuf *fbp;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_look: ENTER dcp %p nm %s\n", (void *)dcp,
									nm);
#endif
	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT(dcp->c_metadata.md_flags & MD_POPULATED);
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
		error = ENOTDIR;
		goto out;
	}

	dvp = dcp->c_frontvp;
	va.va_mask = AT_SIZE;		/* XXX should save dir size */
	error = VOP_GETATTR(dvp, &va, 0, kcred, NULL);
	if (error) {
		cachefs_inval_object(dcp);
		error = ENOTDIR;
		goto out;
	}

	ASSERT(va.va_size != 0LL);
	nmlen = (int)strlen(nm);
	while (blockoff < va.va_size) {
		offset = 0;
		error =
		    fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
		if (error)
			goto out;

		while (offset < MAXBSIZE && (blockoff + offset) < va.va_size) {
			struct c_dirent *dep;

			dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr +
								offset);
			if ((dep->d_flag & CDE_VALID) &&
				(nmlen == dep->d_namelen) &&
				strcmp(dep->d_name, nm) == 0) {
				if (dep->d_flag & CDE_COMPLETE) {
					if (cookiep) {
						CACHEFS_FID_COPY(&dep->d_cookie,
							cookiep);
					}
					if (flagp)
						*flagp = dep->d_flag;
					error = 0;
				} else {
					error = EINVAL;
				}
				if (cidp)
					*cidp = dep->d_id;
				if (d_offsetp)
					*d_offsetp = offset + blockoff;
				fbrelse(fbp, S_OTHER);
				goto out;
			}
			ASSERT(dep->d_length != 0);
			offset += dep->d_length;
		}
		fbrelse(fbp, S_OTHER);
		blockoff += MAXBSIZE;
	}
	error = ENOENT;

out:
	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_RFDIR))
		cachefs_log_rfdir(cachep, error, fscp->fs_cfsvfsp,
		    &dcp->c_metadata.md_cookie, dcp->c_id.cid_fileno, 0);
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("c_dir_look: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * creates a new directory and populates it with "." and ".."
 */
int
cachefs_dir_new(cnode_t *dcp, cnode_t *cp)
{
	int		error = 0;
	struct c_dirent	*dep;
	u_offset_t	size;
	int len;
	struct fbuf	*fbp;
#ifdef CFSDEBUG
	struct vattr	va;

	CFS_DEBUG(CFSDEBUG_DIR)
		printf("c_dir_new: ENTER dcp %p cp %p\n", (void *)dcp,
							(void *)cp);
#endif

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(CTOV(cp)->v_type == VDIR);
	ASSERT((cp->c_flags & CN_ASYNC_POPULATE) == 0);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(C_TO_FSCACHE(dcp)) == 0);

	if (cp->c_frontvp == NULL) {
		error = cachefs_getfrontfile(cp);
		if (error)
			goto out;
	}

#ifdef CFSDEBUG
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(cp->c_frontvp, &va, 0, kcred, NULL);
	if (error)
		goto out;
	ASSERT(va.va_size == 0);
#endif

	/*
	 * Extend the directory by one MAXBSIZE chunk
	 */
	size = 0LL;
	error = cachefs_dir_extend(cp, &size, 1);
	if (error != 0)
		goto out;
	error = fbread(cp->c_frontvp, (offset_t)0, MAXBSIZE, S_OTHER, &fbp);
	if (error)
		goto out;

	/*
	 * Insert "." and ".."
	 */
	len = (int)CDE_SIZE(".");
	dep = (struct c_dirent *)fbp->fb_addr;
	dep->d_length = len;
	dep->d_offset = (offset_t)len;
	dep->d_flag = CDE_VALID | CDE_COMPLETE;
	CACHEFS_FID_COPY(&cp->c_cookie, &dep->d_cookie);
	dep->d_id = cp->c_id;
	dep->d_namelen = 1;
	bcopy(".", dep->d_name, 2);

	dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + len);
	dep->d_length = MAXBSIZE - len;
	dep->d_offset = MAXBSIZE;
	dep->d_flag = CDE_VALID | CDE_COMPLETE;
	CACHEFS_FID_COPY(&dcp->c_cookie, &dep->d_cookie);
	dep->d_id = dcp->c_id;
	dep->d_namelen = 2;
	bcopy("..", dep->d_name, 3);

	(void) fbdwrite(fbp);
#ifdef INVALREADDIR
	cp->c_metadata.md_flags |= MD_POPULATED | MD_INVALREADDIR;
#else
	cp->c_metadata.md_flags |= MD_POPULATED;
#endif
	cp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;
out:
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_new: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * cachefs_dir_enter adds a new directory entry. Takes as input a fid,
 * fileno and a sync flag. Most of the time, the caller is content with the
 * write to the (front) directory being done async. The exception being - for
 * local files, we should make sure that the directory entry is made
 * synchronously. That is notified by the caller.
 * 		issync == 0 || issync == SM_ASYNC !
 *
 * The new entry is inserted at the end, so that we can generate local offsets
 * which are compatible with the backfs offsets (which are used when
 * disconnected.
 */
int
cachefs_dir_enter(cnode_t *dcp, char *nm, fid_t *cookiep, cfs_cid_t *cidp,
    int issync)
{
	struct vattr	va;
	int offset;
	u_offset_t blockoff = 0LL;
	u_offset_t	prev_offset;
	int		error = 0;
	vnode_t		*dvp;
	struct c_dirent	*dep;
	uint_t		esize;
	u_offset_t	dirsize;
	struct fbuf	*fbp;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("c_dir_enter: ENTER dcp %p nm %s dirflg %x\n",
			(void *)dcp, nm, dcp->c_metadata.md_flags);
#endif

	ASSERT(MUTEX_HELD(&dcp->c_statelock));
	ASSERT(dcp->c_metadata.md_flags & MD_POPULATED);
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);
	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT(issync == 0 || issync == SM_ASYNC);
	ASSERT(strlen(nm) <= MAXNAMELEN);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
		error = ENOTDIR;
		goto out;
	}
	dvp = dcp->c_frontvp;

	/*
	 * Get the current EOF for the directory(data file)
	 */
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(dvp, &va, 0, kcred, NULL);
	if (error) {
		cachefs_inval_object(dcp);
		error = ENOTDIR;
		goto out;
	}

	/*
	 * Get the last block of the directory
	 */
	dirsize = va.va_size;
	ASSERT(dirsize != 0LL);
	ASSERT(!(dirsize & MAXBOFFSET));
	ASSERT(dirsize <= MAXOFF_T);
	blockoff = dirsize - MAXBSIZE;
	error = fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
	if (error)
		goto out;

	/*
	 * Find the last entry
	 */
	offset = 0;
	prev_offset = blockoff;
	for (;;) {
		dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + offset);
		if (offset + dep->d_length == MAXBSIZE)
			break;
		prev_offset = dep->d_offset;
		offset += dep->d_length;
		ASSERT(offset < MAXBSIZE);
	}
	esize = C_DIRSIZ(dep);

	if (dep->d_length - esize >= CDE_SIZE(nm)) {
		/*
		 * It has room. If the entry is not valid, we can just use
		 * it. Otherwise, we need to adjust its length and offset
		 */
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_DIR) {
			if (prev_offset >= dep->d_offset) {
				printf("cachefs_dir_enter: looks like "
				    "we might fail the assert\n");
				printf("addr %p, offset %x, "
				    "prev_offset %llx, dep->d_offset %llx\n",
				    (void *)fbp->fb_addr, offset, prev_offset,
				    dep->d_offset);
				offset = 0;
				prev_offset = blockoff;
				for (;;) {
					dep = (struct c_dirent *)
					    ((uintptr_t)fbp->fb_addr + offset);
					printf("offset %x, prev_offset %llx\n",
					    offset, prev_offset);
					printf("dep->d_offset %llx, "
					    "dep->d_length %x\n",
					    dep->d_offset, dep->d_length);
					if (offset + dep->d_length == MAXBSIZE)
						break;
					prev_offset = dep->d_offset;
					offset += dep->d_length;
				}
			}
		}
#endif /* CFSDEBUG */

		if (offset)
			ASSERT(prev_offset < dep->d_offset);
		if (dep->d_flag & CDE_VALID) {
			dep->d_length = esize;
			dep->d_offset = prev_offset + (u_offset_t)esize;
			dep = (struct c_dirent *)((uintptr_t)dep + esize);
		}
		dep->d_length = (int)((offset_t)MAXBSIZE -
				((uintptr_t)dep - (uintptr_t)fbp->fb_addr));
	} else {
		/*
		 * No room - so extend the file by one more
		 * MAXBSIZE chunk, and fit the entry there.
		 */
		fbrelse(fbp, S_OTHER);
		error = cachefs_dir_extend(dcp, &dirsize, 1);
		if (error != 0)
			goto out;
		error =
		    fbread(dvp, (offset_t)va.va_size, MAXBSIZE, S_OTHER, &fbp);
		if (error)
			goto out;
		dep = (struct c_dirent *)fbp->fb_addr;
		dep->d_length = MAXBSIZE;
	}

	/*
	 * Fill in the rest of the new entry
	 */
	dep->d_offset = dirsize;
	dep->d_flag = CDE_VALID;
	if (cookiep) {
		dep->d_flag |= CDE_COMPLETE;
		CACHEFS_FID_COPY(cookiep, &dep->d_cookie);
	}
	dep->d_id = *cidp;
	dep->d_namelen = (ushort_t)strlen(nm);
	(void) bcopy(nm, dep->d_name, dep->d_namelen + 1);

#ifdef INVALREADDIR
	dcp->c_metadata.md_flags |= MD_INVALREADDIR;
#endif
	dcp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;
	if (issync)
		(void) fbwrite(fbp);
	else
		(void) fbdwrite(fbp);
out:
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_enter: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * Quite simple, if the deleted entry is the first in the MAXBSIZE block,
 * we simply mark it invalid. Otherwise, the deleted entries d_length is
 * just added to the previous entry.
 */
int
cachefs_dir_rmentry(cnode_t *dcp, char *nm)
{
	u_offset_t blockoff = 0LL;
	int offset = 0;
	struct vattr va;
	int error = ENOENT;
	vnode_t *dvp;
	int nmlen;
	struct fbuf *fbp;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_rmentry: ENTER dcp %p nm %s\n",
		    (void *)dcp, nm);
#endif
	ASSERT(dcp->c_metadata.md_flags & MD_POPULATED);
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
		error = ENOTDIR;
		goto out;
	}
	dvp = dcp->c_frontvp;

	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT((dcp->c_flags & CN_NOCACHE) == 0);
	ASSERT(dvp != NULL);
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(dvp, &va, 0, kcred, NULL);
	if (error) {
		cachefs_inval_object(dcp);
		error = ENOTDIR;
		goto out;
	}
	ASSERT(va.va_size != 0LL);

	nmlen = (int)strlen(nm);
	while (blockoff < va.va_size) {
		uint_t *last_len;

		offset = 0;
		last_len = NULL;
		error =
		    fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
		if (error)
			goto out;
		while (offset < MAXBSIZE && (blockoff + offset) < va.va_size) {
			struct c_dirent *dep;

			dep  = (struct c_dirent *)((uintptr_t)fbp->fb_addr +
								offset);
			if ((dep->d_flag & CDE_VALID) &&
				(nmlen == dep->d_namelen) &&
				strcmp(dep->d_name, nm) == 0) {
				/*
				 * Found the entry. If this was the first entry
				 * in the MAXBSIZE block, Mark it invalid. Else
				 * add it's length to the previous entry's
				 * length.
				 */
				if (last_len == NULL) {
					ASSERT(offset == 0);
					dep->d_flag = 0;
				} else
					*last_len += dep->d_length;
				(void) fbdwrite(fbp);
				dcp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;
				goto out;
			}
			last_len = &dep->d_length;
			offset += dep->d_length;
		}
		fbrelse(fbp, S_OTHER);
		blockoff += MAXBSIZE;
	}
	error = ENOENT;

out:
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_rmentry: EXIT error = %d\n", error);
#endif
	return (error);
}

#if 0
/*
 * This function is used only in cachefs_lookup_back() routine but
 * is inside #if 0 directive in this routine. So I am keeping this
 * routine also in #if 0 directive.
 */

/*
 * This function fills in the cookie and file no of the directory entry
 * at the offset specified by offset - In other words, makes the entry
 * "complete".
 */
int
cachefs_dir_modentry(cnode_t *dcp, u_offset_t offset, fid_t *cookiep,
    cfs_cid_t *cidp)
{
	struct c_dirent *dep;
	u_offset_t blockoff = (offset & (offset_t)MAXBMASK);
	uint_t off = (uint_t)(offset & (offset_t)MAXBOFFSET);
	struct fbuf *fbp;
	vnode_t *dvp;
	int error = 0;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_modentry: ENTER dcp %p offset %lld\n",
			(void *)dcp, offset);
#endif
	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT(dcp->c_metadata.md_flags & MD_POPULATED);
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
		return;
	}
	dvp = dcp->c_frontvp;

	error = fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
	if (error)
		goto out;
	dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
	if (cookiep) {
		dep->d_flag |= CDE_COMPLETE;
		CACHEFS_FID_COPY(cookiep, &dep->d_cookie);
	}
	if (cidp)
		dep->d_id = *cidp;
	(void) fbdwrite(fbp);
	dcp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;

out:
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_modentry: EXIT\n");
#endif
	return (error);
}

#endif  /* of #if 0 */

/*
 * Called by cachefs_read_dir(). Gets a bunch if directory entries into buf and
 * packs them into buf.
 */
static int
cachefs_dir_getentrys(struct cnode *dcp, u_offset_t beg_off,
		u_offset_t *last_offp, uint_t *cntp, uint_t bufsize,
				caddr_t buf, int *eofp)
{

#define	DIR_ENDOFF	0x7fffffffLL

	struct vattr va;
	struct c_dirent *dep;
	struct fbuf *fbp = NULL;
	struct dirent64 *gdp;
	u_offset_t blockoff;
	uint_t off;
	int error;
	vnode_t *dvp = dcp->c_frontvp;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
	printf("cachefs_dir_getentrys: "
	    "ENTER dcp %p beg_off %lld mdflags %x cflags %x\n",
	    dcp, beg_off, dcp->c_metadata.md_flags, dcp->c_flags);
#endif

	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	/*
	 * blockoff has the offset of the MAXBSIZE block that contains the
	 * entry  to start with. off contains the offset relative to the
	 * begining of the MAXBSIZE block.
	 */
	if (eofp)
		*eofp = 0;
	gdp = (struct dirent64 *)buf;
	*cntp = bufsize;
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(dvp, &va, 0, kcred, NULL);
	if (error) {
		*cntp = 0;
		*last_offp = 0;
		if (eofp)
			*eofp = 1;
		goto out;
	}
	ASSERT(va.va_size != 0LL);

	if (beg_off == DIR_ENDOFF) {
		*cntp = 0;
		*last_offp = DIR_ENDOFF;
		if (eofp)
			*eofp = 1;
		goto out;
	}

	/*
	 * locate the offset where we start reading.
	 */
	for (blockoff = 0; blockoff < va.va_size; blockoff += MAXBSIZE) {
		error =
		    fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
		if (error)
			goto out;
		dep = (struct c_dirent *)fbp->fb_addr;
		off = 0;
		while (off < MAXBSIZE && dep->d_offset <= beg_off) {
			off += dep->d_length;
			dep =
			    (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
		}
		if (off < MAXBSIZE)
			break;
		fbrelse(fbp, S_OTHER);
		fbp = NULL;
	}

	if (blockoff >= va.va_size) {
		*cntp = 0;
		*last_offp = DIR_ENDOFF;
		if (eofp)
			*eofp = 1;
		goto out;
	}

	/*
	 * Just load up the buffer with directory entries.
	 */
	for (;;) {
		uint_t size;
		int this_reclen;

		ASSERT((uintptr_t)dep < ((uintptr_t)fbp->fb_addr + MAXBSIZE));
		if (dep->d_flag & CDE_VALID) {
			this_reclen = DIRENT64_RECLEN(dep->d_namelen);
			size = C_DIRSIZ(dep);
			ASSERT(size < MAXBSIZE);
			if (this_reclen > bufsize)
				break;
			ASSERT(dep->d_namelen <= MAXNAMELEN);
			ASSERT(dep->d_offset > (*last_offp));
			gdp->d_ino = dep->d_id.cid_fileno;
			gdp->d_off = dep->d_offset;

			/* use strncpy(9f) to zero out uninitialized bytes */

			ASSERT(strlen(dep->d_name) + 1 <=
			    DIRENT64_NAMELEN(this_reclen));
			(void) strncpy(gdp->d_name, dep->d_name,
			    DIRENT64_NAMELEN(this_reclen));

			gdp->d_reclen = (ushort_t)this_reclen;
			bufsize -= this_reclen;
			gdp = (struct dirent64 *)((uintptr_t)gdp +
				gdp->d_reclen);
			*last_offp = dep->d_offset;
		}

		/*
		 * Increment the offset. If we've hit EOF, fill in
		 * the lastoff and current entries d_off field.
		 */
		off += dep->d_length;
		ASSERT(off <= MAXBSIZE);
		if ((blockoff + off) >= va.va_size) {
			*last_offp = DIR_ENDOFF;
			if (eofp)
				*eofp = 1;
			break;
		}
		/*
		 * If off == MAXBSIZE, then we need to adjust our
		 * window to the next MAXBSIZE block of the directory.
		 * Adjust blockoff, off and map it in. Also, increment
		 * the directory and buffer pointers.
		 */
		if (off == MAXBSIZE) {
			fbrelse(fbp, S_OTHER);
			fbp = NULL;
			off = 0;
			blockoff += MAXBSIZE;
			error = fbread(dvp, (offset_t)blockoff, MAXBSIZE,
								S_OTHER, &fbp);
			if (error)
				goto out;
		}
		dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
	}
	*cntp -= bufsize;
out:
	/*
	 * Release any buffer and maping that may exist.
	 */
	if (fbp)
		(void) fbrelse(fbp, S_OTHER);
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("ccachefs_dir_getentrys: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * Called by cachefs_readdir(). Fills a directory request from the cache
 */
int
cachefs_dir_read(struct cnode *dcp, struct uio *uiop, int *eofp)
{
	int error;
	uint_t count;
	uint_t size;
	caddr_t buf;
	u_offset_t next = uiop->uio_loffset;
	struct fscache *fscp = C_TO_FSCACHE(dcp);
	cachefscache_t *cachep = fscp->fs_cache;
	caddr_t chrp, end;
	dirent64_t *de;

	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT(RW_READ_HELD(&dcp->c_rwlock));

	ASSERT(next <= MAXOFF_T);
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_read: ENTER dcp %p\n", (void *)dcp);
#endif
	ASSERT((dcp->c_metadata.md_flags & (MD_FILE|MD_POPULATED)) ==
	    (MD_FILE|MD_POPULATED));
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
		error = ENOTDIR;
		goto out;
	}

	size = (uint_t)uiop->uio_resid;
	buf = cachefs_kmem_alloc(size, KM_SLEEP);
	error = cachefs_dir_getentrys(dcp, next, &next, &count, size,
	    buf, eofp);
	if (error == 0 && (int)count > 0) {
		ASSERT(count <= size);
		if (fscp->fs_inum_size > 0) {
			ino64_t newinum;

			mutex_exit(&dcp->c_statelock);
			mutex_enter(&fscp->fs_fslock);
			end = (caddr_t)((uintptr_t)buf + count);
			for (chrp = buf; chrp < end; chrp += de->d_reclen) {
				de = (dirent64_t *)chrp;

				newinum = cachefs_inum_real2fake(fscp,
				    de->d_ino);
				if (newinum == 0)
					newinum = cachefs_fileno_conflict(fscp,
					    de->d_ino);
				de->d_ino = newinum;
			}
			mutex_exit(&fscp->fs_fslock);
			mutex_enter(&dcp->c_statelock);
		}
		error = uiomove(buf, count, UIO_READ, uiop);
		if (error == 0)
			uiop->uio_loffset = next;
	}
	(void) cachefs_kmem_free(buf, size);
out:
	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_RFDIR))
		cachefs_log_rfdir(cachep, error, fscp->fs_cfsvfsp,
		    &dcp->c_metadata.md_cookie, dcp->c_id.cid_fileno, 0);
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_read: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * Fully (including cookie) populates the directory from the back filesystem.
 */
int
cachefs_dir_fill(cnode_t *dcp, cred_t *cr)
{
	int error = 0;
	u_offset_t frontsize;
	struct fscache *fscp = C_TO_FSCACHE(dcp);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_fill: ENTER dcp %p\n", (void *)dcp);
#endif
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
	ASSERT(MUTEX_HELD(&dcp->c_statelock));

	/* XXX for now return success if async populate is scheduled */
	if (dcp->c_flags & CN_ASYNC_POPULATE)
		goto out;

	/* get the back vp */
	if (dcp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, dcp);
		if (error) {
			goto out;
		}
	}

	/* get the front file vp */
	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if (dcp->c_flags & CN_NOCACHE) {
		error = ENOTDIR;
		goto out;
	}

	/* if dir was modified, toss old contents */
	if (dcp->c_metadata.md_flags & MD_INVALREADDIR) {
		cachefs_inval_object(dcp);
		if (dcp->c_flags & CN_NOCACHE) {
			error = ENOTDIR;
			goto out;
		}
	}

	error = cachefs_dir_fill_common(dcp, cr,
	    dcp->c_frontvp, dcp->c_backvp, &frontsize);
	if (error == 0)
		error = cachefs_dir_complete(fscp, dcp->c_backvp,
		    dcp->c_frontvp, cr, 0);
	if (error != 0)
		goto out;

	/*
	 * Mark the directory as not empty. Also bang the flag that says that
	 * this directory needs to be sync'ed on inactive.
	 */
	dcp->c_metadata.md_flags |= MD_POPULATED;
	dcp->c_metadata.md_flags &= ~MD_INVALREADDIR;
	dcp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;
	/*LINTED alignment okay*/
	dcp->c_metadata.md_frontblks = frontsize / MAXBSIZE;

out:
	if (error) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_INVALIDATE)
			printf("c_dir_fill: invalidating %llu\n",
			    (u_longlong_t)dcp->c_id.cid_fileno);
#endif
		cachefs_inval_object(dcp);
	}

	return (error);
}

/*
 * Does work of populating directory.
 * Must be called while holding dcp->c_statelock
 */

static int
cachefs_dir_fill_common(cnode_t *dcp, cred_t *cr,
    vnode_t *frontvp, vnode_t *backvp, u_offset_t *frontsize)
{
	int error = 0;
	struct uio uio;
	struct iovec iov;
	caddr_t buf = NULL;
	int count;
	int eof = 0;
	u_offset_t frontoff;
	struct fscache *fscp = C_TO_FSCACHE(dcp);
	cachefscache_t *cachep = fscp->fs_cache;
#ifdef DEBUG
	int loop_count = 0;
#endif
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_fill_common: ENTER dcp %p\n", (void *)dcp);
#endif

	ASSERT(MUTEX_HELD(&dcp->c_statelock));

	frontoff = *frontsize = 0LL;

	buf = cachefs_kmem_alloc(MAXBSIZE, KM_SLEEP);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;
	for (;;) {
#ifdef DEBUG
		loop_count++;
#endif
		/*
		 * Read in a buffer's worth of dirents and enter them in to the
		 * directory.
		 */
		uio.uio_resid = MAXBSIZE;
		iov.iov_base = buf;
		iov.iov_len = MAXBSIZE;
		(void) VOP_RWLOCK(backvp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(backvp, &uio, cr, &eof, NULL, 0);
		VOP_RWUNLOCK(backvp, V_WRITELOCK_FALSE, NULL);
		if (error)
			goto out;

		/*LINTED alignment okay*/
		count = MAXBSIZE - (int)uio.uio_resid;
		ASSERT(count >= 0);
		if (count > 0) {
			if (error = cachefs_dir_stuff(dcp, count, buf,
			    frontvp, &frontoff, frontsize))
				goto out;
			ASSERT((*frontsize) != 0LL);
		}
		if (eof || count == 0)
			break;
	}

	if (*frontsize == 0LL) {
		/* keep us from caching an empty directory */
		error = EINVAL;
		goto out;
	}

out:
	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_FILLDIR))
		cachefs_log_filldir(cachep, error, fscp->fs_cfsvfsp,
		    &dcp->c_metadata.md_cookie, dcp->c_id.cid_fileno,
		    *frontsize);
	if (buf)
		cachefs_kmem_free(buf, (uint_t)MAXBSIZE);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_fill: EXIT error = %d\n", error);
#endif
	return (error);
}

/*
 * If the directory contains only the elements "." and "..", then this returns
 * 0, otherwise returns an error.
 */
int
cachefs_dir_empty(cnode_t *dcp)
{
	struct vattr va;
	u_offset_t blockoff = 0;
	int offset;
	struct fbuf *fbp;
	int error;
	vnode_t *dvp = dcp->c_frontvp;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_dir_empty: ENTER dcp %p\n", (void *)dcp);
#endif
	ASSERT(CTOV(dcp)->v_type == VDIR);
	ASSERT(dcp->c_metadata.md_flags & MD_POPULATED);
	ASSERT((dcp->c_flags & CN_ASYNC_POPULATE) == 0);

	if (dcp->c_frontvp == NULL)
		(void) cachefs_getfrontfile(dcp);
	if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0)
		return (ENOTDIR);

	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(dvp, &va, 0, kcred, NULL);
	if (error)
		return (ENOTDIR);

	ASSERT(va.va_size != 0LL);
	while (blockoff < va.va_size) {
		offset = 0;
		error =
		    fbread(dvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
		if (error)
			return (error);
		while (offset < MAXBSIZE && (blockoff + offset) < va.va_size) {
			struct c_dirent *dep;

			dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr +
								offset);
			if ((dep->d_flag & CDE_VALID) &&
				((strcmp(dep->d_name, ".") != 0) &&
				(strcmp(dep->d_name, "..") != 0))) {
				(void) fbrelse(fbp, S_OTHER);
				return (0);
			}
			offset += dep->d_length;
		}
		(void) fbrelse(fbp, S_OTHER);
		blockoff += MAXBSIZE;
	}
	return (EEXIST);
}

/*
 * Called by cachefs_dir_fill() to stuff a buffer of dir entries into
 * a front file.  This is more efficient than repeated calls to
 * cachefs_dir_enter, and it also allows us to maintain entries in backfs
 * order (readdir requires that entry offsets be ascending).
 */
static int
cachefs_dir_stuff(cnode_t *dcp, uint_t count, caddr_t buf,
    vnode_t *frontvp, u_offset_t *offsetp, u_offset_t *fsizep)
{
	int error = 0;
	struct fbuf *fbp;
	struct c_dirent *cdep, *last;
	struct dirent64 *dep;
	int inblk, entsize;
	u_offset_t blockoff = (*offsetp & (offset_t)MAXBMASK);
	/*LINTED alignment okay*/
	uint_t off = (uint_t)(*offsetp & (offset_t)MAXBOFFSET);

	/*LINTED want count != 0*/
	ASSERT(count > 0);

	if (*offsetp >= *fsizep) {
		error = cachefs_dir_extend(dcp, fsizep, 0);
		if (error)
			return (error);
	}

	ASSERT(*fsizep != 0LL);
	last = NULL;
	error = fbread(frontvp, (offset_t)blockoff, MAXBSIZE, S_OTHER, &fbp);
	if (error)
		return (error);
	cdep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
	inblk = MAXBSIZE-off;
	if (*offsetp != 0) {
		ASSERT(cdep->d_length == inblk);
		inblk -= C_DIRSIZ(cdep);
		last = cdep;
		last->d_length -= inblk;
		off += last->d_length;
		cdep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
	}
	dep = (struct dirent64 *)buf;
	/*LINTED want count != 0*/
	while (count > 0) {
		if (last) {
			ASSERT(dep->d_off > last->d_offset);
		}
		entsize = (int)CDE_SIZE(dep->d_name);
		if (entsize > inblk) {
			if (last) {
				last->d_length += inblk;
			}
			(void) fbwrite(fbp);
			error = cachefs_dir_extend(dcp, fsizep, 0);
			if (error)
				return (error);
			ASSERT(*fsizep != 0LL);
			blockoff += MAXBSIZE;
			error = fbread(frontvp, (offset_t)blockoff, MAXBSIZE,
							S_OTHER, &fbp);
			if (error)
				return (error);
			off = 0;
			cdep = (struct c_dirent *)fbp->fb_addr;
			inblk = MAXBSIZE;
			last = NULL;
		}
		cdep->d_length = entsize;
		cdep->d_id.cid_fileno = dep->d_ino;
		cdep->d_id.cid_flags = 0;
		cdep->d_namelen = (ushort_t)strlen(dep->d_name);
		cdep->d_flag = CDE_VALID;
		bcopy(dep->d_name, cdep->d_name, cdep->d_namelen+1);
		cdep->d_offset = dep->d_off;
		inblk -= entsize;
		count -= dep->d_reclen;
		dep = (struct dirent64 *)((uintptr_t)dep + dep->d_reclen);
		*offsetp = blockoff + (u_offset_t)off;
		off += entsize;
		last = cdep;
		cdep = (struct c_dirent *)((uintptr_t)fbp->fb_addr + off);
	}
	if (last) {
		last->d_length += inblk;
	}
	(void) fbwrite(fbp);
	return (error);
}

static int
cachefs_dir_extend(cnode_t *dcp, u_offset_t *cursize, int incr_frontblks)
{
	struct vattr va;
	cachefscache_t *cachep = C_TO_FSCACHE(dcp)->fs_cache;
	int error = 0;
	struct fscache *fscp = VFS_TO_FSCACHE(CTOV(dcp)->v_vfsp);

	ASSERT(MUTEX_HELD(&dcp->c_statelock));
	ASSERT(((*cursize) & (MAXBSIZE-1)) == 0);

	va.va_mask = AT_SIZE;
	va.va_size = (u_offset_t)(*cursize + MAXBSIZE);
	error = cachefs_allocblocks(cachep, 1, dcp->c_metadata.md_rltype);
	if (error)
		return (error);
	error = VOP_SETATTR(dcp->c_frontvp, &va, 0, kcred, NULL);
	if (error) {
		cachefs_freeblocks(cachep, 1, dcp->c_metadata.md_rltype);
		return (error);
	}
	if (incr_frontblks)
		dcp->c_metadata.md_frontblks++;
	if (fscp->fs_cdconnected != CFS_CD_CONNECTED) {
		dcp->c_size += MAXBSIZE;
		dcp->c_attr.va_size = dcp->c_size;
	}
	*cursize += MAXBSIZE;
	ASSERT(*cursize != 0LL);
	if (incr_frontblks)
		dcp->c_flags |= CN_UPDATED;
	return (0);
}

int
cachefs_async_populate_dir(struct cachefs_populate_req *pop, cred_t *cr,
    vnode_t *backvp, vnode_t *frontvp)
{
	vnode_t *dvp = pop->cpop_vp;
	struct cnode *dcp = VTOC(dvp);
	u_offset_t frontsize;
	int error = 0;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_async_populate_dir: ENTER dvp %p\n",
								(void *)dvp);
#endif
	ASSERT(MUTEX_HELD(&dcp->c_statelock));
	ASSERT(dvp->v_type == VDIR);
	ASSERT((dcp->c_metadata.md_flags & MD_POPULATED) == 0);
	ASSERT(dcp->c_frontvp == frontvp);
	ASSERT(dcp->c_backvp == backvp);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(C_TO_FSCACHE(dcp)) == 0);

	/* if dir was modified, toss old contents */
	if (dcp->c_metadata.md_flags & MD_INVALREADDIR) {
		cachefs_inval_object(dcp);
		if (dcp->c_flags & CN_NOCACHE) {
			error = ENOTDIR;
			goto out;
		} else {
			dcp->c_metadata.md_flags &= ~MD_INVALREADDIR;
		}
	}


	error = cachefs_dir_fill_common(dcp, cr, frontvp, backvp, &frontsize);
	if (error != 0)
		goto out;
	ASSERT(frontsize != 0LL);
	mutex_exit(&dcp->c_statelock);
	/*
	 * I don't like to break lock here but cachefs_dir_complete()
	 * needs it.
	 */
	error = cachefs_dir_complete(C_TO_FSCACHE(dcp), backvp,
	    frontvp, cr, 1);
	mutex_enter(&dcp->c_statelock);
	if (error != 0)
		goto out;
	/* if went nocache while lock was dropped, get out */
	if ((dcp->c_flags & CN_NOCACHE) || (dcp->c_frontvp == NULL)) {
		error = EINVAL;
	} else {
		/* allocfile and allocblocks have already happened. */
		dcp->c_metadata.md_frontblks = frontsize / MAXBSIZE;
	}

out:

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_DIR)
		printf("cachefs_async_populate_dir: EXIT error = %d\n", error);
#endif

	return (error);
}

static int
cachefs_dir_complete(fscache_t *fscp, vnode_t *backvp, vnode_t *frontvp,
    cred_t *cr, int acltoo)
{
	struct c_dirent *dep;
	caddr_t buf = kmem_alloc(MAXBSIZE, KM_SLEEP);
	struct vattr va;
	u_offset_t blockoff;
	int offset;
	u_offset_t dir_size;
	struct fbuf *fbp;
	cnode_t *cp;
	fid_t cookie;
	vnode_t *entry_vp;
	int error = 0;

	/*
	 * note: caller better not hold a c_statelock if acltoo is set.
	 */

	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(frontvp, &va, 0, cr, NULL);
	if (error)
		goto out;

	ASSERT(va.va_size != 0LL);
	dir_size = va.va_size;
	ASSERT(dir_size <= MAXOFF_T);

	for (blockoff = 0; blockoff < dir_size; blockoff += MAXBSIZE) {
		if (error = fbread(frontvp, (offset_t)blockoff,
		    MAXBSIZE, S_OTHER, &fbp))
			goto out;

		/*
		 * We cannot hold any page locks across the below VOP
		 * operations. We thus copy the directory entries into a
		 * staging buffer, and release the page lock on the directory
		 * by calling fbrelse().  Once any necessary cnodes have
		 * been created, we'll reacquire the page lock with fbread()
		 * and copy the staging buffer back into the frontvp at
		 * blockoff.
		 */
		bcopy(fbp->fb_addr, buf, MAXBSIZE);
		fbrelse(fbp, S_OTHER);

		for (offset = 0;
		    offset < MAXBSIZE &&
		    (blockoff + (u_offset_t)offset) < dir_size;
		    offset += dep->d_length) {

			dep = (struct c_dirent *)((uintptr_t)buf + offset);
			ASSERT(dep->d_length != 0);
			if ((dep->d_flag & (CDE_VALID | CDE_COMPLETE)) !=
			    CDE_VALID)
				continue;

			error = VOP_LOOKUP(backvp, dep->d_name,
			    &entry_vp, (struct pathname *)NULL, 0,
			    (vnode_t *)NULL, cr, NULL, NULL, NULL);
			if (error) {
				/* lookup on .. in / on coc gets ENOENT */
				if (error == ENOENT) {
					error = 0;
					continue;
				}
				goto out;
			}

			error = cachefs_getcookie(entry_vp, &cookie, NULL, cr,
				TRUE);
			if (error) {
#ifdef CFSDEBUG
				CFS_DEBUG(CFSDEBUG_DIR)
					printf("\t%s: getcookie error\n",
					    dep->d_name);
#endif /* CFSDEBUG */
				VN_RELE(entry_vp);
				goto out;
			}
			CACHEFS_FID_COPY(&cookie, &dep->d_cookie);
			dep->d_flag |= CDE_COMPLETE;

			if ((! acltoo) ||
			    (! cachefs_vtype_aclok(entry_vp)) ||
			    (fscp->fs_info.fi_mntflags & CFS_NOACL)) {
				VN_RELE(entry_vp);
				continue;
			}

			error = cachefs_cnode_make(&dep->d_id, fscp, &cookie,
			    NULL, entry_vp, cr, 0, &cp);
			VN_RELE(entry_vp);
			if (error != 0)
				goto out;

			ASSERT(cp != NULL);
			mutex_enter(&cp->c_statelock);

			if ((cp->c_flags & CN_NOCACHE) ||
			    (cp->c_metadata.md_flags & MD_ACL)) {
				mutex_exit(&cp->c_statelock);
				VN_RELE(CTOV(cp));
				continue;
			}

			(void) cachefs_cacheacl(cp, NULL);
			mutex_exit(&cp->c_statelock);
			VN_RELE(CTOV(cp));
		}

		/*
		 * We must now re-lock the page corresponding to the frontvp,
		 * and copy our staging buffer onto it.
		 */
		if (error = fbread(frontvp, (offset_t)blockoff,
		    MAXBSIZE, S_OTHER, &fbp))
			goto out;

		bcopy(buf, fbp->fb_addr, MAXBSIZE);
		(void) fbdwrite(fbp);
	}

out:
	kmem_free(buf, MAXBSIZE);
	return (error);
}
