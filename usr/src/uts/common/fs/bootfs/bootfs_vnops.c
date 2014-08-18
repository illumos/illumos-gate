/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * bootfs vnode operations
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <fs/fs_subr.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/dirent.h>
#include <sys/uio.h>
#include <vm/pvn.h>
#include <vm/hat.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <sys/vmsystm.h>

#include <sys/fs/bootfs_impl.h>

struct vnodeops *bootfs_vnodeops;

/*ARGSUSED*/
static int
bootfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/*ARGSUSED*/
static int
bootfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/*ARGSUSED*/
static int
bootfs_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	int err;
	ssize_t sres = uiop->uio_resid;
	bootfs_node_t *bnp = vp->v_data;

	if (vp->v_type == VDIR)
		return (EISDIR);

	if (vp->v_type != VREG)
		return (EINVAL);

	if (uiop->uio_loffset < 0)
		return (EINVAL);

	if (uiop->uio_loffset >= bnp->bvn_size)
		return (0);

	err = 0;
	while (uiop->uio_resid != 0) {
		caddr_t base;
		long offset, frem;
		ulong_t poff, segoff;
		size_t bytes;
		int relerr;

		offset = uiop->uio_loffset;
		poff = offset & PAGEOFFSET;
		bytes = MIN(PAGESIZE - poff, uiop->uio_resid);

		frem = bnp->bvn_size - offset;
		if (frem <= 0) {
			err = 0;
			break;
		}

		/* Don't read past EOF */
		bytes = MIN(bytes, frem);

		/*
		 * Segmaps are likely larger than our page size, so make sure we
		 * have the proper offfset into the resulting segmap data.
		 */
		segoff = (offset & PAGEMASK) & MAXBOFFSET;

		base = segmap_getmapflt(segkmap, vp, offset & MAXBMASK, bytes,
		    1, S_READ);

		err = uiomove(base + segoff + poff, bytes, UIO_READ, uiop);
		relerr = segmap_release(segkmap, base, 0);

		if (err == 0)
			err = relerr;

		if (err != 0)
			break;
	}

	/* Even if we had an error in a partial read, return success */
	if (uiop->uio_resid > sres)
		err = 0;

	gethrestime(&bnp->bvn_attr.va_atime);

	return (err);
}

/*ARGSUSED*/
static int
bootfs_ioctl(vnode_t *vp, int cmd, intptr_t data, int flag,
    cred_t *cr, int *rvalp, caller_context_t *ct)
{
	return (ENOTTY);
}

/*ARGSUSED*/
static int
bootfs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	uint32_t mask;
	bootfs_node_t *bpn = (bootfs_node_t *)vp->v_data;

	mask = vap->va_mask;
	bcopy(&bpn->bvn_attr, vap, sizeof (vattr_t));
	vap->va_mask = mask;
	return (0);
}

/*ARGSUSED*/
static int
bootfs_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int shift = 0;
	bootfs_node_t *bpn = (bootfs_node_t *)vp->v_data;

	if (crgetuid(cr) != bpn->bvn_attr.va_uid) {
		shift += 3;
		if (groupmember(bpn->bvn_attr.va_gid, cr) == 0)
			shift += 3;
	}

	return (secpolicy_vnode_access2(cr, vp, bpn->bvn_attr.va_uid,
	    bpn->bvn_attr.va_mode << shift, mode));
}

/*ARGSUSED*/
static int
bootfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	avl_index_t where;
	bootfs_node_t sn, *bnp;
	bootfs_node_t *bpp = (bootfs_node_t *)dvp->v_data;

	if (flags & LOOKUP_XATTR)
		return (EINVAL);

	if (bpp->bvn_attr.va_type != VDIR)
		return (ENOTDIR);

	if (*nm == '\0' || strcmp(nm, ".") == 0) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	if (strcmp(nm, "..") == 0) {
		VN_HOLD(bpp->bvn_parent->bvn_vnp);
		*vpp = bpp->bvn_parent->bvn_vnp;
		return (0);
	}

	sn.bvn_name = nm;
	bnp = avl_find(&bpp->bvn_dir, &sn, &where);
	if (bnp == NULL)
		return (ENOENT);

	VN_HOLD(bnp->bvn_vnp);
	*vpp = bnp->bvn_vnp;
	return (0);
}

/*ARGSUSED*/
static int
bootfs_readdir(vnode_t *vp, struct uio *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	bootfs_node_t *bnp = (bootfs_node_t *)vp->v_data;
	dirent64_t *dp;
	void *buf;
	ulong_t bsize, brem;
	offset_t coff, roff;
	int dlen, ret;
	bootfs_node_t *dnp;
	boolean_t first = B_TRUE;

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp != NULL)
			*eofp = 1;
		return (0);
	}

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (!(uiop->uio_iov->iov_len > 0))
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	roff = uiop->uio_loffset;
	coff = 0;
	brem = bsize = uiop->uio_iov->iov_len;
	buf = kmem_alloc(bsize, KM_SLEEP);
	dp = buf;

	/*
	 * Recall that offsets here are done based on the name of the dirent
	 * excluding the null terminator. Therefore `.` is always at 0, `..` is
	 * always at 1, and then the first real dirent is at 3. This offset is
	 * what's actually stored when we update the offset in the structure.
	 */
	if (roff == 0) {
		dlen = DIRENT64_RECLEN(1);
		if (first == B_TRUE) {
			if (dlen > brem) {
				kmem_free(buf, bsize);
				return (EINVAL);
			}
			first = B_FALSE;
		}
		dp->d_ino = (ino64_t)bnp->bvn_attr.va_nodeid;
		dp->d_off = 0;
		dp->d_reclen = (ushort_t)dlen;
		(void) strncpy(dp->d_name, ".", DIRENT64_NAMELEN(dlen));
		dp = (struct dirent64 *)((uintptr_t)dp + dp->d_reclen);
		brem -= dlen;
	}

	if (roff <= 1) {
		dlen = DIRENT64_RECLEN(2);
		if (first == B_TRUE) {
			if (dlen > brem) {
				kmem_free(buf, bsize);
				return (EINVAL);
			}
			first = B_FALSE;
		}
		dp->d_ino = (ino64_t)bnp->bvn_parent->bvn_attr.va_nodeid;
		dp->d_off = 1;
		dp->d_reclen = (ushort_t)dlen;
		(void) strncpy(dp->d_name, "..", DIRENT64_NAMELEN(dlen));
		dp = (struct dirent64 *)((uintptr_t)dp + dp->d_reclen);
		brem -= dlen;
	}

	coff = 3;
	for (dnp = avl_first(&bnp->bvn_dir); dnp != NULL;
	    dnp = AVL_NEXT(&bnp->bvn_dir, dnp)) {
		size_t nlen = strlen(dnp->bvn_name);

		if (roff > coff) {
			coff += nlen;
			continue;
		}

		dlen = DIRENT64_RECLEN(nlen);
		if (dlen > brem) {
			if (first == B_TRUE) {
				kmem_free(buf, bsize);
				return (EINVAL);
			}
			break;
		}
		first = B_FALSE;

		dp->d_ino = (ino64_t)dnp->bvn_attr.va_nodeid;
		dp->d_off = coff;
		dp->d_reclen = (ushort_t)dlen;
		(void) strncpy(dp->d_name, dnp->bvn_name,
		    DIRENT64_NAMELEN(dlen));
		dp = (struct dirent64 *)((uintptr_t)dp + dp->d_reclen);
		brem -= dlen;
		coff += nlen;
	}

	ret = uiomove(buf, (bsize - brem), UIO_READ, uiop);

	if (ret == 0) {
		if (dnp == NULL) {
			coff++;
			if (eofp != NULL)
				*eofp = 1;
		} else if (eofp != NULL) {
			*eofp = 0;
		}
		uiop->uio_loffset = coff;
	}
	gethrestime(&bnp->bvn_attr.va_atime);
	kmem_free(buf, bsize);
	return (ret);
}

/*ARGSUSED*/
static void
bootfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
}

/*ARGSUSED*/
static int
bootfs_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	if (write_lock != 0)
		return (EINVAL);
	return (0);
}

/*ARGSUSED*/
static void
bootfs_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
}

/*ARGSUSED*/
static int
bootfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	bootfs_node_t *bnp = (bootfs_node_t *)vp->v_data;
	if (vp->v_type == VDIR)
		return (0);
	return ((*noffp < 0 || *noffp > bnp->bvn_size ? EINVAL : 0));
}

/*
 * We need to fill in a single page of a vnode's memory based on the actual data
 * from the kernel. We'll use this node's sliding window into physical memory
 * and update one page at a time.
 */
/*ARGSUSED*/
static int
bootfs_getapage(vnode_t *vp, u_offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr, enum seg_rw rw,
    cred_t *cr)
{
	bootfs_node_t *bnp = vp->v_data;
	page_t *pp, *fpp;
	pfn_t pfn;

	for (;;) {
		/* Easy case where the page exists */
		pp = page_lookup(vp, off, rw == S_CREATE ? SE_EXCL : SE_SHARED);
		if (pp != NULL) {
			if (pl != NULL) {
				pl[0] = pp;
				pl[1] = NULL;
			} else {
				page_unlock(pp);
			}
			return (0);
		}

		pp = page_create_va(vp, off, PAGESIZE, PG_EXCL | PG_WAIT, seg,
		    addr);

		/*
		 * If we didn't get the page, that means someone else beat us to
		 * creating this so we need to try again.
		 */
		if (pp != NULL)
			break;
	}

	pfn = btop((bnp->bvn_addr + off) & PAGEMASK);
	fpp = page_numtopp_nolock(pfn);

	if (ppcopy(fpp, pp) == 0) {
		pvn_read_done(pp, B_ERROR);
		return (EIO);
	}

	if (pl != NULL) {
		pvn_plist_init(pp, pl, plsz, off, PAGESIZE, rw);
	} else {
		pvn_io_done(pp);
	}

	return (0);
}

/*ARGSUSED*/
static int
bootfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr, enum seg_rw rw,
    cred_t *cr, caller_context_t *ct)
{
	int err;
	bootfs_node_t *bnp = vp->v_data;

	if (off + len > bnp->bvn_size + PAGEOFFSET)
		return (EFAULT);

	if (len <= PAGESIZE)
		err = bootfs_getapage(vp, (u_offset_t)off, len, protp, pl,
		    plsz, seg, addr, rw, cr);
	else
		err = pvn_getpages(bootfs_getapage, vp, (u_offset_t)off, len,
		    protp, pl, plsz, seg, addr, rw, cr);

	return (err);
}

/*ARGSUSED*/
static int
bootfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	int ret;
	segvn_crargs_t vn_a;

#ifdef	_ILP32
	if (len > MAXOFF_T)
		return (ENOMEM);
#endif

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < 0 || off > MAXOFFSET_T - off)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	if (prot & PROT_WRITE)
		return (ENOTSUP);

	as_rangelock(as);
	ret = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (ret != 0) {
		as_rangeunlock(as);
		return (ret);
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	ret = as_map(as, *addrp, len, segvn_create, &vn_a);

	as_rangeunlock(as);
	return (ret);

}

/*ARGSUSED*/
static int
bootfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/*ARGSUSED*/
static int
bootfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

static int
bootfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	int ret;

	switch (cmd) {
	case _PC_TIMESTAMP_RESOLUTION:
		*valp = 1L;
		ret = 0;
		break;
	default:
		ret = fs_pathconf(vp, cmd, valp, cr, ct);
	}

	return (ret);
}

const fs_operation_def_t bootfs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = bootfs_open },
	VOPNAME_CLOSE,		{ .vop_close = bootfs_close },
	VOPNAME_READ,		{ .vop_read = bootfs_read },
	VOPNAME_IOCTL,		{ .vop_ioctl = bootfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = bootfs_getattr },
	VOPNAME_ACCESS,		{ .vop_access = bootfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = bootfs_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = bootfs_readdir },
	VOPNAME_INACTIVE,	{ .vop_inactive = bootfs_inactive },
	VOPNAME_RWLOCK,		{ .vop_rwlock = bootfs_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = bootfs_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = bootfs_seek },
	VOPNAME_GETPAGE,	{ .vop_getpage = bootfs_getpage },
	VOPNAME_MAP,		{ .vop_map = bootfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = bootfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = bootfs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = bootfs_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_nosupport },
	NULL,			NULL
};
