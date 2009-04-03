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

#ifndef	_VM_VPM_H
#define	_VM_VPM_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The vnode page mappings(VPM) interfaces.
 * "Commitment level - Consolidation private". They are subject
 * to change without notice. Use them at your own risk.
 *
 * At this stage these interfaces are provided only to utilize the
 * segkpm mappings. Therefore these interfaces have to be used under
 * the 'vpm_enable' check as an alternative to segmap interfaces where
 * applicable.
 *
 * The VPM interfaces provide temporary mappings to file pages. They
 * return the mappings in a scatter gather list(SGL).
 * The SGL elements are the structure 'vmap_t'.
 *
 *	typedef struct vmap {
 *		caddr_t	vs_addr;        / public - mapped address /
 *		size_t	vs_len;         / public - length of mapping /
 *		void	*vs_data;	/ opaque - private data /
 *	} vmap_t;
 *
 * An array of this structure has to be passed to the interface routines
 * along with the size(# of elements) of the SGL array. Depending on the
 * requested length and mapped chunk sizes(PAGESIZE here), the number of
 * valid mappings returned can be less then actual size of the SGL array.
 * Always, an element in the SGL will have 'vs_addr' set to NULL which
 * marks the end of the valid entires in the SGL.
 *
 * The vmap_t structure members are populated with the mapped address
 * in 'vs_addr' and length of the mapping in 'vs_len'. Currently the
 * mapping length is fixed at PAGESIZE. The 'vs_data' member is private
 * and the caller should not access or modify it.
 *
 * Using a scatter gather list to return the mappings and length makes it
 * possible to provide mappings of variable length. Mapping length upto
 * VPMMAXLEN is supported.  The scatter gather list array size needs to
 * be a minimum of MINVMAPS elements.
 *
 * Interfaces:
 *
 * int vpm_map_pages( struct vnode *vp, u_offset_t off, size_t len,
 *			int fetchpage, vmap_t *vml, int vmlsz,
 *			int *newpagecreated, enum seg_rw rw);
 *
 * This function returns mappings to vnode pages.
 *
 * It takes a vnode, offset and length and returns mappings to the  pages
 * covering the range [off, off + len) in the vmap_t SGL array 'vml'.
 * The length passed in should satisfy the following criteria
 * '(off + len)  <= ((off & PAGEMASK) + VPMMAXLEN)'
 * The mapped address returned, in 'vs_addr', of first vml[] entry
 * is at begining of page containing 'off'.
 *
 * The 'vmlsz' is the size(# elements) of the 'vml' array.
 *
 * When the 'fetchpage' flag is set, the vnode(file) pages will be fetched
 * (calls VOP_GETPAGE) from the backing store(disk) if not found in the
 * system page cache. If 'fetchpage == 0', the vnode(file) pages for the
 * given offset will be just created if they are not already present in the
 * system page cache. The 'newpagecreated' flag is set on return if new pages
 * are created when 'fetchpage == 0'(requested to just create new pages).
 *
 * The 'seg_rw rw' indicates the intended operation on these mappings
 * (S_WRITE or S_READ).
 *
 * Currently these interfaces only return segkpm mappings. The vnode pages
 * that are being accessed will be locked(at least SHARED locked) for the
 * duration these mappings are in use. After use, the  unmap function,
 * vpm_unmap_pages(), has to be called and the same SGL array
 * needs to be passed to the unmap function.
 *
 *
 * void vpm_unmap_pages(vpmap_t *vml, enum seg_rw rw);.
 *
 * This function unmaps the pages that where mapped by vpm_map_pages.
 * The SGL array 'vml' has to be the one that was passed to vpm_map_pages().
 *
 *
 * ex:
 * To copy file data of vnode(file) 'vp' at offset 'off' to a kernel buffer
 * 'buf' the following code snippet shows how to use the above two interfaces.
 * Here the the copy length is till the MAXBSIZE boundary. This code can be
 * executed repeatedly, in a loop to copy more then MAXBSIZE length of data.
 *
 *	vmap_t  vml[MINVMAPS];
 *	int err, i, newpage, len;
 *	int pon;
 *
 *	pon = (off & PAGEOFFSET);
 *	len = MAXBSIZE - pon;
 *
 *	if (vpm_enable) {
 *             err = vpm_map_pages(vp, off, len, 0, vml, MINVMAPS,
 *				 &newpage, S_WRITE);
 *
 *		if (err)
 *			return;
 *
 *		for (i=0; vml[i].vs_addr != NULL); i++) {
 *			bcopy (buf, vml[i].vs_addr + pon,
 *				 PAGESIZE - pon);
 *			buf += (PAGESIZE - pon);
 *			pon = 0;
 *		}
 *
 *		if (newpage) {
 *			pon = (off & PAGEOFFSET);
 *			bzero(vml[i-1].vs_addr + pon, PAGESIZE - pon);
 *		}
 *
 *		vpm_unmap_pages(vml, S_WRITE);
 *	}
 *
 *
 *
 *
 * int vpm_data_copy(struct vnode *vp, u_offset_t off, size_t len,
 *		struct uio *uio, int fetchpage, int *newpagecreated,
 *		int zerostart, enum seg_rw rw);
 *
 * This function can be called if the need is to just transfer data to/from
 * the vnode pages. It takes a 'uio' structure and  calls 'uiomove()' to
 * do the data transfer. It can be used in the context of read and write
 * system calls to transfer data between a user buffer, which is specified
 * in the uio structure, and the vnode pages. If the data needs to be
 * transferred between a kernel buffer and the pages, like in the above
 * example, a uio structure can be set up accordingly and passed. The 'rw'
 * parameter will determine the direction of the data transfer.
 *
 * The 'fetchpage' and 'newpagecreated' are same as explained before.
 * The 'zerostart' flag when set will zero fill start of the page till the
 * offset 'off' in the first page. i.e  from 'off & PAGEMASK' to 'off'.
 *
 *
 * int vpm_sync_pages(struct vnode *vp, u_offset_t off,
 *					 size_t len, uint_t flags)
 *
 * This function can be called to flush or sync the vnode(file) pages that
 * have been accessed. It will call VOP_PUTPAGE().
 *
 * For the given vnode, off and len the pages covering the range
 * [off, off + len) are flushed. Currently it uses the same flags that
 * are used with segmap_release() interface. Refer vm/seg_map.h.
 * (SM_DONTNEED, SM_ASYNC, SM_FREE, SM_INVAL, SM_DESTROY)
 *
 */


/*
 * vpm cache related definitions.
 */
#define	VPMAP_MINCACHE		(64 * 1024 * 1024)
#define	VPMAP_MAXCACHE		(256L * 1024L * 1024L * 1024L)  /* 256G */


/*
 * vpm caching mode
 */
#define	VPMCACHE_LRU		0
#define	VPMCACHE_RANDOM		1
/*
 * Data structures to manage the cache of pages referenced by
 * the vpm interfaces. There is one vpmap struct per page in the cache.
 */
struct vpmap {
	kmutex_t	vpm_mtx;	/* protects non list fields */
	struct vnode	*vpm_vp;	/* pointer to vnode of cached page */
	struct vpmap	*vpm_next;	/* free list pointers */
	struct vpmap	*vpm_prev;
	u_offset_t	vpm_off;	/* offset of the page */
	page_t		*vpm_pp;	/* page pointer */
	ushort_t	vpm_refcnt;	/* Number active references */
	ushort_t	vpm_ndxflg;	/* indicates which queue */
	ushort_t	vpm_free_ndx;	/* freelist it belongs to */
};

/*
 * Multiple vpmap free lists are maintaned so that allocations
 * scale with cpu count. To further reduce contentions between
 * allocation and deallocations, each list is made up of two queues.
 */
#define	VPM_FREEQ_PAD	64
union vpm_freeq {
	struct {
		struct vpmap	*vpmsq_free;
		kmutex_t	vpmsq_mtx;
	} vpmfq;
	char vpmq_pad[VPM_FREEQ_PAD];
};

#define	vpmq_free	vpmfq.vpmsq_free
#define	vpmq_mtx	vpmfq.vpmsq_mtx

struct vpmfree {
	union vpm_freeq vpm_freeq[2];	/* alloc and release queue */
	union vpm_freeq *vpm_allocq;	/* current alloc queue */
	union vpm_freeq *vpm_releq;	/* current release queue */
	kcondvar_t	vpm_free_cv;
	ushort_t	vpm_want;
};

#define	VPMALLOCQ	0
#define	VPMRELEQ	1

/*
 * VPM Interface definitions.
 */

/*
 * This structure is the scatter gather list element. The page
 * mappings will be returned in this structure. A pointer to an
 * array of this structure is passed to the interface routines.
 */
typedef struct vmap {
	caddr_t	vs_addr;	/* mapped address */
	size_t	vs_len;		/* length, currently fixed at PAGESIZE */
	void	*vs_data;	/* opaque - private data */
} vmap_t;

#define	VPM_FETCHPAGE 0x01	/* fault in pages */

/*
 * Max request length - Needs to be a multiple of
 * 8192 (PAGESIZE on sparc) so it works properly on both
 * x86 & sparc systems. Max set to 128k.
 */
#define	VPMMAXLEN	(128*1024)

/*
 * The minimum and maximum number of array elements in the scatter
 * gather list.
 */
#define	MINVMAPS   3		/* ((MAXBSIZE/4096 + 1)  min # mappings */
#if defined(__sparc)
#define	VPMMAXPGS	(VPMMAXLEN/8192)	/* Max # pages at a time */
#else
#define	VPMMAXPGS	(VPMMAXLEN/4096)
#endif
#define	MAXVMAPS	(VPMMAXPGS + 1)		/* Max # elements in the */
						/* scatter gather list */
						/* +1 element to mark the */
						/* end of the list of valid */
						/*  mappings */

#ifdef _KERNEL

extern int	vpm_enable;
/*
 * vpm page mapping operations.
 */
extern void	vpm_init(void);
extern int	vpm_map_pages(struct vnode *, u_offset_t, size_t, int,
		vmap_t *, int, int  *, enum seg_rw);

extern void	vpm_unmap_pages(vmap_t *, enum seg_rw);
extern int	vpm_sync_pages(struct vnode *, u_offset_t, size_t, uint_t);
extern int	vpm_data_copy(struct vnode *, u_offset_t, size_t,
		struct uio *, int, int *, int, enum seg_rw rw);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_VPM_H */
