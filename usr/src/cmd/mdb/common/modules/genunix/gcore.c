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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * This file implements the mdb ::gcore command.  The command relies on the
 * libproc Pgcore function to actually generate the core file but we provide
 * our own ops vector to populate data required by Pgcore.  The ops vector
 * function implementations simulate the functionality implemented by procfs.
 * The data provided by some of the ops vector functions is not complete
 * (missing data is documented in function headers) but there is enough
 * information to generate a core file that can be loaded into mdb.
 *
 * Currently only x86 is supported. ISA-dependent functions are implemented
 * in gcore_isadep.c.
 */

#ifndef _KMDB

/*
 * The kernel has its own definition of exit which has a different signature
 * than the user space definition.  This seems to be the standard way to deal
 * with this.
 */
#define	exit kern_exit

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_param.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gcore.h>

#include <sys/class.h>
#include <sys/cpuvar.h>
#include <sys/proc.h>
#include <sys/lgrp.h>
#include <sys/pool.h>
#include <sys/project.h>
#include <sys/regset.h>
#include <sys/schedctl.h>
#include <sys/session.h>
#include <sys/syscall.h>
#include <sys/task.h>
#include <sys/var.h>
#include <sys/privregs.h>
#include <sys/fault.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <vm/seg.h>
#include <vm/vpage.h>
#include <fs/proc/prdata.h>

#undef exit

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <libproc.h>
#include <errno.h>

#include "avl.h"

#ifdef _LP64
#define	LSPAN(type)	(P2ROUNDUP(sizeof (type), 16))
#else
#define	LSPAN(type)	(P2ROUNDUP(sizeof (type), 8))
#endif

#define	vpgtob(n)	((n) * sizeof (struct vpage))

/* Macros to invoke gcore seg operations */
#define	GSOP_INIT(_gs)		(_gs)->gs_ops->gsop_init((_gs))
#define	GSOP_FINI(_gs)		(_gs)->gs_ops->gsop_fini((_gs))
#define	GSOP_INCORE(_gs, _addr, _eaddr)	\
	(_gs)->gs_ops->gsop_incore((_gs), (_addr), (_eaddr))
#define	GSOP_GETPROT(_gs, _addr)	\
	(_gs)->gs_ops->gsop_getprot((_gs), (_addr))
#define	GSOP_GETOFFSET(_gs, _addr)	\
	(_gs)->gs_ops->gsop_getoffset((_gs), (_addr))
#define	GSOP_GETTYPE(_gs, _addr)	\
	(_gs)->gs_ops->gsop_gettype((_gs), (_addr))
#define	GSOP_NAME(_gs, _name, _size)	\
	(_gs)->gs_ops->gsop_name((_gs), (_name), (_size))
#define	GSOP_NORESERVE(_gs)		\
	(_gs)->gs_ops->gsop_noreserve((_gs))

#ifdef GCORE_DEBUG
#define	dprintf(...)	mdb_printf(__VA_ARGS__)
#else
#define	dprintf(...)
#endif

/* Callback function type for processing lwp entries */
typedef int (*lwp_callback_t)(mdb_proc_t *, lwpent_t *, void *);

/* Private data */
static uintptr_t gcore_segvn_ops;
static priv_impl_info_t prinfo;
static sclass_t *gcore_sclass;
static uintptr_t gcore_kas;
static boolean_t gcore_initialized = B_FALSE;

typedef int (*gsop_init_t)(gcore_seg_t *);
typedef void (*gsop_fini_t)(gcore_seg_t *);
typedef u_offset_t (*gsop_incore_t)(gcore_seg_t *, u_offset_t, u_offset_t);
typedef uint_t (*gsop_getprot_t)(gcore_seg_t *, u_offset_t);
typedef int (*gsop_getoffset_t)(gcore_seg_t *, u_offset_t);
typedef void (*gsop_name_t)(gcore_seg_t *, char *name, size_t size);
typedef int (*gsop_gettype_t)(gcore_seg_t *, u_offset_t);
typedef boolean_t (*gsop_noreserve_t)(gcore_seg_t *);

typedef struct gcore_segops {
	gsop_init_t		gsop_init;
	gsop_fini_t		gsop_fini;
	gsop_incore_t		gsop_incore;
	gsop_getprot_t		gsop_getprot;
	gsop_getoffset_t	gsop_getoffset;
	gsop_name_t		gsop_name;
	gsop_gettype_t		gsop_gettype;
	gsop_noreserve_t	gsop_noreserve;
} gcore_segops_t;

static void map_list_free(prmap_node_t *);
static uintptr_t gcore_prchoose(mdb_proc_t *);

/*
 * Segvn ops
 */
static int gsvn_init(gcore_seg_t *);
static void gsvn_fini(gcore_seg_t *);
static u_offset_t gsvn_incore(gcore_seg_t *, u_offset_t, u_offset_t);
static uint_t gsvn_getprot(gcore_seg_t *, u_offset_t);
static int gsvn_getoffset(gcore_seg_t *, u_offset_t);
static void gsvn_name(gcore_seg_t *, char *, size_t);
static int gsvn_gettype(gcore_seg_t *, u_offset_t);
static boolean_t gsvn_noreserve(gcore_seg_t *);

static gcore_segops_t gsvn_ops = {
	.gsop_init		= gsvn_init,
	.gsop_fini		= gsvn_fini,
	.gsop_incore		= gsvn_incore,
	.gsop_getprot		= gsvn_getprot,
	.gsop_getoffset		= gsvn_getoffset,
	.gsop_name		= gsvn_name,
	.gsop_gettype		= gsvn_gettype,
	.gsop_noreserve		= gsvn_noreserve
};

static int
gsvn_init(gcore_seg_t *gs)
{
	mdb_seg_t		*seg = gs->gs_seg;
	mdb_segvn_data_t	*svd = NULL;
	struct vpage		*vpage = NULL;
	size_t			nvpage = 0;

	if (seg->s_data != NULL) {
		svd = mdb_alloc(sizeof (*svd), UM_SLEEP);
		if (mdb_ctf_vread(svd, "segvn_data_t", "mdb_segvn_data_t",
		    seg->s_data, 0) == -1) {
			goto error;
		}

		if (svd->pageprot != 0) {
			nvpage = seg_pages(seg);
			dprintf("vpage count: %d\n", nvpage);

			vpage = mdb_alloc(vpgtob(nvpage), UM_SLEEP);
			if (mdb_vread(vpage, vpgtob(nvpage),
			    (uintptr_t)svd->vpage) != vpgtob(nvpage)) {
				mdb_warn("Failed to read vpages from %p\n",
				    svd->vpage);
				goto error;
			}

			svd->vpage = vpage;
		} else {
			svd->vpage = NULL;
		}
		gs->gs_data = svd;
	} else {
		gs->gs_data = NULL;
	}

	return (0);

error:
	mdb_free(vpage, vpgtob(nvpage));
	mdb_free(svd, sizeof (*svd));
	return (-1);
}

/*ARGSUSED*/
static int
gsvn_getoffset(gcore_seg_t *gs, u_offset_t addr)
{
	mdb_segvn_data_t	*svd = gs->gs_data;
	mdb_seg_t		*seg = gs->gs_seg;

	return (svd->offset + (uintptr_t)(addr - seg->s_base));
}

static void
gsvn_name(gcore_seg_t *gs, char *name, size_t size)
{
	mdb_segvn_data_t	*svd = gs->gs_data;

	name[0] = '\0';
	if (svd->vp != 0) {
		mdb_seg_t	*seg = gs->gs_seg;
		mdb_as_t	as;
		mdb_proc_t	p;
		mdb_vnode_t	vn;

		if (mdb_ctf_vread(&vn, "vnode_t", "mdb_vnode_t", svd->vp, 0)
		    == -1) {
			return;
		}

		if (mdb_ctf_vread(&as, "struct as", "mdb_as_t", seg->s_as, 0)
		    == -1) {
			return;
		}

		if (mdb_ctf_vread(&p, "proc_t", "mdb_proc_t", as.a_proc, 0)
		    == -1) {
			return;
		}

		if (vn.v_type == VREG && svd->vp == p.p_exec) {
			(void) strncpy(name, "a.out", size);
		}

		/*
		 * procfs has more logic here to construct a name using
		 * vfs/vnode identifiers but didn't seem worthwhile to add
		 * here.
		 */
	}
}

/*ARGSUSED*/
static int
gsvn_gettype(gcore_seg_t *gs, u_offset_t addr)
{
	return (0);
}

static void
gsvn_fini(gcore_seg_t *gs)
{
	mdb_segvn_data_t	*svd = gs->gs_data;

	if (svd != NULL) {
		if (svd->vpage != NULL) {
			size_t nvpage = seg_pages(gs->gs_seg);

			mdb_free(svd->vpage, vpgtob(nvpage));
		}
		mdb_free(svd, sizeof (*svd));
	}
}

static boolean_t
gsvn_noreserve(gcore_seg_t *gs)
{
	mdb_segvn_data_t	*svd = gs->gs_data;

	if (svd == NULL) {
		return (B_FALSE);
	}

	if (svd->flags & MAP_NORESERVE) {
		mdb_vnode_t vn;

		if (svd->vp == 0) {
			return (B_TRUE);
		}

		if (mdb_ctf_vread(&vn, "vnode_t", "mdb_vnode_t",
		    svd->vp, 0) == -1) {
			return (B_FALSE);
		}

		if (vn.v_type != VREG) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static uintptr_t
gcore_anon_get_ptr(uintptr_t ah_addr, ulong_t an_idx)
{
	mdb_anon_hdr_t	ah;
	uintptr_t	anon_addr;
	uintptr_t	anon_ptr;

	if (mdb_ctf_vread(&ah, "struct anon_hdr", "mdb_anon_hdr_t", ah_addr,
	    0) == -1) {
		return (0);
	}

	/*
	 * Single level case.
	 */
	if ((ah.size <= ANON_CHUNK_SIZE) || (ah.flags & ANON_ALLOC_FORCE)) {
		anon_addr = ah.array_chunk + (sizeof (anon_ptr) * an_idx);
		if (mdb_vread(&anon_ptr, sizeof (anon_ptr), anon_addr) !=
		    sizeof (anon_ptr)) {
			mdb_warn("Failed to read anon_ptr from %p (1 level)\n",
			    anon_addr);
			return (0);
		}

		return (anon_ptr & ANON_PTRMASK);
	}

	/*
	 * 2 level case.
	 */
	anon_addr = ah.array_chunk + (sizeof (anon_ptr) *
	    (an_idx >> ANON_CHUNK_SHIFT));

	if (mdb_vread(&anon_ptr, sizeof (anon_ptr), anon_addr) !=
	    sizeof (anon_ptr)) {
		mdb_warn("Failed to read anon_ptr from %p (2a level)\n",
		    anon_addr);
		return (0);
	}

	if (anon_ptr == 0) {
		return (0);
	}

	anon_addr = anon_ptr + (sizeof (anon_ptr) *
	    (an_idx & ANON_CHUNK_OFF));
	if (mdb_vread(&anon_ptr, sizeof (anon_ptr), anon_addr) !=
	    sizeof (anon_ptr)) {
		mdb_warn("Failed to read anon_ptr from %p (2b level)\n",
		    anon_addr);
		return (0);
	}

	return (anon_ptr & ANON_PTRMASK);
}

static void
gcore_anon_get(uintptr_t ahp, ulong_t an_index, uintptr_t *vp, u_offset_t *off)
{
	mdb_anon_t	anon;
	uintptr_t	ap;

	ap = gcore_anon_get_ptr(ahp, an_index);
	if (ap != 0) {
		if (mdb_ctf_vread(&anon, "struct anon", "mdb_anon_t", ap, 0) ==
		    -1) {
			return;
		}

		*vp = anon.an_vp;
		*off = anon.an_off;
	} else {
		*vp = 0;
		*off = 0;
	}
}

static u_offset_t
gsvn_incore(gcore_seg_t *gs, u_offset_t addr, u_offset_t eaddr)
{
	mdb_segvn_data_t	*svd = gs->gs_data;
	mdb_seg_t		*seg = gs->gs_seg;
	mdb_amp_t		amp;
	u_offset_t		offset;
	uintptr_t		vp;
	size_t			p, ep;

	if (svd->amp != 0 && mdb_ctf_vread(&amp, "amp_t", "mdb_amp_t", svd->amp,
	    0) == -1) {
		return (eaddr);
	}

	p = seg_page(seg, addr);
	ep = seg_page(seg, eaddr);
	for (; p < ep; p++, addr += PAGESIZE) {
		/* First check the anon map */
		if (svd->amp != 0) {
			gcore_anon_get(amp.ahp, svd->anon_index + p, &vp,
			    &offset);
			if (vp != 0 && mdb_page_lookup(vp, offset) != 0) {
				break;
			}
		}

		/* Now check the segment's vnode */
		vp = svd->vp;
		offset = svd->offset + (addr - gs->gs_seg->s_base);
		if (mdb_page_lookup(vp, offset) != 0) {
			break;
		}

		dprintf("amp: %p vp: %p addr: %p offset: %p not in core!\n",
		    svd->amp, svd->vp, addr, offset);
	}

	return (addr);
}

static uint_t
gsvn_getprot(gcore_seg_t *gs, u_offset_t addr)
{
	mdb_segvn_data_t	*svd = gs->gs_data;
	mdb_seg_t		*seg = gs->gs_seg;

	if (svd->pageprot == 0) {
		return (svd->prot);
	}

	dprintf("addr: %p pgno: %p\n", addr, seg_page(seg, addr));
	return (VPP_PROT(&svd->vpage[seg_page(seg, addr)]));
}

/*
 * Helper functions for constructing the process address space maps.
 */
/*ARGSUSED*/
static int
as_segat_cb(uintptr_t seg_addr, const void *aw_buff, void *arg)
{
	as_segat_cbarg_t *as_segat_arg = arg;
	mdb_seg_t	seg;

	if (mdb_ctf_vread(&seg, "struct seg", "mdb_seg_t", seg_addr, 0) == -1) {
		return (WALK_ERR);
	}

	if (as_segat_arg->addr < seg.s_base) {
		return (WALK_NEXT);
	}

	if (as_segat_arg->addr >= seg.s_base + seg.s_size) {
		return (WALK_NEXT);
	}

	as_segat_arg->res = seg_addr;
	return (WALK_DONE);
}

/*
 * Find a segment containing addr.
 */
static uintptr_t
gcore_as_segat(uintptr_t as_addr, uintptr_t addr)
{
	as_segat_cbarg_t as_segat_arg;
	uintptr_t	segtree_addr;

	as_segat_arg.addr = addr;
	as_segat_arg.res = 0;

	segtree_addr = as_addr + mdb_ctf_offsetof_by_name("struct as",
	    "a_segtree");
	(void) avl_walk_mdb(segtree_addr, as_segat_cb, &as_segat_arg);

	return (as_segat_arg.res);
}

static uintptr_t
gcore_break_seg(mdb_proc_t *p)
{
	uintptr_t addr = p->p_brkbase;

	if (p->p_brkbase != 0)
		addr += p->p_brksize - 1;

	return (gcore_as_segat(p->p_as, addr));
}

static u_offset_t
gcore_vnode_size(uintptr_t vnode_addr)
{
	mdb_vnode_t	vnode;
	mdb_vnodeops_t	vnodeops;
	char		vops_name[128];

	if (mdb_ctf_vread(&vnode, "vnode_t", "mdb_vnode_t", vnode_addr, 0) ==
	    -1) {
		return (-1);
	}

	if (mdb_ctf_vread(&vnodeops, "vnodeops_t", "mdb_vnodeops_t",
	    vnode.v_op, 0) == -1) {
		return (-1);
	}

	if (mdb_readstr(vops_name, sizeof (vops_name), vnodeops.vnop_name) ==
	    -1) {
		mdb_warn("Failed to read vnop_name from %p\n",
		    vnodeops.vnop_name);
		return (-1);
	}

	if (strcmp(vops_name, "zfs") == 0) {
		mdb_znode_t	znode;

		if (mdb_ctf_vread(&znode, "znode_t", "mdb_znode_t",
		    vnode.v_data, 0) == -1) {
			return (-1);
		}
		return (znode.z_size);
	}

	if (strcmp(vops_name, "tmpfs") == 0) {
		mdb_tmpnode_t	tnode;

		if (mdb_ctf_vread(&tnode, "struct tmpnode", "mdb_tmpnode_t",
		    vnode.v_data, 0) == -1)  {
			return (-1);
		}
		return (tnode.tn_attr.va_size);
	}

	/* Unknown file system type. */
	mdb_warn("Unknown fs type: %s\n", vops_name);
	return (-1);
}

static uint64_t
gcore_pr_getsegsize(mdb_seg_t *seg)
{
	uint64_t size = seg->s_size;

	if (seg->s_ops == gcore_segvn_ops) {
		mdb_segvn_data_t svd;

		if (mdb_ctf_vread(&svd, "segvn_data_t", "mdb_segvn_data_t",
		    seg->s_data, 0) == -1) {
			return (-1);
		}

		if (svd.vp != 0) {
			u_offset_t fsize;
			u_offset_t offset;

			fsize = gcore_vnode_size(svd.vp);
			if (fsize == -1) {
				return (-1);
			}
			offset = svd.offset;

			if (fsize < offset) {
				fsize = 0;
			} else {
				fsize -= offset;
			}

			fsize = roundup(fsize, PAGESIZE);
		}

		return (size);
	}

	return (size);
}

/*ARGSUSED*/
static int
gcore_getwatchprot_cb(uintptr_t node_addr, const void *aw_buff, void *arg)
{
	getwatchprot_cbarg_t	*cbarg = arg;

	if (mdb_ctf_vread(&cbarg->wp, "struct watched_page",
	    "mdb_watched_page_t", node_addr, 0) == -1) {
		return (WALK_ERR);
	}

	if (cbarg->wp.wp_vaddr == cbarg->wp_vaddr) {
		cbarg->found = B_TRUE;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

static void
gcore_getwatchprot(uintptr_t as_addr, u_offset_t addr, uint_t *prot)
{
	getwatchprot_cbarg_t	cbarg;
	uintptr_t		wp_addr;

	cbarg.wp_vaddr = (uintptr_t)addr & (uintptr_t)PAGEMASK;
	cbarg.found = B_FALSE;

	wp_addr = as_addr + mdb_ctf_offsetof_by_name("struct as", "a_wpage");
	(void) avl_walk_mdb(wp_addr, gcore_getwatchprot_cb, &cbarg);

	if (cbarg.found) {
		*prot = cbarg.wp.wp_oprot;
	}
}

static u_offset_t
gcore_pr_nextprot(gcore_seg_t *gs, u_offset_t *saddrp, u_offset_t eaddr,
    uint_t *protp)
{
	uint_t		prot, nprot;
	u_offset_t	addr = *saddrp;
	uintptr_t	as_addr = gs->gs_seg->s_as;
	int		noreserve = 0;

	noreserve = GSOP_NORESERVE(gs);
	dprintf("addr: %p noreserve: %d\n", addr, noreserve);

	if (noreserve) {
		addr = GSOP_INCORE(gs, addr, eaddr);
		if (addr == eaddr) {
			prot = 0;
			*saddrp = addr;
			goto out;
		}
	}

	prot = GSOP_GETPROT(gs, addr);
	gcore_getwatchprot(as_addr, addr, &prot);
	*saddrp = addr;

	for (addr += PAGESIZE; addr < eaddr; addr += PAGESIZE) {
		/* Discontinuity */
		if (noreserve && GSOP_INCORE(gs, addr, eaddr) != addr) {
			goto out;
		}

		nprot = GSOP_GETPROT(gs, addr);
		gcore_getwatchprot(as_addr, addr, &nprot);

		if (nprot != prot) {
			break;
		}
	}

out:
	*protp = prot;
	return (addr);
}

/*
 * Get the page protection for the given start address.
 *   - saddrp: in - start address
 *	       out - contains address of first in core page
 *   - naddrp: out - address of next in core page that has different protection
 *   - eaddr: in - end address
 */
static uint_t
gcore_pr_getprot(gcore_seg_t *gs, u_offset_t *saddrp, u_offset_t *naddrp,
    u_offset_t eaddr)
{
	u_offset_t	naddr;
	uint_t		prot;

	dprintf("seg: %p saddr: %p eaddr: %p\n",
	    gs->gs_seg, *saddrp, eaddr);

	naddr = gcore_pr_nextprot(gs, saddrp, eaddr, &prot);

	dprintf("seg: %p saddr: %p naddr: %p eaddr: %p\n",
	    gs->gs_seg, *saddrp, naddr, eaddr);

	*naddrp = naddr;
	return (prot);
}

static gcore_seg_t *
gcore_seg_create(mdb_seg_t *seg)
{
	gcore_seg_t	*gs;

	gs = mdb_alloc(sizeof (*gs), UM_SLEEP);
	gs->gs_seg = seg;
	if (seg->s_ops == gcore_segvn_ops) {
		gs->gs_ops = &gsvn_ops;
	} else {
		mdb_warn("Unhandled segment type, ops: %p\n", seg->s_ops);
		goto error;
	}

	if (GSOP_INIT(gs) != 0) {
		goto error;
	}

	return (gs);

error:
	mdb_free(gs, sizeof (*gs));
	return (NULL);
}

static void
gcore_seg_destroy(gcore_seg_t *gs)
{
	GSOP_FINI(gs);
	mdb_free(gs, sizeof (*gs));
}

/*ARGSUSED*/
static int
read_maps_cb(uintptr_t seg_addr, const void *aw_buff, void *arg)
{
	read_maps_cbarg_t	*cbarg = arg;
	mdb_segvn_data_t	svd;
	mdb_seg_t		s;
	mdb_seg_t		*seg;
	uint_t			prot;
	gcore_seg_t		*gs;
	uintptr_t		eaddr;
	u_offset_t		saddr, baddr;
	prmap_node_t		*mnode;
	prmap_t			*mp;

	if (mdb_ctf_vread(&s, "struct seg", "mdb_seg_t", seg_addr, 0) == -1) {
		return (WALK_ERR);
	}
	seg = &s;
	eaddr = seg->s_base + gcore_pr_getsegsize(seg);

	if ((gs = gcore_seg_create(seg)) == NULL) {
		mdb_warn("gcore_seg_create failed!\n");
		return (WALK_ERR);
	}

	/*
	 * Iterate from the base of the segment to its end, allocating a new
	 * prmap_node at each address boundary (baddr) between ranges that
	 * have different virtual memory protections.
	 */
	for (saddr = seg->s_base; saddr < eaddr; saddr = baddr) {
		prot = gcore_pr_getprot(gs, &saddr, &baddr, eaddr);
		if (saddr == eaddr) {
			break;
		}

		mnode = mdb_alloc(sizeof (*mnode), UM_SLEEP);
		mnode->next = NULL;
		mp = &mnode->m;

		if (cbarg->map_head == NULL) {
			cbarg->map_head = cbarg->map_tail = mnode;
		} else {
			cbarg->map_tail->next = mnode;
			cbarg->map_tail = mnode;
		}
		cbarg->map_len++;

		mp->pr_vaddr = (uintptr_t)saddr;
		mp->pr_size = baddr - saddr;
		mp->pr_offset = GSOP_GETOFFSET(gs, saddr);
		mp->pr_mflags = 0;
		if (prot & PROT_READ)
			mp->pr_mflags |= MA_READ;
		if (prot & PROT_WRITE)
			mp->pr_mflags |= MA_WRITE;
		if (prot & PROT_EXEC)
			mp->pr_mflags |= MA_EXEC;
		if (GSOP_GETTYPE(gs, saddr) & MAP_SHARED)
			mp->pr_mflags |= MA_SHARED;
		if (GSOP_GETTYPE(gs, saddr) & MAP_NORESERVE)
			mp->pr_mflags |= MA_NORESERVE;
		if (seg->s_ops == gcore_segvn_ops) {
			if (mdb_ctf_vread(&svd, "segvn_data_t",
			    "mdb_segvn_data_t", seg->s_data, 0) == 0 &&
			    svd.vp == NULL) {
				mp->pr_mflags |= MA_ANON;
			}
		}
		if (seg_addr == cbarg->brkseg)
			mp->pr_mflags |= MA_BREAK;
		else if (seg_addr == cbarg->stkseg)
			mp->pr_mflags |= MA_STACK;

		mp->pr_pagesize = PAGESIZE;

		/*
		 * Manufacture a filename for the "object" dir.
		 */
		GSOP_NAME(gs, mp->pr_mapname, sizeof (mp->pr_mapname));
	}

	gcore_seg_destroy(gs);

	return (0);
}

/*
 * Helper functions for retrieving process and lwp state.
 */
static int
pcommon_init(mdb_proc_t *p, pcommon_t *pc)
{
	mdb_pid_t	pid;
	mdb_sess_t	sess;
	mdb_task_t	task;
	mdb_kproject_t	proj;
	mdb_zone_t	zone;

	pc->pc_nlwp = p->p_lwpcnt;
	pc->pc_nzomb = p->p_zombcnt;

	if (mdb_ctf_vread(&pid, "struct pid", "mdb_pid_t", p->p_pidp, 0) ==
	    -1) {
		return (-1);
	}
	pc->pc_pid = pid.pid_id;
	pc->pc_ppid = p->p_ppid;

	if (mdb_ctf_vread(&pid, "struct pid", "mdb_pid_t", p->p_pgidp, 0) ==
	    -1) {
		return (-1);
	}
	pc->pc_pgid = pid.pid_id;

	if (mdb_ctf_vread(&sess, "sess_t", "mdb_sess_t", p->p_sessp, 0) ==
	    -1) {
		return (-1);
	}
	if (mdb_ctf_vread(&pid, "struct pid", "mdb_pid_t", sess.s_sidp, 0) ==
	    -1) {
		return (-1);
	}
	pc->pc_sid = pid.pid_id;

	if (mdb_ctf_vread(&task, "task_t", "mdb_task_t", p->p_task, 0) == -1) {
		return (-1);
	}
	pc->pc_taskid = task.tk_tkid;

	if (mdb_ctf_vread(&proj, "kproject_t", "mdb_kproject_t", task.tk_proj,
	    0) == -1) {
		return (-1);
	}
	pc->pc_projid = proj.kpj_id;

	if (mdb_ctf_vread(&zone, "zone_t", "mdb_zone_t", p->p_zone, 0) == -1) {
		return (-1);
	}
	pc->pc_zoneid = zone.zone_id;

	switch (p->p_model) {
	case DATAMODEL_ILP32:
		pc->pc_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		pc->pc_dmodel = PR_MODEL_LP64;
		break;
	}

	return (0);
}

static uintptr_t
gcore_prchoose(mdb_proc_t *p)
{
	mdb_kthread_t	kthr;
	mdb_kthread_t	*t = &kthr;
	ushort_t	t_istop_whystop = 0;
	ushort_t	t_istop_whatstop = 0;
	uintptr_t	t_addr = NULL;
	uintptr_t	t_onproc = NULL; // running on processor
	uintptr_t	t_run = NULL;	 // runnable, on disp queue
	uintptr_t	t_sleep = NULL;	 // sleeping
	uintptr_t	t_susp = NULL;	 // suspended stop
	uintptr_t	t_jstop = NULL;	 // jobcontrol stop, w/o directed stop
	uintptr_t	t_jdstop = NULL; // jobcontrol stop with directed stop
	uintptr_t	t_req = NULL;	 // requested stop
	uintptr_t	t_istop = NULL;	 // event-of-interest stop
	uintptr_t	t_dtrace = NULL; // DTrace stop

	/*
	 * If the agent lwp exists, it takes precedence over all others.
	 */
	if ((t_addr = p->p_agenttp) != NULL) {
		return (t_addr);
	}

	if ((t_addr = p->p_tlist) == NULL) /* start at the head of the list */
		return (t_addr);
	do {		/* for each lwp in the process */
		if (mdb_ctf_vread(&kthr, "kthread_t", "mdb_kthread_t",
		    t_addr, 0) == -1) {
			return (0);
		}

		if (VSTOPPED(t)) {	/* virtually stopped */
			if (t_req == NULL)
				t_req = t_addr;
			continue;
		}

		switch (t->t_state) {
		default:
			return (0);
		case TS_SLEEP:
			if (t_sleep == NULL)
				t_sleep = t_addr;
			break;
		case TS_RUN:
		case TS_WAIT:
			if (t_run == NULL)
				t_run = t_addr;
			break;
		case TS_ONPROC:
			if (t_onproc == NULL)
				t_onproc = t_addr;
			break;
			/*
			 * Threads in the zombie state have the lowest
			 * priority when selecting a representative lwp.
			 */
		case TS_ZOMB:
			break;
		case TS_STOPPED:
			switch (t->t_whystop) {
			case PR_SUSPENDED:
				if (t_susp == NULL)
					t_susp = t_addr;
				break;
			case PR_JOBCONTROL:
				if (t->t_proc_flag & TP_PRSTOP) {
					if (t_jdstop == NULL)
						t_jdstop = t_addr;
				} else {
					if (t_jstop == NULL)
						t_jstop = t_addr;
				}
				break;
			case PR_REQUESTED:
				if (t->t_dtrace_stop && t_dtrace == NULL)
					t_dtrace = t_addr;
				else if (t_req == NULL)
					t_req = t_addr;
				break;
			case PR_SYSENTRY:
			case PR_SYSEXIT:
			case PR_SIGNALLED:
			case PR_FAULTED:
				/*
				 * Make an lwp calling exit() be the
				 * last lwp seen in the process.
				 */
				if (t_istop == NULL ||
				    (t_istop_whystop == PR_SYSENTRY &&
				    t_istop_whatstop == SYS_exit)) {
					t_istop = t_addr;
					t_istop_whystop = t->t_whystop;
					t_istop_whatstop = t->t_whatstop;
				}
				break;
			case PR_CHECKPOINT:	/* can't happen? */
				break;
			default:
				return (0);
			}
			break;
		}
	} while ((t_addr = t->t_forw) != p->p_tlist);

	if (t_onproc)
		t_addr = t_onproc;
	else if (t_run)
		t_addr = t_run;
	else if (t_sleep)
		t_addr = t_sleep;
	else if (t_jstop)
		t_addr = t_jstop;
	else if (t_jdstop)
		t_addr = t_jdstop;
	else if (t_istop)
		t_addr = t_istop;
	else if (t_dtrace)
		t_addr = t_dtrace;
	else if (t_req)
		t_addr = t_req;
	else if (t_susp)
		t_addr = t_susp;
	else			/* TS_ZOMB */
		t_addr = p->p_tlist;

	return (t_addr);
}

/*
 * Fields not populated:
 *   - pr_stype
 *   - pr_oldpri
 *   - pr_nice
 *   - pr_time
 *   - pr_pctcpu
 *   - pr_cpu
 */
static int
gcore_prgetlwpsinfo(uintptr_t t_addr, mdb_kthread_t *t, lwpsinfo_t *psp)
{
	char		c, state;
	mdb_cpu_t	cpu;
	mdb_lpl_t	lgrp;
	uintptr_t	str_addr;

	bzero(psp, sizeof (*psp));

	psp->pr_flag = 0;	/* lwpsinfo_t.pr_flag is deprecated */
	psp->pr_lwpid = t->t_tid;
	psp->pr_addr = t_addr;
	psp->pr_wchan = (uintptr_t)t->t_wchan;

	/* map the thread state enum into a process state enum */
	state = VSTOPPED(t) ? TS_STOPPED : t->t_state;
	switch (state) {
	case TS_SLEEP:		state = SSLEEP;		c = 'S';	break;
	case TS_RUN:		state = SRUN;		c = 'R';	break;
	case TS_ONPROC:		state = SONPROC;	c = 'O';	break;
	case TS_ZOMB:		state = SZOMB;		c = 'Z';	break;
	case TS_STOPPED:	state = SSTOP;		c = 'T';	break;
	case TS_WAIT:		state = SWAIT;		c = 'W';	break;
	default:		state = 0;		c = '?';	break;
	}
	psp->pr_state = state;
	psp->pr_sname = c;
	psp->pr_syscall = t->t_sysnum;
	psp->pr_pri = t->t_pri;
	psp->pr_start.tv_sec = t->t_start;
	psp->pr_start.tv_nsec = 0L;

	str_addr = (uintptr_t)gcore_sclass[t->t_cid].cl_name;
	if (mdb_readstr(psp->pr_clname, sizeof (psp->pr_clname) - 1, str_addr)
	    == -1) {
		mdb_warn("Failed to read string from %p\n", str_addr);
		return (-1);
	}
	bzero(psp->pr_name, sizeof (psp->pr_name));

	if (mdb_ctf_vread(&cpu, "struct cpu", "mdb_cpu_t", t->t_cpu, 0) == -1) {
		return (-1);
	}
	psp->pr_onpro = cpu.cpu_id;
	psp->pr_bindpro = t->t_bind_cpu;
	psp->pr_bindpset = t->t_bind_pset;

	if (mdb_ctf_vread(&lgrp, "lpl_t", "mdb_lpl_t", t->t_lpl, 0) == -1) {
		return (-1);
	}
	psp->pr_lgrp = lgrp.lpl_lgrpid;

	return (0);
}

/*ARGSUSED*/
static int
gcore_lpsinfo_cb(mdb_proc_t *p, lwpent_t *lwent, void *data)
{
	lwpsinfo_t	*lpsinfo = data;
	uintptr_t	t_addr = (uintptr_t)lwent->le_thread;
	mdb_kthread_t	kthrd;

	if (t_addr != 0) {
		if (mdb_ctf_vread(&kthrd, "kthread_t", "mdb_kthread_t", t_addr,
		    0) == -1) {
			return (-1);
		}
		return (gcore_prgetlwpsinfo(t_addr, &kthrd, lpsinfo));
	}

	bzero(lpsinfo, sizeof (*lpsinfo));
	lpsinfo->pr_lwpid = lwent->le_lwpid;
	lpsinfo->pr_state = SZOMB;
	lpsinfo->pr_sname = 'Z';
	lpsinfo->pr_start.tv_sec = lwent->le_start;
	lpsinfo->pr_bindpro = PBIND_NONE;
	lpsinfo->pr_bindpset = PS_NONE;
	return (0);
}

static void
gcore_schedctl_finish_sigblock(mdb_kthread_t *t)
{
	mdb_sc_shared_t td;
	mdb_sc_shared_t *tdp;

	if (t->t_schedctl == NULL) {
		return;
	}

	if (mdb_ctf_vread(&td, "sc_shared_t", "mdb_sc_shared_t", t->t_schedctl,
	    0) == -1) {
		return;
	}
	tdp = &td;

	if (tdp->sc_sigblock) {
		t->t_hold.__sigbits[0] = FILLSET0 & ~CANTMASK0;
		t->t_hold.__sigbits[1] = FILLSET1 & ~CANTMASK1;
		t->t_hold.__sigbits[2] = FILLSET2 & ~CANTMASK2;
		tdp->sc_sigblock = 0;
	}
}

static void
gcore_prgetaction(mdb_proc_t *p, user_t *up, uint_t sig, struct sigaction *sp)
{
	int nsig = NSIG;

	bzero(sp, sizeof (*sp));

	if (sig != 0 && (unsigned)sig < nsig) {
		sp->sa_handler = up->u_signal[sig-1];
		prassignset(&sp->sa_mask, &up->u_sigmask[sig-1]);
		if (sigismember(&up->u_sigonstack, sig))
			sp->sa_flags |= SA_ONSTACK;
		if (sigismember(&up->u_sigresethand, sig))
			sp->sa_flags |= SA_RESETHAND;
		if (sigismember(&up->u_sigrestart, sig))
			sp->sa_flags |= SA_RESTART;
		if (sigismember(&p->p_siginfo, sig))
			sp->sa_flags |= SA_SIGINFO;
		if (sigismember(&up->u_signodefer, sig))
			sp->sa_flags |= SA_NODEFER;
		if (sig == SIGCLD) {
			if (p->p_flag & SNOWAIT)
				sp->sa_flags |= SA_NOCLDWAIT;
			if ((p->p_flag & SJCTL) == 0)
				sp->sa_flags |= SA_NOCLDSTOP;
		}
	}
}

static void
gcore_prgetprregs(mdb_klwp_t *lwp, prgregset_t prp)
{
	gcore_getgregs(lwp, prp);
}

/*
 * Field not populated:
 *   - pr_tstamp
 *   - pr_utime
 *   - pr_stime
 *   - pr_syscall
 *   - pr_syarg
 *   - pr_nsysarg
 *   - pr_fpreg
 */
/*ARGSUSED*/
static int
gcore_prgetlwpstatus(mdb_proc_t *p, uintptr_t t_addr, mdb_kthread_t *t,
    lwpstatus_t *sp, zone_t *zp)
{
	uintptr_t	lwp_addr = ttolwp(t);
	mdb_klwp_t	lw;
	mdb_klwp_t	*lwp;
	ulong_t		instr;
	int		flags;
	uintptr_t	str_addr;
	struct pid	pid;

	if (mdb_ctf_vread(&lw, "klwp_t", "mdb_klwp_t", lwp_addr, 0) == -1) {
		return (-1);
	}
	lwp = &lw;

	bzero(sp, sizeof (*sp));
	flags = 0L;
	if (t->t_state == TS_STOPPED) {
		flags |= PR_STOPPED;
		if ((t->t_schedflag & TS_PSTART) == 0)
			flags |= PR_ISTOP;
	} else if (VSTOPPED(t)) {
		flags |= PR_STOPPED|PR_ISTOP;
	}
	if (!(flags & PR_ISTOP) && (t->t_proc_flag & TP_PRSTOP))
		flags |= PR_DSTOP;
	if (lwp->lwp_asleep)
		flags |= PR_ASLEEP;
	if (t_addr == p->p_agenttp)
		flags |= PR_AGENT;
	if (!(t->t_proc_flag & TP_TWAIT))
		flags |= PR_DETACH;
	if (t->t_proc_flag & TP_DAEMON)
		flags |= PR_DAEMON;
	if (p->p_proc_flag & P_PR_FORK)
		flags |= PR_FORK;
	if (p->p_proc_flag & P_PR_RUNLCL)
		flags |= PR_RLC;
	if (p->p_proc_flag & P_PR_KILLCL)
		flags |= PR_KLC;
	if (p->p_proc_flag & P_PR_ASYNC)
		flags |= PR_ASYNC;
	if (p->p_proc_flag & P_PR_BPTADJ)
		flags |= PR_BPTADJ;
	if (p->p_proc_flag & P_PR_PTRACE)
		flags |= PR_PTRACE;
	if (p->p_flag & SMSACCT)
		flags |= PR_MSACCT;
	if (p->p_flag & SMSFORK)
		flags |= PR_MSFORK;
	if (p->p_flag & SVFWAIT)
		flags |= PR_VFORKP;

	if (mdb_vread(&pid, sizeof (struct pid), p->p_pgidp) != sizeof (pid)) {
		mdb_warn("Failed to read pid from %p\n", p->p_pgidp);
		return (-1);
	}
	if (pid.pid_pgorphaned)
		flags |= PR_ORPHAN;
	if (p->p_pidflag & CLDNOSIGCHLD)
		flags |= PR_NOSIGCHLD;
	if (p->p_pidflag & CLDWAITPID)
		flags |= PR_WAITPID;
	sp->pr_flags = flags;
	if (VSTOPPED(t)) {
		sp->pr_why   = PR_REQUESTED;
		sp->pr_what  = 0;
	} else {
		sp->pr_why   = t->t_whystop;
		sp->pr_what  = t->t_whatstop;
	}
	sp->pr_lwpid = t->t_tid;
	sp->pr_cursig  = lwp->lwp_cursig;
	prassignset(&sp->pr_lwppend, &t->t_sig);
	gcore_schedctl_finish_sigblock(t);
	prassignset(&sp->pr_lwphold, &t->t_hold);
	if (t->t_whystop == PR_FAULTED) {
		bcopy(&lwp->lwp_siginfo,
		    &sp->pr_info, sizeof (k_siginfo_t));
	} else if (lwp->lwp_curinfo) {
		mdb_sigqueue_t	sigq;

		if (mdb_ctf_vread(&sigq, "sigqueue_t", "mdb_sigqueue_t",
		    lwp->lwp_curinfo, 0) == -1) {
			return (-1);
		}
		bcopy(&sigq.sq_info, &sp->pr_info, sizeof (k_siginfo_t));
	}

	sp->pr_altstack = lwp->lwp_sigaltstack;
	gcore_prgetaction(p, PTOU(p), lwp->lwp_cursig, &sp->pr_action);
	sp->pr_oldcontext = lwp->lwp_oldcontext;
	sp->pr_ustack = lwp->lwp_ustack;

	str_addr = (uintptr_t)gcore_sclass[t->t_cid].cl_name;
	if (mdb_readstr(sp->pr_clname, sizeof (sp->pr_clname) - 1, str_addr) ==
	    -1) {
		mdb_warn("Failed to read string from %p\n", str_addr);
		return (-1);
	}

	/*
	 * Fetch the current instruction, if not a system process.
	 * We don't attempt this unless the lwp is stopped.
	 */
	if ((p->p_flag & SSYS) || p->p_as == gcore_kas)
		sp->pr_flags |= (PR_ISSYS|PR_PCINVAL);
	else if (!(flags & PR_STOPPED))
		sp->pr_flags |= PR_PCINVAL;
	else if (!gcore_prfetchinstr(lwp, &instr))
		sp->pr_flags |= PR_PCINVAL;
	else
		sp->pr_instr = instr;

	if (gcore_prisstep(lwp))
		sp->pr_flags |= PR_STEP;
	gcore_prgetprregs(lwp, sp->pr_reg);
	if ((t->t_state == TS_STOPPED && t->t_whystop == PR_SYSEXIT) ||
	    (flags & PR_VFORKP)) {
		user_t *up;
		auxv_t *auxp;
		int i;

		sp->pr_errno = gcore_prgetrvals(lwp, &sp->pr_rval1,
		    &sp->pr_rval2);
		if (sp->pr_errno == 0)
			sp->pr_errpriv = PRIV_NONE;
		else
			sp->pr_errpriv = lwp->lwp_badpriv;

		if (t->t_sysnum == SYS_execve) {
			up = PTOU(p);
			sp->pr_sysarg[0] = 0;
			sp->pr_sysarg[1] = (uintptr_t)up->u_argv;
			sp->pr_sysarg[2] = (uintptr_t)up->u_envp;
			for (i = 0, auxp = up->u_auxv;
			    i < sizeof (up->u_auxv) / sizeof (up->u_auxv[0]);
			    i++, auxp++) {
				if (auxp->a_type == AT_SUN_EXECNAME) {
					sp->pr_sysarg[0] =
					    (uintptr_t)auxp->a_un.a_ptr;
					break;
				}
			}
		}
	}
	return (0);
}

static int
gcore_lstatus_cb(mdb_proc_t *p, lwpent_t *lwent, void *data)
{
	lwpstatus_t	*lstatus = data;
	uintptr_t	t_addr = (uintptr_t)lwent->le_thread;
	mdb_kthread_t	kthrd;

	if (t_addr == NULL) {
		return (1);
	}

	if (mdb_ctf_vread(&kthrd, "kthread_t", "mdb_kthread_t", t_addr, 0)
	    == -1) {
		return (-1);
	}

	return (gcore_prgetlwpstatus(p, t_addr, &kthrd, lstatus, NULL));
}

static prheader_t *
gcore_walk_lwps(mdb_proc_t *p, lwp_callback_t callback, int nlwp,
    size_t ent_size)
{
	void		*ent;
	prheader_t	*php;
	lwpdir_t	*ldp;
	lwpdir_t	ld;
	lwpent_t	lwent;
	int		status;
	int		i;

	php = calloc(1, sizeof (prheader_t) + nlwp * ent_size);
	if (php == NULL) {
		return (NULL);
	}
	php->pr_nent = nlwp;
	php->pr_entsize = ent_size;

	ent = php + 1;
	for (ldp = (lwpdir_t *)p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++,
	    ldp++) {
		if (mdb_vread(&ld, sizeof (ld), (uintptr_t)ldp) !=
		    sizeof (ld)) {
			mdb_warn("Failed to read lwpdir_t from %p\n", ldp);
			goto error;
		}

		if (ld.ld_entry == NULL) {
			continue;
		}

		if (mdb_vread(&lwent, sizeof (lwent), (uintptr_t)ld.ld_entry) !=
		    sizeof (lwent)) {
			mdb_warn("Failed to read lwpent_t from %p\n",
			    ld.ld_entry);
			goto error;
		}

		status = callback(p, &lwent, ent);
		if (status == -1) {
			dprintf("lwp callback %p returned -1\n", callback);
			goto error;
		}
		if (status == 1) {
			dprintf("lwp callback %p returned 1\n", callback);
			continue;
		}

		ent = (caddr_t)ent + ent_size;
	}

	return (php);

error:
	free(php);
	return (NULL);
}

/*
 * Misc helper functions.
 */
/*
 * convert code/data pair into old style wait status
 */
static int
gcore_wstat(int code, int data)
{
	int stat = (data & 0377);

	switch (code) {
	case CLD_EXITED:
		stat <<= 8;
		break;
	case CLD_DUMPED:
		stat |= WCOREFLG;
		break;
	case CLD_KILLED:
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	default:
		mdb_warn("wstat: bad code %d\n", code);
	}
	return (stat);
}

#if defined(__i386) || defined(__amd64)
static void
gcore_usd_to_ssd(user_desc_t *usd, struct ssd *ssd, selector_t sel)
{
	ssd->bo = USEGD_GETBASE(usd);
	ssd->ls = USEGD_GETLIMIT(usd);
	ssd->sel = sel;

	/*
	 * set type, dpl and present bits.
	 */
	ssd->acc1 = usd->usd_type;
	ssd->acc1 |= usd->usd_dpl << 5;
	ssd->acc1 |= usd->usd_p << (5 + 2);

	/*
	 * set avl, DB and granularity bits.
	 */
	ssd->acc2 = usd->usd_avl;

#if defined(__amd64)
	ssd->acc2 |= usd->usd_long << 1;
#else
	ssd->acc2 |= usd->usd_reserved << 1;
#endif

	ssd->acc2 |= usd->usd_def32 << (1 + 1);
	ssd->acc2 |= usd->usd_gran << (1 + 1 + 1);
}
#endif

static priv_set_t *
gcore_priv_getset(cred_t *cr, int set)
{
	if ((CR_FLAGS(cr) & PRIV_AWARE) == 0) {
		switch (set) {
		case PRIV_EFFECTIVE:
			return (&CR_OEPRIV(cr));
		case PRIV_PERMITTED:
			return (&CR_OPPRIV(cr));
		}
	}
	return (&CR_PRIVS(cr)->crprivs[set]);
}

static void
gcore_priv_getinfo(const cred_t *cr, void *buf)
{
	struct priv_info_uint *ii;

	ii = buf;
	ii->val = CR_FLAGS(cr);
	ii->info.priv_info_size = (uint32_t)sizeof (*ii);
	ii->info.priv_info_type = PRIV_INFO_FLAGS;
}

static void
map_list_free(prmap_node_t *n)
{
	prmap_node_t	*next;

	while (n != NULL) {
		next = n->next;
		mdb_free(n, sizeof (*n));
		n = next;
	}
}

/*
 * Ops vector functions for ::gcore.
 */
/*ARGSUSED*/
static ssize_t
Pread_gcore(struct ps_prochandle *P, void *buf, size_t n, uintptr_t addr,
    void *data)
{
	mdb_proc_t	*p = data;
	ssize_t		ret;

	ret = mdb_aread(buf, n, addr, (void *)p->p_as);
	if (ret != n) {
		dprintf("%s: addr: %p len: %llx\n", __func__, addr, n);
		(void) memset(buf, 0, n);
		return (n);
	}

	return (ret);
}

/*ARGSUSED*/
static ssize_t
Pwrite_gcore(struct ps_prochandle *P, const void *buf, size_t n, uintptr_t addr,
    void *data)
{
	dprintf("%s: addr: %p len: %llx\n", __func__, addr, n);

	return (-1);
}

/*ARGSUSED*/
static int
Pread_maps_gcore(struct ps_prochandle *P, prmap_t **Pmapp, ssize_t *nmapp,
    void *data)
{
	mdb_proc_t	*p = data;
	read_maps_cbarg_t cbarg;
	prmap_node_t	*n;
	prmap_t		*pmap;
	uintptr_t	segtree_addr;
	int		error;
	int		i;

	cbarg.p = p;
	cbarg.brkseg = gcore_break_seg(p);
	cbarg.stkseg = gcore_as_segat(p->p_as, gcore_prgetstackbase(p));

	(void) memset(&cbarg, 0, sizeof (cbarg));
	segtree_addr = p->p_as + mdb_ctf_offsetof_by_name("struct as",
	    "a_segtree");
	error = avl_walk_mdb(segtree_addr, read_maps_cb, &cbarg);
	if (error != WALK_DONE) {
		return (-1);
	}

	/* Conver the linked list into an array */
	pmap = malloc(cbarg.map_len * sizeof (*pmap));
	if (pmap == NULL) {
		map_list_free(cbarg.map_head);
		return (-1);
	}

	for (i = 0, n = cbarg.map_head; i < cbarg.map_len; i++, n = n->next) {
		(void) memcpy(&pmap[i], &n->m, sizeof (prmap_t));
	}
	map_list_free(cbarg.map_head);

	for (i = 0; i < cbarg.map_len; i++) {
		dprintf("pr_vaddr: %p pr_size: %llx, pr_name: %s "
		    "pr_offset: %p pr_mflags: 0x%x\n",
		    pmap[i].pr_vaddr, pmap[i].pr_size,
		    pmap[i].pr_mapname, pmap[i].pr_offset,
		    pmap[i].pr_mflags);
	}

	*Pmapp = pmap;
	*nmapp = cbarg.map_len;

	return (0);
}

/*ARGSUSED*/
static void
Pread_aux_gcore(struct ps_prochandle *P, auxv_t **auxvp, int *nauxp, void *data)
{
	mdb_proc_t	*p = data;
	auxv_t		*auxv;
	int		naux;

	naux = __KERN_NAUXV_IMPL;
	auxv = calloc(naux + 1, sizeof (*auxv));
	if (auxv == NULL) {
		*auxvp = NULL;
		*nauxp = 0;
		return;
	}

	(void) memcpy(auxv, p->p_user.u_auxv, naux * sizeof (*auxv));

	*auxvp = auxv;
	*nauxp = naux;
}

/*ARGSUSED*/
static int
Pcred_gcore(struct ps_prochandle *P, prcred_t *prcp, int ngroups, void *data)
{
	mdb_proc_t	*p = data;
	cred_t		cr;
	credgrp_t	crgrp;
	int		i;

	if (mdb_vread(&cr, sizeof (cr), p->p_cred) != sizeof (cr)) {
		mdb_warn("Failed to read cred_t from %p\n", p->p_cred);
		return (-1);
	}

	prcp->pr_euid = cr.cr_uid;
	prcp->pr_ruid = cr.cr_ruid;
	prcp->pr_suid = cr.cr_suid;
	prcp->pr_egid = cr.cr_gid;
	prcp->pr_rgid = cr.cr_rgid;
	prcp->pr_sgid = cr.cr_sgid;

	if (cr.cr_grps == 0) {
		prcp->pr_ngroups = 0;
		return (0);
	}

	if (mdb_vread(&crgrp, sizeof (crgrp), (uintptr_t)cr.cr_grps) !=
	    sizeof (crgrp)) {
		mdb_warn("Failed to read credgrp_t from %p\n", cr.cr_grps);
		return (-1);
	}

	prcp->pr_ngroups = MIN(ngroups, crgrp.crg_ngroups);
	for (i = 0; i < prcp->pr_ngroups; i++) {
		prcp->pr_groups[i] = crgrp.crg_groups[i];
	}

	return (0);
}

/*ARGSUSED*/
static int
Ppriv_gcore(struct ps_prochandle *P, prpriv_t **pprv, void *data)
{
	mdb_proc_t	*p = data;
	prpriv_t	*pp;
	cred_t		cr;
	priv_set_t	*psa;
	size_t		pprv_size;
	int		i;

	pprv_size = sizeof (prpriv_t) + PRIV_SETBYTES - sizeof (priv_chunk_t) +
	    prinfo.priv_infosize;

	pp = malloc(pprv_size);
	if (pp == NULL) {
		return (-1);
	}

	if (mdb_vread(&cr, sizeof (cr), p->p_cred) != sizeof (cr)) {
		mdb_warn("Failed to read cred_t from %p\n", p->p_cred);
		free(pp);
		return (-1);
	}

	pp->pr_nsets = PRIV_NSET;
	pp->pr_setsize = PRIV_SETSIZE;
	pp->pr_infosize = prinfo.priv_infosize;

	psa = (priv_set_t *)pp->pr_sets;
	for (i = 0; i < PRIV_NSET; i++) {
		psa[i] = *gcore_priv_getset(&cr, i);
	}

	gcore_priv_getinfo(&cr, (char *)pp + PRIV_PRPRIV_INFO_OFFSET(pp));

	*pprv = pp;
	return (0);
}

/*
 * Fields not filled populated:
 *   - pr_utime
 *   - pr_stkbase
 *   - pr_cutime
 *   - pr_cstime
 *   - pr_agentid
 */
/*ARGSUSED*/
static void
Pstatus_gcore(struct ps_prochandle *P, pstatus_t *sp, void *data)
{
	mdb_proc_t	*p = data;
	uintptr_t	t_addr;
	mdb_kthread_t	kthr;
	mdb_kthread_t	*t;
	pcommon_t	pc;

	t_addr = gcore_prchoose(p);
	if (t_addr != NULL) {
		if (mdb_ctf_vread(&kthr, "kthread_t", "mdb_kthread_t", t_addr,
		    0) == -1) {
			return;
		}
		t = &kthr;
	}

	/* just bzero the process part, prgetlwpstatus() does the rest */
	bzero(sp, sizeof (pstatus_t) - sizeof (lwpstatus_t));

	if (pcommon_init(p, &pc) == -1) {
		return;
	}
	sp->pr_nlwp = pc.pc_nlwp;
	sp->pr_nzomb = pc.pc_nzomb;
	sp->pr_pid = pc.pc_pid;
	sp->pr_ppid = pc.pc_ppid;
	sp->pr_pgid = pc.pc_pgid;
	sp->pr_sid = pc.pc_sid;
	sp->pr_taskid = pc.pc_taskid;
	sp->pr_projid = pc.pc_projid;
	sp->pr_zoneid = pc.pc_zoneid;
	sp->pr_dmodel = pc.pc_dmodel;

	prassignset(&sp->pr_sigpend, &p->p_sig);
	sp->pr_brkbase = p->p_brkbase;
	sp->pr_brksize = p->p_brksize;
	sp->pr_stkbase = gcore_prgetstackbase(p);
	sp->pr_stksize = p->p_stksize;

	prassignset(&sp->pr_sigtrace, &p->p_sigmask);
	prassignset(&sp->pr_flttrace, &p->p_fltmask);
	prassignset(&sp->pr_sysentry, &PTOU(p)->u_entrymask);
	prassignset(&sp->pr_sysexit, &PTOU(p)->u_exitmask);

	/* get the chosen lwp's status */
	gcore_prgetlwpstatus(p, t_addr, t, &sp->pr_lwp, NULL);

	/* replicate the flags */
	sp->pr_flags = sp->pr_lwp.pr_flags;
}

/*
 * Fields not populated:
 *   - pr_contract
 *   - pr_addr
 *   - pr_rtime
 *   - pr_ctime
 *   - pr_ttydev
 *   - pr_pctcpu
 *   - pr_size
 *   - pr_rsize
 *   - pr_pctmem
 */
/*ARGSUSED*/
static const psinfo_t *
Ppsinfo_gcore(struct ps_prochandle *P, psinfo_t *psp, void *data)
{
	mdb_proc_t	*p = data;
	mdb_kthread_t	*t;
	mdb_pool_t	pool;
	cred_t		cr;
	uintptr_t	t_addr;
	pcommon_t	pc;

	if ((t_addr = gcore_prchoose(p)) == NULL) {
		bzero(psp, sizeof (*psp));
	} else {
		bzero(psp, sizeof (*psp) - sizeof (psp->pr_lwp));
	}

	if (pcommon_init(p, &pc) == -1) {
		return (NULL);
	}
	psp->pr_nlwp = pc.pc_nlwp;
	psp->pr_nzomb = pc.pc_nzomb;
	psp->pr_pid = pc.pc_pid;
	psp->pr_ppid = pc.pc_ppid;
	psp->pr_pgid = pc.pc_pgid;
	psp->pr_sid = pc.pc_sid;
	psp->pr_taskid = pc.pc_taskid;
	psp->pr_projid = pc.pc_projid;
	psp->pr_dmodel = pc.pc_dmodel;

	/*
	 * only export SSYS and SMSACCT; everything else is off-limits to
	 * userland apps.
	 */
	psp->pr_flag = p->p_flag & (SSYS | SMSACCT);

	if (mdb_vread(&cr, sizeof (cr), p->p_cred) != sizeof (cr)) {
		mdb_warn("Failed to read cred_t from %p\n", p->p_cred);
		return (NULL);
	}

	psp->pr_uid = cr.cr_ruid;
	psp->pr_euid = cr.cr_uid;
	psp->pr_gid = cr.cr_rgid;
	psp->pr_egid = cr.cr_gid;

	if (mdb_ctf_vread(&pool, "pool_t", "mdb_pool_t", p->p_pool, 0) == -1) {
		return (NULL);
	}
	psp->pr_poolid = pool.pool_id;

	if (t_addr == 0) {
		int wcode = p->p_wcode;

		if (wcode)
			psp->pr_wstat = gcore_wstat(wcode, p->p_wdata);
		psp->pr_ttydev = PRNODEV;
		psp->pr_lwp.pr_state = SZOMB;
		psp->pr_lwp.pr_sname = 'Z';
		psp->pr_lwp.pr_bindpro = PBIND_NONE;
		psp->pr_lwp.pr_bindpset = PS_NONE;
	} else {
		mdb_kthread_t	kthr;
		user_t		*up = PTOU(p);

		psp->pr_start = up->u_start;
		bcopy(up->u_comm, psp->pr_fname,
		    MIN(sizeof (up->u_comm), sizeof (psp->pr_fname)-1));
		bcopy(up->u_psargs, psp->pr_psargs,
		    MIN(PRARGSZ-1, PSARGSZ));

		psp->pr_argc = up->u_argc;
		psp->pr_argv = up->u_argv;
		psp->pr_envp = up->u_envp;

		/* get the chosen lwp's lwpsinfo */
		if (mdb_ctf_vread(&kthr, "kthread_t", "mdb_kthread_t", t_addr,
		    0) == -1) {
			return (NULL);
		}
		t = &kthr;

		gcore_prgetlwpsinfo(t_addr, t, &psp->pr_lwp);
	}

	return (NULL);
}

/*ARGSUSED*/
static prheader_t *
Plstatus_gcore(struct ps_prochandle *P, void *data)
{
	mdb_proc_t	*p = data;
	int		nlwp = p->p_lwpcnt;
	size_t		ent_size = LSPAN(lwpstatus_t);

	return (gcore_walk_lwps(p, gcore_lstatus_cb, nlwp, ent_size));
}

/*ARGSUSED*/
static prheader_t *
Plpsinfo_gcore(struct ps_prochandle *P, void *data)
{
	mdb_proc_t	*p = data;
	int		nlwp = p->p_lwpcnt + p->p_zombcnt;
	size_t		ent_size = LSPAN(lwpsinfo_t);

	return (gcore_walk_lwps(p, gcore_lpsinfo_cb, nlwp, ent_size));
}

/*ARGSUSED*/
static char *
Pplatform_gcore(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	char	platform[SYS_NMLN];

	if (mdb_readvar(platform, "platform") == -1) {
		mdb_warn("failed to read platform!\n");
		return (NULL);
	}
	dprintf("platform: %s\n", platform);

	(void) strncpy(s, platform, n);
	return (s);
}

/*ARGSUSED*/
static int
Puname_gcore(struct ps_prochandle *P, struct utsname *u, void *data)
{
	if (mdb_readvar(u, "utsname") != sizeof (*u)) {
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static char *
Pzonename_gcore(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	mdb_proc_t	*p = data;
	mdb_zone_t	zone;

	if (mdb_ctf_vread(&zone, "zone_t", "mdb_zone_t", p->p_zone, 0) == -1) {
		return (NULL);
	}

	if (mdb_readstr(s, n, zone.zone_name) == -1) {
		mdb_warn("Failed to read zone name from %p\n", zone.zone_name);
		return (NULL);
	}

	return (s);
}

/*ARGSUSED*/
static char *
Pexecname_gcore(struct ps_prochandle *P, char *buf, size_t buflen, void *data)
{
	mdb_proc_t	*p = data;
	mdb_vnode_t	vn;

	if (mdb_ctf_vread(&vn, "vnode_t", "mdb_vnode_t", p->p_exec, 0) == -1) {
		return (NULL);
	}

	if (mdb_readstr(buf, buflen, vn.v_path) == -1) {
		mdb_warn("Failed to read vnode path from %p\n", vn.v_path);
		return (NULL);
	}

	dprintf("execname: %s\n", buf);

	return (buf);
}

#if defined(__i386) || defined(__amd64)
/*ARGSUSED*/
static int
Pldt_gcore(struct ps_prochandle *P, struct ssd *pldt, int nldt, void *data)
{
	mdb_proc_t	*p = data;
	user_desc_t	*udp;
	user_desc_t	*ldts;
	size_t		ldt_size;
	int		i, limit;

	if (p->p_ldt == NULL) {
		return (0);
	}

	limit = p->p_ldtlimit;

	/* Is this call just to query the size ? */
	if (pldt == NULL || nldt == 0) {
		return (limit);
	}

	ldt_size = limit * sizeof (*ldts);
	ldts = malloc(ldt_size);
	if (ldts == NULL) {
		mdb_warn("Failed to malloc ldts (size %lld)n", ldt_size);
		return (-1);
	}

	if (mdb_vread(ldts, ldt_size, p->p_ldt) != ldt_size) {
		mdb_warn("Failed to read ldts from %p\n", p->p_ldt);
		free(ldts);
		return (-1);
	}

	for (i = LDT_UDBASE, udp = &ldts[i]; i <= limit; i++, udp++) {
		if (udp->usd_type != 0 || udp->usd_dpl != 0 ||
		    udp->usd_p != 0) {
			gcore_usd_to_ssd(udp, pldt++, SEL_LDT(i));
		}
	}

	free(ldts);
	return (limit);
}
#endif

static const ps_ops_t Pgcore_ops = {
	.pop_pread	= Pread_gcore,
	.pop_pwrite	= Pwrite_gcore,
	.pop_read_maps	= Pread_maps_gcore,
	.pop_read_aux	= Pread_aux_gcore,
	.pop_cred	= Pcred_gcore,
	.pop_priv	= Ppriv_gcore,
	.pop_psinfo	= Ppsinfo_gcore,
	.pop_status	= Pstatus_gcore,
	.pop_lstatus	= Plstatus_gcore,
	.pop_lpsinfo	= Plpsinfo_gcore,
	.pop_platform	= Pplatform_gcore,
	.pop_uname	= Puname_gcore,
	.pop_zonename	= Pzonename_gcore,
	.pop_execname	= Pexecname_gcore,
#if defined(__i386) || defined(__amd64)
	.pop_ldt	= Pldt_gcore
#endif
};

/*ARGSUSED*/
int
gcore_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct ps_prochandle *P;
	char		core_name[MAXNAMELEN];
	mdb_proc_t	p;
	mdb_pid_t	pid;

	if (!gcore_initialized) {
		mdb_warn("gcore unavailable\n");
		return (DCMD_ERR);
	}

	if (mdb_ctf_vread(&p, "proc_t", "mdb_proc_t", addr, 0) == -1) {
		return (DCMD_ERR);
	}

	if (p.p_flag & SSYS) {
		mdb_warn("'%s' is a system process\n", p.p_user.u_comm);
		return (DCMD_ERR);
	}

	if (mdb_ctf_vread(&pid, "struct pid", "mdb_pid_t", p.p_pidp, 0)
	    == -1) {
		return (DCMD_ERR);
	}

	if ((P = Pgrab_ops(pid.pid_id, &p, &Pgcore_ops, PGRAB_INCORE)) ==
	    NULL) {
		mdb_warn("Failed to initialize proc handle");
		return (DCMD_ERR);
	}

	(void) snprintf(core_name, sizeof (core_name), "core.%s.%d",
	    p.p_user.u_comm, pid.pid_id);

	if (Pgcore(P, core_name, CC_CONTENT_DEFAULT) != 0) {
		mdb_warn("Failed to generate core file: %d", errno);
		Pfree(P);
		return (DCMD_ERR);
	}

	Pfree(P);
	mdb_printf("Created core file: %s\n", core_name);

	return (0);
}

void
gcore_init(void)
{
	GElf_Sym	sym;
	uintptr_t	priv_info_addr;

	if (mdb_lookup_by_name("segvn_ops", &sym) == -1) {
		mdb_warn("Failed to lookup symbol 'segvn_ops'\n");
		return;
	}
	gcore_segvn_ops = sym.st_value;

	if (mdb_readvar(&priv_info_addr, "priv_info") == -1) {
		mdb_warn("Failed to read variable 'priv_info'\n");
		return;
	}

	if (mdb_vread(&prinfo, sizeof (prinfo), priv_info_addr) == -1) {
		mdb_warn("Failed to read prinfo from %p\n", priv_info_addr);
		return;
	}

	if (mdb_lookup_by_name("sclass", &sym) == -1) {
		mdb_warn("Failed to lookup symbol 'segvn_ops'\n");
		return;
	}

	gcore_sclass = mdb_zalloc(sym.st_size, UM_SLEEP);
	if (mdb_vread(gcore_sclass, sym.st_size, sym.st_value) != sym.st_size) {
		mdb_warn("Failed to read sclass' from %p\n", sym.st_value);
		return;
	}

	if (mdb_lookup_by_name("kas", &sym) == -1) {
		mdb_warn("Failed to lookup symbol 'kas'\n");
		return;
	}
	gcore_kas = sym.st_value;

	gcore_initialized = B_TRUE;
}

#endif /* _KMDB */
