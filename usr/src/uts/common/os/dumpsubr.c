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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/mem.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/memlist.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>
#include <sys/ksyms.h>
#include <sys/compress.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/bitmap.h>
#include <sys/modctl.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/vmem.h>
#include <sys/log.h>
#include <sys/var.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <fs/fs_subr.h>
#include <sys/fs/snode.h>
#include <sys/ontrap.h>
#include <sys/panic.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/errorq.h>
#include <sys/fm/util.h>
#include <sys/fs/zfs.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>

kmutex_t	dump_lock;	/* lock for dump configuration */
dumphdr_t	*dumphdr;	/* dump header */
int		dump_conflags = DUMP_KERNEL; /* dump configuration flags */
vnode_t		*dumpvp;	/* dump device vnode pointer */
u_offset_t	dumpvp_size;	/* size of dump device, in bytes */
static u_offset_t dumpvp_limit;	/* maximum write offset */
char		*dumppath;	/* pathname of dump device */
int		dump_timeout = 120; /* timeout for dumping page during panic */
int		dump_timeleft;	/* portion of dump_timeout remaining */
int		dump_ioerr;	/* dump i/o error */

#ifdef DEBUG
int		dumpfaildebug = 1;	/* enter debugger if dump fails */
#else
int		dumpfaildebug = 0;
#endif

static ulong_t	*dump_bitmap;	/* bitmap for marking pages to dump */
static pgcnt_t	dump_bitmapsize; /* size of bitmap */
static pid_t	*dump_pids;	/* list of process IDs at dump time */
static offset_t	dumpvp_off;	/* current dump device offset */
static char	*dump_cmap;	/* VA for dump compression mapping */
static char	*dumpbuf_cur, *dumpbuf_start, *dumpbuf_end;
static char	*dump_cbuf;	/* compression buffer */
static char	*dump_uebuf;	/* memory error detection buffer */
static size_t	dumpbuf_size;	/* size of dumpbuf in bytes */
static size_t	dumpbuf_limit = 1UL << 23;	/* 8MB */
static size_t	dump_iosize;	/* device's best transfer size, if any */
static uint64_t	dumpbuf_thresh = 1ULL << 30;	/* 1GB */
static ulong_t	dumpbuf_mult = 8;

/*
 * The dump i/o buffer must be at least one page, at most xfer_size bytes, and
 * should scale with physmem in between.  The transfer size passed in will
 * either represent a global default (maxphys) or the best size for the device.
 * Once the physical memory size exceeds dumpbuf_thresh (1GB by default), we
 * increase the percentage of physical memory that dumpbuf can consume by a
 * factor of dumpbuf_mult (8 by default) to improve large memory performance.
 * The size of the dumpbuf i/o buffer is limited by dumpbuf_limit (8MB by
 * default) because the dump performance saturates beyond a certain size.
 */
static size_t
dumpbuf_iosize(size_t xfer_size)
{
	pgcnt_t scale = physmem;
	size_t iosize;

	if (scale >= dumpbuf_thresh / PAGESIZE) {
		scale *= dumpbuf_mult; /* increase scaling factor */
		iosize = MIN(xfer_size, scale) & PAGEMASK;
		if (dumpbuf_limit && iosize > dumpbuf_limit)
			iosize = MAX(PAGESIZE, dumpbuf_limit & PAGEMASK);
	} else
		iosize = MAX(PAGESIZE, MIN(xfer_size, scale) & PAGEMASK);

	return (iosize);
}

static void
dumpbuf_resize(void)
{
	char *old_buf = dumpbuf_start;
	size_t old_size = dumpbuf_size;
	char *new_buf;
	size_t new_size;

	ASSERT(MUTEX_HELD(&dump_lock));

	if ((new_size = dumpbuf_iosize(MAX(dump_iosize, maxphys))) <= old_size)
		return; /* no need to reallocate buffer */

	new_buf = kmem_alloc(new_size, KM_SLEEP);
	dumpbuf_size = new_size;
	dumpbuf_start = new_buf;
	dumpbuf_end = new_buf + new_size;
	kmem_free(old_buf, old_size);
}

static void
dumphdr_init(void)
{
	pgcnt_t npages = 0;

	ASSERT(MUTEX_HELD(&dump_lock));

	if (dumphdr == NULL) {
		dumphdr = kmem_zalloc(sizeof (dumphdr_t), KM_SLEEP);
		dumphdr->dump_magic = DUMP_MAGIC;
		dumphdr->dump_version = DUMP_VERSION;
		dumphdr->dump_wordsize = DUMP_WORDSIZE;
		dumphdr->dump_pageshift = PAGESHIFT;
		dumphdr->dump_pagesize = PAGESIZE;
		dumphdr->dump_utsname = utsname;
		(void) strcpy(dumphdr->dump_platform, platform);
		dump_cmap = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
		dumpbuf_size = dumpbuf_iosize(maxphys);
		dumpbuf_start = kmem_alloc(dumpbuf_size, KM_SLEEP);
		dumpbuf_end = dumpbuf_start + dumpbuf_size;
		dump_cbuf = kmem_alloc(PAGESIZE, KM_SLEEP); /* compress buf */
		dump_uebuf = kmem_alloc(PAGESIZE, KM_SLEEP); /* UE buf */
		dump_pids = kmem_alloc(v.v_proc * sizeof (pid_t), KM_SLEEP);
	}

	npages = num_phys_pages();

	if (dump_bitmapsize != npages) {
		void *map = kmem_alloc(BT_SIZEOFMAP(npages), KM_SLEEP);
		kmem_free(dump_bitmap, BT_SIZEOFMAP(dump_bitmapsize));
		dump_bitmap = map;
		dump_bitmapsize = npages;
	}
}

/*
 * Establish a new dump device.
 */
int
dumpinit(vnode_t *vp, char *name, int justchecking)
{
	vnode_t *cvp;
	vattr_t vattr;
	vnode_t *cdev_vp;
	int error = 0;

	ASSERT(MUTEX_HELD(&dump_lock));

	dumphdr_init();

	cvp = common_specvp(vp);
	if (cvp == dumpvp)
		return (0);

	/*
	 * Determine whether this is a plausible dump device.  We want either:
	 * (1) a real device that's not mounted and has a cb_dump routine, or
	 * (2) a swapfile on some filesystem that has a vop_dump routine.
	 */
	if ((error = VOP_OPEN(&cvp, FREAD | FWRITE, kcred, NULL)) != 0)
		return (error);

	vattr.va_mask = AT_SIZE | AT_TYPE | AT_RDEV;
	if ((error = VOP_GETATTR(cvp, &vattr, 0, kcred, NULL)) == 0) {
		if (vattr.va_type == VBLK || vattr.va_type == VCHR) {
			if (devopsp[getmajor(vattr.va_rdev)]->
			    devo_cb_ops->cb_dump == nodev)
				error = ENOTSUP;
			else if (vfs_devismounted(vattr.va_rdev))
				error = EBUSY;
		} else {
			if (vn_matchopval(cvp, VOPNAME_DUMP, fs_nosys) ||
			    !IS_SWAPVP(cvp))
				error = ENOTSUP;
		}
	}

	if (error == 0 && vattr.va_size < 2 * DUMP_LOGSIZE + DUMP_ERPTSIZE)
		error = ENOSPC;

	if (error || justchecking) {
		(void) VOP_CLOSE(cvp, FREAD | FWRITE, 1, (offset_t)0,
		    kcred, NULL);
		return (error);
	}

	VN_HOLD(cvp);

	if (dumpvp != NULL)
		dumpfini();	/* unconfigure the old dump device */

	dumpvp = cvp;
	dumpvp_size = vattr.va_size & -DUMP_OFFSET;
	dumppath = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(dumppath, name);
	dump_iosize = 0;

	/*
	 * If the dump device is a block device, attempt to open up the
	 * corresponding character device and determine its maximum transfer
	 * size.  We use this information to potentially resize dumpbuf to a
	 * larger and more optimal size for performing i/o to the dump device.
	 */
	if (cvp->v_type == VBLK &&
	    (cdev_vp = makespecvp(VTOS(cvp)->s_dev, VCHR)) != NULL) {
		if (VOP_OPEN(&cdev_vp, FREAD | FWRITE, kcred, NULL) == 0) {
			size_t blk_size;
			struct dk_cinfo dki;
			struct vtoc vtoc;

			if (VOP_IOCTL(cdev_vp, DKIOCGVTOC, (intptr_t)&vtoc,
			    FKIOCTL, kcred, NULL, NULL) == 0 &&
			    vtoc.v_sectorsz != 0)
				blk_size = vtoc.v_sectorsz;
			else
				blk_size = DEV_BSIZE;

			if (VOP_IOCTL(cdev_vp, DKIOCINFO, (intptr_t)&dki,
			    FKIOCTL, kcred, NULL, NULL) == 0) {
				dump_iosize = dki.dki_maxtransfer * blk_size;
				dumpbuf_resize();
			}
			/*
			 * If we are working with a zvol then call into
			 * it to dumpify itself.
			 */
			if (strcmp(dki.dki_dname, ZVOL_DRIVER) == 0) {
				if ((error = VOP_IOCTL(cdev_vp,
				    DKIOCDUMPINIT, NULL, FKIOCTL, kcred,
				    NULL, NULL)) != 0) {
					dumpfini();
				}
			}

			(void) VOP_CLOSE(cdev_vp, FREAD | FWRITE, 1, 0,
			    kcred, NULL);
		}

		VN_RELE(cdev_vp);
	}

	cmn_err(CE_CONT, "?dump on %s size %llu MB\n", name, dumpvp_size >> 20);

	return (error);
}

void
dumpfini(void)
{
	vattr_t vattr;
	boolean_t is_zfs = B_FALSE;
	vnode_t *cdev_vp;
	ASSERT(MUTEX_HELD(&dump_lock));

	kmem_free(dumppath, strlen(dumppath) + 1);

	/*
	 * Determine if we are using zvols for our dump device
	 */
	vattr.va_mask = AT_RDEV;
	if (VOP_GETATTR(dumpvp, &vattr, 0, kcred, NULL) == 0) {
		is_zfs = (getmajor(vattr.va_rdev) ==
		    ddi_name_to_major(ZFS_DRIVER)) ? B_TRUE : B_FALSE;
	}

	/*
	 * If we have a zvol dump device then we call into zfs so
	 * that it may have a chance to cleanup.
	 */
	if (is_zfs &&
	    (cdev_vp = makespecvp(VTOS(dumpvp)->s_dev, VCHR)) != NULL) {
		if (VOP_OPEN(&cdev_vp, FREAD | FWRITE, kcred, NULL) == 0) {
			(void) VOP_IOCTL(cdev_vp, DKIOCDUMPFINI, NULL, FKIOCTL,
			    kcred, NULL, NULL);
			(void) VOP_CLOSE(cdev_vp, FREAD | FWRITE, 1, 0,
			    kcred, NULL);
		}
		VN_RELE(cdev_vp);
	}

	(void) VOP_CLOSE(dumpvp, FREAD | FWRITE, 1, (offset_t)0, kcred, NULL);

	VN_RELE(dumpvp);

	dumpvp = NULL;
	dumpvp_size = 0;
	dumppath = NULL;
}

static pfn_t
dump_bitnum_to_pfn(pgcnt_t bitnum)
{
	struct memlist *mp;

	for (mp = phys_install; mp != NULL; mp = mp->next) {
		if (bitnum < (mp->size >> PAGESHIFT))
			return ((mp->address >> PAGESHIFT) + bitnum);
		bitnum -= mp->size >> PAGESHIFT;
	}
	return (PFN_INVALID);
}

static pgcnt_t
dump_pfn_to_bitnum(pfn_t pfn)
{
	struct memlist *mp;
	pgcnt_t bitnum = 0;

	for (mp = phys_install; mp != NULL; mp = mp->next) {
		if (pfn >= (mp->address >> PAGESHIFT) &&
		    pfn < ((mp->address + mp->size) >> PAGESHIFT))
			return (bitnum + pfn - (mp->address >> PAGESHIFT));
		bitnum += mp->size >> PAGESHIFT;
	}
	return ((pgcnt_t)-1);
}

static offset_t
dumpvp_flush(void)
{
	size_t size = P2ROUNDUP(dumpbuf_cur - dumpbuf_start, PAGESIZE);
	int err;

	if (dumpvp_off + size > dumpvp_limit) {
		dump_ioerr = ENOSPC;
	} else if (size != 0) {
		if (panicstr)
			err = VOP_DUMP(dumpvp, dumpbuf_start,
			    lbtodb(dumpvp_off), btod(size), NULL);
		else
			err = vn_rdwr(UIO_WRITE, dumpvp, dumpbuf_start, size,
			    dumpvp_off, UIO_SYSSPACE, 0, dumpvp_limit,
			    kcred, 0);
		if (err && dump_ioerr == 0)
			dump_ioerr = err;
	}
	dumpvp_off += size;
	dumpbuf_cur = dumpbuf_start;
	dump_timeleft = dump_timeout;
	return (dumpvp_off);
}

void
dumpvp_write(const void *va, size_t size)
{
	while (size != 0) {
		size_t len = MIN(size, dumpbuf_end - dumpbuf_cur);
		if (len == 0) {
			(void) dumpvp_flush();
		} else {
			bcopy(va, dumpbuf_cur, len);
			va = (char *)va + len;
			dumpbuf_cur += len;
			size -= len;
		}
	}
}

/*ARGSUSED*/
static void
dumpvp_ksyms_write(const void *src, void *dst, size_t size)
{
	dumpvp_write(src, size);
}

/*
 * Mark 'pfn' in the bitmap and dump its translation table entry.
 */
void
dump_addpage(struct as *as, void *va, pfn_t pfn)
{
	mem_vtop_t mem_vtop;
	pgcnt_t bitnum;

	if ((bitnum = dump_pfn_to_bitnum(pfn)) != (pgcnt_t)-1) {
		if (!BT_TEST(dump_bitmap, bitnum)) {
			dumphdr->dump_npages++;
			BT_SET(dump_bitmap, bitnum);
		}
		dumphdr->dump_nvtop++;
		mem_vtop.m_as = as;
		mem_vtop.m_va = va;
		mem_vtop.m_pfn = pfn;
		dumpvp_write(&mem_vtop, sizeof (mem_vtop_t));
	}
	dump_timeleft = dump_timeout;
}

/*
 * Mark 'pfn' in the bitmap
 */
void
dump_page(pfn_t pfn)
{
	pgcnt_t bitnum;

	if ((bitnum = dump_pfn_to_bitnum(pfn)) != (pgcnt_t)-1) {
		if (!BT_TEST(dump_bitmap, bitnum)) {
			dumphdr->dump_npages++;
			BT_SET(dump_bitmap, bitnum);
		}
	}
	dump_timeleft = dump_timeout;
}

/*
 * Dump the <as, va, pfn> information for a given address space.
 * SEGOP_DUMP() will call dump_addpage() for each page in the segment.
 */
static void
dump_as(struct as *as)
{
	struct seg *seg;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	for (seg = AS_SEGFIRST(as); seg; seg = AS_SEGNEXT(as, seg)) {
		if (seg->s_as != as)
			break;
		if (seg->s_ops == NULL)
			continue;
		SEGOP_DUMP(seg);
	}
	AS_LOCK_EXIT(as, &as->a_lock);

	if (seg != NULL)
		cmn_err(CE_WARN, "invalid segment %p in address space %p",
		    (void *)seg, (void *)as);
}

static int
dump_process(pid_t pid)
{
	proc_t *p = sprlock(pid);

	if (p == NULL)
		return (-1);
	if (p->p_as != &kas) {
		mutex_exit(&p->p_lock);
		dump_as(p->p_as);
		mutex_enter(&p->p_lock);
	}

	sprunlock(p);

	return (0);
}

void
dump_ereports(void)
{
	u_offset_t dumpvp_start;
	erpt_dump_t ed;

	if (dumpvp == NULL || dumphdr == NULL)
		return;

	dumpbuf_cur = dumpbuf_start;
	dumpvp_limit = dumpvp_size - (DUMP_OFFSET + DUMP_LOGSIZE);
	dumpvp_start = dumpvp_limit - DUMP_ERPTSIZE;
	dumpvp_off = dumpvp_start;

	fm_ereport_dump();
	if (panicstr)
		errorq_dump();

	bzero(&ed, sizeof (ed)); /* indicate end of ereports */
	dumpvp_write(&ed, sizeof (ed));
	(void) dumpvp_flush();

	if (!panicstr) {
		(void) VOP_PUTPAGE(dumpvp, dumpvp_start,
		    (size_t)(dumpvp_off - dumpvp_start),
		    B_INVAL | B_FORCE, kcred, NULL);
	}
}

void
dump_messages(void)
{
	log_dump_t ld;
	mblk_t *mctl, *mdata;
	queue_t *q, *qlast;
	u_offset_t dumpvp_start;

	if (dumpvp == NULL || dumphdr == NULL || log_consq == NULL)
		return;

	dumpbuf_cur = dumpbuf_start;
	dumpvp_limit = dumpvp_size - DUMP_OFFSET;
	dumpvp_start = dumpvp_limit - DUMP_LOGSIZE;
	dumpvp_off = dumpvp_start;

	qlast = NULL;
	do {
		for (q = log_consq; q->q_next != qlast; q = q->q_next)
			continue;
		for (mctl = q->q_first; mctl != NULL; mctl = mctl->b_next) {
			dump_timeleft = dump_timeout;
			mdata = mctl->b_cont;
			ld.ld_magic = LOG_MAGIC;
			ld.ld_msgsize = MBLKL(mctl->b_cont);
			ld.ld_csum = checksum32(mctl->b_rptr, MBLKL(mctl));
			ld.ld_msum = checksum32(mdata->b_rptr, MBLKL(mdata));
			dumpvp_write(&ld, sizeof (ld));
			dumpvp_write(mctl->b_rptr, MBLKL(mctl));
			dumpvp_write(mdata->b_rptr, MBLKL(mdata));
		}
	} while ((qlast = q) != log_consq);

	ld.ld_magic = 0;		/* indicate end of messages */
	dumpvp_write(&ld, sizeof (ld));
	(void) dumpvp_flush();
	if (!panicstr) {
		(void) VOP_PUTPAGE(dumpvp, dumpvp_start,
		    (size_t)(dumpvp_off - dumpvp_start),
		    B_INVAL | B_FORCE, kcred, NULL);
	}
}

static void
dump_pagecopy(void *src, void *dst)
{
	long *wsrc = (long *)src;
	long *wdst = (long *)dst;
	const ulong_t ncopies = PAGESIZE / sizeof (long);
	volatile int w = 0;
	volatile int ueoff = -1;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_EC)) {
		if (ueoff == -1) {
			uint64_t pa;

			ueoff = w * sizeof (long);
			pa = ptob((uint64_t)hat_getpfnum(kas.a_hat, src))
			    + ueoff;
			cmn_err(CE_WARN, "memory error at PA 0x%08x.%08x",
			    (uint32_t)(pa >> 32), (uint32_t)pa);
		}
#ifdef _LP64
		wdst[w++] = 0xbadecc00badecc;
#else
		wdst[w++] = 0xbadecc;
#endif
	}
	while (w < ncopies) {
		wdst[w] = wsrc[w];
		w++;
	}
	no_trap();
}

/*
 * Dump the system.
 */
void
dumpsys(void)
{
	pfn_t pfn;
	pgcnt_t bitnum;
	int npages = 0;
	int percent_done = 0;
	uint32_t csize;
	u_offset_t total_csize = 0;
	int compress_ratio;
	proc_t *p;
	pid_t npids, pidx;
	char *content;

	if (dumpvp == NULL || dumphdr == NULL) {
		uprintf("skipping system dump - no dump device configured\n");
		return;
	}
	dumpbuf_cur = dumpbuf_start;

	/*
	 * Calculate the starting block for dump.  If we're dumping on a
	 * swap device, start 1/5 of the way in; otherwise, start at the
	 * beginning.  And never use the first page -- it may be a disk label.
	 */
	if (dumpvp->v_flag & VISSWAP)
		dumphdr->dump_start = P2ROUNDUP(dumpvp_size / 5, DUMP_OFFSET);
	else
		dumphdr->dump_start = DUMP_OFFSET;

	dumphdr->dump_flags = DF_VALID | DF_COMPLETE | DF_LIVE;
	dumphdr->dump_crashtime = gethrestime_sec();
	dumphdr->dump_npages = 0;
	dumphdr->dump_nvtop = 0;
	bzero(dump_bitmap, BT_SIZEOFMAP(dump_bitmapsize));
	dump_timeleft = dump_timeout;

	if (panicstr) {
		dumphdr->dump_flags &= ~DF_LIVE;
		(void) VOP_DUMPCTL(dumpvp, DUMP_FREE, NULL, NULL);
		(void) VOP_DUMPCTL(dumpvp, DUMP_ALLOC, NULL, NULL);
		(void) vsnprintf(dumphdr->dump_panicstring, DUMP_PANICSIZE,
		    panicstr, panicargs);
	}

	if (dump_conflags & DUMP_ALL)
		content = "all";
	else if (dump_conflags & DUMP_CURPROC)
		content = "kernel + curproc";
	else
		content = "kernel";
	uprintf("dumping to %s, offset %lld, content: %s\n", dumppath,
	    dumphdr->dump_start, content);

	/*
	 * Leave room for the message and ereport save areas and terminal dump
	 * header.
	 */
	dumpvp_limit = dumpvp_size - DUMP_LOGSIZE - DUMP_OFFSET - DUMP_ERPTSIZE;

	/*
	 * Write out the symbol table.  It's no longer compressed,
	 * so its 'size' and 'csize' are equal.
	 */
	dumpvp_off = dumphdr->dump_ksyms = dumphdr->dump_start + PAGESIZE;
	dumphdr->dump_ksyms_size = dumphdr->dump_ksyms_csize =
	    ksyms_snapshot(dumpvp_ksyms_write, NULL, LONG_MAX);

	/*
	 * Write out the translation map.
	 */
	dumphdr->dump_map = dumpvp_flush();
	dump_as(&kas);
	dumphdr->dump_nvtop += dump_plat_addr();

	/*
	 * call into hat, which may have unmapped pages that also need to
	 * be in the dump
	 */
	hat_dump();

	if (dump_conflags & DUMP_ALL) {
		mutex_enter(&pidlock);

		for (npids = 0, p = practive; p != NULL; p = p->p_next)
			dump_pids[npids++] = p->p_pid;

		mutex_exit(&pidlock);

		for (pidx = 0; pidx < npids; pidx++)
			(void) dump_process(dump_pids[pidx]);

		for (bitnum = 0; bitnum < dump_bitmapsize; bitnum++) {
			dump_timeleft = dump_timeout;
			BT_SET(dump_bitmap, bitnum);
		}
		dumphdr->dump_npages = dump_bitmapsize;
		dumphdr->dump_flags |= DF_ALL;

	} else if (dump_conflags & DUMP_CURPROC) {
		/*
		 * Determine which pid is to be dumped.  If we're panicking, we
		 * dump the process associated with panic_thread (if any).  If
		 * this is a live dump, we dump the process associated with
		 * curthread.
		 */
		npids = 0;
		if (panicstr) {
			if (panic_thread != NULL &&
			    panic_thread->t_procp != NULL &&
			    panic_thread->t_procp != &p0) {
				dump_pids[npids++] =
				    panic_thread->t_procp->p_pid;
			}
		} else {
			dump_pids[npids++] = curthread->t_procp->p_pid;
		}

		if (npids && dump_process(dump_pids[0]) == 0)
			dumphdr->dump_flags |= DF_CURPROC;
		else
			dumphdr->dump_flags |= DF_KERNEL;

	} else {
		dumphdr->dump_flags |= DF_KERNEL;
	}

	dumphdr->dump_hashmask = (1 << highbit(dumphdr->dump_nvtop - 1)) - 1;

	/*
	 * Write out the pfn table.
	 */
	dumphdr->dump_pfn = dumpvp_flush();
	for (bitnum = 0; bitnum < dump_bitmapsize; bitnum++) {
		dump_timeleft = dump_timeout;
		if (!BT_TEST(dump_bitmap, bitnum))
			continue;
		pfn = dump_bitnum_to_pfn(bitnum);
		ASSERT(pfn != PFN_INVALID);
		dumpvp_write(&pfn, sizeof (pfn_t));
	}
	dump_plat_pfn();

	/*
	 * Write out all the pages.
	 */
	dumphdr->dump_data = dumpvp_flush();
	for (bitnum = 0; bitnum < dump_bitmapsize; bitnum++) {
		dump_timeleft = dump_timeout;
		if (!BT_TEST(dump_bitmap, bitnum))
			continue;
		pfn = dump_bitnum_to_pfn(bitnum);
		ASSERT(pfn != PFN_INVALID);

		/*
		 * Map in page frame 'pfn', scan it for UE's while copying
		 * the data to dump_uebuf, unmap it, compress dump_uebuf into
		 * dump_cbuf, and write out dump_cbuf.  The UE check ensures
		 * that we don't lose the whole dump because of a latent UE.
		 */
		hat_devload(kas.a_hat, dump_cmap, PAGESIZE, pfn, PROT_READ,
		    HAT_LOAD_NOCONSIST);
		dump_pagecopy(dump_cmap, dump_uebuf);
		hat_unload(kas.a_hat, dump_cmap, PAGESIZE, HAT_UNLOAD);
		csize = (uint32_t)compress(dump_uebuf, dump_cbuf, PAGESIZE);
		dumpvp_write(&csize, sizeof (uint32_t));
		dumpvp_write(dump_cbuf, csize);
		if (dump_ioerr) {
			dumphdr->dump_flags &= ~DF_COMPLETE;
			dumphdr->dump_npages = npages;
			break;
		}
		total_csize += csize;
		if (++npages * 100LL / dumphdr->dump_npages > percent_done) {
			uprintf("^\r%3d%% done", ++percent_done);
			if (!panicstr)
				delay(1);	/* let the output be sent */
		}
	}
	dumphdr->dump_npages += dump_plat_data(dump_cbuf);

	(void) dumpvp_flush();

	/*
	 * Write out the initial and terminal dump headers.
	 */
	dumpvp_off = dumphdr->dump_start;
	dumpvp_write(dumphdr, sizeof (dumphdr_t));
	(void) dumpvp_flush();

	dumpvp_limit = dumpvp_size;
	dumpvp_off = dumpvp_limit - DUMP_OFFSET;
	dumpvp_write(dumphdr, sizeof (dumphdr_t));
	(void) dumpvp_flush();

	compress_ratio = (int)(100LL * npages / (btopr(total_csize + 1)));

	uprintf("\r%3d%% done: %d pages dumped, compression ratio %d.%02d, ",
	    percent_done, npages, compress_ratio / 100, compress_ratio % 100);

	if (dump_ioerr == 0) {
		uprintf("dump succeeded\n");
	} else {
		uprintf("dump failed: error %d\n", dump_ioerr);
		if (panicstr && dumpfaildebug)
			debug_enter("dump failed");
	}

	/*
	 * Write out all undelivered messages.  This has to be the *last*
	 * thing we do because the dump process itself emits messages.
	 */
	if (panicstr) {
		dump_ereports();
		dump_messages();
	}

	delay(2 * hz);	/* let people see the 'done' message */
	dump_timeleft = 0;
	dump_ioerr = 0;
}

/*
 * This function is called whenever the memory size, as represented
 * by the phys_install list, changes.
 */
void
dump_resize()
{
	mutex_enter(&dump_lock);
	dumphdr_init();
	dumpbuf_resize();
	mutex_exit(&dump_lock);
}

/*
 * This function allows for dynamic resizing of a dump area. It assumes that
 * the underlying device has update its appropriate size(9P).
 */
int
dumpvp_resize()
{
	int error;
	vattr_t vattr;

	mutex_enter(&dump_lock);
	vattr.va_mask = AT_SIZE;
	if ((error = VOP_GETATTR(dumpvp, &vattr, 0, kcred, NULL)) != 0) {
		mutex_exit(&dump_lock);
		return (error);
	}

	if (error == 0 && vattr.va_size < 2 * DUMP_LOGSIZE + DUMP_ERPTSIZE) {
		mutex_exit(&dump_lock);
		return (ENOSPC);
	}

	dumpvp_size = vattr.va_size & -DUMP_OFFSET;
	mutex_exit(&dump_lock);
	return (0);
}
