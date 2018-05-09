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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

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
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <sys/clock_impl.h>
#include <sys/hold_page.h>

#include <bzip2/bzlib.h>

#define	ONE_GIG	(1024 * 1024 * 1024UL)

/*
 * Crash dump time is dominated by disk write time.  To reduce this,
 * the stronger compression method bzip2 is applied to reduce the dump
 * size and hence reduce I/O time.  However, bzip2 is much more
 * computationally expensive than the existing lzjb algorithm, so to
 * avoid increasing compression time, CPUs that are otherwise idle
 * during panic are employed to parallelize the compression task.
 * Many helper CPUs are needed to prevent bzip2 from being a
 * bottleneck, and on systems with too few CPUs, the lzjb algorithm is
 * parallelized instead. Lastly, I/O and compression are performed by
 * different CPUs, and are hence overlapped in time, unlike the older
 * serial code.
 *
 * Another important consideration is the speed of the dump
 * device. Faster disks need less CPUs in order to benefit from
 * parallel lzjb versus parallel bzip2. Therefore, the CPU count
 * threshold for switching from parallel lzjb to paralled bzip2 is
 * elevated for faster disks. The dump device speed is adduced from
 * the setting for dumpbuf.iosize, see dump_update_clevel.
 */

/*
 * exported vars
 */
kmutex_t	dump_lock;		/* lock for dump configuration */
dumphdr_t	*dumphdr;		/* dump header */
int		dump_conflags = DUMP_KERNEL; /* dump configuration flags */
vnode_t		*dumpvp;		/* dump device vnode pointer */
u_offset_t	dumpvp_size;		/* size of dump device, in bytes */
char		*dumppath;		/* pathname of dump device */
int		dump_timeout = 120;	/* timeout for dumping pages */
int		dump_timeleft;		/* portion of dump_timeout remaining */
int		dump_ioerr;		/* dump i/o error */
int		dump_check_used;	/* enable check for used pages */
char	    *dump_stack_scratch; /* scratch area for saving stack summary */

/*
 * Tunables for dump compression and parallelism. These can be set via
 * /etc/system.
 *
 * dump_ncpu_low	number of helpers for parallel lzjb
 *	This is also the minimum configuration.
 *
 * dump_bzip2_level	bzip2 compression level: 1-9
 *	Higher numbers give greater compression, but take more memory
 *	and time. Memory used per helper is ~(dump_bzip2_level * 1MB).
 *
 * dump_plat_mincpu	the cross-over limit for using bzip2 (per platform):
 *	if dump_plat_mincpu == 0, then always do single threaded dump
 *	if ncpu >= dump_plat_mincpu then try to use bzip2
 *
 * dump_metrics_on	if set, metrics are collected in the kernel, passed
 *	to savecore via the dump file, and recorded by savecore in
 *	METRICS.txt.
 */
uint_t dump_ncpu_low = 4;	/* minimum config for parallel lzjb */
uint_t dump_bzip2_level = 1;	/* bzip2 level (1-9) */

/* Use dump_plat_mincpu_default unless this variable is set by /etc/system */
#define	MINCPU_NOT_SET	((uint_t)-1)
uint_t dump_plat_mincpu = MINCPU_NOT_SET;

/* tunables for pre-reserved heap */
uint_t dump_kmem_permap = 1024;
uint_t dump_kmem_pages = 0;

/* Define multiple buffers per helper to avoid stalling */
#define	NCBUF_PER_HELPER	2
#define	NCMAP_PER_HELPER	4

/* minimum number of helpers configured */
#define	MINHELPERS	(dump_ncpu_low)
#define	MINCBUFS	(MINHELPERS * NCBUF_PER_HELPER)

/*
 * Define constant parameters.
 *
 * CBUF_SIZE		size of an output buffer
 *
 * CBUF_MAPSIZE		size of virtual range for mapping pages
 *
 * CBUF_MAPNP		size of virtual range in pages
 *
 */
#define	DUMP_1KB	((size_t)1 << 10)
#define	DUMP_1MB	((size_t)1 << 20)
#define	CBUF_SIZE	((size_t)1 << 17)
#define	CBUF_MAPSHIFT	(22)
#define	CBUF_MAPSIZE	((size_t)1 << CBUF_MAPSHIFT)
#define	CBUF_MAPNP	((size_t)1 << (CBUF_MAPSHIFT - PAGESHIFT))

/*
 * Compression metrics are accumulated nano-second subtotals. The
 * results are normalized by the number of pages dumped. A report is
 * generated when dumpsys() completes and is saved in the dump image
 * after the trailing dump header.
 *
 * Metrics are always collected. Set the variable dump_metrics_on to
 * cause metrics to be saved in the crash file, where savecore will
 * save it in the file METRICS.txt.
 */
#define	PERPAGES \
	PERPAGE(bitmap) PERPAGE(map) PERPAGE(unmap) \
	PERPAGE(copy) PERPAGE(compress) \
	PERPAGE(write) \
	PERPAGE(inwait) PERPAGE(outwait)

typedef struct perpage {
#define	PERPAGE(x) hrtime_t x;
	PERPAGES
#undef PERPAGE
} perpage_t;

/*
 * This macro controls the code generation for collecting dump
 * performance information. By default, the code is generated, but
 * automatic saving of the information is disabled. If dump_metrics_on
 * is set to 1, the timing information is passed to savecore via the
 * crash file, where it is appended to the file dump-dir/METRICS.txt.
 */
#define	COLLECT_METRICS

#ifdef COLLECT_METRICS
uint_t dump_metrics_on = 0;	/* set to 1 to enable recording metrics */

#define	HRSTART(v, m)		v##ts.m = gethrtime()
#define	HRSTOP(v, m)		v.m += gethrtime() - v##ts.m
#define	HRBEGIN(v, m, s)	v##ts.m = gethrtime(); v.size += s
#define	HREND(v, m)		v.m += gethrtime() - v##ts.m
#define	HRNORM(v, m, n)		v.m /= (n)

#else
#define	HRSTART(v, m)
#define	HRSTOP(v, m)
#define	HRBEGIN(v, m, s)
#define	HREND(v, m)
#define	HRNORM(v, m, n)
#endif	/* COLLECT_METRICS */

/*
 * Buffers for copying and compressing memory pages.
 *
 * cbuf_t buffer controllers: used for both input and output.
 *
 * The buffer state indicates how it is being used:
 *
 * CBUF_FREEMAP: CBUF_MAPSIZE virtual address range is available for
 * mapping input pages.
 *
 * CBUF_INREADY: input pages are mapped and ready for compression by a
 * helper.
 *
 * CBUF_USEDMAP: mapping has been consumed by a helper. Needs unmap.
 *
 * CBUF_FREEBUF: CBUF_SIZE output buffer, which is available.
 *
 * CBUF_WRITE: CBUF_SIZE block of compressed pages from a helper,
 * ready to write out.
 *
 * CBUF_ERRMSG: CBUF_SIZE block of error messages from a helper
 * (reports UE errors.)
 */

typedef enum cbufstate {
	CBUF_FREEMAP,
	CBUF_INREADY,
	CBUF_USEDMAP,
	CBUF_FREEBUF,
	CBUF_WRITE,
	CBUF_ERRMSG
} cbufstate_t;

typedef struct cbuf cbuf_t;

struct cbuf {
	cbuf_t *next;			/* next in list */
	cbufstate_t state;		/* processing state */
	size_t used;			/* amount used */
	size_t size;			/* mem size */
	char *buf;			/* kmem or vmem */
	pgcnt_t pagenum;		/* index to pfn map */
	pgcnt_t bitnum;			/* first set bitnum */
	pfn_t pfn;			/* first pfn in mapped range */
	int off;			/* byte offset to first pfn */
};

static char dump_osimage_uuid[36 + 1];

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')
#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))

/*
 * cqueue_t queues: a uni-directional channel for communication
 * from the master to helper tasks or vice-versa using put and
 * get primitives. Both mappings and data buffers are passed via
 * queues. Producers close a queue when done. The number of
 * active producers is reference counted so the consumer can
 * detect end of data. Concurrent access is mediated by atomic
 * operations for panic dump, or mutex/cv for live dump.
 *
 * There a four queues, used as follows:
 *
 * Queue		Dataflow		NewState
 * --------------------------------------------------
 * mainq		master -> master	FREEMAP
 * master has initialized or unmapped an input buffer
 * --------------------------------------------------
 * helperq		master -> helper	INREADY
 * master has mapped input for use by helper
 * --------------------------------------------------
 * mainq		master <- helper	USEDMAP
 * helper is done with input
 * --------------------------------------------------
 * freebufq		master -> helper	FREEBUF
 * master has initialized or written an output buffer
 * --------------------------------------------------
 * mainq		master <- helper	WRITE
 * block of compressed pages from a helper
 * --------------------------------------------------
 * mainq		master <- helper	ERRMSG
 * error messages from a helper (memory error case)
 * --------------------------------------------------
 * writerq		master <- master	WRITE
 * non-blocking queue of blocks to write
 * --------------------------------------------------
 */
typedef struct cqueue {
	cbuf_t *volatile first;		/* first in list */
	cbuf_t *last;			/* last in list */
	hrtime_t ts;			/* timestamp */
	hrtime_t empty;			/* total time empty */
	kmutex_t mutex;			/* live state lock */
	kcondvar_t cv;			/* live wait var */
	lock_t spinlock;		/* panic mode spin lock */
	volatile uint_t open;		/* producer ref count */
} cqueue_t;

/*
 * Convenience macros for using the cqueue functions
 * Note that the caller must have defined "dumpsync_t *ds"
 */
#define	CQ_IS_EMPTY(q)					\
	(ds->q.first == NULL)

#define	CQ_OPEN(q)					\
	atomic_inc_uint(&ds->q.open)

#define	CQ_CLOSE(q)					\
	dumpsys_close_cq(&ds->q, ds->live)

#define	CQ_PUT(q, cp, st)				\
	dumpsys_put_cq(&ds->q, cp, st, ds->live)

#define	CQ_GET(q)					\
	dumpsys_get_cq(&ds->q, ds->live)

/*
 * Dynamic state when dumpsys() is running.
 */
typedef struct dumpsync {
	pgcnt_t npages;			/* subtotal of pages dumped */
	pgcnt_t pages_mapped;		/* subtotal of pages mapped */
	pgcnt_t pages_used;		/* subtotal of pages used per map */
	size_t nwrite;			/* subtotal of bytes written */
	uint_t live;			/* running live dump */
	uint_t neednl;			/* will need to print a newline */
	uint_t percent;			/* dump progress */
	uint_t percent_done;		/* dump progress reported */
	int sec_done;			/* dump progress last report time */
	cqueue_t freebufq;		/* free kmem bufs for writing */
	cqueue_t mainq;			/* input for main task */
	cqueue_t helperq;		/* input for helpers */
	cqueue_t writerq;		/* input for writer */
	hrtime_t start;			/* start time */
	hrtime_t elapsed;		/* elapsed time when completed */
	hrtime_t iotime;		/* time spent writing nwrite bytes */
	hrtime_t iowait;		/* time spent waiting for output */
	hrtime_t iowaitts;		/* iowait timestamp */
	perpage_t perpage;		/* metrics */
	perpage_t perpagets;
	int dumpcpu;			/* master cpu */
} dumpsync_t;

static dumpsync_t dumpsync;		/* synchronization vars */

/*
 * helper_t helpers: contains the context for a stream. CPUs run in
 * parallel at dump time; each CPU creates a single stream of
 * compression data.  Stream data is divided into CBUF_SIZE blocks.
 * The blocks are written in order within a stream. But, blocks from
 * multiple streams can be interleaved. Each stream is identified by a
 * unique tag.
 */
typedef struct helper {
	int helper;			/* bound helper id */
	int tag;			/* compression stream tag */
	perpage_t perpage;		/* per page metrics */
	perpage_t perpagets;		/* per page metrics (timestamps) */
	taskqid_t taskqid;		/* live dump task ptr */
	int in, out;			/* buffer offsets */
	cbuf_t *cpin, *cpout, *cperr;	/* cbuf objects in process */
	dumpsync_t *ds;			/* pointer to sync vars */
	size_t used;			/* counts input consumed */
	char *page;			/* buffer for page copy */
	char *lzbuf;			/* lzjb output */
	bz_stream bzstream;		/* bzip2 state */
} helper_t;

#define	MAINHELPER	(-1)		/* helper is also the main task */
#define	FREEHELPER	(-2)		/* unbound helper */
#define	DONEHELPER	(-3)		/* helper finished */

/*
 * configuration vars for dumpsys
 */
typedef struct dumpcfg {
	int	threshold;	/* ncpu threshold for bzip2 */
	int	nhelper;	/* number of helpers */
	int	nhelper_used;	/* actual number of helpers used */
	int	ncmap;		/* number VA pages for compression */
	int	ncbuf;		/* number of bufs for compression */
	int	ncbuf_used;	/* number of bufs in use */
	uint_t	clevel;		/* dump compression level */
	helper_t *helper;	/* array of helpers */
	cbuf_t	*cmap;		/* array of input (map) buffers */
	cbuf_t	*cbuf;		/* array of output  buffers */
	ulong_t	*helpermap;	/* set of dumpsys helper CPU ids */
	ulong_t	*bitmap;	/* bitmap for marking pages to dump */
	ulong_t	*rbitmap;	/* bitmap for used CBUF_MAPSIZE ranges */
	pgcnt_t	bitmapsize;	/* size of bitmap */
	pgcnt_t	rbitmapsize;	/* size of bitmap for ranges */
	pgcnt_t found4m;	/* number ranges allocated by dump */
	pgcnt_t foundsm;	/* number small pages allocated by dump */
	pid_t	*pids;		/* list of process IDs at dump time */
	size_t	maxsize;	/* memory size needed at dump time */
	size_t	maxvmsize;	/* size of reserved VM */
	char	*maxvm;		/* reserved VM for spare pages */
	lock_t	helper_lock;	/* protect helper state */
	char	helpers_wanted;	/* flag to enable parallelism */
} dumpcfg_t;

static dumpcfg_t dumpcfg;	/* config vars */

/*
 * The dump I/O buffer.
 *
 * There is one I/O buffer used by dumpvp_write and dumvp_flush. It is
 * sized according to the optimum device transfer speed.
 */
typedef struct dumpbuf {
	vnode_t	*cdev_vp;	/* VCHR open of the dump device */
	len_t	vp_limit;	/* maximum write offset */
	offset_t vp_off;	/* current dump device offset */
	char	*cur;		/* dump write pointer */
	char	*start;		/* dump buffer address */
	char	*end;		/* dump buffer end */
	size_t	size;		/* size of dumpbuf in bytes */
	size_t	iosize;		/* best transfer size for device */
} dumpbuf_t;

dumpbuf_t dumpbuf;		/* I/O buffer */

/*
 * The dump I/O buffer must be at least one page, at most xfer_size
 * bytes, and should scale with physmem in between.  The transfer size
 * passed in will either represent a global default (maxphys) or the
 * best size for the device.  The size of the dumpbuf I/O buffer is
 * limited by dumpbuf_limit (8MB by default) because the dump
 * performance saturates beyond a certain size.  The default is to
 * select 1/4096 of the memory.
 */
static int	dumpbuf_fraction = 12;	/* memory size scale factor */
static size_t	dumpbuf_limit = 8 * DUMP_1MB;	/* max I/O buf size */

static size_t
dumpbuf_iosize(size_t xfer_size)
{
	size_t iosize = ptob(physmem >> dumpbuf_fraction);

	if (iosize < PAGESIZE)
		iosize = PAGESIZE;
	else if (iosize > xfer_size)
		iosize = xfer_size;
	if (iosize > dumpbuf_limit)
		iosize = dumpbuf_limit;
	return (iosize & PAGEMASK);
}

/*
 * resize the I/O buffer
 */
static void
dumpbuf_resize(void)
{
	char *old_buf = dumpbuf.start;
	size_t old_size = dumpbuf.size;
	char *new_buf;
	size_t new_size;

	ASSERT(MUTEX_HELD(&dump_lock));

	new_size = dumpbuf_iosize(MAX(dumpbuf.iosize, maxphys));
	if (new_size <= old_size)
		return; /* no need to reallocate buffer */

	new_buf = kmem_alloc(new_size, KM_SLEEP);
	dumpbuf.size = new_size;
	dumpbuf.start = new_buf;
	dumpbuf.end = new_buf + new_size;
	kmem_free(old_buf, old_size);
}

/*
 * dump_update_clevel is called when dumpadm configures the dump device.
 * 	Calculate number of helpers and buffers.
 * 	Allocate the minimum configuration for now.
 *
 * When the dump file is configured we reserve a minimum amount of
 * memory for use at crash time. But we reserve VA for all the memory
 * we really want in order to do the fastest dump possible. The VA is
 * backed by pages not being dumped, according to the bitmap. If
 * there is insufficient spare memory, however, we fall back to the
 * minimum.
 *
 * Live dump (savecore -L) always uses the minimum config.
 *
 * clevel 0 is single threaded lzjb
 * clevel 1 is parallel lzjb
 * clevel 2 is parallel bzip2
 *
 * The ncpu threshold is selected with dump_plat_mincpu.
 * On OPL, set_platform_defaults() overrides the sun4u setting.
 * The actual values are defined via DUMP_PLAT_*_MINCPU macros.
 *
 * Architecture		Threshold	Algorithm
 * sun4u       		<  51		parallel lzjb
 * sun4u       		>= 51		parallel bzip2(*)
 * sun4u OPL   		<  8		parallel lzjb
 * sun4u OPL   		>= 8		parallel bzip2(*)
 * sun4v       		<  128		parallel lzjb
 * sun4v       		>= 128		parallel bzip2(*)
 * x86			< 11		parallel lzjb
 * x86			>= 11		parallel bzip2(*)
 * 32-bit      		N/A		single-threaded lzjb
 *
 * (*) bzip2 is only chosen if there is sufficient available
 * memory for buffers at dump time. See dumpsys_get_maxmem().
 *
 * Faster dump devices have larger I/O buffers. The threshold value is
 * increased according to the size of the dump I/O buffer, because
 * parallel lzjb performs better with faster disks. For buffers >= 1MB
 * the threshold is 3X; for buffers >= 256K threshold is 2X.
 *
 * For parallel dumps, the number of helpers is ncpu-1. The CPU
 * running panic runs the main task. For single-threaded dumps, the
 * panic CPU does lzjb compression (it is tagged as MAINHELPER.)
 *
 * Need multiple buffers per helper so that they do not block waiting
 * for the main task.
 *				parallel	single-threaded
 * Number of output buffers:	nhelper*2		1
 * Number of mapping buffers:	nhelper*4		1
 *
 */
static void
dump_update_clevel()
{
	int tag;
	size_t bz2size;
	helper_t *hp, *hpend;
	cbuf_t *cp, *cpend;
	dumpcfg_t *old = &dumpcfg;
	dumpcfg_t newcfg = *old;
	dumpcfg_t *new = &newcfg;

	ASSERT(MUTEX_HELD(&dump_lock));

	/*
	 * Free the previously allocated bufs and VM.
	 */
	if (old->helper != NULL) {

		/* helpers */
		hpend = &old->helper[old->nhelper];
		for (hp = old->helper; hp != hpend; hp++) {
			if (hp->lzbuf != NULL)
				kmem_free(hp->lzbuf, PAGESIZE);
			if (hp->page != NULL)
				kmem_free(hp->page, PAGESIZE);
		}
		kmem_free(old->helper, old->nhelper * sizeof (helper_t));

		/* VM space for mapping pages */
		cpend = &old->cmap[old->ncmap];
		for (cp = old->cmap; cp != cpend; cp++)
			vmem_xfree(heap_arena, cp->buf, CBUF_MAPSIZE);
		kmem_free(old->cmap, old->ncmap * sizeof (cbuf_t));

		/* output bufs */
		cpend = &old->cbuf[old->ncbuf];
		for (cp = old->cbuf; cp != cpend; cp++)
			if (cp->buf != NULL)
				kmem_free(cp->buf, cp->size);
		kmem_free(old->cbuf, old->ncbuf * sizeof (cbuf_t));

		/* reserved VM for dumpsys_get_maxmem */
		if (old->maxvmsize > 0)
			vmem_xfree(heap_arena, old->maxvm, old->maxvmsize);
	}

	/*
	 * Allocate memory and VM.
	 * One CPU runs dumpsys, the rest are helpers.
	 */
	new->nhelper = ncpus - 1;
	if (new->nhelper < 1)
		new->nhelper = 1;

	if (new->nhelper > DUMP_MAX_NHELPER)
		new->nhelper = DUMP_MAX_NHELPER;

	/* use platform default, unless /etc/system overrides */
	if (dump_plat_mincpu == MINCPU_NOT_SET)
		dump_plat_mincpu = dump_plat_mincpu_default;

	/* increase threshold for faster disks */
	new->threshold = dump_plat_mincpu;
	if (dumpbuf.iosize >= DUMP_1MB)
		new->threshold *= 3;
	else if (dumpbuf.iosize >= (256 * DUMP_1KB))
		new->threshold *= 2;

	/* figure compression level based upon the computed threshold. */
	if (dump_plat_mincpu == 0 || new->nhelper < 2) {
		new->clevel = 0;
		new->nhelper = 1;
	} else if ((new->nhelper + 1) >= new->threshold) {
		new->clevel = DUMP_CLEVEL_BZIP2;
	} else {
		new->clevel = DUMP_CLEVEL_LZJB;
	}

	if (new->clevel == 0) {
		new->ncbuf = 1;
		new->ncmap = 1;
	} else {
		new->ncbuf = NCBUF_PER_HELPER * new->nhelper;
		new->ncmap = NCMAP_PER_HELPER * new->nhelper;
	}

	/*
	 * Allocate new data structures and buffers for MINHELPERS,
	 * and also figure the max desired size.
	 */
	bz2size = BZ2_bzCompressInitSize(dump_bzip2_level);
	new->maxsize = 0;
	new->maxvmsize = 0;
	new->maxvm = NULL;
	tag = 1;
	new->helper = kmem_zalloc(new->nhelper * sizeof (helper_t), KM_SLEEP);
	hpend = &new->helper[new->nhelper];
	for (hp = new->helper; hp != hpend; hp++) {
		hp->tag = tag++;
		if (hp < &new->helper[MINHELPERS]) {
			hp->lzbuf = kmem_alloc(PAGESIZE, KM_SLEEP);
			hp->page = kmem_alloc(PAGESIZE, KM_SLEEP);
		} else if (new->clevel < DUMP_CLEVEL_BZIP2) {
			new->maxsize += 2 * PAGESIZE;
		} else {
			new->maxsize += PAGESIZE;
		}
		if (new->clevel >= DUMP_CLEVEL_BZIP2)
			new->maxsize += bz2size;
	}

	new->cbuf = kmem_zalloc(new->ncbuf * sizeof (cbuf_t), KM_SLEEP);
	cpend = &new->cbuf[new->ncbuf];
	for (cp = new->cbuf; cp != cpend; cp++) {
		cp->state = CBUF_FREEBUF;
		cp->size = CBUF_SIZE;
		if (cp < &new->cbuf[MINCBUFS])
			cp->buf = kmem_alloc(cp->size, KM_SLEEP);
		else
			new->maxsize += cp->size;
	}

	new->cmap = kmem_zalloc(new->ncmap * sizeof (cbuf_t), KM_SLEEP);
	cpend = &new->cmap[new->ncmap];
	for (cp = new->cmap; cp != cpend; cp++) {
		cp->state = CBUF_FREEMAP;
		cp->size = CBUF_MAPSIZE;
		cp->buf = vmem_xalloc(heap_arena, CBUF_MAPSIZE, CBUF_MAPSIZE,
		    0, 0, NULL, NULL, VM_SLEEP);
	}

	/* reserve VA to be backed with spare pages at crash time */
	if (new->maxsize > 0) {
		new->maxsize = P2ROUNDUP(new->maxsize, PAGESIZE);
		new->maxvmsize = P2ROUNDUP(new->maxsize, CBUF_MAPSIZE);
		new->maxvm = vmem_xalloc(heap_arena, new->maxvmsize,
		    CBUF_MAPSIZE, 0, 0, NULL, NULL, VM_SLEEP);
	}

	/*
	 * Reserve memory for kmem allocation calls made during crash dump.  The
	 * hat layer allocates memory for each mapping created, and the I/O path
	 * allocates buffers and data structs.
	 *
	 * On larger systems, we easily exceed the lower amount, so we need some
	 * more space; the cut-over point is relatively arbitrary.  If we run
	 * out, the only impact is that kmem state in the dump becomes
	 * inconsistent.
	 */

	if (dump_kmem_pages == 0) {
		if (physmem > (16 * ONE_GIG) / PAGESIZE)
			dump_kmem_pages = 20;
		else
			dump_kmem_pages = 8;
	}

	kmem_dump_init((new->ncmap * dump_kmem_permap) +
	    (dump_kmem_pages * PAGESIZE));

	/* set new config pointers */
	*old = *new;
}

/*
 * Define a struct memlist walker to optimize bitnum to pfn
 * lookup. The walker maintains the state of the list traversal.
 */
typedef struct dumpmlw {
	struct memlist	*mp;		/* current memlist */
	pgcnt_t		basenum;	/* bitnum base offset */
	pgcnt_t		mppages;	/* current memlist size */
	pgcnt_t		mpleft;		/* size to end of current memlist */
	pfn_t		mpaddr;		/* first pfn in memlist */
} dumpmlw_t;

/* initialize the walker */
static inline void
dump_init_memlist_walker(dumpmlw_t *pw)
{
	pw->mp = phys_install;
	pw->basenum = 0;
	pw->mppages = pw->mp->ml_size >> PAGESHIFT;
	pw->mpleft = pw->mppages;
	pw->mpaddr = pw->mp->ml_address >> PAGESHIFT;
}

/*
 * Lookup pfn given bitnum. The memlist can be quite long on some
 * systems (e.g.: one per board). To optimize sequential lookups, the
 * caller initializes and presents a memlist walker.
 */
static pfn_t
dump_bitnum_to_pfn(pgcnt_t bitnum, dumpmlw_t *pw)
{
	bitnum -= pw->basenum;
	while (pw->mp != NULL) {
		if (bitnum < pw->mppages) {
			pw->mpleft = pw->mppages - bitnum;
			return (pw->mpaddr + bitnum);
		}
		bitnum -= pw->mppages;
		pw->basenum += pw->mppages;
		pw->mp = pw->mp->ml_next;
		if (pw->mp != NULL) {
			pw->mppages = pw->mp->ml_size >> PAGESHIFT;
			pw->mpleft = pw->mppages;
			pw->mpaddr = pw->mp->ml_address >> PAGESHIFT;
		}
	}
	return (PFN_INVALID);
}

static pgcnt_t
dump_pfn_to_bitnum(pfn_t pfn)
{
	struct memlist *mp;
	pgcnt_t bitnum = 0;

	for (mp = phys_install; mp != NULL; mp = mp->ml_next) {
		if (pfn >= (mp->ml_address >> PAGESHIFT) &&
		    pfn < ((mp->ml_address + mp->ml_size) >> PAGESHIFT))
			return (bitnum + pfn - (mp->ml_address >> PAGESHIFT));
		bitnum += mp->ml_size >> PAGESHIFT;
	}
	return ((pgcnt_t)-1);
}

/*
 * Set/test bitmap for a CBUF_MAPSIZE range which includes pfn. The
 * mapping of pfn to range index is imperfect because pfn and bitnum
 * do not have the same phase. To make sure a CBUF_MAPSIZE range is
 * covered, call this for both ends:
 *	dump_set_used(base)
 *	dump_set_used(base+CBUF_MAPNP-1)
 *
 * This is used during a panic dump to mark pages allocated by
 * dumpsys_get_maxmem(). The macro IS_DUMP_PAGE(pp) is used by
 * page_get_mnode_freelist() to make sure pages used by dump are never
 * allocated.
 */
#define	CBUF_MAPP2R(pfn)	((pfn) >> (CBUF_MAPSHIFT - PAGESHIFT))

static void
dump_set_used(pfn_t pfn)
{

	pgcnt_t bitnum, rbitnum;

	bitnum = dump_pfn_to_bitnum(pfn);
	ASSERT(bitnum != (pgcnt_t)-1);

	rbitnum = CBUF_MAPP2R(bitnum);
	ASSERT(rbitnum < dumpcfg.rbitmapsize);

	BT_SET(dumpcfg.rbitmap, rbitnum);
}

int
dump_test_used(pfn_t pfn)
{
	pgcnt_t bitnum, rbitnum;

	bitnum = dump_pfn_to_bitnum(pfn);
	ASSERT(bitnum != (pgcnt_t)-1);

	rbitnum = CBUF_MAPP2R(bitnum);
	ASSERT(rbitnum < dumpcfg.rbitmapsize);

	return (BT_TEST(dumpcfg.rbitmap, rbitnum));
}

/*
 * dumpbzalloc and dumpbzfree are callbacks from the bzip2 library.
 * dumpsys_get_maxmem() uses them for BZ2_bzCompressInit().
 */
static void *
dumpbzalloc(void *opaque, int items, int size)
{
	size_t *sz;
	char *ret;

	ASSERT(opaque != NULL);
	sz = opaque;
	ret = dumpcfg.maxvm + *sz;
	*sz += items * size;
	*sz = P2ROUNDUP(*sz, BZ2_BZALLOC_ALIGN);
	ASSERT(*sz <= dumpcfg.maxvmsize);
	return (ret);
}

/*ARGSUSED*/
static void
dumpbzfree(void *opaque, void *addr)
{
}

/*
 * Perform additional checks on the page to see if we can really use
 * it. The kernel (kas) pages are always set in the bitmap. However,
 * boot memory pages (prom_ppages or P_BOOTPAGES) are not in the
 * bitmap. So we check for them.
 */
static inline int
dump_pfn_check(pfn_t pfn)
{
	page_t *pp = page_numtopp_nolock(pfn);
	if (pp == NULL || pp->p_pagenum != pfn ||
#if defined(__sparc)
	    pp->p_vnode == &promvp ||
#else
	    PP_ISBOOTPAGES(pp) ||
#endif
	    pp->p_toxic != 0)
		return (0);
	return (1);
}

/*
 * Check a range to see if all contained pages are available and
 * return non-zero if the range can be used.
 */
static inline int
dump_range_check(pgcnt_t start, pgcnt_t end, pfn_t pfn)
{
	for (; start < end; start++, pfn++) {
		if (BT_TEST(dumpcfg.bitmap, start))
			return (0);
		if (!dump_pfn_check(pfn))
			return (0);
	}
	return (1);
}

/*
 * dumpsys_get_maxmem() is called during panic. Find unused ranges
 * and use them for buffers. If we find enough memory switch to
 * parallel bzip2, otherwise use parallel lzjb.
 *
 * It searches the dump bitmap in 2 passes. The first time it looks
 * for CBUF_MAPSIZE ranges. On the second pass it uses small pages.
 */
static void
dumpsys_get_maxmem()
{
	dumpcfg_t *cfg = &dumpcfg;
	cbuf_t *endcp = &cfg->cbuf[cfg->ncbuf];
	helper_t *endhp = &cfg->helper[cfg->nhelper];
	pgcnt_t bitnum, end;
	size_t sz, endsz, bz2size;
	pfn_t pfn, off;
	cbuf_t *cp;
	helper_t *hp, *ohp;
	dumpmlw_t mlw;
	int k;

	/*
	 * Setting dump_plat_mincpu to 0 at any time forces a serial
	 * dump.
	 */
	if (dump_plat_mincpu == 0) {
		cfg->clevel = 0;
		return;
	}

	/*
	 * There may be no point in looking for spare memory. If
	 * dumping all memory, then none is spare. If doing a serial
	 * dump, then already have buffers.
	 */
	if (cfg->maxsize == 0 || cfg->clevel < DUMP_CLEVEL_LZJB ||
	    (dump_conflags & DUMP_ALL) != 0) {
		if (cfg->clevel > DUMP_CLEVEL_LZJB)
			cfg->clevel = DUMP_CLEVEL_LZJB;
		return;
	}

	sz = 0;
	cfg->found4m = 0;
	cfg->foundsm = 0;

	/* bitmap of ranges used to estimate which pfns are being used */
	bzero(dumpcfg.rbitmap, BT_SIZEOFMAP(dumpcfg.rbitmapsize));

	/* find ranges that are not being dumped to use for buffers */
	dump_init_memlist_walker(&mlw);
	for (bitnum = 0; bitnum < dumpcfg.bitmapsize; bitnum = end) {
		dump_timeleft = dump_timeout;
		end = bitnum + CBUF_MAPNP;
		pfn = dump_bitnum_to_pfn(bitnum, &mlw);
		ASSERT(pfn != PFN_INVALID);

		/* skip partial range at end of mem segment */
		if (mlw.mpleft < CBUF_MAPNP) {
			end = bitnum + mlw.mpleft;
			continue;
		}

		/* skip non aligned pages */
		off = P2PHASE(pfn, CBUF_MAPNP);
		if (off != 0) {
			end -= off;
			continue;
		}

		if (!dump_range_check(bitnum, end, pfn))
			continue;

		ASSERT((sz + CBUF_MAPSIZE) <= cfg->maxvmsize);
		hat_devload(kas.a_hat, cfg->maxvm + sz, CBUF_MAPSIZE, pfn,
		    PROT_READ | PROT_WRITE, HAT_LOAD_NOCONSIST);
		sz += CBUF_MAPSIZE;
		cfg->found4m++;

		/* set the bitmap for both ends to be sure to cover the range */
		dump_set_used(pfn);
		dump_set_used(pfn + CBUF_MAPNP - 1);

		if (sz >= cfg->maxsize)
			goto foundmax;
	}

	/* Add small pages if we can't find enough large pages. */
	dump_init_memlist_walker(&mlw);
	for (bitnum = 0; bitnum < dumpcfg.bitmapsize; bitnum = end) {
		dump_timeleft = dump_timeout;
		end = bitnum + CBUF_MAPNP;
		pfn = dump_bitnum_to_pfn(bitnum, &mlw);
		ASSERT(pfn != PFN_INVALID);

		/* Find any non-aligned pages at start and end of segment. */
		off = P2PHASE(pfn, CBUF_MAPNP);
		if (mlw.mpleft < CBUF_MAPNP) {
			end = bitnum + mlw.mpleft;
		} else if (off != 0) {
			end -= off;
		} else if (cfg->found4m && dump_test_used(pfn)) {
			continue;
		}

		for (; bitnum < end; bitnum++, pfn++) {
			dump_timeleft = dump_timeout;
			if (BT_TEST(dumpcfg.bitmap, bitnum))
				continue;
			if (!dump_pfn_check(pfn))
				continue;
			ASSERT((sz + PAGESIZE) <= cfg->maxvmsize);
			hat_devload(kas.a_hat, cfg->maxvm + sz, PAGESIZE, pfn,
			    PROT_READ | PROT_WRITE, HAT_LOAD_NOCONSIST);
			sz += PAGESIZE;
			cfg->foundsm++;
			dump_set_used(pfn);
			if (sz >= cfg->maxsize)
				goto foundmax;
		}
	}

	/* Fall back to lzjb if we did not get enough memory for bzip2. */
	endsz = (cfg->maxsize * cfg->threshold) / cfg->nhelper;
	if (sz < endsz) {
		cfg->clevel = DUMP_CLEVEL_LZJB;
	}

	/* Allocate memory for as many helpers as we can. */
foundmax:

	/* Byte offsets into memory found and mapped above */
	endsz = sz;
	sz = 0;

	/* Set the size for bzip2 state. Only bzip2 needs it. */
	bz2size = BZ2_bzCompressInitSize(dump_bzip2_level);

	/* Skip the preallocate output buffers. */
	cp = &cfg->cbuf[MINCBUFS];

	/* Use this to move memory up from the preallocated helpers. */
	ohp = cfg->helper;

	/* Loop over all helpers and allocate memory. */
	for (hp = cfg->helper; hp < endhp; hp++) {

		/* Skip preallocated helpers by checking hp->page. */
		if (hp->page == NULL) {
			if (cfg->clevel <= DUMP_CLEVEL_LZJB) {
				/* lzjb needs 2 1-page buffers */
				if ((sz + (2 * PAGESIZE)) > endsz)
					break;
				hp->page = cfg->maxvm + sz;
				sz += PAGESIZE;
				hp->lzbuf = cfg->maxvm + sz;
				sz += PAGESIZE;

			} else if (ohp->lzbuf != NULL) {
				/* re-use the preallocted lzjb page for bzip2 */
				hp->page = ohp->lzbuf;
				ohp->lzbuf = NULL;
				++ohp;

			} else {
				/* bzip2 needs a 1-page buffer */
				if ((sz + PAGESIZE) > endsz)
					break;
				hp->page = cfg->maxvm + sz;
				sz += PAGESIZE;
			}
		}

		/*
		 * Add output buffers per helper. The number of
		 * buffers per helper is determined by the ratio of
		 * ncbuf to nhelper.
		 */
		for (k = 0; cp < endcp && (sz + CBUF_SIZE) <= endsz &&
		    k < NCBUF_PER_HELPER; k++) {
			cp->state = CBUF_FREEBUF;
			cp->size = CBUF_SIZE;
			cp->buf = cfg->maxvm + sz;
			sz += CBUF_SIZE;
			++cp;
		}

		/*
		 * bzip2 needs compression state. Use the dumpbzalloc
		 * and dumpbzfree callbacks to allocate the memory.
		 * bzip2 does allocation only at init time.
		 */
		if (cfg->clevel >= DUMP_CLEVEL_BZIP2) {
			if ((sz + bz2size) > endsz) {
				hp->page = NULL;
				break;
			} else {
				hp->bzstream.opaque = &sz;
				hp->bzstream.bzalloc = dumpbzalloc;
				hp->bzstream.bzfree = dumpbzfree;
				(void) BZ2_bzCompressInit(&hp->bzstream,
				    dump_bzip2_level, 0, 0);
				hp->bzstream.opaque = NULL;
			}
		}
	}

	/* Finish allocating output buffers */
	for (; cp < endcp && (sz + CBUF_SIZE) <= endsz; cp++) {
		cp->state = CBUF_FREEBUF;
		cp->size = CBUF_SIZE;
		cp->buf = cfg->maxvm + sz;
		sz += CBUF_SIZE;
	}

	/* Enable IS_DUMP_PAGE macro, which checks for pages we took. */
	if (cfg->found4m || cfg->foundsm)
		dump_check_used = 1;

	ASSERT(sz <= endsz);
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
		dumpbuf.size = dumpbuf_iosize(maxphys);
		dumpbuf.start = kmem_alloc(dumpbuf.size, KM_SLEEP);
		dumpbuf.end = dumpbuf.start + dumpbuf.size;
		dumpcfg.pids = kmem_alloc(v.v_proc * sizeof (pid_t), KM_SLEEP);
		dumpcfg.helpermap = kmem_zalloc(BT_SIZEOFMAP(NCPU), KM_SLEEP);
		LOCK_INIT_HELD(&dumpcfg.helper_lock);
		dump_stack_scratch = kmem_alloc(STACK_BUF_SIZE, KM_SLEEP);
		(void) strncpy(dumphdr->dump_uuid, dump_get_uuid(),
		    sizeof (dumphdr->dump_uuid));
	}

	npages = num_phys_pages();

	if (dumpcfg.bitmapsize != npages) {
		size_t rlen = CBUF_MAPP2R(P2ROUNDUP(npages, CBUF_MAPNP));
		void *map = kmem_alloc(BT_SIZEOFMAP(npages), KM_SLEEP);
		void *rmap = kmem_alloc(BT_SIZEOFMAP(rlen), KM_SLEEP);

		if (dumpcfg.bitmap != NULL)
			kmem_free(dumpcfg.bitmap, BT_SIZEOFMAP(dumpcfg.
			    bitmapsize));
		if (dumpcfg.rbitmap != NULL)
			kmem_free(dumpcfg.rbitmap, BT_SIZEOFMAP(dumpcfg.
			    rbitmapsize));
		dumpcfg.bitmap = map;
		dumpcfg.bitmapsize = npages;
		dumpcfg.rbitmap = rmap;
		dumpcfg.rbitmapsize = rlen;
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
			if (strcmp(ddi_driver_name(VTOS(cvp)->s_dip),
			    ZFS_DRIVER) == 0 &&
			    IS_SWAPVP(common_specvp(cvp)))
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
	dumpbuf.iosize = 0;

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
			struct dk_minfo minf;

			if (VOP_IOCTL(cdev_vp, DKIOCGMEDIAINFO,
			    (intptr_t)&minf, FKIOCTL, kcred, NULL, NULL)
			    == 0 && minf.dki_lbsize != 0)
				blk_size = minf.dki_lbsize;
			else
				blk_size = DEV_BSIZE;

			if (VOP_IOCTL(cdev_vp, DKIOCINFO, (intptr_t)&dki,
			    FKIOCTL, kcred, NULL, NULL) == 0) {
				dumpbuf.iosize = dki.dki_maxtransfer * blk_size;
				dumpbuf_resize();
			}
			/*
			 * If we are working with a zvol then dumpify it
			 * if it's not being used as swap.
			 */
			if (strcmp(dki.dki_dname, ZVOL_DRIVER) == 0) {
				if (IS_SWAPVP(common_specvp(cvp)))
					error = EBUSY;
				else if ((error = VOP_IOCTL(cdev_vp,
				    DKIOCDUMPINIT, NULL, FKIOCTL, kcred,
				    NULL, NULL)) != 0)
					dumpfini();
			}

			(void) VOP_CLOSE(cdev_vp, FREAD | FWRITE, 1, 0,
			    kcred, NULL);
		}

		VN_RELE(cdev_vp);
	}

	cmn_err(CE_CONT, "?dump on %s size %llu MB\n", name, dumpvp_size >> 20);

	dump_update_clevel();

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

static offset_t
dumpvp_flush(void)
{
	size_t size = P2ROUNDUP(dumpbuf.cur - dumpbuf.start, PAGESIZE);
	hrtime_t iotime;
	int err;

	if (dumpbuf.vp_off + size > dumpbuf.vp_limit) {
		dump_ioerr = ENOSPC;
		dumpbuf.vp_off = dumpbuf.vp_limit;
	} else if (size != 0) {
		iotime = gethrtime();
		dumpsync.iowait += iotime - dumpsync.iowaitts;
		if (panicstr)
			err = VOP_DUMP(dumpvp, dumpbuf.start,
			    lbtodb(dumpbuf.vp_off), btod(size), NULL);
		else
			err = vn_rdwr(UIO_WRITE, dumpbuf.cdev_vp != NULL ?
			    dumpbuf.cdev_vp : dumpvp, dumpbuf.start, size,
			    dumpbuf.vp_off, UIO_SYSSPACE, 0, dumpbuf.vp_limit,
			    kcred, 0);
		if (err && dump_ioerr == 0)
			dump_ioerr = err;
		dumpsync.iowaitts = gethrtime();
		dumpsync.iotime += dumpsync.iowaitts - iotime;
		dumpsync.nwrite += size;
		dumpbuf.vp_off += size;
	}
	dumpbuf.cur = dumpbuf.start;
	dump_timeleft = dump_timeout;
	return (dumpbuf.vp_off);
}

/* maximize write speed by keeping seek offset aligned with size */
void
dumpvp_write(const void *va, size_t size)
{
	size_t len, off, sz;

	while (size != 0) {
		len = MIN(size, dumpbuf.end - dumpbuf.cur);
		if (len == 0) {
			off = P2PHASE(dumpbuf.vp_off, dumpbuf.size);
			if (off == 0 || !ISP2(dumpbuf.size)) {
				(void) dumpvp_flush();
			} else {
				sz = dumpbuf.size - off;
				dumpbuf.cur = dumpbuf.start + sz;
				(void) dumpvp_flush();
				ovbcopy(dumpbuf.start + sz, dumpbuf.start, off);
				dumpbuf.cur += off;
			}
		} else {
			bcopy(va, dumpbuf.cur, len);
			va = (char *)va + len;
			dumpbuf.cur += len;
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
		if (!BT_TEST(dumpcfg.bitmap, bitnum)) {
			dumphdr->dump_npages++;
			BT_SET(dumpcfg.bitmap, bitnum);
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
		if (!BT_TEST(dumpcfg.bitmap, bitnum)) {
			dumphdr->dump_npages++;
			BT_SET(dumpcfg.bitmap, bitnum);
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

	AS_LOCK_ENTER(as, RW_READER);
	for (seg = AS_SEGFIRST(as); seg; seg = AS_SEGNEXT(as, seg)) {
		if (seg->s_as != as)
			break;
		if (seg->s_ops == NULL)
			continue;
		SEGOP_DUMP(seg);
	}
	AS_LOCK_EXIT(as);

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

/*
 * The following functions (dump_summary(), dump_ereports(), and
 * dump_messages()), write data to an uncompressed area within the
 * crashdump. The layout of these is
 *
 * +------------------------------------------------------------+
 * |     compressed pages       | summary | ereports | messages |
 * +------------------------------------------------------------+
 *
 * With the advent of saving a compressed crash dump by default, we
 * need to save a little more data to describe the failure mode in
 * an uncompressed buffer available before savecore uncompresses
 * the dump. Initially this is a copy of the stack trace. Additional
 * summary information should be added here.
 */

void
dump_summary(void)
{
	u_offset_t dumpvp_start;
	summary_dump_t sd;

	if (dumpvp == NULL || dumphdr == NULL)
		return;

	dumpbuf.cur = dumpbuf.start;

	dumpbuf.vp_limit = dumpvp_size - (DUMP_OFFSET + DUMP_LOGSIZE +
	    DUMP_ERPTSIZE);
	dumpvp_start = dumpbuf.vp_limit - DUMP_SUMMARYSIZE;
	dumpbuf.vp_off = dumpvp_start;

	sd.sd_magic = SUMMARY_MAGIC;
	sd.sd_ssum = checksum32(dump_stack_scratch, STACK_BUF_SIZE);
	dumpvp_write(&sd, sizeof (sd));
	dumpvp_write(dump_stack_scratch, STACK_BUF_SIZE);

	sd.sd_magic = 0; /* indicate end of summary */
	dumpvp_write(&sd, sizeof (sd));
	(void) dumpvp_flush();
}

void
dump_ereports(void)
{
	u_offset_t dumpvp_start;
	erpt_dump_t ed;

	if (dumpvp == NULL || dumphdr == NULL)
		return;

	dumpbuf.cur = dumpbuf.start;
	dumpbuf.vp_limit = dumpvp_size - (DUMP_OFFSET + DUMP_LOGSIZE);
	dumpvp_start = dumpbuf.vp_limit - DUMP_ERPTSIZE;
	dumpbuf.vp_off = dumpvp_start;

	fm_ereport_dump();
	if (panicstr)
		errorq_dump();

	bzero(&ed, sizeof (ed)); /* indicate end of ereports */
	dumpvp_write(&ed, sizeof (ed));
	(void) dumpvp_flush();

	if (!panicstr) {
		(void) VOP_PUTPAGE(dumpvp, dumpvp_start,
		    (size_t)(dumpbuf.vp_off - dumpvp_start),
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

	dumpbuf.cur = dumpbuf.start;
	dumpbuf.vp_limit = dumpvp_size - DUMP_OFFSET;
	dumpvp_start = dumpbuf.vp_limit - DUMP_LOGSIZE;
	dumpbuf.vp_off = dumpvp_start;

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
		    (size_t)(dumpbuf.vp_off - dumpvp_start),
		    B_INVAL | B_FORCE, kcred, NULL);
	}
}

/*
 * The following functions are called on multiple CPUs during dump.
 * They must not use most kernel services, because all cross-calls are
 * disabled during panic. Therefore, blocking locks and cache flushes
 * will not work.
 */

/*
 * Copy pages, trapping ECC errors. Also, for robustness, trap data
 * access in case something goes wrong in the hat layer and the
 * mapping is broken.
 */
static int
dump_pagecopy(void *src, void *dst)
{
	long *wsrc = (long *)src;
	long *wdst = (long *)dst;
	const ulong_t ncopies = PAGESIZE / sizeof (long);
	volatile int w = 0;
	volatile int ueoff = -1;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_EC | OT_DATA_ACCESS)) {
		if (ueoff == -1)
			ueoff = w * sizeof (long);
		/* report "bad ECC" or "bad address" */
#ifdef _LP64
		if (otd.ot_trap & OT_DATA_EC)
			wdst[w++] = 0x00badecc00badecc;
		else
			wdst[w++] = 0x00badadd00badadd;
#else
		if (otd.ot_trap & OT_DATA_EC)
			wdst[w++] = 0x00badecc;
		else
			wdst[w++] = 0x00badadd;
#endif
	}
	while (w < ncopies) {
		wdst[w] = wsrc[w];
		w++;
	}
	no_trap();
	return (ueoff);
}

static void
dumpsys_close_cq(cqueue_t *cq, int live)
{
	if (live) {
		mutex_enter(&cq->mutex);
		atomic_dec_uint(&cq->open);
		cv_signal(&cq->cv);
		mutex_exit(&cq->mutex);
	} else {
		atomic_dec_uint(&cq->open);
	}
}

static inline void
dumpsys_spinlock(lock_t *lp)
{
	uint_t backoff = 0;
	int loop_count = 0;

	while (LOCK_HELD(lp) || !lock_spin_try(lp)) {
		if (++loop_count >= ncpus) {
			backoff = mutex_lock_backoff(0);
			loop_count = 0;
		} else {
			backoff = mutex_lock_backoff(backoff);
		}
		mutex_lock_delay(backoff);
	}
}

static inline void
dumpsys_spinunlock(lock_t *lp)
{
	lock_clear(lp);
}

static inline void
dumpsys_lock(cqueue_t *cq, int live)
{
	if (live)
		mutex_enter(&cq->mutex);
	else
		dumpsys_spinlock(&cq->spinlock);
}

static inline void
dumpsys_unlock(cqueue_t *cq, int live, int signal)
{
	if (live) {
		if (signal)
			cv_signal(&cq->cv);
		mutex_exit(&cq->mutex);
	} else {
		dumpsys_spinunlock(&cq->spinlock);
	}
}

static void
dumpsys_wait_cq(cqueue_t *cq, int live)
{
	if (live) {
		cv_wait(&cq->cv, &cq->mutex);
	} else {
		dumpsys_spinunlock(&cq->spinlock);
		while (cq->open)
			if (cq->first)
				break;
		dumpsys_spinlock(&cq->spinlock);
	}
}

static void
dumpsys_put_cq(cqueue_t *cq, cbuf_t *cp, int newstate, int live)
{
	if (cp == NULL)
		return;

	dumpsys_lock(cq, live);

	if (cq->ts != 0) {
		cq->empty += gethrtime() - cq->ts;
		cq->ts = 0;
	}

	cp->state = newstate;
	cp->next = NULL;
	if (cq->last == NULL)
		cq->first = cp;
	else
		cq->last->next = cp;
	cq->last = cp;

	dumpsys_unlock(cq, live, 1);
}

static cbuf_t *
dumpsys_get_cq(cqueue_t *cq, int live)
{
	cbuf_t *cp;
	hrtime_t now = gethrtime();

	dumpsys_lock(cq, live);

	/* CONSTCOND */
	while (1) {
		cp = (cbuf_t *)cq->first;
		if (cp == NULL) {
			if (cq->open == 0)
				break;
			dumpsys_wait_cq(cq, live);
			continue;
		}
		cq->first = cp->next;
		if (cq->first == NULL) {
			cq->last = NULL;
			cq->ts = now;
		}
		break;
	}

	dumpsys_unlock(cq, live, cq->first != NULL || cq->open == 0);
	return (cp);
}

/*
 * Send an error message to the console. If the main task is running
 * just write the message via uprintf. If a helper is running the
 * message has to be put on a queue for the main task. Setting fmt to
 * NULL means flush the error message buffer. If fmt is not NULL, just
 * add the text to the existing buffer.
 */
static void
dumpsys_errmsg(helper_t *hp, const char *fmt, ...)
{
	dumpsync_t *ds = hp->ds;
	cbuf_t *cp = hp->cperr;
	va_list adx;

	if (hp->helper == MAINHELPER) {
		if (fmt != NULL) {
			if (ds->neednl) {
				uprintf("\n");
				ds->neednl = 0;
			}
			va_start(adx, fmt);
			vuprintf(fmt, adx);
			va_end(adx);
		}
	} else if (fmt == NULL) {
		if (cp != NULL) {
			CQ_PUT(mainq, cp, CBUF_ERRMSG);
			hp->cperr = NULL;
		}
	} else {
		if (hp->cperr == NULL) {
			cp = CQ_GET(freebufq);
			hp->cperr = cp;
			cp->used = 0;
		}
		va_start(adx, fmt);
		cp->used += vsnprintf(cp->buf + cp->used, cp->size - cp->used,
		    fmt, adx);
		va_end(adx);
		if ((cp->used + LOG_MSGSIZE) > cp->size) {
			CQ_PUT(mainq, cp, CBUF_ERRMSG);
			hp->cperr = NULL;
		}
	}
}

/*
 * Write an output buffer to the dump file. If the main task is
 * running just write the data. If a helper is running the output is
 * placed on a queue for the main task.
 */
static void
dumpsys_swrite(helper_t *hp, cbuf_t *cp, size_t used)
{
	dumpsync_t *ds = hp->ds;

	if (hp->helper == MAINHELPER) {
		HRSTART(ds->perpage, write);
		dumpvp_write(cp->buf, used);
		HRSTOP(ds->perpage, write);
		CQ_PUT(freebufq, cp, CBUF_FREEBUF);
	} else {
		cp->used = used;
		CQ_PUT(mainq, cp, CBUF_WRITE);
	}
}

/*
 * Copy one page within the mapped range. The offset starts at 0 and
 * is relative to the first pfn. cp->buf + cp->off is the address of
 * the first pfn. If dump_pagecopy returns a UE offset, create an
 * error message.  Returns the offset to the next pfn in the range
 * selected by the bitmap.
 */
static int
dumpsys_copy_page(helper_t *hp, int offset)
{
	cbuf_t *cp = hp->cpin;
	int ueoff;

	ASSERT(cp->off + offset + PAGESIZE <= cp->size);
	ASSERT(BT_TEST(dumpcfg.bitmap, cp->bitnum));

	ueoff = dump_pagecopy(cp->buf + cp->off + offset, hp->page);

	/* ueoff is the offset in the page to a UE error */
	if (ueoff != -1) {
		uint64_t pa = ptob(cp->pfn) + offset + ueoff;

		dumpsys_errmsg(hp, "cpu %d: memory error at PA 0x%08x.%08x\n",
		    CPU->cpu_id, (uint32_t)(pa >> 32), (uint32_t)pa);
	}

	/*
	 * Advance bitnum and offset to the next input page for the
	 * next call to this function.
	 */
	offset += PAGESIZE;
	cp->bitnum++;
	while (cp->off + offset < cp->size) {
		if (BT_TEST(dumpcfg.bitmap, cp->bitnum))
			break;
		offset += PAGESIZE;
		cp->bitnum++;
	}

	return (offset);
}

/*
 * Read the helper queue, and copy one mapped page. Return 0 when
 * done. Return 1 when a page has been copied into hp->page.
 */
static int
dumpsys_sread(helper_t *hp)
{
	dumpsync_t *ds = hp->ds;

	/* CONSTCOND */
	while (1) {

		/* Find the next input buffer. */
		if (hp->cpin == NULL) {
			HRSTART(hp->perpage, inwait);

			/* CONSTCOND */
			while (1) {
				hp->cpin = CQ_GET(helperq);
				dump_timeleft = dump_timeout;

				/*
				 * NULL return means the helper queue
				 * is closed and empty.
				 */
				if (hp->cpin == NULL)
					break;

				/* Have input, check for dump I/O error. */
				if (!dump_ioerr)
					break;

				/*
				 * If an I/O error occurs, stay in the
				 * loop in order to empty the helper
				 * queue. Return the buffers to the
				 * main task to unmap and free it.
				 */
				hp->cpin->used = 0;
				CQ_PUT(mainq, hp->cpin, CBUF_USEDMAP);
			}
			HRSTOP(hp->perpage, inwait);

			/* Stop here when the helper queue is closed. */
			if (hp->cpin == NULL)
				break;

			/* Set the offset=0 to get the first pfn. */
			hp->in = 0;

			/* Set the total processed to 0 */
			hp->used = 0;
		}

		/* Process the next page. */
		if (hp->used < hp->cpin->used) {

			/*
			 * Get the next page from the input buffer and
			 * return a copy.
			 */
			ASSERT(hp->in != -1);
			HRSTART(hp->perpage, copy);
			hp->in = dumpsys_copy_page(hp, hp->in);
			hp->used += PAGESIZE;
			HRSTOP(hp->perpage, copy);
			break;

		} else {

			/*
			 * Done with the input. Flush the VM and
			 * return the buffer to the main task.
			 */
			if (panicstr && hp->helper != MAINHELPER)
				hat_flush_range(kas.a_hat,
				    hp->cpin->buf, hp->cpin->size);
			dumpsys_errmsg(hp, NULL);
			CQ_PUT(mainq, hp->cpin, CBUF_USEDMAP);
			hp->cpin = NULL;
		}
	}

	return (hp->cpin != NULL);
}

/*
 * Compress size bytes starting at buf with bzip2
 * mode:
 *	BZ_RUN		add one more compressed page
 *	BZ_FINISH	no more input, flush the state
 */
static void
dumpsys_bzrun(helper_t *hp, void *buf, size_t size, int mode)
{
	dumpsync_t *ds = hp->ds;
	const int CSIZE = sizeof (dumpcsize_t);
	bz_stream *ps = &hp->bzstream;
	int rc = 0;
	uint32_t csize;
	dumpcsize_t cs;

	/* Set input pointers to new input page */
	if (size > 0) {
		ps->avail_in = size;
		ps->next_in = buf;
	}

	/* CONSTCOND */
	while (1) {

		/* Quit when all input has been consumed */
		if (ps->avail_in == 0 && mode == BZ_RUN)
			break;

		/* Get a new output buffer */
		if (hp->cpout == NULL) {
			HRSTART(hp->perpage, outwait);
			hp->cpout = CQ_GET(freebufq);
			HRSTOP(hp->perpage, outwait);
			ps->avail_out = hp->cpout->size - CSIZE;
			ps->next_out = hp->cpout->buf + CSIZE;
		}

		/* Compress input, or finalize */
		HRSTART(hp->perpage, compress);
		rc = BZ2_bzCompress(ps, mode);
		HRSTOP(hp->perpage, compress);

		/* Check for error */
		if (mode == BZ_RUN && rc != BZ_RUN_OK) {
			dumpsys_errmsg(hp, "%d: BZ_RUN error %s at page %lx\n",
			    hp->helper, BZ2_bzErrorString(rc),
			    hp->cpin->pagenum);
			break;
		}

		/* Write the buffer if it is full, or we are flushing */
		if (ps->avail_out == 0 || mode == BZ_FINISH) {
			csize = hp->cpout->size - CSIZE - ps->avail_out;
			cs = DUMP_SET_TAG(csize, hp->tag);
			if (csize > 0) {
				(void) memcpy(hp->cpout->buf, &cs, CSIZE);
				dumpsys_swrite(hp, hp->cpout, csize + CSIZE);
				hp->cpout = NULL;
			}
		}

		/* Check for final complete */
		if (mode == BZ_FINISH) {
			if (rc == BZ_STREAM_END)
				break;
			if (rc != BZ_FINISH_OK) {
				dumpsys_errmsg(hp, "%d: BZ_FINISH error %s\n",
				    hp->helper, BZ2_bzErrorString(rc));
				break;
			}
		}
	}

	/* Cleanup state and buffers */
	if (mode == BZ_FINISH) {

		/* Reset state so that it is re-usable. */
		(void) BZ2_bzCompressReset(&hp->bzstream);

		/* Give any unused outout buffer to the main task */
		if (hp->cpout != NULL) {
			hp->cpout->used = 0;
			CQ_PUT(mainq, hp->cpout, CBUF_ERRMSG);
			hp->cpout = NULL;
		}
	}
}

static void
dumpsys_bz2compress(helper_t *hp)
{
	dumpsync_t *ds = hp->ds;
	dumpstreamhdr_t sh;

	(void) strcpy(sh.stream_magic, DUMP_STREAM_MAGIC);
	sh.stream_pagenum = (pgcnt_t)-1;
	sh.stream_npages = 0;
	hp->cpin = NULL;
	hp->cpout = NULL;
	hp->cperr = NULL;
	hp->in = 0;
	hp->out = 0;
	hp->bzstream.avail_in = 0;

	/* Bump reference to mainq while we are running */
	CQ_OPEN(mainq);

	/* Get one page at a time */
	while (dumpsys_sread(hp)) {
		if (sh.stream_pagenum != hp->cpin->pagenum) {
			sh.stream_pagenum = hp->cpin->pagenum;
			sh.stream_npages = btop(hp->cpin->used);
			dumpsys_bzrun(hp, &sh, sizeof (sh), BZ_RUN);
		}
		dumpsys_bzrun(hp, hp->page, PAGESIZE, 0);
	}

	/* Done with input, flush any partial buffer */
	if (sh.stream_pagenum != (pgcnt_t)-1) {
		dumpsys_bzrun(hp, NULL, 0, BZ_FINISH);
		dumpsys_errmsg(hp, NULL);
	}

	ASSERT(hp->cpin == NULL && hp->cpout == NULL && hp->cperr == NULL);

	/* Decrement main queue count, we are done */
	CQ_CLOSE(mainq);
}

/*
 * Compress with lzjb
 * write stream block if full or size==0
 * if csize==0 write stream header, else write <csize, data>
 * size==0 is a call to flush a buffer
 * hp->cpout is the buffer we are flushing or filling
 * hp->out is the next index to fill data
 * osize is either csize+data, or the size of a stream header
 */
static void
dumpsys_lzjbrun(helper_t *hp, size_t csize, void *buf, size_t size)
{
	dumpsync_t *ds = hp->ds;
	const int CSIZE = sizeof (dumpcsize_t);
	dumpcsize_t cs;
	size_t osize = csize > 0 ? CSIZE + size : size;

	/* If flush, and there is no buffer, just return */
	if (size == 0 && hp->cpout == NULL)
		return;

	/* If flush, or cpout is full, write it out */
	if (size == 0 ||
	    hp->cpout != NULL && hp->out + osize > hp->cpout->size) {

		/* Set tag+size word at the front of the stream block. */
		cs = DUMP_SET_TAG(hp->out - CSIZE, hp->tag);
		(void) memcpy(hp->cpout->buf, &cs, CSIZE);

		/* Write block to dump file. */
		dumpsys_swrite(hp, hp->cpout, hp->out);

		/* Clear pointer to indicate we need a new buffer */
		hp->cpout = NULL;

		/* flushing, we are done */
		if (size == 0)
			return;
	}

	/* Get an output buffer if we dont have one. */
	if (hp->cpout == NULL) {
		HRSTART(hp->perpage, outwait);
		hp->cpout = CQ_GET(freebufq);
		HRSTOP(hp->perpage, outwait);
		hp->out = CSIZE;
	}

	/* Store csize word. This is the size of compressed data. */
	if (csize > 0) {
		cs = DUMP_SET_TAG(csize, 0);
		(void) memcpy(hp->cpout->buf + hp->out, &cs, CSIZE);
		hp->out += CSIZE;
	}

	/* Store the data. */
	(void) memcpy(hp->cpout->buf + hp->out, buf, size);
	hp->out += size;
}

static void
dumpsys_lzjbcompress(helper_t *hp)
{
	dumpsync_t *ds = hp->ds;
	size_t csize;
	dumpstreamhdr_t sh;

	(void) strcpy(sh.stream_magic, DUMP_STREAM_MAGIC);
	sh.stream_pagenum = (pfn_t)-1;
	sh.stream_npages = 0;
	hp->cpin = NULL;
	hp->cpout = NULL;
	hp->cperr = NULL;
	hp->in = 0;
	hp->out = 0;

	/* Bump reference to mainq while we are running */
	CQ_OPEN(mainq);

	/* Get one page at a time */
	while (dumpsys_sread(hp)) {

		/* Create a stream header for each new input map */
		if (sh.stream_pagenum != hp->cpin->pagenum) {
			sh.stream_pagenum = hp->cpin->pagenum;
			sh.stream_npages = btop(hp->cpin->used);
			dumpsys_lzjbrun(hp, 0, &sh, sizeof (sh));
		}

		/* Compress one page */
		HRSTART(hp->perpage, compress);
		csize = compress(hp->page, hp->lzbuf, PAGESIZE);
		HRSTOP(hp->perpage, compress);

		/* Add csize+data to output block */
		ASSERT(csize > 0 && csize <= PAGESIZE);
		dumpsys_lzjbrun(hp, csize, hp->lzbuf, csize);
	}

	/* Done with input, flush any partial buffer */
	if (sh.stream_pagenum != (pfn_t)-1) {
		dumpsys_lzjbrun(hp, 0, NULL, 0);
		dumpsys_errmsg(hp, NULL);
	}

	ASSERT(hp->cpin == NULL && hp->cpout == NULL && hp->cperr == NULL);

	/* Decrement main queue count, we are done */
	CQ_CLOSE(mainq);
}

/*
 * Dump helper called from panic_idle() to compress pages.  CPUs in
 * this path must not call most kernel services.
 *
 * During panic, all but one of the CPUs is idle. These CPUs are used
 * as helpers working in parallel to copy and compress memory
 * pages. During a panic, however, these processors cannot call any
 * kernel services. This is because mutexes become no-ops during
 * panic, and, cross-call interrupts are inhibited.  Therefore, during
 * panic dump the helper CPUs communicate with the panic CPU using
 * memory variables. All memory mapping and I/O is performed by the
 * panic CPU.
 *
 * At dump configuration time, helper_lock is set and helpers_wanted
 * is 0. dumpsys() decides whether to set helpers_wanted before
 * clearing helper_lock.
 *
 * At panic time, idle CPUs spin-wait on helper_lock, then alternately
 * take the lock and become a helper, or return.
 */
void
dumpsys_helper()
{
	dumpsys_spinlock(&dumpcfg.helper_lock);
	if (dumpcfg.helpers_wanted) {
		helper_t *hp, *hpend = &dumpcfg.helper[dumpcfg.nhelper];

		for (hp = dumpcfg.helper; hp != hpend; hp++) {
			if (hp->helper == FREEHELPER) {
				hp->helper = CPU->cpu_id;
				BT_SET(dumpcfg.helpermap, CPU->cpu_seqid);

				dumpsys_spinunlock(&dumpcfg.helper_lock);

				if (dumpcfg.clevel < DUMP_CLEVEL_BZIP2)
					dumpsys_lzjbcompress(hp);
				else
					dumpsys_bz2compress(hp);

				hp->helper = DONEHELPER;
				return;
			}
		}

		/* No more helpers are needed. */
		dumpcfg.helpers_wanted = 0;

	}
	dumpsys_spinunlock(&dumpcfg.helper_lock);
}

/*
 * No-wait helper callable in spin loops.
 *
 * Do not wait for helper_lock. Just check helpers_wanted. The caller
 * may decide to continue. This is the "c)ontinue, s)ync, r)eset? s"
 * case.
 */
void
dumpsys_helper_nw()
{
	if (dumpcfg.helpers_wanted)
		dumpsys_helper();
}

/*
 * Dump helper for live dumps.
 * These run as a system task.
 */
static void
dumpsys_live_helper(void *arg)
{
	helper_t *hp = arg;

	BT_ATOMIC_SET(dumpcfg.helpermap, CPU->cpu_seqid);
	if (dumpcfg.clevel < DUMP_CLEVEL_BZIP2)
		dumpsys_lzjbcompress(hp);
	else
		dumpsys_bz2compress(hp);
}

/*
 * Compress one page with lzjb (single threaded case)
 */
static void
dumpsys_lzjb_page(helper_t *hp, cbuf_t *cp)
{
	dumpsync_t *ds = hp->ds;
	uint32_t csize;

	hp->helper = MAINHELPER;
	hp->in = 0;
	hp->used = 0;
	hp->cpin = cp;
	while (hp->used < cp->used) {
		HRSTART(hp->perpage, copy);
		hp->in = dumpsys_copy_page(hp, hp->in);
		hp->used += PAGESIZE;
		HRSTOP(hp->perpage, copy);

		HRSTART(hp->perpage, compress);
		csize = compress(hp->page, hp->lzbuf, PAGESIZE);
		HRSTOP(hp->perpage, compress);

		HRSTART(hp->perpage, write);
		dumpvp_write(&csize, sizeof (csize));
		dumpvp_write(hp->lzbuf, csize);
		HRSTOP(hp->perpage, write);
	}
	CQ_PUT(mainq, hp->cpin, CBUF_USEDMAP);
	hp->cpin = NULL;
}

/*
 * Main task to dump pages. This is called on the dump CPU.
 */
static void
dumpsys_main_task(void *arg)
{
	dumpsync_t *ds = arg;
	pgcnt_t pagenum = 0, bitnum = 0, hibitnum;
	dumpmlw_t mlw;
	cbuf_t *cp;
	pgcnt_t baseoff, pfnoff;
	pfn_t base, pfn;
	int i, dumpserial;

	/*
	 * Fall back to serial mode if there are no helpers.
	 * dump_plat_mincpu can be set to 0 at any time.
	 * dumpcfg.helpermap must contain at least one member.
	 */
	dumpserial = 1;

	if (dump_plat_mincpu != 0 && dumpcfg.clevel != 0) {
		for (i = 0; i < BT_BITOUL(NCPU); ++i) {
			if (dumpcfg.helpermap[i] != 0) {
				dumpserial = 0;
				break;
			}
		}
	}

	if (dumpserial) {
		dumpcfg.clevel = 0;
		if (dumpcfg.helper[0].lzbuf == NULL)
			dumpcfg.helper[0].lzbuf = dumpcfg.helper[1].page;
	}

	dump_init_memlist_walker(&mlw);

	for (;;) {
		int sec = (gethrtime() - ds->start) / NANOSEC;

		/*
		 * Render a simple progress display on the system console to
		 * make clear to the operator that the system has not hung.
		 * Emit an update when dump progress has advanced by one
		 * percent, or when no update has been drawn in the last
		 * second.
		 */
		if (ds->percent > ds->percent_done || sec > ds->sec_done) {
			ds->sec_done = sec;
			ds->percent_done = ds->percent;
			uprintf("^\rdumping: %2d:%02d %3d%% done",
			    sec / 60, sec % 60, ds->percent);
			ds->neednl = 1;
		}

		while (CQ_IS_EMPTY(mainq) && !CQ_IS_EMPTY(writerq)) {

			/* the writerq never blocks */
			cp = CQ_GET(writerq);
			if (cp == NULL)
				break;

			dump_timeleft = dump_timeout;

			HRSTART(ds->perpage, write);
			dumpvp_write(cp->buf, cp->used);
			HRSTOP(ds->perpage, write);

			CQ_PUT(freebufq, cp, CBUF_FREEBUF);
		}

		/*
		 * Wait here for some buffers to process. Returns NULL
		 * when all helpers have terminated and all buffers
		 * have been processed.
		 */
		cp = CQ_GET(mainq);

		if (cp == NULL) {

			/* Drain the write queue. */
			if (!CQ_IS_EMPTY(writerq))
				continue;

			/* Main task exits here. */
			break;
		}

		dump_timeleft = dump_timeout;

		switch (cp->state) {

		case CBUF_FREEMAP:

			/*
			 * Note that we drop CBUF_FREEMAP buffers on
			 * the floor (they will not be on any cqueue)
			 * when we no longer need them.
			 */
			if (bitnum >= dumpcfg.bitmapsize)
				break;

			if (dump_ioerr) {
				bitnum = dumpcfg.bitmapsize;
				CQ_CLOSE(helperq);
				break;
			}

			HRSTART(ds->perpage, bitmap);
			for (; bitnum < dumpcfg.bitmapsize; bitnum++)
				if (BT_TEST(dumpcfg.bitmap, bitnum))
					break;
			HRSTOP(ds->perpage, bitmap);
			dump_timeleft = dump_timeout;

			if (bitnum >= dumpcfg.bitmapsize) {
				CQ_CLOSE(helperq);
				break;
			}

			/*
			 * Try to map CBUF_MAPSIZE ranges. Can't
			 * assume that memory segment size is a
			 * multiple of CBUF_MAPSIZE. Can't assume that
			 * the segment starts on a CBUF_MAPSIZE
			 * boundary.
			 */
			pfn = dump_bitnum_to_pfn(bitnum, &mlw);
			ASSERT(pfn != PFN_INVALID);
			ASSERT(bitnum + mlw.mpleft <= dumpcfg.bitmapsize);

			base = P2ALIGN(pfn, CBUF_MAPNP);
			if (base < mlw.mpaddr) {
				base = mlw.mpaddr;
				baseoff = P2PHASE(base, CBUF_MAPNP);
			} else {
				baseoff = 0;
			}

			pfnoff = pfn - base;
			if (pfnoff + mlw.mpleft < CBUF_MAPNP) {
				hibitnum = bitnum + mlw.mpleft;
				cp->size = ptob(pfnoff + mlw.mpleft);
			} else {
				hibitnum = bitnum - pfnoff + CBUF_MAPNP -
				    baseoff;
				cp->size = CBUF_MAPSIZE - ptob(baseoff);
			}

			cp->pfn = pfn;
			cp->bitnum = bitnum++;
			cp->pagenum = pagenum++;
			cp->off = ptob(pfnoff);

			for (; bitnum < hibitnum; bitnum++)
				if (BT_TEST(dumpcfg.bitmap, bitnum))
					pagenum++;

			dump_timeleft = dump_timeout;
			cp->used = ptob(pagenum - cp->pagenum);

			HRSTART(ds->perpage, map);
			hat_devload(kas.a_hat, cp->buf, cp->size, base,
			    PROT_READ, HAT_LOAD_NOCONSIST);
			HRSTOP(ds->perpage, map);

			ds->pages_mapped += btop(cp->size);
			ds->pages_used += pagenum - cp->pagenum;

			CQ_OPEN(mainq);

			/*
			 * If there are no helpers the main task does
			 * non-streams lzjb compress.
			 */
			if (dumpserial) {
				dumpsys_lzjb_page(dumpcfg.helper, cp);
				break;
			}

			/* pass mapped pages to a helper */
			CQ_PUT(helperq, cp, CBUF_INREADY);

			/* the last page was done */
			if (bitnum >= dumpcfg.bitmapsize)
				CQ_CLOSE(helperq);

			break;

		case CBUF_USEDMAP:

			ds->npages += btop(cp->used);

			HRSTART(ds->perpage, unmap);
			hat_unload(kas.a_hat, cp->buf, cp->size, HAT_UNLOAD);
			HRSTOP(ds->perpage, unmap);

			if (bitnum < dumpcfg.bitmapsize)
				CQ_PUT(mainq, cp, CBUF_FREEMAP);
			CQ_CLOSE(mainq);

			ASSERT(ds->npages <= dumphdr->dump_npages);
			ds->percent = ds->npages * 100LL / dumphdr->dump_npages;
			break;

		case CBUF_WRITE:

			CQ_PUT(writerq, cp, CBUF_WRITE);
			break;

		case CBUF_ERRMSG:

			if (cp->used > 0) {
				cp->buf[cp->size - 2] = '\n';
				cp->buf[cp->size - 1] = '\0';
				if (ds->neednl) {
					uprintf("\n%s", cp->buf);
					ds->neednl = 0;
				} else {
					uprintf("%s", cp->buf);
				}
				/* wait for console output */
				drv_usecwait(200000);
				dump_timeleft = dump_timeout;
			}
			CQ_PUT(freebufq, cp, CBUF_FREEBUF);
			break;

		default:
			uprintf("dump: unexpected buffer state %d, "
			    "buffer will be lost\n", cp->state);
			break;

		} /* end switch */
	}
}

#ifdef	COLLECT_METRICS
size_t
dumpsys_metrics(dumpsync_t *ds, char *buf, size_t size)
{
	dumpcfg_t *cfg = &dumpcfg;
	int myid = CPU->cpu_seqid;
	int i, compress_ratio;
	int sec, iorate;
	helper_t *hp, *hpend = &cfg->helper[cfg->nhelper];
	char *e = buf + size;
	char *p = buf;

	sec = ds->elapsed / (1000 * 1000 * 1000ULL);
	if (sec < 1)
		sec = 1;

	if (ds->iotime < 1)
		ds->iotime = 1;
	iorate = (ds->nwrite * 100000ULL) / ds->iotime;

	compress_ratio = 100LL * ds->npages / btopr(ds->nwrite + 1);

#define	P(...) (p += p < e ? snprintf(p, e - p, __VA_ARGS__) : 0)

	P("Master cpu_seqid,%d\n", CPU->cpu_seqid);
	P("Master cpu_id,%d\n", CPU->cpu_id);
	P("dump_flags,0x%x\n", dumphdr->dump_flags);
	P("dump_ioerr,%d\n", dump_ioerr);

	P("Helpers:\n");
	for (i = 0; i < ncpus; i++) {
		if ((i & 15) == 0)
			P(",,%03d,", i);
		if (i == myid)
			P("   M");
		else if (BT_TEST(cfg->helpermap, i))
			P("%4d", cpu_seq[i]->cpu_id);
		else
			P("   *");
		if ((i & 15) == 15)
			P("\n");
	}

	P("ncbuf_used,%d\n", cfg->ncbuf_used);
	P("ncmap,%d\n", cfg->ncmap);

	P("Found %ldM ranges,%ld\n", (CBUF_MAPSIZE / DUMP_1MB), cfg->found4m);
	P("Found small pages,%ld\n", cfg->foundsm);

	P("Compression level,%d\n", cfg->clevel);
	P("Compression type,%s %s\n", cfg->clevel == 0 ? "serial" : "parallel",
	    cfg->clevel >= DUMP_CLEVEL_BZIP2 ? "bzip2" : "lzjb");
	P("Compression ratio,%d.%02d\n", compress_ratio / 100, compress_ratio %
	    100);
	P("nhelper_used,%d\n", cfg->nhelper_used);

	P("Dump I/O rate MBS,%d.%02d\n", iorate / 100, iorate % 100);
	P("..total bytes,%lld\n", (u_longlong_t)ds->nwrite);
	P("..total nsec,%lld\n", (u_longlong_t)ds->iotime);
	P("dumpbuf.iosize,%ld\n", dumpbuf.iosize);
	P("dumpbuf.size,%ld\n", dumpbuf.size);

	P("Dump pages/sec,%llu\n", (u_longlong_t)ds->npages / sec);
	P("Dump pages,%llu\n", (u_longlong_t)ds->npages);
	P("Dump time,%d\n", sec);

	if (ds->pages_mapped > 0)
		P("per-cent map utilization,%d\n", (int)((100 * ds->pages_used)
		    / ds->pages_mapped));

	P("\nPer-page metrics:\n");
	if (ds->npages > 0) {
		for (hp = cfg->helper; hp != hpend; hp++) {
#define	PERPAGE(x)	ds->perpage.x += hp->perpage.x;
			PERPAGES;
#undef PERPAGE
		}
#define	PERPAGE(x) \
		P("%s nsec/page,%d\n", #x, (int)(ds->perpage.x / ds->npages));
		PERPAGES;
#undef PERPAGE
		P("freebufq.empty,%d\n", (int)(ds->freebufq.empty /
		    ds->npages));
		P("helperq.empty,%d\n", (int)(ds->helperq.empty /
		    ds->npages));
		P("writerq.empty,%d\n", (int)(ds->writerq.empty /
		    ds->npages));
		P("mainq.empty,%d\n", (int)(ds->mainq.empty / ds->npages));

		P("I/O wait nsec/page,%llu\n", (u_longlong_t)(ds->iowait /
		    ds->npages));
	}
#undef P
	if (p < e)
		bzero(p, e - p);
	return (p - buf);
}
#endif	/* COLLECT_METRICS */

/*
 * Dump the system.
 */
void
dumpsys(void)
{
	dumpsync_t *ds = &dumpsync;
	taskq_t *livetaskq = NULL;
	pfn_t pfn;
	pgcnt_t bitnum;
	proc_t *p;
	helper_t *hp, *hpend = &dumpcfg.helper[dumpcfg.nhelper];
	cbuf_t *cp;
	pid_t npids, pidx;
	char *content;
	char *buf;
	size_t size;
	int save_dump_clevel;
	dumpmlw_t mlw;
	dumpcsize_t datatag;
	dumpdatahdr_t datahdr;

	if (dumpvp == NULL || dumphdr == NULL) {
		uprintf("skipping system dump - no dump device configured\n");
		if (panicstr) {
			dumpcfg.helpers_wanted = 0;
			dumpsys_spinunlock(&dumpcfg.helper_lock);
		}
		return;
	}
	dumpbuf.cur = dumpbuf.start;

	/* clear the sync variables */
	ASSERT(dumpcfg.nhelper > 0);
	bzero(ds, sizeof (*ds));
	ds->dumpcpu = CPU->cpu_id;

	/*
	 * Calculate the starting block for dump.  If we're dumping on a
	 * swap device, start 1/5 of the way in; otherwise, start at the
	 * beginning.  And never use the first page -- it may be a disk label.
	 */
	if (dumpvp->v_flag & VISSWAP)
		dumphdr->dump_start = P2ROUNDUP(dumpvp_size / 5, DUMP_OFFSET);
	else
		dumphdr->dump_start = DUMP_OFFSET;

	dumphdr->dump_flags = DF_VALID | DF_COMPLETE | DF_LIVE | DF_COMPRESSED;
	dumphdr->dump_crashtime = gethrestime_sec();
	dumphdr->dump_npages = 0;
	dumphdr->dump_nvtop = 0;
	bzero(dumpcfg.bitmap, BT_SIZEOFMAP(dumpcfg.bitmapsize));
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

	/* Make sure nodename is current */
	bcopy(utsname.nodename, dumphdr->dump_utsname.nodename, SYS_NMLN);

	/*
	 * If this is a live dump, try to open a VCHR vnode for better
	 * performance. We must take care to flush the buffer cache
	 * first.
	 */
	if (!panicstr) {
		vnode_t *cdev_vp, *cmn_cdev_vp;

		ASSERT(dumpbuf.cdev_vp == NULL);
		cdev_vp = makespecvp(VTOS(dumpvp)->s_dev, VCHR);
		if (cdev_vp != NULL) {
			cmn_cdev_vp = common_specvp(cdev_vp);
			if (VOP_OPEN(&cmn_cdev_vp, FREAD | FWRITE, kcred, NULL)
			    == 0) {
				if (vn_has_cached_data(dumpvp))
					(void) pvn_vplist_dirty(dumpvp, 0, NULL,
					    B_INVAL | B_TRUNC, kcred);
				dumpbuf.cdev_vp = cmn_cdev_vp;
			} else {
				VN_RELE(cdev_vp);
			}
		}
	}

	/*
	 * Store a hires timestamp so we can look it up during debugging.
	 */
	lbolt_debug_entry();

	/*
	 * Leave room for the message and ereport save areas and terminal dump
	 * header.
	 */
	dumpbuf.vp_limit = dumpvp_size - DUMP_LOGSIZE - DUMP_OFFSET -
	    DUMP_ERPTSIZE;

	/*
	 * Write out the symbol table.  It's no longer compressed,
	 * so its 'size' and 'csize' are equal.
	 */
	dumpbuf.vp_off = dumphdr->dump_ksyms = dumphdr->dump_start + PAGESIZE;
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
			dumpcfg.pids[npids++] = p->p_pid;

		mutex_exit(&pidlock);

		for (pidx = 0; pidx < npids; pidx++)
			(void) dump_process(dumpcfg.pids[pidx]);

		dump_init_memlist_walker(&mlw);
		for (bitnum = 0; bitnum < dumpcfg.bitmapsize; bitnum++) {
			dump_timeleft = dump_timeout;
			pfn = dump_bitnum_to_pfn(bitnum, &mlw);
			/*
			 * Some hypervisors do not have all pages available to
			 * be accessed by the guest OS.  Check for page
			 * accessibility.
			 */
			if (plat_hold_page(pfn, PLAT_HOLD_NO_LOCK, NULL) !=
			    PLAT_HOLD_OK)
				continue;
			BT_SET(dumpcfg.bitmap, bitnum);
		}
		dumphdr->dump_npages = dumpcfg.bitmapsize;
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
				dumpcfg.pids[npids++] =
				    panic_thread->t_procp->p_pid;
			}
		} else {
			dumpcfg.pids[npids++] = curthread->t_procp->p_pid;
		}

		if (npids && dump_process(dumpcfg.pids[0]) == 0)
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
	dump_init_memlist_walker(&mlw);
	for (bitnum = 0; bitnum < dumpcfg.bitmapsize; bitnum++) {
		dump_timeleft = dump_timeout;
		if (!BT_TEST(dumpcfg.bitmap, bitnum))
			continue;
		pfn = dump_bitnum_to_pfn(bitnum, &mlw);
		ASSERT(pfn != PFN_INVALID);
		dumpvp_write(&pfn, sizeof (pfn_t));
	}
	dump_plat_pfn();

	/*
	 * Write out all the pages.
	 * Map pages, copy them handling UEs, compress, and write them out.
	 * Cooperate with any helpers running on CPUs in panic_idle().
	 */
	dumphdr->dump_data = dumpvp_flush();

	bzero(dumpcfg.helpermap, BT_SIZEOFMAP(NCPU));
	ds->live = dumpcfg.clevel > 0 &&
	    (dumphdr->dump_flags & DF_LIVE) != 0;

	save_dump_clevel = dumpcfg.clevel;
	if (panicstr)
		dumpsys_get_maxmem();
	else if (dumpcfg.clevel >= DUMP_CLEVEL_BZIP2)
		dumpcfg.clevel = DUMP_CLEVEL_LZJB;

	dumpcfg.nhelper_used = 0;
	for (hp = dumpcfg.helper; hp != hpend; hp++) {
		if (hp->page == NULL) {
			hp->helper = DONEHELPER;
			continue;
		}
		++dumpcfg.nhelper_used;
		hp->helper = FREEHELPER;
		hp->taskqid = NULL;
		hp->ds = ds;
		bzero(&hp->perpage, sizeof (hp->perpage));
		if (dumpcfg.clevel >= DUMP_CLEVEL_BZIP2)
			(void) BZ2_bzCompressReset(&hp->bzstream);
	}

	CQ_OPEN(freebufq);
	CQ_OPEN(helperq);

	dumpcfg.ncbuf_used = 0;
	for (cp = dumpcfg.cbuf; cp != &dumpcfg.cbuf[dumpcfg.ncbuf]; cp++) {
		if (cp->buf != NULL) {
			CQ_PUT(freebufq, cp, CBUF_FREEBUF);
			++dumpcfg.ncbuf_used;
		}
	}

	for (cp = dumpcfg.cmap; cp != &dumpcfg.cmap[dumpcfg.ncmap]; cp++)
		CQ_PUT(mainq, cp, CBUF_FREEMAP);

	ds->start = gethrtime();
	ds->iowaitts = ds->start;

	/* start helpers */
	if (ds->live) {
		int n = dumpcfg.nhelper_used;
		int pri = MINCLSYSPRI - 25;

		livetaskq = taskq_create("LiveDump", n, pri, n, n,
		    TASKQ_PREPOPULATE);
		for (hp = dumpcfg.helper; hp != hpend; hp++) {
			if (hp->page == NULL)
				continue;
			hp->helper = hp - dumpcfg.helper;
			hp->taskqid = taskq_dispatch(livetaskq,
			    dumpsys_live_helper, (void *)hp, TQ_NOSLEEP);
		}

	} else {
		if (panicstr)
			kmem_dump_begin();
		dumpcfg.helpers_wanted = dumpcfg.clevel > 0;
		dumpsys_spinunlock(&dumpcfg.helper_lock);
	}

	/* run main task */
	dumpsys_main_task(ds);

	ds->elapsed = gethrtime() - ds->start;
	if (ds->elapsed < 1)
		ds->elapsed = 1;

	if (livetaskq != NULL)
		taskq_destroy(livetaskq);

	if (ds->neednl) {
		uprintf("\n");
		ds->neednl = 0;
	}

	/* record actual pages dumped */
	dumphdr->dump_npages = ds->npages;

	/* platform-specific data */
	dumphdr->dump_npages += dump_plat_data(dumpcfg.cbuf[0].buf);

	/* note any errors by clearing DF_COMPLETE */
	if (dump_ioerr || ds->npages < dumphdr->dump_npages)
		dumphdr->dump_flags &= ~DF_COMPLETE;

	/* end of stream blocks */
	datatag = 0;
	dumpvp_write(&datatag, sizeof (datatag));

	bzero(&datahdr, sizeof (datahdr));

	/* buffer for metrics */
	buf = dumpcfg.cbuf[0].buf;
	size = MIN(dumpcfg.cbuf[0].size, DUMP_OFFSET - sizeof (dumphdr_t) -
	    sizeof (dumpdatahdr_t));

	/* finish the kmem intercepts, collect kmem verbose info */
	if (panicstr) {
		datahdr.dump_metrics = kmem_dump_finish(buf, size);
		buf += datahdr.dump_metrics;
		size -= datahdr.dump_metrics;
	}

	/* record in the header whether this is a fault-management panic */
	if (panicstr)
		dumphdr->dump_fm_panic = is_fm_panic();

	/* compression info in data header */
	datahdr.dump_datahdr_magic = DUMP_DATAHDR_MAGIC;
	datahdr.dump_datahdr_version = DUMP_DATAHDR_VERSION;
	datahdr.dump_maxcsize = CBUF_SIZE;
	datahdr.dump_maxrange = CBUF_MAPSIZE / PAGESIZE;
	datahdr.dump_nstreams = dumpcfg.nhelper_used;
	datahdr.dump_clevel = dumpcfg.clevel;
#ifdef COLLECT_METRICS
	if (dump_metrics_on)
		datahdr.dump_metrics += dumpsys_metrics(ds, buf, size);
#endif
	datahdr.dump_data_csize = dumpvp_flush() - dumphdr->dump_data;

	/*
	 * Write out the initial and terminal dump headers.
	 */
	dumpbuf.vp_off = dumphdr->dump_start;
	dumpvp_write(dumphdr, sizeof (dumphdr_t));
	(void) dumpvp_flush();

	dumpbuf.vp_limit = dumpvp_size;
	dumpbuf.vp_off = dumpbuf.vp_limit - DUMP_OFFSET;
	dumpvp_write(dumphdr, sizeof (dumphdr_t));
	dumpvp_write(&datahdr, sizeof (dumpdatahdr_t));
	dumpvp_write(dumpcfg.cbuf[0].buf, datahdr.dump_metrics);

	(void) dumpvp_flush();

	uprintf("\r%3d%% done: %llu pages dumped, ",
	    ds->percent_done, (u_longlong_t)ds->npages);

	if (dump_ioerr == 0) {
		uprintf("dump succeeded\n");
	} else {
		uprintf("dump failed: error %d\n", dump_ioerr);
#ifdef DEBUG
		if (panicstr)
			debug_enter("dump failed");
#endif
	}

	/*
	 * Write out all undelivered messages.  This has to be the *last*
	 * thing we do because the dump process itself emits messages.
	 */
	if (panicstr) {
		dump_summary();
		dump_ereports();
		dump_messages();
	}

	delay(2 * hz);	/* let people see the 'done' message */
	dump_timeleft = 0;
	dump_ioerr = 0;

	/* restore settings after live dump completes */
	if (!panicstr) {
		dumpcfg.clevel = save_dump_clevel;

		/* release any VCHR open of the dump device */
		if (dumpbuf.cdev_vp != NULL) {
			(void) VOP_CLOSE(dumpbuf.cdev_vp, FREAD | FWRITE, 1, 0,
			    kcred, NULL);
			VN_RELE(dumpbuf.cdev_vp);
			dumpbuf.cdev_vp = NULL;
		}
	}
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
	dump_update_clevel();
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

int
dump_set_uuid(const char *uuidstr)
{
	const char *ptr;
	int i;

	if (uuidstr == NULL || strnlen(uuidstr, 36 + 1) != 36)
		return (EINVAL);

	/* uuid_parse is not common code so check manually */
	for (i = 0, ptr = uuidstr; i < 36; i++, ptr++) {
		switch (i) {
		case 8:
		case 13:
		case 18:
		case 23:
			if (*ptr != '-')
				return (EINVAL);
			break;

		default:
			if (!isxdigit(*ptr))
				return (EINVAL);
			break;
		}
	}

	if (dump_osimage_uuid[0] != '\0')
		return (EALREADY);

	(void) strncpy(dump_osimage_uuid, uuidstr, 36 + 1);

	cmn_err(CE_CONT, "?This Solaris instance has UUID %s\n",
	    dump_osimage_uuid);

	return (0);
}

const char *
dump_get_uuid(void)
{
	return (dump_osimage_uuid[0] != '\0' ? dump_osimage_uuid : "");
}
