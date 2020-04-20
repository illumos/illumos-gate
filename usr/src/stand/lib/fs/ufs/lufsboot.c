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

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_log.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/machparam.h>

#include <sys/stat.h>
#include <sys/bootdebug.h>
#include <sys/salib.h>
#include <sys/saio.h>
#include <sys/filep.h>


/*
 * Big theory statement on how ufsboot makes use of the log
 * in case the filesystem wasn't shut down cleanly.
 *
 * The structure of the ufs on-disk log looks like this:
 *
 * +-----------------+
 * | SUPERBLOCK      |
 * | ...             |
 * | fs_logbno       +--> +-----------------------+
 * | ...             |    | EXTENT BLOCK          |
 * +-----------------+    |   ...                 |
 *                        |   nextents            |
 * +----------------------+   extents[0].pbno     |
 * |                      | { extents[1].pbno }   +------------+
 * |                      |   ...                 +--> ...     |
 * |                      +-----------------------+            |
 * v                                                           |
 * +-----------------------------+      \                      |
 * | ON-DISK LOG HEADER          |      |                      |
 * | ...                         |      |                      |
 * | od_head_lof                 +--+   |                      |
 * | ...                         |  |   |                      |
 * +-----------------------------+ <|---|- od_bol_lof          |
 * | sector (may contain deltas) |  |   |  (logical offset)    |
 * |   +-------------------------+  |   |                      |
 * |   | trailer (some ident#)   |  |    > extents[0].nbno     |
 * +---+-------------------------+  |   |  blocks ("sectors")  |
 * .                             .  |   |                      |
 * .                             .  |   |                      |
 * +-----------------------------+<-+   |                      |
 * | delta1 delta2       delta3  |      |                      |
 * | d +-------------------------+      |                      |
 * | e | ident#: od_head_ident   |      |                      |
 * +---+-------------------------+      /                      |
 *                                                             |
 * +-----------------------------+ <---------------------------+
 * | lta4    delta5 delta6    de |
 * | l +-------------------------+
 * | t | ident#: od_head_ident+1 |
 * +---+-------------------------+
 * .                             .
 * +-----------------------------+
 * | sector (may contain deltas) |
 * |          +------------------+
 * |          | trailer (ident#) |
 * +----------+------------------+ <-- od_eol_lof (logical offset)
 *
 * The ufs on-disk log has the following properties:
 *
 * 1. The log is made up from at least one extent. "fs_logbno" in
 *    the superblock points to where this is found.
 * 2. Extents describe the logical layout.
 *      - Logical offset 0 is the on-disk log header. It's also
 *        at the beginning of the first physical block.
 *      - If there's more than one extent, the equation holds:
 *             extent[i+1].lbno == extent[i].lbno + extent[i].nbno
 *        i.e. logical offsets form a contiguous sequence. Yet on disk,
 *        two logically-adjacent offsets may be located in two
 *        physically disjoint extents, so logical offsets need to be
 *        translated into physical disk block addresses for access.
 *      - Various fields in the on-disk log header structure refer
 *        to such logical log offsets.
 * 3. The actual logical logspace begins after the log header, at
 *    the logical offset indicated by "od_bol_lof". Every 512 Bytes
 *    (a "sector" in terms of ufs logging) is a sector trailer which
 *    contains a sequence number, the sector ident.
 * 4. Deltas are packed tight in the remaining space, i.e. a delta
 *    may be part of more than one sector. Reads from the logspace
 *    must be split at sector boundaries, since the trailer is never
 *    part of a delta. Delta sizes vary.
 * 5. The field "od_head_lof" points to the start of the dirty part
 *    of the log, i.e. to the first delta header. Likewise, "od_head_ident"
 *    is the sequence number where the valid part of the log starts; if
 *    the sector pointed to by "od_head_lof" has a sector ident different
 *    from "od_head_ident", the log is empty.
 * 6. The valid part of the log extends for as many sectors as their ident
 *    numbers form a contiguous sequence. When reaching the logical end of
 *    the log, "od_bol_lof", logical offsets wrap around to "od_bol_lof",
 *    i.e. the log forms a circular buffer.
 *
 * For the strategy how to handle accessing the log, item 4. is the
 * most important one - its consequence is that the log can only be
 * read in one direction - forward, starting at the head.
 *
 * The task of identifying whether a given metadata block is
 * actually in the log therefore requires reading the entire
 * log. Doing so is memory-efficient but kills speed if re-done
 * at every metadata read (64MB log size vs. 512 byte metadata
 * block size: 128 times as much I/O, possibly only to find out
 * that this block was not in the log ...).
 *
 * First thought to speed this up is to let ufsboot roll the log.
 * But this is not possible because:
 * - ufsboot currently does not implement any write functionality,
 *   the boot-time ufs implementation is read-only.
 * - firmware write interfaces may or may not be available, in any
 *   case, they're rarely used and untested for such a purpose.
 * - that would duplicate a lot of code, since at the moment only
 *   kernel ufs logging implements log rolling.
 * - the boot environment cannot be considered high-performance;
 *   rolling the log there would be slow.
 * - boot device and root device could well be different, creating
 *   inconsistencies e.g. with a mirrored root if the log is rolled.
 *
 * Therefore, caching the log structural information (boot-relevant
 * deltas and their logical log offset) is required for fast access
 * to the data in the log. This code builds a logmap for that purpose.
 *
 * As a simple optimization, if we find the log is empty, we will not
 * use it - log reader support for ufsboot has no noticeable overhead
 * for clean logs, or for root filesystems that aren't logging.
 */

#define	LB_HASHSHIFT		13
#define	LB_HASHSIZE		(1 << LB_HASHSHIFT)
#define	LB_HASHFUNC(mof)	(((mof) >> LB_HASHSHIFT) & (LB_HASHSIZE - 1))

#define	LOGBUF_MAXSIZE	(8*1024*1024)
#define	LOGBUF_MINSIZE	(256*1024)

#define	LOG_IS_EMPTY	0
#define	LOG_IS_OK	1
#define	LOG_IS_ERRORED	2

/*
 * We build a hashed logmap of those while scanning the log.
 * sizeof(lb_map_t) is 40 on 64bit, 32 on 32bit; the max sized
 * resalloc'ed buffer can accomodate around ~500k of those;
 * this is approximately the maximum amount of deltas we'll
 * see if a 64MB ufs log is completely filled. We'll make no
 * attempt to free and reallocate the resalloc'ed buffer if
 * we overflow, as conservative sizing should make that an
 * impossibility. A future enhancement may allocate memory
 * here as needed - once the boot time memory allocator
 * supports that.
 */
typedef struct lb_mapentry {
	struct lb_mapentry	*l_next;	/* hash chaining */
	struct lb_mapentry	*l_prev;	/* hash chaining */
	int64_t		l_mof;		/* disk addr this delta is against */
	int16_t		l_nb;		/* size of delta */
	int16_t		l_flags;
	int32_t		l_lof;		/* log offset for delta header */
	int32_t		l_tid;		/* transaction this delta is part of */
	delta_t		l_typ;		/* see <sys/fs/ufs_trans.h> */
} lb_me_t;

#define	LB_ISCANCELLED	1

#define	inslist(lh, l)	if ((*(lh))) {				\
				(*(lh))->l_prev->l_next = (l);	\
				(l)->l_next = (*(lh));		\
				(l)->l_prev = (*(lh))->l_prev;	\
				(*(lh))->l_prev = (l);		\
			} else {				\
				(l)->l_next = (l);		\
				(l)->l_prev = (l);		\
				(*(lh)) = l;			\
			}

#define	remlist(lh, l)	\
	if ((l)->l_next == (l)) {			\
		if (*(lh) != (l) || (l)->l_prev != (l))	\
			dprintf("Logmap hash inconsistency.\n");	\
		*(lh) = (lb_me_t *)NULL;		\
	} else {					\
		if (*(lh) == (l))			\
			*(lh) = (l)->l_next;		\
		(l)->l_prev->l_next = (l)->l_next;	\
		(l)->l_next->l_prev = (l)->l_prev;	\
	}

#define	lufs_alloc_me()	\
	(lb_me_t *)lufs_alloc_from_logbuf(sizeof (lb_me_t))

extern int		boothowto;
static int		ufs_is_lufs = 0;
static fileid_t		*logfp = (fileid_t *)NULL;
static extent_block_t	*eb = (extent_block_t *)NULL;
static ml_odunit_t	odi;

static char		logbuffer_min[LOGBUF_MINSIZE];
static caddr_t		logbuffer = (caddr_t)NULL;
static caddr_t		elogbuffer = (caddr_t)NULL;
static caddr_t		logbuf_curptr;
static lb_me_t		**loghash = (lb_me_t **)NULL;
static lb_me_t		*lfreelist;

static uint32_t		curtid;


int	lufs_support = 1;

void	lufs_boot_init(fileid_t *);
void	lufs_closeall(void);
void	lufs_merge_deltas(fileid_t *);

static	int	lufs_logscan(void);

extern	int	diskread(fileid_t *filep);
extern	caddr_t	resalloc(enum RESOURCES, size_t, caddr_t, int);

#if defined(__sparcv9)
#define	LOGBUF_BASEADDR	((caddr_t)(SYSBASE - LOGBUF_MAXSIZE))
#endif

static int
lufs_alloc_logbuf(void)
{
	/*
	 * Allocate memory for caching the log. Since the logbuffer can
	 * potentially exceed the boot scratch memory limit, we use resalloc
	 * directly, passing the allocation to the low-level boot-time
	 * backend allocator. The chosen VA range is the top end of
	 * the kernel's segmap segment, so we're not interfering
	 * with the kernel because segmap is created at a time when
	 * the 2nd-stage boot has already been unloaded and this VA
	 * range was given back.
	 *
	 * On sparc platforms, the kernel cannot recover the memory
	 * obtained from resalloc because the page structs are allocated
	 * before the call to BOP_QUIESCE. To avoid leaking this
	 * memory, the logbuffer is allocated from a small bss array
	 * that should hold the logmap except in the most extreme cases.
	 * If the bss array is too small, the logbuffer is extended
	 * from resalloc 1 page at a time.
	 */

	logbuffer = logbuffer_min;
	elogbuffer = logbuffer+LOGBUF_MINSIZE;
	logbuf_curptr = logbuffer;
	lfreelist = (lb_me_t *)NULL;

	if (logbuffer == (caddr_t)NULL)
		return (0);

	dprintf("Buffer for boot loader logging support: 0x%p, size 0x%x\n",
	    logbuffer, elogbuffer-logbuffer);

	return (1);
}

static void
lufs_free_logbuf()
{
	/*
	 * Solaris/x86 has no prom_free() routine at this time.
	 * Reclaiming the VA range below KERNEL_TEXT on Solaris/x86
	 * is done by the kernel startup itself, in hat_unload_prom()
	 * after the bootloader has been quiesced.
	 *
	 * Solaris on sparc has a prom_free() routine that will update
	 *   the memlist properties to reflect the freeing of the
	 *   logbuffer. However, the sparc kernel cannot recover
	 *   the memory freed after the call to BOP_QUIESCE as the
	 *   page struct have already been allocated. We call
	 *   prom_free anyway so that the kernel can reclaim this
	 *   memory in the future.
	 */
	if (logbuffer == LOGBUF_BASEADDR)
		prom_free(logbuffer, elogbuffer-logbuffer);
	logbuffer = (caddr_t)NULL;
}

static caddr_t
lufs_alloc_from_logbuf(size_t sz)
{
	caddr_t tmpaddr;
	lb_me_t	*l;

	/*
	 * Satisfy lb_me_t allocations from the freelist
	 * first if possible.
	 */
	if ((sz == sizeof (lb_me_t)) && lfreelist) {
		l = lfreelist;
		lfreelist = lfreelist->l_next;
		return ((caddr_t)l);
	}
	if (elogbuffer < logbuf_curptr + sz) {
		caddr_t np;
		size_t nsz;

		/*
		 * Out of space in current chunk - try to add another.
		 */
		if (logbuffer == logbuffer_min) {
			np = LOGBUF_BASEADDR;
		} else {
			np = elogbuffer;
		}
		nsz = roundup(sz, PAGESIZE);
		if (np + nsz > LOGBUF_BASEADDR + LOGBUF_MAXSIZE) {
			return ((caddr_t)NULL);
		}

		np = resalloc(RES_CHILDVIRT, nsz, np, 0UL);
		if (np == (caddr_t)NULL) {
			return ((caddr_t)NULL);
		}
		if (logbuffer == logbuffer_min)
			logbuffer = LOGBUF_BASEADDR;
		logbuf_curptr = np;
		elogbuffer = logbuf_curptr + nsz;
	}

	tmpaddr = logbuf_curptr;
	logbuf_curptr += sz;
	bzero(tmpaddr, sz);
	return (tmpaddr);
}

static int32_t
lufs_read_log(int32_t addr, caddr_t va, int nb)
{
	int		i, fastpath = 0;
	daddr_t		pblk, lblk;
	sect_trailer_t	*st;
	uint32_t	ident;

	/*
	 * Fast path for skipping the read if no target buffer
	 * is specified. Don't do this for the initial scan.
	 */
	if (ufs_is_lufs && (va == (caddr_t)NULL))
		fastpath = 1;

	while (nb) {
		/* log wraparound check */
		if (addr == odi.od_eol_lof)
			addr = odi.od_bol_lof;
		if (fastpath)
			goto read_done;

		/*
		 * Translate logically-contiguous log offsets into physical
		 * block numbers. For a log consisting of a single extent:
		 *	pbno = btodb(addr) - extents[0].lbno;
		 * Otherwise, search for the extent which contains addr.
		 */
		pblk = 0;
		lblk = btodb(addr);
		for (i = 0; i < eb->nextents; i++) {
			if (lblk >= eb->extents[i].lbno &&
			    lblk < eb->extents[i].lbno +
			    eb->extents[i].nbno) {
				pblk = lblk - eb->extents[i].lbno +
				    eb->extents[i].pbno;
				break;
			}
		}

		if (pblk == 0) {
			/*
			 * block #0 can never be in a log extent since this
			 * block always contains the primary superblock copy.
			 */
			dprintf("No log extent found for log offset 0x%llx.\n",
			    addr);
			return (0);
		}

		/*
		 * Check whether the block we want is cached from the last
		 * read. If not, read it in now.
		 */
		if (logfp->fi_blocknum != pblk) {
			logfp->fi_blocknum = pblk;
			logfp->fi_memp = logfp->fi_buf;
			logfp->fi_count = DEV_BSIZE;
			logfp->fi_offset = 0;
			if (diskread(logfp)) {
				dprintf("I/O error reading the ufs log" \
				    " at block 0x%x.\n",
				    logfp->fi_blocknum);
				return (0);
			}
			/*
			 * Log structure verification. The block which we just
			 * read has an ident number that must match its offset
			 * in blocks from the head of the log. Since the log
			 * can wrap around, we have to check for that to get the
			 * ident right. Out-of-sequence idents can happen after
			 * power failures, panics during a partial transaction,
			 * media errors, ... - in any case, they mark the end of
			 * the valid part of the log.
			 */
			st = (sect_trailer_t *)(logfp->fi_memp +
			    LDL_USABLE_BSIZE);
			/* od_head_ident is where the sequence starts */
			ident = odi.od_head_ident;
			if (lblk >= lbtodb(odi.od_head_lof)) {
				/* no wraparound */
				ident += (lblk - lbtodb(odi.od_head_lof));
			} else {
				/* log wrapped around the end */
				ident += (lbtodb(odi.od_eol_lof) -
				    lbtodb(odi.od_head_lof));
				ident += (lblk - lbtodb(odi.od_bol_lof));
			}

			if (ident != st->st_ident)
				return (0);
		}
read_done:
		/*
		 * Copy the delta contents to the destination buffer if
		 * one was specified. Otherwise, just skip the contents.
		 */
		i = MIN(NB_LEFT_IN_SECTOR(addr), nb);
		if (va != NULL) {
			bcopy(logfp->fi_buf + (addr - ldbtob(lbtodb(addr))),
			    va, i);
			va += i;
		}
		nb -= i;
		addr += i;
		/*
		 * Skip sector trailer if necessary.
		 */
		if (NB_LEFT_IN_SECTOR(addr) == 0)
			addr += sizeof (sect_trailer_t);
	}
	return (addr);
}

void
lufs_boot_init(fileid_t *filep)
{
	struct fs *sb = (struct fs *)filep->fi_memp;
	int err = 0;

	/*
	 * boot_ufs_mountroot() should have called us with a
	 * filep pointing to the superblock. Verify that this
	 * is so first.
	 * Then check whether this filesystem has a dirty log.
	 * Also return if lufs support was disabled on request.
	 */
	if (!lufs_support ||
	    sb != (struct fs *)&filep->fi_devp->un_fs.di_fs ||
	    sb->fs_clean != FSLOG || sb->fs_logbno == 0) {
		return;
	}

	if (boothowto & RB_VERBOSE)
		printf("The boot filesystem is logging.\n");

	/*
	 * The filesystem is logging, there is a log area
	 * allocated for it. Check the log state and determine
	 * whether it'll be possible to use this log.
	 */

	/*
	 * Allocate a private fileid_t for use when reading
	 * from the log.
	 */
	eb = (extent_block_t *)bkmem_zalloc(sb->fs_bsize);
	logfp = (fileid_t *)bkmem_zalloc(sizeof (fileid_t));
	logfp->fi_memp = logfp->fi_buf;
	logfp->fi_devp = filep->fi_devp;

	/*
	 * Read the extent block and verify that what we
	 * find there are actually lufs extents.
	 * Make it simple: the extent block including all
	 * extents cannot be larger than a filesystem block.
	 * So read a whole filesystem block, to make sure
	 * we have read all extents in the same operation.
	 */
	logfp->fi_blocknum = sb->fs_logbno;
	logfp->fi_count = sb->fs_bsize;
	logfp->fi_memp = (caddr_t)eb;
	logfp->fi_offset = 0;
	if (diskread(logfp) || eb->type != LUFS_EXTENTS) {
		dprintf("Failed to read log extent block.\n");
		err = LOG_IS_ERRORED;
		goto out;
	}

	/*
	 * Read the on disk log header. If that fails,
	 * try the backup copy on the adjacent block.
	 */
	logfp->fi_blocknum = eb->extents[0].pbno;
	logfp->fi_count = sizeof (ml_odunit_t);
	logfp->fi_memp = (caddr_t)&odi;
	logfp->fi_offset = 0;
	if (diskread(logfp)) {
		logfp->fi_blocknum = eb->extents[0].pbno + 1;
		logfp->fi_count = sizeof (ml_odunit_t);
		logfp->fi_memp = (caddr_t)&odi;
		logfp->fi_offset = 0;
		if (diskread(logfp)) {
			dprintf("Failed to read on-disk log header.\n");
			err = LOG_IS_ERRORED;
			goto out;
		}
	}

	/*
	 * Verify that we understand this log, and
	 * that the log isn't bad or empty.
	 */
	if (odi.od_version != LUFS_VERSION_LATEST) {
		dprintf("On-disk log format v%d != supported format v%d.\n",
		    odi.od_version, LUFS_VERSION_LATEST);
		err = LOG_IS_ERRORED;
	} else if (odi.od_badlog) {
		dprintf("On-disk log is marked bad.\n");
		err = LOG_IS_ERRORED;
	} else if (odi.od_chksum != odi.od_head_ident + odi.od_tail_ident) {
		dprintf("On-disk log checksum %d != ident sum %d.\n",
		    odi.od_chksum, odi.od_head_ident + odi.od_tail_ident);
		err = LOG_IS_ERRORED;
	} else {
		/*
		 * All consistency checks ok. Scan the log, build the
		 * log hash. If this succeeds we'll be using the log
		 * when reading from this filesystem.
		 */
		err = lufs_logscan();
	}
out:
	ufs_is_lufs = 1;
	switch (err) {
	case LOG_IS_EMPTY:
		if (boothowto & RB_VERBOSE)
			printf("The ufs log is empty and will not be used.\n");
		lufs_closeall();
		break;
	case LOG_IS_OK:
		if (boothowto & RB_VERBOSE)
			printf("Using the ufs log.\n");
		break;
	case LOG_IS_ERRORED:
		if (boothowto & RB_VERBOSE)
			printf("Couldn't build log hash. Can't use ufs log.\n");
		lufs_closeall();
		break;
	default:
		dprintf("Invalid error %d while scanning the ufs log.\n", err);
		break;
	}
}

static int
lufs_logscan_read(int32_t *addr, struct delta *d)
{
	*addr = lufs_read_log(*addr, (caddr_t)d, sizeof (struct delta));

	if (*addr == 0 ||
	    (int)d->d_typ < DT_NONE || d->d_typ > DT_MAX ||
	    d->d_nb >= odi.od_logsize)
		return (0);

	return (1);
}

static int
lufs_logscan_skip(int32_t *addr, struct delta *d)
{
	switch (d->d_typ) {
	case DT_COMMIT:
		/*
		 * A DT_COMMIT delta has no size as such, but will
		 * always "fill up" the sector that contains it.
		 * The next delta header is found at the beginning
		 * of the next 512-Bytes sector, adjust "addr" to
		 * reflect that.
		 */
		*addr += ((*addr & (DEV_BSIZE - 1))) ?
		    NB_LEFT_IN_SECTOR(*addr) +
		    sizeof (sect_trailer_t) : 0;
		return (1);
	case DT_CANCEL:
	case DT_ABZERO:
		/*
		 * These types of deltas occupy no space in the log
		 */
		return (1);
	default:
		/*
		 * Skip over the delta contents.
		 */
		*addr = lufs_read_log(*addr, NULL, d->d_nb);
	}

	return (*addr != 0);
}

static void
lufs_logscan_freecancel(void)
{
	lb_me_t		**lh, *l, *lnext;
	int		i;

	/*
	 * Walk the entire log hash and put cancelled entries
	 * onto the freelist. Corner cases:
	 * a) empty hash chain (*lh == NULL)
	 * b) only one entry in chain, and that is cancelled.
	 *    If for every cancelled delta another one would've
	 *    been added, this situation couldn't occur, but a
	 *    DT_CANCEL delta can lead to this as it is never
	 *    added.
	 */
	for (i = 0; i < LB_HASHSIZE; i++) {
		lh = &loghash[i];
		l = *lh;
		do {
			if (*lh == (lb_me_t *)NULL)
				break;
			lnext = l->l_next;
			if (l->l_flags & LB_ISCANCELLED) {
				remlist(lh, l);
				bzero((caddr_t)l, sizeof (lb_me_t));
				l->l_next = lfreelist;
				lfreelist = l;
				/*
				 * Just removed the hash head. In order not
				 * to terminate the while loop, respin chain
				 * walk for this hash chain.
				 */
				if (lnext == *lh) {
					i--;
					break;
				}
			}
			l = lnext;
		} while (l != *lh);
	}
}

static int
lufs_logscan_addmap(int32_t *addr, struct delta *d)
{
	lb_me_t		**lh, *l;

	switch (d->d_typ) {
	case DT_COMMIT:
		/*
		 * Handling DT_COMMIT deltas is special. We need to:
		 * 1. increase the transaction ID
		 * 2. remove cancelled entries.
		 */
		lufs_logscan_freecancel();
		curtid++;
		break;
	case DT_INODE:
		/*
		 * Deltas against parts of on-disk inodes are
		 * assumed to be timestamps. Ignore those.
		 */
		if (d->d_nb != sizeof (struct dinode))
			break;
		/* FALLTHROUGH */
	case DT_CANCEL:
	case DT_ABZERO:
	case DT_AB:
	case DT_DIR:
	case DT_FBI:
		/*
		 * These types of deltas contain and/or modify structural
		 * information that is needed for booting the system:
		 * - where to find a file (DT_DIR, DT_FBI)
		 * - the file itself (DT_INODE)
		 * - data blocks associated with a file (DT_AB, DT_ABZERO)
		 *
		 * Building the hash chains becomes complicated because there
		 * may exist an older (== previously added) entry that overlaps
		 * with the one we want to add.
		 * Four cases must be distinguished:
		 * 1. The new delta is an exact match for an existing one,
		 *    or is a superset of an existing one, and both
		 *    belong to the same transaction.
		 *    The new delta completely supersedes the old one, so
		 *    remove that and reuse the structure for the new.
		 *    Then add the new delta to the head of the hashchain.
		 * 2. The new delta is an exact match for an existing one,
		 *    or is a superset of an existing one, but the two
		 *    belong to different transactions (i.e. the old one is
		 *    committed).
		 *    The existing one is marked to be cancelled when the
		 *    next DT_COMMIT record is found, and the hash chain
		 *    walk is continued as there may be more existing entries
		 *    found which overlap the new delta (happens if that is
		 *    a superset of those in the log).
		 *    Once no more overlaps are found, goto 4.
		 * 3. An existing entry completely covers the new one.
		 *    The new delta is then added directly before this
		 *    existing one.
		 * 4. No (more) overlaps with existing entries are found.
		 *    Unless this is a DT_CANCEL delta, whose only purpose
		 *    is already handled by marking overlapping entries for
		 *    cancellation, add the new delta at the hash chain head.
		 *
		 * This strategy makes sure that the hash chains are properly
		 * ordered. lufs_merge_deltas() walks the hash chain backward,
		 * which then ensures that delta merging is done in the same
		 * order as those deltas occur in the log - remember, the
		 * log can only be read in one direction.
		 *
		 */
		lh = &loghash[LB_HASHFUNC(d->d_mof)];
		l = *lh;
		do {
			if (l == (lb_me_t *)NULL)
				break;
			/*
			 * This covers the first two cases above.
			 * If this is a perfect match from the same transaction,
			 * and it isn't already cancelled, we simply replace it
			 * with its newer incarnation.
			 * Otherwise, mark it for cancellation. Handling of
			 * DT_COMMIT is going to remove it, then.
			 */
			if (WITHIN(l->l_mof, l->l_nb, d->d_mof, d->d_nb)) {
				if (!(l->l_flags & LB_ISCANCELLED)) {
					if (l->l_tid == curtid &&
					    d->d_typ != DT_CANCEL) {
						remlist(lh, l);
						l->l_mof = d->d_mof;
						l->l_lof = *addr;
						l->l_nb = d->d_nb;
						l->l_typ = d->d_typ;
						l->l_flags = 0;
						l->l_tid = curtid;
						inslist(lh, l);
						return (1);
					} else {
						/*
						 * 2nd case - cancel only.
						 */
						l->l_flags |= LB_ISCANCELLED;
					}
				}
			} else if (WITHIN(d->d_mof, d->d_nb,
			    l->l_mof, l->l_nb)) {
				/*
				 * This is the third case above.
				 * With deltas DT_ABZERO/DT_AB and DT_FBI/DT_DIR
				 * this may happen - an existing previous delta
				 * is larger than the current one we're planning
				 * to add - DT_ABZERO deltas are supersets of
				 * DT_AB deltas, and likewise DT_FBI/DT_DIR.
				 * In order to do merging correctly, such deltas
				 * put up a barrier for new ones that overlap,
				 * and we have to add the new delta immediately
				 * before (!) the existing one.
				 */
				lb_me_t *newl;
				newl = lufs_alloc_me();
				if (newl == (lb_me_t *)NULL) {
					/*
					 * No memory. Throw away everything
					 * and try booting without logging
					 * support.
					 */
					curtid = 0;
					return (0);
				}
				newl->l_mof = d->d_mof;
				newl->l_lof = *addr;	/* "payload" address */
				newl->l_nb = d->d_nb;
				newl->l_typ = d->d_typ;
				newl->l_tid = curtid;
				newl->l_prev = l->l_prev;
				newl->l_next = l;
				l->l_prev->l_next = newl;
				l->l_prev = newl;
				if (*lh == l)
					*lh = newl;
				return (1);
			}
			l = l->l_next;
		} while (l != *lh);

		/*
		 * This is case 4., add a new delta at the head of the chain.
		 *
		 * If the new delta is a DT_CANCEL entry, we handled it by
		 * marking everything it covered for cancellation. We can
		 * get by without actually adding the delta itself to the
		 * hash, as it'd need to be removed by the commit code anyway.
		 */
		if (d->d_typ == DT_CANCEL)
			break;

		l = lufs_alloc_me();
		if (l == (lb_me_t *)NULL) {
			/*
			 * No memory. Throw away everything
			 * and try booting without logging
			 * support.
			 */
			curtid = 0;
			return (0);
		}
		l->l_mof = d->d_mof;
		l->l_lof = *addr;	/* this is the "payload" address */
		l->l_nb = d->d_nb;
		l->l_typ = d->d_typ;
		l->l_tid = curtid;
		inslist(lh, l);
		break;
	default:
		break;
	}
	return (1);
}

static int
lufs_logscan_prescan(void)
{
	/*
	 * Simulate a full log by setting the tail to be one sector
	 * behind the head. This will make the logscan read all
	 * of the log until an out-of-sequence sector ident is
	 * found.
	 */
	odi.od_tail_lof = dbtob(btodb(odi.od_head_lof)) - DEV_BSIZE;
	if (odi.od_tail_lof < odi.od_bol_lof)
		odi.od_tail_lof = odi.od_eol_lof - DEV_BSIZE;
	if (odi.od_tail_lof >= odi.od_eol_lof)
		odi.od_tail_lof = odi.od_bol_lof;

	/*
	 * While sector trailers maintain TID values, od_head_tid
	 * is not being updated by the kernel ufs logging support
	 * at this time. We therefore count transactions ourselves
	 * starting at zero - as does the kernel ufs logscan code.
	 */
	curtid = 0;

	if (!lufs_alloc_logbuf()) {
		dprintf("Failed to allocate log buffer.\n");
		return (0);
	}

	loghash = (lb_me_t **)lufs_alloc_from_logbuf(
	    LB_HASHSIZE * sizeof (lb_me_t *));
	if (loghash == (lb_me_t **)NULL) {
		dprintf("Can't allocate loghash[] array.");
		return (0);
	}
	return (1);
}

/*
 * This function must remove all uncommitted entries (l->l_tid == curtid)
 * from the log hash. Doing this, we implicitly delete pending cancellations
 * as well.
 * It uses the same hash walk algorithm as lufs_logscan_freecancel(). Only
 * the check for entries that need to be removed is different.
 */
static void
lufs_logscan_postscan(void)
{
	lb_me_t	**lh, *l, *lnext;
	int	i;

	for (i = 0; i < LB_HASHSIZE; i++) {
		lh = &loghash[i];
		l = *lh;
		do {
			if (l == (lb_me_t *)NULL)
				break;
			lnext = l->l_next;
			if (l->l_tid == curtid) {
				remlist(lh, l);
				bzero((caddr_t)l, sizeof (lb_me_t));
				l->l_next = lfreelist;
				lfreelist = l;
				if (*lh == (lb_me_t *)NULL)
					break;
				/*
				 * Just removed the hash head. In order not
				 * to terminate the while loop, respin chain
				 * walk for this hash chain.
				 */
				if (lnext == *lh) {
					i--;
					break;
				}
			} else {
				l->l_flags &= ~(LB_ISCANCELLED);
			}
			l = lnext;
		} while (l != *lh);
	}
}

/*
 * This function builds the log hash. It performs the same sequence
 * of actions at logscan as the kernel ufs logging support:
 * - Prepare the log for scanning by simulating a full log.
 * - As long as sectors read from the log have contiguous idents, do:
 *	read the delta header
 *	add the delta to the logmap
 *	skip over the contents to the start of the next delta header
 * - After terminating the scan, remove uncommitted entries.
 *
 * This function cannot fail except if mapping the logbuffer area
 * during lufs_logscan_prescan() fails. If there is a structural
 * integrity problem and the on-disk log cannot be read, we'll
 * treat this as the same situation as an uncommitted transaction
 * at the end of the log (or, corner case of that, an empty log
 * with no committed transactions in it at all).
 *
 */
static int
lufs_logscan(void)
{
	int32_t		addr;
	struct delta	d;

	if (!lufs_logscan_prescan())
		return (LOG_IS_ERRORED);

	addr = odi.od_head_lof;

	/*
	 * Note that addr == od_tail_lof means a completely filled
	 * log. This almost never happens, so the common exit path
	 * from this loop is via one of the 'break's.
	 */
	while (addr != odi.od_tail_lof) {
		if (!lufs_logscan_read(&addr, &d))
			break;
		if (!lufs_logscan_addmap(&addr, &d))
			return (LOG_IS_ERRORED);
		if (!lufs_logscan_skip(&addr, &d))
			break;
	}

	lufs_logscan_postscan();
	/*
	 * Check whether the log contains data, and if so whether
	 * it contains committed data.
	 */
	if (addr == odi.od_head_lof || curtid == 0) {
		return (LOG_IS_EMPTY);
	}
	return (LOG_IS_OK);
}

/*
 * A metadata block was read from disk. Check whether the logmap
 * has a delta against this byte range, and if so read it in, since
 * the data in the log is more recent than what was read from other
 * places on the disk.
 */
void
lufs_merge_deltas(fileid_t *fp)
{
	int		nb;
	int64_t		bof;
	lb_me_t		**lh, *l;
	int32_t		skip;

	/*
	 * No logmap: Empty log. Nothing to do here.
	 */
	if (!ufs_is_lufs || logbuffer == (caddr_t)NULL)
		return;

	bof = ldbtob(fp->fi_blocknum);
	nb = fp->fi_count;

	/*
	 * Search the log hash.
	 * Merge deltas if an overlap is found.
	 */

	lh = &loghash[LB_HASHFUNC(bof)];

	if (*lh == (lb_me_t *)NULL)
		return;

	l = *lh;

	do {
		l = l->l_prev;
		if (OVERLAP(l->l_mof, l->l_nb, bof, nb)) {
			/*
			 * Found a delta in the log hash which overlaps
			 * with the current metadata block. Read the
			 * actual delta payload from the on-disk log
			 * directly into the file buffer.
			 */
			if (l->l_typ != DT_ABZERO) {
				/*
				 * We have to actually read this part of the
				 * log as it could contain a sector trailer, or
				 * wrap around the end of the log.
				 * If it did, the second offset generation would
				 * be incorrect if we'd started at l->l_lof.
				 */
				if (!(skip = lufs_read_log(l->l_lof, NULL,
				    MAX(bof - l->l_mof, 0))))
					dprintf("scan/merge error, pre-skip\n");
				if (!(skip = lufs_read_log(skip,
				    fp->fi_memp + MAX(l->l_mof - bof, 0),
				    MIN(l->l_mof + l->l_nb, bof + nb) -
				    MAX(l->l_mof, bof))))
					dprintf("scan/merge error, merge\n");
			} else {
				/*
				 * DT_ABZERO requires no disk access, just
				 * clear the byte range which overlaps with
				 * the delta.
				 */
				bzero(fp->fi_memp + MAX(l->l_mof - bof, 0),
				    MIN(l->l_mof + l->l_nb, bof + nb) -
				    MAX(l->l_mof, bof));
			}
		}
	} while (l->l_prev != (*lh)->l_prev);

	printf("*\b");
}

void
lufs_closeall(void)
{
	if (ufs_is_lufs) {
		bkmem_free((char *)eb, logfp->fi_devp->un_fs.di_fs.fs_bsize);
		bkmem_free((char *)logfp, sizeof (fileid_t));
		eb = (extent_block_t *)NULL;
		bzero((caddr_t)&odi, sizeof (ml_odunit_t));
		logfp = (fileid_t *)NULL;
		lufs_free_logbuf();
		ufs_is_lufs = 0;
	}
}
