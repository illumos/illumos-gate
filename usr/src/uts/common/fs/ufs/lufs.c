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

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/fssnap_if.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_filio.h>
#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/inttypes.h>
#include <sys/vfs.h>
#include <sys/mntent.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/kstat.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>

#define	LUFS_GENID_PRIME	UINT64_C(4294967291)
#define	LUFS_GENID_BASE		UINT64_C(311)
#define	LUFS_NEXT_ID(id)	((uint32_t)(((id) * LUFS_GENID_BASE) % \
				    LUFS_GENID_PRIME))

extern	kmutex_t	ufs_scan_lock;

static kmutex_t	log_mutex;	/* general purpose log layer lock */
kmutex_t	ml_scan;	/* Scan thread syncronization */
kcondvar_t	ml_scan_cv;	/* Scan thread syncronization */

struct kmem_cache	*lufs_sv;
struct kmem_cache	*lufs_bp;

/* Tunables */
uint_t		ldl_maxlogsize	= LDL_MAXLOGSIZE;
uint_t		ldl_minlogsize	= LDL_MINLOGSIZE;
uint_t		ldl_softlogcap	= LDL_SOFTLOGCAP;
uint32_t	ldl_divisor	= LDL_DIVISOR;
uint32_t	ldl_mintransfer	= LDL_MINTRANSFER;
uint32_t	ldl_maxtransfer	= LDL_MAXTRANSFER;
uint32_t	ldl_minbufsize	= LDL_MINBUFSIZE;
uint32_t	ldl_cgsizereq	= 0;

/* Generation of header ids */
static kmutex_t	genid_mutex;
static uint32_t	last_loghead_ident = UINT32_C(0);

/*
 * Logging delta and roll statistics
 */
struct delta_kstats {
	kstat_named_t ds_superblock_deltas;
	kstat_named_t ds_bitmap_deltas;
	kstat_named_t ds_suminfo_deltas;
	kstat_named_t ds_allocblk_deltas;
	kstat_named_t ds_ab0_deltas;
	kstat_named_t ds_dir_deltas;
	kstat_named_t ds_inode_deltas;
	kstat_named_t ds_fbiwrite_deltas;
	kstat_named_t ds_quota_deltas;
	kstat_named_t ds_shadow_deltas;

	kstat_named_t ds_superblock_rolled;
	kstat_named_t ds_bitmap_rolled;
	kstat_named_t ds_suminfo_rolled;
	kstat_named_t ds_allocblk_rolled;
	kstat_named_t ds_ab0_rolled;
	kstat_named_t ds_dir_rolled;
	kstat_named_t ds_inode_rolled;
	kstat_named_t ds_fbiwrite_rolled;
	kstat_named_t ds_quota_rolled;
	kstat_named_t ds_shadow_rolled;
} dkstats = {
	{ "superblock_deltas",	KSTAT_DATA_UINT64 },
	{ "bitmap_deltas",	KSTAT_DATA_UINT64 },
	{ "suminfo_deltas",	KSTAT_DATA_UINT64 },
	{ "allocblk_deltas",	KSTAT_DATA_UINT64 },
	{ "ab0_deltas",		KSTAT_DATA_UINT64 },
	{ "dir_deltas",		KSTAT_DATA_UINT64 },
	{ "inode_deltas",	KSTAT_DATA_UINT64 },
	{ "fbiwrite_deltas",	KSTAT_DATA_UINT64 },
	{ "quota_deltas",	KSTAT_DATA_UINT64 },
	{ "shadow_deltas",	KSTAT_DATA_UINT64 },

	{ "superblock_rolled",	KSTAT_DATA_UINT64 },
	{ "bitmap_rolled",	KSTAT_DATA_UINT64 },
	{ "suminfo_rolled",	KSTAT_DATA_UINT64 },
	{ "allocblk_rolled",	KSTAT_DATA_UINT64 },
	{ "ab0_rolled",		KSTAT_DATA_UINT64 },
	{ "dir_rolled",		KSTAT_DATA_UINT64 },
	{ "inode_rolled",	KSTAT_DATA_UINT64 },
	{ "fbiwrite_rolled",	KSTAT_DATA_UINT64 },
	{ "quota_rolled",	KSTAT_DATA_UINT64 },
	{ "shadow_rolled",	KSTAT_DATA_UINT64 }
};

uint64_t delta_stats[DT_MAX];
uint64_t roll_stats[DT_MAX];

/*
 * General logging kstats
 */
struct logstats logstats = {
	{ "master_reads",		KSTAT_DATA_UINT64 },
	{ "master_writes",		KSTAT_DATA_UINT64 },
	{ "log_reads_inmem",		KSTAT_DATA_UINT64 },
	{ "log_reads",			KSTAT_DATA_UINT64 },
	{ "log_writes",			KSTAT_DATA_UINT64 },
	{ "log_master_reads",		KSTAT_DATA_UINT64 },
	{ "log_roll_reads",		KSTAT_DATA_UINT64 },
	{ "log_roll_writes",		KSTAT_DATA_UINT64 }
};

int
trans_not_done(struct buf *cb)
{
	sema_v(&cb->b_io);
	return (0);
}

static void
trans_wait_panic(struct buf *cb)
{
	while ((cb->b_flags & B_DONE) == 0)
		drv_usecwait(10);
}

int
trans_not_wait(struct buf *cb)
{
	/*
	 * In case of panic, busy wait for completion
	 */
	if (panicstr)
		trans_wait_panic(cb);
	else
		sema_p(&cb->b_io);

	return (geterror(cb));
}

int
trans_wait(struct buf *cb)
{
	/*
	 * In case of panic, busy wait for completion and run md daemon queues
	 */
	if (panicstr)
		trans_wait_panic(cb);
	return (biowait(cb));
}

static void
setsum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t csum = 0;

	*sp = 0;
	nb /= sizeof (int32_t);
	while (nb--)
		csum += *lp++;
	*sp = csum;
}

static int
checksum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t ssum = *sp;

	setsum(sp, lp, nb);
	if (ssum != *sp) {
		*sp = ssum;
		return (0);
	}
	return (1);
}

void
lufs_unsnarf(ufsvfs_t *ufsvfsp)
{
	ml_unit_t *ul;
	mt_map_t *mtm;

	ul = ufsvfsp->vfs_log;
	if (ul == NULL)
		return;

	mtm = ul->un_logmap;

	/*
	 * Wait for a pending top_issue_sync which is
	 * dispatched (via taskq_dispatch()) but hasnt completed yet.
	 */

	mutex_enter(&mtm->mtm_lock);

	while (mtm->mtm_taskq_sync_count != 0) {
		cv_wait(&mtm->mtm_cv, &mtm->mtm_lock);
	}

	mutex_exit(&mtm->mtm_lock);

	/* Roll committed transactions */
	logmap_roll_dev(ul);

	/* Kill the roll thread */
	logmap_kill_roll(ul);

	/* release saved alloction info */
	if (ul->un_ebp)
		kmem_free(ul->un_ebp, ul->un_nbeb);

	/* release circular bufs */
	free_cirbuf(&ul->un_rdbuf);
	free_cirbuf(&ul->un_wrbuf);

	/* release maps */
	if (ul->un_logmap)
		ul->un_logmap = map_put(ul->un_logmap);
	if (ul->un_deltamap)
		ul->un_deltamap = map_put(ul->un_deltamap);
	if (ul->un_matamap)
		ul->un_matamap = map_put(ul->un_matamap);

	mutex_destroy(&ul->un_log_mutex);
	mutex_destroy(&ul->un_state_mutex);

	/* release state buffer MUST BE LAST!! (contains our ondisk data) */
	if (ul->un_bp)
		brelse(ul->un_bp);
	kmem_free(ul, sizeof (*ul));

	ufsvfsp->vfs_log = NULL;
}

int
lufs_snarf(ufsvfs_t *ufsvfsp, struct fs *fs, int ronly)
{
	buf_t		*bp, *tbp;
	ml_unit_t	*ul;
	extent_block_t	*ebp;
	ic_extent_block_t  *nebp;
	size_t		nb;
	daddr_t		bno;	/* in disk blocks */
	int		i;

	/* LINTED: warning: logical expression always true: op "||" */
	ASSERT(sizeof (ml_odunit_t) < DEV_BSIZE);

	/*
	 * Get the allocation table
	 *	During a remount the superblock pointed to by the ufsvfsp
	 *	is out of date.  Hence the need for the ``new'' superblock
	 *	pointer, fs, passed in as a parameter.
	 */
	bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, logbtodb(fs, fs->fs_logbno),
	    fs->fs_bsize);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return (EIO);
	}
	ebp = (void *)bp->b_un.b_addr;
	if (!checksum(&ebp->chksum, (int32_t *)bp->b_un.b_addr,
	    fs->fs_bsize)) {
		brelse(bp);
		return (ENODEV);
	}

	/*
	 * It is possible to get log blocks with all zeros.
	 * We should also check for nextents to be zero in such case.
	 */
	if (ebp->type != LUFS_EXTENTS || ebp->nextents == 0) {
		brelse(bp);
		return (EDOM);
	}
	/*
	 * Put allocation into memory.  This requires conversion between
	 * on the ondisk format of the extent (type extent_t) and the
	 * in-core format of the extent (type ic_extent_t).  The
	 * difference is the in-core form of the extent block stores
	 * the physical offset of the extent in disk blocks, which
	 * can require more than a 32-bit field.
	 */
	nb = (size_t)(sizeof (ic_extent_block_t) +
	    ((ebp->nextents - 1) * sizeof (ic_extent_t)));
	nebp = kmem_alloc(nb, KM_SLEEP);
	nebp->ic_nextents = ebp->nextents;
	nebp->ic_nbytes = ebp->nbytes;
	nebp->ic_nextbno = ebp->nextbno;
	for (i = 0; i < ebp->nextents; i++) {
		nebp->ic_extents[i].ic_lbno = ebp->extents[i].lbno;
		nebp->ic_extents[i].ic_nbno = ebp->extents[i].nbno;
		nebp->ic_extents[i].ic_pbno =
		    logbtodb(fs, ebp->extents[i].pbno);
	}
	brelse(bp);

	/*
	 * Get the log state
	 */
	bno = nebp->ic_extents[0].ic_pbno;
	bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, bno, DEV_BSIZE);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, bno + 1, DEV_BSIZE);
		if (bp->b_flags & B_ERROR) {
			brelse(bp);
			kmem_free(nebp, nb);
			return (EIO);
		}
	}

	/*
	 * Put ondisk struct into an anonymous buffer
	 *	This buffer will contain the memory for the ml_odunit struct
	 */
	tbp = ngeteblk(dbtob(LS_SECTORS));
	tbp->b_edev = bp->b_edev;
	tbp->b_dev = bp->b_dev;
	tbp->b_blkno = bno;
	bcopy(bp->b_un.b_addr, tbp->b_un.b_addr, DEV_BSIZE);
	bcopy(bp->b_un.b_addr, tbp->b_un.b_addr + DEV_BSIZE, DEV_BSIZE);
	bp->b_flags |= (B_STALE | B_AGE);
	brelse(bp);
	bp = tbp;

	/*
	 * Verify the log state
	 *
	 * read/only mounts w/bad logs are allowed.  umount will
	 * eventually roll the bad log until the first IO error.
	 * fsck will then repair the file system.
	 *
	 * read/write mounts with bad logs are not allowed.
	 *
	 */
	ul = (ml_unit_t *)kmem_zalloc(sizeof (*ul), KM_SLEEP);
	bcopy(bp->b_un.b_addr, &ul->un_ondisk, sizeof (ml_odunit_t));
	if ((ul->un_chksum != ul->un_head_ident + ul->un_tail_ident) ||
	    (ul->un_version != LUFS_VERSION_LATEST) ||
	    (!ronly && ul->un_badlog)) {
		kmem_free(ul, sizeof (*ul));
		brelse(bp);
		kmem_free(nebp, nb);
		return (EIO);
	}
	/*
	 * Initialize the incore-only fields
	 */
	if (ronly)
		ul->un_flags |= LDL_NOROLL;
	ul->un_bp = bp;
	ul->un_ufsvfs = ufsvfsp;
	ul->un_dev = ufsvfsp->vfs_dev;
	ul->un_ebp = nebp;
	ul->un_nbeb = nb;
	ul->un_maxresv = btodb(ul->un_logsize) * LDL_USABLE_BSIZE;
	ul->un_deltamap = map_get(ul, deltamaptype, DELTAMAP_NHASH);
	ul->un_logmap = map_get(ul, logmaptype, LOGMAP_NHASH);
	if (ul->un_debug & MT_MATAMAP)
		ul->un_matamap = map_get(ul, matamaptype, DELTAMAP_NHASH);
	mutex_init(&ul->un_log_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ul->un_state_mutex, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Aquire the ufs_scan_lock before linking the mtm data
	 * structure so that we keep ufs_sync() and ufs_update() away
	 * when they execute the ufs_scan_inodes() run while we're in
	 * progress of enabling/disabling logging.
	 */
	mutex_enter(&ufs_scan_lock);
	ufsvfsp->vfs_log = ul;

	/* remember the state of the log before the log scan */
	logmap_logscan(ul);
	mutex_exit(&ufs_scan_lock);

	/*
	 * Error during scan
	 *
	 * If this is a read/only mount; ignore the error.
	 * At a later time umount/fsck will repair the fs.
	 *
	 */
	if (ul->un_flags & LDL_ERROR) {
		if (!ronly) {
			/*
			 * Aquire the ufs_scan_lock before de-linking
			 * the mtm data structure so that we keep ufs_sync()
			 * and ufs_update() away when they execute the
			 * ufs_scan_inodes() run while we're in progress of
			 * enabling/disabling logging.
			 */
			mutex_enter(&ufs_scan_lock);
			lufs_unsnarf(ufsvfsp);
			mutex_exit(&ufs_scan_lock);
			return (EIO);
		}
		ul->un_flags &= ~LDL_ERROR;
	}
	if (!ronly)
		logmap_start_roll(ul);
	return (0);
}

uint32_t
lufs_hd_genid(const ml_unit_t *up)
{
	uint32_t id;

	mutex_enter(&genid_mutex);

	/*
	 * The formula below implements an exponential, modular sequence.
	 *
	 * ID(N) = (SEED * (BASE^N)) % PRIME
	 *
	 * The numbers will be pseudo random.  They depend on SEED, BASE, PRIME,
	 * but will sweep through almost all of the range 1....PRIME-1.
	 * Most  importantly  they  will  not  repeat  for PRIME-2 (4294967289)
	 * repetitions.  If they would repeat that  could possibly cause  hangs,
	 * panics at mount/umount and failed mount operations.
	 */
	id = LUFS_NEXT_ID(last_loghead_ident);

	/* Checking if new identity used already */
	if (up != NULL && up->un_head_ident == id) {
		DTRACE_PROBE1(head_ident_collision, uint32_t, id);

		/*
		 * The  following  preserves  the  algorithm  for  the fix  for
		 * "panic: free: freeing free frag, dev:0x2000000018, blk:34605,
		 * cg:26, ino:148071,".
		 * If  the header identities  un_head_ident  are  equal  to the
		 * present element  in the sequence,  the next element  of  the
		 * sequence is returned instead.
		 */
		id = LUFS_NEXT_ID(id);
	}

	last_loghead_ident = id;

	mutex_exit(&genid_mutex);

	return (id);
}

static void
lufs_genid_init(void)
{
	uint64_t seed;

	/* Initialization */
	mutex_init(&genid_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* Seed the algorithm */
	do {
		timestruc_t tv;

		gethrestime(&tv);

		seed = (tv.tv_nsec << 3);
		seed ^= tv.tv_sec;

		last_loghead_ident = (uint32_t)(seed % LUFS_GENID_PRIME);
	} while (last_loghead_ident == UINT32_C(0));
}

static int
lufs_initialize(
	ufsvfs_t *ufsvfsp,
	daddr_t bno,
	size_t nb,
	struct fiolog *flp)
{
	ml_odunit_t	*ud, *ud2;
	buf_t		*bp;

	/* LINTED: warning: logical expression always true: op "||" */
	ASSERT(sizeof (ml_odunit_t) < DEV_BSIZE);
	ASSERT(nb >= ldl_minlogsize);

	bp = UFS_GETBLK(ufsvfsp, ufsvfsp->vfs_dev, bno, dbtob(LS_SECTORS));
	bzero(bp->b_un.b_addr, bp->b_bcount);

	ud = (void *)bp->b_un.b_addr;
	ud->od_version = LUFS_VERSION_LATEST;
	ud->od_maxtransfer = MIN(ufsvfsp->vfs_iotransz, ldl_maxtransfer);
	if (ud->od_maxtransfer < ldl_mintransfer)
		ud->od_maxtransfer = ldl_mintransfer;
	ud->od_devbsize = DEV_BSIZE;

	ud->od_requestsize = flp->nbytes_actual;
	ud->od_statesize = dbtob(LS_SECTORS);
	ud->od_logsize = nb - ud->od_statesize;

	ud->od_statebno = INT32_C(0);

	ud->od_head_ident = lufs_hd_genid(NULL);
	ud->od_tail_ident = ud->od_head_ident;
	ud->od_chksum = ud->od_head_ident + ud->od_tail_ident;

	ud->od_bol_lof = dbtob(ud->od_statebno) + ud->od_statesize;
	ud->od_eol_lof = ud->od_bol_lof + ud->od_logsize;
	ud->od_head_lof = ud->od_bol_lof;
	ud->od_tail_lof = ud->od_bol_lof;

	ASSERT(lufs_initialize_debug(ud));

	ud2 = (void *)(bp->b_un.b_addr + DEV_BSIZE);
	bcopy(ud, ud2, sizeof (*ud));

	UFS_BWRITE2(ufsvfsp, bp);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return (EIO);
	}
	brelse(bp);

	return (0);
}

/*
 * Free log space
 *	Assumes the file system is write locked and is not logging
 */
static int
lufs_free(struct ufsvfs *ufsvfsp)
{
	int		error = 0, i, j;
	buf_t		*bp = NULL;
	extent_t	*ep;
	extent_block_t	*ebp;
	struct fs	*fs = ufsvfsp->vfs_fs;
	daddr_t		fno;
	int32_t		logbno;
	long		nfno;
	inode_t		*ip = NULL;
	char		clean;

	/*
	 * Nothing to free
	 */
	if (fs->fs_logbno == 0)
		return (0);

	/*
	 * Mark the file system as FSACTIVE and no log but honor the
	 * current value of fs_reclaim.  The reclaim thread could have
	 * been active when lufs_disable() was called and if fs_reclaim
	 * is reset to zero here it could lead to lost inodes.
	 */
	ufsvfsp->vfs_ulockfs.ul_sbowner = curthread;
	mutex_enter(&ufsvfsp->vfs_lock);
	clean = fs->fs_clean;
	logbno = fs->fs_logbno;
	fs->fs_clean = FSACTIVE;
	fs->fs_logbno = INT32_C(0);
	ufs_sbwrite(ufsvfsp);
	mutex_exit(&ufsvfsp->vfs_lock);
	ufsvfsp->vfs_ulockfs.ul_sbowner = (kthread_id_t)-1;
	if (ufsvfsp->vfs_bufp->b_flags & B_ERROR) {
		error = EIO;
		fs->fs_clean = clean;
		fs->fs_logbno = logbno;
		goto errout;
	}

	/*
	 * fetch the allocation block
	 *	superblock -> one block of extents -> log data
	 */
	bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, logbtodb(fs, logbno),
	    fs->fs_bsize);
	if (bp->b_flags & B_ERROR) {
		error = EIO;
		goto errout;
	}

	/*
	 * Free up the allocated space (dummy inode needed for free())
	 */
	ip = ufs_alloc_inode(ufsvfsp, UFSROOTINO);
	ebp = (void *)bp->b_un.b_addr;
	for (i = 0, ep = &ebp->extents[0]; i < ebp->nextents; ++i, ++ep) {
		fno = logbtofrag(fs, ep->pbno);
		nfno = dbtofsb(fs, ep->nbno);
		for (j = 0; j < nfno; j += fs->fs_frag, fno += fs->fs_frag)
			free(ip, fno, fs->fs_bsize, 0);
	}
	free(ip, logbtofrag(fs, logbno), fs->fs_bsize, 0);
	brelse(bp);
	bp = NULL;

	/*
	 * Push the metadata dirtied during the allocations
	 */
	ufsvfsp->vfs_ulockfs.ul_sbowner = curthread;
	sbupdate(ufsvfsp->vfs_vfs);
	ufsvfsp->vfs_ulockfs.ul_sbowner = (kthread_id_t)-1;
	bflush(ufsvfsp->vfs_dev);
	error = bfinval(ufsvfsp->vfs_dev, 0);
	if (error)
		goto errout;

	/*
	 * Free the dummy inode
	 */
	ufs_free_inode(ip);

	return (0);

errout:
	/*
	 * Free up all resources
	 */
	if (bp)
		brelse(bp);
	if (ip)
		ufs_free_inode(ip);
	return (error);
}

/*
 * Allocate log space
 *	Assumes the file system is write locked and is not logging
 */
static int
lufs_alloc(struct ufsvfs *ufsvfsp, struct fiolog *flp, size_t minb, cred_t *cr)
{
	int		error = 0;
	buf_t		*bp = NULL;
	extent_t	*ep, *nep;
	extent_block_t	*ebp;
	struct fs	*fs = ufsvfsp->vfs_fs;
	daddr_t		fno;	/* in frags */
	daddr_t		bno;	/* in disk blocks */
	int32_t		logbno = INT32_C(0);	/* will be fs_logbno */
	struct inode	*ip = NULL;
	size_t		nb = flp->nbytes_actual;
	size_t		tb = 0;

	/*
	 * Mark the file system as FSACTIVE
	 */
	ufsvfsp->vfs_ulockfs.ul_sbowner = curthread;
	mutex_enter(&ufsvfsp->vfs_lock);
	fs->fs_clean = FSACTIVE;
	ufs_sbwrite(ufsvfsp);
	mutex_exit(&ufsvfsp->vfs_lock);
	ufsvfsp->vfs_ulockfs.ul_sbowner = (kthread_id_t)-1;

	/*
	 * Allocate the allocation block (need dummy shadow inode;
	 * we use a shadow inode so the quota sub-system ignores
	 * the block allocations.)
	 *	superblock -> one block of extents -> log data
	 */
	ip = ufs_alloc_inode(ufsvfsp, UFSROOTINO);
	ip->i_mode = IFSHAD;		/* make the dummy a shadow inode */
	rw_enter(&ip->i_contents, RW_WRITER);
	fno = contigpref(ufsvfsp, nb + fs->fs_bsize, minb);
	error = alloc(ip, fno, fs->fs_bsize, &fno, cr);
	if (error)
		goto errout;
	bno = fsbtodb(fs, fno);

	bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, bno, fs->fs_bsize);
	if (bp->b_flags & B_ERROR) {
		error = EIO;
		goto errout;
	}

	ebp = (void *)bp->b_un.b_addr;
	ebp->type = LUFS_EXTENTS;
	ebp->nextbno = UINT32_C(0);
	ebp->nextents = UINT32_C(0);
	ebp->chksum = INT32_C(0);
	if (fs->fs_magic == FS_MAGIC)
		logbno = bno;
	else
		logbno = dbtofsb(fs, bno);

	/*
	 * Initialize the first extent
	 */
	ep = &ebp->extents[0];
	error = alloc(ip, fno + fs->fs_frag, fs->fs_bsize, &fno, cr);
	if (error)
		goto errout;
	bno = fsbtodb(fs, fno);

	ep->lbno = UINT32_C(0);
	if (fs->fs_magic == FS_MAGIC)
		ep->pbno = (uint32_t)bno;
	else
		ep->pbno = (uint32_t)fno;
	ep->nbno = (uint32_t)fsbtodb(fs, fs->fs_frag);
	ebp->nextents = UINT32_C(1);
	tb = fs->fs_bsize;
	nb -= fs->fs_bsize;

	while (nb) {
		error = alloc(ip, fno + fs->fs_frag, fs->fs_bsize, &fno, cr);
		if (error) {
			if (tb < minb)
				goto errout;
			error = 0;
			break;
		}
		bno = fsbtodb(fs, fno);
		if ((daddr_t)((logbtodb(fs, ep->pbno) + ep->nbno) == bno))
			ep->nbno += (uint32_t)(fsbtodb(fs, fs->fs_frag));
		else {
			nep = ep + 1;
			if ((caddr_t)(nep + 1) >
			    (bp->b_un.b_addr + fs->fs_bsize)) {
				free(ip, fno, fs->fs_bsize, 0);
				break;
			}
			nep->lbno = ep->lbno + ep->nbno;
			if (fs->fs_magic == FS_MAGIC)
				nep->pbno = (uint32_t)bno;
			else
				nep->pbno = (uint32_t)fno;
			nep->nbno = (uint32_t)(fsbtodb(fs, fs->fs_frag));
			ebp->nextents++;
			ep = nep;
		}
		tb += fs->fs_bsize;
		nb -= fs->fs_bsize;
	}

	if (tb < minb) {	/* Failed to reach minimum log size */
		error = ENOSPC;
		goto errout;
	}

	ebp->nbytes = (uint32_t)tb;
	setsum(&ebp->chksum, (int32_t *)bp->b_un.b_addr, fs->fs_bsize);
	UFS_BWRITE2(ufsvfsp, bp);
	if (bp->b_flags & B_ERROR) {
		error = EIO;
		goto errout;
	}
	/*
	 * Initialize the first two sectors of the log
	 */
	error = lufs_initialize(ufsvfsp, logbtodb(fs, ebp->extents[0].pbno),
	    tb, flp);
	if (error)
		goto errout;

	/*
	 * We are done initializing the allocation block and the log
	 */
	brelse(bp);
	bp = NULL;

	/*
	 * Update the superblock and push the dirty metadata
	 */
	ufsvfsp->vfs_ulockfs.ul_sbowner = curthread;
	sbupdate(ufsvfsp->vfs_vfs);
	ufsvfsp->vfs_ulockfs.ul_sbowner = (kthread_id_t)-1;
	bflush(ufsvfsp->vfs_dev);
	error = bfinval(ufsvfsp->vfs_dev, 1);
	if (error)
		goto errout;
	if (ufsvfsp->vfs_bufp->b_flags & B_ERROR) {
		error = EIO;
		goto errout;
	}

	/*
	 * Everything is safely on disk; update log space pointer in sb
	 */
	ufsvfsp->vfs_ulockfs.ul_sbowner = curthread;
	mutex_enter(&ufsvfsp->vfs_lock);
	fs->fs_logbno = (uint32_t)logbno;
	ufs_sbwrite(ufsvfsp);
	mutex_exit(&ufsvfsp->vfs_lock);
	ufsvfsp->vfs_ulockfs.ul_sbowner = (kthread_id_t)-1;

	/*
	 * Free the dummy inode
	 */
	rw_exit(&ip->i_contents);
	ufs_free_inode(ip);

	/* inform user of real log size */
	flp->nbytes_actual = tb;
	return (0);

errout:
	/*
	 * Free all resources
	 */
	if (bp)
		brelse(bp);
	if (logbno) {
		fs->fs_logbno = logbno;
		(void) lufs_free(ufsvfsp);
	}
	if (ip) {
		rw_exit(&ip->i_contents);
		ufs_free_inode(ip);
	}
	return (error);
}

/*
 * Disable logging
 */
int
lufs_disable(vnode_t *vp, struct fiolog *flp)
{
	int		error = 0;
	inode_t		*ip = VTOI(vp);
	ufsvfs_t	*ufsvfsp = ip->i_ufsvfs;
	struct fs	*fs = ufsvfsp->vfs_fs;
	struct lockfs	lf;
	struct ulockfs	*ulp;

	flp->error = FIOLOG_ENONE;

	/*
	 * Logging is already disabled; done
	 */
	if (fs->fs_logbno == 0 || ufsvfsp->vfs_log == NULL)
		return (0);

	/*
	 * Readonly file system
	 */
	if (fs->fs_ronly) {
		flp->error = FIOLOG_EROFS;
		return (0);
	}

	/*
	 * File system must be write locked to disable logging
	 */
	error = ufs_fiolfss(vp, &lf);
	if (error) {
		return (error);
	}
	if (!LOCKFS_IS_ULOCK(&lf)) {
		flp->error = FIOLOG_EULOCK;
		return (0);
	}
	lf.lf_lock = LOCKFS_WLOCK;
	lf.lf_flags = 0;
	lf.lf_comment = NULL;
	error = ufs_fiolfs(vp, &lf, 1);
	if (error) {
		flp->error = FIOLOG_EWLOCK;
		return (0);
	}

	if (ufsvfsp->vfs_log == NULL || fs->fs_logbno == 0)
		goto errout;

	/*
	 * WE ARE COMMITTED TO DISABLING LOGGING PAST THIS POINT
	 */

	/*
	 * Disable logging:
	 * Suspend the reclaim thread and force the delete thread to exit.
	 *	When a nologging mount has completed there may still be
	 *	work for reclaim to do so just suspend this thread until
	 *	it's [deadlock-] safe for it to continue.  The delete
	 *	thread won't be needed as ufs_iinactive() calls
	 *	ufs_delete() when logging is disabled.
	 * Freeze and drain reader ops.
	 *	Commit any outstanding reader transactions (ufs_flush).
	 *	Set the ``unmounted'' bit in the ufstrans struct.
	 *	If debug, remove metadata from matamap.
	 *	Disable matamap processing.
	 *	NULL the trans ops table.
	 *	Free all of the incore structs related to logging.
	 * Allow reader ops.
	 */
	ufs_thread_suspend(&ufsvfsp->vfs_reclaim);
	ufs_thread_exit(&ufsvfsp->vfs_delete);

	vfs_lock_wait(ufsvfsp->vfs_vfs);
	ulp = &ufsvfsp->vfs_ulockfs;
	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);
	(void) ufs_quiesce(ulp);

	(void) ufs_flush(ufsvfsp->vfs_vfs);

	TRANS_MATA_UMOUNT(ufsvfsp);
	ufsvfsp->vfs_domatamap = 0;

	/*
	 * Free all of the incore structs
	 * Aquire the ufs_scan_lock before de-linking the mtm data
	 * structure so that we keep ufs_sync() and ufs_update() away
	 * when they execute the ufs_scan_inodes() run while we're in
	 * progress of enabling/disabling logging.
	 */
	mutex_enter(&ufs_scan_lock);
	(void) lufs_unsnarf(ufsvfsp);
	mutex_exit(&ufs_scan_lock);

	atomic_dec_ulong(&ufs_quiesce_pend);
	mutex_exit(&ulp->ul_lock);
	vfs_setmntopt(ufsvfsp->vfs_vfs, MNTOPT_NOLOGGING, NULL, 0);
	vfs_unlock(ufsvfsp->vfs_vfs);

	fs->fs_rolled = FS_ALL_ROLLED;
	ufsvfsp->vfs_nolog_si = 0;

	/*
	 * Free the log space and mark the superblock as FSACTIVE
	 */
	(void) lufs_free(ufsvfsp);

	/*
	 * Allow the reclaim thread to continue.
	 */
	ufs_thread_continue(&ufsvfsp->vfs_reclaim);

	/*
	 * Unlock the file system
	 */
	lf.lf_lock = LOCKFS_ULOCK;
	lf.lf_flags = 0;
	error = ufs_fiolfs(vp, &lf, 1);
	if (error)
		flp->error = FIOLOG_ENOULOCK;

	return (0);

errout:
	lf.lf_lock = LOCKFS_ULOCK;
	lf.lf_flags = 0;
	(void) ufs_fiolfs(vp, &lf, 1);
	return (error);
}

/*
 * Enable logging
 */
int
lufs_enable(struct vnode *vp, struct fiolog *flp, cred_t *cr)
{
	int		error;
	int		reclaim;
	inode_t		*ip = VTOI(vp);
	ufsvfs_t	*ufsvfsp = ip->i_ufsvfs;
	struct fs	*fs;
	ml_unit_t	*ul;
	struct lockfs	lf;
	struct ulockfs	*ulp;
	vfs_t		*vfsp = ufsvfsp->vfs_vfs;
	uint64_t	tmp_nbytes_actual;
	uint64_t	cg_minlogsize;
	uint32_t	cgsize;
	static int	minlogsizewarn = 0;
	static int	maxlogsizewarn = 0;

	/*
	 * Check if logging is already enabled
	 */
	if (ufsvfsp->vfs_log) {
		flp->error = FIOLOG_ETRANS;
		/* for root ensure logging option is set */
		vfs_setmntopt(vfsp, MNTOPT_LOGGING, NULL, 0);
		return (0);
	}
	fs = ufsvfsp->vfs_fs;

	/*
	 * Come back here to recheck if we had to disable the log.
	 */
recheck:
	error = 0;
	reclaim = 0;
	flp->error = FIOLOG_ENONE;

	/*
	 * The size of the ufs log is determined using the following rules:
	 *
	 * 1) If no size is requested the log size is calculated as a
	 *    ratio of the total file system size. By default this is
	 *    1MB of log per 1GB of file system. This calculation is then
	 *    capped at the log size specified by ldl_softlogcap.
	 * 2) The log size requested may then be increased based on the
	 *    number of cylinder groups contained in the file system.
	 *    To prevent a hang the log has to be large enough to contain a
	 *    single transaction that alters every cylinder group in the file
	 *    system. This is calculated as cg_minlogsize.
	 * 3) Finally a check is made that the log size requested is within
	 *    the limits of ldl_minlogsize and ldl_maxlogsize.
	 */

	/*
	 * Adjust requested log size
	 */
	flp->nbytes_actual = flp->nbytes_requested;
	if (flp->nbytes_actual == 0) {
		tmp_nbytes_actual =
		    (((uint64_t)fs->fs_size) / ldl_divisor) << fs->fs_fshift;
		flp->nbytes_actual = (uint_t)MIN(tmp_nbytes_actual, INT_MAX);
		/*
		 * The 1MB per 1GB log size allocation only applies up to
		 * ldl_softlogcap size of log.
		 */
		flp->nbytes_actual = MIN(flp->nbytes_actual, ldl_softlogcap);
	}

	cgsize = ldl_cgsizereq ? ldl_cgsizereq : LDL_CGSIZEREQ(fs);

	/*
	 * Determine the log size required based on the number of cylinder
	 * groups in the file system. The log has to be at least this size
	 * to prevent possible hangs due to log space exhaustion.
	 */
	cg_minlogsize = cgsize * fs->fs_ncg;

	/*
	 * Ensure that the minimum log size isn't so small that it could lead
	 * to a full log hang.
	 */
	if (ldl_minlogsize < LDL_MINLOGSIZE) {
		ldl_minlogsize = LDL_MINLOGSIZE;
		if (!minlogsizewarn) {
			cmn_err(CE_WARN, "ldl_minlogsize too small, increasing "
			    "to 0x%x", LDL_MINLOGSIZE);
			minlogsizewarn = 1;
		}
	}

	/*
	 * Ensure that the maximum log size isn't greater than INT_MAX as the
	 * logical log offset fields would overflow.
	 */
	if (ldl_maxlogsize > INT_MAX) {
		ldl_maxlogsize = INT_MAX;
		if (!maxlogsizewarn) {
			cmn_err(CE_WARN, "ldl_maxlogsize too large, reducing "
			    "to 0x%x", INT_MAX);
			maxlogsizewarn = 1;
		}
	}

	if (cg_minlogsize > ldl_maxlogsize) {
		cmn_err(CE_WARN,
		    "%s: reducing calculated log size from 0x%x to "
		    "ldl_maxlogsize (0x%x).", fs->fs_fsmnt, (int)cg_minlogsize,
		    ldl_maxlogsize);
	}

	cg_minlogsize = MAX(cg_minlogsize, ldl_minlogsize);
	cg_minlogsize = MIN(cg_minlogsize, ldl_maxlogsize);

	flp->nbytes_actual = MAX(flp->nbytes_actual, cg_minlogsize);
	flp->nbytes_actual = MAX(flp->nbytes_actual, ldl_minlogsize);
	flp->nbytes_actual = MIN(flp->nbytes_actual, ldl_maxlogsize);
	flp->nbytes_actual = blkroundup(fs, flp->nbytes_actual);

	/*
	 * logging is enabled and the log is the right size; done
	 */
	ul = ufsvfsp->vfs_log;
	if (ul && fs->fs_logbno && (flp->nbytes_actual == ul->un_requestsize))
			return (0);

	/*
	 * Readonly file system
	 */
	if (fs->fs_ronly) {
		flp->error = FIOLOG_EROFS;
		return (0);
	}

	/*
	 * File system must be write locked to enable logging
	 */
	error = ufs_fiolfss(vp, &lf);
	if (error) {
		return (error);
	}
	if (!LOCKFS_IS_ULOCK(&lf)) {
		flp->error = FIOLOG_EULOCK;
		return (0);
	}
	lf.lf_lock = LOCKFS_WLOCK;
	lf.lf_flags = 0;
	lf.lf_comment = NULL;
	error = ufs_fiolfs(vp, &lf, 1);
	if (error) {
		flp->error = FIOLOG_EWLOCK;
		return (0);
	}

	/*
	 * Grab appropriate locks to synchronize with the rest
	 * of the system
	 */
	vfs_lock_wait(vfsp);
	ulp = &ufsvfsp->vfs_ulockfs;
	mutex_enter(&ulp->ul_lock);

	/*
	 * File system must be fairly consistent to enable logging
	 */
	if (fs->fs_clean != FSLOG &&
	    fs->fs_clean != FSACTIVE &&
	    fs->fs_clean != FSSTABLE &&
	    fs->fs_clean != FSCLEAN) {
		flp->error = FIOLOG_ECLEAN;
		goto unlockout;
	}

	/*
	 * A write-locked file system is only active if there are
	 * open deleted files; so remember to set FS_RECLAIM later.
	 */
	if (fs->fs_clean == FSACTIVE)
		reclaim = FS_RECLAIM;

	/*
	 * Logging is already enabled; must be changing the log's size
	 */
	if (fs->fs_logbno && ufsvfsp->vfs_log) {
		/*
		 * Before we can disable logging, we must give up our
		 * lock.  As a consequence of unlocking and disabling the
		 * log, the fs structure may change.  Because of this, when
		 * disabling is complete, we will go back to recheck to
		 * repeat all of the checks that we performed to get to
		 * this point.  Disabling sets fs->fs_logbno to 0, so this
		 * will not put us into an infinite loop.
		 */
		mutex_exit(&ulp->ul_lock);
		vfs_unlock(vfsp);

		lf.lf_lock = LOCKFS_ULOCK;
		lf.lf_flags = 0;
		error = ufs_fiolfs(vp, &lf, 1);
		if (error) {
			flp->error = FIOLOG_ENOULOCK;
			return (0);
		}
		error = lufs_disable(vp, flp);
		if (error || (flp->error != FIOLOG_ENONE))
			return (0);
		goto recheck;
	}

	error = lufs_alloc(ufsvfsp, flp, cg_minlogsize, cr);
	if (error)
		goto errout;

	/*
	 * Create all of the incore structs
	 */
	error = lufs_snarf(ufsvfsp, fs, 0);
	if (error)
		goto errout;

	/*
	 * DON'T ``GOTO ERROUT'' PAST THIS POINT
	 */

	/*
	 * Pretend we were just mounted with logging enabled
	 *		Get the ops vector
	 *		If debug, record metadata locations with log subsystem
	 *		Start the delete thread
	 *		Start the reclaim thread, if necessary
	 */
	vfs_setmntopt(vfsp, MNTOPT_LOGGING, NULL, 0);

	TRANS_DOMATAMAP(ufsvfsp);
	TRANS_MATA_MOUNT(ufsvfsp);
	TRANS_MATA_SI(ufsvfsp, fs);
	ufs_thread_start(&ufsvfsp->vfs_delete, ufs_thread_delete, vfsp);
	if (fs->fs_reclaim & (FS_RECLAIM|FS_RECLAIMING)) {
		fs->fs_reclaim &= ~FS_RECLAIM;
		fs->fs_reclaim |=  FS_RECLAIMING;
		ufs_thread_start(&ufsvfsp->vfs_reclaim,
		    ufs_thread_reclaim, vfsp);
	} else
		fs->fs_reclaim |= reclaim;

	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vfsp);

	/*
	 * Unlock the file system
	 */
	lf.lf_lock = LOCKFS_ULOCK;
	lf.lf_flags = 0;
	error = ufs_fiolfs(vp, &lf, 1);
	if (error) {
		flp->error = FIOLOG_ENOULOCK;
		return (0);
	}

	/*
	 * There's nothing in the log yet (we've just allocated it)
	 * so directly write out the super block.
	 * Note, we have to force this sb out to disk
	 * (not just to the log) so that if we crash we know we are logging
	 */
	mutex_enter(&ufsvfsp->vfs_lock);
	fs->fs_clean = FSLOG;
	fs->fs_rolled = FS_NEED_ROLL; /* Mark the fs as unrolled */
	UFS_BWRITE2(NULL, ufsvfsp->vfs_bufp);
	mutex_exit(&ufsvfsp->vfs_lock);

	return (0);

errout:
	/*
	 * Aquire the ufs_scan_lock before de-linking the mtm data
	 * structure so that we keep ufs_sync() and ufs_update() away
	 * when they execute the ufs_scan_inodes() run while we're in
	 * progress of enabling/disabling logging.
	 */
	mutex_enter(&ufs_scan_lock);
	(void) lufs_unsnarf(ufsvfsp);
	mutex_exit(&ufs_scan_lock);

	(void) lufs_free(ufsvfsp);
unlockout:
	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vfsp);

	lf.lf_lock = LOCKFS_ULOCK;
	lf.lf_flags = 0;
	(void) ufs_fiolfs(vp, &lf, 1);
	return (error);
}

void
lufs_read_strategy(ml_unit_t *ul, buf_t *bp)
{
	mt_map_t	*logmap	= ul->un_logmap;
	offset_t	mof	= ldbtob(bp->b_blkno);
	off_t		nb	= bp->b_bcount;
	mapentry_t	*age;
	char		*va;
	int		(*saviodone)();
	int		entire_range;

	/*
	 * get a linked list of overlapping deltas
	 * returns with &mtm->mtm_rwlock held
	 */
	entire_range = logmap_list_get(logmap, mof, nb, &age);

	/*
	 * no overlapping deltas were found; read master
	 */
	if (age == NULL) {
		rw_exit(&logmap->mtm_rwlock);
		if (ul->un_flags & LDL_ERROR) {
			bp->b_flags |= B_ERROR;
			bp->b_error = EIO;
			biodone(bp);
		} else {
			ul->un_ufsvfs->vfs_iotstamp = ddi_get_lbolt();
			logstats.ls_lreads.value.ui64++;
			(void) bdev_strategy(bp);
			lwp_stat_update(LWP_STAT_INBLK, 1);
		}
		return;
	}

	va = bp_mapin_common(bp, VM_SLEEP);
	/*
	 * if necessary, sync read the data from master
	 *	errors are returned in bp
	 */
	if (!entire_range) {
		saviodone = bp->b_iodone;
		bp->b_iodone = trans_not_done;
		logstats.ls_mreads.value.ui64++;
		(void) bdev_strategy(bp);
		lwp_stat_update(LWP_STAT_INBLK, 1);
		if (trans_not_wait(bp))
			ldl_seterror(ul, "Error reading master");
		bp->b_iodone = saviodone;
	}

	/*
	 * sync read the data from the log
	 *	errors are returned inline
	 */
	if (ldl_read(ul, va, mof, nb, age)) {
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
	}

	/*
	 * unlist the deltas
	 */
	logmap_list_put(logmap, age);

	/*
	 * all done
	 */
	if (ul->un_flags & LDL_ERROR) {
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
	}
	biodone(bp);
}

void
lufs_write_strategy(ml_unit_t *ul, buf_t *bp)
{
	offset_t	mof	= ldbtob(bp->b_blkno);
	off_t		nb	= bp->b_bcount;
	char		*va;
	mapentry_t	*me;

	ASSERT((nb & DEV_BMASK) == 0);
	ul->un_logmap->mtm_ref = 1;

	/*
	 * if there are deltas, move into log
	 */
	me = deltamap_remove(ul->un_deltamap, mof, nb);
	if (me) {

		va = bp_mapin_common(bp, VM_SLEEP);

		ASSERT(((ul->un_debug & MT_WRITE_CHECK) == 0) ||
		    (ul->un_matamap == NULL)||
		    matamap_within(ul->un_matamap, mof, nb));

		/*
		 * move to logmap
		 */
		if (ufs_crb_enable) {
			logmap_add_buf(ul, va, mof, me,
			    bp->b_un.b_addr, nb);
		} else {
			logmap_add(ul, va, mof, me);
		}

		if (ul->un_flags & LDL_ERROR) {
			bp->b_flags |= B_ERROR;
			bp->b_error = EIO;
		}
		biodone(bp);
		return;
	}
	if (ul->un_flags & LDL_ERROR) {
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
		biodone(bp);
		return;
	}

	/*
	 * Check that we are not updating metadata, or if so then via B_PHYS.
	 */
	ASSERT((ul->un_matamap == NULL) ||
	    !(matamap_overlap(ul->un_matamap, mof, nb) &&
	    ((bp->b_flags & B_PHYS) == 0)));

	ul->un_ufsvfs->vfs_iotstamp = ddi_get_lbolt();
	logstats.ls_lwrites.value.ui64++;

	/* If snapshots are enabled, write through the snapshot driver */
	if (ul->un_ufsvfs->vfs_snapshot)
		fssnap_strategy(&ul->un_ufsvfs->vfs_snapshot, bp);
	else
		(void) bdev_strategy(bp);

	lwp_stat_update(LWP_STAT_OUBLK, 1);
}

void
lufs_strategy(ml_unit_t *ul, buf_t *bp)
{
	if (bp->b_flags & B_READ)
		lufs_read_strategy(ul, bp);
	else
		lufs_write_strategy(ul, bp);
}

/* ARGSUSED */
static int
delta_stats_update(kstat_t *ksp, int rw)
{
	if (rw == KSTAT_WRITE) {
		delta_stats[DT_SB] = dkstats.ds_superblock_deltas.value.ui64;
		delta_stats[DT_CG] = dkstats.ds_bitmap_deltas.value.ui64;
		delta_stats[DT_SI] = dkstats.ds_suminfo_deltas.value.ui64;
		delta_stats[DT_AB] = dkstats.ds_allocblk_deltas.value.ui64;
		delta_stats[DT_ABZERO] = dkstats.ds_ab0_deltas.value.ui64;
		delta_stats[DT_DIR] = dkstats.ds_dir_deltas.value.ui64;
		delta_stats[DT_INODE] = dkstats.ds_inode_deltas.value.ui64;
		delta_stats[DT_FBI] = dkstats.ds_fbiwrite_deltas.value.ui64;
		delta_stats[DT_QR] = dkstats.ds_quota_deltas.value.ui64;
		delta_stats[DT_SHAD] = dkstats.ds_shadow_deltas.value.ui64;

		roll_stats[DT_SB] = dkstats.ds_superblock_rolled.value.ui64;
		roll_stats[DT_CG] = dkstats.ds_bitmap_rolled.value.ui64;
		roll_stats[DT_SI] = dkstats.ds_suminfo_rolled.value.ui64;
		roll_stats[DT_AB] = dkstats.ds_allocblk_rolled.value.ui64;
		roll_stats[DT_ABZERO] = dkstats.ds_ab0_rolled.value.ui64;
		roll_stats[DT_DIR] = dkstats.ds_dir_rolled.value.ui64;
		roll_stats[DT_INODE] = dkstats.ds_inode_rolled.value.ui64;
		roll_stats[DT_FBI] = dkstats.ds_fbiwrite_rolled.value.ui64;
		roll_stats[DT_QR] = dkstats.ds_quota_rolled.value.ui64;
		roll_stats[DT_SHAD] = dkstats.ds_shadow_rolled.value.ui64;
	} else {
		dkstats.ds_superblock_deltas.value.ui64 = delta_stats[DT_SB];
		dkstats.ds_bitmap_deltas.value.ui64 = delta_stats[DT_CG];
		dkstats.ds_suminfo_deltas.value.ui64 = delta_stats[DT_SI];
		dkstats.ds_allocblk_deltas.value.ui64 = delta_stats[DT_AB];
		dkstats.ds_ab0_deltas.value.ui64 = delta_stats[DT_ABZERO];
		dkstats.ds_dir_deltas.value.ui64 = delta_stats[DT_DIR];
		dkstats.ds_inode_deltas.value.ui64 = delta_stats[DT_INODE];
		dkstats.ds_fbiwrite_deltas.value.ui64 = delta_stats[DT_FBI];
		dkstats.ds_quota_deltas.value.ui64 = delta_stats[DT_QR];
		dkstats.ds_shadow_deltas.value.ui64 = delta_stats[DT_SHAD];

		dkstats.ds_superblock_rolled.value.ui64 = roll_stats[DT_SB];
		dkstats.ds_bitmap_rolled.value.ui64 = roll_stats[DT_CG];
		dkstats.ds_suminfo_rolled.value.ui64 = roll_stats[DT_SI];
		dkstats.ds_allocblk_rolled.value.ui64 = roll_stats[DT_AB];
		dkstats.ds_ab0_rolled.value.ui64 = roll_stats[DT_ABZERO];
		dkstats.ds_dir_rolled.value.ui64 = roll_stats[DT_DIR];
		dkstats.ds_inode_rolled.value.ui64 = roll_stats[DT_INODE];
		dkstats.ds_fbiwrite_rolled.value.ui64 = roll_stats[DT_FBI];
		dkstats.ds_quota_rolled.value.ui64 = roll_stats[DT_QR];
		dkstats.ds_shadow_rolled.value.ui64 = roll_stats[DT_SHAD];
	}
	return (0);
}

extern size_t ufs_crb_limit;
extern int ufs_max_crb_divisor;

void
lufs_init(void)
{
	kstat_t *ksp;

	/* Create kmem caches */
	lufs_sv = kmem_cache_create("lufs_save", sizeof (lufs_save_t), 0,
	    NULL, NULL, NULL, NULL, NULL, 0);
	lufs_bp = kmem_cache_create("lufs_bufs", sizeof (lufs_buf_t), 0,
	    NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&log_mutex, NULL, MUTEX_DEFAULT, NULL);

	_init_top();

	if (bio_lufs_strategy == NULL)
		bio_lufs_strategy = (void (*) (void *, buf_t *)) lufs_strategy;

	/*
	 * Initialise general logging and delta kstats
	 */
	ksp = kstat_create("ufs_log", 0, "logstats", "ufs", KSTAT_TYPE_NAMED,
	    sizeof (logstats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &logstats;
		kstat_install(ksp);
	}

	ksp = kstat_create("ufs_log", 0, "deltastats", "ufs", KSTAT_TYPE_NAMED,
	    sizeof (dkstats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &dkstats;
		ksp->ks_update = delta_stats_update;
		kstat_install(ksp);
	}

	/* Initialize  generation of logging ids */
	lufs_genid_init();

	/*
	 * Set up the maximum amount of kmem that the crbs (system wide)
	 * can use.
	 */
	ufs_crb_limit = kmem_maxavail() / ufs_max_crb_divisor;
}
