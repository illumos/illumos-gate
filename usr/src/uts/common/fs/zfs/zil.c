/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/arc.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/zil.h>
#include <sys/zil_impl.h>
#include <sys/dsl_dataset.h>
#include <sys/vdev.h>

/*
 * The zfs intent log (ZIL) saves transaction records of system calls
 * that change the file system in memory with enough information
 * to be able to replay them. These are stored in memory until
 * either the DMU transaction group (txg) commits them to the stable pool
 * and they can be discarded, or they are flushed to the stable log
 * (also in the pool) due to a fsync, O_DSYNC or other synchronous
 * requirement. In the event of a panic or power fail then those log
 * records (transactions) are replayed.
 *
 * There is one ZIL per file system. Its on-disk (pool) format consists
 * of 3 parts:
 *
 * 	- ZIL header
 * 	- ZIL blocks
 * 	- ZIL records
 *
 * A log record holds a system call transaction. Log blocks can
 * hold many log records and the blocks are chained together.
 * Each ZIL block contains a block pointer (blkptr_t) to the next
 * ZIL block in the chain. The ZIL header points to the first
 * block in the chain. Note there is not a fixed place in the pool
 * to hold blocks. They are dynamically allocated and freed as
 * needed from the blocks available. Figure X shows the ZIL structure:
 */

/*
 * These global ZIL switches affect all pools
 */
int zil_disable = 0;	/* disable intent logging */
int zil_always = 0;	/* make every transaction synchronous */
int zil_purge = 0;	/* at pool open, just throw everything away */
int zil_noflush = 0;	/* don't flush write cache buffers on disks */

static kmem_cache_t *zil_lwb_cache;

static int
zil_dva_compare(const void *x1, const void *x2)
{
	const dva_t *dva1 = x1;
	const dva_t *dva2 = x2;

	if (DVA_GET_VDEV(dva1) < DVA_GET_VDEV(dva2))
		return (-1);
	if (DVA_GET_VDEV(dva1) > DVA_GET_VDEV(dva2))
		return (1);

	if (DVA_GET_OFFSET(dva1) < DVA_GET_OFFSET(dva2))
		return (-1);
	if (DVA_GET_OFFSET(dva1) > DVA_GET_OFFSET(dva2))
		return (1);

	return (0);
}

static void
zil_dva_tree_init(avl_tree_t *t)
{
	avl_create(t, zil_dva_compare, sizeof (zil_dva_node_t),
	    offsetof(zil_dva_node_t, zn_node));
}

static void
zil_dva_tree_fini(avl_tree_t *t)
{
	zil_dva_node_t *zn;
	void *cookie = NULL;

	while ((zn = avl_destroy_nodes(t, &cookie)) != NULL)
		kmem_free(zn, sizeof (zil_dva_node_t));

	avl_destroy(t);
}

static int
zil_dva_tree_add(avl_tree_t *t, dva_t *dva)
{
	zil_dva_node_t *zn;
	avl_index_t where;

	if (avl_find(t, dva, &where) != NULL)
		return (EEXIST);

	zn = kmem_alloc(sizeof (zil_dva_node_t), KM_SLEEP);
	zn->zn_dva = *dva;
	avl_insert(t, zn, where);

	return (0);
}

/*
 * Read a log block, make sure it's valid, and byteswap it if necessary.
 */
static int
zil_read_log_block(zilog_t *zilog, blkptr_t *bp, char *buf)
{
	uint64_t blksz = BP_GET_LSIZE(bp);
	zil_trailer_t *ztp = (zil_trailer_t *)(buf + blksz) - 1;
	zio_cksum_t cksum;
	int error;

	error = zio_wait(zio_read(NULL, zilog->zl_spa, bp, buf, blksz,
	    NULL, NULL, ZIO_PRIORITY_SYNC_READ,
	    ZIO_FLAG_CANFAIL | ZIO_FLAG_SPECULATIVE));
	if (error) {
		dprintf_bp(bp, "zilog %p bp %p read failed, error %d: ",
		    zilog, bp, error);
		return (error);
	}

	if (BP_SHOULD_BYTESWAP(bp))
		byteswap_uint64_array(buf, blksz);

	/*
	 * Sequence numbers should be... sequential.  The checksum verifier for
	 * the next block should be: <logid[0], logid[1], objset id, seq + 1>.
	 */
	cksum = bp->blk_cksum;
	cksum.zc_word[3]++;
	if (bcmp(&cksum, &ztp->zit_next_blk.blk_cksum, sizeof (cksum)) != 0) {
		dprintf_bp(bp, "zilog %p bp %p stale pointer: ", zilog, bp);
		return (ESTALE);
	}

	if (BP_IS_HOLE(&ztp->zit_next_blk)) {
		dprintf_bp(bp, "zilog %p bp %p hole: ", zilog, bp);
		return (ENOENT);
	}

	if (ztp->zit_nused > (blksz - sizeof (zil_trailer_t))) {
		dprintf("zilog %p bp %p nused exceeds blksz\n", zilog, bp);
		return (EOVERFLOW);
	}

	dprintf_bp(bp, "zilog %p bp %p good block: ", zilog, bp);

	return (0);
}

/*
 * Parse the intent log, and call parse_func for each valid record within.
 */
void
zil_parse(zilog_t *zilog, zil_parse_blk_func_t *parse_blk_func,
    zil_parse_lr_func_t *parse_lr_func, void *arg, uint64_t txg)
{
	blkptr_t blk;
	char *lrbuf, *lrp;
	zil_trailer_t *ztp;
	int reclen, error;

	blk = zilog->zl_header->zh_log;
	if (BP_IS_HOLE(&blk))
		return;

	/*
	 * Starting at the block pointed to by zh_log we read the log chain.
	 * For each block in the chain we strongly check that block to
	 * ensure its validity.  We stop when an invalid block is found.
	 * For each block pointer in the chain we call parse_blk_func().
	 * For each record in each valid block we call parse_lr_func().
	 */
	zil_dva_tree_init(&zilog->zl_dva_tree);
	lrbuf = zio_buf_alloc(SPA_MAXBLOCKSIZE);
	for (;;) {
		error = zil_read_log_block(zilog, &blk, lrbuf);

		if (parse_blk_func != NULL)
			parse_blk_func(zilog, &blk, arg, txg);

		if (error)
			break;

		ztp = (zil_trailer_t *)(lrbuf + BP_GET_LSIZE(&blk)) - 1;
		blk = ztp->zit_next_blk;

		if (parse_lr_func == NULL)
			continue;

		for (lrp = lrbuf; lrp < lrbuf + ztp->zit_nused; lrp += reclen) {
			lr_t *lr = (lr_t *)lrp;
			reclen = lr->lrc_reclen;
			ASSERT3U(reclen, >=, sizeof (lr_t));
			parse_lr_func(zilog, lr, arg, txg);
		}
	}
	zio_buf_free(lrbuf, SPA_MAXBLOCKSIZE);
	zil_dva_tree_fini(&zilog->zl_dva_tree);
}

/* ARGSUSED */
static void
zil_claim_log_block(zilog_t *zilog, blkptr_t *bp, void *tx, uint64_t first_txg)
{
	spa_t *spa = zilog->zl_spa;
	int err;

	dprintf_bp(bp, "first_txg %llu: ", first_txg);

	/*
	 * Claim log block if not already committed and not already claimed.
	 */
	if (bp->blk_birth >= first_txg &&
	    zil_dva_tree_add(&zilog->zl_dva_tree, BP_IDENTITY(bp)) == 0) {
		err = zio_wait(zio_claim(NULL, spa, first_txg, bp, NULL, NULL));
		ASSERT(err == 0);
	}
}

static void
zil_claim_log_record(zilog_t *zilog, lr_t *lrc, void *tx, uint64_t first_txg)
{
	if (lrc->lrc_txtype == TX_WRITE) {
		lr_write_t *lr = (lr_write_t *)lrc;
		zil_claim_log_block(zilog, &lr->lr_blkptr, tx, first_txg);
	}
}

/* ARGSUSED */
static void
zil_free_log_block(zilog_t *zilog, blkptr_t *bp, void *tx, uint64_t claim_txg)
{
	zio_free_blk(zilog->zl_spa, bp, dmu_tx_get_txg(tx));
}

static void
zil_free_log_record(zilog_t *zilog, lr_t *lrc, void *tx, uint64_t claim_txg)
{
	/*
	 * If we previously claimed it, we need to free it.
	 */
	if (claim_txg != 0 && lrc->lrc_txtype == TX_WRITE) {
		lr_write_t *lr = (lr_write_t *)lrc;
		blkptr_t *bp = &lr->lr_blkptr;
		if (bp->blk_birth >= claim_txg &&
		    !zil_dva_tree_add(&zilog->zl_dva_tree, BP_IDENTITY(bp))) {
			(void) arc_free(NULL, zilog->zl_spa,
			    dmu_tx_get_txg(tx), bp, NULL, NULL, ARC_WAIT);
		}
	}
}

/*
 * Create an on-disk intent log.
 */
static void
zil_create(zilog_t *zilog)
{
	lwb_t *lwb;
	uint64_t txg;
	dmu_tx_t *tx;
	blkptr_t blk;
	int error;
	int no_blk;

	ASSERT(zilog->zl_header->zh_claim_txg == 0);
	ASSERT(zilog->zl_header->zh_replay_seq == 0);

	/*
	 * Initialize the log header block.
	 */
	tx = dmu_tx_create(zilog->zl_os);
	(void) dmu_tx_assign(tx, TXG_WAIT);
	dsl_dataset_dirty(dmu_objset_ds(zilog->zl_os), tx);
	txg = dmu_tx_get_txg(tx);

	/*
	 * If we don't have a log block already then
	 * allocate the first log block and assign its checksum verifier.
	 */
	no_blk = BP_IS_HOLE(&zilog->zl_header->zh_log);
	if (no_blk) {
		error = zio_alloc_blk(zilog->zl_spa, ZIO_CHECKSUM_ZILOG,
		    ZIL_MIN_BLKSZ, &blk, txg);
	} else {
		blk = zilog->zl_header->zh_log;
		error = 0;
	}
	if (error == 0) {
		ZIO_SET_CHECKSUM(&blk.blk_cksum,
		    spa_get_random(-1ULL), spa_get_random(-1ULL),
		    dmu_objset_id(zilog->zl_os), 1ULL);

		/*
		 * Allocate a log write buffer (lwb) for the first log block.
		 */
		lwb = kmem_cache_alloc(zil_lwb_cache, KM_SLEEP);
		lwb->lwb_zilog = zilog;
		lwb->lwb_blk = blk;
		lwb->lwb_nused = 0;
		lwb->lwb_sz = BP_GET_LSIZE(&lwb->lwb_blk);
		lwb->lwb_buf = zio_buf_alloc(lwb->lwb_sz);
		lwb->lwb_max_txg = txg;
		lwb->lwb_seq = 0;
		lwb->lwb_state = UNWRITTEN;
		mutex_enter(&zilog->zl_lock);
		list_insert_tail(&zilog->zl_lwb_list, lwb);
		mutex_exit(&zilog->zl_lock);
	}

	dmu_tx_commit(tx);
	if (no_blk)
		txg_wait_synced(zilog->zl_dmu_pool, txg);
}

/*
 * In one tx, free all log blocks and clear the log header.
 */
void
zil_destroy(zilog_t *zilog)
{
	dmu_tx_t *tx;
	uint64_t txg;

	mutex_enter(&zilog->zl_destroy_lock);

	if (BP_IS_HOLE(&zilog->zl_header->zh_log)) {
		mutex_exit(&zilog->zl_destroy_lock);
		return;
	}

	tx = dmu_tx_create(zilog->zl_os);
	(void) dmu_tx_assign(tx, TXG_WAIT);
	dsl_dataset_dirty(dmu_objset_ds(zilog->zl_os), tx);
	txg = dmu_tx_get_txg(tx);

	zil_parse(zilog, zil_free_log_block, zil_free_log_record, tx,
	    zilog->zl_header->zh_claim_txg);
	/*
	 * zil_sync clears the zil header as soon as the zl_destroy_txg commits
	 */
	zilog->zl_destroy_txg = txg;

	dmu_tx_commit(tx);
	txg_wait_synced(zilog->zl_dmu_pool, txg);

	mutex_exit(&zilog->zl_destroy_lock);
}

void
zil_claim(char *osname, void *txarg)
{
	dmu_tx_t *tx = txarg;
	uint64_t first_txg = dmu_tx_get_txg(tx);
	zilog_t *zilog;
	zil_header_t *zh;
	objset_t *os;
	int error;

	error = dmu_objset_open(osname, DMU_OST_ANY, DS_MODE_STANDARD, &os);
	if (error) {
		cmn_err(CE_WARN, "can't process intent log for %s", osname);
		return;
	}

	zilog = dmu_objset_zil(os);
	zh = zilog->zl_header;

	/*
	 * Claim all log blocks if we haven't already done so.
	 */
	ASSERT3U(zh->zh_claim_txg, <=, first_txg);
	if (zh->zh_claim_txg == 0 && !BP_IS_HOLE(&zh->zh_log)) {
		zh->zh_claim_txg = first_txg;
		zil_parse(zilog, zil_claim_log_block, zil_claim_log_record,
		    tx, first_txg);
		dsl_dataset_dirty(dmu_objset_ds(os), tx);
	}
	ASSERT3U(first_txg, ==, (spa_last_synced_txg(zilog->zl_spa) + 1));
	dmu_objset_close(os);
}

void
zil_add_vdev(zilog_t *zilog, uint64_t vdev, uint64_t seq)
{
	zil_vdev_t *zv;

	if (zil_noflush)
		return;

	ASSERT(MUTEX_HELD(&zilog->zl_lock));
	zv = kmem_alloc(sizeof (zil_vdev_t), KM_SLEEP);
	zv->vdev = vdev;
	zv->seq = seq;
	list_insert_tail(&zilog->zl_vdev_list, zv);
}

void
zil_flush_vdevs(zilog_t *zilog, uint64_t seq)
{
	vdev_t *vd;
	zil_vdev_t *zv, *zv2;
	zio_t *zio;
	spa_t *spa;
	uint64_t vdev;

	if (zil_noflush)
		return;

	ASSERT(MUTEX_HELD(&zilog->zl_lock));

	spa = zilog->zl_spa;
	zio = NULL;

	while ((zv = list_head(&zilog->zl_vdev_list)) != NULL &&
	    zv->seq <= seq) {
		vdev = zv->vdev;
		list_remove(&zilog->zl_vdev_list, zv);
		kmem_free(zv, sizeof (zil_vdev_t));

		/*
		 * remove all chained entries <= seq with same vdev
		 */
		zv = list_head(&zilog->zl_vdev_list);
		while (zv && zv->seq <= seq) {
			zv2 = list_next(&zilog->zl_vdev_list, zv);
			if (zv->vdev == vdev) {
				list_remove(&zilog->zl_vdev_list, zv);
				kmem_free(zv, sizeof (zil_vdev_t));
			}
			zv = zv2;
		}

		/* flush the write cache for this vdev */
		mutex_exit(&zilog->zl_lock);
		if (zio == NULL)
			zio = zio_root(spa, NULL, NULL, ZIO_FLAG_CANFAIL);
		vd = vdev_lookup_top(spa, vdev);
		ASSERT(vd);
		(void) zio_nowait(zio_ioctl(zio, spa, vd, DKIOCFLUSHWRITECACHE,
		    NULL, NULL, ZIO_PRIORITY_NOW,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY));
		mutex_enter(&zilog->zl_lock);
	}

	/*
	 * Wait for all the flushes to complete.  Not all devices actually
	 * support the DKIOCFLUSHWRITECACHE ioctl, so it's OK if it fails.
	 */
	if (zio != NULL) {
		mutex_exit(&zilog->zl_lock);
		(void) zio_wait(zio);
		mutex_enter(&zilog->zl_lock);
	}
}

/*
 * Function called when a log block write completes
 */
static void
zil_lwb_write_done(zio_t *zio)
{
	lwb_t *prev;
	lwb_t *lwb = zio->io_private;
	zilog_t *zilog = lwb->lwb_zilog;
	uint64_t max_seq;

	/*
	 * Now that we've written this log block, we have a stable pointer
	 * to the next block in the chain, so it's OK to let the txg in
	 * which we allocated the next block sync.
	 */
	txg_rele_to_sync(&lwb->lwb_txgh);

	zio_buf_free(lwb->lwb_buf, lwb->lwb_sz);
	mutex_enter(&zilog->zl_lock);
	lwb->lwb_buf = NULL;
	if (zio->io_error) {
		zilog->zl_log_error = B_TRUE;
		mutex_exit(&zilog->zl_lock);
		cv_broadcast(&zilog->zl_cv_seq);
		return;
	}

	prev = list_prev(&zilog->zl_lwb_list, lwb);
	if (prev && prev->lwb_state != SEQ_COMPLETE) {
		/* There's an unwritten buffer in the chain before this one */
		lwb->lwb_state = SEQ_INCOMPLETE;
		mutex_exit(&zilog->zl_lock);
		return;
	}

	max_seq = lwb->lwb_seq;
	lwb->lwb_state = SEQ_COMPLETE;
	/*
	 * We must also follow up the chain for already written buffers
	 * to see if we can set zl_ss_seq even higher.
	 */
	while (lwb = list_next(&zilog->zl_lwb_list, lwb)) {
		if (lwb->lwb_state != SEQ_INCOMPLETE)
			break;
		lwb->lwb_state = SEQ_COMPLETE;
		/* lwb_seq will be zero if we've written an empty buffer */
		if (lwb->lwb_seq) {
			ASSERT3U(max_seq, <, lwb->lwb_seq);
			max_seq = lwb->lwb_seq;
		}
	}
	zilog->zl_ss_seq = MAX(max_seq, zilog->zl_ss_seq);
	mutex_exit(&zilog->zl_lock);
	cv_broadcast(&zilog->zl_cv_seq);
}

/*
 * Start a log block write and advance to the next log block.
 * Calls are serialized.
 */
static lwb_t *
zil_lwb_write_start(zilog_t *zilog, lwb_t *lwb)
{
	lwb_t *nlwb;
	zil_trailer_t *ztp = (zil_trailer_t *)(lwb->lwb_buf + lwb->lwb_sz) - 1;
	uint64_t txg;
	uint64_t zil_blksz;
	int error;

	ASSERT(lwb->lwb_nused <= ZIL_BLK_DATA_SZ(lwb));

	/*
	 * Allocate the next block and save its address in this block
	 * before writing it in order to establish the log chain.
	 * Note that if the allocation of nlwb synced before we wrote
	 * the block that points at it (lwb), we'd leak it if we crashed.
	 * Therefore, we don't do txg_rele_to_sync() until zil_lwb_write_done().
	 */
	txg = txg_hold_open(zilog->zl_dmu_pool, &lwb->lwb_txgh);
	txg_rele_to_quiesce(&lwb->lwb_txgh);

	/*
	 * Pick a ZIL blocksize. We request a size that is the
	 * maximum of the previous used size, the current used size and
	 * the amount waiting in the queue.
	 */
	zil_blksz = MAX(zilog->zl_cur_used, zilog->zl_prev_used);
	zil_blksz = MAX(zil_blksz, zilog->zl_itx_list_sz + sizeof (*ztp));
	zil_blksz = P2ROUNDUP(zil_blksz, ZIL_MIN_BLKSZ);
	if (zil_blksz > ZIL_MAX_BLKSZ)
		zil_blksz = ZIL_MAX_BLKSZ;

	error = zio_alloc_blk(zilog->zl_spa, ZIO_CHECKSUM_ZILOG,
	    zil_blksz, &ztp->zit_next_blk, txg);
	if (error) {
		txg_rele_to_sync(&lwb->lwb_txgh);
		return (NULL);
	}

	ASSERT3U(ztp->zit_next_blk.blk_birth, ==, txg);
	ztp->zit_nused = lwb->lwb_nused;
	ztp->zit_bt.zbt_cksum = lwb->lwb_blk.blk_cksum;
	ztp->zit_next_blk.blk_cksum = lwb->lwb_blk.blk_cksum;
	ztp->zit_next_blk.blk_cksum.zc_word[3]++;

	/*
	 * Allocate a new log write buffer (lwb).
	 */
	nlwb = kmem_cache_alloc(zil_lwb_cache, KM_SLEEP);

	nlwb->lwb_zilog = zilog;
	nlwb->lwb_blk = ztp->zit_next_blk;
	nlwb->lwb_nused = 0;
	nlwb->lwb_sz = BP_GET_LSIZE(&nlwb->lwb_blk);
	nlwb->lwb_buf = zio_buf_alloc(nlwb->lwb_sz);
	nlwb->lwb_max_txg = txg;
	nlwb->lwb_seq = 0;
	nlwb->lwb_state = UNWRITTEN;

	/*
	 * Put new lwb at the end of the log chain,
	 * and record the vdev for later flushing
	 */
	mutex_enter(&zilog->zl_lock);
	list_insert_tail(&zilog->zl_lwb_list, nlwb);
	zil_add_vdev(zilog, DVA_GET_VDEV(BP_IDENTITY(&(lwb->lwb_blk))),
	    lwb->lwb_seq);
	mutex_exit(&zilog->zl_lock);

	/*
	 * write the old log block
	 */
	dprintf_bp(&lwb->lwb_blk, "lwb %p txg %llu: ", lwb, txg);
	zio_nowait(zio_rewrite(NULL, zilog->zl_spa, ZIO_CHECKSUM_ZILOG, 0,
	    &lwb->lwb_blk, lwb->lwb_buf, lwb->lwb_sz, zil_lwb_write_done, lwb,
	    ZIO_PRIORITY_LOG_WRITE, ZIO_FLAG_MUSTSUCCEED));

	return (nlwb);
}

static lwb_t *
zil_lwb_commit(zilog_t *zilog, itx_t *itx, lwb_t *lwb)
{
	lr_t *lrc = &itx->itx_lr; /* common log record */
	uint64_t seq = lrc->lrc_seq;
	uint64_t txg = lrc->lrc_txg;
	uint64_t reclen = lrc->lrc_reclen;
	int error;

	if (lwb == NULL)
		return (NULL);
	ASSERT(lwb->lwb_buf != NULL);

	/*
	 * If it's a write, fetch the data or get its blkptr as appropriate.
	 */
	if (lrc->lrc_txtype == TX_WRITE) {
		lr_write_t *lr = (lr_write_t *)lrc;
		if (txg > spa_freeze_txg(zilog->zl_spa))
			txg_wait_synced(zilog->zl_dmu_pool, txg);

		if (!itx->itx_data_copied &&
		    (error = zilog->zl_get_data(itx->itx_private, lr)) != 0) {
			if (error != ENOENT && error != EALREADY) {
				txg_wait_synced(zilog->zl_dmu_pool, txg);
				mutex_enter(&zilog->zl_lock);
				zilog->zl_ss_seq = MAX(seq, zilog->zl_ss_seq);
				zil_add_vdev(zilog,
				    DVA_GET_VDEV(BP_IDENTITY(&(lr->lr_blkptr))),
				    seq);
				mutex_exit(&zilog->zl_lock);
				return (lwb);
			}
			mutex_enter(&zilog->zl_lock);
			zil_add_vdev(zilog,
			    DVA_GET_VDEV(BP_IDENTITY(&(lr->lr_blkptr))), seq);
			mutex_exit(&zilog->zl_lock);
			return (lwb);
		}
	}

	zilog->zl_cur_used += reclen;

	/*
	 * If this record won't fit in the current log block, start a new one.
	 */
	if (lwb->lwb_nused + reclen > ZIL_BLK_DATA_SZ(lwb)) {
		lwb = zil_lwb_write_start(zilog, lwb);
		if (lwb == NULL)
			return (NULL);
		if (lwb->lwb_nused + reclen > ZIL_BLK_DATA_SZ(lwb)) {
			txg_wait_synced(zilog->zl_dmu_pool, txg);
			mutex_enter(&zilog->zl_lock);
			zilog->zl_ss_seq = MAX(seq, zilog->zl_ss_seq);
			mutex_exit(&zilog->zl_lock);
			return (lwb);
		}
	}

	bcopy(lrc, lwb->lwb_buf + lwb->lwb_nused, reclen);
	lwb->lwb_nused += reclen;
	lwb->lwb_max_txg = MAX(lwb->lwb_max_txg, txg);
	ASSERT3U(lwb->lwb_seq, <, seq);
	lwb->lwb_seq = seq;
	ASSERT3U(lwb->lwb_nused, <=, ZIL_BLK_DATA_SZ(lwb));
	ASSERT3U(P2PHASE(lwb->lwb_nused, sizeof (uint64_t)), ==, 0);

	return (lwb);
}

itx_t *
zil_itx_create(int txtype, size_t lrsize)
{
	itx_t *itx;

	lrsize = P2ROUNDUP(lrsize, sizeof (uint64_t));

	itx = kmem_alloc(offsetof(itx_t, itx_lr) + lrsize, KM_SLEEP);
	itx->itx_lr.lrc_txtype = txtype;
	itx->itx_lr.lrc_reclen = lrsize;
	itx->itx_lr.lrc_seq = 0;	/* defensive */

	return (itx);
}

uint64_t
zil_itx_assign(zilog_t *zilog, itx_t *itx, dmu_tx_t *tx)
{
	uint64_t seq;

	ASSERT(itx->itx_lr.lrc_seq == 0);

	mutex_enter(&zilog->zl_lock);
	list_insert_tail(&zilog->zl_itx_list, itx);
	zilog->zl_itx_list_sz += itx->itx_lr.lrc_reclen;
	itx->itx_lr.lrc_txg = dmu_tx_get_txg(tx);
	itx->itx_lr.lrc_seq = seq = ++zilog->zl_itx_seq;
	mutex_exit(&zilog->zl_lock);

	return (seq);
}

/*
 * Free up all in-memory intent log transactions that have now been synced.
 */
static void
zil_itx_clean(zilog_t *zilog)
{
	uint64_t synced_txg = spa_last_synced_txg(zilog->zl_spa);
	uint64_t freeze_txg = spa_freeze_txg(zilog->zl_spa);
	uint64_t max_seq = 0;
	itx_t *itx;

	mutex_enter(&zilog->zl_lock);
	while ((itx = list_head(&zilog->zl_itx_list)) != NULL &&
	    itx->itx_lr.lrc_txg <= MIN(synced_txg, freeze_txg)) {
		list_remove(&zilog->zl_itx_list, itx);
		zilog->zl_itx_list_sz -= itx->itx_lr.lrc_reclen;
		ASSERT3U(max_seq, <, itx->itx_lr.lrc_seq);
		max_seq = itx->itx_lr.lrc_seq;
		kmem_free(itx, offsetof(itx_t, itx_lr)
		    + itx->itx_lr.lrc_reclen);
	}
	if (max_seq > zilog->zl_ss_seq) {
		zilog->zl_ss_seq = max_seq;
		cv_broadcast(&zilog->zl_cv_seq);
	}
	mutex_exit(&zilog->zl_lock);
}

void
zil_clean(zilog_t *zilog)
{
	/*
	 * Check for any log blocks that can be freed.
	 * Log blocks are only freed when the log block allocation and
	 * log records contained within are both known to be committed.
	 */
	mutex_enter(&zilog->zl_lock);
	if (list_head(&zilog->zl_itx_list) != NULL)
		(void) taskq_dispatch(zilog->zl_clean_taskq,
		    (void (*)(void *))zil_itx_clean, zilog, TQ_NOSLEEP);
	mutex_exit(&zilog->zl_lock);
}

/*
 * Push zfs transactions to stable storage up to the supplied sequence number.
 */
void
zil_commit(zilog_t *zilog, uint64_t seq, int ioflag)
{
	uint64_t txg;
	uint64_t max_seq;
	uint64_t reclen;
	itx_t *itx;
	lwb_t *lwb;
	spa_t *spa;

	if (zilog == NULL || seq == 0 ||
	    ((ioflag & (FSYNC | FDSYNC | FRSYNC)) == 0 && !zil_always))
		return;

	spa = zilog->zl_spa;
	mutex_enter(&zilog->zl_lock);

	seq = MIN(seq, zilog->zl_itx_seq);	/* cap seq at largest itx seq */

	for (;;) {
		if (zilog->zl_ss_seq >= seq) {	/* already on stable storage */
			cv_signal(&zilog->zl_cv_write);
			mutex_exit(&zilog->zl_lock);
			return;
		}

		if (zilog->zl_writer == B_FALSE) /* no one writing, do it */
			break;

		cv_wait(&zilog->zl_cv_write, &zilog->zl_lock);
	}

	zilog->zl_writer = B_TRUE;
	max_seq = 0;

	if (zilog->zl_suspend) {
		lwb = NULL;
	} else {
		lwb = list_tail(&zilog->zl_lwb_list);
		if (lwb == NULL) {
			mutex_exit(&zilog->zl_lock);
			zil_create(zilog);
			mutex_enter(&zilog->zl_lock);
			lwb = list_tail(&zilog->zl_lwb_list);
		}
	}

	/*
	 * Loop through in-memory log transactions filling log blocks,
	 * until we reach the given sequence number and there's no more
	 * room in the write buffer.
	 */
	for (;;) {
		itx = list_head(&zilog->zl_itx_list);
		if (itx == NULL)
			break;

		reclen = itx->itx_lr.lrc_reclen;
		if ((itx->itx_lr.lrc_seq > seq) &&
		    ((lwb == NULL) || (lwb->lwb_nused + reclen >
		    ZIL_BLK_DATA_SZ(lwb))))
			break;

		list_remove(&zilog->zl_itx_list, itx);
		txg = itx->itx_lr.lrc_txg;
		ASSERT(txg);

		mutex_exit(&zilog->zl_lock);
		if (txg > spa_last_synced_txg(spa) ||
		    txg > spa_freeze_txg(spa))
			lwb = zil_lwb_commit(zilog, itx, lwb);
		else
			max_seq = itx->itx_lr.lrc_seq;
		kmem_free(itx, offsetof(itx_t, itx_lr)
		    + itx->itx_lr.lrc_reclen);
		mutex_enter(&zilog->zl_lock);
		zilog->zl_itx_list_sz -= reclen;
	}

	mutex_exit(&zilog->zl_lock);

	/* write the last block out */
	if (lwb != NULL && lwb->lwb_nused != 0)
		lwb = zil_lwb_write_start(zilog, lwb);

	zilog->zl_prev_used = zilog->zl_cur_used;
	zilog->zl_cur_used = 0;

	mutex_enter(&zilog->zl_lock);
	if (max_seq > zilog->zl_ss_seq) {
		zilog->zl_ss_seq = max_seq;
		cv_broadcast(&zilog->zl_cv_seq);
	}
	/*
	 * Wait if necessary for our seq to be committed.
	 */
	if (lwb) {
		while (zilog->zl_ss_seq < seq && zilog->zl_log_error == 0)
			cv_wait(&zilog->zl_cv_seq, &zilog->zl_lock);
		zil_flush_vdevs(zilog, seq);
	}

	if (zilog->zl_log_error || lwb == NULL) {
		zilog->zl_log_error = 0;
		max_seq = zilog->zl_itx_seq;
		mutex_exit(&zilog->zl_lock);
		txg_wait_synced(zilog->zl_dmu_pool, 0);
		mutex_enter(&zilog->zl_lock);
		zilog->zl_ss_seq = MAX(max_seq, zilog->zl_ss_seq);
		cv_broadcast(&zilog->zl_cv_seq);
	}
	/* wake up others waiting to start a write */
	zilog->zl_writer = B_FALSE;
	mutex_exit(&zilog->zl_lock);
	cv_signal(&zilog->zl_cv_write);
}

/*
 * Called in syncing context to free committed log blocks and update log header.
 */
void
zil_sync(zilog_t *zilog, dmu_tx_t *tx)
{
	uint64_t txg = dmu_tx_get_txg(tx);
	spa_t *spa = zilog->zl_spa;
	lwb_t *lwb;

	ASSERT(zilog->zl_stop_sync == 0);

	zilog->zl_header->zh_replay_seq = zilog->zl_replay_seq[txg & TXG_MASK];

	if (zilog->zl_destroy_txg == txg) {
		bzero(zilog->zl_header, sizeof (zil_header_t));
		bzero(zilog->zl_replay_seq, sizeof (zilog->zl_replay_seq));
		zilog->zl_destroy_txg = 0;
	}

	mutex_enter(&zilog->zl_lock);
	for (;;) {
		lwb = list_head(&zilog->zl_lwb_list);
		if (lwb == NULL) {
			mutex_exit(&zilog->zl_lock);
			return;
		}
		if (lwb->lwb_buf != NULL || lwb->lwb_max_txg > txg)
			break;
		list_remove(&zilog->zl_lwb_list, lwb);
		zio_free_blk(spa, &lwb->lwb_blk, txg);
		kmem_cache_free(zil_lwb_cache, lwb);
	}
	zilog->zl_header->zh_log = lwb->lwb_blk;
	mutex_exit(&zilog->zl_lock);
}

void
zil_init(void)
{
	zil_lwb_cache = kmem_cache_create("zil_lwb_cache",
	    sizeof (struct lwb), NULL, NULL, NULL, NULL, NULL, NULL, 0);
}

void
zil_fini(void)
{
	kmem_cache_destroy(zil_lwb_cache);
}

zilog_t *
zil_alloc(objset_t *os, zil_header_t *zh_phys)
{
	zilog_t *zilog;

	zilog = kmem_zalloc(sizeof (zilog_t), KM_SLEEP);

	zilog->zl_header = zh_phys;
	zilog->zl_os = os;
	zilog->zl_spa = dmu_objset_spa(os);
	zilog->zl_dmu_pool = dmu_objset_pool(os);

	list_create(&zilog->zl_itx_list, sizeof (itx_t),
	    offsetof(itx_t, itx_node));

	list_create(&zilog->zl_lwb_list, sizeof (lwb_t),
	    offsetof(lwb_t, lwb_node));

	list_create(&zilog->zl_vdev_list, sizeof (zil_vdev_t),
	    offsetof(zil_vdev_t, vdev_seq_node));

	return (zilog);
}

void
zil_free(zilog_t *zilog)
{
	lwb_t *lwb;
	zil_vdev_t *zv;

	zilog->zl_stop_sync = 1;

	while ((lwb = list_head(&zilog->zl_lwb_list)) != NULL) {
		list_remove(&zilog->zl_lwb_list, lwb);
		if (lwb->lwb_buf != NULL)
			zio_buf_free(lwb->lwb_buf, lwb->lwb_sz);
		kmem_cache_free(zil_lwb_cache, lwb);
	}
	list_destroy(&zilog->zl_lwb_list);

	while ((zv = list_head(&zilog->zl_vdev_list)) != NULL) {
		list_remove(&zilog->zl_vdev_list, zv);
		kmem_free(zv, sizeof (zil_vdev_t));
	}
	list_destroy(&zilog->zl_vdev_list);

	ASSERT(list_head(&zilog->zl_itx_list) == NULL);
	list_destroy(&zilog->zl_itx_list);

	kmem_free(zilog, sizeof (zilog_t));
}

/*
 * return true if there is a valid initial zil log block
 */
static int
zil_empty(zilog_t *zilog)
{
	blkptr_t blk;
	char *lrbuf;
	int error;

	blk = zilog->zl_header->zh_log;
	if (BP_IS_HOLE(&blk))
		return (1);

	lrbuf = zio_buf_alloc(SPA_MAXBLOCKSIZE);
	error = zil_read_log_block(zilog, &blk, lrbuf);
	zio_buf_free(lrbuf, SPA_MAXBLOCKSIZE);
	return (error ? 1 : 0);
}

/*
 * Open an intent log.
 */
zilog_t *
zil_open(objset_t *os, zil_get_data_t *get_data)
{
	zilog_t *zilog = dmu_objset_zil(os);

	zilog->zl_get_data = get_data;
	zilog->zl_clean_taskq = taskq_create("zil_clean", 1, minclsyspri,
	    2, 2, TASKQ_PREPOPULATE);

	return (zilog);
}

/*
 * Close an intent log.
 */
void
zil_close(zilog_t *zilog)
{
	if (!zil_empty(zilog))
		txg_wait_synced(zilog->zl_dmu_pool, 0);
	taskq_destroy(zilog->zl_clean_taskq);
	zilog->zl_clean_taskq = NULL;
	zilog->zl_get_data = NULL;

	zil_itx_clean(zilog);
	ASSERT(list_head(&zilog->zl_itx_list) == NULL);
}

/*
 * Suspend an intent log.  While in suspended mode, we still honor
 * synchronous semantics, but we rely on txg_wait_synced() to do it.
 * We suspend the log briefly when taking a snapshot so that the snapshot
 * contains all the data it's supposed to, and has an empty intent log.
 */
int
zil_suspend(zilog_t *zilog)
{
	lwb_t *lwb;

	mutex_enter(&zilog->zl_lock);
	if (zilog->zl_header->zh_claim_txg != 0) {	/* unplayed log */
		mutex_exit(&zilog->zl_lock);
		return (EBUSY);
	}
	zilog->zl_suspend++;
	mutex_exit(&zilog->zl_lock);

	zil_commit(zilog, UINT64_MAX, FSYNC);

	mutex_enter(&zilog->zl_lock);
	while ((lwb = list_head(&zilog->zl_lwb_list)) != NULL) {
		if (lwb->lwb_buf != NULL) {
			/*
			 * Wait for the buffer if it's in the process of
			 * being written.
			 */
			if ((lwb->lwb_seq != 0) &&
			    (lwb->lwb_state != SEQ_COMPLETE)) {
				cv_wait(&zilog->zl_cv_seq, &zilog->zl_lock);
				continue;
			}
			zio_buf_free(lwb->lwb_buf, lwb->lwb_sz);
		}
		list_remove(&zilog->zl_lwb_list, lwb);
		kmem_cache_free(zil_lwb_cache, lwb);
	}
	mutex_exit(&zilog->zl_lock);

	zil_destroy(zilog);

	return (0);
}

void
zil_resume(zilog_t *zilog)
{
	mutex_enter(&zilog->zl_lock);
	ASSERT(zilog->zl_suspend != 0);
	zilog->zl_suspend--;
	mutex_exit(&zilog->zl_lock);
}

typedef struct zil_replay_arg {
	objset_t	*zr_os;
	zil_replay_func_t **zr_replay;
	void		*zr_arg;
	void		(*zr_rm_sync)(void *arg);
	uint64_t	*zr_txgp;
	boolean_t	zr_byteswap;
	char		*zr_lrbuf;
} zil_replay_arg_t;

static void
zil_replay_log_record(zilog_t *zilog, lr_t *lr, void *zra, uint64_t claim_txg)
{
	zil_replay_arg_t *zr = zra;
	zil_header_t *zh = zilog->zl_header;
	uint64_t reclen = lr->lrc_reclen;
	uint64_t txtype = lr->lrc_txtype;
	int pass, error;

	if (zilog->zl_stop_replay)
		return;

	if (lr->lrc_txg < claim_txg)		/* already committed */
		return;

	if (lr->lrc_seq <= zh->zh_replay_seq)	/* already replayed */
		return;

	/*
	 * Make a copy of the data so we can revise and extend it.
	 */
	bcopy(lr, zr->zr_lrbuf, reclen);

	/*
	 * The log block containing this lr may have been byteswapped
	 * so that we can easily examine common fields like lrc_txtype.
	 * However, the log is a mix of different data types, and only the
	 * replay vectors know how to byteswap their records.  Therefore, if
	 * the lr was byteswapped, undo it before invoking the replay vector.
	 */
	if (zr->zr_byteswap)
		byteswap_uint64_array(zr->zr_lrbuf, reclen);

	/*
	 * If this is a TX_WRITE with a blkptr, suck in the data.
	 */
	if (txtype == TX_WRITE && reclen == sizeof (lr_write_t)) {
		lr_write_t *lrw = (lr_write_t *)lr;
		blkptr_t *wbp = &lrw->lr_blkptr;
		uint64_t wlen = lrw->lr_length;
		char *wbuf = zr->zr_lrbuf + reclen;

		if (BP_IS_HOLE(wbp)) {	/* compressed to a hole */
			bzero(wbuf, wlen);
		} else {
			/*
			 * A subsequent write may have overwritten this block,
			 * in which case wbp may have been been freed and
			 * reallocated, and our read of wbp may fail with a
			 * checksum error.  We can safely ignore this because
			 * the later write will provide the correct data.
			 */
			(void) zio_wait(zio_read(NULL, zilog->zl_spa,
			    wbp, wbuf, BP_GET_LSIZE(wbp), NULL, NULL,
			    ZIO_PRIORITY_SYNC_READ,
			    ZIO_FLAG_CANFAIL | ZIO_FLAG_SPECULATIVE));
			(void) memmove(wbuf, wbuf + lrw->lr_blkoff, wlen);
		}
	}

	/*
	 * We must now do two things atomically: replay this log record,
	 * and update the log header to reflect the fact that we did so.
	 * We use the DMU's ability to assign into a specific txg to do this.
	 */
	for (pass = 1; /* CONSTANTCONDITION */; pass++) {
		uint64_t replay_txg;
		dmu_tx_t *replay_tx;

		replay_tx = dmu_tx_create(zr->zr_os);
		error = dmu_tx_assign(replay_tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(replay_tx);
			break;
		}

		replay_txg = dmu_tx_get_txg(replay_tx);

		if (txtype == 0 || txtype >= TX_MAX_TYPE) {
			error = EINVAL;
		} else {
			/*
			 * On the first pass, arrange for the replay vector
			 * to fail its dmu_tx_assign().  That's the only way
			 * to ensure that those code paths remain well tested.
			 */
			*zr->zr_txgp = replay_txg - (pass == 1);
			error = zr->zr_replay[txtype](zr->zr_arg, zr->zr_lrbuf,
			    zr->zr_byteswap);
			*zr->zr_txgp = TXG_NOWAIT;
		}

		if (error == 0) {
			dsl_dataset_dirty(dmu_objset_ds(zr->zr_os), replay_tx);
			zilog->zl_replay_seq[replay_txg & TXG_MASK] =
			    lr->lrc_seq;
		}

		dmu_tx_commit(replay_tx);

		if (error != ERESTART)
			break;

		if (pass != 1)
			txg_wait_open(spa_get_dsl(zilog->zl_spa),
			    replay_txg + 1);

		dprintf("pass %d, retrying\n", pass);
	}

	if (error) {
		char *name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		dmu_objset_name(zr->zr_os, name);
		cmn_err(CE_WARN, "ZFS replay transaction error %d, "
		    "dataset %s, seq 0x%llx, txtype %llu\n",
		    error, name,
		    (u_longlong_t)lr->lrc_seq, (u_longlong_t)txtype);
		zilog->zl_stop_replay = 1;
		kmem_free(name, MAXNAMELEN);
	}

	/*
	 * The DMU's dnode layer doesn't see removes until the txg commits,
	 * so a subsequent claim can spuriously fail with EEXIST.
	 * To prevent this, if we might have removed an object,
	 * wait for the delete thread to delete it, and then
	 * wait for the transaction group to sync.
	 */
	if (txtype == TX_REMOVE || txtype == TX_RMDIR || txtype == TX_RENAME) {
		if (zr->zr_rm_sync != NULL)
			zr->zr_rm_sync(zr->zr_arg);
		txg_wait_synced(spa_get_dsl(zilog->zl_spa), 0);
	}
}

/*
 * If this dataset has a non-empty intent log, replay it and destroy it.
 */
void
zil_replay(objset_t *os, void *arg, uint64_t *txgp,
	zil_replay_func_t *replay_func[TX_MAX_TYPE], void (*rm_sync)(void *arg))
{
	zilog_t *zilog = dmu_objset_zil(os);
		zil_replay_arg_t zr;

	if (zil_empty(zilog)) {
		/*
		 * Initialise the log header but don't free the log block
		 * which will get reused.
		 */
		zilog->zl_header->zh_claim_txg = 0;
		zilog->zl_header->zh_replay_seq = 0;
		return;
	}

	zr.zr_os = os;
	zr.zr_replay = replay_func;
	zr.zr_arg = arg;
	zr.zr_rm_sync = rm_sync;
	zr.zr_txgp = txgp;
	zr.zr_byteswap = BP_SHOULD_BYTESWAP(&zilog->zl_header->zh_log);
	zr.zr_lrbuf = kmem_alloc(2 * SPA_MAXBLOCKSIZE, KM_SLEEP);

	/*
	 * Wait for in-progress removes to sync before starting replay.
	 */
	if (rm_sync != NULL)
		rm_sync(arg);
	txg_wait_synced(zilog->zl_dmu_pool, 0);

	zilog->zl_stop_replay = 0;
	zil_parse(zilog, NULL, zil_replay_log_record, &zr,
	    zilog->zl_header->zh_claim_txg);
	kmem_free(zr.zr_lrbuf, 2 * SPA_MAXBLOCKSIZE);

	zil_destroy(zilog);
}
