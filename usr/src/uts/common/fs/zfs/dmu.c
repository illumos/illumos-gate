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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#ifdef _KERNEL
#include <sys/vmsystm.h>
#endif

const dmu_object_type_info_t dmu_ot[DMU_OT_NUMTYPES] = {
	{	byteswap_uint8_array,	TRUE,	"unallocated"		},
	{	zap_byteswap,		TRUE,	"object directory"	},
	{	byteswap_uint64_array,	TRUE,	"object array"		},
	{	byteswap_uint8_array,	TRUE,	"packed nvlist"		},
	{	byteswap_uint64_array,	TRUE,	"packed nvlist size"	},
	{	byteswap_uint64_array,	TRUE,	"bplist"		},
	{	byteswap_uint64_array,	TRUE,	"bplist header"		},
	{	byteswap_uint64_array,	TRUE,	"SPA space map header"	},
	{	byteswap_uint64_array,	TRUE,	"SPA space map"		},
	{	byteswap_uint64_array,	TRUE,	"ZIL intent log"	},
	{	dnode_buf_byteswap,	TRUE,	"DMU dnode"		},
	{	dmu_objset_byteswap,	TRUE,	"DMU objset"		},
	{	byteswap_uint64_array,	TRUE,	"DSL directory"		},
	{	zap_byteswap,		TRUE,	"DSL directory child map"},
	{	zap_byteswap,		TRUE,	"DSL dataset snap map"	},
	{	zap_byteswap,		TRUE,	"DSL props"		},
	{	byteswap_uint64_array,	TRUE,	"DSL dataset"		},
	{	zfs_znode_byteswap,	TRUE,	"ZFS znode"		},
	{	zfs_acl_byteswap,	TRUE,	"ZFS ACL"		},
	{	byteswap_uint8_array,	FALSE,	"ZFS plain file"	},
	{	zap_byteswap,		TRUE,	"ZFS directory"		},
	{	zap_byteswap,		TRUE,	"ZFS master node"	},
	{	zap_byteswap,		TRUE,	"ZFS delete queue"	},
	{	byteswap_uint8_array,	FALSE,	"zvol object"		},
	{	zap_byteswap,		TRUE,	"zvol prop"		},
	{	byteswap_uint8_array,	FALSE,	"other uint8[]"		},
	{	byteswap_uint64_array,	FALSE,	"other uint64[]"	},
	{	zap_byteswap,		TRUE,	"other ZAP"		},
	{	zap_byteswap,		TRUE,	"persistent error log"	},
};

int
dmu_buf_hold(objset_t *os, uint64_t object, uint64_t offset,
    void *tag, dmu_buf_t **dbp)
{
	dnode_t *dn;
	uint64_t blkid;
	dmu_buf_impl_t *db;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	blkid = dbuf_whichblock(dn, offset);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	db = dbuf_hold(dn, blkid, tag);
	rw_exit(&dn->dn_struct_rwlock);
	if (db == NULL) {
		err = EIO;
	} else {
		err = dbuf_read(db, NULL, DB_RF_CANFAIL);
		if (err) {
			dbuf_rele(db, tag);
			db = NULL;
		}
	}

	dnode_rele(dn, FTAG);
	*dbp = &db->db;
	return (err);
}

int
dmu_bonus_max(void)
{
	return (DN_MAX_BONUSLEN);
}

/*
 * returns ENOENT, EIO, or 0.
 */
int
dmu_bonus_hold(objset_t *os, uint64_t object, void *tag, dmu_buf_t **dbp)
{
	dnode_t *dn;
	int err, count;
	dmu_buf_impl_t *db;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_bonus == NULL) {
		rw_exit(&dn->dn_struct_rwlock);
		rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
		if (dn->dn_bonus == NULL)
			dn->dn_bonus = dbuf_create_bonus(dn);
	}
	db = dn->dn_bonus;
	rw_exit(&dn->dn_struct_rwlock);
	mutex_enter(&db->db_mtx);
	count = refcount_add(&db->db_holds, tag);
	mutex_exit(&db->db_mtx);
	if (count == 1)
		dnode_add_ref(dn, db);
	dnode_rele(dn, FTAG);

	VERIFY(0 == dbuf_read(db, NULL, DB_RF_MUST_SUCCEED));

	*dbp = &db->db;
	return (0);
}

/*
 * Note: longer-term, we should modify all of the dmu_buf_*() interfaces
 * to take a held dnode rather than <os, object> -- the lookup is wasteful,
 * and can induce severe lock contention when writing to several files
 * whose dnodes are in the same block.
 */
static int
dmu_buf_hold_array_by_dnode(dnode_t *dn, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dmu_buf_t **dbp;
	uint64_t blkid, nblks, i;
	uint32_t flags;
	int err;
	zio_t *zio;

	ASSERT(length <= DMU_MAX_ACCESS);

	flags = DB_RF_CANFAIL | DB_RF_NEVERWAIT;
	if (length > zfetch_array_rd_sz)
		flags |= DB_RF_NOPREFETCH;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+length, 1ULL<<blkshift) -
			P2ALIGN(offset, 1ULL<<blkshift)) >> blkshift;
	} else {
		ASSERT3U(offset + length, <=, dn->dn_datablksz);
		nblks = 1;
	}
	dbp = kmem_zalloc(sizeof (dmu_buf_t *) * nblks, KM_SLEEP);

	zio = zio_root(dn->dn_objset->os_spa, NULL, NULL, TRUE);
	blkid = dbuf_whichblock(dn, offset);
	for (i = 0; i < nblks; i++) {
		dmu_buf_impl_t *db = dbuf_hold(dn, blkid+i, tag);
		if (db == NULL) {
			rw_exit(&dn->dn_struct_rwlock);
			dmu_buf_rele_array(dbp, nblks, tag);
			zio_nowait(zio);
			return (EIO);
		}
		/* initiate async i/o */
		if (read) {
			rw_exit(&dn->dn_struct_rwlock);
			(void) dbuf_read(db, zio, flags);
			rw_enter(&dn->dn_struct_rwlock, RW_READER);
		}
		dbp[i] = &db->db;
	}
	rw_exit(&dn->dn_struct_rwlock);

	/* wait for async i/o */
	err = zio_wait(zio);
	if (err) {
		dmu_buf_rele_array(dbp, nblks, tag);
		return (err);
	}

	/* wait for other io to complete */
	if (read) {
		for (i = 0; i < nblks; i++) {
			dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbp[i];
			mutex_enter(&db->db_mtx);
			while (db->db_state == DB_READ ||
			    db->db_state == DB_FILL)
				cv_wait(&db->db_changed, &db->db_mtx);
			if (db->db_state == DB_UNCACHED)
				err = EIO;
			mutex_exit(&db->db_mtx);
			if (err) {
				dmu_buf_rele_array(dbp, nblks, tag);
				return (err);
			}
		}
	}

	*numbufsp = nblks;
	*dbpp = dbp;
	return (0);
}

static int
dmu_buf_hold_array(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);

	err = dmu_buf_hold_array_by_dnode(dn, offset, length, read, tag,
	    numbufsp, dbpp);

	dnode_rele(dn, FTAG);

	return (err);
}

int
dmu_buf_hold_array_by_bonus(dmu_buf_t *db, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;
	int err;

	err = dmu_buf_hold_array_by_dnode(dn, offset, length, read, tag,
	    numbufsp, dbpp);

	return (err);
}

void
dmu_buf_rele_array(dmu_buf_t **dbp_fake, int numbufs, void *tag)
{
	int i;
	dmu_buf_impl_t **dbp = (dmu_buf_impl_t **)dbp_fake;

	if (numbufs == 0)
		return;

	for (i = 0; i < numbufs; i++) {
		if (dbp[i])
			dbuf_rele(dbp[i], tag);
	}

	kmem_free(dbp, sizeof (dmu_buf_t *) * numbufs);
}

void
dmu_prefetch(objset_t *os, uint64_t object, uint64_t offset, uint64_t len)
{
	dnode_t *dn;
	uint64_t blkid;
	int nblks, i, err;

	if (len == 0) {  /* they're interested in the bonus buffer */
		dn = os->os->os_meta_dnode;

		if (object == 0 || object >= DN_MAX_OBJECT)
			return;

		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		blkid = dbuf_whichblock(dn, object * sizeof (dnode_phys_t));
		dbuf_prefetch(dn, blkid);
		rw_exit(&dn->dn_struct_rwlock);
		return;
	}

	/*
	 * XXX - Note, if the dnode for the requested object is not
	 * already cached, we will do a *synchronous* read in the
	 * dnode_hold() call.  The same is true for any indirects.
	 */
	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err != 0)
		return;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+len, 1<<blkshift) -
			P2ALIGN(offset, 1<<blkshift)) >> blkshift;
	} else {
		nblks = (offset < dn->dn_datablksz);
	}

	if (nblks != 0) {
		blkid = dbuf_whichblock(dn, offset);
		for (i = 0; i < nblks; i++)
			dbuf_prefetch(dn, blkid+i);
	}

	rw_exit(&dn->dn_struct_rwlock);

	dnode_rele(dn, FTAG);
}

int
dmu_free_range(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t size, dmu_tx_t *tx)
{
	dnode_t *dn;
	int err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	ASSERT(offset < UINT64_MAX);
	ASSERT(size == -1ULL || size <= UINT64_MAX - offset);
	dnode_free_range(dn, offset, size, tx);
	dnode_rele(dn, FTAG);
	return (0);
}

int
dmu_read(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *buf)
{
	dnode_t *dn;
	dmu_buf_t **dbp;
	int numbufs, i, err;

	/*
	 * Deal with odd block sizes, where there can't be data past the
	 * first block.
	 */
	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	if (dn->dn_datablkshift == 0) {
		int newsz = offset > dn->dn_datablksz ? 0 :
		    MIN(size, dn->dn_datablksz - offset);
		bzero((char *)buf + newsz, size - newsz);
		size = newsz;
	}

	while (size > 0) {
		uint64_t mylen = MIN(size, DMU_MAX_ACCESS / 2);
		int err;

		/*
		 * NB: we could do this block-at-a-time, but it's nice
		 * to be reading in parallel.
		 */
		err = dmu_buf_hold_array_by_dnode(dn, offset, mylen,
		    TRUE, FTAG, &numbufs, &dbp);
		if (err)
			return (err);

		for (i = 0; i < numbufs; i++) {
			int tocpy;
			int bufoff;
			dmu_buf_t *db = dbp[i];

			ASSERT(size > 0);

			bufoff = offset - db->db_offset;
			tocpy = (int)MIN(db->db_size - bufoff, size);

			bcopy((char *)db->db_data + bufoff, buf, tocpy);

			offset += tocpy;
			size -= tocpy;
			buf = (char *)buf + tocpy;
		}
		dmu_buf_rele_array(dbp, numbufs, FTAG);
	}
	dnode_rele(dn, FTAG);
	return (0);
}

void
dmu_write(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    const void *buf, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;

	if (size == 0)
		return;

	VERIFY(0 == dmu_buf_hold_array(os, object, offset, size,
	    FALSE, FTAG, &numbufs, &dbp));

	for (i = 0; i < numbufs; i++) {
		int tocpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];

		ASSERT(size > 0);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		bcopy(buf, (char *)db->db_data + bufoff, tocpy);

		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		offset += tocpy;
		size -= tocpy;
		buf = (char *)buf + tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
}

#ifdef _KERNEL
int
dmu_write_uio(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    uio_t *uio, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err = 0;

	if (size == 0)
		return (0);

	err = dmu_buf_hold_array(os, object, offset, size,
	    FALSE, FTAG, &numbufs, &dbp);
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];

		ASSERT(size > 0);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		/*
		 * XXX uiomove could block forever (eg. nfs-backed
		 * pages).  There needs to be a uiolockdown() function
		 * to lock the pages in memory, so that uiomove won't
		 * block.
		 */
		err = uiomove((char *)db->db_data + bufoff, tocpy,
		    UIO_WRITE, uio);

		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		if (err)
			break;

		offset += tocpy;
		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
	return (err);
}

int
dmu_write_pages(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    page_t *pp, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err;

	if (size == 0)
		return (0);

	err = dmu_buf_hold_array(os, object, offset, size,
	    FALSE, FTAG, &numbufs, &dbp);
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy, copied, thiscpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];
		caddr_t va;

		ASSERT(size > 0);
		ASSERT3U(db->db_size, >=, PAGESIZE);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		for (copied = 0; copied < tocpy; copied += PAGESIZE) {
			ASSERT3U(pp->p_offset, ==, db->db_offset + bufoff);
			thiscpy = MIN(PAGESIZE, tocpy - copied);
			va = ppmapin(pp, PROT_READ, (caddr_t)-1);
			bcopy(va, (char *)db->db_data + bufoff, thiscpy);
			ppmapout(va);
			pp = pp->p_next;
			bufoff += PAGESIZE;
		}

		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		if (err)
			break;

		offset += tocpy;
		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
	return (err);
}
#endif

typedef struct {
	uint64_t	txg;
	dmu_buf_impl_t	*db;
	dmu_sync_cb_t	*done;
	void		*arg;
} dmu_sync_cbin_t;

typedef union {
	dmu_sync_cbin_t	data;
	blkptr_t	blk;
} dmu_sync_cbarg_t;

/* ARGSUSED */
static void
dmu_sync_done(zio_t *zio, arc_buf_t *buf, void *varg)
{
	dmu_sync_cbin_t *in = (dmu_sync_cbin_t *)varg;
	dmu_buf_impl_t *db = in->db;
	uint64_t txg = in->txg;
	dmu_sync_cb_t *done = in->done;
	void *arg = in->arg;
	blkptr_t *blk = (blkptr_t *)varg;

	if (!BP_IS_HOLE(zio->io_bp)) {
		zio->io_bp->blk_fill = 1;
		BP_SET_TYPE(zio->io_bp, db->db_dnode->dn_type);
		BP_SET_LEVEL(zio->io_bp, 0);
	}

	*blk = *zio->io_bp; /* structure assignment */

	mutex_enter(&db->db_mtx);
	ASSERT(db->db_d.db_overridden_by[txg&TXG_MASK] == IN_DMU_SYNC);
	db->db_d.db_overridden_by[txg&TXG_MASK] = blk;
	cv_broadcast(&db->db_changed);
	mutex_exit(&db->db_mtx);

	if (done)
		done(&(db->db), arg);
}

/*
 * Intent log support: sync the block associated with db to disk.
 * N.B. and XXX: the caller is responsible for making sure that the
 * data isn't changing while dmu_sync() is writing it.
 *
 * Return values:
 *
 *	EEXIST: this txg has already been synced, so there's nothing to to.
 *		The caller should not log the write.
 *
 *	ENOENT: the block was dbuf_free_range()'d, so there's nothing to do.
 *		The caller should not log the write.
 *
 *	EALREADY: this block is already in the process of being synced.
 *		The caller should track its progress (somehow).
 *
 *	EINPROGRESS: the IO has been initiated.
 *		The caller should log this blkptr in the callback.
 *
 *	0: completed.  Sets *bp to the blkptr just written.
 *		The caller should log this blkptr immediately.
 */
int
dmu_sync(zio_t *pio, dmu_buf_t *db_fake,
    blkptr_t *bp, uint64_t txg, dmu_sync_cb_t *done, void *arg)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	objset_impl_t *os = db->db_objset;
	dsl_pool_t *dp = os->os_dsl_dataset->ds_dir->dd_pool;
	tx_state_t *tx = &dp->dp_tx;
	dmu_sync_cbin_t *in;
	blkptr_t *blk;
	zbookmark_t zb;
	uint32_t arc_flag;
	int err;

	ASSERT(BP_IS_HOLE(bp));
	ASSERT(txg != 0);


	dprintf("dmu_sync txg=%llu, s,o,q %llu %llu %llu\n",
	    txg, tx->tx_synced_txg, tx->tx_open_txg, tx->tx_quiesced_txg);

	/*
	 * XXX - would be nice if we could do this without suspending...
	 */
	txg_suspend(dp);

	/*
	 * If this txg already synced, there's nothing to do.
	 */
	if (txg <= tx->tx_synced_txg) {
		txg_resume(dp);
		/*
		 * If we're running ziltest, we need the blkptr regardless.
		 */
		if (txg > spa_freeze_txg(dp->dp_spa)) {
			/* if db_blkptr == NULL, this was an empty write */
			if (db->db_blkptr)
				*bp = *db->db_blkptr; /* structure assignment */
			return (0);
		}
		return (EEXIST);
	}

	mutex_enter(&db->db_mtx);

	blk = db->db_d.db_overridden_by[txg&TXG_MASK];
	if (blk == IN_DMU_SYNC) {
		/*
		 * We have already issued a sync write for this buffer.
		 */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (EALREADY);
	} else if (blk != NULL) {
		/*
		 * This buffer had already been synced.  It could not
		 * have been dirtied since, or we would have cleared blk.
		 */
		*bp = *blk; /* structure assignment */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (0);
	}

	if (txg == tx->tx_syncing_txg) {
		while (db->db_data_pending) {
			/*
			 * IO is in-progress.  Wait for it to finish.
			 * XXX - would be nice to be able to somehow "attach"
			 * this zio to the parent zio passed in.
			 */
			cv_wait(&db->db_changed, &db->db_mtx);
			if (!db->db_data_pending &&
			    db->db_blkptr && BP_IS_HOLE(db->db_blkptr)) {
				/*
				 * IO was compressed away
				 */
				*bp = *db->db_blkptr; /* structure assignment */
				mutex_exit(&db->db_mtx);
				txg_resume(dp);
				return (0);
			}
			ASSERT(db->db_data_pending ||
			    (db->db_blkptr && db->db_blkptr->blk_birth == txg));
		}

		if (db->db_blkptr && db->db_blkptr->blk_birth == txg) {
			/*
			 * IO is already completed.
			 */
			*bp = *db->db_blkptr; /* structure assignment */
			mutex_exit(&db->db_mtx);
			txg_resume(dp);
			return (0);
		}
	}

	if (db->db_d.db_data_old[txg&TXG_MASK] == NULL) {
		/*
		 * This dbuf isn't dirty, must have been free_range'd.
		 * There's no need to log writes to freed blocks, so we're done.
		 */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (ENOENT);
	}

	ASSERT(db->db_d.db_overridden_by[txg&TXG_MASK] == NULL);
	db->db_d.db_overridden_by[txg&TXG_MASK] = IN_DMU_SYNC;
	/*
	 * XXX - a little ugly to stash the blkptr in the callback
	 * buffer.  We always need to make sure the following is true:
	 * ASSERT(sizeof(blkptr_t) >= sizeof(dmu_sync_cbin_t));
	 */
	in = kmem_alloc(sizeof (blkptr_t), KM_SLEEP);
	in->db = db;
	in->txg = txg;
	in->done = done;
	in->arg = arg;
	mutex_exit(&db->db_mtx);
	txg_resume(dp);

	arc_flag = pio == NULL ? ARC_WAIT : ARC_NOWAIT;
	zb.zb_objset = os->os_dsl_dataset->ds_object;
	zb.zb_object = db->db.db_object;
	zb.zb_level = db->db_level;
	zb.zb_blkid = db->db_blkid;
	err = arc_write(pio, os->os_spa,
	    zio_checksum_select(db->db_dnode->dn_checksum, os->os_checksum),
	    zio_compress_select(db->db_dnode->dn_compress, os->os_compress),
	    dmu_get_replication_level(os->os_spa, &zb, db->db_dnode->dn_type),
	    txg, bp, db->db_d.db_data_old[txg&TXG_MASK], dmu_sync_done, in,
	    ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_MUSTSUCCEED, arc_flag, &zb);
	ASSERT(err == 0);

	return (arc_flag == ARC_NOWAIT ? EINPROGRESS : 0);
}

int
dmu_object_set_blocksize(objset_t *os, uint64_t object, uint64_t size, int ibs,
	dmu_tx_t *tx)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	err = dnode_set_blksz(dn, size, ibs, tx);
	dnode_rele(dn, FTAG);
	return (err);
}

void
dmu_object_set_checksum(objset_t *os, uint64_t object, uint8_t checksum,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os->os, object, FTAG, &dn);
	ASSERT(checksum < ZIO_CHECKSUM_FUNCTIONS);
	dn->dn_checksum = checksum;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

void
dmu_object_set_compress(objset_t *os, uint64_t object, uint8_t compress,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os->os, object, FTAG, &dn);
	ASSERT(compress < ZIO_COMPRESS_FUNCTIONS);
	dn->dn_compress = compress;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

/*
 * XXX - eventually, this should take into account per-dataset (or
 *       even per-object?) user requests for higher levels of replication.
 */
int
dmu_get_replication_level(spa_t *spa, zbookmark_t *zb, dmu_object_type_t ot)
{
	int ncopies = 1;

	if (dmu_ot[ot].ot_metadata)
		ncopies++;
	if (zb->zb_level != 0)
		ncopies++;
	if (zb->zb_objset == 0 && zb->zb_object == 0)
		ncopies++;
	return (MIN(ncopies, spa_max_replication(spa)));
}

int
dmu_offset_next(objset_t *os, uint64_t object, boolean_t hole, uint64_t *off)
{
	dnode_t *dn;
	int i, err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	/*
	 * Sync any current changes before
	 * we go trundling through the block pointers.
	 */
	for (i = 0; i < TXG_SIZE; i++) {
		if (list_link_active(&dn->dn_dirty_link[i]))
			break;
	}
	if (i != TXG_SIZE) {
		dnode_rele(dn, FTAG);
		txg_wait_synced(dmu_objset_pool(os), 0);
		err = dnode_hold(os->os, object, FTAG, &dn);
		if (err)
			return (err);
	}

	err = dnode_next_offset(dn, hole, off, 1, 1);
	dnode_rele(dn, FTAG);

	return (err);
}

void
dmu_object_info_from_dnode(dnode_t *dn, dmu_object_info_t *doi)
{
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	mutex_enter(&dn->dn_mtx);

	doi->doi_data_block_size = dn->dn_datablksz;
	doi->doi_metadata_block_size = dn->dn_indblkshift ?
	    1ULL << dn->dn_indblkshift : 0;
	doi->doi_indirection = dn->dn_nlevels;
	doi->doi_checksum = dn->dn_checksum;
	doi->doi_compress = dn->dn_compress;
	doi->doi_physical_blks = (DN_USED_BYTES(dn->dn_phys) +
	    SPA_MINBLOCKSIZE/2) >> SPA_MINBLOCKSHIFT;
	doi->doi_max_block_offset = dn->dn_phys->dn_maxblkid;
	doi->doi_type = dn->dn_type;
	doi->doi_bonus_size = dn->dn_bonuslen;
	doi->doi_bonus_type = dn->dn_bonustype;

	mutex_exit(&dn->dn_mtx);
	rw_exit(&dn->dn_struct_rwlock);
}

/*
 * Get information on a DMU object.
 * If doi is NULL, just indicates whether the object exists.
 */
int
dmu_object_info(objset_t *os, uint64_t object, dmu_object_info_t *doi)
{
	dnode_t *dn;
	int err = dnode_hold(os->os, object, FTAG, &dn);

	if (err)
		return (err);

	if (doi != NULL)
		dmu_object_info_from_dnode(dn, doi);

	dnode_rele(dn, FTAG);
	return (0);
}

/*
 * As above, but faster; can be used when you have a held dbuf in hand.
 */
void
dmu_object_info_from_db(dmu_buf_t *db, dmu_object_info_t *doi)
{
	dmu_object_info_from_dnode(((dmu_buf_impl_t *)db)->db_dnode, doi);
}

/*
 * Faster still when you only care about the size.
 * This is specifically optimized for zfs_getattr().
 */
void
dmu_object_size_from_db(dmu_buf_t *db, uint32_t *blksize, u_longlong_t *nblk512)
{
	dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;

	*blksize = dn->dn_datablksz;
	/* add 1 for dnode space */
	*nblk512 = ((DN_USED_BYTES(dn->dn_phys) + SPA_MINBLOCKSIZE/2) >>
	    SPA_MINBLOCKSHIFT) + 1;
}

/*
 * Given a bookmark, return the name of the dataset, object, and range in
 * human-readable format.
 */
int
spa_bookmark_name(spa_t *spa, zbookmark_t *zb, nvlist_t *nvl)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds = NULL;
	objset_t *os = NULL;
	dnode_t *dn = NULL;
	int err, shift;
	char dsname[MAXNAMELEN];
	char objname[32];
	char range[64];

	dp = spa_get_dsl(spa);
	if (zb->zb_objset != 0) {
		rw_enter(&dp->dp_config_rwlock, RW_READER);
		err = dsl_dataset_open_obj(dp, zb->zb_objset,
		    NULL, DS_MODE_NONE, FTAG, &ds);
		if (err) {
			rw_exit(&dp->dp_config_rwlock);
			return (err);
		}
		dsl_dataset_name(ds, dsname);
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		rw_exit(&dp->dp_config_rwlock);

		err = dmu_objset_open(dsname, DMU_OST_ANY, DS_MODE_NONE, &os);
		if (err)
			goto out;

	} else {
		dsl_dataset_name(NULL, dsname);
		os = dp->dp_meta_objset;
	}


	if (zb->zb_object == DMU_META_DNODE_OBJECT) {
		(void) strncpy(objname, "mdn", sizeof (objname));
	} else {
		(void) snprintf(objname, sizeof (objname), "%lld",
		    (longlong_t)zb->zb_object);
	}

	err = dnode_hold(os->os, zb->zb_object, FTAG, &dn);
	if (err)
		goto out;

	shift = (dn->dn_datablkshift?dn->dn_datablkshift:SPA_MAXBLOCKSHIFT) +
	    zb->zb_level * (dn->dn_indblkshift - SPA_BLKPTRSHIFT);
	(void) snprintf(range, sizeof (range), "%llu-%llu",
	    (u_longlong_t)(zb->zb_blkid << shift),
	    (u_longlong_t)((zb->zb_blkid+1) << shift));

	if ((err = nvlist_add_string(nvl, ZPOOL_ERR_DATASET, dsname)) != 0 ||
	    (err = nvlist_add_string(nvl, ZPOOL_ERR_OBJECT, objname)) != 0 ||
	    (err = nvlist_add_string(nvl, ZPOOL_ERR_RANGE, range)) != 0)
		goto out;

out:
	if (dn)
		dnode_rele(dn, FTAG);
	if (os && os != dp->dp_meta_objset)
		dmu_objset_close(os);
	return (err);
}

void
byteswap_uint64_array(void *vbuf, size_t size)
{
	uint64_t *buf = vbuf;
	size_t count = size >> 3;
	int i;

	ASSERT((size & 7) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_64(buf[i]);
}

void
byteswap_uint32_array(void *vbuf, size_t size)
{
	uint32_t *buf = vbuf;
	size_t count = size >> 2;
	int i;

	ASSERT((size & 3) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_32(buf[i]);
}

void
byteswap_uint16_array(void *vbuf, size_t size)
{
	uint16_t *buf = vbuf;
	size_t count = size >> 1;
	int i;

	ASSERT((size & 1) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_16(buf[i]);
}

/* ARGSUSED */
void
byteswap_uint8_array(void *vbuf, size_t size)
{
}

void
dmu_init(void)
{
	dbuf_init();
	dnode_init();
	arc_init();
}

void
dmu_fini(void)
{
	arc_fini();
	dnode_fini();
	dbuf_fini();
}
