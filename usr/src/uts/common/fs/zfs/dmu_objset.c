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

#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_pool.h>
#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/dmu_tx.h>
#include <sys/zio_checksum.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/dmu_impl.h>


spa_t *
dmu_objset_spa(objset_t *os)
{
	return (os->os->os_spa);
}

zilog_t *
dmu_objset_zil(objset_t *os)
{
	return (os->os->os_zil);
}

dsl_pool_t *
dmu_objset_pool(objset_t *os)
{
	dsl_dataset_t *ds;

	if ((ds = os->os->os_dsl_dataset) != NULL && ds->ds_dir)
		return (ds->ds_dir->dd_pool);
	else
		return (spa_get_dsl(os->os->os_spa));
}

dsl_dataset_t *
dmu_objset_ds(objset_t *os)
{
	return (os->os->os_dsl_dataset);
}

dmu_objset_type_t
dmu_objset_type(objset_t *os)
{
	return (os->os->os_phys->os_type);
}

void
dmu_objset_name(objset_t *os, char *buf)
{
	dsl_dataset_name(os->os->os_dsl_dataset, buf);
}

uint64_t
dmu_objset_id(objset_t *os)
{
	dsl_dataset_t *ds = os->os->os_dsl_dataset;

	return (ds ? ds->ds_object : 0);
}

static void
checksum_changed_cb(void *arg, uint64_t newval)
{
	objset_impl_t *osi = arg;

	/*
	 * Inheritance should have been done by now.
	 */
	ASSERT(newval != ZIO_CHECKSUM_INHERIT);

	osi->os_checksum = zio_checksum_select(newval, ZIO_CHECKSUM_ON_VALUE);
}

static void
compression_changed_cb(void *arg, uint64_t newval)
{
	objset_impl_t *osi = arg;

	/*
	 * Inheritance and range checking should have been done by now.
	 */
	ASSERT(newval != ZIO_COMPRESS_INHERIT);

	osi->os_compress = zio_compress_select(newval, ZIO_COMPRESS_ON_VALUE);
}

void
dmu_objset_byteswap(void *buf, size_t size)
{
	objset_phys_t *osp = buf;

	ASSERT(size == sizeof (objset_phys_t));
	dnode_byteswap(&osp->os_meta_dnode);
	byteswap_uint64_array(&osp->os_zil_header, sizeof (zil_header_t));
	osp->os_type = BSWAP_64(osp->os_type);
}

int
dmu_objset_open_impl(spa_t *spa, dsl_dataset_t *ds, blkptr_t *bp,
    objset_impl_t **osip)
{
	objset_impl_t *winner, *osi;
	int i, err, checksum;

	osi = kmem_zalloc(sizeof (objset_impl_t), KM_SLEEP);
	osi->os.os = osi;
	osi->os_dsl_dataset = ds;
	osi->os_spa = spa;
	if (bp)
		osi->os_rootbp = *bp;
	osi->os_phys = zio_buf_alloc(sizeof (objset_phys_t));
	if (!BP_IS_HOLE(&osi->os_rootbp)) {
		zbookmark_t zb;
		zb.zb_objset = ds ? ds->ds_object : 0;
		zb.zb_object = 0;
		zb.zb_level = -1;
		zb.zb_blkid = 0;

		dprintf_bp(&osi->os_rootbp, "reading %s", "");
		err = arc_read(NULL, spa, &osi->os_rootbp,
		    dmu_ot[DMU_OT_OBJSET].ot_byteswap,
		    arc_bcopy_func, osi->os_phys,
		    ZIO_PRIORITY_SYNC_READ, ZIO_FLAG_CANFAIL, ARC_WAIT, &zb);
		if (err) {
			zio_buf_free(osi->os_phys, sizeof (objset_phys_t));
			kmem_free(osi, sizeof (objset_impl_t));
			return (err);
		}
	} else {
		bzero(osi->os_phys, sizeof (objset_phys_t));
	}

	/*
	 * Note: the changed_cb will be called once before the register
	 * func returns, thus changing the checksum/compression from the
	 * default (fletcher2/off).  Snapshots don't need to know, and
	 * registering would complicate clone promotion.
	 */
	if (ds && ds->ds_phys->ds_num_children == 0) {
		err = dsl_prop_register(ds, "checksum",
		    checksum_changed_cb, osi);
		if (err == 0)
			err = dsl_prop_register(ds, "compression",
			    compression_changed_cb, osi);
		if (err) {
			zio_buf_free(osi->os_phys, sizeof (objset_phys_t));
			kmem_free(osi, sizeof (objset_impl_t));
			return (err);
		}
	} else if (ds == NULL) {
		/* It's the meta-objset. */
		osi->os_checksum = ZIO_CHECKSUM_FLETCHER_4;
		osi->os_compress = ZIO_COMPRESS_LZJB;
	}

	osi->os_zil = zil_alloc(&osi->os, &osi->os_phys->os_zil_header);

	/*
	 * Metadata always gets compressed and checksummed.
	 * If the data checksum is multi-bit correctable, and it's not
	 * a ZBT-style checksum, then it's suitable for metadata as well.
	 * Otherwise, the metadata checksum defaults to fletcher4.
	 */
	checksum = osi->os_checksum;

	if (zio_checksum_table[checksum].ci_correctable &&
	    !zio_checksum_table[checksum].ci_zbt)
		osi->os_md_checksum = checksum;
	else
		osi->os_md_checksum = ZIO_CHECKSUM_FLETCHER_4;
	osi->os_md_compress = ZIO_COMPRESS_LZJB;

	for (i = 0; i < TXG_SIZE; i++) {
		list_create(&osi->os_dirty_dnodes[i], sizeof (dnode_t),
		    offsetof(dnode_t, dn_dirty_link[i]));
		list_create(&osi->os_free_dnodes[i], sizeof (dnode_t),
		    offsetof(dnode_t, dn_dirty_link[i]));
	}
	list_create(&osi->os_dnodes, sizeof (dnode_t),
	    offsetof(dnode_t, dn_link));
	list_create(&osi->os_downgraded_dbufs, sizeof (dmu_buf_impl_t),
	    offsetof(dmu_buf_impl_t, db_link));

	osi->os_meta_dnode = dnode_special_open(osi,
	    &osi->os_phys->os_meta_dnode, DMU_META_DNODE_OBJECT);

	if (ds != NULL) {
		winner = dsl_dataset_set_user_ptr(ds, osi, dmu_objset_evict);
		if (winner) {
			dmu_objset_evict(ds, osi);
			osi = winner;
		}
	}

	*osip = osi;
	return (0);
}

/* called from zpl */
int
dmu_objset_open(const char *name, dmu_objset_type_t type, int mode,
    objset_t **osp)
{
	dsl_dataset_t *ds;
	int err;
	objset_t *os;
	objset_impl_t *osi;

	os = kmem_alloc(sizeof (objset_t), KM_SLEEP);
	err = dsl_dataset_open(name, mode, os, &ds);
	if (err) {
		kmem_free(os, sizeof (objset_t));
		return (err);
	}

	osi = dsl_dataset_get_user_ptr(ds);
	if (osi == NULL) {
		blkptr_t bp;

		dsl_dataset_get_blkptr(ds, &bp);
		err = dmu_objset_open_impl(dsl_dataset_get_spa(ds),
		    ds, &bp, &osi);
		if (err) {
			dsl_dataset_close(ds, mode, os);
			kmem_free(os, sizeof (objset_t));
			return (err);
		}
	}

	os->os = osi;
	os->os_mode = mode;

	if (type != DMU_OST_ANY && type != os->os->os_phys->os_type) {
		dmu_objset_close(os);
		return (EINVAL);
	}
	*osp = os;
	return (0);
}

void
dmu_objset_close(objset_t *os)
{
	dsl_dataset_close(os->os->os_dsl_dataset, os->os_mode, os);
	kmem_free(os, sizeof (objset_t));
}

int
dmu_objset_evict_dbufs(objset_t *os, int try)
{
	objset_impl_t *osi = os->os;
	dnode_t *dn;

	mutex_enter(&osi->os_lock);

	/* process the mdn last, since the other dnodes have holds on it */
	list_remove(&osi->os_dnodes, osi->os_meta_dnode);
	list_insert_tail(&osi->os_dnodes, osi->os_meta_dnode);

	/*
	 * Find the first dnode with holds.  We have to do this dance
	 * because dnode_add_ref() only works if you already have a
	 * hold.  If there are no holds then it has no dbufs so OK to
	 * skip.
	 */
	for (dn = list_head(&osi->os_dnodes);
	    dn && refcount_is_zero(&dn->dn_holds);
	    dn = list_next(&osi->os_dnodes, dn))
		continue;
	if (dn)
		dnode_add_ref(dn, FTAG);

	while (dn) {
		dnode_t *next_dn = dn;

		do {
			next_dn = list_next(&osi->os_dnodes, next_dn);
		} while (next_dn && refcount_is_zero(&next_dn->dn_holds));
		if (next_dn)
			dnode_add_ref(next_dn, FTAG);

		mutex_exit(&osi->os_lock);
		if (dnode_evict_dbufs(dn, try)) {
			dnode_rele(dn, FTAG);
			if (next_dn)
				dnode_rele(next_dn, FTAG);
			return (1);
		}
		dnode_rele(dn, FTAG);
		mutex_enter(&osi->os_lock);
		dn = next_dn;
	}
	mutex_exit(&osi->os_lock);
	return (0);
}

void
dmu_objset_evict(dsl_dataset_t *ds, void *arg)
{
	objset_impl_t *osi = arg;
	objset_t os;
	int i;

	for (i = 0; i < TXG_SIZE; i++) {
		ASSERT(list_head(&osi->os_dirty_dnodes[i]) == NULL);
		ASSERT(list_head(&osi->os_free_dnodes[i]) == NULL);
	}

	if (ds && ds->ds_phys->ds_num_children == 0) {
		VERIFY(0 == dsl_prop_unregister(ds, "checksum",
		    checksum_changed_cb, osi));
		VERIFY(0 == dsl_prop_unregister(ds, "compression",
		    compression_changed_cb, osi));
	}

	/*
	 * We should need only a single pass over the dnode list, since
	 * nothing can be added to the list at this point.
	 */
	os.os = osi;
	(void) dmu_objset_evict_dbufs(&os, 0);

	ASSERT3P(list_head(&osi->os_dnodes), ==, osi->os_meta_dnode);
	ASSERT3P(list_tail(&osi->os_dnodes), ==, osi->os_meta_dnode);
	ASSERT3P(list_head(&osi->os_meta_dnode->dn_dbufs), ==, NULL);

	dnode_special_close(osi->os_meta_dnode);
	zil_free(osi->os_zil);

	zio_buf_free(osi->os_phys, sizeof (objset_phys_t));
	kmem_free(osi, sizeof (objset_impl_t));
}

/* called from dsl for meta-objset */
objset_impl_t *
dmu_objset_create_impl(spa_t *spa, dsl_dataset_t *ds, dmu_objset_type_t type,
    dmu_tx_t *tx)
{
	objset_impl_t *osi;
	dnode_t *mdn;

	ASSERT(dmu_tx_is_syncing(tx));
	VERIFY(0 == dmu_objset_open_impl(spa, ds, NULL, &osi));
	mdn = osi->os_meta_dnode;

	dnode_allocate(mdn, DMU_OT_DNODE, 1 << DNODE_BLOCK_SHIFT,
	    DN_MAX_INDBLKSHIFT, DMU_OT_NONE, 0, tx);

	/*
	 * We don't want to have to increase the meta-dnode's nlevels
	 * later, because then we could do it in quescing context while
	 * we are also accessing it in open context.
	 *
	 * This precaution is not necessary for the MOS (ds == NULL),
	 * because the MOS is only updated in syncing context.
	 * This is most fortunate: the MOS is the only objset that
	 * needs to be synced multiple times as spa_sync() iterates
	 * to convergence, so minimizing its dn_nlevels matters.
	 */
	if (ds != NULL) {
		int levels = 1;

		/*
		 * Determine the number of levels necessary for the meta-dnode
		 * to contain DN_MAX_OBJECT dnodes.
		 */
		while ((uint64_t)mdn->dn_nblkptr << (mdn->dn_datablkshift +
		    (levels - 1) * (mdn->dn_indblkshift - SPA_BLKPTRSHIFT)) <
		    DN_MAX_OBJECT * sizeof (dnode_phys_t))
			levels++;

		mdn->dn_next_nlevels[tx->tx_txg & TXG_MASK] =
		    mdn->dn_nlevels = levels;
	}

	ASSERT(type != DMU_OST_NONE);
	ASSERT(type != DMU_OST_ANY);
	ASSERT(type < DMU_OST_NUMTYPES);
	osi->os_phys->os_type = type;

	dsl_dataset_dirty(ds, tx);

	return (osi);
}

struct oscarg {
	void (*userfunc)(objset_t *os, void *arg, dmu_tx_t *tx);
	void *userarg;
	dsl_dataset_t *clone_parent;
	const char *fullname;
	const char *lastname;
	dmu_objset_type_t type;
};

static int
dmu_objset_create_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct oscarg *oa = arg;
	dsl_dataset_t *ds;
	int err;
	blkptr_t bp;

	ASSERT(dmu_tx_is_syncing(tx));

	err = dsl_dataset_create_sync(dd, oa->fullname, oa->lastname,
	    oa->clone_parent, tx);
	dprintf_dd(dd, "fn=%s ln=%s err=%d\n",
	    oa->fullname, oa->lastname, err);
	if (err)
		return (err);

	VERIFY(0 == dsl_dataset_open_spa(dd->dd_pool->dp_spa, oa->fullname,
	    DS_MODE_STANDARD | DS_MODE_READONLY, FTAG, &ds));
	dsl_dataset_get_blkptr(ds, &bp);
	if (BP_IS_HOLE(&bp)) {
		objset_impl_t *osi;

		/* This is an empty dmu_objset; not a clone. */
		osi = dmu_objset_create_impl(dsl_dataset_get_spa(ds),
		    ds, oa->type, tx);

		if (oa->userfunc)
			oa->userfunc(&osi->os, oa->userarg, tx);
	}
	dsl_dataset_close(ds, DS_MODE_STANDARD | DS_MODE_READONLY, FTAG);

	return (0);
}

int
dmu_objset_create(const char *name, dmu_objset_type_t type,
    objset_t *clone_parent,
    void (*func)(objset_t *os, void *arg, dmu_tx_t *tx), void *arg)
{
	dsl_dir_t *pds;
	const char *tail;
	int err = 0;

	err = dsl_dir_open(name, FTAG, &pds, &tail);
	if (err)
		return (err);
	if (tail == NULL) {
		dsl_dir_close(pds, FTAG);
		return (EEXIST);
	}

	dprintf("name=%s\n", name);

	if (tail[0] == '@') {
		/*
		 * If we're creating a snapshot, make sure everything
		 * they might want is on disk.  XXX Sketchy to know
		 * about snapshots here, better to put in DSL.
		 */
		objset_t *os;
		size_t plen = strchr(name, '@') - name + 1;
		char *pbuf = kmem_alloc(plen, KM_SLEEP);
		bcopy(name, pbuf, plen - 1);
		pbuf[plen - 1] = '\0';

		err = dmu_objset_open(pbuf, DMU_OST_ANY, DS_MODE_STANDARD, &os);
		if (err == 0) {
			err = zil_suspend(dmu_objset_zil(os));
			if (err == 0) {
				err = dsl_dir_sync_task(pds,
				    dsl_dataset_snapshot_sync,
				    (void*)(tail+1), 16*1024);
				zil_resume(dmu_objset_zil(os));
			}
			dmu_objset_close(os);
		}
		kmem_free(pbuf, plen);
	} else {
		struct oscarg oa = { 0 };
		oa.userfunc = func;
		oa.userarg = arg;
		oa.fullname = name;
		oa.lastname = tail;
		oa.type = type;
		if (clone_parent != NULL) {
			/*
			 * You can't clone to a different type.
			 */
			if (clone_parent->os->os_phys->os_type != type) {
				dsl_dir_close(pds, FTAG);
				return (EINVAL);
			}
			oa.clone_parent = clone_parent->os->os_dsl_dataset;
		}
		err = dsl_dir_sync_task(pds, dmu_objset_create_sync, &oa,
		    256*1024);
	}
	dsl_dir_close(pds, FTAG);
	return (err);
}

int
dmu_objset_destroy(const char *name)
{
	objset_t *os;
	int error;

	/*
	 * If it looks like we'll be able to destroy it, and there's
	 * an unplayed replay log sitting around, destroy the log.
	 * It would be nicer to do this in dsl_dataset_destroy_sync(),
	 * but the replay log objset is modified in open context.
	 */
	error = dmu_objset_open(name, DMU_OST_ANY, DS_MODE_EXCLUSIVE, &os);
	if (error == 0) {
		zil_destroy(dmu_objset_zil(os), B_FALSE);
		dmu_objset_close(os);
	}

	/* XXX uncache everything? */
	return (dsl_dataset_destroy(name));
}

int
dmu_objset_rollback(const char *name)
{
	int err;
	objset_t *os;

	err = dmu_objset_open(name, DMU_OST_ANY, DS_MODE_EXCLUSIVE, &os);
	if (err == 0) {
		err = zil_suspend(dmu_objset_zil(os));
		if (err == 0)
			zil_resume(dmu_objset_zil(os));
		dmu_objset_close(os);
		if (err == 0) {
			/* XXX uncache everything? */
			err = dsl_dataset_rollback(name);
		}
	}
	return (err);
}

static void
dmu_objset_sync_dnodes(objset_impl_t *os, list_t *list, dmu_tx_t *tx)
{
	dnode_t *dn = list_head(list);
	int level, err;

	for (level = 0; dn = list_head(list); level++) {
		zio_t *zio;
		zio = zio_root(os->os_spa, NULL, NULL, ZIO_FLAG_MUSTSUCCEED);

		ASSERT3U(level, <=, DN_MAX_LEVELS);

		while (dn) {
			dnode_t *next = list_next(list, dn);

			list_remove(list, dn);
			if (dnode_sync(dn, level, zio, tx) == 0) {
				/*
				 * This dnode requires syncing at higher
				 * levels; put it back onto the list.
				 */
				if (next)
					list_insert_before(list, next, dn);
				else
					list_insert_tail(list, dn);
			}
			dn = next;
		}
		err = zio_wait(zio);
		ASSERT(err == 0);
	}
}

/* ARGSUSED */
static void
killer(zio_t *zio, arc_buf_t *abuf, void *arg)
{
	objset_impl_t *os = arg;
	objset_phys_t *osphys = zio->io_data;
	dnode_phys_t *dnp = &osphys->os_meta_dnode;
	int i;

	ASSERT3U(zio->io_error, ==, 0);

	/*
	 * Update rootbp fill count.
	 */
	os->os_rootbp.blk_fill = 1;	/* count the meta-dnode */
	for (i = 0; i < dnp->dn_nblkptr; i++)
		os->os_rootbp.blk_fill += dnp->dn_blkptr[i].blk_fill;

	BP_SET_TYPE(zio->io_bp, DMU_OT_OBJSET);
	BP_SET_LEVEL(zio->io_bp, 0);

	if (!DVA_EQUAL(BP_IDENTITY(zio->io_bp),
	    BP_IDENTITY(&zio->io_bp_orig))) {
		dsl_dataset_block_kill(os->os_dsl_dataset, &zio->io_bp_orig,
		    os->os_synctx);
		dsl_dataset_block_born(os->os_dsl_dataset, zio->io_bp,
		    os->os_synctx);
	}
}


/* called from dsl */
void
dmu_objset_sync(objset_impl_t *os, dmu_tx_t *tx)
{
	extern taskq_t *dbuf_tq;
	int txgoff;
	list_t *dirty_list;
	int err;
	zbookmark_t zb;
	arc_buf_t *abuf =
	    arc_buf_alloc(os->os_spa, sizeof (objset_phys_t), FTAG);

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(os->os_synctx == NULL);
	/* XXX the write_done callback should really give us the tx... */
	os->os_synctx = tx;

	dprintf_ds(os->os_dsl_dataset, "txg=%llu\n", tx->tx_txg);

	txgoff = tx->tx_txg & TXG_MASK;

	dmu_objset_sync_dnodes(os, &os->os_free_dnodes[txgoff], tx);
	dmu_objset_sync_dnodes(os, &os->os_dirty_dnodes[txgoff], tx);

	/*
	 * Free intent log blocks up to this tx.
	 */
	zil_sync(os->os_zil, tx);

	/*
	 * Sync meta-dnode
	 */
	dirty_list = &os->os_dirty_dnodes[txgoff];
	ASSERT(list_head(dirty_list) == NULL);
	list_insert_tail(dirty_list, os->os_meta_dnode);
	dmu_objset_sync_dnodes(os, dirty_list, tx);

	/*
	 * Sync the root block.
	 */
	bcopy(os->os_phys, abuf->b_data, sizeof (objset_phys_t));
	zb.zb_objset = os->os_dsl_dataset ? os->os_dsl_dataset->ds_object : 0;
	zb.zb_object = 0;
	zb.zb_level = -1;
	zb.zb_blkid = 0;
	err = arc_write(NULL, os->os_spa, os->os_md_checksum,
	    os->os_md_compress,
	    dmu_get_replication_level(os->os_spa, &zb, DMU_OT_OBJSET),
	    tx->tx_txg, &os->os_rootbp, abuf, killer, os,
	    ZIO_PRIORITY_ASYNC_WRITE, ZIO_FLAG_MUSTSUCCEED, ARC_WAIT, &zb);
	ASSERT(err == 0);
	VERIFY(arc_buf_remove_ref(abuf, FTAG) == 1);

	dsl_dataset_set_blkptr(os->os_dsl_dataset, &os->os_rootbp, tx);

	ASSERT3P(os->os_synctx, ==, tx);
	taskq_wait(dbuf_tq);
	os->os_synctx = NULL;
}

void
dmu_objset_stats(objset_t *os, dmu_objset_stats_t *dds)
{
	if (os->os->os_dsl_dataset != NULL) {
		dsl_dataset_stats(os->os->os_dsl_dataset, dds);
	} else {
		ASSERT(os->os->os_phys->os_type == DMU_OST_META);
		bzero(dds, sizeof (*dds));
	}
	dds->dds_type = os->os->os_phys->os_type;
}

int
dmu_objset_is_snapshot(objset_t *os)
{
	if (os->os->os_dsl_dataset != NULL)
		return (dsl_dataset_is_snapshot(os->os->os_dsl_dataset));
	else
		return (B_FALSE);
}

int
dmu_snapshot_list_next(objset_t *os, int namelen, char *name,
    uint64_t *idp, uint64_t *offp)
{
	dsl_dataset_t *ds = os->os->os_dsl_dataset;
	zap_cursor_t cursor;
	zap_attribute_t attr;

	if (ds->ds_phys->ds_snapnames_zapobj == 0)
		return (ENOENT);

	zap_cursor_init_serialized(&cursor,
	    ds->ds_dir->dd_pool->dp_meta_objset,
	    ds->ds_phys->ds_snapnames_zapobj, *offp);

	if (zap_cursor_retrieve(&cursor, &attr) != 0) {
		zap_cursor_fini(&cursor);
		return (ENOENT);
	}

	if (strlen(attr.za_name) + 1 > namelen) {
		zap_cursor_fini(&cursor);
		return (ENAMETOOLONG);
	}

	(void) strcpy(name, attr.za_name);
	if (idp)
		*idp = attr.za_first_integer;
	zap_cursor_advance(&cursor);
	*offp = zap_cursor_serialize(&cursor);
	zap_cursor_fini(&cursor);

	return (0);
}

int
dmu_dir_list_next(objset_t *os, int namelen, char *name,
    uint64_t *idp, uint64_t *offp)
{
	dsl_dir_t *dd = os->os->os_dsl_dataset->ds_dir;
	zap_cursor_t cursor;
	zap_attribute_t attr;

	if (dd->dd_phys->dd_child_dir_zapobj == 0)
		return (ENOENT);

	/* there is no next dir on a snapshot! */
	if (os->os->os_dsl_dataset->ds_object !=
	    dd->dd_phys->dd_head_dataset_obj)
		return (ENOENT);

	zap_cursor_init_serialized(&cursor,
	    dd->dd_pool->dp_meta_objset,
	    dd->dd_phys->dd_child_dir_zapobj, *offp);

	if (zap_cursor_retrieve(&cursor, &attr) != 0) {
		zap_cursor_fini(&cursor);
		return (ENOENT);
	}

	if (strlen(attr.za_name) + 1 > namelen) {
		zap_cursor_fini(&cursor);
		return (ENAMETOOLONG);
	}

	(void) strcpy(name, attr.za_name);
	if (idp)
		*idp = attr.za_first_integer;
	zap_cursor_advance(&cursor);
	*offp = zap_cursor_serialize(&cursor);
	zap_cursor_fini(&cursor);

	return (0);
}

/*
 * Find all objsets under name, and for each, call 'func(child_name, arg)'.
 */
void
dmu_objset_find(char *name, void func(char *, void *), void *arg, int flags)
{
	dsl_dir_t *dd;
	objset_t *os;
	uint64_t snapobj;
	zap_cursor_t zc;
	zap_attribute_t attr;
	char *child;
	int do_self, err;

	err = dsl_dir_open(name, FTAG, &dd, NULL);
	if (err)
		return;

	do_self = (dd->dd_phys->dd_head_dataset_obj != 0);

	/*
	 * Iterate over all children.
	 */
	if (dd->dd_phys->dd_child_dir_zapobj != 0) {
		for (zap_cursor_init(&zc, dd->dd_pool->dp_meta_objset,
		    dd->dd_phys->dd_child_dir_zapobj);
		    zap_cursor_retrieve(&zc, &attr) == 0;
		    (void) zap_cursor_advance(&zc)) {
			ASSERT(attr.za_integer_length == sizeof (uint64_t));
			ASSERT(attr.za_num_integers == 1);

			/*
			 * No separating '/' because parent's name ends in /.
			 */
			child = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			/* XXX could probably just use name here */
			dsl_dir_name(dd, child);
			(void) strcat(child, "/");
			(void) strcat(child, attr.za_name);
			dmu_objset_find(child, func, arg, flags);
			kmem_free(child, MAXPATHLEN);
		}
		zap_cursor_fini(&zc);
	}

	/*
	 * Iterate over all snapshots.
	 */
	if ((flags & DS_FIND_SNAPSHOTS) &&
	    dmu_objset_open(name, DMU_OST_ANY,
	    DS_MODE_STANDARD | DS_MODE_READONLY, &os) == 0) {

		snapobj = os->os->os_dsl_dataset->ds_phys->ds_snapnames_zapobj;
		dmu_objset_close(os);

		for (zap_cursor_init(&zc, dd->dd_pool->dp_meta_objset, snapobj);
		    zap_cursor_retrieve(&zc, &attr) == 0;
		    (void) zap_cursor_advance(&zc)) {
			ASSERT(attr.za_integer_length == sizeof (uint64_t));
			ASSERT(attr.za_num_integers == 1);

			child = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			/* XXX could probably just use name here */
			dsl_dir_name(dd, child);
			(void) strcat(child, "@");
			(void) strcat(child, attr.za_name);
			func(child, arg);
			kmem_free(child, MAXPATHLEN);
		}
		zap_cursor_fini(&zc);
	}

	dsl_dir_close(dd, FTAG);

	/*
	 * Apply to self if appropriate.
	 */
	if (do_self)
		func(name, arg);
}
