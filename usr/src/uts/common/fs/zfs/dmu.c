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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>

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
};

static int
dmu_buf_read_array_impl(dmu_buf_impl_t **dbp, int numbufs, uint32_t flags)
{
	int i, err = 0;
	dnode_t *dn;
	zio_t *zio;
	int canfail;
	uint64_t rd_sz;

	if (numbufs == 0)
		return (0);

	rd_sz = numbufs * dbp[0]->db.db_size;
	ASSERT(rd_sz <= DMU_MAX_ACCESS);

	dn = dbp[0]->db_dnode;
	if (flags & DB_RF_CANFAIL) {
		canfail = 1;
	} else {
		canfail = 0;
	}
	zio = zio_root(dn->dn_objset->os_spa, NULL, NULL, canfail);

	/* don't prefetch if read the read is large */
	if (rd_sz >= zfetch_array_rd_sz) {
		flags |= DB_RF_NOPREFETCH;
	}

	/* initiate async reads */
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	for (i = 0; i < numbufs; i++) {
		if (dbp[i]->db_state == DB_UNCACHED)
			dbuf_read_impl(dbp[i], zio, flags);
	}
	rw_exit(&dn->dn_struct_rwlock);
	err = zio_wait(zio);

	if (err)
		return (err);

	/* wait for other io to complete */
	for (i = 0; i < numbufs; i++) {
		mutex_enter(&dbp[i]->db_mtx);
		while (dbp[i]->db_state == DB_READ ||
		    dbp[i]->db_state == DB_FILL)
			cv_wait(&dbp[i]->db_changed, &dbp[i]->db_mtx);
		ASSERT(dbp[i]->db_state == DB_CACHED);
		mutex_exit(&dbp[i]->db_mtx);
	}

	return (0);
}

void
dmu_buf_read_array(dmu_buf_t **dbp_fake, int numbufs)
{
	dmu_buf_impl_t **dbp = (dmu_buf_impl_t **)dbp_fake;
	int err;

	err = dmu_buf_read_array_impl(dbp, numbufs, DB_RF_MUST_SUCCEED);
	ASSERT(err == 0);
}

int
dmu_buf_read_array_canfail(dmu_buf_t **dbp_fake, int numbufs)
{
	dmu_buf_impl_t **dbp = (dmu_buf_impl_t **)dbp_fake;

	return (dmu_buf_read_array_impl(dbp, numbufs, DB_RF_CANFAIL));
}

dmu_buf_t *
dmu_buf_hold(objset_t *os, uint64_t object, uint64_t offset)
{
	dnode_t *dn;
	uint64_t blkid;
	dmu_buf_impl_t *db;

	/* dataset_verify(dd); */

	dn = dnode_hold(os->os, object, FTAG);
	blkid = dbuf_whichblock(dn, offset);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	db = dbuf_hold(dn, blkid);
	rw_exit(&dn->dn_struct_rwlock);
	dnode_rele(dn, FTAG);
	return (&db->db);
}

dmu_buf_t *
dmu_bonus_hold(objset_t *os, uint64_t object)
{
	return (dmu_bonus_hold_tag(os, object, NULL));
}

int
dmu_bonus_max(void)
{
	return (DN_MAX_BONUSLEN);
}

/*
 * Returns held bonus buffer if the object exists, NULL if it doesn't.
 */
dmu_buf_t *
dmu_bonus_hold_tag(objset_t *os, uint64_t object, void *tag)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	dmu_buf_impl_t *db;

	if (dn == NULL)
		return (NULL);

	db = dbuf_hold_bonus(dn, tag);
	/* XXX - hack: hold the first block if this is a ZAP object */
	if (dmu_ot[dn->dn_type].ot_byteswap == zap_byteswap) {
		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		dn->dn_db0 = dbuf_hold(dn, 0);
		rw_exit(&dn->dn_struct_rwlock);
	}
	dnode_rele(dn, FTAG);
	return (&db->db);
}

static dmu_buf_t **
dbuf_hold_array(dnode_t *dn,
    uint64_t offset, uint64_t length, int *numbufsp)
{
	dmu_buf_t **dbp;
	uint64_t blkid, nblks, i;

	if (length == 0) {
		if (numbufsp)
			*numbufsp = 0;
		return (NULL);
	}

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+length, 1ULL<<blkshift) -
			P2ALIGN(offset, 1ULL<<blkshift)) >> blkshift;
	} else {
		ASSERT3U(offset + length, <=, dn->dn_datablksz);
		nblks = 1;
	}
	dbp = kmem_alloc(sizeof (dmu_buf_t *) * nblks, KM_SLEEP);

	blkid = dbuf_whichblock(dn, offset);
	for (i = 0; i < nblks; i++) {
		dmu_buf_impl_t *dbuf;
		dbuf = dbuf_hold(dn, blkid+i);
		dbp[i] = &dbuf->db;
	}
	rw_exit(&dn->dn_struct_rwlock);

	if (numbufsp)
		*numbufsp = nblks;
	return (dbp);
}

dmu_buf_t **
dmu_buf_hold_array(objset_t *os, uint64_t object,
	uint64_t offset, uint64_t length, int *numbufsp)
{
	dnode_t *dn;
	dmu_buf_t **dbp;

	ASSERT(length <= DMU_MAX_ACCESS);

	if (length == 0) {
		if (numbufsp)
			*numbufsp = 0;
		return (NULL);
	}

	dn = dnode_hold(os->os, object, FTAG);
	dbp = dbuf_hold_array(dn, offset, length, numbufsp);
	dnode_rele(dn, FTAG);

	return (dbp);
}

void
dmu_buf_add_ref(dmu_buf_t *dbuf, void *tag)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbuf;
	dbuf_add_ref(db, tag);
}

void
dmu_buf_remove_ref(dmu_buf_t *dbuf, void *tag)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbuf;
	dbuf_remove_ref(db, tag);
}

void
dmu_buf_rele(dmu_buf_t *dbuf_fake)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbuf_fake;

	/* XXX - hack: hold the first block  if this is a ZAP object */
	if (db->db_blkid == DB_BONUS_BLKID &&
	    dmu_ot[db->db_dnode->dn_type].ot_byteswap == zap_byteswap)
		dbuf_rele(db->db_dnode->dn_db0);
	dbuf_rele(db);
}

void
dmu_buf_rele_tag(dmu_buf_t *dbuf_fake, void *tag)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbuf_fake;

	/* XXX - hack: hold the first block  if this is a ZAP object */
	if (db->db_blkid == DB_BONUS_BLKID &&
	    dmu_ot[db->db_dnode->dn_type].ot_byteswap == zap_byteswap)
		dbuf_rele(db->db_dnode->dn_db0);
	dbuf_remove_ref(db, tag);
}

void
dmu_buf_rele_array(dmu_buf_t **dbp_fake, int numbufs)
{
	int i;
	dmu_buf_impl_t **dbp = (dmu_buf_impl_t **)dbp_fake;

	if (numbufs == 0)
		return;

	ASSERT((numbufs * dbp[0]->db.db_size) <= DMU_MAX_ACCESS);

	for (i = 0; i < numbufs; i++)
		dbuf_rele(dbp[i]);

	kmem_free(dbp, sizeof (dmu_buf_t *) * numbufs);
}

void
dmu_prefetch(objset_t *os, uint64_t object, uint64_t offset, uint64_t len)
{
	dnode_t *dn;
	uint64_t blkid;
	int nblks, i;

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
	dn = dnode_hold(os->os, object, FTAG);
	if (dn == NULL)
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

void
dmu_free_range(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t size, dmu_tx_t *tx)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	ASSERT(offset < UINT64_MAX);
	ASSERT(size == -1ULL || size <= UINT64_MAX - offset);
	dnode_free_range(dn, offset, size, tx);
	dnode_rele(dn, FTAG);
}

static int
dmu_read_impl(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *buf, uint32_t flags)
{
	dnode_t *dn;
	dmu_buf_t **dbp;
	int numbufs, i;

	dn = dnode_hold(os->os, object, FTAG);

	if (dn->dn_datablkshift == 0) {
		int newsz = offset > dn->dn_datablksz ? 0 :
		    MIN(size, dn->dn_datablksz - offset);
		bzero((char *)buf + newsz, size - newsz);
		size = newsz;
	}

	dnode_rele(dn, FTAG);

	if (size == 0)
		return (0);

	while (size > 0) {
		uint64_t mylen = MIN(size, DMU_MAX_ACCESS / 2);
		int err;

		/*
		 * NB: we could do this block-at-a-time, but it's nice
		 * to be reading in parallel.
		 */
		dbp = dmu_buf_hold_array(os, object, offset, mylen, &numbufs);
		err = dmu_buf_read_array_impl((dmu_buf_impl_t **)dbp, numbufs,
		    flags);
		if (err) {
			dmu_buf_rele_array(dbp, numbufs);
			return (err);
		}

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
		dmu_buf_rele_array(dbp, numbufs);
	}
	return (0);
}

void
dmu_read(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *buf)
{
	int err;

	err = dmu_read_impl(os, object, offset, size, buf, DB_RF_MUST_SUCCEED);
	ASSERT3U(err, ==, 0);
}

int
dmu_read_canfail(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *buf)
{
	return (dmu_read_impl(os, object, offset, size, buf, DB_RF_CANFAIL));
}

void
dmu_write(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    const void *buf, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;

	dbp = dmu_buf_hold_array(os, object, offset, size, &numbufs);

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
	dmu_buf_rele_array(dbp, numbufs);
}

#ifdef _KERNEL
int
dmu_write_uio(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    uio_t *uio, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err = 0;

	dbp = dmu_buf_hold_array(os, object, offset, size, &numbufs);

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
	dmu_buf_rele_array(dbp, numbufs);
	return (err);
}
#endif

struct backuparg {
	dmu_replay_record_t *drr;
	vnode_t *vp;
	objset_t *os;
	int err;
};

static int
dump_bytes(struct backuparg *ba, void *buf, int len)
{
	ssize_t resid; /* have to get resid to get detailed errno */
	/* Need to compute checksum here */
	ASSERT3U(len % 8, ==, 0);
	ba->err = vn_rdwr(UIO_WRITE, ba->vp,
	    (caddr_t)buf, len,
	    0, UIO_SYSSPACE, FAPPEND, RLIM_INFINITY, CRED(), &resid);
	return (ba->err);
}

static int
dump_free(struct backuparg *ba, uint64_t object, uint64_t offset,
    uint64_t length)
{
	/* write a FREE record */
	bzero(ba->drr, sizeof (dmu_replay_record_t));
	ba->drr->drr_type = DRR_FREE;
	ba->drr->drr_u.drr_free.drr_object = object;
	ba->drr->drr_u.drr_free.drr_offset = offset;
	ba->drr->drr_u.drr_free.drr_length = length;

	if (dump_bytes(ba, ba->drr, sizeof (dmu_replay_record_t)))
		return (EINTR);
	return (0);
}

static int
dump_data(struct backuparg *ba, dmu_object_type_t type,
    uint64_t object, uint64_t offset, int blksz, void *data)
{
	/* write a DATA record */
	bzero(ba->drr, sizeof (dmu_replay_record_t));
	ba->drr->drr_type = DRR_WRITE;
	ba->drr->drr_u.drr_write.drr_object = object;
	ba->drr->drr_u.drr_write.drr_type = type;
	ba->drr->drr_u.drr_write.drr_offset = offset;
	ba->drr->drr_u.drr_write.drr_length = blksz;

	if (dump_bytes(ba, ba->drr, sizeof (dmu_replay_record_t)))
		return (EINTR);
	if (dump_bytes(ba, data, blksz))
		return (EINTR);
	return (0);
}

static int
dump_freeobjects(struct backuparg *ba, uint64_t firstobj, uint64_t numobjs)
{
	/* write a FREEOBJECTS record */
	bzero(ba->drr, sizeof (dmu_replay_record_t));
	ba->drr->drr_type = DRR_FREEOBJECTS;
	ba->drr->drr_u.drr_freeobjects.drr_firstobj = firstobj;
	ba->drr->drr_u.drr_freeobjects.drr_numobjs = numobjs;

	if (dump_bytes(ba, ba->drr, sizeof (dmu_replay_record_t)))
		return (EINTR);
	return (0);
}

static int
dump_dnode(struct backuparg *ba, uint64_t object, dnode_phys_t *dnp)
{
	if (dnp == NULL || dnp->dn_type == DMU_OT_NONE)
		return (dump_freeobjects(ba, object, 1));

	/* write an OBJECT record */
	bzero(ba->drr, sizeof (dmu_replay_record_t));
	ba->drr->drr_type = DRR_OBJECT;
	ba->drr->drr_u.drr_object.drr_object = object;
	ba->drr->drr_u.drr_object.drr_type = dnp->dn_type;
	ba->drr->drr_u.drr_object.drr_bonustype = dnp->dn_bonustype;
	ba->drr->drr_u.drr_object.drr_blksz =
	    dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	ba->drr->drr_u.drr_object.drr_bonuslen = dnp->dn_bonuslen;
	ba->drr->drr_u.drr_object.drr_checksum = dnp->dn_checksum;
	ba->drr->drr_u.drr_object.drr_compress = dnp->dn_compress;

	if (dump_bytes(ba, ba->drr, sizeof (dmu_replay_record_t)))
		return (EINTR);

	if (dump_bytes(ba, DN_BONUS(dnp), P2ROUNDUP(dnp->dn_bonuslen, 8)))
		return (EINTR);

	/* free anything past the end of the file */
	if (dump_free(ba, object, (dnp->dn_maxblkid + 1) *
	    (dnp->dn_datablkszsec << SPA_MINBLOCKSHIFT), -1ULL))
		return (EINTR);
	if (ba->err)
		return (EINTR);
	return (0);
}

#define	BP_SPAN(dnp, level) \
	(((uint64_t)dnp->dn_datablkszsec) << (SPA_MINBLOCKSHIFT + \
	(level) * (dnp->dn_indblkshift - SPA_BLKPTRSHIFT)))

static int
backup_cb(traverse_blk_cache_t *bc, spa_t *spa, void *arg)
{
	struct backuparg *ba = arg;
	uint64_t object = bc->bc_bookmark.zb_object;
	int level = bc->bc_bookmark.zb_level;
	uint64_t blkid = bc->bc_bookmark.zb_blkid;
	blkptr_t *bp = bc->bc_blkptr.blk_birth ? &bc->bc_blkptr : NULL;
	dmu_object_type_t type = bp ? BP_GET_TYPE(bp) : DMU_OT_NONE;
	void *data = bc->bc_data;
	int err = 0;

	if (issig(JUSTLOOKING))
		return (EINTR);

	ASSERT(data || bp == NULL);

	if (bp == NULL && object == 0) {
		uint64_t span = BP_SPAN(bc->bc_dnode, level);
		uint64_t dnobj = (blkid * span) >> DNODE_SHIFT;
		err = dump_freeobjects(ba, dnobj, span >> DNODE_SHIFT);
	} else if (bp == NULL) {
		uint64_t span = BP_SPAN(bc->bc_dnode, level);
		err = dump_free(ba, object, blkid * span, span);
	} else if (data && level == 0 && type == DMU_OT_DNODE) {
		dnode_phys_t *blk = data;
		int i;
		int blksz = BP_GET_LSIZE(bp);

		for (i = 0; i < blksz >> DNODE_SHIFT; i++) {
			uint64_t dnobj =
			    (blkid << (DNODE_BLOCK_SHIFT - DNODE_SHIFT)) + i;
			err = dump_dnode(ba, dnobj, blk+i);
			if (err)
				break;
		}
	} else if (level == 0 &&
	    type != DMU_OT_DNODE && type != DMU_OT_OBJSET) {
		int blksz = BP_GET_LSIZE(bp);
		if (data == NULL) {
			arc_buf_t *abuf;

			(void) arc_read(NULL, spa, bp,
			    dmu_ot[type].ot_byteswap, arc_getbuf_func, &abuf,
			    ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_MUSTSUCCEED,
			    ARC_WAIT);

			if (abuf) {
				err = dump_data(ba, type, object, blkid * blksz,
				    blksz, abuf->b_data);
				arc_buf_free(abuf, &abuf);
			}
		} else {
			err = dump_data(ba, type, object, blkid * blksz,
			    blksz, data);
		}
	}

	ASSERT(err == 0 || err == EINTR);
	return (err);
}

int
dmu_sendbackup(objset_t *tosnap, objset_t *fromsnap, vnode_t *vp)
{
	dsl_dataset_t *ds = tosnap->os->os_dsl_dataset;
	dsl_dataset_t *fromds = fromsnap ? fromsnap->os->os_dsl_dataset : NULL;
	dmu_replay_record_t *drr;
	struct backuparg ba;
	int err;

	/* tosnap must be a snapshot */
	if (ds->ds_phys->ds_next_snap_obj == 0)
		return (EINVAL);

	/* fromsnap must be an earlier snapshot from the same fs as tosnap */
	if (fromds && (ds->ds_dir != fromds->ds_dir ||
	    fromds->ds_phys->ds_creation_txg >=
	    ds->ds_phys->ds_creation_txg))
		return (EXDEV);

	drr = kmem_zalloc(sizeof (dmu_replay_record_t), KM_SLEEP);
	drr->drr_type = DRR_BEGIN;
	drr->drr_u.drr_begin.drr_magic = DMU_BACKUP_MAGIC;
	drr->drr_u.drr_begin.drr_version = DMU_BACKUP_VERSION;
	drr->drr_u.drr_begin.drr_creation_time =
	    ds->ds_phys->ds_creation_time;
	drr->drr_u.drr_begin.drr_type = tosnap->os->os_phys->os_type;
	drr->drr_u.drr_begin.drr_toguid = ds->ds_phys->ds_guid;
	if (fromds)
		drr->drr_u.drr_begin.drr_fromguid = fromds->ds_phys->ds_guid;
	dsl_dataset_name(ds, drr->drr_u.drr_begin.drr_toname);

	ba.drr = drr;
	ba.vp = vp;
	ba.os = tosnap;

	if (dump_bytes(&ba, drr, sizeof (dmu_replay_record_t))) {
		kmem_free(drr, sizeof (dmu_replay_record_t));
		return (ba.err);
	}

	err = traverse_dsl_dataset(ds,
	    fromds ? fromds->ds_phys->ds_creation_txg : 0,
	    ADVANCE_PRE | ADVANCE_HOLES | ADVANCE_DATA | ADVANCE_NOLOCK,
	    backup_cb, &ba);

	if (err) {
		if (err == EINTR && ba.err)
			err = ba.err;
		return (err);
	}

	bzero(drr, sizeof (dmu_replay_record_t));
	drr->drr_type = DRR_END;

	if (dump_bytes(&ba, drr, sizeof (dmu_replay_record_t)))
		return (ba.err);

	kmem_free(drr, sizeof (dmu_replay_record_t));

	return (0);
}

struct restorearg {
	int err;
	int byteswap;
	vnode_t *vp;
	char *buf;
	uint64_t voff;
	int buflen; /* number of valid bytes in buf */
	int bufoff; /* next offset to read */
	int bufsize; /* amount of memory allocated for buf */
};

static int
replay_incremental_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct drr_begin *drrb = arg;
	dsl_dataset_t *ds = NULL;
	dsl_dataset_t *ds_prev = NULL;
	const char *snapname;
	int err = EINVAL;
	uint64_t val;

	/* this must be a filesytem */
	if (dd->dd_phys->dd_head_dataset_obj == 0)
		goto die;

	ds = dsl_dataset_open_obj(dd->dd_pool, dd->dd_phys->dd_head_dataset_obj,
	    NULL, DS_MODE_EXCLUSIVE, FTAG);

	if (ds == NULL) {
		err = EBUSY;
		goto die;
	}

	/* must already be a snapshot of this fs */
	if (ds->ds_phys->ds_prev_snap_obj == 0) {
		err = ENODEV;
		goto die;
	}

	/* most recent snapshot must match fromguid */
	ds_prev = dsl_dataset_open_obj(dd->dd_pool,
	    ds->ds_phys->ds_prev_snap_obj, NULL,
	    DS_MODE_STANDARD | DS_MODE_READONLY, FTAG);
	if (ds_prev->ds_phys->ds_guid != drrb->drr_fromguid) {
		err = ENODEV;
		goto die;
	}

	/* must not have any changes since most recent snapshot */
	if (ds->ds_phys->ds_bp.blk_birth >
	    ds_prev->ds_phys->ds_creation_txg) {
		err = ETXTBSY;
		goto die;
	}

	/* new snapshot name must not exist */
	snapname = strrchr(drrb->drr_toname, '@');
	if (snapname == NULL) {
		err = EEXIST;
		goto die;
	}
	snapname++;
	err = zap_lookup(dd->dd_pool->dp_meta_objset,
	    ds->ds_phys->ds_snapnames_zapobj, snapname, 8, 1, &val);
	if (err != ENOENT) {
		if (err == 0)
			err = EEXIST;
		dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
		dsl_dataset_close(ds_prev, DS_MODE_STANDARD, FTAG);
		return (err);
	}

	dsl_dataset_close(ds_prev, DS_MODE_STANDARD, FTAG);

	/* The point of no (unsuccessful) return. */

	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	ds->ds_phys->ds_restoring = TRUE;

	dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
	return (0);

die:
	if (ds_prev)
		dsl_dataset_close(ds_prev, DS_MODE_STANDARD, FTAG);
	if (ds)
		dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
	return (err);
}

static int
replay_full_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct drr_begin *drrb = arg;
	int err;
	char *fsfullname, *fslastname, *cp;
	dsl_dataset_t *ds;

	fsfullname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) strncpy(fsfullname, drrb->drr_toname, MAXNAMELEN);
	cp = strchr(fsfullname, '@');
	if (cp == NULL) {
		kmem_free(fsfullname, MAXNAMELEN);
		return (EINVAL);
	}
	*cp = '\0';
	fslastname = strrchr(fsfullname, '/');
	if (fslastname == NULL) {
		kmem_free(fsfullname, MAXNAMELEN);
		return (EINVAL);
	}
	fslastname++;

	err = dsl_dataset_create_sync(dd, fsfullname, fslastname, NULL, tx);
	if (err) {
		kmem_free(fsfullname, MAXNAMELEN);
		return (err);
	}

	/* the point of no (unsuccessful) return */

	err = dsl_dataset_open_spa(dd->dd_pool->dp_spa, fsfullname,
	    DS_MODE_EXCLUSIVE, FTAG, &ds);
	ASSERT3U(err, ==, 0);
	kmem_free(fsfullname, MAXNAMELEN);

	(void) dmu_objset_create_impl(dsl_dataset_get_spa(ds),
	    ds, drrb->drr_type, tx);

	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	ds->ds_phys->ds_restoring = TRUE;

	dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
	return (0);
}

static int
replay_end_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct drr_begin *drrb = arg;
	int err;
	char *snapname;
	dsl_dataset_t *ds;

	/* XXX verify that drr_toname is in dd */

	snapname = strchr(drrb->drr_toname, '@');
	if (snapname == NULL)
		return (EINVAL);
	snapname++;

	/* create snapshot */
	err = dsl_dataset_snapshot_sync(dd, snapname, tx);
	if (err)
		return (err);

	/* set snapshot's creation time and guid */
	err = dsl_dataset_open_spa(dd->dd_pool->dp_spa, drrb->drr_toname,
	    DS_MODE_PRIMARY | DS_MODE_READONLY | DS_MODE_RESTORE, FTAG, &ds);
	ASSERT3U(err, ==, 0);

	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	ds->ds_phys->ds_creation_time = drrb->drr_creation_time;
	ds->ds_phys->ds_guid = drrb->drr_toguid;
	ds->ds_phys->ds_restoring = FALSE;

	dsl_dataset_close(ds, DS_MODE_PRIMARY, FTAG);

	ds = dsl_dataset_open_obj(dd->dd_pool, dd->dd_phys->dd_head_dataset_obj,
	    NULL, DS_MODE_STANDARD | DS_MODE_RESTORE, FTAG);
	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	ds->ds_phys->ds_restoring = FALSE;
	dsl_dataset_close(ds, DS_MODE_STANDARD, FTAG);

	return (0);
}

void *
restore_read(struct restorearg *ra, int len)
{
	void *rv;

	/* some things will require 8-byte alignment, so everything must */
	ASSERT3U(len % 8, ==, 0);

	while (ra->buflen - ra->bufoff < len) {
		ssize_t resid;
		int leftover = ra->buflen - ra->bufoff;

		(void) memmove(ra->buf, ra->buf + ra->bufoff, leftover);
		ra->err = vn_rdwr(UIO_READ, ra->vp,
		    (caddr_t)ra->buf + leftover, ra->bufsize - leftover,
		    ra->voff, UIO_SYSSPACE, FAPPEND,
		    RLIM_INFINITY, CRED(), &resid);

		/* Need to compute checksum */

		ra->voff += ra->bufsize - leftover - resid;
		ra->buflen = ra->bufsize - resid;
		ra->bufoff = 0;
		if (resid == ra->bufsize - leftover)
			ra->err = EINVAL;
		if (ra->err)
			return (NULL);
	}

	ASSERT3U(ra->bufoff % 8, ==, 0);
	ASSERT3U(ra->buflen - ra->bufoff, >=, len);
	rv = ra->buf + ra->bufoff;
	ra->bufoff += len;
	return (rv);
}

static void
backup_byteswap(dmu_replay_record_t *drr)
{
#define	DO64(X) (drr->drr_u.X = BSWAP_64(drr->drr_u.X))
#define	DO32(X) (drr->drr_u.X = BSWAP_32(drr->drr_u.X))
	drr->drr_type = BSWAP_32(drr->drr_type);
	switch (drr->drr_type) {
	case DRR_BEGIN:
		DO64(drr_begin.drr_magic);
		DO64(drr_begin.drr_version);
		DO64(drr_begin.drr_creation_time);
		DO32(drr_begin.drr_type);
		DO64(drr_begin.drr_toguid);
		DO64(drr_begin.drr_fromguid);
		break;
	case DRR_OBJECT:
		DO64(drr_object.drr_object);
		/* DO64(drr_object.drr_allocation_txg); */
		DO32(drr_object.drr_type);
		DO32(drr_object.drr_bonustype);
		DO32(drr_object.drr_blksz);
		DO32(drr_object.drr_bonuslen);
		break;
	case DRR_FREEOBJECTS:
		DO64(drr_freeobjects.drr_firstobj);
		DO64(drr_freeobjects.drr_numobjs);
		break;
	case DRR_WRITE:
		DO64(drr_write.drr_object);
		DO32(drr_write.drr_type);
		DO64(drr_write.drr_offset);
		DO64(drr_write.drr_length);
		break;
	case DRR_FREE:
		DO64(drr_free.drr_object);
		DO64(drr_free.drr_offset);
		DO64(drr_free.drr_length);
		break;
	case DRR_END:
		DO64(drr_end.drr_checksum);
		break;
	}
#undef DO64
#undef DO32
}

static int
restore_object(struct restorearg *ra, objset_t *os, struct drr_object *drro)
{
	int err;
	dmu_tx_t *tx;

	err = dmu_object_info(os, drro->drr_object, NULL);

	if (err != 0 && err != ENOENT)
		return (EINVAL);

	if (drro->drr_type == DMU_OT_NONE ||
	    drro->drr_type >= DMU_OT_NUMTYPES ||
	    drro->drr_bonustype >= DMU_OT_NUMTYPES ||
	    drro->drr_checksum >= ZIO_CHECKSUM_FUNCTIONS ||
	    drro->drr_compress >= ZIO_COMPRESS_FUNCTIONS ||
	    P2PHASE(drro->drr_blksz, SPA_MINBLOCKSIZE) ||
	    drro->drr_blksz < SPA_MINBLOCKSIZE ||
	    drro->drr_blksz > SPA_MAXBLOCKSIZE ||
	    drro->drr_bonuslen > DN_MAX_BONUSLEN) {
		return (EINVAL);
	}

	tx = dmu_tx_create(os);

	if (err == ENOENT) {
		/* currently free, want to be allocated */
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, 1);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err) {
			dmu_tx_abort(tx);
			return (err);
		}
		err = dmu_object_claim(os, drro->drr_object,
		    drro->drr_type, drro->drr_blksz,
		    drro->drr_bonustype, drro->drr_bonuslen, tx);
	} else {
		/* currently allocated, want to be allocated */
		dmu_tx_hold_bonus(tx, drro->drr_object);
		/*
		 * We may change blocksize, so need to
		 * hold_write
		 */
		dmu_tx_hold_write(tx, drro->drr_object, 0, 1);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err) {
			dmu_tx_abort(tx);
			return (err);
		}

		err = dmu_object_reclaim(os, drro->drr_object,
		    drro->drr_type, drro->drr_blksz,
		    drro->drr_bonustype, drro->drr_bonuslen, tx);
	}
	if (err) {
		dmu_tx_commit(tx);
		return (EINVAL);
	}

	dmu_object_set_checksum(os, drro->drr_object, drro->drr_checksum, tx);
	dmu_object_set_compress(os, drro->drr_object, drro->drr_compress, tx);

	if (drro->drr_bonuslen) {
		dmu_buf_t *db;
		void *data;
		db = dmu_bonus_hold(os, drro->drr_object);
		dmu_buf_will_dirty(db, tx);

		ASSERT3U(db->db_size, ==, drro->drr_bonuslen);
		data = restore_read(ra, P2ROUNDUP(db->db_size, 8));
		if (data == NULL) {
			dmu_tx_commit(tx);
			return (ra->err);
		}
		bcopy(data, db->db_data, db->db_size);
		if (ra->byteswap) {
			dmu_ot[drro->drr_bonustype].ot_byteswap(db->db_data,
			    drro->drr_bonuslen);
		}
		dmu_buf_rele(db);
	}
	dmu_tx_commit(tx);
	return (0);
}

/* ARGSUSED */
static int
restore_freeobjects(struct restorearg *ra, objset_t *os,
    struct drr_freeobjects *drrfo)
{
	uint64_t obj;

	if (drrfo->drr_firstobj + drrfo->drr_numobjs < drrfo->drr_firstobj)
		return (EINVAL);

	for (obj = drrfo->drr_firstobj;
	    obj < drrfo->drr_firstobj + drrfo->drr_numobjs; obj++) {
		dmu_tx_t *tx;
		int err;

		if (dmu_object_info(os, obj, NULL) != 0)
			continue;

		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, obj);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err) {
			dmu_tx_abort(tx);
			return (err);
		}
		err = dmu_object_free(os, obj, tx);
		dmu_tx_commit(tx);
		if (err && err != ENOENT)
			return (EINVAL);
	}
	return (0);
}

static int
restore_write(struct restorearg *ra, objset_t *os,
    struct drr_write *drrw)
{
	dmu_tx_t *tx;
	void *data;
	int err;

	if (drrw->drr_offset + drrw->drr_length < drrw->drr_offset ||
	    drrw->drr_type >= DMU_OT_NUMTYPES)
		return (EINVAL);

	data = restore_read(ra, drrw->drr_length);
	if (data == NULL)
		return (ra->err);

	if (dmu_object_info(os, drrw->drr_object, NULL) != 0)
		return (EINVAL);

	tx = dmu_tx_create(os);

	dmu_tx_hold_write(tx, drrw->drr_object,
	    drrw->drr_offset, drrw->drr_length);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (err);
	}
	if (ra->byteswap)
		dmu_ot[drrw->drr_type].ot_byteswap(data, drrw->drr_length);
	dmu_write(os, drrw->drr_object,
	    drrw->drr_offset, drrw->drr_length, data, tx);
	dmu_tx_commit(tx);
	return (0);
}

/* ARGSUSED */
static int
restore_free(struct restorearg *ra, objset_t *os,
    struct drr_free *drrf)
{
	dmu_tx_t *tx;
	int err;

	if (drrf->drr_length != -1ULL &&
	    drrf->drr_offset + drrf->drr_length < drrf->drr_offset)
		return (EINVAL);

	if (dmu_object_info(os, drrf->drr_object, NULL) != 0)
		return (EINVAL);

	tx = dmu_tx_create(os);

	dmu_tx_hold_free(tx, drrf->drr_object,
	    drrf->drr_offset, drrf->drr_length);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (err);
	}
	dmu_free_range(os, drrf->drr_object,
	    drrf->drr_offset, drrf->drr_length, tx);
	dmu_tx_commit(tx);
	return (0);
}

int
dmu_recvbackup(struct drr_begin *drrb, uint64_t *sizep,
    vnode_t *vp, uint64_t voffset)
{
	struct restorearg ra;
	dmu_replay_record_t *drr;
	char *cp, *tosnap;
	dsl_dir_t *dd = NULL;
	objset_t *os = NULL;

	bzero(&ra, sizeof (ra));
	ra.vp = vp;
	ra.voff = voffset;
	ra.bufsize = 1<<20;
	ra.buf = kmem_alloc(ra.bufsize, KM_SLEEP);

	if (drrb->drr_magic == DMU_BACKUP_MAGIC) {
		ra.byteswap = FALSE;
	} else if (drrb->drr_magic == BSWAP_64(DMU_BACKUP_MAGIC)) {
		ra.byteswap = TRUE;
	} else {
		ra.err = EINVAL;
		goto out;
	}

	if (ra.byteswap) {
		drrb->drr_magic = BSWAP_64(drrb->drr_magic);
		drrb->drr_version = BSWAP_64(drrb->drr_version);
		drrb->drr_creation_time = BSWAP_64(drrb->drr_creation_time);
		drrb->drr_type = BSWAP_32(drrb->drr_type);
		drrb->drr_toguid = BSWAP_64(drrb->drr_toguid);
		drrb->drr_fromguid = BSWAP_64(drrb->drr_fromguid);
	}

	ASSERT3U(drrb->drr_magic, ==, DMU_BACKUP_MAGIC);

	tosnap = drrb->drr_toname;
	if (drrb->drr_version != DMU_BACKUP_VERSION ||
	    drrb->drr_type >= DMU_OST_NUMTYPES ||
	    strchr(drrb->drr_toname, '@') == NULL) {
		ra.err = EINVAL;
		goto out;
	}

	/*
	 * Process the begin in syncing context.
	 */
	if (drrb->drr_fromguid) {
		/* incremental backup */

		cp = strchr(tosnap, '@');
		*cp = '\0';
		dd = dsl_dir_open(tosnap, FTAG, NULL);
		*cp = '@';
		if (dd == NULL) {
			ra.err = ENOENT;
			goto out;
		}

		ra.err = dsl_dir_sync_task(dd, replay_incremental_sync,
		    drrb, 1<<20);
	} else {
		/* full backup */
		const char *tail;

		cp = strchr(tosnap, '@');
		*cp = '\0';
		dd = dsl_dir_open(tosnap, FTAG, &tail);
		*cp = '@';
		if (dd == NULL) {
			ra.err = ENOENT;
			goto out;
		}
		if (tail == NULL) {
			ra.err = EEXIST;
			goto out;
		}

		ra.err = dsl_dir_sync_task(dd, replay_full_sync,
		    drrb, 1<<20);
	}
	if (ra.err)
		goto out;

	/*
	 * Open the objset we are modifying.
	 */

	cp = strchr(tosnap, '@');
	*cp = '\0';
	ra.err = dmu_objset_open(tosnap, DMU_OST_ANY,
	    DS_MODE_PRIMARY | DS_MODE_RESTORE, &os);
	*cp = '@';
	ASSERT3U(ra.err, ==, 0);

	/*
	 * Read records and process them.
	 */
	while (ra.err == 0 &&
	    NULL != (drr = restore_read(&ra, sizeof (*drr)))) {
		if (issig(JUSTLOOKING)) {
			ra.err = EINTR;
			goto out;
		}

		if (ra.byteswap)
			backup_byteswap(drr);

		switch (drr->drr_type) {
		case DRR_OBJECT:
		{
			/*
			 * We need to make a copy of the record header,
			 * because restore_{object,write} may need to
			 * restore_read(), which will invalidate drr.
			 */
			struct drr_object drro = drr->drr_u.drr_object;
			ra.err = restore_object(&ra, os, &drro);
			break;
		}
		case DRR_FREEOBJECTS:
		{
			struct drr_freeobjects drrfo =
			    drr->drr_u.drr_freeobjects;
			ra.err = restore_freeobjects(&ra, os, &drrfo);
			break;
		}
		case DRR_WRITE:
		{
			struct drr_write drrw = drr->drr_u.drr_write;
			ra.err = restore_write(&ra, os, &drrw);
			break;
		}
		case DRR_FREE:
		{
			struct drr_free drrf = drr->drr_u.drr_free;
			ra.err = restore_free(&ra, os, &drrf);
			break;
		}
		case DRR_END:
			/* Need to verify checksum. */
			/*
			 * dd may be the parent of the dd we are
			 * restoring into (eg. if it's a full backup).
			 */
			ra.err = dsl_dir_sync_task(dmu_objset_ds(os)->
			    ds_dir, replay_end_sync, drrb, 1<<20);
			goto out;
		default:
			ra.err = EINVAL;
			goto out;
		}
	}

out:
	if (os)
		dmu_objset_close(os);

	/*
	 * Make sure we don't rollback/destroy unless we actually
	 * processed the begin properly.  'os' will only be set if this
	 * is the case.
	 */
	if (ra.err && os && dd && tosnap && strchr(tosnap, '@')) {
		/*
		 * rollback or destroy what we created, so we don't
		 * leave it in the restoring state.
		 */
		txg_wait_synced(dd->dd_pool, 0);
		if (drrb->drr_fromguid) {
			/* incremental: rollback to most recent snapshot */
			(void) dsl_dir_sync_task(dd,
			    dsl_dataset_rollback_sync, NULL, 0);
		} else {
			/* full: destroy whole fs */
			cp = strchr(tosnap, '@');
			*cp = '\0';
			cp = strchr(tosnap, '/');
			if (cp) {
				(void) dsl_dir_sync_task(dd,
				    dsl_dir_destroy_sync, cp+1, 0);
			}
			cp = strchr(tosnap, '\0');
			*cp = '@';
		}

	}

	if (dd)
		dsl_dir_close(dd, FTAG);
	kmem_free(ra.buf, ra.bufsize);
	if (sizep)
		*sizep = ra.voff;
	return (ra.err);
}

/*
 * Intent log support: sync the block at <os, object, offset> to disk.
 * N.B. and XXX: the caller is responsible for serializing dmu_sync()s
 * of the same block, and for making sure that the data isn't changing
 * while dmu_sync() is writing it.
 *
 * Return values:
 *
 *	EALREADY: this txg has already been synced, so there's nothing to to.
 *		The caller should not log the write.
 *
 *	ENOENT: the block was dbuf_free_range()'d, so there's nothing to do.
 *		The caller should not log the write.
 *
 *	EINPROGRESS: the block is in the process of being synced by the
 *		usual mechanism (spa_sync()), so we can't sync it here.
 *		The caller should txg_wait_synced() and not log the write.
 *
 *	EBUSY: another thread is trying to dmu_sync() the same dbuf.
 *		(This case cannot arise under the current locking rules.)
 *		The caller should txg_wait_synced() and not log the write.
 *
 *	ESTALE: the block was dirtied or freed while we were writing it,
 *		so the data is no longer valid.
 *		The caller should txg_wait_synced() and not log the write.
 *
 *	0: success.  Sets *bp to the blkptr just written, and sets
 *		*blkoff to the data's offset within that block.
 *		The caller should log this blkptr/blkoff in its lr_write_t.
 */
int
dmu_sync(objset_t *os, uint64_t object, uint64_t offset, uint64_t *blkoff,
    blkptr_t *bp, uint64_t txg)
{
	dsl_pool_t *dp = os->os->os_dsl_dataset->ds_dir->dd_pool;
	tx_state_t *tx = &dp->dp_tx;
	dmu_buf_impl_t *db;
	blkptr_t *blk;
	int err;

	ASSERT(RW_LOCK_HELD(&tx->tx_suspend));
	ASSERT(BP_IS_HOLE(bp));
	ASSERT(txg != 0);

	dprintf("dmu_sync txg=%llu, s,o,q %llu %llu %llu\n",
	    txg, tx->tx_synced_txg, tx->tx_open_txg, tx->tx_quiesced_txg);

	/*
	 * If this txg already synced, there's nothing to do.
	 */
	if (txg <= tx->tx_synced_txg) {
		/*
		 * If we're running ziltest, we need the blkptr regardless.
		 */
		if (txg > spa_freeze_txg(dp->dp_spa)) {
			db = (dmu_buf_impl_t *)dmu_buf_hold(os, object, offset);
			/* if db_blkptr == NULL, this was an empty write */
			if (db->db_blkptr)
				*bp = *db->db_blkptr; /* structure assignment */
			else
				bzero(bp, sizeof (blkptr_t));
			*blkoff = offset - db->db.db_offset;
			ASSERT3U(*blkoff, <, db->db.db_size);
			dmu_buf_rele((dmu_buf_t *)db);
			return (0);
		}
		return (EALREADY);
	}

	/*
	 * If this txg is in the middle of syncing, just wait for it.
	 */
	if (txg == tx->tx_syncing_txg) {
		ASSERT(txg != tx->tx_open_txg);
		return (EINPROGRESS);
	}

	db = (dmu_buf_impl_t *)dmu_buf_hold(os, object, offset);

	mutex_enter(&db->db_mtx);

	/*
	 * If this dbuf isn't dirty, must have been free_range'd.
	 * There's no need to log writes to freed blocks, so we're done.
	 */
	if (!list_link_active(&db->db_dirty_node[txg&TXG_MASK])) {
		mutex_exit(&db->db_mtx);
		dmu_buf_rele((dmu_buf_t *)db);
		return (ENOENT);
	}

	blk = db->db_d.db_overridden_by[txg&TXG_MASK];

	/*
	 * If we already did a dmu_sync() of this dbuf in this txg,
	 * free the old block before writing the new one.
	 */
	if (blk != NULL) {
		ASSERT(blk != IN_DMU_SYNC);
		if (blk == IN_DMU_SYNC) {
			mutex_exit(&db->db_mtx);
			dmu_buf_rele((dmu_buf_t *)db);
			return (EBUSY);
		}
		arc_release(db->db_d.db_data_old[txg&TXG_MASK], db);
		if (!BP_IS_HOLE(blk)) {
			(void) arc_free(NULL, os->os->os_spa, txg, blk,
			    NULL, NULL, ARC_WAIT);
		}
		kmem_free(blk, sizeof (blkptr_t));
	}

	db->db_d.db_overridden_by[txg&TXG_MASK] = IN_DMU_SYNC;
	mutex_exit(&db->db_mtx);

	blk = kmem_alloc(sizeof (blkptr_t), KM_SLEEP);
	blk->blk_birth = 0; /* mark as invalid */

	err = arc_write(NULL, os->os->os_spa,
	    zio_checksum_select(db->db_dnode->dn_checksum, os->os->os_checksum),
	    zio_compress_select(db->db_dnode->dn_compress, os->os->os_compress),
	    txg, blk, db->db_d.db_data_old[txg&TXG_MASK], NULL, NULL,
	    ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_MUSTSUCCEED, ARC_WAIT);
	ASSERT(err == 0);

	if (!BP_IS_HOLE(blk)) {
		blk->blk_fill = 1;
		BP_SET_TYPE(blk, db->db_dnode->dn_type);
		BP_SET_LEVEL(blk, 0);
	}

	/* copy the block pointer back to caller */
	*bp = *blk; /* structure assignment */
	*blkoff = offset - db->db.db_offset;
	ASSERT3U(*blkoff, <, db->db.db_size);

	mutex_enter(&db->db_mtx);
	if (db->db_d.db_overridden_by[txg&TXG_MASK] != IN_DMU_SYNC) {
		/* we were dirtied/freed during the sync */
		ASSERT3P(db->db_d.db_overridden_by[txg&TXG_MASK], ==, NULL);
		arc_release(db->db_d.db_data_old[txg&TXG_MASK], db);
		mutex_exit(&db->db_mtx);
		dmu_buf_rele((dmu_buf_t *)db);
		/* Note that this block does not free on disk until txg syncs */

		/*
		 * XXX can we use ARC_NOWAIT here?
		 * XXX should we be ignoring the return code?
		 */
		if (!BP_IS_HOLE(blk)) {
			(void) arc_free(NULL, os->os->os_spa, txg, blk,
			    NULL, NULL, ARC_WAIT);
		}
		kmem_free(blk, sizeof (blkptr_t));
		return (ESTALE);
	}

	db->db_d.db_overridden_by[txg&TXG_MASK] = blk;
	mutex_exit(&db->db_mtx);
	dmu_buf_rele((dmu_buf_t *)db);
	ASSERT3U(txg, >, tx->tx_syncing_txg);
	return (0);
}

uint64_t
dmu_object_max_nonzero_offset(objset_t *os, uint64_t object)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	uint64_t rv = dnode_max_nonzero_offset(dn);
	dnode_rele(dn, FTAG);
	return (rv);
}

int
dmu_object_set_blocksize(objset_t *os, uint64_t object, uint64_t size, int ibs,
	dmu_tx_t *tx)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	int err = dnode_set_blksz(dn, size, ibs, tx);
	dnode_rele(dn, FTAG);
	return (err);
}

void
dmu_object_set_checksum(objset_t *os, uint64_t object, uint8_t checksum,
	dmu_tx_t *tx)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	ASSERT(checksum < ZIO_CHECKSUM_FUNCTIONS);
	dn->dn_checksum = checksum;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

void
dmu_object_set_compress(objset_t *os, uint64_t object, uint8_t compress,
	dmu_tx_t *tx)
{
	dnode_t *dn = dnode_hold(os->os, object, FTAG);
	ASSERT(compress < ZIO_COMPRESS_FUNCTIONS);
	dn->dn_compress = compress;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

int
dmu_offset_next(objset_t *os, uint64_t object, boolean_t hole, uint64_t *off)
{
	dnode_t *dn;
	int i, err;

	dn = dnode_hold(os->os, object, FTAG);
	/*
	 * Sync any current changes before
	 * we go trundling through the block pointers.
	 */
	for (i = 0; i < TXG_SIZE; i++) {
		if (dn->dn_dirtyblksz[i])
			break;
	}
	if (i != TXG_SIZE) {
		dnode_rele(dn, FTAG);
		txg_wait_synced(dmu_objset_pool(os), 0);
		dn = dnode_hold(os->os, object, FTAG);
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
	doi->doi_physical_blks = dn->dn_phys->dn_secphys;
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
	dnode_t *dn = dnode_hold(os->os, object, FTAG);

	if (dn == NULL)
		return (ENOENT);

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
	*nblk512 = dn->dn_phys->dn_secphys + 1;	/* add 1 for dnode space */
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
