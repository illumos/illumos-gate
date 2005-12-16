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

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/fs/zfs.h>

/*
 * Virtual device vector for RAID-Z.
 */

/*
 * We currently allow up to two-way replication (i.e. single-fault
 * reconstruction) models in RAID-Z vdevs.  The blocks in such vdevs
 * must all be multiples of two times the leaf vdev blocksize.
 */
#define	VDEV_RAIDZ_ALIGN	2ULL

typedef struct raidz_col {
	uint64_t	rc_col;
	uint64_t	rc_offset;
	uint64_t	rc_size;
	void		*rc_data;
	int		rc_error;
	short		rc_tried;
	short		rc_skipped;
} raidz_col_t;

typedef struct raidz_map {
	uint64_t	rm_cols;
	uint64_t	rm_bigcols;
	uint64_t	rm_asize;
	int		rm_missing_child;
	int		rm_firstdatacol;
	raidz_col_t	rm_col[1];
} raidz_map_t;

static raidz_map_t *
vdev_raidz_map_alloc(zio_t *zio, uint64_t unit_shift, uint64_t dcols)
{
	raidz_map_t *rm;
	uint64_t b = zio->io_offset >> unit_shift;
	uint64_t s = zio->io_size >> unit_shift;
	uint64_t f = b % dcols;
	uint64_t o = (b / dcols) << unit_shift;
	uint64_t q, r, c, bc, col, acols, coff;
	int firstdatacol;

	q = s / (dcols - 1);
	r = s - q * (dcols - 1);
	bc = r + !!r;
	firstdatacol = 1;

	acols = (q == 0 ? bc : dcols);

	rm = kmem_alloc(offsetof(raidz_map_t, rm_col[acols]), KM_SLEEP);

	rm->rm_cols = acols;
	rm->rm_bigcols = bc;
	rm->rm_asize = 0;
	rm->rm_missing_child = -1;
	rm->rm_firstdatacol = firstdatacol;

	for (c = 0; c < acols; c++) {
		col = f + c;
		coff = o;
		if (col >= dcols) {
			col -= dcols;
			coff += 1ULL << unit_shift;
		}
		rm->rm_col[c].rc_col = col;
		rm->rm_col[c].rc_offset = coff;
		rm->rm_col[c].rc_size = (q + (c < bc)) << unit_shift;
		rm->rm_col[c].rc_data = NULL;
		rm->rm_col[c].rc_error = 0;
		rm->rm_col[c].rc_tried = 0;
		rm->rm_col[c].rc_skipped = 0;
		rm->rm_asize += rm->rm_col[c].rc_size;
	}

	rm->rm_asize = P2ROUNDUP(rm->rm_asize, VDEV_RAIDZ_ALIGN << unit_shift);

	for (c = 0; c < rm->rm_firstdatacol; c++)
		rm->rm_col[c].rc_data = zio_buf_alloc(rm->rm_col[c].rc_size);

	rm->rm_col[c].rc_data = zio->io_data;

	for (c = c + 1; c < acols; c++)
		rm->rm_col[c].rc_data = (char *)rm->rm_col[c - 1].rc_data +
		    rm->rm_col[c - 1].rc_size;

	/*
	 * To prevent hot parity disks, switch the parity and data
	 * columns every 1MB.
	 */
	ASSERT(rm->rm_cols >= 2);
	ASSERT(rm->rm_col[0].rc_size == rm->rm_col[1].rc_size);

	if (zio->io_offset & (1ULL << 20)) {
		col = rm->rm_col[0].rc_col;
		o = rm->rm_col[0].rc_offset;
		rm->rm_col[0].rc_col = rm->rm_col[1].rc_col;
		rm->rm_col[0].rc_offset = rm->rm_col[1].rc_offset;
		rm->rm_col[1].rc_col = col;
		rm->rm_col[1].rc_offset = o;
	}

	zio->io_vsd = rm;
	return (rm);
}

static void
vdev_raidz_map_free(zio_t *zio)
{
	raidz_map_t *rm = zio->io_vsd;
	int c;

	for (c = 0; c < rm->rm_firstdatacol; c++)
		zio_buf_free(rm->rm_col[c].rc_data, rm->rm_col[c].rc_size);

	kmem_free(rm, offsetof(raidz_map_t, rm_col[rm->rm_cols]));
	zio->io_vsd = NULL;
}

static void
vdev_raidz_reconstruct(raidz_map_t *rm, int x)
{
	uint64_t *dst, *src, count, xsize, csize;
	int i, c;

	for (c = 0; c < rm->rm_cols; c++) {
		if (c == x)
			continue;
		src = rm->rm_col[c].rc_data;
		dst = rm->rm_col[x].rc_data;
		csize = rm->rm_col[c].rc_size;
		xsize = rm->rm_col[x].rc_size;
		count = MIN(csize, xsize) / sizeof (uint64_t);
		if (c == !x) {
			/*
			 * The initial copy happens at either c == 0 or c == 1.
			 * Both of these columns are 'big' columns, so we'll
			 * definitely initialize all of column x.
			 */
			ASSERT3U(xsize, <=, csize);
			for (i = 0; i < count; i++)
				*dst++ = *src++;
		} else {
			for (i = 0; i < count; i++)
				*dst++ ^= *src++;
		}
	}
}

static int
vdev_raidz_open(vdev_t *vd, uint64_t *asize, uint64_t *ashift)
{
	vdev_t *cvd;
	int c, error;
	int lasterror = 0;
	int numerrors = 0;

	/*
	 * XXX -- minimum children should be raid-type-specific
	 */
	if (vd->vdev_children < 2) {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (EINVAL);
	}

	for (c = 0; c < vd->vdev_children; c++) {
		cvd = vd->vdev_child[c];

		if ((error = vdev_open(cvd)) != 0) {
			lasterror = error;
			numerrors++;
			continue;
		}

		*asize = MIN(*asize - 1, cvd->vdev_asize - 1) + 1;
		*ashift = cvd->vdev_ashift;
	}

	*asize *= vd->vdev_children;

	if (numerrors > 1) {
		vd->vdev_stat.vs_aux = VDEV_AUX_NO_REPLICAS;
		return (lasterror);
	}

	return (0);
}

static void
vdev_raidz_close(vdev_t *vd)
{
	int c;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_close(vd->vdev_child[c]);
}

static uint64_t
vdev_raidz_asize(vdev_t *vd, uint64_t psize)
{
	uint64_t asize;
	uint64_t cols = vd->vdev_children;

	asize = psize >> vd->vdev_ashift;
	asize += (asize + cols - 2) / (cols - 1);
	asize = P2ROUNDUP(asize, VDEV_RAIDZ_ALIGN) << vd->vdev_ashift;

	return (asize);
}

static void
vdev_raidz_child_done(zio_t *zio)
{
	raidz_col_t *rc = zio->io_private;

	rc->rc_error = zio->io_error;
	rc->rc_tried = 1;
	rc->rc_skipped = 0;
}

static void
vdev_raidz_repair_done(zio_t *zio)
{
	zio_buf_free(zio->io_data, zio->io_size);
}

static void
vdev_raidz_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_t *cvd;
	blkptr_t *bp = zio->io_bp;
	raidz_map_t *rm;
	raidz_col_t *rc;
	int c;

	rm = vdev_raidz_map_alloc(zio, vd->vdev_ashift, vd->vdev_children);

	if (DVA_GET_GANG(ZIO_GET_DVA(zio))) {
		ASSERT3U(rm->rm_asize, ==,
		    vdev_psize_to_asize(vd, SPA_GANGBLOCKSIZE));
		ASSERT3U(zio->io_size, ==, SPA_GANGBLOCKSIZE);
	} else {
		ASSERT3U(rm->rm_asize, ==, DVA_GET_ASIZE(ZIO_GET_DVA(zio)));
		ASSERT3U(zio->io_size, ==, BP_GET_PSIZE(bp));
	}

	if (zio->io_type == ZIO_TYPE_WRITE) {

		/*
		 * Generate RAID parity in virtual column 0.
		 */
		vdev_raidz_reconstruct(rm, 0);

		for (c = 0; c < rm->rm_cols; c++) {
			rc = &rm->rm_col[c];
			cvd = vd->vdev_child[rc->rc_col];
			zio_nowait(zio_vdev_child_io(zio, NULL, cvd,
			    rc->rc_offset, rc->rc_data, rc->rc_size,
			    zio->io_type, zio->io_priority, ZIO_FLAG_CANFAIL,
			    vdev_raidz_child_done, rc));
		}
		zio_wait_children_done(zio);
		return;
	}

	ASSERT(zio->io_type == ZIO_TYPE_READ);

	for (c = rm->rm_cols - 1; c >= 0; c--) {
		rc = &rm->rm_col[c];
		cvd = vd->vdev_child[rc->rc_col];
		if (vdev_is_dead(cvd)) {
			rm->rm_missing_child = c;
			rc->rc_error = ENXIO;
			rc->rc_tried = 1;	/* don't even try */
			rc->rc_skipped = 1;
			continue;
		}
		if (vdev_dtl_contains(&cvd->vdev_dtl_map, bp->blk_birth, 1)) {
			rm->rm_missing_child = c;
			rc->rc_error = ESTALE;
			rc->rc_skipped = 1;
			continue;
		}
		if (c >= rm->rm_firstdatacol || rm->rm_missing_child != -1 ||
		    (zio->io_flags & ZIO_FLAG_SCRUB)) {
			zio_nowait(zio_vdev_child_io(zio, NULL, cvd,
			    rc->rc_offset, rc->rc_data, rc->rc_size,
			    zio->io_type, zio->io_priority, ZIO_FLAG_CANFAIL,
			    vdev_raidz_child_done, rc));
		}
	}

	zio_wait_children_done(zio);
}

static void
vdev_raidz_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_t *cvd;
	raidz_map_t *rm = zio->io_vsd;
	raidz_col_t *rc;
	blkptr_t *bp = zio->io_bp;
	int unexpected_errors = 0;
	int c;

	ASSERT(bp != NULL);	/* XXX need to add code to enforce this */

	zio->io_error = 0;
	zio->io_numerrors = 0;

	for (c = 0; c < rm->rm_cols; c++) {
		rc = &rm->rm_col[c];

		/*
		 * We preserve any EIOs because those may be worth retrying;
		 * whereas ECKSUM and ENXIO are more likely to be persistent.
		 */
		if (rc->rc_error) {
			if (zio->io_error != EIO)
				zio->io_error = rc->rc_error;
			if (!rc->rc_skipped)
				unexpected_errors++;
			zio->io_numerrors++;
		}
	}

	if (zio->io_type == ZIO_TYPE_WRITE) {
		/*
		 * If this is not a failfast write, and we were able to
		 * write enough columns to reconstruct the data, good enough.
		 */
		/* XXPOLICY */
		if (zio->io_numerrors <= rm->rm_firstdatacol &&
		    !(zio->io_flags & ZIO_FLAG_FAILFAST))
			zio->io_error = 0;

		vdev_raidz_map_free(zio);
		zio_next_stage(zio);
		return;
	}

	ASSERT(zio->io_type == ZIO_TYPE_READ);

	/*
	 * If there were no I/O errors, and the data checksums correctly,
	 * the read is complete.
	 */
	/* XXPOLICY */
	if (zio->io_numerrors == 0 && zio_checksum_error(zio) == 0) {
		ASSERT(unexpected_errors == 0);
		ASSERT(zio->io_error == 0);

		/*
		 * We know the data's good.  If we read the parity,
		 * verify that it's good as well.  If not, fix it.
		 */
		for (c = 0; c < rm->rm_firstdatacol; c++) {
			void *orig;
			rc = &rm->rm_col[c];
			if (!rc->rc_tried)
				continue;
			orig = zio_buf_alloc(rc->rc_size);
			bcopy(rc->rc_data, orig, rc->rc_size);
			vdev_raidz_reconstruct(rm, c);
			if (bcmp(orig, rc->rc_data, rc->rc_size) != 0) {
				vdev_checksum_error(zio,
				    vd->vdev_child[rc->rc_col]);
				rc->rc_error = ECKSUM;
				unexpected_errors++;
			}
			zio_buf_free(orig, rc->rc_size);
		}
		goto done;
	}

	/*
	 * If there was exactly one I/O error, it's the one we expected,
	 * and the reconstructed data checksums, the read is complete.
	 * This happens when one child is offline and vdev_fault_assess()
	 * knows it, or when one child has stale data and the DTL knows it.
	 */
	if (zio->io_numerrors == 1 && (c = rm->rm_missing_child) != -1) {
		rc = &rm->rm_col[c];
		ASSERT(unexpected_errors == 0);
		ASSERT(rc->rc_error == ENXIO || rc->rc_error == ESTALE);
		vdev_raidz_reconstruct(rm, c);
		if (zio_checksum_error(zio) == 0) {
			zio->io_error = 0;
			goto done;
		}
	}

	/*
	 * This isn't a typical error -- either we got a read error or
	 * more than one child claimed a problem.  Read every block we
	 * haven't already so we can try combinatorial reconstruction.
	 */
	unexpected_errors = 1;
	rm->rm_missing_child = -1;

	for (c = 0; c < rm->rm_cols; c++)
		if (!rm->rm_col[c].rc_tried)
			break;

	if (c != rm->rm_cols) {
		zio->io_error = 0;
		zio_vdev_io_redone(zio);
		for (c = 0; c < rm->rm_cols; c++) {
			rc = &rm->rm_col[c];
			if (rc->rc_tried)
				continue;
			zio_nowait(zio_vdev_child_io(zio, NULL,
			    vd->vdev_child[rc->rc_col],
			    rc->rc_offset, rc->rc_data, rc->rc_size,
			    zio->io_type, zio->io_priority, ZIO_FLAG_CANFAIL,
			    vdev_raidz_child_done, rc));
		}
		zio_wait_children_done(zio);
		return;
	}

	/*
	 * If there were more errors than parity disks, give up.
	 */
	if (zio->io_numerrors > rm->rm_firstdatacol) {
		ASSERT(zio->io_error != 0);
		goto done;
	}

	/*
	 * The number of I/O errors is correctable.  Correct them here.
	 */
	ASSERT(zio->io_numerrors <= rm->rm_firstdatacol);
	for (c = 0; c < rm->rm_cols; c++) {
		rc = &rm->rm_col[c];
		ASSERT(rc->rc_tried);
		if (rc->rc_error) {
			vdev_raidz_reconstruct(rm, c);
			if (zio_checksum_error(zio) == 0)
				zio->io_error = 0;
			else
				zio->io_error = rc->rc_error;
			goto done;
		}
	}

	/*
	 * There were no I/O errors, but the data doesn't checksum.
	 * Try all permutations to see if we can find one that does.
	 */
	ASSERT(zio->io_numerrors == 0);
	for (c = 0; c < rm->rm_cols; c++) {
		void *orig;
		rc = &rm->rm_col[c];

		orig = zio_buf_alloc(rc->rc_size);
		bcopy(rc->rc_data, orig, rc->rc_size);
		vdev_raidz_reconstruct(rm, c);

		if (zio_checksum_error(zio) == 0) {
			zio_buf_free(orig, rc->rc_size);
			zio->io_error = 0;
			/*
			 * If this child didn't know that it returned bad data,
			 * inform it.
			 */
			if (rc->rc_tried && rc->rc_error == 0)
				vdev_checksum_error(zio,
				    vd->vdev_child[rc->rc_col]);
			rc->rc_error = ECKSUM;
			goto done;
		}

		bcopy(orig, rc->rc_data, rc->rc_size);
		zio_buf_free(orig, rc->rc_size);
	}

	/*
	 * All combinations failed to checksum.
	 */
	zio->io_error = ECKSUM;

done:
	zio_checksum_verified(zio);

	if (zio->io_error == 0 && (spa_mode & FWRITE) &&
	    (unexpected_errors || (zio->io_flags & ZIO_FLAG_RESILVER))) {
		/*
		 * Use the good data we have in hand to repair damaged children.
		 */
		for (c = 0; c < rm->rm_cols; c++) {
			rc = &rm->rm_col[c];
			cvd = vd->vdev_child[rc->rc_col];

			if (rc->rc_error) {
				/*
				 * Make a copy of the data because we're
				 * going to free the RAID-Z map below.
				 */
				void *data = zio_buf_alloc(rc->rc_size);
				bcopy(rc->rc_data, data, rc->rc_size);

				dprintf("%s resilvered %s @ 0x%llx error %d\n",
				    vdev_description(vd),
				    vdev_description(cvd),
				    zio->io_offset, rc->rc_error);

				zio_nowait(zio_vdev_child_io(zio, NULL, cvd,
				    rc->rc_offset, data, rc->rc_size,
				    ZIO_TYPE_WRITE, zio->io_priority,
				    ZIO_FLAG_IO_REPAIR | ZIO_FLAG_CANFAIL |
				    ZIO_FLAG_DONT_PROPAGATE,
				    vdev_raidz_repair_done, NULL));
			}
		}
	}

	vdev_raidz_map_free(zio);
	zio_next_stage(zio);
}

static void
vdev_raidz_state_change(vdev_t *vd, int faulted, int degraded)
{
	if (faulted > 1)
		vdev_set_state(vd, VDEV_STATE_CANT_OPEN, VDEV_AUX_NO_REPLICAS);
	else if (degraded + faulted != 0)
		vdev_set_state(vd, VDEV_STATE_DEGRADED, VDEV_AUX_NONE);
	else
		vdev_set_state(vd, VDEV_STATE_HEALTHY, VDEV_AUX_NONE);
}

vdev_ops_t vdev_raidz_ops = {
	vdev_raidz_open,
	vdev_raidz_close,
	vdev_raidz_asize,
	vdev_raidz_io_start,
	vdev_raidz_io_done,
	vdev_raidz_state_change,
	VDEV_TYPE_RAIDZ,	/* name of this vdev type */
	B_FALSE			/* not a leaf vdev */
};
