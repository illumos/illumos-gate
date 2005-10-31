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
#include <sys/fs/zfs.h>

/*
 * Virtual device vector for mirroring.
 */

typedef struct mirror_map {
	int	mm_error;
	short	mm_tried;
	short	mm_skipped;
} mirror_map_t;

static mirror_map_t *
vdev_mirror_map_alloc(zio_t *zio)
{
	zio->io_vsd = kmem_zalloc(zio->io_vd->vdev_children *
	    sizeof (mirror_map_t), KM_SLEEP);
	return (zio->io_vsd);
}

static void
vdev_mirror_map_free(zio_t *zio)
{
	kmem_free(zio->io_vsd,
	    zio->io_vd->vdev_children * sizeof (mirror_map_t));
	zio->io_vsd = NULL;
}

static int
vdev_mirror_open(vdev_t *vd, uint64_t *asize, uint64_t *ashift)
{
	vdev_t *cvd;
	uint64_t c;
	int numerrors = 0;
	int ret, lasterror = 0;

	if (vd->vdev_children == 0) {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (EINVAL);
	}

	for (c = 0; c < vd->vdev_children; c++) {
		cvd = vd->vdev_child[c];

		if ((ret = vdev_open(cvd)) != 0) {
			lasterror = ret;
			numerrors++;
			continue;
		}

		*asize = MIN(*asize - 1, cvd->vdev_asize - 1) + 1;
		*ashift = cvd->vdev_ashift;
	}

	if (numerrors == vd->vdev_children) {
		vd->vdev_stat.vs_aux = VDEV_AUX_NO_REPLICAS;
		return (lasterror);
	}

	return (0);
}

static void
vdev_mirror_close(vdev_t *vd)
{
	uint64_t c;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_close(vd->vdev_child[c]);
}

static void
vdev_mirror_child_done(zio_t *zio)
{
	mirror_map_t *mm = zio->io_private;

	mm->mm_error = zio->io_error;
	mm->mm_tried = 1;
	mm->mm_skipped = 0;
}

static void
vdev_mirror_scrub_done(zio_t *zio)
{
	mirror_map_t *mm = zio->io_private;

	if (zio->io_error == 0) {
		zio_t *pio = zio->io_parent;
		mutex_enter(&pio->io_lock);
		bcopy(zio->io_data, pio->io_data, pio->io_size);
		mutex_exit(&pio->io_lock);
	}

	zio_buf_free(zio->io_data, zio->io_size);

	mm->mm_error = zio->io_error;
	mm->mm_tried = 1;
	mm->mm_skipped = 0;
}

/*
 * Try to find a child whose DTL doesn't contain the block we want to read.
 * If we can't, try the read on any vdev we haven't already tried.
 */
static int
vdev_mirror_child_select(zio_t *zio)
{
	mirror_map_t *mm = zio->io_vsd;
	vdev_t *vd = zio->io_vd;
	vdev_t *cvd;
	uint64_t txg = zio->io_txg;
	int i, c;

	ASSERT(zio->io_bp == NULL || zio->io_bp->blk_birth == txg);

	/*
	 * Select the child we'd like to read from absent any errors.
	 * The current policy is to alternate sides at 8M granularity.
	 * XXX -- investigate other policies for read distribution.
	 */
	c = (zio->io_offset >> (SPA_MAXBLOCKSHIFT + 6)) % vd->vdev_children;

	/*
	 * If this is a replacing vdev, always try child 0 (the source) first.
	 */
	if (vd->vdev_ops == &vdev_replacing_ops)
		c = 0;

	/*
	 * Try to find a child whose DTL doesn't contain the block to read.
	 * If a child is known to be completely inaccessible (indicated by
	 * vdev_is_dead() returning B_TRUE), don't even try.
	 */
	for (i = 0; i < vd->vdev_children; i++, c++) {
		if (c >= vd->vdev_children)
			c = 0;
		if (mm[c].mm_tried || mm[c].mm_skipped)
			continue;
		cvd = vd->vdev_child[c];
		if (vdev_is_dead(cvd)) {
			mm[c].mm_error = ENXIO;
			mm[c].mm_tried = 1;	/* don't even try */
			mm[c].mm_skipped = 1;
			continue;
		}
		if (!vdev_dtl_contains(&cvd->vdev_dtl_map, txg, 1))
			return (c);
		mm[c].mm_error = ESTALE;
		mm[c].mm_skipped = 1;
	}

	/*
	 * Every device is either missing or has this txg in its DTL.
	 * If we don't have any sibling replicas to consult, look for
	 * any child we haven't already tried before giving up.
	 */
	if (vd == vd->vdev_top || vd->vdev_parent->vdev_children <= 1) {
		for (c = 0; c < vd->vdev_children; c++) {
			if (!mm[c].mm_tried)
				return (c);
		}
	}

	/*
	 * Every child failed.  There's no place left to look.
	 */
	return (-1);
}

static void
vdev_mirror_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	mirror_map_t *mm;
	int c, children;

	mm = vdev_mirror_map_alloc(zio);

	if (zio->io_type == ZIO_TYPE_READ) {
		if (zio->io_flags & ZIO_FLAG_SCRUB) {
			/*
			 * For scrubbing reads we need to allocate a read
			 * buffer for each child and issue reads to all
			 * children.  If any child succeeds, it will copy its
			 * data into zio->io_data in vdev_mirror_scrub_done.
			 */
			for (c = 0; c < vd->vdev_children; c++) {
				zio_nowait(zio_vdev_child_io(zio, zio->io_bp,
				    vd->vdev_child[c], zio->io_offset,
				    zio_buf_alloc(zio->io_size), zio->io_size,
				    zio->io_type, zio->io_priority,
				    ZIO_FLAG_CANFAIL, vdev_mirror_scrub_done,
				    &mm[c]));
			}
			zio_wait_children_done(zio);
			return;
		}
		/*
		 * For normal reads just pick one child.
		 */
		c = vdev_mirror_child_select(zio);
		children = (c >= 0);
	} else {
		ASSERT(zio->io_type == ZIO_TYPE_WRITE);

		/*
		 * If this is a resilvering I/O to a replacing vdev,
		 * only the last child should be written -- unless the
		 * first child happens to have a DTL entry here as well.
		 * All other writes go to all children.
		 */
		if ((zio->io_flags & ZIO_FLAG_RESILVER) &&
		    vd->vdev_ops == &vdev_replacing_ops &&
		    !vdev_dtl_contains(&vd->vdev_child[0]->vdev_dtl_map,
		    zio->io_txg, 1)) {
			c = vd->vdev_children - 1;
			children = 1;
		} else {
			c = 0;
			children = vd->vdev_children;
		}
	}

	while (children--) {
		zio_nowait(zio_vdev_child_io(zio, zio->io_bp,
		    vd->vdev_child[c], zio->io_offset, zio->io_data,
		    zio->io_size, zio->io_type, zio->io_priority,
		    ZIO_FLAG_CANFAIL, vdev_mirror_child_done, &mm[c]));
		c++;
	}

	zio_wait_children_done(zio);
}

static void
vdev_mirror_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_t *cvd;
	mirror_map_t *mm = zio->io_vsd;
	int c;
	int good_copies = 0;
	int unexpected_errors = 0;

	ASSERT(mm != NULL);

	zio->io_error = 0;
	zio->io_numerrors = 0;

	for (c = 0; c < vd->vdev_children; c++) {
		if (mm[c].mm_tried && mm[c].mm_error == 0) {
			good_copies++;
			continue;
		}

		/*
		 * We preserve any EIOs because those may be worth retrying;
		 * whereas ECKSUM and ENXIO are more likely to be persistent.
		 */
		if (mm[c].mm_error) {
			if (zio->io_error != EIO)
				zio->io_error = mm[c].mm_error;
			if (!mm[c].mm_skipped)
				unexpected_errors++;
			zio->io_numerrors++;
		}
	}

	if (zio->io_type == ZIO_TYPE_WRITE) {
		/*
		 * XXX -- for now, treat partial writes as success.
		 */
		/* XXPOLICY */
		if (good_copies != 0)
			zio->io_error = 0;
		ASSERT(mm != NULL);
		vdev_mirror_map_free(zio);
		zio_next_stage(zio);
		return;
	}

	ASSERT(zio->io_type == ZIO_TYPE_READ);

	/*
	 * If we don't have a good copy yet, keep trying other children.
	 */
	/* XXPOLICY */
	if (good_copies == 0 && (c = vdev_mirror_child_select(zio)) != -1) {
		ASSERT(c >= 0 && c < vd->vdev_children);
		cvd = vd->vdev_child[c];
		dprintf("%s: retrying i/o (err=%d) on child %s\n",
		    vdev_description(zio->io_vd), zio->io_error,
		    vdev_description(cvd));
		zio->io_error = 0;
		zio_vdev_io_redone(zio);
		zio_nowait(zio_vdev_child_io(zio, zio->io_bp, cvd,
		    zio->io_offset, zio->io_data, zio->io_size,
		    ZIO_TYPE_READ, zio->io_priority, ZIO_FLAG_CANFAIL,
		    vdev_mirror_child_done, &mm[c]));
		zio_wait_children_done(zio);
		return;
	}

	/* XXPOLICY */
	if (good_copies)
		zio->io_error = 0;
	else
		ASSERT(zio->io_error != 0);

	if (good_copies && (spa_mode & FWRITE) &&
	    (unexpected_errors || (zio->io_flags & ZIO_FLAG_RESILVER))) {
		/*
		 * Use the good data we have in hand to repair damaged children.
		 */
		for (c = 0; c < vd->vdev_children; c++) {
			/*
			 * Don't rewrite known good children.
			 * Not only is it unnecessary, it could
			 * actually be harmful: if the system lost
			 * power while rewriting the only good copy,
			 * there would be no good copies left!
			 */
			cvd = vd->vdev_child[c];

			if (mm[c].mm_error == 0) {
				if (mm[c].mm_tried)
					continue;
				if (!vdev_dtl_contains(&cvd->vdev_dtl_map,
				    zio->io_txg, 1))
					continue;
				mm[c].mm_error = ESTALE;
			}

			dprintf("%s resilvered %s @ 0x%llx error %d\n",
			    vdev_description(vd),
			    vdev_description(cvd),
			    zio->io_offset, mm[c].mm_error);

			zio_nowait(zio_vdev_child_io(zio, zio->io_bp, cvd,
			    zio->io_offset, zio->io_data, zio->io_size,
			    ZIO_TYPE_WRITE, zio->io_priority,
			    ZIO_FLAG_IO_REPAIR | ZIO_FLAG_CANFAIL |
			    ZIO_FLAG_DONT_PROPAGATE, NULL, NULL));
		}
	}

	vdev_mirror_map_free(zio);
	zio_next_stage(zio);
}

static void
vdev_mirror_state_change(vdev_t *vd, int faulted, int degraded)
{
	if (faulted == vd->vdev_children)
		vdev_set_state(vd, VDEV_STATE_CANT_OPEN, VDEV_AUX_NO_REPLICAS);
	else if (degraded + faulted != 0)
		vdev_set_state(vd, VDEV_STATE_DEGRADED, VDEV_AUX_NONE);
	else
		vdev_set_state(vd, VDEV_STATE_HEALTHY, VDEV_AUX_NONE);
}

vdev_ops_t vdev_mirror_ops = {
	vdev_mirror_open,
	vdev_mirror_close,
	vdev_default_asize,
	vdev_mirror_io_start,
	vdev_mirror_io_done,
	vdev_mirror_state_change,
	VDEV_TYPE_MIRROR,	/* name of this vdev type */
	B_FALSE			/* not a leaf vdev */
};

vdev_ops_t vdev_replacing_ops = {
	vdev_mirror_open,
	vdev_mirror_close,
	vdev_default_asize,
	vdev_mirror_io_start,
	vdev_mirror_io_done,
	vdev_mirror_state_change,
	VDEV_TYPE_REPLACING,	/* name of this vdev type */
	B_FALSE			/* not a leaf vdev */
};
