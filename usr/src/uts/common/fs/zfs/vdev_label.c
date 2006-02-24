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

/*
 * Virtual Device Labels
 * ---------------------
 *
 * The vdev label serves several distinct purposes:
 *
 *	1. Uniquely identify this device as part of a ZFS pool and confirm its
 *	   identity within the pool.
 *
 * 	2. Verify that all the devices given in a configuration are present
 *         within the pool.
 *
 * 	3. Determine the uberblock for the pool.
 *
 * 	4. In case of an import operation, determine the configuration of the
 *         toplevel vdev of which it is a part.
 *
 * 	5. If an import operation cannot find all the devices in the pool,
 *         provide enough information to the administrator to determine which
 *         devices are missing.
 *
 * It is important to note that while the kernel is responsible for writing the
 * label, it only consumes the information in the first three cases.  The
 * latter information is only consumed in userland when determining the
 * configuration to import a pool.
 *
 *
 * Label Organization
 * ------------------
 *
 * Before describing the contents of the label, it's important to understand how
 * the labels are written and updated with respect to the uberblock.
 *
 * When the pool configuration is altered, either because it was newly created
 * or a device was added, we want to update all the labels such that we can deal
 * with fatal failure at any point.  To this end, each disk has two labels which
 * are updated before and after the uberblock is synced.  Assuming we have
 * labels and an uberblock with the following transacation groups:
 *
 *              L1          UB          L2
 *           +------+    +------+    +------+
 *           |      |    |      |    |      |
 *           | t10  |    | t10  |    | t10  |
 *           |      |    |      |    |      |
 *           +------+    +------+    +------+
 *
 * In this stable state, the labels and the uberblock were all updated within
 * the same transaction group (10).  Each label is mirrored and checksummed, so
 * that we can detect when we fail partway through writing the label.
 *
 * In order to identify which labels are valid, the labels are written in the
 * following manner:
 *
 * 	1. For each vdev, update 'L1' to the new label
 * 	2. Update the uberblock
 * 	3. For each vdev, update 'L2' to the new label
 *
 * Given arbitrary failure, we can determine the correct label to use based on
 * the transaction group.  If we fail after updating L1 but before updating the
 * UB, we will notice that L1's transaction group is greater than the uberblock,
 * so L2 must be valid.  If we fail after writing the uberblock but before
 * writing L2, we will notice that L2's transaction group is less than L1, and
 * therefore L1 is valid.
 *
 * Another added complexity is that not every label is updated when the config
 * is synced.  If we add a single device, we do not want to have to re-write
 * every label for every device in the pool.  This means that both L1 and L2 may
 * be older than the pool uberblock, because the necessary information is stored
 * on another vdev.
 *
 *
 * On-disk Format
 * --------------
 *
 * The vdev label consists of two distinct parts, and is wrapped within the
 * vdev_label_t structure.  The label includes 8k of padding to permit legacy
 * VTOC disk labels, but is otherwise ignored.
 *
 * The first half of the label is a packed nvlist which contains pool wide
 * properties, per-vdev properties, and configuration information.  It is
 * described in more detail below.
 *
 * The latter half of the label consists of a redundant array of uberblocks.
 * These uberblocks are updated whenever a transaction group is committed,
 * or when the configuration is updated.  When a pool is loaded, we scan each
 * vdev for the 'best' uberblock.
 *
 *
 * Configuration Information
 * -------------------------
 *
 * The nvlist describing the pool and vdev contains the following elements:
 *
 * 	version		ZFS on-disk version
 * 	name		Pool name
 * 	state		Pool state
 * 	txg		Transaction group in which this label was written
 * 	pool_guid	Unique identifier for this pool
 * 	vdev_tree	An nvlist describing vdev tree.
 *
 * Each leaf device label also contains the following:
 *
 * 	top_guid	Unique ID for top-level vdev in which this is contained
 * 	guid		Unique ID for the leaf vdev
 *
 * The 'vs' configuration follows the format described in 'spa_config.c'.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/uberblock_impl.h>
#include <sys/metaslab.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>

/*
 * Basic routines to read and write from a vdev label.
 * Used throughout the rest of this file.
 */
uint64_t
vdev_label_offset(uint64_t psize, int l, uint64_t offset)
{
	return (offset + l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : psize - VDEV_LABELS * sizeof (vdev_label_t)));
}

static void
vdev_label_read(zio_t *zio, vdev_t *vd, int l, void *buf, uint64_t offset,
	uint64_t size, zio_done_func_t *done, void *private)
{
	ASSERT(vd->vdev_children == 0);

	zio_nowait(zio_read_phys(zio, vd,
	    vdev_label_offset(vd->vdev_psize, l, offset),
	    size, buf, ZIO_CHECKSUM_LABEL, done, private,
	    ZIO_PRIORITY_SYNC_READ, ZIO_FLAG_SPECULATIVE |
	    ZIO_FLAG_CANFAIL | ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_DONT_RETRY));
}

static void
vdev_label_write(zio_t *zio, vdev_t *vd, int l, void *buf, uint64_t offset,
	uint64_t size, zio_done_func_t *done, void *private)
{
	ASSERT(vd->vdev_children == 0);

	zio_nowait(zio_write_phys(zio, vd,
	    vdev_label_offset(vd->vdev_psize, l, offset),
	    size, buf, ZIO_CHECKSUM_LABEL, done, private,
	    ZIO_PRIORITY_SYNC_WRITE,
	    ZIO_FLAG_CANFAIL | ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_DONT_RETRY));
}

/*
 * Generate the nvlist representing this vdev's config.
 */
nvlist_t *
vdev_config_generate(vdev_t *vd, int getstats)
{
	nvlist_t *nv = NULL;

	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, 0) == 0);

	VERIFY(nvlist_add_string(nv, ZPOOL_CONFIG_TYPE,
	    vd->vdev_ops->vdev_op_type) == 0);
	VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_ID, vd->vdev_id) == 0);
	VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_GUID, vd->vdev_guid) == 0);

	if (vd->vdev_path != NULL)
		VERIFY(nvlist_add_string(nv, ZPOOL_CONFIG_PATH,
		    vd->vdev_path) == 0);

	if (vd->vdev_devid != NULL)
		VERIFY(nvlist_add_string(nv, ZPOOL_CONFIG_DEVID,
		    vd->vdev_devid) == 0);

	if (vd->vdev_wholedisk != -1ULL)
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_WHOLE_DISK,
		    vd->vdev_wholedisk) == 0);

	if (vd == vd->vdev_top) {
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_METASLAB_ARRAY,
		    vd->vdev_ms_array) == 0);
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_METASLAB_SHIFT,
		    vd->vdev_ms_shift) == 0);
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_ASHIFT,
		    vd->vdev_ashift) == 0);
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_ASIZE,
		    vd->vdev_asize) == 0);
	}

	if (vd->vdev_dtl.smo_object != 0)
		VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_DTL,
		    vd->vdev_dtl.smo_object) == 0);

	if (getstats) {
		vdev_stat_t vs;
		vdev_get_stats(vd, &vs);
		VERIFY(nvlist_add_uint64_array(nv, ZPOOL_CONFIG_STATS,
		    (uint64_t *)&vs, sizeof (vs) / sizeof (uint64_t)) == 0);
	}

	if (!vd->vdev_ops->vdev_op_leaf) {
		nvlist_t **child;
		int c;

		child = kmem_alloc(vd->vdev_children * sizeof (nvlist_t *),
		    KM_SLEEP);

		for (c = 0; c < vd->vdev_children; c++)
			child[c] = vdev_config_generate(vd->vdev_child[c],
			    getstats);

		VERIFY(nvlist_add_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
		    child, vd->vdev_children) == 0);

		for (c = 0; c < vd->vdev_children; c++)
			nvlist_free(child[c]);

		kmem_free(child, vd->vdev_children * sizeof (nvlist_t *));

	} else {
		if (!vd->vdev_tmpoffline) {
		    if (vd->vdev_offline)
			VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_OFFLINE,
				B_TRUE) == 0);
		    else
			(void) nvlist_remove(nv, ZPOOL_CONFIG_OFFLINE,
				DATA_TYPE_UINT64);
		}
	}

	return (nv);
}

nvlist_t *
vdev_label_read_config(vdev_t *vd)
{
	nvlist_t *config = NULL;
	vdev_phys_t *vp;
	uint64_t version;
	zio_t *zio;
	int l;

	if (vdev_is_dead(vd))
		return (NULL);

	vp = zio_buf_alloc(sizeof (vdev_phys_t));

	for (l = 0; l < VDEV_LABELS; l++) {

		zio = zio_root(vd->vdev_spa, NULL, NULL,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_CONFIG_HELD);

		vdev_label_read(zio, vd, l, vp,
		    offsetof(vdev_label_t, vl_vdev_phys),
		    sizeof (vdev_phys_t), NULL, NULL);

		if (zio_wait(zio) == 0 &&
		    nvlist_unpack(vp->vp_nvlist, sizeof (vp->vp_nvlist),
		    &config, 0) == 0 &&
		    nvlist_lookup_uint64(config, ZPOOL_CONFIG_VERSION,
		    &version) == 0 &&
		    version == UBERBLOCK_VERSION)
			break;

		if (config != NULL) {
			nvlist_free(config);
			config = NULL;
		}
	}

	zio_buf_free(vp, sizeof (vdev_phys_t));

	return (config);
}

int
vdev_label_init(vdev_t *vd, uint64_t crtxg)
{
	spa_t *spa = vd->vdev_spa;
	nvlist_t *label;
	vdev_phys_t *vp;
	vdev_boot_header_t *vb;
	uberblock_phys_t *ubphys;
	zio_t *zio;
	int l, c, n;
	char *buf;
	size_t buflen;
	int error;

	for (c = 0; c < vd->vdev_children; c++)
		if ((error = vdev_label_init(vd->vdev_child[c], crtxg)) != 0)
			return (error);

	if (!vd->vdev_ops->vdev_op_leaf)
		return (0);

	/*
	 * Make sure each leaf device is writable, and zero its initial content.
	 * Along the way, also make sure that no leaf is already in use.
	 * Note that it's important to do this sequentially, not in parallel,
	 * so that we catch cases of multiple use of the same leaf vdev in
	 * the vdev we're creating -- e.g. mirroring a disk with itself.
	 */
	if (vdev_is_dead(vd))
		return (EIO);

	/*
	 * Check whether this device is already in use.
	 * Ignore the check if crtxg == 0, which we use for device removal.
	 */
	if (crtxg != 0 && (label = vdev_label_read_config(vd)) != NULL) {
		uint64_t version, state, pool_guid, device_guid, txg;
		uint64_t mycrtxg = 0;

		(void) nvlist_lookup_uint64(label, ZPOOL_CONFIG_CREATE_TXG,
		    &mycrtxg);

		if (nvlist_lookup_uint64(label, ZPOOL_CONFIG_VERSION,
		    &version) == 0 && version == UBERBLOCK_VERSION &&
		    nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE,
		    &state) == 0 && state == POOL_STATE_ACTIVE &&
		    nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID,
		    &pool_guid) == 0 &&
		    nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID,
		    &device_guid) == 0 &&
		    spa_guid_exists(pool_guid, device_guid) &&
		    nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_TXG,
		    &txg) == 0 && (txg != 0 || mycrtxg == crtxg)) {
			dprintf("vdev %s in use, pool_state %d\n",
			    vdev_description(vd), state);
			nvlist_free(label);
			return (EBUSY);
		}
		nvlist_free(label);
	}

	/*
	 * The device isn't in use, so initialize its label.
	 */
	vp = zio_buf_alloc(sizeof (vdev_phys_t));
	bzero(vp, sizeof (vdev_phys_t));

	/*
	 * Generate a label describing the pool and our top-level vdev.
	 * We mark it as being from txg 0 to indicate that it's not
	 * really part of an active pool just yet.  The labels will
	 * be written again with a meaningful txg by spa_sync().
	 */
	label = spa_config_generate(spa, vd, 0ULL, 0);

	/*
	 * Add our creation time.  This allows us to detect multiple vdev
	 * uses as described above, and automatically expires if we fail.
	 */
	VERIFY(nvlist_add_uint64(label, ZPOOL_CONFIG_CREATE_TXG, crtxg) == 0);

	buf = vp->vp_nvlist;
	buflen = sizeof (vp->vp_nvlist);

	if (nvlist_pack(label, &buf, &buflen, NV_ENCODE_XDR, 0) != 0) {
		nvlist_free(label);
		zio_buf_free(vp, sizeof (vdev_phys_t));
		return (EINVAL);
	}

	/*
	 * Initialize boot block header.
	 */
	vb = zio_buf_alloc(sizeof (vdev_boot_header_t));
	bzero(vb, sizeof (vdev_boot_header_t));
	vb->vb_magic = VDEV_BOOT_MAGIC;
	vb->vb_version = VDEV_BOOT_VERSION;
	vb->vb_offset = VDEV_BOOT_OFFSET;
	vb->vb_size = VDEV_BOOT_SIZE;

	/*
	 * Initialize uberblock template.
	 */
	ubphys = zio_buf_alloc(sizeof (uberblock_phys_t));
	bzero(ubphys, sizeof (uberblock_phys_t));
	ubphys->ubp_uberblock = spa->spa_uberblock;
	ubphys->ubp_uberblock.ub_txg = 0;

	/*
	 * Write everything in parallel.
	 */
	zio = zio_root(spa, NULL, NULL,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);

	for (l = 0; l < VDEV_LABELS; l++) {

		vdev_label_write(zio, vd, l, vp,
		    offsetof(vdev_label_t, vl_vdev_phys),
		    sizeof (vdev_phys_t), NULL, NULL);

		vdev_label_write(zio, vd, l, vb,
		    offsetof(vdev_label_t, vl_boot_header),
		    sizeof (vdev_boot_header_t), NULL, NULL);

		for (n = 0; n < VDEV_UBERBLOCKS; n++) {

			vdev_label_write(zio, vd, l, ubphys,
			    offsetof(vdev_label_t, vl_uberblock[n]),
			    sizeof (uberblock_phys_t), NULL, NULL);

		}
	}

	error = zio_wait(zio);

	nvlist_free(label);
	zio_buf_free(ubphys, sizeof (uberblock_phys_t));
	zio_buf_free(vb, sizeof (vdev_boot_header_t));
	zio_buf_free(vp, sizeof (vdev_phys_t));

	return (error);
}

/*
 * ==========================================================================
 * uberblock load/sync
 * ==========================================================================
 */

/*
 * Consider the following situation: txg is safely synced to disk.  We've
 * written the first uberblock for txg + 1, and then we lose power.  When we
 * come back up, we fail to see the uberblock for txg + 1 because, say,
 * it was on a mirrored device and the replica to which we wrote txg + 1
 * is now offline.  If we then make some changes and sync txg + 1, and then
 * the missing replica comes back, then for a new seconds we'll have two
 * conflicting uberblocks on disk with the same txg.  The solution is simple:
 * among uberblocks with equal txg, choose the one with the latest timestamp.
 */
static int
vdev_uberblock_compare(uberblock_t *ub1, uberblock_t *ub2)
{
	if (ub1->ub_txg < ub2->ub_txg)
		return (-1);
	if (ub1->ub_txg > ub2->ub_txg)
		return (1);

	if (ub1->ub_timestamp < ub2->ub_timestamp)
		return (-1);
	if (ub1->ub_timestamp > ub2->ub_timestamp)
		return (1);

	return (0);
}

static void
vdev_uberblock_load_done(zio_t *zio)
{
	uberblock_phys_t *ubphys = zio->io_data;
	uberblock_t *ub = &ubphys->ubp_uberblock;
	uberblock_t *ubbest = zio->io_private;
	spa_t *spa = zio->io_spa;

	ASSERT3U(zio->io_size, ==, sizeof (uberblock_phys_t));

	if (uberblock_verify(ub) == 0) {
		mutex_enter(&spa->spa_uberblock_lock);
		if (vdev_uberblock_compare(ub, ubbest) > 0)
			*ubbest = *ub;
		mutex_exit(&spa->spa_uberblock_lock);
	}

	zio_buf_free(zio->io_data, zio->io_size);
}

void
vdev_uberblock_load(zio_t *zio, vdev_t *vd, uberblock_t *ubbest)
{
	int l, c, n;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_uberblock_load(zio, vd->vdev_child[c], ubbest);

	if (!vd->vdev_ops->vdev_op_leaf)
		return;

	if (vdev_is_dead(vd))
		return;

	for (l = 0; l < VDEV_LABELS; l++) {
		for (n = 0; n < VDEV_UBERBLOCKS; n++) {
			vdev_label_read(zio, vd, l,
			    zio_buf_alloc(sizeof (uberblock_phys_t)),
			    offsetof(vdev_label_t, vl_uberblock[n]),
			    sizeof (uberblock_phys_t),
			    vdev_uberblock_load_done, ubbest);
		}
	}
}

/*
 * Write the uberblock to both labels of all leaves of the specified vdev.
 */
static void
vdev_uberblock_sync_done(zio_t *zio)
{
	uint64_t *good_writes = zio->io_root->io_private;

	if (zio->io_error == 0)
		atomic_add_64(good_writes, 1);
}

static void
vdev_uberblock_sync(zio_t *zio, uberblock_phys_t *ubphys, vdev_t *vd,
	uint64_t txg)
{
	int l, c, n;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_uberblock_sync(zio, ubphys, vd->vdev_child[c], txg);

	if (!vd->vdev_ops->vdev_op_leaf)
		return;

	if (vdev_is_dead(vd))
		return;

	n = txg & (VDEV_UBERBLOCKS - 1);

	ASSERT(ubphys->ubp_uberblock.ub_txg == txg);

	for (l = 0; l < VDEV_LABELS; l++)
		vdev_label_write(zio, vd, l, ubphys,
		    offsetof(vdev_label_t, vl_uberblock[n]),
		    sizeof (uberblock_phys_t), vdev_uberblock_sync_done, NULL);

	dprintf("vdev %s in txg %llu\n", vdev_description(vd), txg);
}

static int
vdev_uberblock_sync_tree(spa_t *spa, uberblock_t *ub, vdev_t *uvd, uint64_t txg)
{
	uberblock_phys_t *ubphys;
	uint64_t *good_writes;
	zio_t *zio;
	int error;

	ubphys = zio_buf_alloc(sizeof (uberblock_phys_t));
	bzero(ubphys, sizeof (uberblock_phys_t));
	ubphys->ubp_uberblock = *ub;

	good_writes = kmem_zalloc(sizeof (uint64_t), KM_SLEEP);

	zio = zio_root(spa, NULL, good_writes,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);

	vdev_uberblock_sync(zio, ubphys, uvd, txg);

	error = zio_wait(zio);

	if (error && *good_writes != 0) {
		dprintf("partial success: good_writes = %llu\n", *good_writes);
		error = 0;
	}

	/*
	 * It's possible to have no good writes and no error if every vdev is in
	 * the CANT_OPEN state.
	 */
	if (*good_writes == 0 && error == 0)
		error = EIO;

	kmem_free(good_writes, sizeof (uint64_t));
	zio_buf_free(ubphys, sizeof (uberblock_phys_t));

	return (error);
}

/*
 * Sync out an individual vdev.
 */
static void
vdev_sync_label_done(zio_t *zio)
{
	uint64_t *good_writes = zio->io_root->io_private;

	if (zio->io_error == 0)
		atomic_add_64(good_writes, 1);
}

static void
vdev_sync_label(zio_t *zio, vdev_t *vd, int l, uint64_t txg)
{
	nvlist_t *label;
	vdev_phys_t *vp;
	char *buf;
	size_t buflen;
	int c;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_sync_label(zio, vd->vdev_child[c], l, txg);

	if (!vd->vdev_ops->vdev_op_leaf)
		return;

	if (vdev_is_dead(vd))
		return;

	/*
	 * Generate a label describing the top-level config to which we belong.
	 */
	label = spa_config_generate(vd->vdev_spa, vd, txg, 0);

	vp = zio_buf_alloc(sizeof (vdev_phys_t));
	bzero(vp, sizeof (vdev_phys_t));

	buf = vp->vp_nvlist;
	buflen = sizeof (vp->vp_nvlist);

	if (nvlist_pack(label, &buf, &buflen, NV_ENCODE_XDR, 0) == 0)
		vdev_label_write(zio, vd, l, vp,
		    offsetof(vdev_label_t, vl_vdev_phys), sizeof (vdev_phys_t),
		    vdev_sync_label_done, NULL);

	zio_buf_free(vp, sizeof (vdev_phys_t));
	nvlist_free(label);

	dprintf("%s label %d txg %llu\n", vdev_description(vd), l, txg);
}

static int
vdev_sync_labels(vdev_t *vd, int l, uint64_t txg)
{
	uint64_t *good_writes;
	zio_t *zio;
	int error;

	ASSERT(vd == vd->vdev_top);

	good_writes = kmem_zalloc(sizeof (uint64_t), KM_SLEEP);

	zio = zio_root(vd->vdev_spa, NULL, good_writes,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);

	/*
	 * Recursively kick off writes to all labels.
	 */
	vdev_sync_label(zio, vd, l, txg);

	error = zio_wait(zio);

	if (error && *good_writes != 0) {
		dprintf("partial success: good_writes = %llu\n", *good_writes);
		error = 0;
	}

	if (*good_writes == 0 && error == 0)
		error = ENODEV;

	kmem_free(good_writes, sizeof (uint64_t));

	return (error);
}

/*
 * Sync the entire vdev configuration.
 *
 * The order of operations is carefully crafted to ensure that
 * if the system panics or loses power at any time, the state on disk
 * is still transactionally consistent.  The in-line comments below
 * describe the failure semantics at each stage.
 *
 * Moreover, it is designed to be idempotent: if spa_sync_labels() fails
 * at any time, you can just call it again, and it will resume its work.
 */
int
spa_sync_labels(spa_t *spa, uint64_t txg)
{
	uberblock_t *ub = &spa->spa_uberblock;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd, *uvd;
	zio_t *zio;
	int c, l, error;

	ASSERT(ub->ub_txg <= txg);

	/*
	 * If this isn't a resync due to I/O errors, and nothing changed
	 * in this transaction group, and the vdev configuration hasn't changed,
	 * and this isn't an explicit sync-all, then there's nothing to do.
	 */
	if (ub->ub_txg < txg && uberblock_update(ub, rvd, txg) == B_FALSE &&
	    list_is_empty(&spa->spa_dirty_list)) {
		dprintf("nothing to sync in %s in txg %llu\n",
		    spa_name(spa), txg);
		return (0);
	}

	if (txg > spa_freeze_txg(spa))
		return (0);

	dprintf("syncing %s txg %llu\n", spa_name(spa), txg);

	/*
	 * Flush the write cache of every disk that's been written to
	 * in this transaction group.  This ensures that all blocks
	 * written in this txg will be committed to stable storage
	 * before any uberblock that references them.
	 */
	zio = zio_root(spa, NULL, NULL,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);
	for (vd = txg_list_head(&spa->spa_vdev_txg_list, TXG_CLEAN(txg)); vd;
	    vd = txg_list_next(&spa->spa_vdev_txg_list, vd, TXG_CLEAN(txg))) {
		zio_nowait(zio_ioctl(zio, spa, vd, DKIOCFLUSHWRITECACHE,
		    NULL, NULL, ZIO_PRIORITY_NOW,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY));
	}
	(void) zio_wait(zio);

	/*
	 * Sync out the even labels (L0, L2) for every dirty vdev.  If the
	 * system dies in the middle of this process, that's OK: all of the
	 * even labels that made it to disk will be newer than any uberblock,
	 * and will therefore be considered invalid.  The odd labels (L1, L3),
	 * which have not yet been touched, will still be valid.
	 */
	for (vd = list_head(&spa->spa_dirty_list); vd != NULL;
	    vd = list_next(&spa->spa_dirty_list, vd)) {
		for (l = 0; l < VDEV_LABELS; l++) {
			if (l & 1)
				continue;
			if ((error = vdev_sync_labels(vd, l, txg)) != 0)
				return (error);
		}
	}

	/*
	 * Flush the new labels to disk.  This ensures that all even-label
	 * updates are committed to stable storage before the uberblock update.
	 */
	zio = zio_root(spa, NULL, NULL,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);
	for (vd = list_head(&spa->spa_dirty_list); vd != NULL;
	    vd = list_next(&spa->spa_dirty_list, vd)) {
		zio_nowait(zio_ioctl(zio, spa, vd, DKIOCFLUSHWRITECACHE,
		    NULL, NULL, ZIO_PRIORITY_NOW,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY));
	}
	(void) zio_wait(zio);

	/*
	 * If there are any dirty vdevs, sync the uberblock to all vdevs.
	 * Otherwise, pick one top-level vdev at random.
	 */
	if (!list_is_empty(&spa->spa_dirty_list))
		uvd = rvd;
	else
		uvd = rvd->vdev_child[spa_get_random(rvd->vdev_children)];

	/*
	 * Sync the uberblocks.  If the system dies in the middle of this
	 * step, there are two cases to consider, and the on-disk state
	 * is consistent either way:
	 *
	 * (1)	If none of the new uberblocks made it to disk, then the
	 *	previous uberblock will be the newest, and the odd labels
	 *	(which had not yet been touched) will be valid with respect
	 *	to that uberblock.
	 *
	 * (2)	If one or more new uberblocks made it to disk, then they
	 *	will be the newest, and the even labels (which had all
	 *	been successfully committed) will be valid with respect
	 *	to the new uberblocks.
	 */
	if ((error = vdev_uberblock_sync_tree(spa, ub, uvd, txg)) != 0)
		return (error);

	/*
	 * Flush the uberblocks to disk.  This ensures that the odd labels
	 * are no longer needed (because the new uberblocks and the even
	 * labels are safely on disk), so it is safe to overwrite them.
	 */
	(void) zio_wait(zio_ioctl(NULL, spa, uvd, DKIOCFLUSHWRITECACHE,
	    NULL, NULL, ZIO_PRIORITY_NOW,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY));

	/*
	 * Sync out odd labels for every dirty vdev.  If the system dies
	 * in the middle of this process, the even labels and the new
	 * uberblocks will suffice to open the pool.  The next time
	 * the pool is opened, the first thing we'll do -- before any
	 * user data is modified -- is mark every vdev dirty so that
	 * all labels will be brought up to date.
	 */
	for (vd = list_head(&spa->spa_dirty_list); vd != NULL;
	    vd = list_next(&spa->spa_dirty_list, vd)) {
		for (l = 0; l < VDEV_LABELS; l++) {
			if ((l & 1) == 0)
				continue;
			if ((error = vdev_sync_labels(vd, l, txg)) != 0)
				return (error);
		}
	}

	/*
	 * Flush the new labels to disk.  This ensures that all odd-label
	 * updates are committed to stable storage before the next
	 * transaction group begins.
	 */
	zio = zio_root(spa, NULL, NULL,
	    ZIO_FLAG_CONFIG_HELD | ZIO_FLAG_CANFAIL);
	for (vd = list_head(&spa->spa_dirty_list); vd != NULL;
	    vd = list_next(&spa->spa_dirty_list, vd)) {
		zio_nowait(zio_ioctl(zio, spa, vd, DKIOCFLUSHWRITECACHE,
		    NULL, NULL, ZIO_PRIORITY_NOW,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY));
	}
	(void) zio_wait(zio);

	/*
	 * Clear the dirty list.
	 */
	while (!list_is_empty(&spa->spa_dirty_list))
		vdev_config_clean(list_head(&spa->spa_dirty_list));

#ifdef DEBUG
	for (c = 0; c < rvd->vdev_children; c++) {
		ASSERT(rvd->vdev_child[c]->vdev_is_dirty == 0);
	}
#endif

	return (0);
}
