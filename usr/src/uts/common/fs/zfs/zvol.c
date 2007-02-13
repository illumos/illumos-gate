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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ZFS volume emulation driver.
 *
 * Makes a DMU object look like a volume of arbitrary size, up to 2^64 bytes.
 * Volumes are accessed through the symbolic links named:
 *
 * /dev/zvol/dsk/<pool_name>/<dataset_name>
 * /dev/zvol/rdsk/<pool_name>/<dataset_name>
 *
 * These links are created by the ZFS-specific devfsadm link generator.
 * Volumes are persistent through reboot.  No user command needs to be
 * run before opening and using a device.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dsl_prop.h>
#include <sys/dkio.h>
#include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/crc32.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/mkdev.h>
#include <sys/zil.h>
#include <sys/refcount.h>

#include "zfs_namecheck.h"

#define	ZVOL_OBJ		1ULL
#define	ZVOL_ZAP_OBJ		2ULL

static void *zvol_state;

/*
 * This lock protects the zvol_state structure from being modified
 * while it's being used, e.g. an open that comes in before a create
 * finishes.  It also protects temporary opens of the dataset so that,
 * e.g., an open doesn't get a spurious EBUSY.
 */
static kmutex_t zvol_state_lock;
static uint32_t zvol_minors;

/*
 * The in-core state of each volume.
 */
typedef struct zvol_state {
	char		zv_name[MAXPATHLEN]; /* pool/dd name */
	uint64_t	zv_volsize;	/* amount of space we advertise */
	uint64_t	zv_volblocksize; /* volume block size */
	minor_t		zv_minor;	/* minor number */
	uint8_t		zv_min_bs;	/* minimum addressable block shift */
	uint8_t		zv_readonly;	/* hard readonly; like write-protect */
	objset_t	*zv_objset;	/* objset handle */
	uint32_t	zv_mode;	/* DS_MODE_* flags at open time */
	uint32_t	zv_open_count[OTYPCNT];	/* open counts */
	uint32_t	zv_total_opens;	/* total open count */
	zilog_t		*zv_zilog;	/* ZIL handle */
	uint64_t	zv_txg_assign;	/* txg to assign during ZIL replay */
	krwlock_t	zv_dslock;	/* dmu_sync() rwlock */
} zvol_state_t;

/*
 * zvol maximum transfer in one DMU tx.
 */
int zvol_maxphys = DMU_MAX_ACCESS/2;

static int zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio);

static void
zvol_size_changed(zvol_state_t *zv, dev_t dev)
{
	dev = makedevice(getmajor(dev), zv->zv_minor);

	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Size", zv->zv_volsize) == DDI_SUCCESS);
	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Nblocks", lbtodb(zv->zv_volsize)) == DDI_SUCCESS);
}

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (EINVAL);

	if (volsize % blocksize != 0)
		return (EINVAL);

#ifdef _ILP32
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (EOVERFLOW);
#endif
	return (0);
}

int
zvol_check_volblocksize(uint64_t volblocksize)
{
	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (EDOM);

	return (0);
}

static void
zvol_readonly_changed_cb(void *arg, uint64_t newval)
{
	zvol_state_t *zv = arg;

	zv->zv_readonly = (uint8_t)newval;
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t doi;
	uint64_t val;


	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (error);

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);

	error = dmu_object_info(os, ZVOL_OBJ, &doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi.doi_data_block_size);
	}

	return (error);
}

/*
 * Find a free minor number.
 */
static minor_t
zvol_minor_alloc(void)
{
	minor_t minor;

	ASSERT(MUTEX_HELD(&zvol_state_lock));

	for (minor = 1; minor <= ZVOL_MAX_MINOR; minor++)
		if (ddi_get_soft_state(zvol_state, minor) == NULL)
			return (minor);

	return (0);
}

static zvol_state_t *
zvol_minor_lookup(const char *name)
{
	minor_t minor;
	zvol_state_t *zv;

	ASSERT(MUTEX_HELD(&zvol_state_lock));

	for (minor = 1; minor <= ZVOL_MAX_MINOR; minor++) {
		zv = ddi_get_soft_state(zvol_state, minor);
		if (zv == NULL)
			continue;
		if (strcmp(zv->zv_name, name) == 0)
			break;
	}

	return (zv);
}

void
zvol_create_cb(objset_t *os, void *arg, dmu_tx_t *tx)
{
	zfs_create_data_t *zc = arg;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(zc->zc_props,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE), &volsize) == 0);
	if (nvlist_lookup_uint64(zc->zc_props,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properites must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(zc->zc_props,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(zc->zc_props,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);
}

/*
 * Replay a TX_WRITE ZIL transaction that didn't get committed
 * after a system failure
 */
static int
zvol_replay_write(zvol_state_t *zv, lr_write_t *lr, boolean_t byteswap)
{
	objset_t *os = zv->zv_objset;
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	uint64_t off = lr->lr_offset;
	uint64_t len = lr->lr_length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	tx = dmu_tx_create(os);
	dmu_tx_hold_write(tx, ZVOL_OBJ, off, len);
	error = dmu_tx_assign(tx, zv->zv_txg_assign);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		dmu_write(os, ZVOL_OBJ, off, len, data, tx);
		dmu_tx_commit(tx);
	}

	return (error);
}

/* ARGSUSED */
static int
zvol_replay_err(zvol_state_t *zv, lr_t *lr, boolean_t byteswap)
{
	return (ENOTSUP);
}

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE is needed for zvol.
 */
zil_replay_func_t *zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,	/* 0 no such transaction type */
	zvol_replay_err,	/* TX_CREATE */
	zvol_replay_err,	/* TX_MKDIR */
	zvol_replay_err,	/* TX_MKXATTR */
	zvol_replay_err,	/* TX_SYMLINK */
	zvol_replay_err,	/* TX_REMOVE */
	zvol_replay_err,	/* TX_RMDIR */
	zvol_replay_err,	/* TX_LINK */
	zvol_replay_err,	/* TX_RENAME */
	zvol_replay_write,	/* TX_WRITE */
	zvol_replay_err,	/* TX_TRUNCATE */
	zvol_replay_err,	/* TX_SETATTR */
	zvol_replay_err,	/* TX_ACL */
};

/*
 * Create a minor node for the specified volume.
 */
int
zvol_create_minor(const char *name, dev_t dev)
{
	zvol_state_t *zv;
	objset_t *os;
	dmu_object_info_t doi;
	uint64_t volsize;
	minor_t minor = 0;
	struct pathname linkpath;
	int ds_mode = DS_MODE_PRIMARY;
	vnode_t *vp = NULL;
	char *devpath;
	size_t devpathlen = strlen(ZVOL_FULL_DEV_DIR) + 1 + strlen(name) + 1;
	char chrbuf[30], blkbuf[30];
	int error;

	mutex_enter(&zvol_state_lock);

	if ((zv = zvol_minor_lookup(name)) != NULL) {
		mutex_exit(&zvol_state_lock);
		return (EEXIST);
	}

	if (strchr(name, '@') != 0)
		ds_mode |= DS_MODE_READONLY;

	error = dmu_objset_open(name, DMU_OST_ZVOL, ds_mode, &os);

	if (error) {
		mutex_exit(&zvol_state_lock);
		return (error);
	}

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);

	if (error) {
		dmu_objset_close(os);
		mutex_exit(&zvol_state_lock);
		return (error);
	}

	/*
	 * If there's an existing /dev/zvol symlink, try to use the
	 * same minor number we used last time.
	 */
	devpath = kmem_alloc(devpathlen, KM_SLEEP);

	(void) sprintf(devpath, "%s/%s", ZVOL_FULL_DEV_DIR, name);

	error = lookupname(devpath, UIO_SYSSPACE, NO_FOLLOW, NULL, &vp);

	kmem_free(devpath, devpathlen);

	if (error == 0 && vp->v_type != VLNK)
		error = EINVAL;

	if (error == 0) {
		pn_alloc(&linkpath);
		error = pn_getsymlink(vp, &linkpath, kcred);
		if (error == 0) {
			char *ms = strstr(linkpath.pn_path, ZVOL_PSEUDO_DEV);
			if (ms != NULL) {
				ms += strlen(ZVOL_PSEUDO_DEV);
				minor = stoi(&ms);
			}
		}
		pn_free(&linkpath);
	}

	if (vp != NULL)
		VN_RELE(vp);

	/*
	 * If we found a minor but it's already in use, we must pick a new one.
	 */
	if (minor != 0 && ddi_get_soft_state(zvol_state, minor) != NULL)
		minor = 0;

	if (minor == 0)
		minor = zvol_minor_alloc();

	if (minor == 0) {
		dmu_objset_close(os);
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	if (ddi_soft_state_zalloc(zvol_state, minor) != DDI_SUCCESS) {
		dmu_objset_close(os);
		mutex_exit(&zvol_state_lock);
		return (EAGAIN);
	}

	(void) ddi_prop_update_string(minor, zfs_dip, ZVOL_PROP_NAME,
	    (char *)name);

	(void) sprintf(chrbuf, "%uc,raw", minor);

	if (ddi_create_minor_node(zfs_dip, chrbuf, S_IFCHR,
	    minor, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_soft_state_free(zvol_state, minor);
		dmu_objset_close(os);
		mutex_exit(&zvol_state_lock);
		return (EAGAIN);
	}

	(void) sprintf(blkbuf, "%uc", minor);

	if (ddi_create_minor_node(zfs_dip, blkbuf, S_IFBLK,
	    minor, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(zfs_dip, chrbuf);
		ddi_soft_state_free(zvol_state, minor);
		dmu_objset_close(os);
		mutex_exit(&zvol_state_lock);
		return (EAGAIN);
	}

	zv = ddi_get_soft_state(zvol_state, minor);

	(void) strcpy(zv->zv_name, name);
	zv->zv_min_bs = DEV_BSHIFT;
	zv->zv_minor = minor;
	zv->zv_volsize = volsize;
	zv->zv_objset = os;
	zv->zv_mode = ds_mode;
	zv->zv_zilog = zil_open(os, zvol_get_data);

	/* get and cache the blocksize */
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	ASSERT(error == 0);
	zv->zv_volblocksize = doi.doi_data_block_size;

	rw_init(&zv->zv_dslock, NULL, RW_DEFAULT, NULL);

	zil_replay(os, zv, &zv->zv_txg_assign, zvol_replay_vector);

	zvol_size_changed(zv, dev);

	/* XXX this should handle the possible i/o error */
	VERIFY(dsl_prop_register(dmu_objset_ds(zv->zv_objset),
	    "readonly", zvol_readonly_changed_cb, zv) == 0);

	zvol_minors++;

	mutex_exit(&zvol_state_lock);

	return (0);
}

/*
 * Remove minor node for the specified volume.
 */
int
zvol_remove_minor(const char *name)
{
	zvol_state_t *zv;
	char namebuf[30];

	mutex_enter(&zvol_state_lock);

	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	if (zv->zv_total_opens != 0) {
		mutex_exit(&zvol_state_lock);
		return (EBUSY);
	}

	(void) sprintf(namebuf, "%uc,raw", zv->zv_minor);
	ddi_remove_minor_node(zfs_dip, namebuf);

	(void) sprintf(namebuf, "%uc", zv->zv_minor);
	ddi_remove_minor_node(zfs_dip, namebuf);

	VERIFY(dsl_prop_unregister(dmu_objset_ds(zv->zv_objset),
	    "readonly", zvol_readonly_changed_cb, zv) == 0);

	zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;
	dmu_objset_close(zv->zv_objset);
	zv->zv_objset = NULL;

	ddi_soft_state_free(zvol_state, zv->zv_minor);

	zvol_minors--;

	mutex_exit(&zvol_state_lock);

	return (0);
}

int
zvol_set_volsize(const char *name, dev_t dev, uint64_t volsize)
{
	zvol_state_t *zv;
	dmu_tx_t *tx;
	int error;
	dmu_object_info_t doi;

	mutex_enter(&zvol_state_lock);

	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	if ((error = dmu_object_info(zv->zv_objset, ZVOL_OBJ, &doi)) != 0 ||
	    (error = zvol_check_volsize(volsize,
	    doi.doi_data_block_size)) != 0) {
		mutex_exit(&zvol_state_lock);
		return (error);
	}

	if (zv->zv_readonly || (zv->zv_mode & DS_MODE_READONLY)) {
		mutex_exit(&zvol_state_lock);
		return (EROFS);
	}

	tx = dmu_tx_create(zv->zv_objset);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_hold_free(tx, ZVOL_OBJ, volsize, DMU_OBJECT_END);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		mutex_exit(&zvol_state_lock);
		return (error);
	}

	error = zap_update(zv->zv_objset, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &volsize, tx);
	if (error == 0) {
		error = dmu_free_range(zv->zv_objset, ZVOL_OBJ, volsize,
		    DMU_OBJECT_END, tx);
	}

	dmu_tx_commit(tx);

	if (error == 0) {
		zv->zv_volsize = volsize;
		zvol_size_changed(zv, dev);
	}

	mutex_exit(&zvol_state_lock);

	return (error);
}

int
zvol_set_volblocksize(const char *name, uint64_t volblocksize)
{
	zvol_state_t *zv;
	dmu_tx_t *tx;
	int error;

	mutex_enter(&zvol_state_lock);

	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	if (zv->zv_readonly || (zv->zv_mode & DS_MODE_READONLY)) {
		mutex_exit(&zvol_state_lock);
		return (EROFS);
	}

	tx = dmu_tx_create(zv->zv_objset);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		error = dmu_object_set_blocksize(zv->zv_objset, ZVOL_OBJ,
		    volblocksize, 0, tx);
		if (error == ENOTSUP)
			error = EBUSY;
		dmu_tx_commit(tx);
	}

	mutex_exit(&zvol_state_lock);

	return (error);
}

/*ARGSUSED*/
int
zvol_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	minor_t minor = getminor(*devp);
	zvol_state_t *zv;

	if (minor == 0)			/* This is the control device */
		return (0);

	mutex_enter(&zvol_state_lock);

	zv = ddi_get_soft_state(zvol_state, minor);
	if (zv == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	ASSERT(zv->zv_objset != NULL);

	if ((flag & FWRITE) &&
	    (zv->zv_readonly || (zv->zv_mode & DS_MODE_READONLY))) {
		mutex_exit(&zvol_state_lock);
		return (EROFS);
	}

	if (zv->zv_open_count[otyp] == 0 || otyp == OTYP_LYR) {
		zv->zv_open_count[otyp]++;
		zv->zv_total_opens++;
	}

	mutex_exit(&zvol_state_lock);

	return (0);
}

/*ARGSUSED*/
int
zvol_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;

	if (minor == 0)		/* This is the control device */
		return (0);

	mutex_enter(&zvol_state_lock);

	zv = ddi_get_soft_state(zvol_state, minor);
	if (zv == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	/*
	 * The next statement is a workaround for the following DDI bug:
	 * 6343604 specfs race: multiple "last-close" of the same device
	 */
	if (zv->zv_total_opens == 0) {
		mutex_exit(&zvol_state_lock);
		return (0);
	}

	/*
	 * If the open count is zero, this is a spurious close.
	 * That indicates a bug in the kernel / DDI framework.
	 */
	ASSERT(zv->zv_open_count[otyp] != 0);
	ASSERT(zv->zv_total_opens != 0);

	/*
	 * You may get multiple opens, but only one close.
	 */
	zv->zv_open_count[otyp]--;
	zv->zv_total_opens--;

	mutex_exit(&zvol_state_lock);

	return (0);
}

static void
zvol_get_done(dmu_buf_t *db, void *vzgd)
{
	zgd_t *zgd = (zgd_t *)vzgd;

	dmu_buf_rele(db, vzgd);
	zil_add_vdev(zgd->zgd_zilog, DVA_GET_VDEV(BP_IDENTITY(zgd->zgd_bp)));
	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
static int
zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zvol_state_t *zv = arg;
	objset_t *os = zv->zv_objset;
	dmu_buf_t *db;
	zgd_t *zgd;
	int error;

	ASSERT(zio);
	ASSERT(lr->lr_length != 0);

	if (buf != NULL)
		return (dmu_read(os, ZVOL_OBJ,
		    lr->lr_offset, lr->lr_length, buf));

	zgd = (zgd_t *)kmem_alloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_zilog = zv->zv_zilog;
	zgd->zgd_bp = &lr->lr_blkptr;

	VERIFY(0 == dmu_buf_hold(os, ZVOL_OBJ, lr->lr_offset, zgd, &db));
	/*
	 * Have to lock to ensure when when the data is
	 * written out and it's checksum is being calculated
	 * that no one can change the data.
	 */
	rw_enter(&zv->zv_dslock, RW_READER);
	error = dmu_sync(zio, db, &lr->lr_blkptr,
	    lr->lr_common.lrc_txg, zvol_get_done, zgd);
	rw_exit(&zv->zv_dslock);
	if (error == 0)
		zil_add_vdev(zv->zv_zilog,
		    DVA_GET_VDEV(BP_IDENTITY(&lr->lr_blkptr)));
	/*
	 * If we get EINPROGRESS, then we need to wait for a
	 * write IO initiated by dmu_sync() to complete before
	 * we can release this dbuf.  We will finish everything
	 * up in the zvol_get_done() callback.
	 */
	if (error == EINPROGRESS)
		return (0);
	dmu_buf_rele(db, zgd);
	kmem_free(zgd, sizeof (zgd_t));
	return (error);
}

/*
 * zvol_log_write() handles synchronous writes using TX_WRITE ZIL transactions.
 *
 * We store data in the log buffers if it's small enough.
 * Otherwise we will later flush the data out via dmu_sync().
 */
ssize_t zvol_immediate_write_sz = 32768;

static void
zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, offset_t off, ssize_t len)
{
	uint32_t blocksize = zv->zv_volblocksize;
	lr_write_t *lr;

	while (len) {
		ssize_t nbytes = MIN(len, blocksize - P2PHASE(off, blocksize));
		itx_t *itx = zil_itx_create(TX_WRITE, sizeof (*lr));

		itx->itx_wr_state =
		    len > zvol_immediate_write_sz ?  WR_INDIRECT : WR_NEED_COPY;
		itx->itx_private = zv;
		lr = (lr_write_t *)&itx->itx_lr;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = off;
		lr->lr_length = nbytes;
		lr->lr_blkoff = off - P2ALIGN_TYPED(off, blocksize, uint64_t);
		BP_ZERO(&lr->lr_blkptr);

		(void) zil_itx_assign(zv->zv_zilog, itx, tx);
		len -= nbytes;
		off += nbytes;
	}
}

int
zvol_strategy(buf_t *bp)
{
	zvol_state_t *zv = ddi_get_soft_state(zvol_state, getminor(bp->b_edev));
	uint64_t off, volsize;
	size_t size, resid;
	char *addr;
	objset_t *os;
	int error = 0;
	int sync;
	int reading;

	if (zv == NULL) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	if (getminor(bp->b_edev) == 0) {
		bioerror(bp, EINVAL);
		biodone(bp);
		return (0);
	}

	if ((zv->zv_readonly || (zv->zv_mode & DS_MODE_READONLY)) &&
	    !(bp->b_flags & B_READ)) {
		bioerror(bp, EROFS);
		biodone(bp);
		return (0);
	}

	off = ldbtob(bp->b_blkno);
	volsize = zv->zv_volsize;

	os = zv->zv_objset;
	ASSERT(os != NULL);
	sync = !(bp->b_flags & B_ASYNC) && !(zil_disable);

	bp_mapin(bp);
	addr = bp->b_un.b_addr;
	resid = bp->b_bcount;

	/*
	 * There must be no buffer changes when doing a dmu_sync() because
	 * we can't change the data whilst calculating the checksum.
	 * A better approach than a per zvol rwlock would be to lock ranges.
	 */
	reading = bp->b_flags & B_READ;
	if (reading || resid <= zvol_immediate_write_sz)
		rw_enter(&zv->zv_dslock, RW_READER);
	else
		rw_enter(&zv->zv_dslock, RW_WRITER);

	while (resid != 0 && off < volsize) {

		size = MIN(resid, zvol_maxphys); /* zvol_maxphys per tx */

		if (size > volsize - off)	/* don't write past the end */
			size = volsize - off;

		if (reading) {
			error = dmu_read(os, ZVOL_OBJ, off, size, addr);
		} else {
			dmu_tx_t *tx = dmu_tx_create(os);
			dmu_tx_hold_write(tx, ZVOL_OBJ, off, size);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
			} else {
				dmu_write(os, ZVOL_OBJ, off, size, addr, tx);
				zvol_log_write(zv, tx, off, size);
				dmu_tx_commit(tx);
			}
		}
		if (error)
			break;
		off += size;
		addr += size;
		resid -= size;
	}
	rw_exit(&zv->zv_dslock);

	if ((bp->b_resid = resid) == bp->b_bcount)
		bioerror(bp, off > volsize ? EINVAL : error);

	if (sync)
		zil_commit(zv->zv_zilog, UINT64_MAX, ZVOL_OBJ);

	biodone(bp);

	return (0);
}

/*
 * Set the buffer count to the zvol maximum transfer.
 * Using our own routine instead of the default minphys()
 * means that for larger writes we write bigger buffers on X86
 * (128K instead of 56K) and flush the disk write cache less often
 * (every zvol_maxphys - currently 1MB) instead of minphys (currently
 * 56K on X86 and 128K on sparc).
 */
void
zvol_minphys(struct buf *bp)
{
	if (bp->b_bcount > zvol_maxphys)
		bp->b_bcount = zvol_maxphys;
}

/*ARGSUSED*/
int
zvol_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	zvol_state_t *zv = ddi_get_soft_state(zvol_state, getminor(dev));
	int error = 0;

	while (uio->uio_resid > 0) {
		uint64_t bytes = MIN(uio->uio_resid, DMU_MAX_ACCESS >> 1);

		error =  dmu_read_uio(zv->zv_objset, ZVOL_OBJ, uio, bytes);
		if (error)
			break;
	}
	return (error);
}

/*ARGSUSED*/
int
zvol_write(dev_t dev, uio_t *uio, cred_t *cr)
{
	zvol_state_t *zv = ddi_get_soft_state(zvol_state, getminor(dev));
	int error = 0;

	while (uio->uio_resid > 0) {
		uint64_t bytes = MIN(uio->uio_resid, DMU_MAX_ACCESS >> 1);
		uint64_t off = uio->uio_loffset;

		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);
		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio(zv->zv_objset, ZVOL_OBJ, uio, bytes, tx);
		if (error == 0)
			zvol_log_write(zv, tx, off, bytes);
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	return (error);
}

/*
 * Dirtbag ioctls to support mkfs(1M) for UFS filesystems.  See dkio(7I).
 */
/*ARGSUSED*/
int
zvol_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp)
{
	zvol_state_t *zv;
	struct dk_cinfo dkc;
	struct dk_minfo dkm;
	dk_efi_t efi;
	struct uuid uuid = EFI_RESERVED;
	uint32_t crc;
	int error = 0;

	mutex_enter(&zvol_state_lock);

	zv = ddi_get_soft_state(zvol_state, getminor(dev));

	if (zv == NULL) {
		mutex_exit(&zvol_state_lock);
		return (ENXIO);
	}

	switch (cmd) {

	case DKIOCINFO:
		bzero(&dkc, sizeof (dkc));
		(void) strcpy(dkc.dki_cname, "zvol");
		(void) strcpy(dkc.dki_dname, "zvol");
		dkc.dki_ctype = DKC_UNKNOWN;
		dkc.dki_maxtransfer = 1 << (SPA_MAXBLOCKSHIFT - zv->zv_min_bs);
		mutex_exit(&zvol_state_lock);
		if (ddi_copyout(&dkc, (void *)arg, sizeof (dkc), flag))
			error = EFAULT;
		return (error);

	case DKIOCGMEDIAINFO:
		bzero(&dkm, sizeof (dkm));
		dkm.dki_lbsize = 1U << zv->zv_min_bs;
		dkm.dki_capacity = zv->zv_volsize >> zv->zv_min_bs;
		dkm.dki_media_type = DK_UNKNOWN;
		mutex_exit(&zvol_state_lock);
		if (ddi_copyout(&dkm, (void *)arg, sizeof (dkm), flag))
			error = EFAULT;
		return (error);

	case DKIOCGETEFI:
		if (ddi_copyin((void *)arg, &efi, sizeof (dk_efi_t), flag)) {
			mutex_exit(&zvol_state_lock);
			return (EFAULT);
		}
		efi.dki_data = (void *)(uintptr_t)efi.dki_data_64;

		/*
		 * Some clients may attempt to request a PMBR for the
		 * zvol.  Currently this interface will return ENOTTY to
		 * such requests.  These requests could be supported by
		 * adding a check for lba == 0 and consing up an appropriate
		 * RMBR.
		 */
		if (efi.dki_lba == 1) {
			efi_gpt_t gpt;
			efi_gpe_t gpe;

			bzero(&gpt, sizeof (gpt));
			bzero(&gpe, sizeof (gpe));

			if (efi.dki_length < sizeof (gpt)) {
				mutex_exit(&zvol_state_lock);
				return (EINVAL);
			}

			gpt.efi_gpt_Signature = LE_64(EFI_SIGNATURE);
			gpt.efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);
			gpt.efi_gpt_HeaderSize = LE_32(sizeof (gpt));
			gpt.efi_gpt_FirstUsableLBA = LE_64(34ULL);
			gpt.efi_gpt_LastUsableLBA =
			    LE_64((zv->zv_volsize >> zv->zv_min_bs) - 1);
			gpt.efi_gpt_NumberOfPartitionEntries = LE_32(1);
			gpt.efi_gpt_PartitionEntryLBA = LE_64(2ULL);
			gpt.efi_gpt_SizeOfPartitionEntry = LE_32(sizeof (gpe));

			UUID_LE_CONVERT(gpe.efi_gpe_PartitionTypeGUID, uuid);
			gpe.efi_gpe_StartingLBA = gpt.efi_gpt_FirstUsableLBA;
			gpe.efi_gpe_EndingLBA = gpt.efi_gpt_LastUsableLBA;

			CRC32(crc, &gpe, sizeof (gpe), -1U, crc32_table);
			gpt.efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);

			CRC32(crc, &gpt, sizeof (gpt), -1U, crc32_table);
			gpt.efi_gpt_HeaderCRC32 = LE_32(~crc);

			mutex_exit(&zvol_state_lock);
			if (ddi_copyout(&gpt, efi.dki_data, sizeof (gpt), flag))
				error = EFAULT;
		} else if (efi.dki_lba == 2) {
			efi_gpe_t gpe;

			bzero(&gpe, sizeof (gpe));

			if (efi.dki_length < sizeof (gpe)) {
				mutex_exit(&zvol_state_lock);
				return (EINVAL);
			}

			UUID_LE_CONVERT(gpe.efi_gpe_PartitionTypeGUID, uuid);
			gpe.efi_gpe_StartingLBA = LE_64(34ULL);
			gpe.efi_gpe_EndingLBA =
			    LE_64((zv->zv_volsize >> zv->zv_min_bs) - 1);

			mutex_exit(&zvol_state_lock);
			if (ddi_copyout(&gpe, efi.dki_data, sizeof (gpe), flag))
				error = EFAULT;
		} else {
			mutex_exit(&zvol_state_lock);
			error = EINVAL;
		}
		return (error);

	case DKIOCFLUSHWRITECACHE:
		zil_commit(zv->zv_zilog, UINT64_MAX, ZVOL_OBJ);
		break;

	case DKIOCGGEOM:
	case DKIOCGVTOC:
		/* commands using these (like prtvtoc) expect ENOTSUP */
		error = ENOTSUP;
		break;

	default:
		error = ENOTTY;
		break;

	}
	mutex_exit(&zvol_state_lock);
	return (error);
}

int
zvol_busy(void)
{
	return (zvol_minors != 0);
}

void
zvol_init(void)
{
	VERIFY(ddi_soft_state_init(&zvol_state, sizeof (zvol_state_t), 1) == 0);
	mutex_init(&zvol_state_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
zvol_fini(void)
{
	mutex_destroy(&zvol_state_lock);
	ddi_soft_state_fini(&zvol_state);
}
