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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2016 Andrey Sokolov
 */

/*
 * lofi (loopback file) driver - allows you to attach a file to a device,
 * which can then be accessed through that device. The simple model is that
 * you tell lofi to open a file, and then use the block device you get as
 * you would any block device. lofi translates access to the block device
 * into I/O on the underlying file. This is mostly useful for
 * mounting images of filesystems.
 *
 * lofi is controlled through /dev/lofictl - this is the only device exported
 * during attach, and is minor number 0. lofiadm communicates with lofi through
 * ioctls on this device. When a file is attached to lofi, block and character
 * devices are exported in /dev/lofi and /dev/rlofi. Currently, these devices
 * are identified by their minor number, and the minor number is also used
 * as the name in /dev/lofi. If we ever decide to support virtual disks,
 * we'll have to divide the minor number space to identify fdisk partitions
 * and slices, and the name will then be the minor number shifted down a
 * few bits. Minor devices are tracked with state structures handled with
 * ddi_soft_state(9F) for simplicity.
 *
 * A file attached to lofi is opened when attached and not closed until
 * explicitly detached from lofi. This seems more sensible than deferring
 * the open until the /dev/lofi device is opened, for a number of reasons.
 * One is that any failure is likely to be noticed by the person (or script)
 * running lofiadm. Another is that it would be a security problem if the
 * file was replaced by another one after being added but before being opened.
 *
 * The only hard part about lofi is the ioctls. In order to support things
 * like 'newfs' on a lofi device, it needs to support certain disk ioctls.
 * So it has to fake disk geometry and partition information. More may need
 * to be faked if your favorite utility doesn't work and you think it should
 * (fdformat doesn't work because it really wants to know the type of floppy
 * controller to talk to, and that didn't seem easy to fake. Or possibly even
 * necessary, since we have mkfs_pcfs now).
 *
 * Normally, a lofi device cannot be detached if it is open (i.e. busy).  To
 * support simulation of hotplug events, an optional force flag is provided.
 * If a lofi device is open when a force detach is requested, then the
 * underlying file is closed and any subsequent operations return EIO.  When the
 * device is closed for the last time, it will be cleaned up at that time.  In
 * addition, the DKIOCSTATE ioctl will return DKIO_DEV_GONE when the device is
 * detached but not removed.
 *
 * Known problems:
 *
 *	UFS logging. Mounting a UFS filesystem image "logging"
 *	works for basic copy testing but wedges during a build of ON through
 *	that image. Some deadlock in lufs holding the log mutex and then
 *	getting stuck on a buf. So for now, don't do that.
 *
 *	Direct I/O. Since the filesystem data is being cached in the buffer
 *	cache, _and_ again in the underlying filesystem, it's tempting to
 *	enable direct I/O on the underlying file. Don't, because that deadlocks.
 *	I think to fix the cache-twice problem we might need filesystem support.
 *
 * Interesting things to do:
 *
 *	Allow multiple files for each device. A poor-man's metadisk, basically.
 *
 *	Pass-through ioctls on block devices. You can (though it's not
 *	documented), give lofi a block device as a file name. Then we shouldn't
 *	need to fake a geometry, however, it may be relevant if you're replacing
 *	metadisk, or using lofi to get crypto.
 *	It makes sense to do lofiadm -c aes -a /dev/dsk/c0t0d0s4 /dev/lofi/1
 *	and then in /etc/vfstab have an entry for /dev/lofi/1 as /export/home.
 *	In fact this even makes sense if you have lofi "above" metadisk.
 *
 * Encryption:
 *	Each lofi device can have its own symmetric key and cipher.
 *	They are passed to us by lofiadm(1m) in the correct format for use
 *	with the misc/kcf crypto_* routines.
 *
 *	Each block has its own IV, that is calculated in lofi_blk_mech(), based
 *	on the "master" key held in the lsp and the block number of the buffer.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/aio_req.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/lofi.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/filio.h>
#include <sys/fdio.h>
#include <sys/open.h>
#include <sys/disp.h>
#include <vm/seg_map.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/zmod.h>
#include <sys/id_space.h>
#include <sys/mkdev.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/rctl.h>
#include <LzmaDec.h>

#define	NBLOCKS_PROP_NAME	"Nblocks"
#define	SIZE_PROP_NAME		"Size"
#define	ZONE_PROP_NAME		"zone"

#define	SETUP_C_DATA(cd, buf, len) 		\
	(cd).cd_format = CRYPTO_DATA_RAW;	\
	(cd).cd_offset = 0;			\
	(cd).cd_miscdata = NULL;		\
	(cd).cd_length = (len);			\
	(cd).cd_raw.iov_base = (buf);		\
	(cd).cd_raw.iov_len = (len);

#define	UIO_CHECK(uio)	\
	if (((uio)->uio_loffset % DEV_BSIZE) != 0 || \
	    ((uio)->uio_resid % DEV_BSIZE) != 0) { \
		return (EINVAL); \
	}

static dev_info_t *lofi_dip = NULL;
static void *lofi_statep = NULL;
static kmutex_t lofi_lock;		/* state lock */
static id_space_t *lofi_minor_id;
static list_t lofi_list;
static zone_key_t lofi_zone_key;

/*
 * Because lofi_taskq_nthreads limits the actual swamping of the device, the
 * maxalloc parameter (lofi_taskq_maxalloc) should be tuned conservatively
 * high.  If we want to be assured that the underlying device is always busy,
 * we must be sure that the number of bytes enqueued when the number of
 * enqueued tasks exceeds maxalloc is sufficient to keep the device busy for
 * the duration of the sleep time in taskq_ent_alloc().  That is, lofi should
 * set maxalloc to be the maximum throughput (in bytes per second) of the
 * underlying device divided by the minimum I/O size.  We assume a realistic
 * maximum throughput of one hundred megabytes per second; we set maxalloc on
 * the lofi task queue to be 104857600 divided by DEV_BSIZE.
 */
static int lofi_taskq_maxalloc = 104857600 / DEV_BSIZE;
static int lofi_taskq_nthreads = 4;	/* # of taskq threads per device */

const char lofi_crypto_magic[6] = LOFI_CRYPTO_MAGIC;

/*
 * To avoid decompressing data in a compressed segment multiple times
 * when accessing small parts of a segment's data, we cache and reuse
 * the uncompressed segment's data.
 *
 * A single cached segment is sufficient to avoid lots of duplicate
 * segment decompress operations. A small cache size also reduces the
 * memory footprint.
 *
 * lofi_max_comp_cache is the maximum number of decompressed data segments
 * cached for each compressed lofi image. It can be set to 0 to disable
 * caching.
 */

uint32_t lofi_max_comp_cache = 1;

static int gzip_decompress(void *src, size_t srclen, void *dst,
	size_t *destlen, int level);

static int lzma_decompress(void *src, size_t srclen, void *dst,
	size_t *dstlen, int level);

lofi_compress_info_t lofi_compress_table[LOFI_COMPRESS_FUNCTIONS] = {
	{gzip_decompress,	NULL,	6,	"gzip"}, /* default */
	{gzip_decompress,	NULL,	6,	"gzip-6"},
	{gzip_decompress,	NULL,	9,	"gzip-9"},
	{lzma_decompress,	NULL,	0,	"lzma"}
};

/*ARGSUSED*/
static void
*SzAlloc(void *p, size_t size)
{
	return (kmem_alloc(size, KM_SLEEP));
}

/*ARGSUSED*/
static void
SzFree(void *p, void *address, size_t size)
{
	kmem_free(address, size);
}

static ISzAlloc g_Alloc = { SzAlloc, SzFree };

/*
 * Free data referenced by the linked list of cached uncompressed
 * segments.
 */
static void
lofi_free_comp_cache(struct lofi_state *lsp)
{
	struct lofi_comp_cache *lc;

	while ((lc = list_remove_head(&lsp->ls_comp_cache)) != NULL) {
		kmem_free(lc->lc_data, lsp->ls_uncomp_seg_sz);
		kmem_free(lc, sizeof (struct lofi_comp_cache));
		lsp->ls_comp_cache_count--;
	}
	ASSERT(lsp->ls_comp_cache_count == 0);
}

static int
is_opened(struct lofi_state *lsp)
{
	ASSERT(MUTEX_HELD(&lofi_lock));
	return (lsp->ls_chr_open || lsp->ls_blk_open || lsp->ls_lyr_open_count);
}

static int
mark_opened(struct lofi_state *lsp, int otyp)
{
	ASSERT(MUTEX_HELD(&lofi_lock));
	switch (otyp) {
	case OTYP_CHR:
		lsp->ls_chr_open = 1;
		break;
	case OTYP_BLK:
		lsp->ls_blk_open = 1;
		break;
	case OTYP_LYR:
		lsp->ls_lyr_open_count++;
		break;
	default:
		return (-1);
	}
	return (0);
}

static void
mark_closed(struct lofi_state *lsp, int otyp)
{
	ASSERT(MUTEX_HELD(&lofi_lock));
	switch (otyp) {
	case OTYP_CHR:
		lsp->ls_chr_open = 0;
		break;
	case OTYP_BLK:
		lsp->ls_blk_open = 0;
		break;
	case OTYP_LYR:
		lsp->ls_lyr_open_count--;
		break;
	default:
		break;
	}
}

static void
lofi_free_crypto(struct lofi_state *lsp)
{
	ASSERT(MUTEX_HELD(&lofi_lock));

	if (lsp->ls_crypto_enabled) {
		/*
		 * Clean up the crypto state so that it doesn't hang around
		 * in memory after we are done with it.
		 */
		if (lsp->ls_key.ck_data != NULL) {
			bzero(lsp->ls_key.ck_data,
			    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
			kmem_free(lsp->ls_key.ck_data,
			    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
			lsp->ls_key.ck_data = NULL;
			lsp->ls_key.ck_length = 0;
		}

		if (lsp->ls_mech.cm_param != NULL) {
			kmem_free(lsp->ls_mech.cm_param,
			    lsp->ls_mech.cm_param_len);
			lsp->ls_mech.cm_param = NULL;
			lsp->ls_mech.cm_param_len = 0;
		}

		if (lsp->ls_iv_mech.cm_param != NULL) {
			kmem_free(lsp->ls_iv_mech.cm_param,
			    lsp->ls_iv_mech.cm_param_len);
			lsp->ls_iv_mech.cm_param = NULL;
			lsp->ls_iv_mech.cm_param_len = 0;
		}

		mutex_destroy(&lsp->ls_crypto_lock);
	}
}

static void
lofi_destroy(struct lofi_state *lsp, cred_t *credp)
{
	minor_t minor = getminor(lsp->ls_dev);
	int i;

	ASSERT(MUTEX_HELD(&lofi_lock));

	list_remove(&lofi_list, lsp);

	lofi_free_crypto(lsp);

	/*
	 * Free pre-allocated compressed buffers
	 */
	if (lsp->ls_comp_bufs != NULL) {
		for (i = 0; i < lofi_taskq_nthreads; i++) {
			if (lsp->ls_comp_bufs[i].bufsize > 0)
				kmem_free(lsp->ls_comp_bufs[i].buf,
				    lsp->ls_comp_bufs[i].bufsize);
		}
		kmem_free(lsp->ls_comp_bufs,
		    sizeof (struct compbuf) * lofi_taskq_nthreads);
	}

	(void) VOP_CLOSE(lsp->ls_vp, lsp->ls_openflag,
	    1, 0, credp, NULL);
	VN_RELE(lsp->ls_vp);
	if (lsp->ls_stacked_vp != lsp->ls_vp)
		VN_RELE(lsp->ls_stacked_vp);

	taskq_destroy(lsp->ls_taskq);

	if (lsp->ls_kstat != NULL)
		kstat_delete(lsp->ls_kstat);

	/*
	 * Free cached decompressed segment data
	 */
	lofi_free_comp_cache(lsp);
	list_destroy(&lsp->ls_comp_cache);

	if (lsp->ls_uncomp_seg_sz > 0) {
		kmem_free(lsp->ls_comp_index_data, lsp->ls_comp_index_data_sz);
		lsp->ls_uncomp_seg_sz = 0;
	}

	rctl_decr_lofi(lsp->ls_zone.zref_zone, 1);
	zone_rele_ref(&lsp->ls_zone, ZONE_REF_LOFI);

	mutex_destroy(&lsp->ls_comp_cache_lock);
	mutex_destroy(&lsp->ls_comp_bufs_lock);
	mutex_destroy(&lsp->ls_kstat_lock);
	mutex_destroy(&lsp->ls_vp_lock);

	ASSERT(ddi_get_soft_state(lofi_statep, minor) == lsp);
	ddi_soft_state_free(lofi_statep, minor);
	id_free(lofi_minor_id, minor);
}

static void
lofi_free_dev(dev_t dev)
{
	minor_t minor = getminor(dev);
	char namebuf[50];

	ASSERT(MUTEX_HELD(&lofi_lock));

	(void) ddi_prop_remove(dev, lofi_dip, ZONE_PROP_NAME);
	(void) ddi_prop_remove(dev, lofi_dip, SIZE_PROP_NAME);
	(void) ddi_prop_remove(dev, lofi_dip, NBLOCKS_PROP_NAME);

	(void) snprintf(namebuf, sizeof (namebuf), "%d", minor);
	ddi_remove_minor_node(lofi_dip, namebuf);
	(void) snprintf(namebuf, sizeof (namebuf), "%d,raw", minor);
	ddi_remove_minor_node(lofi_dip, namebuf);
}

/*ARGSUSED*/
static void
lofi_zone_shutdown(zoneid_t zoneid, void *arg)
{
	struct lofi_state *lsp;
	struct lofi_state *next;

	mutex_enter(&lofi_lock);

	for (lsp = list_head(&lofi_list); lsp != NULL; lsp = next) {

		/* lofi_destroy() frees lsp */
		next = list_next(&lofi_list, lsp);

		if (lsp->ls_zone.zref_zone->zone_id != zoneid)
			continue;

		/*
		 * No in-zone processes are running, but something has this
		 * open.  It's either a global zone process, or a lofi
		 * mount.  In either case we set ls_cleanup so the last
		 * user destroys the device.
		 */
		if (is_opened(lsp)) {
			lsp->ls_cleanup = 1;
		} else {
			lofi_free_dev(lsp->ls_dev);
			lofi_destroy(lsp, kcred);
		}
	}

	mutex_exit(&lofi_lock);
}

/*ARGSUSED*/
static int
lofi_open(dev_t *devp, int flag, int otyp, struct cred *credp)
{
	minor_t	minor;
	struct lofi_state *lsp;

	/*
	 * lofiadm -a /dev/lofi/1 gets us here.
	 */
	if (mutex_owner(&lofi_lock) == curthread)
		return (EINVAL);

	mutex_enter(&lofi_lock);

	minor = getminor(*devp);

	/* master control device */
	if (minor == 0) {
		mutex_exit(&lofi_lock);
		return (0);
	}

	/* otherwise, the mapping should already exist */
	lsp = ddi_get_soft_state(lofi_statep, minor);
	if (lsp == NULL) {
		mutex_exit(&lofi_lock);
		return (EINVAL);
	}

	if (lsp->ls_vp == NULL) {
		mutex_exit(&lofi_lock);
		return (ENXIO);
	}

	if (lsp->ls_readonly && (flag & FWRITE)) {
		mutex_exit(&lofi_lock);
		return (EROFS);
	}

	if (mark_opened(lsp, otyp) == -1) {
		mutex_exit(&lofi_lock);
		return (EINVAL);
	}

	mutex_exit(&lofi_lock);
	return (0);
}

/*ARGSUSED*/
static int
lofi_close(dev_t dev, int flag, int otyp, struct cred *credp)
{
	minor_t	minor;
	struct lofi_state *lsp;

	mutex_enter(&lofi_lock);
	minor = getminor(dev);
	lsp = ddi_get_soft_state(lofi_statep, minor);
	if (lsp == NULL) {
		mutex_exit(&lofi_lock);
		return (EINVAL);
	}

	if (minor == 0) {
		mutex_exit(&lofi_lock);
		return (0);
	}

	mark_closed(lsp, otyp);

	/*
	 * If we forcibly closed the underlying device (li_force), or
	 * asked for cleanup (li_cleanup), finish up if we're the last
	 * out of the door.
	 */
	if (!is_opened(lsp) && (lsp->ls_cleanup || lsp->ls_vp == NULL)) {
		lofi_free_dev(lsp->ls_dev);
		lofi_destroy(lsp, credp);
	}

	mutex_exit(&lofi_lock);
	return (0);
}

/*
 * Sets the mechanism's initialization vector (IV) if one is needed.
 * The IV is computed from the data block number.  lsp->ls_mech is
 * altered so that:
 *	lsp->ls_mech.cm_param_len is set to the IV len.
 *	lsp->ls_mech.cm_param is set to the IV.
 */
static int
lofi_blk_mech(struct lofi_state *lsp, longlong_t lblkno)
{
	int	ret;
	crypto_data_t cdata;
	char	*iv;
	size_t	iv_len;
	size_t	min;
	void	*data;
	size_t	datasz;

	ASSERT(MUTEX_HELD(&lsp->ls_crypto_lock));

	if (lsp == NULL)
		return (CRYPTO_DEVICE_ERROR);

	/* lsp->ls_mech.cm_param{_len} has already been set for static iv */
	if (lsp->ls_iv_type == IVM_NONE) {
		return (CRYPTO_SUCCESS);
	}

	/*
	 * if kmem already alloced from previous call and it's the same size
	 * we need now, just recycle it; allocate new kmem only if we have to
	 */
	if (lsp->ls_mech.cm_param == NULL ||
	    lsp->ls_mech.cm_param_len != lsp->ls_iv_len) {
		iv_len = lsp->ls_iv_len;
		iv = kmem_zalloc(iv_len, KM_SLEEP);
	} else {
		iv_len = lsp->ls_mech.cm_param_len;
		iv = lsp->ls_mech.cm_param;
		bzero(iv, iv_len);
	}

	switch (lsp->ls_iv_type) {
	case IVM_ENC_BLKNO:
		/* iv is not static, lblkno changes each time */
		data = &lblkno;
		datasz = sizeof (lblkno);
		break;
	default:
		data = 0;
		datasz = 0;
		break;
	}

	/*
	 * write blkno into the iv buffer padded on the left in case
	 * blkno ever grows bigger than its current longlong_t size
	 * or a variation other than blkno is used for the iv data
	 */
	min = MIN(datasz, iv_len);
	bcopy(data, iv + (iv_len - min), min);

	/* encrypt the data in-place to get the IV */
	SETUP_C_DATA(cdata, iv, iv_len);

	ret = crypto_encrypt(&lsp->ls_iv_mech, &cdata, &lsp->ls_key,
	    NULL, NULL, NULL);
	if (ret != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "failed to create iv for block %lld: (0x%x)",
		    lblkno, ret);
		if (lsp->ls_mech.cm_param != iv)
			kmem_free(iv, iv_len);

		return (ret);
	}

	/* clean up the iv from the last computation */
	if (lsp->ls_mech.cm_param != NULL && lsp->ls_mech.cm_param != iv)
		kmem_free(lsp->ls_mech.cm_param, lsp->ls_mech.cm_param_len);

	lsp->ls_mech.cm_param_len = iv_len;
	lsp->ls_mech.cm_param = iv;

	return (CRYPTO_SUCCESS);
}

/*
 * Performs encryption and decryption of a chunk of data of size "len",
 * one DEV_BSIZE block at a time.  "len" is assumed to be a multiple of
 * DEV_BSIZE.
 */
static int
lofi_crypto(struct lofi_state *lsp, struct buf *bp, caddr_t plaintext,
    caddr_t ciphertext, size_t len, boolean_t op_encrypt)
{
	crypto_data_t cdata;
	crypto_data_t wdata;
	int ret;
	longlong_t lblkno = bp->b_lblkno;

	mutex_enter(&lsp->ls_crypto_lock);

	/*
	 * though we could encrypt/decrypt entire "len" chunk of data, we need
	 * to break it into DEV_BSIZE pieces to capture blkno incrementing
	 */
	SETUP_C_DATA(cdata, plaintext, len);
	cdata.cd_length = DEV_BSIZE;
	if (ciphertext != NULL) {		/* not in-place crypto */
		SETUP_C_DATA(wdata, ciphertext, len);
		wdata.cd_length = DEV_BSIZE;
	}

	do {
		ret = lofi_blk_mech(lsp, lblkno);
		if (ret != CRYPTO_SUCCESS)
			continue;

		if (op_encrypt) {
			ret = crypto_encrypt(&lsp->ls_mech, &cdata,
			    &lsp->ls_key, NULL,
			    ((ciphertext != NULL) ? &wdata : NULL), NULL);
		} else {
			ret = crypto_decrypt(&lsp->ls_mech, &cdata,
			    &lsp->ls_key, NULL,
			    ((ciphertext != NULL) ? &wdata : NULL), NULL);
		}

		cdata.cd_offset += DEV_BSIZE;
		if (ciphertext != NULL)
			wdata.cd_offset += DEV_BSIZE;
		lblkno++;
	} while (ret == CRYPTO_SUCCESS && cdata.cd_offset < len);

	mutex_exit(&lsp->ls_crypto_lock);

	if (ret != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s failed for block %lld:  (0x%x)",
		    op_encrypt ? "crypto_encrypt()" : "crypto_decrypt()",
		    lblkno, ret);
	}

	return (ret);
}

#define	RDWR_RAW	1
#define	RDWR_BCOPY	2

static int
lofi_rdwr(caddr_t bufaddr, offset_t offset, struct buf *bp,
    struct lofi_state *lsp, size_t len, int method, caddr_t bcopy_locn)
{
	ssize_t resid;
	int isread;
	int error;

	/*
	 * Handles reads/writes for both plain and encrypted lofi
	 * Note:  offset is already shifted by lsp->ls_crypto_offset
	 * when it gets here.
	 */

	isread = bp->b_flags & B_READ;
	if (isread) {
		if (method == RDWR_BCOPY) {
			/* DO NOT update bp->b_resid for bcopy */
			bcopy(bcopy_locn, bufaddr, len);
			error = 0;
		} else {		/* RDWR_RAW */
			error = vn_rdwr(UIO_READ, lsp->ls_vp, bufaddr, len,
			    offset, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred,
			    &resid);
			bp->b_resid = resid;
		}
		if (lsp->ls_crypto_enabled && error == 0) {
			if (lofi_crypto(lsp, bp, bufaddr, NULL, len,
			    B_FALSE) != CRYPTO_SUCCESS) {
				/*
				 * XXX: original code didn't set residual
				 * back to len because no error was expected
				 * from bcopy() if encryption is not enabled
				 */
				if (method != RDWR_BCOPY)
					bp->b_resid = len;
				error = EIO;
			}
		}
		return (error);
	} else {
		void *iobuf = bufaddr;

		if (lsp->ls_crypto_enabled) {
			/* don't do in-place crypto to keep bufaddr intact */
			iobuf = kmem_alloc(len, KM_SLEEP);
			if (lofi_crypto(lsp, bp, bufaddr, iobuf, len,
			    B_TRUE) != CRYPTO_SUCCESS) {
				kmem_free(iobuf, len);
				if (method != RDWR_BCOPY)
					bp->b_resid = len;
				return (EIO);
			}
		}
		if (method == RDWR_BCOPY) {
			/* DO NOT update bp->b_resid for bcopy */
			bcopy(iobuf, bcopy_locn, len);
			error = 0;
		} else {		/* RDWR_RAW */
			error = vn_rdwr(UIO_WRITE, lsp->ls_vp, iobuf, len,
			    offset, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred,
			    &resid);
			bp->b_resid = resid;
		}
		if (lsp->ls_crypto_enabled) {
			kmem_free(iobuf, len);
		}
		return (error);
	}
}

static int
lofi_mapped_rdwr(caddr_t bufaddr, offset_t offset, struct buf *bp,
    struct lofi_state *lsp)
{
	int error;
	offset_t alignedoffset, mapoffset;
	size_t	xfersize;
	int	isread;
	int	smflags;
	caddr_t	mapaddr;
	size_t	len;
	enum seg_rw srw;
	int	save_error;

	/*
	 * Note:  offset is already shifted by lsp->ls_crypto_offset
	 * when it gets here.
	 */
	if (lsp->ls_crypto_enabled)
		ASSERT(lsp->ls_vp_comp_size == lsp->ls_vp_size);

	/*
	 * segmap always gives us an 8K (MAXBSIZE) chunk, aligned on
	 * an 8K boundary, but the buf transfer address may not be
	 * aligned on more than a 512-byte boundary (we don't enforce
	 * that even though we could). This matters since the initial
	 * part of the transfer may not start at offset 0 within the
	 * segmap'd chunk. So we have to compensate for that with
	 * 'mapoffset'. Subsequent chunks always start off at the
	 * beginning, and the last is capped by b_resid
	 *
	 * Visually, where "|" represents page map boundaries:
	 *   alignedoffset (mapaddr begins at this segmap boundary)
	 *    |   offset (from beginning of file)
	 *    |    |	   len
	 *    v    v	    v
	 * ===|====X========|====...======|========X====|====
	 *	   /-------------...---------------/
	 *		^ bp->b_bcount/bp->b_resid at start
	 *    /----/--------/----...------/--------/
	 *	^	^	^   ^		^
	 *	|	|	|   |		nth xfersize (<= MAXBSIZE)
	 *	|	|	2nd thru n-1st xfersize (= MAXBSIZE)
	 *	|	1st xfersize (<= MAXBSIZE)
	 *    mapoffset (offset into 1st segmap, non-0 1st time, 0 thereafter)
	 *
	 * Notes: "alignedoffset" is "offset" rounded down to nearest
	 * MAXBSIZE boundary.  "len" is next page boundary of size
	 * PAGESIZE after "alignedoffset".
	 */
	mapoffset = offset & MAXBOFFSET;
	alignedoffset = offset - mapoffset;
	bp->b_resid = bp->b_bcount;
	isread = bp->b_flags & B_READ;
	srw = isread ? S_READ : S_WRITE;
	do {
		xfersize = MIN(lsp->ls_vp_comp_size - offset,
		    MIN(MAXBSIZE - mapoffset, bp->b_resid));
		len = roundup(mapoffset + xfersize, PAGESIZE);
		mapaddr = segmap_getmapflt(segkmap, lsp->ls_vp,
		    alignedoffset, MAXBSIZE, 1, srw);
		/*
		 * Now fault in the pages. This lets us check
		 * for errors before we reference mapaddr and
		 * try to resolve the fault in bcopy (which would
		 * panic instead). And this can easily happen,
		 * particularly if you've lofi'd a file over NFS
		 * and someone deletes the file on the server.
		 */
		error = segmap_fault(kas.a_hat, segkmap, mapaddr,
		    len, F_SOFTLOCK, srw);
		if (error) {
			(void) segmap_release(segkmap, mapaddr, 0);
			if (FC_CODE(error) == FC_OBJERR)
				error = FC_ERRNO(error);
			else
				error = EIO;
			break;
		}
		/* error may be non-zero for encrypted lofi */
		error = lofi_rdwr(bufaddr, 0, bp, lsp, xfersize,
		    RDWR_BCOPY, mapaddr + mapoffset);
		if (error == 0) {
			bp->b_resid -= xfersize;
			bufaddr += xfersize;
			offset += xfersize;
		}
		smflags = 0;
		if (isread) {
			smflags |= SM_FREE;
			/*
			 * If we're reading an entire page starting
			 * at a page boundary, there's a good chance
			 * we won't need it again. Put it on the
			 * head of the freelist.
			 */
			if (mapoffset == 0 && xfersize == MAXBSIZE)
				smflags |= SM_DONTNEED;
		} else {
			/*
			 * Write back good pages, it is okay to
			 * always release asynchronous here as we'll
			 * follow with VOP_FSYNC for B_SYNC buffers.
			 */
			if (error == 0)
				smflags |= SM_WRITE | SM_ASYNC;
		}
		(void) segmap_fault(kas.a_hat, segkmap, mapaddr,
		    len, F_SOFTUNLOCK, srw);
		save_error = segmap_release(segkmap, mapaddr, smflags);
		if (error == 0)
			error = save_error;
		/* only the first map may start partial */
		mapoffset = 0;
		alignedoffset += MAXBSIZE;
	} while ((error == 0) && (bp->b_resid > 0) &&
	    (offset < lsp->ls_vp_comp_size));

	return (error);
}

/*
 * Check if segment seg_index is present in the decompressed segment
 * data cache.
 *
 * Returns a pointer to the decompressed segment data cache entry if
 * found, and NULL when decompressed data for this segment is not yet
 * cached.
 */
static struct lofi_comp_cache *
lofi_find_comp_data(struct lofi_state *lsp, uint64_t seg_index)
{
	struct lofi_comp_cache *lc;

	ASSERT(MUTEX_HELD(&lsp->ls_comp_cache_lock));

	for (lc = list_head(&lsp->ls_comp_cache); lc != NULL;
	    lc = list_next(&lsp->ls_comp_cache, lc)) {
		if (lc->lc_index == seg_index) {
			/*
			 * Decompressed segment data was found in the
			 * cache.
			 *
			 * The cache uses an LRU replacement strategy;
			 * move the entry to head of list.
			 */
			list_remove(&lsp->ls_comp_cache, lc);
			list_insert_head(&lsp->ls_comp_cache, lc);
			return (lc);
		}
	}
	return (NULL);
}

/*
 * Add the data for a decompressed segment at segment index
 * seg_index to the cache of the decompressed segments.
 *
 * Returns a pointer to the cache element structure in case
 * the data was added to the cache; returns NULL when the data
 * wasn't cached.
 */
static struct lofi_comp_cache *
lofi_add_comp_data(struct lofi_state *lsp, uint64_t seg_index,
    uchar_t *data)
{
	struct lofi_comp_cache *lc;

	ASSERT(MUTEX_HELD(&lsp->ls_comp_cache_lock));

	while (lsp->ls_comp_cache_count > lofi_max_comp_cache) {
		lc = list_remove_tail(&lsp->ls_comp_cache);
		ASSERT(lc != NULL);
		kmem_free(lc->lc_data, lsp->ls_uncomp_seg_sz);
		kmem_free(lc, sizeof (struct lofi_comp_cache));
		lsp->ls_comp_cache_count--;
	}

	/*
	 * Do not cache when disabled by tunable variable
	 */
	if (lofi_max_comp_cache == 0)
		return (NULL);

	/*
	 * When the cache has not yet reached the maximum allowed
	 * number of segments, allocate a new cache element.
	 * Otherwise the cache is full; reuse the last list element
	 * (LRU) for caching the decompressed segment data.
	 *
	 * The cache element for the new decompressed segment data is
	 * added to the head of the list.
	 */
	if (lsp->ls_comp_cache_count < lofi_max_comp_cache) {
		lc = kmem_alloc(sizeof (struct lofi_comp_cache), KM_SLEEP);
		lc->lc_data = NULL;
		list_insert_head(&lsp->ls_comp_cache, lc);
		lsp->ls_comp_cache_count++;
	} else {
		lc = list_remove_tail(&lsp->ls_comp_cache);
		if (lc == NULL)
			return (NULL);
		list_insert_head(&lsp->ls_comp_cache, lc);
	}

	/*
	 * Free old uncompressed segment data when reusing a cache
	 * entry.
	 */
	if (lc->lc_data != NULL)
		kmem_free(lc->lc_data, lsp->ls_uncomp_seg_sz);

	lc->lc_data = data;
	lc->lc_index = seg_index;
	return (lc);
}


/*ARGSUSED*/
static int
gzip_decompress(void *src, size_t srclen, void *dst,
    size_t *dstlen, int level)
{
	ASSERT(*dstlen >= srclen);

	if (z_uncompress(dst, dstlen, src, srclen) != Z_OK)
		return (-1);
	return (0);
}

#define	LZMA_HEADER_SIZE	(LZMA_PROPS_SIZE + 8)
/*ARGSUSED*/
static int
lzma_decompress(void *src, size_t srclen, void *dst,
	size_t *dstlen, int level)
{
	size_t insizepure;
	void *actual_src;
	ELzmaStatus status;

	insizepure = srclen - LZMA_HEADER_SIZE;
	actual_src = (void *)((Byte *)src + LZMA_HEADER_SIZE);

	if (LzmaDecode((Byte *)dst, (size_t *)dstlen,
	    (const Byte *)actual_src, &insizepure,
	    (const Byte *)src, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status,
	    &g_Alloc) != SZ_OK) {
		return (-1);
	}
	return (0);
}

/*
 * This is basically what strategy used to be before we found we
 * needed task queues.
 */
static void
lofi_strategy_task(void *arg)
{
	struct buf *bp = (struct buf *)arg;
	int error;
	int syncflag = 0;
	struct lofi_state *lsp;
	offset_t offset;
	caddr_t	bufaddr;
	size_t	len;
	size_t	xfersize;
	boolean_t bufinited = B_FALSE;

	lsp = ddi_get_soft_state(lofi_statep, getminor(bp->b_edev));
	if (lsp == NULL) {
		error = ENXIO;
		goto errout;
	}
	if (lsp->ls_kstat) {
		mutex_enter(lsp->ls_kstat->ks_lock);
		kstat_waitq_to_runq(KSTAT_IO_PTR(lsp->ls_kstat));
		mutex_exit(lsp->ls_kstat->ks_lock);
	}
	bp_mapin(bp);
	bufaddr = bp->b_un.b_addr;
	offset = bp->b_lblkno * DEV_BSIZE;	/* offset within file */
	if (lsp->ls_crypto_enabled) {
		/* encrypted data really begins after crypto header */
		offset += lsp->ls_crypto_offset;
	}
	len = bp->b_bcount;
	bufinited = B_TRUE;

	if (lsp->ls_vp == NULL || lsp->ls_vp_closereq) {
		error = EIO;
		goto errout;
	}

	/*
	 * If we're writing and the buffer was not B_ASYNC
	 * we'll follow up with a VOP_FSYNC() to force any
	 * asynchronous I/O to stable storage.
	 */
	if (!(bp->b_flags & B_READ) && !(bp->b_flags & B_ASYNC))
		syncflag = FSYNC;

	/*
	 * We used to always use vn_rdwr here, but we cannot do that because
	 * we might decide to read or write from the the underlying
	 * file during this call, which would be a deadlock because
	 * we have the rw_lock. So instead we page, unless it's not
	 * mapable or it's a character device or it's an encrypted lofi.
	 */
	if ((lsp->ls_vp->v_flag & VNOMAP) || (lsp->ls_vp->v_type == VCHR) ||
	    lsp->ls_crypto_enabled) {
		error = lofi_rdwr(bufaddr, offset, bp, lsp, len, RDWR_RAW,
		    NULL);
	} else if (lsp->ls_uncomp_seg_sz == 0) {
		error = lofi_mapped_rdwr(bufaddr, offset, bp, lsp);
	} else {
		uchar_t *compressed_seg = NULL, *cmpbuf;
		uchar_t *uncompressed_seg = NULL;
		lofi_compress_info_t *li;
		size_t oblkcount;
		ulong_t seglen;
		uint64_t sblkno, eblkno, cmpbytes;
		uint64_t uncompressed_seg_index;
		struct lofi_comp_cache *lc;
		offset_t sblkoff, eblkoff;
		u_offset_t salign, ealign;
		u_offset_t sdiff;
		uint32_t comp_data_sz;
		uint64_t i;
		int j;

		/*
		 * From here on we're dealing primarily with compressed files
		 */
		ASSERT(!lsp->ls_crypto_enabled);

		/*
		 * Compressed files can only be read from and
		 * not written to
		 */
		if (!(bp->b_flags & B_READ)) {
			bp->b_resid = bp->b_bcount;
			error = EROFS;
			goto done;
		}

		ASSERT(lsp->ls_comp_algorithm_index >= 0);
		li = &lofi_compress_table[lsp->ls_comp_algorithm_index];
		/*
		 * Compute starting and ending compressed segment numbers
		 * We use only bitwise operations avoiding division and
		 * modulus because we enforce the compression segment size
		 * to a power of 2
		 */
		sblkno = offset >> lsp->ls_comp_seg_shift;
		sblkoff = offset & (lsp->ls_uncomp_seg_sz - 1);
		eblkno = (offset + bp->b_bcount) >> lsp->ls_comp_seg_shift;
		eblkoff = (offset + bp->b_bcount) & (lsp->ls_uncomp_seg_sz - 1);

		/*
		 * Check the decompressed segment cache.
		 *
		 * The cache is used only when the requested data
		 * is within a segment. Requests that cross
		 * segment boundaries bypass the cache.
		 */
		if (sblkno == eblkno ||
		    (sblkno + 1 == eblkno && eblkoff == 0)) {
			/*
			 * Request doesn't cross a segment boundary,
			 * now check the cache.
			 */
			mutex_enter(&lsp->ls_comp_cache_lock);
			lc = lofi_find_comp_data(lsp, sblkno);
			if (lc != NULL) {
				/*
				 * We've found the decompressed segment
				 * data in the cache; reuse it.
				 */
				bcopy(lc->lc_data + sblkoff, bufaddr,
				    bp->b_bcount);
				mutex_exit(&lsp->ls_comp_cache_lock);
				bp->b_resid = 0;
				error = 0;
				goto done;
			}
			mutex_exit(&lsp->ls_comp_cache_lock);
		}

		/*
		 * Align start offset to block boundary for segmap
		 */
		salign = lsp->ls_comp_seg_index[sblkno];
		sdiff = salign & (DEV_BSIZE - 1);
		salign -= sdiff;
		if (eblkno >= (lsp->ls_comp_index_sz - 1)) {
			/*
			 * We're dealing with the last segment of
			 * the compressed file -- the size of this
			 * segment *may not* be the same as the
			 * segment size for the file
			 */
			eblkoff = (offset + bp->b_bcount) &
			    (lsp->ls_uncomp_last_seg_sz - 1);
			ealign = lsp->ls_vp_comp_size;
		} else {
			ealign = lsp->ls_comp_seg_index[eblkno + 1];
		}

		/*
		 * Preserve original request paramaters
		 */
		oblkcount = bp->b_bcount;

		/*
		 * Assign the calculated parameters
		 */
		comp_data_sz = ealign - salign;
		bp->b_bcount = comp_data_sz;

		/*
		 * Buffers to hold compressed segments are pre-allocated
		 * on a per-thread basis. Find a pre-allocated buffer
		 * that is not currently in use and mark it for use.
		 */
		mutex_enter(&lsp->ls_comp_bufs_lock);
		for (j = 0; j < lofi_taskq_nthreads; j++) {
			if (lsp->ls_comp_bufs[j].inuse == 0) {
				lsp->ls_comp_bufs[j].inuse = 1;
				break;
			}
		}

		mutex_exit(&lsp->ls_comp_bufs_lock);
		ASSERT(j < lofi_taskq_nthreads);

		/*
		 * If the pre-allocated buffer size does not match
		 * the size of the I/O request, re-allocate it with
		 * the appropriate size
		 */
		if (lsp->ls_comp_bufs[j].bufsize < bp->b_bcount) {
			if (lsp->ls_comp_bufs[j].bufsize > 0)
				kmem_free(lsp->ls_comp_bufs[j].buf,
				    lsp->ls_comp_bufs[j].bufsize);
			lsp->ls_comp_bufs[j].buf = kmem_alloc(bp->b_bcount,
			    KM_SLEEP);
			lsp->ls_comp_bufs[j].bufsize = bp->b_bcount;
		}
		compressed_seg = lsp->ls_comp_bufs[j].buf;

		/*
		 * Map in the calculated number of blocks
		 */
		error = lofi_mapped_rdwr((caddr_t)compressed_seg, salign,
		    bp, lsp);

		bp->b_bcount = oblkcount;
		bp->b_resid = oblkcount;
		if (error != 0)
			goto done;

		/*
		 * decompress compressed blocks start
		 */
		cmpbuf = compressed_seg + sdiff;
		for (i = sblkno; i <= eblkno; i++) {
			ASSERT(i < lsp->ls_comp_index_sz - 1);
			uchar_t *useg;

			/*
			 * The last segment is special in that it is
			 * most likely not going to be the same
			 * (uncompressed) size as the other segments.
			 */
			if (i == (lsp->ls_comp_index_sz - 2)) {
				seglen = lsp->ls_uncomp_last_seg_sz;
			} else {
				seglen = lsp->ls_uncomp_seg_sz;
			}

			/*
			 * Each of the segment index entries contains
			 * the starting block number for that segment.
			 * The number of compressed bytes in a segment
			 * is thus the difference between the starting
			 * block number of this segment and the starting
			 * block number of the next segment.
			 */
			cmpbytes = lsp->ls_comp_seg_index[i + 1] -
			    lsp->ls_comp_seg_index[i];

			/*
			 * The first byte in a compressed segment is a flag
			 * that indicates whether this segment is compressed
			 * at all.
			 *
			 * The variable 'useg' is used (instead of
			 * uncompressed_seg) in this loop to keep a
			 * reference to the uncompressed segment.
			 *
			 * N.B. If 'useg' is replaced with uncompressed_seg,
			 * it leads to memory leaks and heap corruption in
			 * corner cases where compressed segments lie
			 * adjacent to uncompressed segments.
			 */
			if (*cmpbuf == UNCOMPRESSED) {
				useg = cmpbuf + SEGHDR;
			} else {
				if (uncompressed_seg == NULL)
					uncompressed_seg =
					    kmem_alloc(lsp->ls_uncomp_seg_sz,
					    KM_SLEEP);
				useg = uncompressed_seg;
				uncompressed_seg_index = i;

				if (li->l_decompress((cmpbuf + SEGHDR),
				    (cmpbytes - SEGHDR), uncompressed_seg,
				    &seglen, li->l_level) != 0) {
					error = EIO;
					goto done;
				}
			}

			/*
			 * Determine how much uncompressed data we
			 * have to copy and copy it
			 */
			xfersize = lsp->ls_uncomp_seg_sz - sblkoff;
			if (i == eblkno)
				xfersize -= (lsp->ls_uncomp_seg_sz - eblkoff);

			bcopy((useg + sblkoff), bufaddr, xfersize);

			cmpbuf += cmpbytes;
			bufaddr += xfersize;
			bp->b_resid -= xfersize;
			sblkoff = 0;

			if (bp->b_resid == 0)
				break;
		} /* decompress compressed blocks ends */

		/*
		 * Skip to done if there is no uncompressed data to cache
		 */
		if (uncompressed_seg == NULL)
			goto done;

		/*
		 * Add the data for the last decompressed segment to
		 * the cache.
		 *
		 * In case the uncompressed segment data was added to (and
		 * is referenced by) the cache, make sure we don't free it
		 * here.
		 */
		mutex_enter(&lsp->ls_comp_cache_lock);
		if ((lc = lofi_add_comp_data(lsp, uncompressed_seg_index,
		    uncompressed_seg)) != NULL) {
			uncompressed_seg = NULL;
		}
		mutex_exit(&lsp->ls_comp_cache_lock);

done:
		if (compressed_seg != NULL) {
			mutex_enter(&lsp->ls_comp_bufs_lock);
			lsp->ls_comp_bufs[j].inuse = 0;
			mutex_exit(&lsp->ls_comp_bufs_lock);
		}
		if (uncompressed_seg != NULL)
			kmem_free(uncompressed_seg, lsp->ls_uncomp_seg_sz);
	} /* end of handling compressed files */

	if ((error == 0) && (syncflag != 0))
		error = VOP_FSYNC(lsp->ls_vp, syncflag, kcred, NULL);

errout:
	if (bufinited && lsp->ls_kstat) {
		size_t n_done = bp->b_bcount - bp->b_resid;
		kstat_io_t *kioptr;

		mutex_enter(lsp->ls_kstat->ks_lock);
		kioptr = KSTAT_IO_PTR(lsp->ls_kstat);
		if (bp->b_flags & B_READ) {
			kioptr->nread += n_done;
			kioptr->reads++;
		} else {
			kioptr->nwritten += n_done;
			kioptr->writes++;
		}
		kstat_runq_exit(kioptr);
		mutex_exit(lsp->ls_kstat->ks_lock);
	}

	mutex_enter(&lsp->ls_vp_lock);
	if (--lsp->ls_vp_iocount == 0)
		cv_broadcast(&lsp->ls_vp_cv);
	mutex_exit(&lsp->ls_vp_lock);

	bioerror(bp, error);
	biodone(bp);
}

static int
lofi_strategy(struct buf *bp)
{
	struct lofi_state *lsp;
	offset_t	offset;

	/*
	 * We cannot just do I/O here, because the current thread
	 * _might_ end up back in here because the underlying filesystem
	 * wants a buffer, which eventually gets into bio_recycle and
	 * might call into lofi to write out a delayed-write buffer.
	 * This is bad if the filesystem above lofi is the same as below.
	 *
	 * We could come up with a complex strategy using threads to
	 * do the I/O asynchronously, or we could use task queues. task
	 * queues were incredibly easy so they win.
	 */
	lsp = ddi_get_soft_state(lofi_statep, getminor(bp->b_edev));
	if (lsp == NULL) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	mutex_enter(&lsp->ls_vp_lock);
	if (lsp->ls_vp == NULL || lsp->ls_vp_closereq) {
		bioerror(bp, EIO);
		biodone(bp);
		mutex_exit(&lsp->ls_vp_lock);
		return (0);
	}

	offset = bp->b_lblkno * DEV_BSIZE;	/* offset within file */
	if (lsp->ls_crypto_enabled) {
		/* encrypted data really begins after crypto header */
		offset += lsp->ls_crypto_offset;
	}
	if (offset == lsp->ls_vp_size) {
		/* EOF */
		if ((bp->b_flags & B_READ) != 0) {
			bp->b_resid = bp->b_bcount;
			bioerror(bp, 0);
		} else {
			/* writes should fail */
			bioerror(bp, ENXIO);
		}
		biodone(bp);
		mutex_exit(&lsp->ls_vp_lock);
		return (0);
	}
	if (offset > lsp->ls_vp_size) {
		bioerror(bp, ENXIO);
		biodone(bp);
		mutex_exit(&lsp->ls_vp_lock);
		return (0);
	}
	lsp->ls_vp_iocount++;
	mutex_exit(&lsp->ls_vp_lock);

	if (lsp->ls_kstat) {
		mutex_enter(lsp->ls_kstat->ks_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(lsp->ls_kstat));
		mutex_exit(lsp->ls_kstat->ks_lock);
	}
	(void) taskq_dispatch(lsp->ls_taskq, lofi_strategy_task, bp, KM_SLEEP);
	return (0);
}

/*ARGSUSED2*/
static int
lofi_read(dev_t dev, struct uio *uio, struct cred *credp)
{
	if (getminor(dev) == 0)
		return (EINVAL);
	UIO_CHECK(uio);
	return (physio(lofi_strategy, NULL, dev, B_READ, minphys, uio));
}

/*ARGSUSED2*/
static int
lofi_write(dev_t dev, struct uio *uio, struct cred *credp)
{
	if (getminor(dev) == 0)
		return (EINVAL);
	UIO_CHECK(uio);
	return (physio(lofi_strategy, NULL, dev, B_WRITE, minphys, uio));
}

/*ARGSUSED2*/
static int
lofi_aread(dev_t dev, struct aio_req *aio, struct cred *credp)
{
	if (getminor(dev) == 0)
		return (EINVAL);
	UIO_CHECK(aio->aio_uio);
	return (aphysio(lofi_strategy, anocancel, dev, B_READ, minphys, aio));
}

/*ARGSUSED2*/
static int
lofi_awrite(dev_t dev, struct aio_req *aio, struct cred *credp)
{
	if (getminor(dev) == 0)
		return (EINVAL);
	UIO_CHECK(aio->aio_uio);
	return (aphysio(lofi_strategy, anocancel, dev, B_WRITE, minphys, aio));
}

/*ARGSUSED*/
static int
lofi_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = lofi_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
lofi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	error;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	lofi_minor_id = id_space_create("lofi_minor_id", 1, L_MAXMIN32 + 1);

	if (!lofi_minor_id)
		return (DDI_FAILURE);

	error = ddi_soft_state_zalloc(lofi_statep, 0);
	if (error == DDI_FAILURE) {
		id_space_destroy(lofi_minor_id);
		return (DDI_FAILURE);
	}
	error = ddi_create_minor_node(dip, LOFI_CTL_NODE, S_IFCHR, 0,
	    DDI_PSEUDO, NULL);
	if (error == DDI_FAILURE) {
		ddi_soft_state_free(lofi_statep, 0);
		id_space_destroy(lofi_minor_id);
		return (DDI_FAILURE);
	}
	/* driver handles kernel-issued IOCTLs */
	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0) != DDI_PROP_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(lofi_statep, 0);
		id_space_destroy(lofi_minor_id);
		return (DDI_FAILURE);
	}

	zone_key_create(&lofi_zone_key, NULL, lofi_zone_shutdown, NULL);

	lofi_dip = dip;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
lofi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&lofi_lock);

	if (!list_is_empty(&lofi_list)) {
		mutex_exit(&lofi_lock);
		return (DDI_FAILURE);
	}

	lofi_dip = NULL;
	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(dip);

	mutex_exit(&lofi_lock);

	if (zone_key_delete(lofi_zone_key) != 0)
		cmn_err(CE_WARN, "failed to delete zone key");

	ddi_soft_state_free(lofi_statep, 0);

	id_space_destroy(lofi_minor_id);

	return (DDI_SUCCESS);
}

/*
 * With addition of encryption, be careful that encryption key is wiped before
 * kernel memory structures are freed, and also that key is not accidentally
 * passed out into userland structures.
 */
static void
free_lofi_ioctl(struct lofi_ioctl *klip)
{
	/* Make sure this encryption key doesn't stick around */
	bzero(klip->li_key, sizeof (klip->li_key));
	kmem_free(klip, sizeof (struct lofi_ioctl));
}

/*
 * These two just simplify the rest of the ioctls that need to copyin/out
 * the lofi_ioctl structure.
 */
int
copy_in_lofi_ioctl(const struct lofi_ioctl *ulip, struct lofi_ioctl **klipp,
    int flag)
{
	struct lofi_ioctl *klip;
	int	error;

	klip = *klipp = kmem_alloc(sizeof (struct lofi_ioctl), KM_SLEEP);
	error = ddi_copyin(ulip, klip, sizeof (struct lofi_ioctl), flag);
	if (error)
		goto err;

	/* ensure NULL termination */
	klip->li_filename[MAXPATHLEN-1] = '\0';
	klip->li_algorithm[MAXALGLEN-1] = '\0';
	klip->li_cipher[CRYPTO_MAX_MECH_NAME-1] = '\0';
	klip->li_iv_cipher[CRYPTO_MAX_MECH_NAME-1] = '\0';

	if (klip->li_minor > L_MAXMIN32) {
		error = EINVAL;
		goto err;
	}

	return (0);

err:
	free_lofi_ioctl(klip);
	return (error);
}

int
copy_out_lofi_ioctl(const struct lofi_ioctl *klip, struct lofi_ioctl *ulip,
	int flag)
{
	int	error;

	/*
	 * NOTE: Do NOT copy the crypto_key_t "back" to userland.
	 * This ensures that an attacker can't trivially find the
	 * key for a mapping just by issuing the ioctl.
	 *
	 * It can still be found by poking around in kmem with mdb(1),
	 * but there is no point in making it easy when the info isn't
	 * of any use in this direction anyway.
	 *
	 * Either way we don't actually have the raw key stored in
	 * a form that we can get it anyway, since we just used it
	 * to create a ctx template and didn't keep "the original".
	 */
	error = ddi_copyout(klip, ulip, sizeof (struct lofi_ioctl), flag);
	if (error)
		return (EFAULT);
	return (0);
}

static int
lofi_access(struct lofi_state *lsp)
{
	ASSERT(MUTEX_HELD(&lofi_lock));
	if (INGLOBALZONE(curproc) || lsp->ls_zone.zref_zone == curzone)
		return (0);
	return (EPERM);
}

/*
 * Find the lofi state for the given filename. We compare by vnode to
 * allow the global zone visibility into NGZ lofi nodes.
 */
static int
file_to_lofi_nocheck(char *filename, boolean_t readonly,
    struct lofi_state **lspp)
{
	struct lofi_state *lsp;
	vnode_t *vp = NULL;
	int err = 0;
	int rdfiles = 0;

	ASSERT(MUTEX_HELD(&lofi_lock));

	if ((err = lookupname(filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &vp)) != 0)
		goto out;

	if (vp->v_type == VREG) {
		vnode_t *realvp;
		if (VOP_REALVP(vp, &realvp, NULL) == 0) {
			VN_HOLD(realvp);
			VN_RELE(vp);
			vp = realvp;
		}
	}

	for (lsp = list_head(&lofi_list); lsp != NULL;
	    lsp = list_next(&lofi_list, lsp)) {
		if (lsp->ls_vp == vp) {
			if (lspp != NULL)
				*lspp = lsp;
			if (lsp->ls_readonly) {
				rdfiles++;
				/* Skip if '-r' is specified */
				if (readonly)
					continue;
			}
			goto out;
		}
	}

	err = ENOENT;

	/*
	 * If a filename is given as an argument for lofi_unmap, we shouldn't
	 * allow unmap if there are multiple read-only lofi devices associated
	 * with this file.
	 */
	if (lspp != NULL) {
		if (rdfiles == 1)
			err = 0;
		else if (rdfiles > 1)
			err = EBUSY;
	}

out:
	if (vp != NULL)
		VN_RELE(vp);
	return (err);
}

/*
 * Find the minor for the given filename, checking the zone can access
 * it.
 */
static int
file_to_lofi(char *filename, boolean_t readonly, struct lofi_state **lspp)
{
	int err = 0;

	ASSERT(MUTEX_HELD(&lofi_lock));

	if ((err = file_to_lofi_nocheck(filename, readonly, lspp)) != 0)
		return (err);

	if ((err = lofi_access(*lspp)) != 0)
		return (err);

	return (0);
}

/*
 * Fakes up a disk geometry, and one big partition, based on the size
 * of the file. This is needed because we allow newfs'ing the device,
 * and newfs will do several disk ioctls to figure out the geometry and
 * partition information. It uses that information to determine the parameters
 * to pass to mkfs. Geometry is pretty much irrelevant these days, but we
 * have to support it.
 */
static void
fake_disk_geometry(struct lofi_state *lsp)
{
	u_offset_t dsize = lsp->ls_vp_size - lsp->ls_crypto_offset;

	/* dk_geom - see dkio(7I) */
	/*
	 * dkg_ncyl _could_ be set to one here (one big cylinder with gobs
	 * of sectors), but that breaks programs like fdisk which want to
	 * partition a disk by cylinder. With one cylinder, you can't create
	 * an fdisk partition and put pcfs on it for testing (hard to pick
	 * a number between one and one).
	 *
	 * The cheezy floppy test is an attempt to not have too few cylinders
	 * for a small file, or so many on a big file that you waste space
	 * for backup superblocks or cylinder group structures.
	 */
	if (dsize < (2 * 1024 * 1024)) /* floppy? */
		lsp->ls_dkg.dkg_ncyl = dsize / (100 * 1024);
	else
		lsp->ls_dkg.dkg_ncyl = dsize / (300 * 1024);
	/* in case file file is < 100k */
	if (lsp->ls_dkg.dkg_ncyl == 0)
		lsp->ls_dkg.dkg_ncyl = 1;
	lsp->ls_dkg.dkg_acyl = 0;
	lsp->ls_dkg.dkg_bcyl = 0;
	lsp->ls_dkg.dkg_nhead = 1;
	lsp->ls_dkg.dkg_obs1 = 0;
	lsp->ls_dkg.dkg_intrlv = 0;
	lsp->ls_dkg.dkg_obs2 = 0;
	lsp->ls_dkg.dkg_obs3 = 0;
	lsp->ls_dkg.dkg_apc = 0;
	lsp->ls_dkg.dkg_rpm = 7200;
	lsp->ls_dkg.dkg_pcyl = lsp->ls_dkg.dkg_ncyl + lsp->ls_dkg.dkg_acyl;
	lsp->ls_dkg.dkg_nsect = dsize / (DEV_BSIZE * lsp->ls_dkg.dkg_ncyl);
	lsp->ls_dkg.dkg_write_reinstruct = 0;
	lsp->ls_dkg.dkg_read_reinstruct = 0;

	/* vtoc - see dkio(7I) */
	bzero(&lsp->ls_vtoc, sizeof (struct vtoc));
	lsp->ls_vtoc.v_sanity = VTOC_SANE;
	lsp->ls_vtoc.v_version = V_VERSION;
	(void) strncpy(lsp->ls_vtoc.v_volume, LOFI_DRIVER_NAME,
	    sizeof (lsp->ls_vtoc.v_volume));
	lsp->ls_vtoc.v_sectorsz = DEV_BSIZE;
	lsp->ls_vtoc.v_nparts = 1;
	lsp->ls_vtoc.v_part[0].p_tag = V_UNASSIGNED;

	/*
	 * A compressed file is read-only, other files can
	 * be read-write
	 */
	if (lsp->ls_uncomp_seg_sz > 0) {
		lsp->ls_vtoc.v_part[0].p_flag = V_UNMNT | V_RONLY;
	} else {
		lsp->ls_vtoc.v_part[0].p_flag = V_UNMNT;
	}
	lsp->ls_vtoc.v_part[0].p_start = (daddr_t)0;
	/*
	 * The partition size cannot just be the number of sectors, because
	 * that might not end on a cylinder boundary. And if that's the case,
	 * newfs/mkfs will print a scary warning. So just figure the size
	 * based on the number of cylinders and sectors/cylinder.
	 */
	lsp->ls_vtoc.v_part[0].p_size = lsp->ls_dkg.dkg_pcyl *
	    lsp->ls_dkg.dkg_nsect * lsp->ls_dkg.dkg_nhead;

	/* dk_cinfo - see dkio(7I) */
	bzero(&lsp->ls_ci, sizeof (struct dk_cinfo));
	(void) strcpy(lsp->ls_ci.dki_cname, LOFI_DRIVER_NAME);
	lsp->ls_ci.dki_ctype = DKC_MD;
	lsp->ls_ci.dki_flags = 0;
	lsp->ls_ci.dki_cnum = 0;
	lsp->ls_ci.dki_addr = 0;
	lsp->ls_ci.dki_space = 0;
	lsp->ls_ci.dki_prio = 0;
	lsp->ls_ci.dki_vec = 0;
	(void) strcpy(lsp->ls_ci.dki_dname, LOFI_DRIVER_NAME);
	lsp->ls_ci.dki_unit = 0;
	lsp->ls_ci.dki_slave = 0;
	lsp->ls_ci.dki_partition = 0;
	/*
	 * newfs uses this to set maxcontig. Must not be < 16, or it
	 * will be 0 when newfs multiplies it by DEV_BSIZE and divides
	 * it by the block size. Then tunefs doesn't work because
	 * maxcontig is 0.
	 */
	lsp->ls_ci.dki_maxtransfer = 16;
}

/*
 * map in a compressed file
 *
 * Read in the header and the index that follows.
 *
 * The header is as follows -
 *
 * Signature (name of the compression algorithm)
 * Compression segment size (a multiple of 512)
 * Number of index entries
 * Size of the last block
 * The array containing the index entries
 *
 * The header information is always stored in
 * network byte order on disk.
 */
static int
lofi_map_compressed_file(struct lofi_state *lsp, char *buf)
{
	uint32_t index_sz, header_len, i;
	ssize_t	resid;
	enum uio_rw rw;
	char *tbuf = buf;
	int error;

	/* The signature has already been read */
	tbuf += sizeof (lsp->ls_comp_algorithm);
	bcopy(tbuf, &(lsp->ls_uncomp_seg_sz), sizeof (lsp->ls_uncomp_seg_sz));
	lsp->ls_uncomp_seg_sz = ntohl(lsp->ls_uncomp_seg_sz);

	/*
	 * The compressed segment size must be a power of 2
	 */
	if (lsp->ls_uncomp_seg_sz < DEV_BSIZE ||
	    !ISP2(lsp->ls_uncomp_seg_sz))
		return (EINVAL);

	for (i = 0; !((lsp->ls_uncomp_seg_sz >> i) & 1); i++)
		;

	lsp->ls_comp_seg_shift = i;

	tbuf += sizeof (lsp->ls_uncomp_seg_sz);
	bcopy(tbuf, &(lsp->ls_comp_index_sz), sizeof (lsp->ls_comp_index_sz));
	lsp->ls_comp_index_sz = ntohl(lsp->ls_comp_index_sz);

	tbuf += sizeof (lsp->ls_comp_index_sz);
	bcopy(tbuf, &(lsp->ls_uncomp_last_seg_sz),
	    sizeof (lsp->ls_uncomp_last_seg_sz));
	lsp->ls_uncomp_last_seg_sz = ntohl(lsp->ls_uncomp_last_seg_sz);

	/*
	 * Compute the total size of the uncompressed data
	 * for use in fake_disk_geometry and other calculations.
	 * Disk geometry has to be faked with respect to the
	 * actual uncompressed data size rather than the
	 * compressed file size.
	 */
	lsp->ls_vp_size =
	    (u_offset_t)(lsp->ls_comp_index_sz - 2) * lsp->ls_uncomp_seg_sz
	    + lsp->ls_uncomp_last_seg_sz;

	/*
	 * Index size is rounded up to DEV_BSIZE for ease
	 * of segmapping
	 */
	index_sz = sizeof (*lsp->ls_comp_seg_index) * lsp->ls_comp_index_sz;
	header_len = sizeof (lsp->ls_comp_algorithm) +
	    sizeof (lsp->ls_uncomp_seg_sz) +
	    sizeof (lsp->ls_comp_index_sz) +
	    sizeof (lsp->ls_uncomp_last_seg_sz);
	lsp->ls_comp_offbase = header_len + index_sz;

	index_sz += header_len;
	index_sz = roundup(index_sz, DEV_BSIZE);

	lsp->ls_comp_index_data = kmem_alloc(index_sz, KM_SLEEP);
	lsp->ls_comp_index_data_sz = index_sz;

	/*
	 * Read in the index -- this has a side-effect
	 * of reading in the header as well
	 */
	rw = UIO_READ;
	error = vn_rdwr(rw, lsp->ls_vp, lsp->ls_comp_index_data, index_sz,
	    0, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);

	if (error != 0)
		return (error);

	/* Skip the header, this is where the index really begins */
	lsp->ls_comp_seg_index =
	    /*LINTED*/
	    (uint64_t *)(lsp->ls_comp_index_data + header_len);

	/*
	 * Now recompute offsets in the index to account for
	 * the header length
	 */
	for (i = 0; i < lsp->ls_comp_index_sz; i++) {
		lsp->ls_comp_seg_index[i] = lsp->ls_comp_offbase +
		    BE_64(lsp->ls_comp_seg_index[i]);
	}

	return (error);
}

static int
lofi_init_crypto(struct lofi_state *lsp, struct lofi_ioctl *klip)
{
	struct crypto_meta chead;
	char buf[DEV_BSIZE];
	ssize_t	resid;
	char *marker;
	int error;
	int ret;
	int i;

	if (!klip->li_crypto_enabled)
		return (0);

	/*
	 * All current algorithms have a max of 448 bits.
	 */
	if (klip->li_iv_len > CRYPTO_BITS2BYTES(512))
		return (EINVAL);

	if (CRYPTO_BITS2BYTES(klip->li_key_len) > sizeof (klip->li_key))
		return (EINVAL);

	lsp->ls_crypto_enabled = klip->li_crypto_enabled;

	mutex_init(&lsp->ls_crypto_lock, NULL, MUTEX_DRIVER, NULL);

	lsp->ls_mech.cm_type = crypto_mech2id(klip->li_cipher);
	if (lsp->ls_mech.cm_type == CRYPTO_MECH_INVALID) {
		cmn_err(CE_WARN, "invalid cipher %s requested for %s",
		    klip->li_cipher, klip->li_filename);
		return (EINVAL);
	}

	/* this is just initialization here */
	lsp->ls_mech.cm_param = NULL;
	lsp->ls_mech.cm_param_len = 0;

	lsp->ls_iv_type = klip->li_iv_type;
	lsp->ls_iv_mech.cm_type = crypto_mech2id(klip->li_iv_cipher);
	if (lsp->ls_iv_mech.cm_type == CRYPTO_MECH_INVALID) {
		cmn_err(CE_WARN, "invalid iv cipher %s requested"
		    " for %s", klip->li_iv_cipher, klip->li_filename);
		return (EINVAL);
	}

	/* iv mech must itself take a null iv */
	lsp->ls_iv_mech.cm_param = NULL;
	lsp->ls_iv_mech.cm_param_len = 0;
	lsp->ls_iv_len = klip->li_iv_len;

	/*
	 * Create ctx using li_cipher & the raw li_key after checking
	 * that it isn't a weak key.
	 */
	lsp->ls_key.ck_format = CRYPTO_KEY_RAW;
	lsp->ls_key.ck_length = klip->li_key_len;
	lsp->ls_key.ck_data = kmem_alloc(
	    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length), KM_SLEEP);
	bcopy(klip->li_key, lsp->ls_key.ck_data,
	    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));

	ret = crypto_key_check(&lsp->ls_mech, &lsp->ls_key);
	if (ret != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "weak key check failed for cipher "
		    "%s on file %s (0x%x)", klip->li_cipher,
		    klip->li_filename, ret);
		return (EINVAL);
	}

	error = vn_rdwr(UIO_READ, lsp->ls_vp, buf, DEV_BSIZE,
	    CRYOFF, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);
	if (error != 0)
		return (error);

	/*
	 * This is the case where the header in the lofi image is already
	 * initialized to indicate it is encrypted.
	 */
	if (strncmp(buf, lofi_crypto_magic, sizeof (lofi_crypto_magic)) == 0) {
		/*
		 * The encryption header information is laid out this way:
		 *	6 bytes:	hex "CFLOFI"
		 *	2 bytes:	version = 0 ... for now
		 *	96 bytes:	reserved1 (not implemented yet)
		 *	4 bytes:	data_sector = 2 ... for now
		 *	more...		not implemented yet
		 */

		marker = buf;

		/* copy the magic */
		bcopy(marker, lsp->ls_crypto.magic,
		    sizeof (lsp->ls_crypto.magic));
		marker += sizeof (lsp->ls_crypto.magic);

		/* read the encryption version number */
		bcopy(marker, &(lsp->ls_crypto.version),
		    sizeof (lsp->ls_crypto.version));
		lsp->ls_crypto.version = ntohs(lsp->ls_crypto.version);
		marker += sizeof (lsp->ls_crypto.version);

		/* read a chunk of reserved data */
		bcopy(marker, lsp->ls_crypto.reserved1,
		    sizeof (lsp->ls_crypto.reserved1));
		marker += sizeof (lsp->ls_crypto.reserved1);

		/* read block number where encrypted data begins */
		bcopy(marker, &(lsp->ls_crypto.data_sector),
		    sizeof (lsp->ls_crypto.data_sector));
		lsp->ls_crypto.data_sector = ntohl(lsp->ls_crypto.data_sector);
		marker += sizeof (lsp->ls_crypto.data_sector);

		/* and ignore the rest until it is implemented */

		lsp->ls_crypto_offset = lsp->ls_crypto.data_sector * DEV_BSIZE;
		return (0);
	}

	/*
	 * We've requested encryption, but no magic was found, so it must be
	 * a new image.
	 */

	for (i = 0; i < sizeof (struct crypto_meta); i++) {
		if (buf[i] != '\0')
			return (EINVAL);
	}

	marker = buf;
	bcopy(lofi_crypto_magic, marker, sizeof (lofi_crypto_magic));
	marker += sizeof (lofi_crypto_magic);
	chead.version = htons(LOFI_CRYPTO_VERSION);
	bcopy(&(chead.version), marker, sizeof (chead.version));
	marker += sizeof (chead.version);
	marker += sizeof (chead.reserved1);
	chead.data_sector = htonl(LOFI_CRYPTO_DATA_SECTOR);
	bcopy(&(chead.data_sector), marker, sizeof (chead.data_sector));

	/* write the header */
	error = vn_rdwr(UIO_WRITE, lsp->ls_vp, buf, DEV_BSIZE,
	    CRYOFF, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);
	if (error != 0)
		return (error);

	/* fix things up so it looks like we read this info */
	bcopy(lofi_crypto_magic, lsp->ls_crypto.magic,
	    sizeof (lofi_crypto_magic));
	lsp->ls_crypto.version = LOFI_CRYPTO_VERSION;
	lsp->ls_crypto.data_sector = LOFI_CRYPTO_DATA_SECTOR;
	lsp->ls_crypto_offset = lsp->ls_crypto.data_sector * DEV_BSIZE;
	return (0);
}

/*
 * Check to see if the passed in signature is a valid one.  If it is
 * valid, return the index into lofi_compress_table.
 *
 * Return -1 if it is invalid
 */
static int
lofi_compress_select(const char *signature)
{
	int i;

	for (i = 0; i < LOFI_COMPRESS_FUNCTIONS; i++) {
		if (strcmp(lofi_compress_table[i].l_name, signature) == 0)
			return (i);
	}

	return (-1);
}

static int
lofi_init_compress(struct lofi_state *lsp)
{
	char buf[DEV_BSIZE];
	int compress_index;
	ssize_t	resid;
	int error;

	error = vn_rdwr(UIO_READ, lsp->ls_vp, buf, DEV_BSIZE, 0, UIO_SYSSPACE,
	    0, RLIM64_INFINITY, kcred, &resid);

	if (error != 0)
		return (error);

	if ((compress_index = lofi_compress_select(buf)) == -1)
		return (0);

	/* compression and encryption are mutually exclusive */
	if (lsp->ls_crypto_enabled)
		return (ENOTSUP);

	/* initialize compression info for compressed lofi */
	lsp->ls_comp_algorithm_index = compress_index;
	(void) strlcpy(lsp->ls_comp_algorithm,
	    lofi_compress_table[compress_index].l_name,
	    sizeof (lsp->ls_comp_algorithm));

	/* Finally setup per-thread pre-allocated buffers */
	lsp->ls_comp_bufs = kmem_zalloc(lofi_taskq_nthreads *
	    sizeof (struct compbuf), KM_SLEEP);

	return (lofi_map_compressed_file(lsp, buf));
}

/*
 * map a file to a minor number. Return the minor number.
 */
static int
lofi_map_file(dev_t dev, struct lofi_ioctl *ulip, int pickminor,
    int *rvalp, struct cred *credp, int ioctl_flag)
{
	minor_t	minor = (minor_t)-1;
	struct lofi_state *lsp = NULL;
	struct lofi_ioctl *klip;
	int	error;
	struct vnode *vp = NULL;
	vattr_t	vattr;
	int	flag;
	dev_t	newdev;
	char	namebuf[50];

	error = copy_in_lofi_ioctl(ulip, &klip, ioctl_flag);
	if (error != 0)
		return (error);

	mutex_enter(&lofi_lock);

	mutex_enter(&curproc->p_lock);
	if ((error = rctl_incr_lofi(curproc, curproc->p_zone, 1)) != 0) {
		mutex_exit(&curproc->p_lock);
		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (error);
	}
	mutex_exit(&curproc->p_lock);

	if (file_to_lofi_nocheck(klip->li_filename, klip->li_readonly,
	    NULL) == 0) {
		error = EBUSY;
		goto err;
	}

	if (pickminor) {
		minor = (minor_t)id_allocff_nosleep(lofi_minor_id);
		if (minor == (minor_t)-1) {
			error = EAGAIN;
			goto err;
		}
	} else {
		if (ddi_get_soft_state(lofi_statep, klip->li_minor) != NULL) {
			error = EEXIST;
			goto err;
		}

		minor = (minor_t)
		    id_alloc_specific_nosleep(lofi_minor_id, klip->li_minor);
		ASSERT(minor != (minor_t)-1);
	}

	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	error = vn_open(klip->li_filename, UIO_SYSSPACE, flag, 0, &vp, 0, 0);
	if (error) {
		/* try read-only */
		flag &= ~FWRITE;
		error = vn_open(klip->li_filename, UIO_SYSSPACE, flag, 0,
		    &vp, 0, 0);
		if (error)
			goto err;
	}

	if (!V_ISLOFIABLE(vp->v_type)) {
		error = EINVAL;
		goto err;
	}

	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, credp, NULL);
	if (error)
		goto err;

	/* the file needs to be a multiple of the block size */
	if ((vattr.va_size % DEV_BSIZE) != 0) {
		error = EINVAL;
		goto err;
	}

	/* lsp alloc+init */

	error = ddi_soft_state_zalloc(lofi_statep, minor);
	if (error == DDI_FAILURE) {
		error = ENOMEM;
		goto err;
	}

	lsp = ddi_get_soft_state(lofi_statep, minor);
	list_insert_tail(&lofi_list, lsp);

	newdev = makedevice(getmajor(dev), minor);
	lsp->ls_dev = newdev;
	zone_init_ref(&lsp->ls_zone);
	zone_hold_ref(curzone, &lsp->ls_zone, ZONE_REF_LOFI);
	lsp->ls_uncomp_seg_sz = 0;
	lsp->ls_comp_algorithm[0] = '\0';
	lsp->ls_crypto_offset = 0;

	cv_init(&lsp->ls_vp_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&lsp->ls_comp_cache_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&lsp->ls_comp_bufs_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&lsp->ls_kstat_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&lsp->ls_vp_lock, NULL, MUTEX_DRIVER, NULL);

	(void) snprintf(namebuf, sizeof (namebuf), "%s_taskq_%d",
	    LOFI_DRIVER_NAME, minor);
	lsp->ls_taskq = taskq_create_proc(namebuf, lofi_taskq_nthreads,
	    minclsyspri, 1, lofi_taskq_maxalloc, curzone->zone_zsched, 0);

	list_create(&lsp->ls_comp_cache, sizeof (struct lofi_comp_cache),
	    offsetof(struct lofi_comp_cache, lc_list));

	/*
	 * save open mode so file can be closed properly and vnode counts
	 * updated correctly.
	 */
	lsp->ls_openflag = flag;

	lsp->ls_vp = vp;
	lsp->ls_stacked_vp = vp;
	/*
	 * Try to handle stacked lofs vnodes.
	 */
	if (vp->v_type == VREG) {
		vnode_t *realvp;

		if (VOP_REALVP(vp, &realvp, NULL) == 0) {
			/*
			 * We need to use the realvp for uniqueness
			 * checking, but keep the stacked vp for
			 * LOFI_GET_FILENAME display.
			 */
			VN_HOLD(realvp);
			lsp->ls_vp = realvp;
		}
	}

	lsp->ls_vp_size = vattr.va_size;
	lsp->ls_vp_comp_size = lsp->ls_vp_size;

	lsp->ls_kstat = kstat_create_zone(LOFI_DRIVER_NAME, minor,
	    NULL, "disk", KSTAT_TYPE_IO, 1, 0, getzoneid());

	if (lsp->ls_kstat == NULL) {
		error = ENOMEM;
		goto err;
	}

	lsp->ls_kstat->ks_lock = &lsp->ls_kstat_lock;
	kstat_zone_add(lsp->ls_kstat, GLOBAL_ZONEID);

	lsp->ls_readonly = klip->li_readonly;

	if ((error = lofi_init_crypto(lsp, klip)) != 0)
		goto err;

	if ((error = lofi_init_compress(lsp)) != 0)
		goto err;

	fake_disk_geometry(lsp);

	/* create minor nodes */

	(void) snprintf(namebuf, sizeof (namebuf), "%d", minor);
	error = ddi_create_minor_node(lofi_dip, namebuf, S_IFBLK, minor,
	    DDI_PSEUDO, NULL);
	if (error != DDI_SUCCESS) {
		error = ENXIO;
		goto err;
	}

	(void) snprintf(namebuf, sizeof (namebuf), "%d,raw", minor);
	error = ddi_create_minor_node(lofi_dip, namebuf, S_IFCHR, minor,
	    DDI_PSEUDO, NULL);
	if (error != DDI_SUCCESS) {
		/* remove block node */
		(void) snprintf(namebuf, sizeof (namebuf), "%d", minor);
		ddi_remove_minor_node(lofi_dip, namebuf);
		error = ENXIO;
		goto err;
	}

	/* create DDI properties */

	if ((ddi_prop_update_int64(newdev, lofi_dip, SIZE_PROP_NAME,
	    lsp->ls_vp_size - lsp->ls_crypto_offset)) != DDI_PROP_SUCCESS) {
		error = EINVAL;
		goto nodeerr;
	}

	if ((ddi_prop_update_int64(newdev, lofi_dip, NBLOCKS_PROP_NAME,
	    (lsp->ls_vp_size - lsp->ls_crypto_offset) / DEV_BSIZE))
	    != DDI_PROP_SUCCESS) {
		error = EINVAL;
		goto nodeerr;
	}

	if (ddi_prop_update_string(newdev, lofi_dip, ZONE_PROP_NAME,
	    (char *)curproc->p_zone->zone_name) != DDI_PROP_SUCCESS) {
		error = EINVAL;
		goto nodeerr;
	}

	kstat_install(lsp->ls_kstat);

	mutex_exit(&lofi_lock);

	if (rvalp)
		*rvalp = (int)minor;
	klip->li_minor = minor;
	(void) copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
	free_lofi_ioctl(klip);
	return (0);

nodeerr:
	lofi_free_dev(newdev);
err:
	if (lsp != NULL) {
		lofi_destroy(lsp, credp);
	} else {
		if (vp != NULL) {
			(void) VOP_CLOSE(vp, flag, 1, 0, credp, NULL);
			VN_RELE(vp);
		}

		if (minor != (minor_t)-1)
			id_free(lofi_minor_id, minor);

		rctl_decr_lofi(curproc->p_zone, 1);
	}

	mutex_exit(&lofi_lock);
	free_lofi_ioctl(klip);
	return (error);
}

/*
 * unmap a file.
 */
static int
lofi_unmap_file(struct lofi_ioctl *ulip, int byfilename,
    struct cred *credp, int ioctl_flag)
{
	struct lofi_state *lsp;
	struct lofi_ioctl *klip;
	int err;

	err = copy_in_lofi_ioctl(ulip, &klip, ioctl_flag);
	if (err != 0)
		return (err);

	mutex_enter(&lofi_lock);
	if (byfilename) {
		if ((err = file_to_lofi(klip->li_filename, klip->li_readonly,
		    &lsp)) != 0) {
			mutex_exit(&lofi_lock);
			return (err);
		}
	} else if (klip->li_minor == 0) {
		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (ENXIO);
	} else {
		lsp = ddi_get_soft_state(lofi_statep, klip->li_minor);
	}

	if (lsp == NULL || lsp->ls_vp == NULL || lofi_access(lsp) != 0) {
		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (ENXIO);
	}

	klip->li_minor = getminor(lsp->ls_dev);

	/*
	 * If it's still held open, we'll do one of three things:
	 *
	 * If no flag is set, just return EBUSY.
	 *
	 * If the 'cleanup' flag is set, unmap and remove the device when
	 * the last user finishes.
	 *
	 * If the 'force' flag is set, then we forcibly close the underlying
	 * file.  Subsequent operations will fail, and the DKIOCSTATE ioctl
	 * will return DKIO_DEV_GONE.  When the device is last closed, the
	 * device will be cleaned up appropriately.
	 *
	 * This is complicated by the fact that we may have outstanding
	 * dispatched I/Os.  Rather than having a single mutex to serialize all
	 * I/O, we keep a count of the number of outstanding I/O requests
	 * (ls_vp_iocount), as well as a flag to indicate that no new I/Os
	 * should be dispatched (ls_vp_closereq).
	 *
	 * We set the flag, wait for the number of outstanding I/Os to reach 0,
	 * and then close the underlying vnode.
	 */
	if (is_opened(lsp)) {
		if (klip->li_force) {
			mutex_enter(&lsp->ls_vp_lock);
			lsp->ls_vp_closereq = B_TRUE;
			/* wake up any threads waiting on dkiocstate */
			cv_broadcast(&lsp->ls_vp_cv);
			while (lsp->ls_vp_iocount > 0)
				cv_wait(&lsp->ls_vp_cv, &lsp->ls_vp_lock);
			mutex_exit(&lsp->ls_vp_lock);

			goto out;
		} else if (klip->li_cleanup) {
			lsp->ls_cleanup = 1;
			mutex_exit(&lofi_lock);
			free_lofi_ioctl(klip);
			return (0);
		}

		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (EBUSY);
	}

out:
	lofi_free_dev(lsp->ls_dev);
	lofi_destroy(lsp, credp);

	mutex_exit(&lofi_lock);
	(void) copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
	free_lofi_ioctl(klip);
	return (0);
}

/*
 * get the filename given the minor number, or the minor number given
 * the name.
 */
/*ARGSUSED*/
static int
lofi_get_info(dev_t dev, struct lofi_ioctl *ulip, int which,
    struct cred *credp, int ioctl_flag)
{
	struct lofi_ioctl *klip;
	struct lofi_state *lsp;
	int	error;

	error = copy_in_lofi_ioctl(ulip, &klip, ioctl_flag);
	if (error != 0)
		return (error);

	switch (which) {
	case LOFI_GET_FILENAME:
		if (klip->li_minor == 0) {
			free_lofi_ioctl(klip);
			return (EINVAL);
		}

		mutex_enter(&lofi_lock);
		lsp = ddi_get_soft_state(lofi_statep, klip->li_minor);
		if (lsp == NULL || lofi_access(lsp) != 0) {
			mutex_exit(&lofi_lock);
			free_lofi_ioctl(klip);
			return (ENXIO);
		}

		/*
		 * This may fail if, for example, we're trying to look
		 * up a zoned NFS path from the global zone.
		 */
		if (vnodetopath(NULL, lsp->ls_stacked_vp, klip->li_filename,
		    sizeof (klip->li_filename), CRED()) != 0) {
			(void) strlcpy(klip->li_filename, "?",
			    sizeof (klip->li_filename));
		}

		klip->li_readonly = lsp->ls_readonly;

		(void) strlcpy(klip->li_algorithm, lsp->ls_comp_algorithm,
		    sizeof (klip->li_algorithm));
		klip->li_crypto_enabled = lsp->ls_crypto_enabled;
		mutex_exit(&lofi_lock);
		error = copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
		free_lofi_ioctl(klip);
		return (error);
	case LOFI_GET_MINOR:
		mutex_enter(&lofi_lock);
		error = file_to_lofi(klip->li_filename,
		    klip->li_readonly, &lsp);
		if (error == 0)
			klip->li_minor = getminor(lsp->ls_dev);
		mutex_exit(&lofi_lock);

		if (error == 0)
			error = copy_out_lofi_ioctl(klip, ulip, ioctl_flag);

		free_lofi_ioctl(klip);
		return (error);
	case LOFI_CHECK_COMPRESSED:
		mutex_enter(&lofi_lock);
		error = file_to_lofi(klip->li_filename,
		    klip->li_readonly, &lsp);
		if (error != 0) {
			mutex_exit(&lofi_lock);
			free_lofi_ioctl(klip);
			return (error);
		}

		klip->li_minor = getminor(lsp->ls_dev);
		(void) strlcpy(klip->li_algorithm, lsp->ls_comp_algorithm,
		    sizeof (klip->li_algorithm));

		mutex_exit(&lofi_lock);
		error = copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
		free_lofi_ioctl(klip);
		return (error);
	default:
		free_lofi_ioctl(klip);
		return (EINVAL);
	}
}

static int
lofi_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp,
    int *rvalp)
{
	int	error;
	enum dkio_state dkstate;
	struct lofi_state *lsp;
	minor_t	minor;

	minor = getminor(dev);
	/* lofi ioctls only apply to the master device */
	if (minor == 0) {
		struct lofi_ioctl *lip = (struct lofi_ioctl *)arg;

		/*
		 * the query command only need read-access - i.e., normal
		 * users are allowed to do those on the ctl device as
		 * long as they can open it read-only.
		 */
		switch (cmd) {
		case LOFI_MAP_FILE:
			if ((flag & FWRITE) == 0)
				return (EPERM);
			return (lofi_map_file(dev, lip, 1, rvalp, credp, flag));
		case LOFI_MAP_FILE_MINOR:
			if ((flag & FWRITE) == 0)
				return (EPERM);
			return (lofi_map_file(dev, lip, 0, rvalp, credp, flag));
		case LOFI_UNMAP_FILE:
			if ((flag & FWRITE) == 0)
				return (EPERM);
			return (lofi_unmap_file(lip, 1, credp, flag));
		case LOFI_UNMAP_FILE_MINOR:
			if ((flag & FWRITE) == 0)
				return (EPERM);
			return (lofi_unmap_file(lip, 0, credp, flag));
		case LOFI_GET_FILENAME:
			return (lofi_get_info(dev, lip, LOFI_GET_FILENAME,
			    credp, flag));
		case LOFI_GET_MINOR:
			return (lofi_get_info(dev, lip, LOFI_GET_MINOR,
			    credp, flag));

		/*
		 * This API made limited sense when this value was fixed
		 * at LOFI_MAX_FILES.  However, its use to iterate
		 * across all possible devices in lofiadm means we don't
		 * want to return L_MAXMIN32, but the highest
		 * *allocated* minor.
		 */
		case LOFI_GET_MAXMINOR:
			minor = 0;

			mutex_enter(&lofi_lock);

			for (lsp = list_head(&lofi_list); lsp != NULL;
			    lsp = list_next(&lofi_list, lsp)) {
				if (lofi_access(lsp) != 0)
					continue;

				if (getminor(lsp->ls_dev) > minor)
					minor = getminor(lsp->ls_dev);
			}

			mutex_exit(&lofi_lock);

			error = ddi_copyout(&minor, &lip->li_minor,
			    sizeof (minor), flag);
			if (error)
				return (EFAULT);
			return (0);

		case LOFI_CHECK_COMPRESSED:
			return (lofi_get_info(dev, lip, LOFI_CHECK_COMPRESSED,
			    credp, flag));
		default:
			return (EINVAL);
		}
	}

	mutex_enter(&lofi_lock);
	lsp = ddi_get_soft_state(lofi_statep, minor);
	if (lsp == NULL || lsp->ls_vp_closereq) {
		mutex_exit(&lofi_lock);
		return (ENXIO);
	}
	mutex_exit(&lofi_lock);

	/*
	 * We explicitly allow DKIOCSTATE, but all other ioctls should fail with
	 * EIO as if the device was no longer present.
	 */
	if (lsp->ls_vp == NULL && cmd != DKIOCSTATE)
		return (EIO);

	/* these are for faking out utilities like newfs */
	switch (cmd) {
	case DKIOCGVTOC:
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct vtoc32 vtoc32;

			vtoctovtoc32(lsp->ls_vtoc, vtoc32);
			if (ddi_copyout(&vtoc32, (void *)arg,
			    sizeof (struct vtoc32), flag))
				return (EFAULT);
			break;
			}

		case DDI_MODEL_NONE:
			if (ddi_copyout(&lsp->ls_vtoc, (void *)arg,
			    sizeof (struct vtoc), flag))
				return (EFAULT);
			break;
		}
		return (0);
	case DKIOCINFO:
		error = ddi_copyout(&lsp->ls_ci, (void *)arg,
		    sizeof (struct dk_cinfo), flag);
		if (error)
			return (EFAULT);
		return (0);
	case DKIOCG_VIRTGEOM:
	case DKIOCG_PHYGEOM:
	case DKIOCGGEOM:
		error = ddi_copyout(&lsp->ls_dkg, (void *)arg,
		    sizeof (struct dk_geom), flag);
		if (error)
			return (EFAULT);
		return (0);
	case DKIOCSTATE:
		/*
		 * Normally, lofi devices are always in the INSERTED state.  If
		 * a device is forcefully unmapped, then the device transitions
		 * to the DKIO_DEV_GONE state.
		 */
		if (ddi_copyin((void *)arg, &dkstate, sizeof (dkstate),
		    flag) != 0)
			return (EFAULT);

		mutex_enter(&lsp->ls_vp_lock);
		lsp->ls_vp_iocount++;
		while (((dkstate == DKIO_INSERTED && lsp->ls_vp != NULL) ||
		    (dkstate == DKIO_DEV_GONE && lsp->ls_vp == NULL)) &&
		    !lsp->ls_vp_closereq) {
			/*
			 * By virtue of having the device open, we know that
			 * 'lsp' will remain valid when we return.
			 */
			if (!cv_wait_sig(&lsp->ls_vp_cv,
			    &lsp->ls_vp_lock)) {
				lsp->ls_vp_iocount--;
				cv_broadcast(&lsp->ls_vp_cv);
				mutex_exit(&lsp->ls_vp_lock);
				return (EINTR);
			}
		}

		dkstate = (!lsp->ls_vp_closereq && lsp->ls_vp != NULL ?
		    DKIO_INSERTED : DKIO_DEV_GONE);
		lsp->ls_vp_iocount--;
		cv_broadcast(&lsp->ls_vp_cv);
		mutex_exit(&lsp->ls_vp_lock);

		if (ddi_copyout(&dkstate, (void *)arg,
		    sizeof (dkstate), flag) != 0)
			return (EFAULT);
		return (0);
	default:
		return (ENOTTY);
	}
}

static struct cb_ops lofi_cb_ops = {
	lofi_open,		/* open */
	lofi_close,		/* close */
	lofi_strategy,		/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	lofi_read,		/* read */
	lofi_write,		/* write */
	lofi_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_64BIT | D_NEW | D_MP,	/* Driver compatibility flag */
	CB_REV,
	lofi_aread,
	lofi_awrite
};

static struct dev_ops lofi_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	lofi_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	lofi_attach,		/* attach */
	lofi_detach,		/* detach */
	nodev,			/* reset */
	&lofi_cb_ops,		/* driver operations */
	NULL,			/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"loopback file driver",
	&lofi_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int error;

	list_create(&lofi_list, sizeof (struct lofi_state),
	    offsetof(struct lofi_state, ls_list));

	error = ddi_soft_state_init(&lofi_statep,
	    sizeof (struct lofi_state), 0);
	if (error)
		return (error);

	mutex_init(&lofi_lock, NULL, MUTEX_DRIVER, NULL);

	error = mod_install(&modlinkage);
	if (error) {
		mutex_destroy(&lofi_lock);
		ddi_soft_state_fini(&lofi_statep);
		list_destroy(&lofi_list);
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	mutex_enter(&lofi_lock);

	if (!list_is_empty(&lofi_list)) {
		mutex_exit(&lofi_lock);
		return (EBUSY);
	}

	mutex_exit(&lofi_lock);

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	mutex_destroy(&lofi_lock);
	ddi_soft_state_fini(&lofi_statep);
	list_destroy(&lofi_list);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
