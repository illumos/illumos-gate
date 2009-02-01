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
 *	lofi on itself. The simple lock strategy (lofi_lock) precludes this
 *	because you'll be in lofi_ioctl, holding the lock when you open the
 *	file, which, if it's lofi, will grab lofi_lock. We prevent this for
 *	now, though not using ddi_soft_state(9F) would make it possible to
 *	do. Though it would still be silly.
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
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>

/*
 * The basis for CRYOFF is derived from usr/src/uts/common/sys/fs/ufs_fs.h.
 * Crypto metadata, if it exists, is located at the end of the boot block
 * (BBOFF + BBSIZE, which is SBOFF).  The super block and everything after
 * is offset by the size of the crypto metadata which is handled by
 * lsp->ls_crypto_offset.
 */
#define	CRYOFF	((off_t)8192)

#define	NBLOCKS_PROP_NAME	"Nblocks"
#define	SIZE_PROP_NAME		"Size"

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

uint32_t lofi_max_files = LOFI_MAX_FILES;
const char lofi_crypto_magic[6] = LOFI_CRYPTO_MAGIC;

static int gzip_decompress(void *src, size_t srclen, void *dst,
	size_t *destlen, int level);

lofi_compress_info_t lofi_compress_table[LOFI_COMPRESS_FUNCTIONS] = {
	{gzip_decompress,	NULL,	6,	"gzip"}, /* default */
	{gzip_decompress,	NULL,	6,	"gzip-6"},
	{gzip_decompress,	NULL,	9,	"gzip-9"}
};

static int
lofi_busy(void)
{
	minor_t	minor;

	/*
	 * We need to make sure no mappings exist - mod_remove won't
	 * help because the device isn't open.
	 */
	mutex_enter(&lofi_lock);
	for (minor = 1; minor <= lofi_max_files; minor++) {
		if (ddi_get_soft_state(lofi_statep, minor) != NULL) {
			mutex_exit(&lofi_lock);
			return (EBUSY);
		}
	}
	mutex_exit(&lofi_lock);
	return (0);
}

static int
is_opened(struct lofi_state *lsp)
{
	ASSERT(mutex_owned(&lofi_lock));
	return (lsp->ls_chr_open || lsp->ls_blk_open || lsp->ls_lyr_open_count);
}

static int
mark_opened(struct lofi_state *lsp, int otyp)
{
	ASSERT(mutex_owned(&lofi_lock));
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
	ASSERT(mutex_owned(&lofi_lock));
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
	ASSERT(mutex_owned(&lofi_lock));

	if (lsp->ls_crypto_enabled) {
		/*
		 * Clean up the crypto state so that it doesn't hang around
		 * in memory after we are done with it.
		 */
		bzero(lsp->ls_key.ck_data,
		    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
		kmem_free(lsp->ls_key.ck_data,
		    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
		lsp->ls_key.ck_data = NULL;
		lsp->ls_key.ck_length = 0;

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
lofi_free_handle(dev_t dev, minor_t minor, struct lofi_state *lsp,
    cred_t *credp)
{
	dev_t	newdev;
	char	namebuf[50];

	ASSERT(mutex_owned(&lofi_lock));

	lofi_free_crypto(lsp);

	if (lsp->ls_vp) {
		(void) VOP_CLOSE(lsp->ls_vp, lsp->ls_openflag,
		    1, 0, credp, NULL);
		VN_RELE(lsp->ls_vp);
		lsp->ls_vp = NULL;
	}

	newdev = makedevice(getmajor(dev), minor);
	(void) ddi_prop_remove(newdev, lofi_dip, SIZE_PROP_NAME);
	(void) ddi_prop_remove(newdev, lofi_dip, NBLOCKS_PROP_NAME);

	(void) snprintf(namebuf, sizeof (namebuf), "%d", minor);
	ddi_remove_minor_node(lofi_dip, namebuf);
	(void) snprintf(namebuf, sizeof (namebuf), "%d,raw", minor);
	ddi_remove_minor_node(lofi_dip, namebuf);

	kmem_free(lsp->ls_filename, lsp->ls_filename_sz);
	taskq_destroy(lsp->ls_taskq);
	if (lsp->ls_kstat) {
		kstat_delete(lsp->ls_kstat);
		mutex_destroy(&lsp->ls_kstat_lock);
	}

	if (lsp->ls_uncomp_seg_sz > 0) {
		kmem_free(lsp->ls_comp_index_data, lsp->ls_comp_index_data_sz);
		lsp->ls_uncomp_seg_sz = 0;
	}
	ddi_soft_state_free(lofi_statep, minor);
}

/*ARGSUSED*/
static int
lofi_open(dev_t *devp, int flag, int otyp, struct cred *credp)
{
	minor_t	minor;
	struct lofi_state *lsp;

	mutex_enter(&lofi_lock);
	minor = getminor(*devp);
	if (minor == 0) {
		/* master control device */
		/* must be opened exclusively */
		if (((flag & FEXCL) != FEXCL) || (otyp != OTYP_CHR)) {
			mutex_exit(&lofi_lock);
			return (EINVAL);
		}
		lsp = ddi_get_soft_state(lofi_statep, 0);
		if (lsp == NULL) {
			mutex_exit(&lofi_lock);
			return (ENXIO);
		}
		if (is_opened(lsp)) {
			mutex_exit(&lofi_lock);
			return (EBUSY);
		}
		(void) mark_opened(lsp, OTYP_CHR);
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
	mark_closed(lsp, otyp);

	/*
	 * If we forcibly closed the underlying device (li_force), or
	 * asked for cleanup (li_cleanup), finish up if we're the last
	 * out of the door.
	 */
	if (minor != 0 && !is_opened(lsp) &&
	    (lsp->ls_cleanup || lsp->ls_vp == NULL))
		lofi_free_handle(dev, minor, lsp, credp);

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

	ASSERT(mutex_owned(&lsp->ls_crypto_lock));

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
	 * MAXBSIZE after "alignedoffset".
	 */
	mapoffset = offset & MAXBOFFSET;
	alignedoffset = offset - mapoffset;
	bp->b_resid = bp->b_bcount;
	isread = bp->b_flags & B_READ;
	srw = isread ? S_READ : S_WRITE;
	do {
		xfersize = MIN(lsp->ls_vp_comp_size - offset,
		    MIN(MAXBSIZE - mapoffset, bp->b_resid));
		len = roundup(mapoffset + xfersize, MAXBSIZE);
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
			if (error == 0)		/* write back good pages */
				smflags |= SM_WRITE;
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

/*ARGSUSED*/
static int gzip_decompress(void *src, size_t srclen, void *dst,
    size_t *dstlen, int level)
{
	ASSERT(*dstlen >= srclen);

	if (z_uncompress(dst, dstlen, src, srclen) != Z_OK)
		return (-1);
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
		unsigned char *compressed_seg = NULL, *cmpbuf;
		unsigned char *uncompressed_seg = NULL;
		lofi_compress_info_t *li;
		size_t oblkcount;
		unsigned long seglen;
		uint64_t sblkno, eblkno, cmpbytes;
		offset_t sblkoff, eblkoff;
		u_offset_t salign, ealign;
		u_offset_t sdiff;
		uint32_t comp_data_sz;
		uint64_t i;

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
		 * Allocate fixed size memory blocks to hold compressed
		 * segments and one uncompressed segment since we
		 * uncompress segments one at a time
		 */
		compressed_seg = kmem_alloc(bp->b_bcount, KM_SLEEP);
		uncompressed_seg = kmem_alloc(lsp->ls_uncomp_seg_sz, KM_SLEEP);
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
		 * We have the compressed blocks, now uncompress them
		 */
		cmpbuf = compressed_seg + sdiff;
		for (i = sblkno; i < (eblkno + 1) && i < lsp->ls_comp_index_sz;
		    i++) {
			/*
			 * Each of the segment index entries contains
			 * the starting block number for that segment.
			 * The number of compressed bytes in a segment
			 * is thus the difference between the starting
			 * block number of this segment and the starting
			 * block number of the next segment.
			 */
			if ((i == eblkno) &&
			    (i == lsp->ls_comp_index_sz - 1)) {
				cmpbytes = lsp->ls_vp_comp_size -
				    lsp->ls_comp_seg_index[i];
			} else {
				cmpbytes = lsp->ls_comp_seg_index[i + 1] -
				    lsp->ls_comp_seg_index[i];
			}

			/*
			 * The first byte in a compressed segment is a flag
			 * that indicates whether this segment is compressed
			 * at all
			 */
			if (*cmpbuf == UNCOMPRESSED) {
				bcopy((cmpbuf + SEGHDR), uncompressed_seg,
				    (cmpbytes - SEGHDR));
			} else {
				seglen = lsp->ls_uncomp_seg_sz;

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
			if (i == eblkno) {
				if (i == (lsp->ls_comp_index_sz - 1))
					xfersize -= (lsp->ls_uncomp_last_seg_sz
					    - eblkoff);
				else
					xfersize -=
					    (lsp->ls_uncomp_seg_sz - eblkoff);
			}

			bcopy((uncompressed_seg + sblkoff), bufaddr, xfersize);

			cmpbuf += cmpbytes;
			bufaddr += xfersize;
			bp->b_resid -= xfersize;
			sblkoff = 0;

			if (bp->b_resid == 0)
				break;
		}
done:
		if (compressed_seg != NULL)
			kmem_free(compressed_seg, comp_data_sz);
		if (uncompressed_seg != NULL)
			kmem_free(uncompressed_seg, lsp->ls_uncomp_seg_sz);
	} /* end of handling compressed files */

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
	error = ddi_soft_state_zalloc(lofi_statep, 0);
	if (error == DDI_FAILURE) {
		return (DDI_FAILURE);
	}
	error = ddi_create_minor_node(dip, LOFI_CTL_NODE, S_IFCHR, 0,
	    DDI_PSEUDO, NULL);
	if (error == DDI_FAILURE) {
		ddi_soft_state_free(lofi_statep, 0);
		return (DDI_FAILURE);
	}
	/* driver handles kernel-issued IOCTLs */
	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0) != DDI_PROP_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(lofi_statep, 0);
		return (DDI_FAILURE);
	}
	lofi_dip = dip;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
lofi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (lofi_busy())
		return (DDI_FAILURE);
	lofi_dip = NULL;
	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(dip);
	ddi_soft_state_free(lofi_statep, 0);
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
struct lofi_ioctl *
copy_in_lofi_ioctl(const struct lofi_ioctl *ulip, int flag)
{
	struct lofi_ioctl *klip;
	int	error;

	klip = kmem_alloc(sizeof (struct lofi_ioctl), KM_SLEEP);
	error = ddi_copyin(ulip, klip, sizeof (struct lofi_ioctl), flag);
	if (error) {
		free_lofi_ioctl(klip);
		return (NULL);
	}

	/* make sure filename is always null-terminated */
	klip->li_filename[MAXPATHLEN-1] = '\0';

	/* validate minor number */
	if (klip->li_minor > lofi_max_files) {
		free_lofi_ioctl(klip);
		cmn_err(CE_WARN, "attempt to map more than lofi_max_files (%d)",
		    lofi_max_files);
		return (NULL);
	}
	return (klip);
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

/*
 * Return the minor number 'filename' is mapped to, if it is.
 */
static int
file_to_minor(char *filename)
{
	minor_t	minor;
	struct lofi_state *lsp;

	ASSERT(mutex_owned(&lofi_lock));
	for (minor = 1; minor <= lofi_max_files; minor++) {
		lsp = ddi_get_soft_state(lofi_statep, minor);
		if (lsp == NULL)
			continue;
		if (strcmp(lsp->ls_filename, filename) == 0)
			return (minor);
	}
	return (0);
}

/*
 * lofiadm does some validation, but since Joe Random (or crashme) could
 * do our ioctls, we need to do some validation too.
 */
static int
valid_filename(const char *filename)
{
	static char *blkprefix = "/dev/" LOFI_BLOCK_NAME "/";
	static char *charprefix = "/dev/" LOFI_CHAR_NAME "/";

	/* must be absolute path */
	if (filename[0] != '/')
		return (0);
	/* must not be lofi */
	if (strncmp(filename, blkprefix, strlen(blkprefix)) == 0)
		return (0);
	if (strncmp(filename, charprefix, strlen(charprefix)) == 0)
		return (0);
	return (1);
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
	if (lsp->ls_uncomp_seg_sz % 2)
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
	lsp->ls_vp_size = (lsp->ls_comp_index_sz - 2) * lsp->ls_uncomp_seg_sz
	    + lsp->ls_uncomp_last_seg_sz;

	/*
	 * Index size is rounded up to a 512 byte boundary for ease
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

/*
 * Check to see if the passed in signature is a valid
 * one.  If it is valid, return the index into
 * lofi_compress_table.
 *
 * Return -1 if it is invalid
 */
static int lofi_compress_select(char *signature)
{
	int i;

	for (i = 0; i < LOFI_COMPRESS_FUNCTIONS; i++) {
		if (strcmp(lofi_compress_table[i].l_name, signature) == 0)
			return (i);
	}

	return (-1);
}

/*
 * map a file to a minor number. Return the minor number.
 */
static int
lofi_map_file(dev_t dev, struct lofi_ioctl *ulip, int pickminor,
    int *rvalp, struct cred *credp, int ioctl_flag)
{
	minor_t	newminor;
	struct lofi_state *lsp;
	struct lofi_ioctl *klip;
	int	error;
	struct vnode *vp;
	int64_t	Nblocks_prop_val;
	int64_t	Size_prop_val;
	int	compress_index;
	vattr_t	vattr;
	int	flag;
	enum vtype v_type;
	int zalloced = 0;
	dev_t	newdev;
	char	namebuf[50];
	char	buf[DEV_BSIZE];
	char	crybuf[DEV_BSIZE];
	ssize_t	resid;
	boolean_t need_vn_close = B_FALSE;
	boolean_t keycopied = B_FALSE;
	boolean_t need_size_update = B_FALSE;

	klip = copy_in_lofi_ioctl(ulip, ioctl_flag);
	if (klip == NULL)
		return (EFAULT);

	mutex_enter(&lofi_lock);

	if (!valid_filename(klip->li_filename)) {
		error = EINVAL;
		goto out;
	}

	if (file_to_minor(klip->li_filename) != 0) {
		error = EBUSY;
		goto out;
	}

	if (pickminor) {
		/* Find a free one */
		for (newminor = 1; newminor <= lofi_max_files; newminor++)
			if (ddi_get_soft_state(lofi_statep, newminor) == NULL)
				break;
		if (newminor >= lofi_max_files) {
			error = EAGAIN;
			goto out;
		}
	} else {
		newminor = klip->li_minor;
		if (ddi_get_soft_state(lofi_statep, newminor) != NULL) {
			error = EEXIST;
			goto out;
		}
	}

	/* make sure it's valid */
	error = lookupname(klip->li_filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &vp);
	if (error) {
		goto out;
	}
	v_type = vp->v_type;
	VN_RELE(vp);
	if (!V_ISLOFIABLE(v_type)) {
		error = EINVAL;
		goto out;
	}
	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	error = vn_open(klip->li_filename, UIO_SYSSPACE, flag, 0, &vp, 0, 0);
	if (error) {
		/* try read-only */
		flag &= ~FWRITE;
		error = vn_open(klip->li_filename, UIO_SYSSPACE, flag, 0,
		    &vp, 0, 0);
		if (error) {
			goto out;
		}
	}
	need_vn_close = B_TRUE;

	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, credp, NULL);
	if (error) {
		goto out;
	}
	/* the file needs to be a multiple of the block size */
	if ((vattr.va_size % DEV_BSIZE) != 0) {
		error = EINVAL;
		goto out;
	}
	newdev = makedevice(getmajor(dev), newminor);
	Size_prop_val = vattr.va_size;
	if ((ddi_prop_update_int64(newdev, lofi_dip,
	    SIZE_PROP_NAME, Size_prop_val)) != DDI_PROP_SUCCESS) {
		error = EINVAL;
		goto out;
	}
	Nblocks_prop_val = vattr.va_size / DEV_BSIZE;
	if ((ddi_prop_update_int64(newdev, lofi_dip,
	    NBLOCKS_PROP_NAME, Nblocks_prop_val)) != DDI_PROP_SUCCESS) {
		error = EINVAL;
		goto propout;
	}
	error = ddi_soft_state_zalloc(lofi_statep, newminor);
	if (error == DDI_FAILURE) {
		error = ENOMEM;
		goto propout;
	}
	zalloced = 1;
	(void) snprintf(namebuf, sizeof (namebuf), "%d", newminor);
	error = ddi_create_minor_node(lofi_dip, namebuf, S_IFBLK, newminor,
	    DDI_PSEUDO, NULL);
	if (error != DDI_SUCCESS) {
		error = ENXIO;
		goto propout;
	}
	(void) snprintf(namebuf, sizeof (namebuf), "%d,raw", newminor);
	error = ddi_create_minor_node(lofi_dip, namebuf, S_IFCHR, newminor,
	    DDI_PSEUDO, NULL);
	if (error != DDI_SUCCESS) {
		/* remove block node */
		(void) snprintf(namebuf, sizeof (namebuf), "%d", newminor);
		ddi_remove_minor_node(lofi_dip, namebuf);
		error = ENXIO;
		goto propout;
	}
	lsp = ddi_get_soft_state(lofi_statep, newminor);
	lsp->ls_filename_sz = strlen(klip->li_filename) + 1;
	lsp->ls_filename = kmem_alloc(lsp->ls_filename_sz, KM_SLEEP);
	(void) snprintf(namebuf, sizeof (namebuf), "%s_taskq_%d",
	    LOFI_DRIVER_NAME, newminor);
	lsp->ls_taskq = taskq_create(namebuf, lofi_taskq_nthreads,
	    minclsyspri, 1, lofi_taskq_maxalloc, 0);
	lsp->ls_kstat = kstat_create(LOFI_DRIVER_NAME, newminor,
	    NULL, "disk", KSTAT_TYPE_IO, 1, 0);
	if (lsp->ls_kstat) {
		mutex_init(&lsp->ls_kstat_lock, NULL, MUTEX_DRIVER, NULL);
		lsp->ls_kstat->ks_lock = &lsp->ls_kstat_lock;
		kstat_install(lsp->ls_kstat);
	}
	cv_init(&lsp->ls_vp_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&lsp->ls_vp_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * save open mode so file can be closed properly and vnode counts
	 * updated correctly.
	 */
	lsp->ls_openflag = flag;

	/*
	 * Try to handle stacked lofs vnodes.
	 */
	if (vp->v_type == VREG) {
		if (VOP_REALVP(vp, &lsp->ls_vp, NULL) != 0) {
			lsp->ls_vp = vp;
		} else {
			/*
			 * Even though vp was obtained via vn_open(), we
			 * can't call vn_close() on it, since lofs will
			 * pass the VOP_CLOSE() on down to the realvp
			 * (which we are about to use). Hence we merely
			 * drop the reference to the lofs vnode and hold
			 * the realvp so things behave as if we've
			 * opened the realvp without any interaction
			 * with lofs.
			 */
			VN_HOLD(lsp->ls_vp);
			VN_RELE(vp);
		}
	} else {
		lsp->ls_vp = vp;
	}
	lsp->ls_vp_size = vattr.va_size;
	(void) strcpy(lsp->ls_filename, klip->li_filename);
	if (rvalp)
		*rvalp = (int)newminor;
	klip->li_minor = newminor;

	/*
	 * Initialize crypto details for encrypted lofi
	 */
	if (klip->li_crypto_enabled) {
		int ret;

		mutex_init(&lsp->ls_crypto_lock, NULL, MUTEX_DRIVER, NULL);

		lsp->ls_mech.cm_type = crypto_mech2id(klip->li_cipher);
		if (lsp->ls_mech.cm_type == CRYPTO_MECH_INVALID) {
			cmn_err(CE_WARN, "invalid cipher %s requested for %s",
			    klip->li_cipher, lsp->ls_filename);
			error = EINVAL;
			goto propout;
		}

		/* this is just initialization here */
		lsp->ls_mech.cm_param = NULL;
		lsp->ls_mech.cm_param_len = 0;

		lsp->ls_iv_type = klip->li_iv_type;
		lsp->ls_iv_mech.cm_type = crypto_mech2id(klip->li_iv_cipher);
		if (lsp->ls_iv_mech.cm_type == CRYPTO_MECH_INVALID) {
			cmn_err(CE_WARN, "invalid iv cipher %s requested"
			    " for %s", klip->li_iv_cipher, lsp->ls_filename);
			error = EINVAL;
			goto propout;
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
		keycopied = B_TRUE;

		ret = crypto_key_check(&lsp->ls_mech, &lsp->ls_key);
		if (ret != CRYPTO_SUCCESS) {
			error = EINVAL;
			cmn_err(CE_WARN, "weak key check failed for cipher "
			    "%s on file %s (0x%x)", klip->li_cipher,
			    lsp->ls_filename, ret);
			goto propout;
		}
	}
	lsp->ls_crypto_enabled = klip->li_crypto_enabled;

	/*
	 * Read the file signature to check if it is compressed or encrypted.
	 * Crypto signature is in a different location; both areas should
	 * read to keep compression and encryption mutually exclusive.
	 */
	if (lsp->ls_crypto_enabled) {
		error = vn_rdwr(UIO_READ, lsp->ls_vp, crybuf, DEV_BSIZE,
		    CRYOFF, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);
		if (error != 0)
			goto propout;
	}
	error = vn_rdwr(UIO_READ, lsp->ls_vp, buf, DEV_BSIZE, 0, UIO_SYSSPACE,
	    0, RLIM64_INFINITY, kcred, &resid);
	if (error != 0)
		goto propout;

	/* initialize these variables for all lofi files */
	lsp->ls_uncomp_seg_sz = 0;
	lsp->ls_vp_comp_size = lsp->ls_vp_size;
	lsp->ls_comp_algorithm[0] = '\0';

	/* encrypted lofi reads/writes shifted by crypto metadata size */
	lsp->ls_crypto_offset = 0;

	/* this is a compressed lofi */
	if ((compress_index = lofi_compress_select(buf)) != -1) {

		/* compression and encryption are mutually exclusive */
		if (klip->li_crypto_enabled) {
			error = ENOTSUP;
			goto propout;
		}

		/* initialize compression info for compressed lofi */
		lsp->ls_comp_algorithm_index = compress_index;
		(void) strlcpy(lsp->ls_comp_algorithm,
		    lofi_compress_table[compress_index].l_name,
		    sizeof (lsp->ls_comp_algorithm));

		error = lofi_map_compressed_file(lsp, buf);
		if (error != 0)
			goto propout;
		need_size_update = B_TRUE;

	/* this is an encrypted lofi */
	} else if (strncmp(crybuf, lofi_crypto_magic,
	    sizeof (lofi_crypto_magic)) == 0) {

		char *marker = crybuf;

		/*
		 * This is the case where the header in the lofi image is
		 * already initialized to indicate it is encrypted.
		 * There is another case (see below) where encryption is
		 * requested but the lofi image has never been used yet,
		 * so the header needs to be written with encryption magic.
		 */

		/* indicate this must be an encrypted lofi due to magic */
		klip->li_crypto_enabled = B_TRUE;

		/*
		 * The encryption header information is laid out this way:
		 *	6 bytes:	hex "CFLOFI"
		 *	2 bytes:	version = 0 ... for now
		 *	96 bytes:	reserved1 (not implemented yet)
		 *	4 bytes:	data_sector = 2 ... for now
		 *	more...		not implemented yet
		 */

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
		need_size_update = B_TRUE;

	/* neither compressed nor encrypted, BUT could be new encrypted lofi */
	} else if (klip->li_crypto_enabled) {

		/*
		 * This is the case where encryption was requested but the
		 * appears to be entirely blank where the encryption header
		 * would have been in the lofi image.  If it is blank,
		 * assume it is a brand new lofi image and initialize the
		 * header area with encryption magic and current version
		 * header data.  If it is not blank, that's an error.
		 */
		int	i;
		char	*marker;
		struct crypto_meta	chead;

		for (i = 0; i < sizeof (struct crypto_meta); i++)
			if (crybuf[i] != '\0')
				break;
		if (i != sizeof (struct crypto_meta)) {
			error = EINVAL;
			goto propout;
		}

		/* nothing there, initialize as encrypted lofi */
		marker = crybuf;
		bcopy(lofi_crypto_magic, marker, sizeof (lofi_crypto_magic));
		marker += sizeof (lofi_crypto_magic);
		chead.version = htons(LOFI_CRYPTO_VERSION);
		bcopy(&(chead.version), marker, sizeof (chead.version));
		marker += sizeof (chead.version);
		marker += sizeof (chead.reserved1);
		chead.data_sector = htonl(LOFI_CRYPTO_DATA_SECTOR);
		bcopy(&(chead.data_sector), marker, sizeof (chead.data_sector));

		/* write the header */
		error = vn_rdwr(UIO_WRITE, lsp->ls_vp, crybuf, DEV_BSIZE,
		    CRYOFF, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);
		if (error != 0)
			goto propout;

		/* fix things up so it looks like we read this info */
		bcopy(lofi_crypto_magic, lsp->ls_crypto.magic,
		    sizeof (lofi_crypto_magic));
		lsp->ls_crypto.version = LOFI_CRYPTO_VERSION;
		lsp->ls_crypto.data_sector = LOFI_CRYPTO_DATA_SECTOR;

		lsp->ls_crypto_offset = lsp->ls_crypto.data_sector * DEV_BSIZE;
		need_size_update = B_TRUE;
	}

	/*
	 * Either lsp->ls_vp_size or lsp->ls_crypto_offset changed;
	 * for encrypted lofi, advertise that it is somewhat shorter
	 * due to embedded crypto metadata section
	 */
	if (need_size_update) {
		/* update DDI properties */
		Size_prop_val = lsp->ls_vp_size - lsp->ls_crypto_offset;
		if ((ddi_prop_update_int64(newdev, lofi_dip, SIZE_PROP_NAME,
		    Size_prop_val)) != DDI_PROP_SUCCESS) {
			error = EINVAL;
			goto propout;
		}
		Nblocks_prop_val =
		    (lsp->ls_vp_size - lsp->ls_crypto_offset) / DEV_BSIZE;
		if ((ddi_prop_update_int64(newdev, lofi_dip, NBLOCKS_PROP_NAME,
		    Nblocks_prop_val)) != DDI_PROP_SUCCESS) {
			error = EINVAL;
			goto propout;
		}
	}

	fake_disk_geometry(lsp);
	mutex_exit(&lofi_lock);
	(void) copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
	free_lofi_ioctl(klip);
	return (0);

propout:
	if (keycopied) {
		bzero(lsp->ls_key.ck_data,
		    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
		kmem_free(lsp->ls_key.ck_data,
		    CRYPTO_BITS2BYTES(lsp->ls_key.ck_length));
		lsp->ls_key.ck_data = NULL;
		lsp->ls_key.ck_length = 0;
	}

	if (zalloced)
		ddi_soft_state_free(lofi_statep, newminor);

	(void) ddi_prop_remove(newdev, lofi_dip, SIZE_PROP_NAME);
	(void) ddi_prop_remove(newdev, lofi_dip, NBLOCKS_PROP_NAME);

out:
	if (need_vn_close) {
		(void) VOP_CLOSE(vp, flag, 1, 0, credp, NULL);
		VN_RELE(vp);
	}

	mutex_exit(&lofi_lock);
	free_lofi_ioctl(klip);
	return (error);
}

/*
 * unmap a file.
 */
static int
lofi_unmap_file(dev_t dev, struct lofi_ioctl *ulip, int byfilename,
    struct cred *credp, int ioctl_flag)
{
	struct lofi_state *lsp;
	struct lofi_ioctl *klip;
	minor_t	minor;

	klip = copy_in_lofi_ioctl(ulip, ioctl_flag);
	if (klip == NULL)
		return (EFAULT);

	mutex_enter(&lofi_lock);
	if (byfilename) {
		minor = file_to_minor(klip->li_filename);
	} else {
		minor = klip->li_minor;
	}
	if (minor == 0) {
		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (ENXIO);
	}
	lsp = ddi_get_soft_state(lofi_statep, minor);
	if (lsp == NULL || lsp->ls_vp == NULL) {
		mutex_exit(&lofi_lock);
		free_lofi_ioctl(klip);
		return (ENXIO);
	}

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
			/*
			 * XXX: the section marked here should probably be
			 * carefully incorporated into lofi_free_handle();
			 * afterward just replace this section with:
			 *	lofi_free_handle(dev, minor, lsp, credp);
			 * and clean up lofi_unmap_file() a bit more
			 */
			lofi_free_crypto(lsp);

			mutex_enter(&lsp->ls_vp_lock);
			lsp->ls_vp_closereq = B_TRUE;
			while (lsp->ls_vp_iocount > 0)
				cv_wait(&lsp->ls_vp_cv, &lsp->ls_vp_lock);
			(void) VOP_CLOSE(lsp->ls_vp, lsp->ls_openflag, 1, 0,
			    credp, NULL);
			VN_RELE(lsp->ls_vp);
			lsp->ls_vp = NULL;
			cv_broadcast(&lsp->ls_vp_cv);
			mutex_exit(&lsp->ls_vp_lock);
			/*
			 * XXX: to here
			 */

			klip->li_minor = minor;
			mutex_exit(&lofi_lock);
			(void) copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
			free_lofi_ioctl(klip);
			return (0);
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

	lofi_free_handle(dev, minor, lsp, credp);

	klip->li_minor = minor;
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
	struct lofi_state *lsp;
	struct lofi_ioctl *klip;
	int	error;
	minor_t	minor;

	klip = copy_in_lofi_ioctl(ulip, ioctl_flag);
	if (klip == NULL)
		return (EFAULT);

	switch (which) {
	case LOFI_GET_FILENAME:
		minor = klip->li_minor;
		if (minor == 0) {
			free_lofi_ioctl(klip);
			return (EINVAL);
		}

		mutex_enter(&lofi_lock);
		lsp = ddi_get_soft_state(lofi_statep, minor);
		if (lsp == NULL) {
			mutex_exit(&lofi_lock);
			free_lofi_ioctl(klip);
			return (ENXIO);
		}
		(void) strcpy(klip->li_filename, lsp->ls_filename);
		(void) strlcpy(klip->li_algorithm, lsp->ls_comp_algorithm,
		    sizeof (klip->li_algorithm));
		klip->li_crypto_enabled = lsp->ls_crypto_enabled;
		mutex_exit(&lofi_lock);
		error = copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
		free_lofi_ioctl(klip);
		return (error);
	case LOFI_GET_MINOR:
		mutex_enter(&lofi_lock);
		klip->li_minor = file_to_minor(klip->li_filename);
		/* caller should not depend on klip->li_crypto_enabled here */
		mutex_exit(&lofi_lock);
		if (klip->li_minor == 0) {
			free_lofi_ioctl(klip);
			return (ENOENT);
		}
		error = copy_out_lofi_ioctl(klip, ulip, ioctl_flag);
		free_lofi_ioctl(klip);
		return (error);
	case LOFI_CHECK_COMPRESSED:
		mutex_enter(&lofi_lock);
		klip->li_minor = file_to_minor(klip->li_filename);
		mutex_exit(&lofi_lock);
		if (klip->li_minor == 0) {
			free_lofi_ioctl(klip);
			return (ENOENT);
		}
		mutex_enter(&lofi_lock);
		lsp = ddi_get_soft_state(lofi_statep, klip->li_minor);
		if (lsp == NULL) {
			mutex_exit(&lofi_lock);
			free_lofi_ioctl(klip);
			return (ENXIO);
		}
		ASSERT(strcmp(klip->li_filename, lsp->ls_filename) == 0);

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
			return (lofi_unmap_file(dev, lip, 1, credp, flag));
		case LOFI_UNMAP_FILE_MINOR:
			if ((flag & FWRITE) == 0)
				return (EPERM);
			return (lofi_unmap_file(dev, lip, 0, credp, flag));
		case LOFI_GET_FILENAME:
			return (lofi_get_info(dev, lip, LOFI_GET_FILENAME,
			    credp, flag));
		case LOFI_GET_MINOR:
			return (lofi_get_info(dev, lip, LOFI_GET_MINOR,
			    credp, flag));
		case LOFI_GET_MAXMINOR:
			error = ddi_copyout(&lofi_max_files, &lip->li_minor,
			    sizeof (lofi_max_files), flag);
			if (error)
				return (EFAULT);
			return (0);
		case LOFI_CHECK_COMPRESSED:
			return (lofi_get_info(dev, lip, LOFI_CHECK_COMPRESSED,
			    credp, flag));
		default:
			break;
		}
	}

	lsp = ddi_get_soft_state(lofi_statep, minor);
	if (lsp == NULL)
		return (ENXIO);

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
		while ((dkstate == DKIO_INSERTED && lsp->ls_vp != NULL) ||
		    (dkstate == DKIO_DEV_GONE && lsp->ls_vp == NULL)) {
			/*
			 * By virtue of having the device open, we know that
			 * 'lsp' will remain valid when we return.
			 */
			if (!cv_wait_sig(&lsp->ls_vp_cv,
			    &lsp->ls_vp_lock)) {
				mutex_exit(&lsp->ls_vp_lock);
				return (EINTR);
			}
		}

		dkstate = (lsp->ls_vp != NULL ? DKIO_INSERTED : DKIO_DEV_GONE);
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

	error = ddi_soft_state_init(&lofi_statep,
	    sizeof (struct lofi_state), 0);
	if (error)
		return (error);

	mutex_init(&lofi_lock, NULL, MUTEX_DRIVER, NULL);
	error = mod_install(&modlinkage);
	if (error) {
		mutex_destroy(&lofi_lock);
		ddi_soft_state_fini(&lofi_statep);
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	if (lofi_busy())
		return (EBUSY);

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	mutex_destroy(&lofi_lock);
	ddi_soft_state_fini(&lofi_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
