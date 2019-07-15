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
 * Copyright (c) 2015, Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2012, Alexey Zaytsev <alexey.zaytsev@gmail.com>
 * Copyright 2019 Joyent Inc.
 */

/*
 * VIRTIO BLOCK DRIVER
 *
 * This driver provides support for Virtio Block devices.  Each driver instance
 * attaches to a single underlying block device.
 *
 * REQUEST CHAIN LAYOUT
 *
 * Every request chain sent to the I/O queue has the following structure.  Each
 * box in the diagram represents a descriptor entry (i.e., a DMA cookie) within
 * the chain:
 *
 *    +-0-----------------------------------------+
 *    | struct virtio_blk_hdr                     |-----------------------\
 *    |   (written by driver, read by device)     |                       |
 *    +-1-----------------------------------------+                       |
 *    | optional data payload                     |--\                    |
 *    |   (written by driver for write requests,  |  |                    |
 *    |    or by device for read requests)        |  |                    |
 *    +-2-----------------------------------------+  |                    |
 *    | ,~`           :                              |-cookies loaned     |
 *    |/              :                        ,~`|  | from blkdev        |
 *                    :                       /   |  |                    |
 *    +-(N - 1)-----------------------------------+  |                    |
 *    | ... end of data payload.                  |  |                    |
 *    |                                           |  |                    |
 *    |                                           |--/                    |
 *    +-N-----------------------------------------+                       |
 *    | status byte                               |                       |
 *    |   (written by device, read by driver)     |--------------------\  |
 *    +-------------------------------------------+                    |  |
 *                                                                     |  |
 * The memory for the header and status bytes (i.e., 0 and N above)    |  |
 * is allocated as a single chunk by vioblk_alloc_reqs():              |  |
 *                                                                     |  |
 *    +-------------------------------------------+                    |  |
 *    | struct virtio_blk_hdr                     |<----------------------/
 *    +-------------------------------------------+                    |
 *    | status byte                               |<-------------------/
 *    +-------------------------------------------+
 */

#include <sys/modctl.h>
#include <sys/blkdev.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/containerof.h>
#include <sys/ctype.h>
#include <sys/sysmacros.h>

#include "virtio.h"
#include "vioblk.h"


static void vioblk_get_id(vioblk_t *);
uint_t vioblk_int_handler(caddr_t, caddr_t);
static uint_t vioblk_poll(vioblk_t *);
static int vioblk_quiesce(dev_info_t *);
static int vioblk_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioblk_detach(dev_info_t *, ddi_detach_cmd_t);


static struct dev_ops vioblk_dev_ops = {
	.devo_rev =			DEVO_REV,
	.devo_refcnt =			0,

	.devo_attach =			vioblk_attach,
	.devo_detach =			vioblk_detach,
	.devo_quiesce =			vioblk_quiesce,

	.devo_getinfo =			ddi_no_info,
	.devo_identify =		nulldev,
	.devo_probe =			nulldev,
	.devo_reset =			nodev,
	.devo_cb_ops =			NULL,
	.devo_bus_ops =			NULL,
	.devo_power =			NULL,
};

static struct modldrv vioblk_modldrv = {
	.drv_modops =			&mod_driverops,
	.drv_linkinfo =			"VIRTIO block driver",
	.drv_dev_ops =			&vioblk_dev_ops
};

static struct modlinkage vioblk_modlinkage = {
	.ml_rev =			MODREV_1,
	.ml_linkage =			{ &vioblk_modldrv, NULL }
};

/*
 * DMA attribute template for header and status blocks.  We also make a
 * per-instance copy of this template with negotiated sizes from the device for
 * blkdev.
 */
static const ddi_dma_attr_t vioblk_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};


static vioblk_req_t *
vioblk_req_alloc(vioblk_t *vib)
{
	vioblk_req_t *vbr;

	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	if ((vbr = list_remove_head(&vib->vib_reqs)) == NULL) {
		return (NULL);
	}
	vib->vib_nreqs_alloc++;

	VERIFY0(vbr->vbr_status);
	vbr->vbr_status |= VIOBLK_REQSTAT_ALLOCATED;

	VERIFY3P(vbr->vbr_xfer, ==, NULL);
	VERIFY3S(vbr->vbr_error, ==, 0);

	return (vbr);
}

static void
vioblk_req_free(vioblk_t *vib, vioblk_req_t *vbr)
{
	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	/*
	 * Check that this request was allocated, then zero the status field to
	 * clear all status bits.
	 */
	VERIFY(vbr->vbr_status & VIOBLK_REQSTAT_ALLOCATED);
	vbr->vbr_status = 0;

	vbr->vbr_xfer = NULL;
	vbr->vbr_error = 0;
	vbr->vbr_type = 0;

	list_insert_head(&vib->vib_reqs, vbr);

	VERIFY3U(vib->vib_nreqs_alloc, >, 0);
	vib->vib_nreqs_alloc--;
}

static void
vioblk_complete(vioblk_t *vib, vioblk_req_t *vbr)
{
	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	VERIFY(!(vbr->vbr_status & VIOBLK_REQSTAT_COMPLETE));
	vbr->vbr_status |= VIOBLK_REQSTAT_COMPLETE;

	if (vbr->vbr_type == VIRTIO_BLK_T_FLUSH) {
		vib->vib_stats->vbs_rw_cacheflush.value.ui64++;
	}

	if (vbr->vbr_xfer != NULL) {
		/*
		 * This is a blkdev framework request.
		 */
		mutex_exit(&vib->vib_mutex);
		bd_xfer_done(vbr->vbr_xfer, vbr->vbr_error);
		mutex_enter(&vib->vib_mutex);
		vbr->vbr_xfer = NULL;
	}
}

static virtio_chain_t *
vioblk_common_start(vioblk_t *vib, int type, uint64_t sector,
    boolean_t polled)
{
	vioblk_req_t *vbr = NULL;
	virtio_chain_t *vic = NULL;

	if ((vbr = vioblk_req_alloc(vib)) == NULL) {
		vib->vib_stats->vbs_rw_outofmemory.value.ui64++;
		return (NULL);
	}
	vbr->vbr_type = type;

	if (polled) {
		/*
		 * Mark this command as polled so that we can wait on it
		 * ourselves.
		 */
		vbr->vbr_status |= VIOBLK_REQSTAT_POLLED;
	}

	if ((vic = virtio_chain_alloc(vib->vib_vq, KM_NOSLEEP)) == NULL) {
		vib->vib_stats->vbs_rw_outofmemory.value.ui64++;
		goto fail;
	}

	struct vioblk_req_hdr vbh;
	vbh.vbh_type = type;
	vbh.vbh_ioprio = 0;
	vbh.vbh_sector = (sector * vib->vib_blk_size) / DEV_BSIZE;
	bcopy(&vbh, virtio_dma_va(vbr->vbr_dma, 0), sizeof (vbh));

	virtio_chain_data_set(vic, vbr);

	/*
	 * Put the header in the first descriptor.  See the block comment at
	 * the top of the file for more details on the chain layout.
	 */
	if (virtio_chain_append(vic, virtio_dma_cookie_pa(vbr->vbr_dma, 0),
	    sizeof (struct vioblk_req_hdr), VIRTIO_DIR_DEVICE_READS) !=
	    DDI_SUCCESS) {
		goto fail;
	}

	return (vic);

fail:
	vbr->vbr_xfer = NULL;
	vioblk_req_free(vib, vbr);
	if (vic != NULL) {
		virtio_chain_free(vic);
	}
	return (NULL);
}

static int
vioblk_common_submit(vioblk_t *vib, virtio_chain_t *vic)
{
	int r;
	vioblk_req_t *vbr = virtio_chain_data(vic);

	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	/*
	 * The device will write the status byte into this last descriptor.
	 * See the block comment at the top of the file for more details on the
	 * chain layout.
	 */
	if (virtio_chain_append(vic, virtio_dma_cookie_pa(vbr->vbr_dma, 0) +
	    sizeof (struct vioblk_req_hdr), sizeof (uint8_t),
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		r = ENOMEM;
		goto out;
	}

	virtio_dma_sync(vbr->vbr_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(vic, B_TRUE);

	if (!(vbr->vbr_status & VIOBLK_REQSTAT_POLLED)) {
		/*
		 * This is not a polled request.  Our request will be freed and
		 * the caller notified later in vioblk_poll().
		 */
		return (0);
	}

	/*
	 * This is a polled request.  We need to block here and wait for the
	 * device to complete request processing.
	 */
	while (!(vbr->vbr_status & VIOBLK_REQSTAT_POLL_COMPLETE)) {
		if (ddi_in_panic()) {
			/*
			 * When panicking, interrupts are disabled.  We must
			 * poll the queue manually.
			 */
			drv_usecwait(10);
			(void) vioblk_poll(vib);
			continue;
		}

		/*
		 * When not panicking, the device will interrupt on command
		 * completion and vioblk_poll() will be called to wake us up.
		 */
		cv_wait(&vib->vib_cv, &vib->vib_mutex);
	}

	vioblk_complete(vib, vbr);
	r = vbr->vbr_error;

out:
	vioblk_req_free(vib, vbr);
	virtio_chain_free(vic);
	return (r);
}

static int
vioblk_internal(vioblk_t *vib, int type, virtio_dma_t *dma,
    uint64_t sector, virtio_direction_t dir)
{
	virtio_chain_t *vic;
	vioblk_req_t *vbr;
	int r;

	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	/*
	 * Allocate a polled request.
	 */
	if ((vic = vioblk_common_start(vib, type, sector, B_TRUE)) == NULL) {
		return (ENOMEM);
	}
	vbr = virtio_chain_data(vic);

	/*
	 * If there is a request payload, it goes between the header and the
	 * status byte.  See the block comment at the top of the file for more
	 * detail on the chain layout.
	 */
	if (dma != NULL) {
		for (uint_t n = 0; n < virtio_dma_ncookies(dma); n++) {
			if (virtio_chain_append(vic,
			    virtio_dma_cookie_pa(dma, n),
			    virtio_dma_cookie_size(dma, n), dir) !=
			    DDI_SUCCESS) {
				r = ENOMEM;
				goto out;
			}
		}
	}

	return (vioblk_common_submit(vib, vic));

out:
	vioblk_req_free(vib, vbr);
	virtio_chain_free(vic);
	return (r);
}

static int
vioblk_request(vioblk_t *vib, bd_xfer_t *xfer, int type)
{
	virtio_chain_t *vic = NULL;
	vioblk_req_t *vbr = NULL;
	uint_t total_cookies = 2;
	boolean_t polled = (xfer->x_flags & BD_XFER_POLL) != 0;
	int r;

	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	/*
	 * Ensure that this request falls within the advertised size of the
	 * block device.  Be careful to avoid overflow.
	 */
	if (xfer->x_nblks > SIZE_MAX - xfer->x_blkno ||
	    (xfer->x_blkno + xfer->x_nblks) > vib->vib_nblks) {
		vib->vib_stats->vbs_rw_badoffset.value.ui64++;
		return (EINVAL);
	}

	if ((vic = vioblk_common_start(vib, type, xfer->x_blkno, polled)) ==
	    NULL) {
		return (ENOMEM);
	}
	vbr = virtio_chain_data(vic);
	vbr->vbr_xfer = xfer;

	/*
	 * If there is a request payload, it goes between the header and the
	 * status byte.  See the block comment at the top of the file for more
	 * detail on the chain layout.
	 */
	if ((type == VIRTIO_BLK_T_IN || type == VIRTIO_BLK_T_OUT) &&
	    xfer->x_nblks > 0) {
		virtio_direction_t dir = (type == VIRTIO_BLK_T_OUT) ?
		    VIRTIO_DIR_DEVICE_READS : VIRTIO_DIR_DEVICE_WRITES;

		for (uint_t n = 0; n < xfer->x_ndmac; n++) {
			ddi_dma_cookie_t dmac;

			if (n == 0) {
				/*
				 * The first cookie is in the blkdev request.
				 */
				dmac = xfer->x_dmac;
			} else {
				ddi_dma_nextcookie(xfer->x_dmah, &dmac);
			}

			if (virtio_chain_append(vic, dmac.dmac_laddress,
			    dmac.dmac_size, dir) != DDI_SUCCESS) {
				r = ENOMEM;
				goto fail;
			}
		}

		total_cookies += xfer->x_ndmac;

	} else if (xfer->x_nblks > 0) {
		dev_err(vib->vib_dip, CE_PANIC,
		    "request of type %d had payload length of %lu blocks", type,
		    xfer->x_nblks);
	}

	if (vib->vib_stats->vbs_rw_cookiesmax.value.ui32 < total_cookies) {
		vib->vib_stats->vbs_rw_cookiesmax.value.ui32 = total_cookies;
	}

	return (vioblk_common_submit(vib, vic));

fail:
	vbr->vbr_xfer = NULL;
	vioblk_req_free(vib, vbr);
	virtio_chain_free(vic);
	return (r);
}

static int
vioblk_bd_read(void *arg, bd_xfer_t *xfer)
{
	vioblk_t *vib = arg;
	int r;

	mutex_enter(&vib->vib_mutex);
	r = vioblk_request(vib, xfer, VIRTIO_BLK_T_IN);
	mutex_exit(&vib->vib_mutex);

	return (r);
}

static int
vioblk_bd_write(void *arg, bd_xfer_t *xfer)
{
	vioblk_t *vib = arg;
	int r;

	mutex_enter(&vib->vib_mutex);
	r = vioblk_request(vib, xfer, VIRTIO_BLK_T_OUT);
	mutex_exit(&vib->vib_mutex);

	return (r);
}

static int
vioblk_bd_flush(void *arg, bd_xfer_t *xfer)
{
	vioblk_t *vib = arg;
	int r;

	mutex_enter(&vib->vib_mutex);
	if (!virtio_feature_present(vib->vib_virtio, VIRTIO_BLK_F_FLUSH)) {
		/*
		 * We don't really expect to get here, because if we did not
		 * negotiate the flush feature we would not have installed this
		 * function in the blkdev ops vector.
		 */
		mutex_exit(&vib->vib_mutex);
		return (ENOTSUP);
	}

	r = vioblk_request(vib, xfer, VIRTIO_BLK_T_FLUSH);
	mutex_exit(&vib->vib_mutex);

	return (r);
}

static void
vioblk_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	vioblk_t *vib = arg;

	drive->d_qsize = vib->vib_reqs_capacity;
	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_TRUE;
	drive->d_target = 0;
	drive->d_lun = 0;

	drive->d_vendor = "Virtio";
	drive->d_vendor_len = strlen(drive->d_vendor);

	drive->d_product = "Block Device";
	drive->d_product_len = strlen(drive->d_product);

	drive->d_serial = vib->vib_devid;
	drive->d_serial_len = strlen(drive->d_serial);

	drive->d_revision = "0000";
	drive->d_revision_len = strlen(drive->d_revision);
}

static int
vioblk_bd_mediainfo(void *arg, bd_media_t *media)
{
	vioblk_t *vib = (void *)arg;

	/*
	 * The device protocol is specified in terms of 512 byte logical
	 * blocks, regardless of the recommended I/O size which might be
	 * larger.
	 */
	media->m_nblks = vib->vib_nblks;
	media->m_blksize = vib->vib_blk_size;

	media->m_readonly = vib->vib_readonly;
	media->m_pblksize = vib->vib_pblk_size;
	return (0);
}

static void
vioblk_get_id(vioblk_t *vib)
{
	virtio_dma_t *dma;
	int r;

	if ((dma = virtio_dma_alloc(vib->vib_virtio, VIRTIO_BLK_ID_BYTES,
	    &vioblk_dma_attr, DDI_DMA_CONSISTENT | DDI_DMA_READ,
	    KM_SLEEP)) == NULL) {
		return;
	}

	mutex_enter(&vib->vib_mutex);
	if ((r = vioblk_internal(vib, VIRTIO_BLK_T_GET_ID, dma, 0,
	    VIRTIO_DIR_DEVICE_WRITES)) == 0) {
		const char *b = virtio_dma_va(dma, 0);
		uint_t pos = 0;

		/*
		 * Save the entire response for debugging purposes.
		 */
		bcopy(virtio_dma_va(dma, 0), vib->vib_rawid,
		    VIRTIO_BLK_ID_BYTES);

		/*
		 * Process the returned ID.
		 */
		bzero(vib->vib_devid, sizeof (vib->vib_devid));
		for (uint_t n = 0; n < VIRTIO_BLK_ID_BYTES; n++) {
			if (isalnum(b[n]) || b[n] == '-' || b[n] == '_') {
				/*
				 * Accept a subset of printable ASCII
				 * characters.
				 */
				vib->vib_devid[pos++] = b[n];
			} else {
				/*
				 * Stop processing at the first sign of
				 * trouble.
				 */
				break;
			}
		}

		vib->vib_devid_fetched = B_TRUE;
	}
	mutex_exit(&vib->vib_mutex);

	virtio_dma_free(dma);
}

static int
vioblk_bd_devid(void *arg, dev_info_t *dip, ddi_devid_t *devid)
{
	vioblk_t *vib = arg;
	size_t len;

	if ((len = strlen(vib->vib_devid)) == 0) {
		/*
		 * The device has no ID.
		 */
		return (DDI_FAILURE);
	}

	return (ddi_devid_init(dip, DEVID_ATA_SERIAL, len, vib->vib_devid,
	    devid));
}

/*
 * As the device completes processing of a request, it returns the chain for
 * that request to our I/O queue.  This routine is called in two contexts:
 *   - from the interrupt handler, in response to notification from the device
 *   - synchronously in line with request processing when panicking
 */
static uint_t
vioblk_poll(vioblk_t *vib)
{
	virtio_chain_t *vic;
	uint_t count = 0;
	boolean_t wakeup = B_FALSE;

	VERIFY(MUTEX_HELD(&vib->vib_mutex));

	while ((vic = virtio_queue_poll(vib->vib_vq)) != NULL) {
		vioblk_req_t *vbr = virtio_chain_data(vic);
		uint8_t status;

		virtio_dma_sync(vbr->vbr_dma, DDI_DMA_SYNC_FORCPU);

		bcopy(virtio_dma_va(vbr->vbr_dma,
		    sizeof (struct vioblk_req_hdr)), &status, sizeof (status));

		switch (status) {
		case VIRTIO_BLK_S_OK:
			vbr->vbr_error = 0;
			break;
		case VIRTIO_BLK_S_IOERR:
			vbr->vbr_error = EIO;
			vib->vib_stats->vbs_io_errors.value.ui64++;
			break;
		case VIRTIO_BLK_S_UNSUPP:
			vbr->vbr_error = ENOTTY;
			vib->vib_stats->vbs_unsupp_errors.value.ui64++;
			break;
		default:
			vbr->vbr_error = ENXIO;
			vib->vib_stats->vbs_nxio_errors.value.ui64++;
			break;
		}

		count++;

		if (vbr->vbr_status & VIOBLK_REQSTAT_POLLED) {
			/*
			 * This request must not be freed as it is being held
			 * by a call to vioblk_common_submit().
			 */
			VERIFY(!(vbr->vbr_status &
			    VIOBLK_REQSTAT_POLL_COMPLETE));
			vbr->vbr_status |= VIOBLK_REQSTAT_POLL_COMPLETE;
			wakeup = B_TRUE;
			continue;
		}

		vioblk_complete(vib, vbr);

		vioblk_req_free(vib, vbr);
		virtio_chain_free(vic);
	}

	if (wakeup) {
		/*
		 * Signal anybody waiting for polled command completion.
		 */
		cv_broadcast(&vib->vib_cv);
	}

	return (count);
}

uint_t
vioblk_int_handler(caddr_t arg0, caddr_t arg1)
{
	vioblk_t *vib = (vioblk_t *)arg0;
	uint_t count;

	mutex_enter(&vib->vib_mutex);
	if ((count = vioblk_poll(vib)) >
	    vib->vib_stats->vbs_intr_queuemax.value.ui32) {
		vib->vib_stats->vbs_intr_queuemax.value.ui32 = count;
	}

	vib->vib_stats->vbs_intr_total.value.ui64++;
	mutex_exit(&vib->vib_mutex);

	return (DDI_INTR_CLAIMED);
}

static void
vioblk_free_reqs(vioblk_t *vib)
{
	VERIFY3U(vib->vib_nreqs_alloc, ==, 0);

	for (uint_t i = 0; i < vib->vib_reqs_capacity; i++) {
		struct vioblk_req *vbr = &vib->vib_reqs_mem[i];

		VERIFY(list_link_active(&vbr->vbr_link));
		list_remove(&vib->vib_reqs, vbr);

		VERIFY0(vbr->vbr_status);

		if (vbr->vbr_dma != NULL) {
			virtio_dma_free(vbr->vbr_dma);
			vbr->vbr_dma = NULL;
		}
	}
	VERIFY(list_is_empty(&vib->vib_reqs));

	if (vib->vib_reqs_mem != NULL) {
		kmem_free(vib->vib_reqs_mem,
		    sizeof (struct vioblk_req) * vib->vib_reqs_capacity);
		vib->vib_reqs_mem = NULL;
		vib->vib_reqs_capacity = 0;
	}
}

static int
vioblk_alloc_reqs(vioblk_t *vib)
{
	vib->vib_reqs_capacity = MIN(virtio_queue_size(vib->vib_vq),
	    VIRTIO_BLK_REQ_BUFS);
	vib->vib_reqs_mem = kmem_zalloc(
	    sizeof (struct vioblk_req) * vib->vib_reqs_capacity, KM_SLEEP);
	vib->vib_nreqs_alloc = 0;

	for (uint_t i = 0; i < vib->vib_reqs_capacity; i++) {
		list_insert_tail(&vib->vib_reqs, &vib->vib_reqs_mem[i]);
	}

	for (vioblk_req_t *vbr = list_head(&vib->vib_reqs); vbr != NULL;
	    vbr = list_next(&vib->vib_reqs, vbr)) {
		if ((vbr->vbr_dma = virtio_dma_alloc(vib->vib_virtio,
		    sizeof (struct vioblk_req_hdr) + sizeof (uint8_t),
		    &vioblk_dma_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    KM_SLEEP)) == NULL) {
			goto fail;
		}
	}

	return (0);

fail:
	vioblk_free_reqs(vib);
	return (ENOMEM);
}

static int
vioblk_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	vioblk_t *vib;
	virtio_t *vio;
	boolean_t did_mutex = B_FALSE;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if ((vio = virtio_init(dip, VIRTIO_BLK_WANTED_FEATURES, B_TRUE)) ==
	    NULL) {
		dev_err(dip, CE_WARN, "failed to start Virtio init");
		return (DDI_FAILURE);
	}

	vib = kmem_zalloc(sizeof (*vib), KM_SLEEP);
	vib->vib_dip = dip;
	vib->vib_virtio = vio;
	ddi_set_driver_private(dip, vib);
	list_create(&vib->vib_reqs, sizeof (vioblk_req_t),
	    offsetof(vioblk_req_t, vbr_link));

	/*
	 * Determine how many scatter-gather entries we can use in a single
	 * request.
	 */
	vib->vib_seg_max = VIRTIO_BLK_DEFAULT_MAX_SEG;
	if (virtio_feature_present(vio, VIRTIO_BLK_F_SEG_MAX)) {
		vib->vib_seg_max = virtio_dev_get32(vio,
		    VIRTIO_BLK_CONFIG_SEG_MAX);

		if (vib->vib_seg_max == 0 || vib->vib_seg_max == PCI_EINVAL32) {
			/*
			 * We need to be able to use at least one data segment,
			 * so we'll assume that this device is just poorly
			 * implemented and try for one.
			 */
			vib->vib_seg_max = 1;
		}
	}

	/*
	 * When allocating the request queue, we include two additional
	 * descriptors (beyond those required for request data) to account for
	 * the header and the status byte.
	 */
	if ((vib->vib_vq = virtio_queue_alloc(vio, VIRTIO_BLK_VIRTQ_IO, "io",
	    vioblk_int_handler, vib, B_FALSE, vib->vib_seg_max + 2)) == NULL) {
		goto fail;
	}

	if (virtio_init_complete(vio, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail;
	}

	cv_init(&vib->vib_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&vib->vib_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	did_mutex = B_TRUE;

	if ((vib->vib_kstat = kstat_create("vioblk", instance,
	    "statistics", "controller", KSTAT_TYPE_NAMED,
	    sizeof (struct vioblk_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		dev_err(dip, CE_WARN, "kstat_create failed");
		goto fail;
	}
	vib->vib_stats = (vioblk_stats_t *)vib->vib_kstat->ks_data;
	kstat_named_init(&vib->vib_stats->vbs_rw_outofmemory,
	    "total_rw_outofmemory", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_rw_badoffset,
	    "total_rw_badoffset", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_intr_total,
	    "total_intr", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_io_errors,
	    "total_io_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_unsupp_errors,
	    "total_unsupp_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_nxio_errors,
	    "total_nxio_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_rw_cacheflush,
	    "total_rw_cacheflush", KSTAT_DATA_UINT64);
	kstat_named_init(&vib->vib_stats->vbs_rw_cookiesmax,
	    "max_rw_cookies", KSTAT_DATA_UINT32);
	kstat_named_init(&vib->vib_stats->vbs_intr_queuemax,
	    "max_intr_queue", KSTAT_DATA_UINT32);
	kstat_install(vib->vib_kstat);

	vib->vib_readonly = virtio_feature_present(vio, VIRTIO_BLK_F_RO);
	if ((vib->vib_nblks = virtio_dev_get64(vio,
	    VIRTIO_BLK_CONFIG_CAPACITY)) == UINT64_MAX) {
		dev_err(dip, CE_WARN, "invalid capacity");
		goto fail;
	}

	/*
	 * Determine the optimal logical block size recommended by the device.
	 * This size is advisory; the protocol always deals in 512 byte blocks.
	 */
	vib->vib_blk_size = DEV_BSIZE;
	if (virtio_feature_present(vio, VIRTIO_BLK_F_BLK_SIZE)) {
		uint32_t v = virtio_dev_get32(vio, VIRTIO_BLK_CONFIG_BLK_SIZE);

		if (v != 0 && v != PCI_EINVAL32) {
			vib->vib_blk_size = v;
		}
	}

	/*
	 * Device capacity is always in 512-byte units, convert to
	 * native blocks.
	 */
	vib->vib_nblks = (vib->vib_nblks * DEV_BSIZE) / vib->vib_blk_size;

	/*
	 * The device may also provide an advisory physical block size.
	 */
	vib->vib_pblk_size = vib->vib_blk_size;
	if (virtio_feature_present(vio, VIRTIO_BLK_F_TOPOLOGY)) {
		uint8_t v = virtio_dev_get8(vio, VIRTIO_BLK_CONFIG_TOPO_PBEXP);

		if (v != PCI_EINVAL8) {
			vib->vib_pblk_size <<= v;
		}
	}

	/*
	 * The maximum size for a cookie in a request.
	 */
	vib->vib_seg_size_max = VIRTIO_BLK_DEFAULT_MAX_SIZE;
	if (virtio_feature_present(vio, VIRTIO_BLK_F_SIZE_MAX)) {
		uint32_t v = virtio_dev_get32(vio, VIRTIO_BLK_CONFIG_SIZE_MAX);

		if (v != 0 && v != PCI_EINVAL32) {
			vib->vib_seg_size_max = v;
		}
	}

	/*
	 * Set up the DMA attributes for blkdev to use for request data.  The
	 * specification is not extremely clear about whether DMA-related
	 * parameters include or exclude the header and status descriptors.
	 * For now, we assume they cover only the request data and not the
	 * headers.
	 */
	vib->vib_bd_dma_attr = vioblk_dma_attr;
	vib->vib_bd_dma_attr.dma_attr_sgllen = vib->vib_seg_max;
	vib->vib_bd_dma_attr.dma_attr_count_max = vib->vib_seg_size_max;
	vib->vib_bd_dma_attr.dma_attr_maxxfer = vib->vib_seg_max *
	    vib->vib_seg_size_max;

	if (vioblk_alloc_reqs(vib) != 0) {
		goto fail;
	}

	/*
	 * The blkdev framework does not provide a way to specify that the
	 * device does not support write cache flushing, except by omitting the
	 * "o_sync_cache" member from the ops vector.  As "bd_alloc_handle()"
	 * makes a copy of the ops vector, we can safely assemble one on the
	 * stack based on negotiated features.
	 */
	bd_ops_t vioblk_bd_ops = {
		.o_version =		BD_OPS_VERSION_0,
		.o_drive_info =		vioblk_bd_driveinfo,
		.o_media_info =		vioblk_bd_mediainfo,
		.o_devid_init =		vioblk_bd_devid,
		.o_sync_cache =		vioblk_bd_flush,
		.o_read =		vioblk_bd_read,
		.o_write =		vioblk_bd_write,
	};
	if (!virtio_feature_present(vio, VIRTIO_BLK_F_FLUSH)) {
		vioblk_bd_ops.o_sync_cache = NULL;
	}

	vib->vib_bd_h = bd_alloc_handle(vib, &vioblk_bd_ops,
	    &vib->vib_bd_dma_attr, KM_SLEEP);

	/*
	 * Enable interrupts now so that we can request the device identity.
	 */
	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		goto fail;
	}

	vioblk_get_id(vib);

	if (bd_attach_handle(dip, vib->vib_bd_h) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "Failed to attach blkdev");
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	if (vib->vib_bd_h != NULL) {
		(void) bd_detach_handle(vib->vib_bd_h);
		bd_free_handle(vib->vib_bd_h);
	}
	if (vio != NULL) {
		(void) virtio_fini(vio, B_TRUE);
	}
	if (did_mutex) {
		mutex_destroy(&vib->vib_mutex);
		cv_destroy(&vib->vib_cv);
	}
	if (vib->vib_kstat != NULL) {
		kstat_delete(vib->vib_kstat);
	}
	vioblk_free_reqs(vib);
	kmem_free(vib, sizeof (*vib));
	return (DDI_FAILURE);
}

static int
vioblk_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vioblk_t *vib = ddi_get_driver_private(dip);

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vib->vib_mutex);
	if (vib->vib_nreqs_alloc > 0) {
		/*
		 * Cannot detach while there are still outstanding requests.
		 */
		mutex_exit(&vib->vib_mutex);
		return (DDI_FAILURE);
	}

	if (bd_detach_handle(vib->vib_bd_h) != DDI_SUCCESS) {
		mutex_exit(&vib->vib_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * Tear down the Virtio framework before freeing the rest of the
	 * resources.  This will ensure the interrupt handlers are no longer
	 * running.
	 */
	virtio_fini(vib->vib_virtio, B_FALSE);

	vioblk_free_reqs(vib);
	kstat_delete(vib->vib_kstat);

	mutex_exit(&vib->vib_mutex);
	mutex_destroy(&vib->vib_mutex);

	kmem_free(vib, sizeof (*vib));

	return (DDI_SUCCESS);
}

static int
vioblk_quiesce(dev_info_t *dip)
{
	vioblk_t *vib;

	if ((vib = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	return (virtio_quiesce(vib->vib_virtio));
}

int
_init(void)
{
	int rv;

	bd_mod_init(&vioblk_dev_ops);

	if ((rv = mod_install(&vioblk_modlinkage)) != 0) {
		bd_mod_fini(&vioblk_dev_ops);
	}

	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&vioblk_modlinkage)) == 0) {
		bd_mod_fini(&vioblk_dev_ops);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vioblk_modlinkage, modinfop));
}
