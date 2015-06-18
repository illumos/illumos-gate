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
#include <sys/sysmacros.h>
#include "virtiovar.h"
#include "virtioreg.h"

/* Feature bits */
#define	VIRTIO_BLK_F_BARRIER	(1<<0)
#define	VIRTIO_BLK_F_SIZE_MAX	(1<<1)
#define	VIRTIO_BLK_F_SEG_MAX	(1<<2)
#define	VIRTIO_BLK_F_GEOMETRY	(1<<4)
#define	VIRTIO_BLK_F_RO		(1<<5)
#define	VIRTIO_BLK_F_BLK_SIZE	(1<<6)
#define	VIRTIO_BLK_F_SCSI	(1<<7)
#define	VIRTIO_BLK_F_FLUSH	(1<<9)
#define	VIRTIO_BLK_F_TOPOLOGY	(1<<10)

/* Configuration registers */
#define	VIRTIO_BLK_CONFIG_CAPACITY	0 /* 64bit */
#define	VIRTIO_BLK_CONFIG_SIZE_MAX	8 /* 32bit */
#define	VIRTIO_BLK_CONFIG_SEG_MAX	12 /* 32bit */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_C	16 /* 16bit */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_H	18 /* 8bit */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_S	19 /* 8bit */
#define	VIRTIO_BLK_CONFIG_BLK_SIZE	20 /* 32bit */
#define	VIRTIO_BLK_CONFIG_TOPO_PBEXP	24 /* 8bit */
#define	VIRTIO_BLK_CONFIG_TOPO_ALIGN	25 /* 8bit */
#define	VIRTIO_BLK_CONFIG_TOPO_MIN_SZ	26 /* 16bit */
#define	VIRTIO_BLK_CONFIG_TOPO_OPT_SZ	28 /* 32bit */

/* Command */
#define	VIRTIO_BLK_T_IN			0
#define	VIRTIO_BLK_T_OUT		1
#define	VIRTIO_BLK_T_SCSI_CMD		2
#define	VIRTIO_BLK_T_SCSI_CMD_OUT	3
#define	VIRTIO_BLK_T_FLUSH		4
#define	VIRTIO_BLK_T_FLUSH_OUT		5
#define	VIRTIO_BLK_T_GET_ID		8
#define	VIRTIO_BLK_T_BARRIER		0x80000000

#define	VIRTIO_BLK_ID_BYTES	20 /* devid */

/* Statuses */
#define	VIRTIO_BLK_S_OK		0
#define	VIRTIO_BLK_S_IOERR	1
#define	VIRTIO_BLK_S_UNSUPP	2

#define	DEF_MAXINDIRECT		(128)
#define	DEF_MAXSECTOR		(4096)

#define	VIOBLK_POISON		0xdead0001dead0001

/*
 * Static Variables.
 */
static char vioblk_ident[] = "VirtIO block driver";

/* Request header structure */
struct vioblk_req_hdr {
	uint32_t		type;   /* VIRTIO_BLK_T_* */
	uint32_t		ioprio;
	uint64_t		sector;
};

struct vioblk_req {
	struct vioblk_req_hdr	hdr;
	uint8_t			status;
	uint8_t			unused[3];
	unsigned int		ndmac;
	ddi_dma_handle_t	dmah;
	ddi_dma_handle_t	bd_dmah;
	ddi_dma_cookie_t	dmac;
	bd_xfer_t		*xfer;
};

struct vioblk_stats {
	struct kstat_named	sts_rw_outofmemory;
	struct kstat_named	sts_rw_badoffset;
	struct kstat_named	sts_rw_queuemax;
	struct kstat_named	sts_rw_cookiesmax;
	struct kstat_named	sts_rw_cacheflush;
	struct kstat_named	sts_intr_queuemax;
	struct kstat_named	sts_intr_total;
	struct kstat_named	sts_io_errors;
	struct kstat_named	sts_unsupp_errors;
	struct kstat_named	sts_nxio_errors;
};

struct vioblk_lstats {
	uint64_t		rw_cacheflush;
	uint64_t		intr_total;
	unsigned int		rw_cookiesmax;
	unsigned int		intr_queuemax;
	unsigned int		io_errors;
	unsigned int		unsupp_errors;
	unsigned int		nxio_errors;
};

struct vioblk_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;
	struct virtqueue	*sc_vq;
	bd_handle_t		bd_h;
	struct vioblk_req	*sc_reqs;
	struct vioblk_stats	*ks_data;
	kstat_t			*sc_intrstat;
	uint64_t		sc_capacity;
	uint64_t		sc_nblks;
	struct vioblk_lstats	sc_stats;
	short			sc_blkflags;
	boolean_t		sc_in_poll_mode;
	boolean_t		sc_readonly;
	int			sc_blk_size;
	int			sc_pblk_size;
	int			sc_seg_max;
	int			sc_seg_size_max;
	kmutex_t		lock_devid;
	kcondvar_t		cv_devid;
	char			devid[VIRTIO_BLK_ID_BYTES + 1];
};

static int vioblk_get_id(struct vioblk_softc *sc);

static int vioblk_read(void *arg, bd_xfer_t *xfer);
static int vioblk_write(void *arg, bd_xfer_t *xfer);
static int vioblk_flush(void *arg, bd_xfer_t *xfer);
static void vioblk_driveinfo(void *arg, bd_drive_t *drive);
static int vioblk_mediainfo(void *arg, bd_media_t *media);
static int vioblk_devid_init(void *, dev_info_t *, ddi_devid_t *);
uint_t vioblk_int_handler(caddr_t arg1, caddr_t arg2);

static bd_ops_t vioblk_ops = {
	BD_OPS_VERSION_0,
	vioblk_driveinfo,
	vioblk_mediainfo,
	vioblk_devid_init,
	vioblk_flush,
	vioblk_read,
	vioblk_write,
};

static int vioblk_quiesce(dev_info_t *);
static int vioblk_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioblk_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops vioblk_dev_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	vioblk_attach,	/* attach */
	vioblk_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* cb_ops */
	NULL,		/* bus_ops */
	NULL,		/* power */
	vioblk_quiesce	/* quiesce */
};



/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	vioblk_ident,    /* short description */
	&vioblk_dev_ops	/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

ddi_device_acc_attr_t vioblk_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* virtio is always native byte order */
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};

/* DMA attr for the header/status blocks. */
static ddi_dma_attr_t vioblk_req_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0,				/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	1,				/* dma_attr_align	*/
	1,				/* dma_attr_burstsizes	*/
	1,				/* dma_attr_minxfer	*/
	0xFFFFFFFFull,			/* dma_attr_maxxfer	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen	*/
	1,				/* dma_attr_granular	*/
	0,				/* dma_attr_flags	*/
};

/* DMA attr for the data blocks. */
static ddi_dma_attr_t vioblk_bd_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0,				/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	1,				/* dma_attr_align	*/
	1,				/* dma_attr_burstsizes	*/
	1,				/* dma_attr_minxfer	*/
	0,				/* dma_attr_maxxfer, set in attach */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg		*/
	0,				/* dma_attr_sgllen, set in attach */
	1,				/* dma_attr_granular	*/
	0,				/* dma_attr_flags	*/
};

static int
vioblk_rw(struct vioblk_softc *sc, bd_xfer_t *xfer, int type,
    uint32_t len)
{
	struct vioblk_req *req;
	struct vq_entry *ve_hdr;
	int total_cookies, write;

	write = (type == VIRTIO_BLK_T_OUT ||
	    type == VIRTIO_BLK_T_FLUSH_OUT) ? 1 : 0;
	total_cookies = 2;

	if ((xfer->x_blkno + xfer->x_nblks) > sc->sc_nblks) {
		sc->ks_data->sts_rw_badoffset.value.ui64++;
		return (EINVAL);
	}

	/* allocate top entry */
	ve_hdr = vq_alloc_entry(sc->sc_vq);
	if (!ve_hdr) {
		sc->ks_data->sts_rw_outofmemory.value.ui64++;
		return (ENOMEM);
	}

	/* getting request */
	req = &sc->sc_reqs[ve_hdr->qe_index];
	req->hdr.type = type;
	req->hdr.ioprio = 0;
	req->hdr.sector = xfer->x_blkno;
	req->xfer = xfer;

	/* Header */
	virtio_ve_add_indirect_buf(ve_hdr, req->dmac.dmac_laddress,
	    sizeof (struct vioblk_req_hdr), B_TRUE);

	/* Payload */
	if (len > 0) {
		virtio_ve_add_cookie(ve_hdr, xfer->x_dmah, xfer->x_dmac,
		    xfer->x_ndmac, write ? B_TRUE : B_FALSE);
		total_cookies += xfer->x_ndmac;
	}

	/* Status */
	virtio_ve_add_indirect_buf(ve_hdr,
	    req->dmac.dmac_laddress + sizeof (struct vioblk_req_hdr),
	    sizeof (uint8_t), B_FALSE);

	/* sending the whole chain to the device */
	virtio_push_chain(ve_hdr, B_TRUE);

	if (sc->sc_stats.rw_cookiesmax < total_cookies)
		sc->sc_stats.rw_cookiesmax = total_cookies;

	return (DDI_SUCCESS);
}

/*
 * Now in polling mode. Interrupts are off, so we
 * 1) poll for the already queued requests to complete.
 * 2) push our request.
 * 3) wait for our request to complete.
 */
static int
vioblk_rw_poll(struct vioblk_softc *sc, bd_xfer_t *xfer,
    int type, uint32_t len)
{
	clock_t tmout;
	int ret;

	ASSERT(xfer->x_flags & BD_XFER_POLL);

	/* Prevent a hard hang. */
	tmout = drv_usectohz(30000000);

	/* Poll for an empty queue */
	while (vq_num_used(sc->sc_vq)) {
		/* Check if any pending requests completed. */
		ret = vioblk_int_handler((caddr_t)&sc->sc_virtio, NULL);
		if (ret != DDI_INTR_CLAIMED) {
			drv_usecwait(10);
			tmout -= 10;
			return (ETIMEDOUT);
		}
	}

	ret = vioblk_rw(sc, xfer, type, len);
	if (ret)
		return (ret);

	tmout = drv_usectohz(30000000);
	/* Poll for an empty queue again. */
	while (vq_num_used(sc->sc_vq)) {
		/* Check if any pending requests completed. */
		ret = vioblk_int_handler((caddr_t)&sc->sc_virtio, NULL);
		if (ret != DDI_INTR_CLAIMED) {
			drv_usecwait(10);
			tmout -= 10;
			return (ETIMEDOUT);
		}
	}

	return (DDI_SUCCESS);
}

static int
vioblk_read(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	if (xfer->x_flags & BD_XFER_POLL) {
		if (!sc->sc_in_poll_mode) {
			virtio_stop_vq_intr(sc->sc_vq);
			sc->sc_in_poll_mode = 1;
		}

		ret = vioblk_rw_poll(sc, xfer, VIRTIO_BLK_T_IN,
		    xfer->x_nblks * DEV_BSIZE);
	} else {
		if (sc->sc_in_poll_mode) {
			virtio_start_vq_intr(sc->sc_vq);
			sc->sc_in_poll_mode = 0;
		}

		ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_IN,
		    xfer->x_nblks * DEV_BSIZE);
	}

	return (ret);
}

static int
vioblk_write(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	if (xfer->x_flags & BD_XFER_POLL) {
		if (!sc->sc_in_poll_mode) {
			virtio_stop_vq_intr(sc->sc_vq);
			sc->sc_in_poll_mode = 1;
		}

		ret = vioblk_rw_poll(sc, xfer, VIRTIO_BLK_T_OUT,
		    xfer->x_nblks * DEV_BSIZE);
	} else {
		if (sc->sc_in_poll_mode) {
			virtio_start_vq_intr(sc->sc_vq);
			sc->sc_in_poll_mode = 0;
		}

		ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_OUT,
		    xfer->x_nblks * DEV_BSIZE);
	}
	return (ret);
}

static int
vioblk_flush(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	ASSERT((xfer->x_flags & BD_XFER_POLL) == 0);

	ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_FLUSH_OUT,
	    xfer->x_nblks * DEV_BSIZE);

	if (!ret)
		sc->sc_stats.rw_cacheflush++;

	return (ret);
}


static void
vioblk_driveinfo(void *arg, bd_drive_t *drive)
{
	struct vioblk_softc *sc = (void *)arg;

	drive->d_qsize = sc->sc_vq->vq_num;
	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_TRUE;
	drive->d_target = 0;
	drive->d_lun = 0;

	drive->d_vendor = "Virtio";
	drive->d_vendor_len = strlen(drive->d_vendor);

	drive->d_product = "Block Device";
	drive->d_product_len = strlen(drive->d_product);

	(void) vioblk_get_id(sc);
	drive->d_serial = sc->devid;
	drive->d_serial_len = strlen(drive->d_serial);

	drive->d_revision = "0000";
	drive->d_revision_len = strlen(drive->d_revision);
}

static int
vioblk_mediainfo(void *arg, bd_media_t *media)
{
	struct vioblk_softc *sc = (void *)arg;

	media->m_nblks = sc->sc_nblks;
	media->m_blksize = sc->sc_blk_size;
	media->m_readonly = sc->sc_readonly;
	media->m_pblksize = sc->sc_pblk_size;
	return (0);
}

static int
vioblk_get_id(struct vioblk_softc *sc)
{
	clock_t deadline;
	int ret;
	bd_xfer_t xfer;

	deadline = ddi_get_lbolt() + (clock_t)drv_usectohz(3 * 1000000);
	(void) memset(&xfer, 0, sizeof (bd_xfer_t));
	xfer.x_nblks = 1;

	ret = ddi_dma_alloc_handle(sc->sc_dev, &vioblk_bd_dma_attr,
	    DDI_DMA_SLEEP, NULL, &xfer.x_dmah);
	if (ret != DDI_SUCCESS)
		goto out_alloc;

	ret = ddi_dma_addr_bind_handle(xfer.x_dmah, NULL, (caddr_t)&sc->devid,
	    VIRTIO_BLK_ID_BYTES, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &xfer.x_dmac, &xfer.x_ndmac);
	if (ret != DDI_DMA_MAPPED) {
		ret = DDI_FAILURE;
		goto out_map;
	}

	mutex_enter(&sc->lock_devid);

	ret = vioblk_rw(sc, &xfer, VIRTIO_BLK_T_GET_ID,
	    VIRTIO_BLK_ID_BYTES);
	if (ret) {
		mutex_exit(&sc->lock_devid);
		goto out_rw;
	}

	/* wait for reply */
	ret = cv_timedwait(&sc->cv_devid, &sc->lock_devid, deadline);
	mutex_exit(&sc->lock_devid);

	(void) ddi_dma_unbind_handle(xfer.x_dmah);
	ddi_dma_free_handle(&xfer.x_dmah);

	/* timeout */
	if (ret < 0) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Cannot get devid from the device");
		return (DDI_FAILURE);
	}

	return (0);

out_rw:
	(void) ddi_dma_unbind_handle(xfer.x_dmah);
out_map:
	ddi_dma_free_handle(&xfer.x_dmah);
out_alloc:
	return (ret);
}

static int
vioblk_devid_init(void *arg, dev_info_t *devinfo, ddi_devid_t *devid)
{
	struct vioblk_softc *sc = (void *)arg;
	int ret;

	ret = vioblk_get_id(sc);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = ddi_devid_init(devinfo, DEVID_ATA_SERIAL,
	    VIRTIO_BLK_ID_BYTES, sc->devid, devid);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "Cannot build devid from the device");
		return (ret);
	}

	dev_debug(sc->sc_dev, CE_NOTE,
	    "devid %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
	    sc->devid[0], sc->devid[1], sc->devid[2], sc->devid[3],
	    sc->devid[4], sc->devid[5], sc->devid[6], sc->devid[7],
	    sc->devid[8], sc->devid[9], sc->devid[10], sc->devid[11],
	    sc->devid[12], sc->devid[13], sc->devid[14], sc->devid[15],
	    sc->devid[16], sc->devid[17], sc->devid[18], sc->devid[19]);

	return (0);
}

static void
vioblk_show_features(struct vioblk_softc *sc, const char *prefix,
    uint32_t features)
{
	char buf[512];
	char *bufp = buf;
	char *bufend = buf + sizeof (buf);

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, prefix);

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += virtio_show_features(features, bufp, bufend - bufp);


	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, "Vioblk ( ");

	if (features & VIRTIO_BLK_F_BARRIER)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "BARRIER ");
	if (features & VIRTIO_BLK_F_SIZE_MAX)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "SIZE_MAX ");
	if (features & VIRTIO_BLK_F_SEG_MAX)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "SEG_MAX ");
	if (features & VIRTIO_BLK_F_GEOMETRY)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GEOMETRY ");
	if (features & VIRTIO_BLK_F_RO)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "RO ");
	if (features & VIRTIO_BLK_F_BLK_SIZE)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "BLK_SIZE ");
	if (features & VIRTIO_BLK_F_SCSI)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "SCSI ");
	if (features & VIRTIO_BLK_F_FLUSH)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "FLUSH ");
	if (features & VIRTIO_BLK_F_TOPOLOGY)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "TOPOLOGY ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, ")");
	*bufp = '\0';

	dev_debug(sc->sc_dev, CE_NOTE, "%s", buf);
}

static int
vioblk_dev_features(struct vioblk_softc *sc)
{
	uint32_t host_features;

	host_features = virtio_negotiate_features(&sc->sc_virtio,
	    VIRTIO_BLK_F_RO |
	    VIRTIO_BLK_F_GEOMETRY |
	    VIRTIO_BLK_F_BLK_SIZE |
	    VIRTIO_BLK_F_FLUSH |
	    VIRTIO_BLK_F_TOPOLOGY |
	    VIRTIO_BLK_F_SEG_MAX |
	    VIRTIO_BLK_F_SIZE_MAX |
	    VIRTIO_F_RING_INDIRECT_DESC);

	vioblk_show_features(sc, "Host features: ", host_features);
	vioblk_show_features(sc, "Negotiated features: ",
	    sc->sc_virtio.sc_features);

	if (!(sc->sc_virtio.sc_features & VIRTIO_F_RING_INDIRECT_DESC)) {
		dev_err(sc->sc_dev, CE_NOTE,
		    "Host does not support RING_INDIRECT_DESC, bye.");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
uint_t
vioblk_int_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *)arg1;
	struct vioblk_softc *sc = container_of(vsc,
	    struct vioblk_softc, sc_virtio);
	struct vq_entry *ve;
	uint32_t len;
	int i = 0, error;

	while ((ve = virtio_pull_chain(sc->sc_vq, &len))) {
		struct vioblk_req *req = &sc->sc_reqs[ve->qe_index];
		bd_xfer_t *xfer = req->xfer;
		uint8_t status = req->status;
		uint32_t type = req->hdr.type;

		if (req->xfer == (void *)VIOBLK_POISON) {
			dev_err(sc->sc_dev, CE_WARN, "Poisoned descriptor!");
			virtio_free_chain(ve);
			return (DDI_INTR_CLAIMED);
		}

		req->xfer = (void *) VIOBLK_POISON;

		/* Note: blkdev tears down the payload mapping for us. */
		virtio_free_chain(ve);

		/* returning payload back to blkdev */
		switch (status) {
			case VIRTIO_BLK_S_OK:
				error = 0;
				break;
			case VIRTIO_BLK_S_IOERR:
				error = EIO;
				sc->sc_stats.io_errors++;
				break;
			case VIRTIO_BLK_S_UNSUPP:
				sc->sc_stats.unsupp_errors++;
				error = ENOTTY;
				break;
			default:
				sc->sc_stats.nxio_errors++;
				error = ENXIO;
				break;
		}

		if (type == VIRTIO_BLK_T_GET_ID) {
			/* notify devid_init */
			mutex_enter(&sc->lock_devid);
			cv_broadcast(&sc->cv_devid);
			mutex_exit(&sc->lock_devid);
		} else
			bd_xfer_done(xfer, error);

		i++;
	}

	/* update stats */
	if (sc->sc_stats.intr_queuemax < i)
		sc->sc_stats.intr_queuemax = i;
	sc->sc_stats.intr_total++;

	return (DDI_INTR_CLAIMED);
}

/* ARGSUSED */
uint_t
vioblk_config_handler(caddr_t arg1, caddr_t arg2)
{
	return (DDI_INTR_CLAIMED);
}

static int
vioblk_register_ints(struct vioblk_softc *sc)
{
	int ret;

	struct virtio_int_handler vioblk_conf_h = {
		vioblk_config_handler
	};

	struct virtio_int_handler vioblk_vq_h[] = {
		{ vioblk_int_handler },
		{ NULL },
	};

	ret = virtio_register_ints(&sc->sc_virtio,
	    &vioblk_conf_h, vioblk_vq_h);

	return (ret);
}

static void
vioblk_free_reqs(struct vioblk_softc *sc)
{
	int i, qsize;

	qsize = sc->sc_vq->vq_num;

	for (i = 0; i < qsize; i++) {
		struct vioblk_req *req = &sc->sc_reqs[i];

		if (req->ndmac)
			(void) ddi_dma_unbind_handle(req->dmah);

		if (req->dmah)
			ddi_dma_free_handle(&req->dmah);
	}

	kmem_free(sc->sc_reqs, sizeof (struct vioblk_req) * qsize);
}

static int
vioblk_alloc_reqs(struct vioblk_softc *sc)
{
	int i, qsize;
	int ret;

	qsize = sc->sc_vq->vq_num;

	sc->sc_reqs = kmem_zalloc(sizeof (struct vioblk_req) * qsize, KM_SLEEP);

	for (i = 0; i < qsize; i++) {
		struct vioblk_req *req = &sc->sc_reqs[i];

		ret = ddi_dma_alloc_handle(sc->sc_dev, &vioblk_req_dma_attr,
		    DDI_DMA_SLEEP, NULL, &req->dmah);
		if (ret != DDI_SUCCESS) {

			dev_err(sc->sc_dev, CE_WARN,
			    "Can't allocate dma handle for req "
			    "buffer %d", i);
			goto exit;
		}

		ret = ddi_dma_addr_bind_handle(req->dmah, NULL,
		    (caddr_t)&req->hdr,
		    sizeof (struct vioblk_req_hdr) + sizeof (uint8_t),
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    NULL, &req->dmac, &req->ndmac);
		if (ret != DDI_DMA_MAPPED) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Can't bind req buffer %d", i);
			goto exit;
		}
	}

	return (0);

exit:
	vioblk_free_reqs(sc);
	return (ENOMEM);
}


static int
vioblk_ksupdate(kstat_t *ksp, int rw)
{
	struct vioblk_softc *sc = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	sc->ks_data->sts_rw_cookiesmax.value.ui32 = sc->sc_stats.rw_cookiesmax;
	sc->ks_data->sts_intr_queuemax.value.ui32 = sc->sc_stats.intr_queuemax;
	sc->ks_data->sts_unsupp_errors.value.ui32 = sc->sc_stats.unsupp_errors;
	sc->ks_data->sts_nxio_errors.value.ui32 = sc->sc_stats.nxio_errors;
	sc->ks_data->sts_io_errors.value.ui32 = sc->sc_stats.io_errors;
	sc->ks_data->sts_rw_cacheflush.value.ui64 = sc->sc_stats.rw_cacheflush;
	sc->ks_data->sts_intr_total.value.ui64 = sc->sc_stats.intr_total;


	return (0);
}

static int
vioblk_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;
	int instance;
	struct vioblk_softc *sc;
	struct virtio_softc *vsc;
	struct vioblk_stats *ks_data;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		dev_err(devinfo, CE_WARN, "resume not supported yet");
		ret = DDI_FAILURE;
		goto exit;

	default:
		dev_err(devinfo, CE_WARN, "cmd 0x%x not recognized", cmd);
		ret = DDI_FAILURE;
		goto exit;
	}

	sc = kmem_zalloc(sizeof (struct vioblk_softc), KM_SLEEP);
	ddi_set_driver_private(devinfo, sc);

	vsc = &sc->sc_virtio;

	/* Duplicate for faster access / less typing */
	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;

	cv_init(&sc->cv_devid, NULL, CV_DRIVER, NULL);
	mutex_init(&sc->lock_devid, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize interrupt kstat.  This should not normally fail, since
	 * we don't use a persistent stat.  We do it this way to avoid having
	 * to test for it at run time on the hot path.
	 */
	sc->sc_intrstat = kstat_create("vioblk", instance,
	    "intrs", "controller", KSTAT_TYPE_NAMED,
	    sizeof (struct vioblk_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT);
	if (sc->sc_intrstat == NULL) {
		dev_err(devinfo, CE_WARN, "kstat_create failed");
		goto exit_intrstat;
	}
	ks_data = (struct vioblk_stats *)sc->sc_intrstat->ks_data;
	kstat_named_init(&ks_data->sts_rw_outofmemory,
	    "total_rw_outofmemory", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_rw_badoffset,
	    "total_rw_badoffset", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_intr_total,
	    "total_intr", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_io_errors,
	    "total_io_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_unsupp_errors,
	    "total_unsupp_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_nxio_errors,
	    "total_nxio_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_rw_cacheflush,
	    "total_rw_cacheflush", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_rw_cookiesmax,
	    "max_rw_cookies", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_intr_queuemax,
	    "max_intr_queue", KSTAT_DATA_UINT32);
	sc->ks_data = ks_data;
	sc->sc_intrstat->ks_private = sc;
	sc->sc_intrstat->ks_update = vioblk_ksupdate;
	kstat_install(sc->sc_intrstat);

	/* map BAR0 */
	ret = ddi_regs_map_setup(devinfo, 1,
	    (caddr_t *)&sc->sc_virtio.sc_io_addr,
	    0, 0, &vioblk_attr, &sc->sc_virtio.sc_ioh);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "unable to map bar0: [%d]", ret);
		goto exit_map;
	}

	virtio_device_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	if (vioblk_register_ints(sc)) {
		dev_err(devinfo, CE_WARN, "Unable to add interrupt");
		goto exit_int;
	}

	ret = vioblk_dev_features(sc);
	if (ret)
		goto exit_features;

	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_RO)
		sc->sc_readonly = B_TRUE;
	else
		sc->sc_readonly = B_FALSE;

	sc->sc_capacity = virtio_read_device_config_8(&sc->sc_virtio,
	    VIRTIO_BLK_CONFIG_CAPACITY);
	sc->sc_nblks = sc->sc_capacity;

	sc->sc_blk_size = DEV_BSIZE;
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_BLK_SIZE) {
		sc->sc_blk_size = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_BLK_SIZE);
	}

	sc->sc_pblk_size = sc->sc_blk_size;
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_TOPOLOGY) {
		sc->sc_pblk_size <<= virtio_read_device_config_1(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_TOPO_PBEXP);
	}

	/* Flushing is not supported. */
	if (!(sc->sc_virtio.sc_features & VIRTIO_BLK_F_FLUSH)) {
		vioblk_ops.o_sync_cache = NULL;
	}

	sc->sc_seg_max = DEF_MAXINDIRECT;
	/* The max number of segments (cookies) in a request */
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_SEG_MAX) {
		sc->sc_seg_max = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_SEG_MAX);

		/* That's what Linux does. */
		if (!sc->sc_seg_max)
			sc->sc_seg_max = 1;

		/*
		 * SEG_MAX corresponds to the number of _data_
		 * blocks in a request
		 */
		sc->sc_seg_max += 2;
	}
	/* 2 descriptors taken for header/status */
	vioblk_bd_dma_attr.dma_attr_sgllen = sc->sc_seg_max - 2;


	/* The maximum size for a cookie in a request. */
	sc->sc_seg_size_max = DEF_MAXSECTOR;
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_SIZE_MAX) {
		sc->sc_seg_size_max = virtio_read_device_config_4(
		    &sc->sc_virtio, VIRTIO_BLK_CONFIG_SIZE_MAX);
	}

	/* The maximum request size */
	vioblk_bd_dma_attr.dma_attr_maxxfer =
	    vioblk_bd_dma_attr.dma_attr_sgllen * sc->sc_seg_size_max;

	dev_debug(devinfo, CE_NOTE,
	    "nblks=%" PRIu64 " blksize=%d (%d) num_seg=%d, "
	    "seg_size=%d, maxxfer=%" PRIu64,
	    sc->sc_nblks, sc->sc_blk_size, sc->sc_pblk_size,
	    vioblk_bd_dma_attr.dma_attr_sgllen,
	    sc->sc_seg_size_max,
	    vioblk_bd_dma_attr.dma_attr_maxxfer);


	sc->sc_vq = virtio_alloc_vq(&sc->sc_virtio, 0, 0,
	    sc->sc_seg_max, "I/O request");
	if (sc->sc_vq == NULL) {
		goto exit_alloc1;
	}

	ret = vioblk_alloc_reqs(sc);
	if (ret) {
		goto exit_alloc2;
	}

	sc->bd_h = bd_alloc_handle(sc, &vioblk_ops, &vioblk_bd_dma_attr,
	    KM_SLEEP);


	virtio_set_status(&sc->sc_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
	virtio_start_vq_intr(sc->sc_vq);

	ret = virtio_enable_ints(&sc->sc_virtio);
	if (ret)
		goto exit_enable_ints;

	ret = bd_attach_handle(devinfo, sc->bd_h);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "Failed to attach blkdev");
		goto exit_attach_bd;
	}

	return (DDI_SUCCESS);

exit_attach_bd:
	/*
	 * There is no virtio_disable_ints(), it's done in virtio_release_ints.
	 * If they ever get split, don't forget to add a call here.
	 */
exit_enable_ints:
	virtio_stop_vq_intr(sc->sc_vq);
	bd_free_handle(sc->bd_h);
	vioblk_free_reqs(sc);
exit_alloc2:
	virtio_free_vq(sc->sc_vq);
exit_alloc1:
exit_features:
	virtio_release_ints(&sc->sc_virtio);
exit_int:
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
exit_map:
	kstat_delete(sc->sc_intrstat);
exit_intrstat:
	mutex_destroy(&sc->lock_devid);
	cv_destroy(&sc->cv_devid);
	kmem_free(sc, sizeof (struct vioblk_softc));
exit:
	return (ret);
}

static int
vioblk_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct vioblk_softc *sc = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend not supported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	(void) bd_detach_handle(sc->bd_h);
	virtio_stop_vq_intr(sc->sc_vq);
	virtio_release_ints(&sc->sc_virtio);
	vioblk_free_reqs(sc);
	virtio_free_vq(sc->sc_vq);
	virtio_device_reset(&sc->sc_virtio);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
	kstat_delete(sc->sc_intrstat);
	kmem_free(sc, sizeof (struct vioblk_softc));

	return (DDI_SUCCESS);
}

static int
vioblk_quiesce(dev_info_t *devinfo)
{
	struct vioblk_softc *sc = ddi_get_driver_private(devinfo);

	virtio_stop_vq_intr(sc->sc_vq);
	virtio_device_reset(&sc->sc_virtio);

	return (DDI_SUCCESS);
}

int
_init(void)
{
	int rv;

	bd_mod_init(&vioblk_dev_ops);

	if ((rv = mod_install(&modlinkage)) != 0) {
		bd_mod_fini(&vioblk_dev_ops);
	}

	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		bd_mod_fini(&vioblk_dev_ops);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
