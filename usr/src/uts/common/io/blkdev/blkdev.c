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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2012 Alexey Zaytsev <alexey.zaytsev@gmail.com> All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/aio_req.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/cmlb.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/scsi/scsi.h>	/* for DTYPE_DIRECT */
#include <sys/kstat.h>
#include <sys/fs/dv_node.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/blkdev.h>
#include <sys/scsi/impl/inquiry.h>

#define	BD_MAXPART	64
#define	BDINST(dev)	(getminor(dev) / BD_MAXPART)
#define	BDPART(dev)	(getminor(dev) % BD_MAXPART)

typedef struct bd bd_t;
typedef struct bd_xfer_impl bd_xfer_impl_t;

struct bd {
	void		*d_private;
	dev_info_t	*d_dip;
	kmutex_t	d_ocmutex;
	kmutex_t	d_iomutex;
	kmutex_t	d_statemutex;
	kcondvar_t	d_statecv;
	enum dkio_state	d_state;
	cmlb_handle_t	d_cmlbh;
	unsigned	d_open_lyr[BD_MAXPART];	/* open count */
	uint64_t	d_open_excl;	/* bit mask indexed by partition */
	uint64_t	d_open_reg[OTYPCNT];		/* bit mask */

	uint32_t	d_qsize;
	uint32_t	d_qactive;
	uint32_t	d_maxxfer;
	uint32_t	d_blkshift;
	uint32_t	d_pblkshift;
	uint64_t	d_numblks;
	ddi_devid_t	d_devid;

	kmem_cache_t	*d_cache;
	list_t		d_runq;
	list_t		d_waitq;
	kstat_t		*d_ksp;
	kstat_io_t	*d_kiop;

	boolean_t	d_rdonly;
	boolean_t	d_ssd;
	boolean_t	d_removable;
	boolean_t	d_hotpluggable;
	boolean_t	d_use_dma;

	ddi_dma_attr_t	d_dma;
	bd_ops_t	d_ops;
	bd_handle_t	d_handle;
};

struct bd_handle {
	bd_ops_t	h_ops;
	ddi_dma_attr_t	*h_dma;
	dev_info_t	*h_parent;
	dev_info_t	*h_child;
	void		*h_private;
	bd_t		*h_bd;
	char		*h_name;
	char		h_addr[20];	/* enough for %X,%X */
};

struct bd_xfer_impl {
	bd_xfer_t	i_public;
	list_node_t	i_linkage;
	bd_t		*i_bd;
	buf_t		*i_bp;
	uint_t		i_num_win;
	uint_t		i_cur_win;
	off_t		i_offset;
	int		(*i_func)(void *, bd_xfer_t *);
	uint32_t	i_blkshift;
	size_t		i_len;
	size_t		i_resid;
};

#define	i_dmah		i_public.x_dmah
#define	i_dmac		i_public.x_dmac
#define	i_ndmac		i_public.x_ndmac
#define	i_kaddr		i_public.x_kaddr
#define	i_nblks		i_public.x_nblks
#define	i_blkno		i_public.x_blkno
#define	i_flags		i_public.x_flags


/*
 * Private prototypes.
 */

static void bd_prop_update_inqstring(dev_info_t *, char *, char *, size_t);
static void bd_create_inquiry_props(dev_info_t *, bd_drive_t *);

static int bd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int bd_attach(dev_info_t *, ddi_attach_cmd_t);
static int bd_detach(dev_info_t *, ddi_detach_cmd_t);

static int bd_open(dev_t *, int, int, cred_t *);
static int bd_close(dev_t, int, int, cred_t *);
static int bd_strategy(struct buf *);
static int bd_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int bd_dump(dev_t, caddr_t, daddr_t, int);
static int bd_read(dev_t, struct uio *, cred_t *);
static int bd_write(dev_t, struct uio *, cred_t *);
static int bd_aread(dev_t, struct aio_req *, cred_t *);
static int bd_awrite(dev_t, struct aio_req *, cred_t *);
static int bd_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
    caddr_t, int *);

static int bd_tg_rdwr(dev_info_t *, uchar_t, void *, diskaddr_t, size_t,
    void *);
static int bd_tg_getinfo(dev_info_t *, int, void *, void *);
static int bd_xfer_ctor(void *, void *, int);
static void bd_xfer_dtor(void *, void *);
static void bd_sched(bd_t *);
static void bd_submit(bd_t *, bd_xfer_impl_t *);
static void bd_runq_exit(bd_xfer_impl_t *, int);
static void bd_update_state(bd_t *);
static int bd_check_state(bd_t *, enum dkio_state *);
static int bd_flush_write_cache(bd_t *, struct dk_callback *);

struct cmlb_tg_ops bd_tg_ops = {
	TG_DK_OPS_VERSION_1,
	bd_tg_rdwr,
	bd_tg_getinfo,
};

static struct cb_ops bd_cb_ops = {
	bd_open, 		/* open */
	bd_close, 		/* close */
	bd_strategy, 		/* strategy */
	nodev, 			/* print */
	bd_dump,		/* dump */
	bd_read, 		/* read */
	bd_write, 		/* write */
	bd_ioctl, 		/* ioctl */
	nodev, 			/* devmap */
	nodev, 			/* mmap */
	nodev, 			/* segmap */
	nochpoll, 		/* poll */
	bd_prop_op, 		/* cb_prop_op */
	0, 			/* streamtab  */
	D_64BIT | D_MP,		/* Driver comaptibility flag */
	CB_REV,			/* cb_rev */
	bd_aread,		/* async read */
	bd_awrite		/* async write */
};

struct dev_ops bd_dev_ops = {
	DEVO_REV, 		/* devo_rev, */
	0, 			/* refcnt  */
	bd_getinfo,		/* getinfo */
	nulldev, 		/* identify */
	nulldev, 		/* probe */
	bd_attach, 		/* attach */
	bd_detach,		/* detach */
	nodev, 			/* reset */
	&bd_cb_ops, 		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Generic Block Device",
	&bd_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, { &modldrv, NULL }
};

static void *bd_state;
static krwlock_t bd_lock;

int
_init(void)
{
	int	rv;

	rv = ddi_soft_state_init(&bd_state, sizeof (struct bd), 2);
	if (rv != DDI_SUCCESS) {
		return (rv);
	}
	rw_init(&bd_lock, NULL, RW_DRIVER, NULL);
	rv = mod_install(&modlinkage);
	if (rv != DDI_SUCCESS) {
		rw_destroy(&bd_lock);
		ddi_soft_state_fini(&bd_state);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	rv = mod_remove(&modlinkage);
	if (rv == DDI_SUCCESS) {
		rw_destroy(&bd_lock);
		ddi_soft_state_fini(&bd_state);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
bd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	bd_t	*bd;
	minor_t	inst;

	_NOTE(ARGUNUSED(dip));

	inst = BDINST((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		bd = ddi_get_soft_state(bd_state, inst);
		if (bd == NULL) {
			return (DDI_FAILURE);
		}
		*resultp = (void *)bd->d_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(intptr_t)inst;
		break;

	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
bd_prop_update_inqstring(dev_info_t *dip, char *name, char *data, size_t len)
{
	int	ilen;
	char	*data_string;

	ilen = scsi_ascii_inquiry_len(data, len);
	ASSERT3U(ilen, <=, len);
	if (ilen <= 0)
		return;
	/* ensure null termination */
	data_string = kmem_zalloc(ilen + 1, KM_SLEEP);
	bcopy(data, data_string, ilen);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, name, data_string);
	kmem_free(data_string, ilen + 1);
}

static void
bd_create_inquiry_props(dev_info_t *dip, bd_drive_t *drive)
{
	if (drive->d_vendor_len > 0)
		bd_prop_update_inqstring(dip, INQUIRY_VENDOR_ID,
		    drive->d_vendor, drive->d_vendor_len);

	if (drive->d_product_len > 0)
		bd_prop_update_inqstring(dip, INQUIRY_PRODUCT_ID,
		    drive->d_product, drive->d_product_len);

	if (drive->d_serial_len > 0)
		bd_prop_update_inqstring(dip, INQUIRY_SERIAL_NO,
		    drive->d_serial, drive->d_serial_len);

	if (drive->d_revision_len > 0)
		bd_prop_update_inqstring(dip, INQUIRY_REVISION_ID,
		    drive->d_revision, drive->d_revision_len);
}

static int
bd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		inst;
	bd_handle_t	hdl;
	bd_t		*bd;
	bd_drive_t	drive;
	int		rv;
	char		name[16];
	char		kcache[32];

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		/* We don't do anything native for suspend/resume */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	hdl = ddi_get_parent_data(dip);

	(void) snprintf(name, sizeof (name), "%s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	(void) snprintf(kcache, sizeof (kcache), "%s_xfer", name);

	if (hdl == NULL) {
		cmn_err(CE_WARN, "%s: missing parent data!", name);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(bd_state, inst) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: unable to zalloc soft state!", name);
		return (DDI_FAILURE);
	}
	bd = ddi_get_soft_state(bd_state, inst);

	if (hdl->h_dma) {
		bd->d_dma = *(hdl->h_dma);
		bd->d_dma.dma_attr_granular =
		    max(DEV_BSIZE, bd->d_dma.dma_attr_granular);
		bd->d_use_dma = B_TRUE;

		if (bd->d_maxxfer &&
		    (bd->d_maxxfer != bd->d_dma.dma_attr_maxxfer)) {
			cmn_err(CE_WARN,
			    "%s: inconsistent maximum transfer size!",
			    name);
			/* We force it */
			bd->d_maxxfer = bd->d_dma.dma_attr_maxxfer;
		} else {
			bd->d_maxxfer = bd->d_dma.dma_attr_maxxfer;
		}
	} else {
		bd->d_use_dma = B_FALSE;
		if (bd->d_maxxfer == 0) {
			bd->d_maxxfer = 1024 * 1024;
		}
	}
	bd->d_ops = hdl->h_ops;
	bd->d_private = hdl->h_private;
	bd->d_blkshift = 9;	/* 512 bytes, to start */

	if (bd->d_maxxfer % DEV_BSIZE) {
		cmn_err(CE_WARN, "%s: maximum transfer misaligned!", name);
		bd->d_maxxfer &= ~(DEV_BSIZE - 1);
	}
	if (bd->d_maxxfer < DEV_BSIZE) {
		cmn_err(CE_WARN, "%s: maximum transfer size too small!", name);
		ddi_soft_state_free(bd_state, inst);
		return (DDI_FAILURE);
	}

	bd->d_dip = dip;
	bd->d_handle = hdl;
	hdl->h_bd = bd;
	ddi_set_driver_private(dip, bd);

	mutex_init(&bd->d_iomutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&bd->d_ocmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&bd->d_statemutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&bd->d_statecv, NULL, CV_DRIVER, NULL);

	list_create(&bd->d_waitq, sizeof (bd_xfer_impl_t),
	    offsetof(struct bd_xfer_impl, i_linkage));
	list_create(&bd->d_runq, sizeof (bd_xfer_impl_t),
	    offsetof(struct bd_xfer_impl, i_linkage));

	bd->d_cache = kmem_cache_create(kcache, sizeof (bd_xfer_impl_t), 8,
	    bd_xfer_ctor, bd_xfer_dtor, NULL, bd, NULL, 0);

	bd->d_ksp = kstat_create(ddi_driver_name(dip), inst, NULL, "disk",
	    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);
	if (bd->d_ksp != NULL) {
		bd->d_ksp->ks_lock = &bd->d_iomutex;
		kstat_install(bd->d_ksp);
		bd->d_kiop = bd->d_ksp->ks_data;
	} else {
		/*
		 * Even if we cannot create the kstat, we create a
		 * scratch kstat.  The reason for this is to ensure
		 * that we can update the kstat all of the time,
		 * without adding an extra branch instruction.
		 */
		bd->d_kiop = kmem_zalloc(sizeof (kstat_io_t), KM_SLEEP);
	}

	cmlb_alloc_handle(&bd->d_cmlbh);

	bd->d_state = DKIO_NONE;

	bzero(&drive, sizeof (drive));
	bd->d_ops.o_drive_info(bd->d_private, &drive);
	bd->d_qsize = drive.d_qsize;
	bd->d_removable = drive.d_removable;
	bd->d_hotpluggable = drive.d_hotpluggable;

	if (drive.d_maxxfer && drive.d_maxxfer < bd->d_maxxfer)
		bd->d_maxxfer = drive.d_maxxfer;

	bd_create_inquiry_props(dip, &drive);

	rv = cmlb_attach(dip, &bd_tg_ops, DTYPE_DIRECT,
	    bd->d_removable, bd->d_hotpluggable,
	    drive.d_lun >= 0 ? DDI_NT_BLOCK_CHAN : DDI_NT_BLOCK,
	    CMLB_FAKE_LABEL_ONE_PARTITION, bd->d_cmlbh, 0);
	if (rv != 0) {
		cmlb_free_handle(&bd->d_cmlbh);
		kmem_cache_destroy(bd->d_cache);
		mutex_destroy(&bd->d_iomutex);
		mutex_destroy(&bd->d_ocmutex);
		mutex_destroy(&bd->d_statemutex);
		cv_destroy(&bd->d_statecv);
		list_destroy(&bd->d_waitq);
		list_destroy(&bd->d_runq);
		if (bd->d_ksp != NULL) {
			kstat_delete(bd->d_ksp);
			bd->d_ksp = NULL;
		} else {
			kmem_free(bd->d_kiop, sizeof (kstat_io_t));
		}
		ddi_soft_state_free(bd_state, inst);
		return (DDI_FAILURE);
	}

	if (bd->d_ops.o_devid_init != NULL) {
		rv = bd->d_ops.o_devid_init(bd->d_private, dip, &bd->d_devid);
		if (rv == DDI_SUCCESS) {
			if (ddi_devid_register(dip, bd->d_devid) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s: unable to register devid", name);
			}
		}
	}

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers).  Also set up properties
	 * used by HAL to identify removable media.
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);
	if (bd->d_removable) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    "removable-media", NULL, 0);
	}
	if (bd->d_hotpluggable) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    "hotpluggable", NULL, 0);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
bd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	bd_t	*bd;

	bd = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		/* We don't suspend, but our parent does */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
	if (bd->d_ksp != NULL) {
		kstat_delete(bd->d_ksp);
		bd->d_ksp = NULL;
	} else {
		kmem_free(bd->d_kiop, sizeof (kstat_io_t));
	}
	cmlb_detach(bd->d_cmlbh, 0);
	cmlb_free_handle(&bd->d_cmlbh);
	if (bd->d_devid)
		ddi_devid_free(bd->d_devid);
	kmem_cache_destroy(bd->d_cache);
	mutex_destroy(&bd->d_iomutex);
	mutex_destroy(&bd->d_ocmutex);
	mutex_destroy(&bd->d_statemutex);
	cv_destroy(&bd->d_statecv);
	list_destroy(&bd->d_waitq);
	list_destroy(&bd->d_runq);
	ddi_soft_state_free(bd_state, ddi_get_instance(dip));
	return (DDI_SUCCESS);
}

static int
bd_xfer_ctor(void *buf, void *arg, int kmflag)
{
	bd_xfer_impl_t	*xi;
	bd_t		*bd = arg;
	int		(*dcb)(caddr_t);

	if (kmflag == KM_PUSHPAGE || kmflag == KM_SLEEP) {
		dcb = DDI_DMA_SLEEP;
	} else {
		dcb = DDI_DMA_DONTWAIT;
	}

	xi = buf;
	bzero(xi, sizeof (*xi));
	xi->i_bd = bd;

	if (bd->d_use_dma) {
		if (ddi_dma_alloc_handle(bd->d_dip, &bd->d_dma, dcb, NULL,
		    &xi->i_dmah) != DDI_SUCCESS) {
			return (-1);
		}
	}

	return (0);
}

static void
bd_xfer_dtor(void *buf, void *arg)
{
	bd_xfer_impl_t	*xi = buf;

	_NOTE(ARGUNUSED(arg));

	if (xi->i_dmah)
		ddi_dma_free_handle(&xi->i_dmah);
	xi->i_dmah = NULL;
}

static bd_xfer_impl_t *
bd_xfer_alloc(bd_t *bd, struct buf *bp, int (*func)(void *, bd_xfer_t *),
    int kmflag)
{
	bd_xfer_impl_t		*xi;
	int			rv = 0;
	int			status;
	unsigned		dir;
	int			(*cb)(caddr_t);
	size_t			len;
	uint32_t		shift;

	if (kmflag == KM_SLEEP) {
		cb = DDI_DMA_SLEEP;
	} else {
		cb = DDI_DMA_DONTWAIT;
	}

	xi = kmem_cache_alloc(bd->d_cache, kmflag);
	if (xi == NULL) {
		bioerror(bp, ENOMEM);
		return (NULL);
	}

	ASSERT(bp);

	xi->i_bp = bp;
	xi->i_func = func;
	xi->i_blkno = bp->b_lblkno;

	if (bp->b_bcount == 0) {
		xi->i_len = 0;
		xi->i_nblks = 0;
		xi->i_kaddr = NULL;
		xi->i_resid = 0;
		xi->i_num_win = 0;
		goto done;
	}

	if (bp->b_flags & B_READ) {
		dir = DDI_DMA_READ;
		xi->i_func = bd->d_ops.o_read;
	} else {
		dir = DDI_DMA_WRITE;
		xi->i_func = bd->d_ops.o_write;
	}

	shift = bd->d_blkshift;
	xi->i_blkshift = shift;

	if (!bd->d_use_dma) {
		bp_mapin(bp);
		rv = 0;
		xi->i_offset = 0;
		xi->i_num_win =
		    (bp->b_bcount + (bd->d_maxxfer - 1)) / bd->d_maxxfer;
		xi->i_cur_win = 0;
		xi->i_len = min(bp->b_bcount, bd->d_maxxfer);
		xi->i_nblks = xi->i_len >> shift;
		xi->i_kaddr = bp->b_un.b_addr;
		xi->i_resid = bp->b_bcount;
	} else {

		/*
		 * We have to use consistent DMA if the address is misaligned.
		 */
		if (((bp->b_flags & (B_PAGEIO | B_REMAPPED)) != B_PAGEIO) &&
		    ((uintptr_t)bp->b_un.b_addr & 0x7)) {
			dir |= DDI_DMA_CONSISTENT | DDI_DMA_PARTIAL;
		} else {
			dir |= DDI_DMA_STREAMING | DDI_DMA_PARTIAL;
		}

		status = ddi_dma_buf_bind_handle(xi->i_dmah, bp, dir, cb,
		    NULL, &xi->i_dmac, &xi->i_ndmac);
		switch (status) {
		case DDI_DMA_MAPPED:
			xi->i_num_win = 1;
			xi->i_cur_win = 0;
			xi->i_offset = 0;
			xi->i_len = bp->b_bcount;
			xi->i_nblks = xi->i_len >> shift;
			xi->i_resid = bp->b_bcount;
			rv = 0;
			break;
		case DDI_DMA_PARTIAL_MAP:
			xi->i_cur_win = 0;

			if ((ddi_dma_numwin(xi->i_dmah, &xi->i_num_win) !=
			    DDI_SUCCESS) ||
			    (ddi_dma_getwin(xi->i_dmah, 0, &xi->i_offset,
			    &len, &xi->i_dmac, &xi->i_ndmac) !=
			    DDI_SUCCESS) ||
			    (P2PHASE(len, shift) != 0)) {
				(void) ddi_dma_unbind_handle(xi->i_dmah);
				rv = EFAULT;
				goto done;
			}
			xi->i_len = len;
			xi->i_nblks = xi->i_len >> shift;
			xi->i_resid = bp->b_bcount;
			rv = 0;
			break;
		case DDI_DMA_NORESOURCES:
			rv = EAGAIN;
			goto done;
		case DDI_DMA_TOOBIG:
			rv = EINVAL;
			goto done;
		case DDI_DMA_NOMAPPING:
		case DDI_DMA_INUSE:
		default:
			rv = EFAULT;
			goto done;
		}
	}

done:
	if (rv != 0) {
		kmem_cache_free(bd->d_cache, xi);
		bioerror(bp, rv);
		return (NULL);
	}

	return (xi);
}

static void
bd_xfer_free(bd_xfer_impl_t *xi)
{
	if (xi->i_dmah) {
		(void) ddi_dma_unbind_handle(xi->i_dmah);
	}
	kmem_cache_free(xi->i_bd->d_cache, xi);
}

static int
bd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	dev_t		dev = *devp;
	bd_t		*bd;
	minor_t		part;
	minor_t		inst;
	uint64_t	mask;
	boolean_t	ndelay;
	int		rv;
	diskaddr_t	nblks;
	diskaddr_t	lba;

	_NOTE(ARGUNUSED(credp));

	part = BDPART(dev);
	inst = BDINST(dev);

	if (otyp >= OTYPCNT)
		return (EINVAL);

	ndelay = (flag & (FNDELAY | FNONBLOCK)) ? B_TRUE : B_FALSE;

	/*
	 * Block any DR events from changing the set of registered
	 * devices while we function.
	 */
	rw_enter(&bd_lock, RW_READER);
	if ((bd = ddi_get_soft_state(bd_state, inst)) == NULL) {
		rw_exit(&bd_lock);
		return (ENXIO);
	}

	mutex_enter(&bd->d_ocmutex);

	ASSERT(part < 64);
	mask = (1U << part);

	bd_update_state(bd);

	if (cmlb_validate(bd->d_cmlbh, 0, 0) != 0) {

		/* non-blocking opens are allowed to succeed */
		if (!ndelay) {
			rv = ENXIO;
			goto done;
		}
	} else if (cmlb_partinfo(bd->d_cmlbh, part, &nblks, &lba,
	    NULL, NULL, 0) == 0) {

		/*
		 * We read the partinfo, verify valid ranges.  If the
		 * partition is invalid, and we aren't blocking or
		 * doing a raw access, then fail. (Non-blocking and
		 * raw accesses can still succeed to allow a disk with
		 * bad partition data to opened by format and fdisk.)
		 */
		if ((!nblks) && ((!ndelay) || (otyp != OTYP_CHR))) {
			rv = ENXIO;
			goto done;
		}
	} else if (!ndelay) {
		/*
		 * cmlb_partinfo failed -- invalid partition or no
		 * disk label.
		 */
		rv = ENXIO;
		goto done;
	}

	if ((flag & FWRITE) && bd->d_rdonly) {
		rv = EROFS;
		goto done;
	}

	if ((bd->d_open_excl) & (mask)) {
		rv = EBUSY;
		goto done;
	}
	if (flag & FEXCL) {
		if (bd->d_open_lyr[part]) {
			rv = EBUSY;
			goto done;
		}
		for (int i = 0; i < OTYP_LYR; i++) {
			if (bd->d_open_reg[i] & mask) {
				rv = EBUSY;
				goto done;
			}
		}
	}

	if (otyp == OTYP_LYR) {
		bd->d_open_lyr[part]++;
	} else {
		bd->d_open_reg[otyp] |= mask;
	}
	if (flag & FEXCL) {
		bd->d_open_excl |= mask;
	}

	rv = 0;
done:
	mutex_exit(&bd->d_ocmutex);
	rw_exit(&bd_lock);

	return (rv);
}

static int
bd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	bd_t		*bd;
	minor_t		inst;
	minor_t		part;
	uint64_t	mask;
	boolean_t	last = B_TRUE;

	_NOTE(ARGUNUSED(flag));
	_NOTE(ARGUNUSED(credp));

	part = BDPART(dev);
	inst = BDINST(dev);

	ASSERT(part < 64);
	mask = (1U << part);

	rw_enter(&bd_lock, RW_READER);

	if ((bd = ddi_get_soft_state(bd_state, inst)) == NULL) {
		rw_exit(&bd_lock);
		return (ENXIO);
	}

	mutex_enter(&bd->d_ocmutex);
	if (bd->d_open_excl & mask) {
		bd->d_open_excl &= ~mask;
	}
	if (otyp == OTYP_LYR) {
		bd->d_open_lyr[part]--;
	} else {
		bd->d_open_reg[otyp] &= ~mask;
	}
	for (int i = 0; i < 64; i++) {
		if (bd->d_open_lyr[part]) {
			last = B_FALSE;
		}
	}
	for (int i = 0; last && (i < OTYP_LYR); i++) {
		if (bd->d_open_reg[i]) {
			last = B_FALSE;
		}
	}
	mutex_exit(&bd->d_ocmutex);

	if (last) {
		cmlb_invalidate(bd->d_cmlbh, 0);
	}
	rw_exit(&bd_lock);

	return (0);
}

static int
bd_dump(dev_t dev, caddr_t caddr, daddr_t blkno, int nblk)
{
	minor_t		inst;
	minor_t		part;
	diskaddr_t	pstart;
	diskaddr_t	psize;
	bd_t		*bd;
	bd_xfer_impl_t	*xi;
	buf_t		*bp;
	int		rv;

	rw_enter(&bd_lock, RW_READER);

	part = BDPART(dev);
	inst = BDINST(dev);

	if ((bd = ddi_get_soft_state(bd_state, inst)) == NULL) {
		rw_exit(&bd_lock);
		return (ENXIO);
	}
	/*
	 * do cmlb, but do it synchronously unless we already have the
	 * partition (which we probably should.)
	 */
	if (cmlb_partinfo(bd->d_cmlbh, part, &psize, &pstart, NULL, NULL,
	    (void *)1)) {
		rw_exit(&bd_lock);
		return (ENXIO);
	}

	if ((blkno + nblk) > psize) {
		rw_exit(&bd_lock);
		return (EINVAL);
	}
	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		rw_exit(&bd_lock);
		return (ENOMEM);
	}

	bp->b_bcount = nblk << bd->d_blkshift;
	bp->b_resid = bp->b_bcount;
	bp->b_lblkno = blkno;
	bp->b_un.b_addr = caddr;

	xi = bd_xfer_alloc(bd, bp,  bd->d_ops.o_write, KM_NOSLEEP);
	if (xi == NULL) {
		rw_exit(&bd_lock);
		freerbuf(bp);
		return (ENOMEM);
	}
	xi->i_blkno = blkno + pstart;
	xi->i_flags = BD_XFER_POLL;
	bd_submit(bd, xi);
	rw_exit(&bd_lock);

	/*
	 * Generally, we should have run this entirely synchronously
	 * at this point and the biowait call should be a no-op.  If
	 * it didn't happen this way, it's a bug in the underlying
	 * driver not honoring BD_XFER_POLL.
	 */
	(void) biowait(bp);
	rv = geterror(bp);
	freerbuf(bp);
	return (rv);
}

void
bd_minphys(struct buf *bp)
{
	minor_t inst;
	bd_t	*bd;
	inst = BDINST(bp->b_edev);

	bd = ddi_get_soft_state(bd_state, inst);

	/*
	 * In a non-debug kernel, bd_strategy will catch !bd as
	 * well, and will fail nicely.
	 */
	ASSERT(bd);

	if (bp->b_bcount > bd->d_maxxfer)
		bp->b_bcount = bd->d_maxxfer;
}

static int
bd_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp));
	return (physio(bd_strategy, NULL, dev, B_READ, bd_minphys, uio));
}

static int
bd_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp));
	return (physio(bd_strategy, NULL, dev, B_WRITE, bd_minphys, uio));
}

static int
bd_aread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp));
	return (aphysio(bd_strategy, anocancel, dev, B_READ, bd_minphys, aio));
}

static int
bd_awrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp));
	return (aphysio(bd_strategy, anocancel, dev, B_WRITE, bd_minphys, aio));
}

static int
bd_strategy(struct buf *bp)
{
	minor_t		inst;
	minor_t		part;
	bd_t		*bd;
	diskaddr_t	p_lba;
	diskaddr_t	p_nblks;
	diskaddr_t	b_nblks;
	bd_xfer_impl_t	*xi;
	uint32_t	shift;
	int		(*func)(void *, bd_xfer_t *);

	part = BDPART(bp->b_edev);
	inst = BDINST(bp->b_edev);

	ASSERT(bp);

	bp->b_resid = bp->b_bcount;

	if ((bd = ddi_get_soft_state(bd_state, inst)) == NULL) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	if (cmlb_partinfo(bd->d_cmlbh, part, &p_nblks, &p_lba,
	    NULL, NULL, 0)) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	shift = bd->d_blkshift;

	if ((P2PHASE(bp->b_bcount, (1U << shift)) != 0) ||
	    (bp->b_lblkno > p_nblks)) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}
	b_nblks = bp->b_bcount >> shift;
	if ((bp->b_lblkno == p_nblks) || (bp->b_bcount == 0)) {
		biodone(bp);
		return (0);
	}

	if ((b_nblks + bp->b_lblkno) > p_nblks) {
		bp->b_resid = ((bp->b_lblkno + b_nblks - p_nblks) << shift);
		bp->b_bcount -= bp->b_resid;
	} else {
		bp->b_resid = 0;
	}
	func = (bp->b_flags & B_READ) ? bd->d_ops.o_read : bd->d_ops.o_write;

	xi = bd_xfer_alloc(bd, bp, func, KM_NOSLEEP);
	if (xi == NULL) {
		xi = bd_xfer_alloc(bd, bp, func, KM_PUSHPAGE);
	}
	if (xi == NULL) {
		/* bd_request_alloc will have done bioerror */
		biodone(bp);
		return (0);
	}
	xi->i_blkno = bp->b_lblkno + p_lba;

	bd_submit(bd, xi);

	return (0);
}

static int
bd_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp, int *rvalp)
{
	minor_t		inst;
	uint16_t	part;
	bd_t		*bd;
	void		*ptr = (void *)arg;
	int		rv;

	part = BDPART(dev);
	inst = BDINST(dev);

	if ((bd = ddi_get_soft_state(bd_state, inst)) == NULL) {
		return (ENXIO);
	}

	rv = cmlb_ioctl(bd->d_cmlbh, dev, cmd, arg, flag, credp, rvalp, 0);
	if (rv != ENOTTY)
		return (rv);

	if (rvalp != NULL) {
		/* the return value of the ioctl is 0 by default */
		*rvalp = 0;
	}

	switch (cmd) {
	case DKIOCGMEDIAINFO: {
		struct dk_minfo minfo;

		/* make sure our state information is current */
		bd_update_state(bd);
		bzero(&minfo, sizeof (minfo));
		minfo.dki_media_type = DK_FIXED_DISK;
		minfo.dki_lbsize = (1U << bd->d_blkshift);
		minfo.dki_capacity = bd->d_numblks;
		if (ddi_copyout(&minfo, ptr, sizeof (minfo), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCGMEDIAINFOEXT: {
		struct dk_minfo_ext miext;

		/* make sure our state information is current */
		bd_update_state(bd);
		bzero(&miext, sizeof (miext));
		miext.dki_media_type = DK_FIXED_DISK;
		miext.dki_lbsize = (1U << bd->d_blkshift);
		miext.dki_pbsize = (1U << bd->d_pblkshift);
		miext.dki_capacity = bd->d_numblks;
		if (ddi_copyout(&miext, ptr, sizeof (miext), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCINFO: {
		struct dk_cinfo cinfo;
		bzero(&cinfo, sizeof (cinfo));
		cinfo.dki_ctype = DKC_BLKDEV;
		cinfo.dki_cnum = ddi_get_instance(ddi_get_parent(bd->d_dip));
		(void) snprintf(cinfo.dki_cname, sizeof (cinfo.dki_cname),
		    "%s", ddi_driver_name(ddi_get_parent(bd->d_dip)));
		(void) snprintf(cinfo.dki_dname, sizeof (cinfo.dki_dname),
		    "%s", ddi_driver_name(bd->d_dip));
		cinfo.dki_unit = inst;
		cinfo.dki_flags = DKI_FMTVOL;
		cinfo.dki_partition = part;
		cinfo.dki_maxtransfer = bd->d_maxxfer / DEV_BSIZE;
		cinfo.dki_addr = 0;
		cinfo.dki_slave = 0;
		cinfo.dki_space = 0;
		cinfo.dki_prio = 0;
		cinfo.dki_vec = 0;
		if (ddi_copyout(&cinfo, ptr, sizeof (cinfo), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCREMOVABLE: {
		int i;
		i = bd->d_removable ? 1 : 0;
		if (ddi_copyout(&i, ptr, sizeof (i), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCHOTPLUGGABLE: {
		int i;
		i = bd->d_hotpluggable ? 1 : 0;
		if (ddi_copyout(&i, ptr, sizeof (i), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCREADONLY: {
		int i;
		i = bd->d_rdonly ? 1 : 0;
		if (ddi_copyout(&i, ptr, sizeof (i), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCSOLIDSTATE: {
		int i;
		i = bd->d_ssd ? 1 : 0;
		if (ddi_copyout(&i, ptr, sizeof (i), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCSTATE: {
		enum dkio_state	state;
		if (ddi_copyin(ptr, &state, sizeof (state), flag)) {
			return (EFAULT);
		}
		if ((rv = bd_check_state(bd, &state)) != 0) {
			return (rv);
		}
		if (ddi_copyout(&state, ptr, sizeof (state), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DKIOCFLUSHWRITECACHE: {
		struct dk_callback *dkc = NULL;

		if (flag & FKIOCTL)
			dkc = (void *)arg;

		rv = bd_flush_write_cache(bd, dkc);
		return (rv);
	}

	default:
		break;

	}
	return (ENOTTY);
}

static int
bd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	bd_t	*bd;

	bd = ddi_get_soft_state(bd_state, ddi_get_instance(dip));
	if (bd == NULL)
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));

	return (cmlb_prop_op(bd->d_cmlbh, dev, dip, prop_op, mod_flags, name,
	    valuep, lengthp, BDPART(dev), 0));
}


static int
bd_tg_rdwr(dev_info_t *dip, uchar_t cmd, void *bufaddr, diskaddr_t start,
    size_t length, void *tg_cookie)
{
	bd_t		*bd;
	buf_t		*bp;
	bd_xfer_impl_t	*xi;
	int		rv;
	int		(*func)(void *, bd_xfer_t *);
	int		kmflag;

	/*
	 * If we are running in polled mode (such as during dump(9e)
	 * execution), then we cannot sleep for kernel allocations.
	 */
	kmflag = tg_cookie ? KM_NOSLEEP : KM_SLEEP;

	bd = ddi_get_soft_state(bd_state, ddi_get_instance(dip));

	if (P2PHASE(length, (1U << bd->d_blkshift)) != 0) {
		/* We can only transfer whole blocks at a time! */
		return (EINVAL);
	}

	if ((bp = getrbuf(kmflag)) == NULL) {
		return (ENOMEM);
	}

	switch (cmd) {
	case TG_READ:
		bp->b_flags = B_READ;
		func = bd->d_ops.o_read;
		break;
	case TG_WRITE:
		bp->b_flags = B_WRITE;
		func = bd->d_ops.o_write;
		break;
	default:
		freerbuf(bp);
		return (EINVAL);
	}

	bp->b_un.b_addr = bufaddr;
	bp->b_bcount = length;
	xi = bd_xfer_alloc(bd, bp, func, kmflag);
	if (xi == NULL) {
		rv = geterror(bp);
		freerbuf(bp);
		return (rv);
	}
	xi->i_flags = tg_cookie ? BD_XFER_POLL : 0;
	xi->i_blkno = start;
	bd_submit(bd, xi);
	(void) biowait(bp);
	rv = geterror(bp);
	freerbuf(bp);

	return (rv);
}

static int
bd_tg_getinfo(dev_info_t *dip, int cmd, void *arg, void *tg_cookie)
{
	bd_t		*bd;

	_NOTE(ARGUNUSED(tg_cookie));
	bd = ddi_get_soft_state(bd_state, ddi_get_instance(dip));

	switch (cmd) {
	case TG_GETPHYGEOM:
	case TG_GETVIRTGEOM:
		/*
		 * We don't have any "geometry" as such, let cmlb
		 * fabricate something.
		 */
		return (ENOTTY);

	case TG_GETCAPACITY:
		bd_update_state(bd);
		*(diskaddr_t *)arg = bd->d_numblks;
		return (0);

	case TG_GETBLOCKSIZE:
		*(uint32_t *)arg = (1U << bd->d_blkshift);
		return (0);

	case TG_GETATTR:
		/*
		 * It turns out that cmlb really doesn't do much for
		 * non-writable media, but lets make the information
		 * available for it in case it does more in the
		 * future.  (The value is currently used for
		 * triggering special behavior for CD-ROMs.)
		 */
		bd_update_state(bd);
		((tg_attribute_t *)arg)->media_is_writable =
		    bd->d_rdonly ? B_FALSE : B_TRUE;
		((tg_attribute_t *)arg)->media_is_solid_state = bd->d_ssd;
		return (0);

	default:
		return (EINVAL);
	}
}


static void
bd_sched(bd_t *bd)
{
	bd_xfer_impl_t	*xi;
	struct buf	*bp;
	int		rv;

	mutex_enter(&bd->d_iomutex);

	while ((bd->d_qactive < bd->d_qsize) &&
	    ((xi = list_remove_head(&bd->d_waitq)) != NULL)) {
		bd->d_qactive++;
		kstat_waitq_to_runq(bd->d_kiop);
		list_insert_tail(&bd->d_runq, xi);

		/*
		 * Submit the job to the driver.  We drop the I/O mutex
		 * so that we can deal with the case where the driver
		 * completion routine calls back into us synchronously.
		 */

		mutex_exit(&bd->d_iomutex);

		rv = xi->i_func(bd->d_private, &xi->i_public);
		if (rv != 0) {
			bp = xi->i_bp;
			bioerror(bp, rv);
			biodone(bp);

			mutex_enter(&bd->d_iomutex);
			bd->d_qactive--;
			kstat_runq_exit(bd->d_kiop);
			list_remove(&bd->d_runq, xi);
			bd_xfer_free(xi);
		} else {
			mutex_enter(&bd->d_iomutex);
		}
	}

	mutex_exit(&bd->d_iomutex);
}

static void
bd_submit(bd_t *bd, bd_xfer_impl_t *xi)
{
	mutex_enter(&bd->d_iomutex);
	list_insert_tail(&bd->d_waitq, xi);
	kstat_waitq_enter(bd->d_kiop);
	mutex_exit(&bd->d_iomutex);

	bd_sched(bd);
}

static void
bd_runq_exit(bd_xfer_impl_t *xi, int err)
{
	bd_t	*bd = xi->i_bd;
	buf_t	*bp = xi->i_bp;

	mutex_enter(&bd->d_iomutex);
	bd->d_qactive--;
	kstat_runq_exit(bd->d_kiop);
	list_remove(&bd->d_runq, xi);
	mutex_exit(&bd->d_iomutex);

	if (err == 0) {
		if (bp->b_flags & B_READ) {
			bd->d_kiop->reads++;
			bd->d_kiop->nread += (bp->b_bcount - xi->i_resid);
		} else {
			bd->d_kiop->writes++;
			bd->d_kiop->nwritten += (bp->b_bcount - xi->i_resid);
		}
	}
	bd_sched(bd);
}

static void
bd_update_state(bd_t *bd)
{
	enum	dkio_state	state = DKIO_INSERTED;
	boolean_t		docmlb = B_FALSE;
	bd_media_t		media;

	bzero(&media, sizeof (media));

	mutex_enter(&bd->d_statemutex);
	if (bd->d_ops.o_media_info(bd->d_private, &media) != 0) {
		bd->d_numblks = 0;
		state = DKIO_EJECTED;
		goto done;
	}

	if ((media.m_blksize < 512) ||
	    (!ISP2(media.m_blksize)) ||
	    (P2PHASE(bd->d_maxxfer, media.m_blksize))) {
		cmn_err(CE_WARN, "%s%d: Invalid media block size (%d)",
		    ddi_driver_name(bd->d_dip), ddi_get_instance(bd->d_dip),
		    media.m_blksize);
		/*
		 * We can't use the media, treat it as not present.
		 */
		state = DKIO_EJECTED;
		bd->d_numblks = 0;
		goto done;
	}

	if (((1U << bd->d_blkshift) != media.m_blksize) ||
	    (bd->d_numblks != media.m_nblks)) {
		/* Device size changed */
		docmlb = B_TRUE;
	}

	bd->d_blkshift = ddi_ffs(media.m_blksize) - 1;
	bd->d_pblkshift = bd->d_blkshift;
	bd->d_numblks = media.m_nblks;
	bd->d_rdonly = media.m_readonly;
	bd->d_ssd = media.m_solidstate;

	/*
	 * Only use the supplied physical block size if it is non-zero,
	 * greater or equal to the block size, and a power of 2. Ignore it
	 * if not, it's just informational and we can still use the media.
	 */
	if ((media.m_pblksize != 0) &&
	    (media.m_pblksize >= media.m_blksize) &&
	    (ISP2(media.m_pblksize)))
		bd->d_pblkshift = ddi_ffs(media.m_pblksize) - 1;

done:
	if (state != bd->d_state) {
		bd->d_state = state;
		cv_broadcast(&bd->d_statecv);
		docmlb = B_TRUE;
	}
	mutex_exit(&bd->d_statemutex);

	if (docmlb) {
		if (state == DKIO_INSERTED) {
			(void) cmlb_validate(bd->d_cmlbh, 0, 0);
		} else {
			cmlb_invalidate(bd->d_cmlbh, 0);
		}
	}
}

static int
bd_check_state(bd_t *bd, enum dkio_state *state)
{
	clock_t		when;

	for (;;) {

		bd_update_state(bd);

		mutex_enter(&bd->d_statemutex);

		if (bd->d_state != *state) {
			*state = bd->d_state;
			mutex_exit(&bd->d_statemutex);
			break;
		}

		when = drv_usectohz(1000000);
		if (cv_reltimedwait_sig(&bd->d_statecv, &bd->d_statemutex,
		    when, TR_CLOCK_TICK) == 0) {
			mutex_exit(&bd->d_statemutex);
			return (EINTR);
		}

		mutex_exit(&bd->d_statemutex);
	}

	return (0);
}

static int
bd_flush_write_cache_done(struct buf *bp)
{
	struct dk_callback *dc = (void *)bp->b_private;

	(*dc->dkc_callback)(dc->dkc_cookie, geterror(bp));
	kmem_free(dc, sizeof (*dc));
	freerbuf(bp);
	return (0);
}

static int
bd_flush_write_cache(bd_t *bd, struct dk_callback *dkc)
{
	buf_t			*bp;
	struct dk_callback	*dc;
	bd_xfer_impl_t		*xi;
	int			rv;

	if (bd->d_ops.o_sync_cache == NULL) {
		return (ENOTSUP);
	}
	if ((bp = getrbuf(KM_SLEEP)) == NULL) {
		return (ENOMEM);
	}
	bp->b_resid = 0;
	bp->b_bcount = 0;

	xi = bd_xfer_alloc(bd, bp, bd->d_ops.o_sync_cache, KM_SLEEP);
	if (xi == NULL) {
		rv = geterror(bp);
		freerbuf(bp);
		return (rv);
	}

	/* Make an asynchronous flush, but only if there is a callback */
	if (dkc != NULL && dkc->dkc_callback != NULL) {
		/* Make a private copy of the callback structure */
		dc = kmem_alloc(sizeof (*dc), KM_SLEEP);
		*dc = *dkc;
		bp->b_private = dc;
		bp->b_iodone = bd_flush_write_cache_done;

		bd_submit(bd, xi);
		return (0);
	}

	/* In case there is no callback, perform a synchronous flush */
	bd_submit(bd, xi);
	(void) biowait(bp);
	rv = geterror(bp);
	freerbuf(bp);

	return (rv);
}

/*
 * Nexus support.
 */
int
bd_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	bd_handle_t	hdl;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		cmn_err(CE_CONT, "?Block device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		hdl = ddi_get_parent_data((dev_info_t *)arg);
		if (hdl == NULL) {
			return (DDI_NOT_WELL_FORMED);
		}
		ddi_set_name_addr((dev_info_t *)arg, hdl->h_addr);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr((dev_info_t *)arg, NULL);
		ndi_prop_remove_all((dev_info_t *)arg);
		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/*
 * Functions for device drivers.
 */
bd_handle_t
bd_alloc_handle(void *private, bd_ops_t *ops, ddi_dma_attr_t *dma, int kmflag)
{
	bd_handle_t	hdl;

	hdl = kmem_zalloc(sizeof (*hdl), kmflag);
	if (hdl != NULL) {
		hdl->h_ops = *ops;
		hdl->h_dma = dma;
		hdl->h_private = private;
	}

	return (hdl);
}

void
bd_free_handle(bd_handle_t hdl)
{
	kmem_free(hdl, sizeof (*hdl));
}

int
bd_attach_handle(dev_info_t *dip, bd_handle_t hdl)
{
	dev_info_t	*child;
	bd_drive_t	drive = { 0 };

	/* if drivers don't override this, make it assume none */
	drive.d_lun = -1;
	hdl->h_ops.o_drive_info(hdl->h_private, &drive);

	hdl->h_parent = dip;
	hdl->h_name = "blkdev";

	if (drive.d_lun >= 0) {
		(void) snprintf(hdl->h_addr, sizeof (hdl->h_addr), "%X,%X",
		    drive.d_target, drive.d_lun);
	} else {
		(void) snprintf(hdl->h_addr, sizeof (hdl->h_addr), "%X",
		    drive.d_target);
	}
	if (ndi_devi_alloc(dip, hdl->h_name, (pnode_t)DEVI_SID_NODEID,
	    &child) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to allocate node %s@%s",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    "blkdev", hdl->h_addr);
		return (DDI_FAILURE);
	}

	ddi_set_parent_data(child, hdl);
	hdl->h_child = child;

	if (ndi_devi_online(child, 0) == NDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: failed bringing node %s@%s online",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    hdl->h_name, hdl->h_addr);
		(void) ndi_devi_free(child);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
bd_detach_handle(bd_handle_t hdl)
{
	int	circ;
	int	rv;
	char	*devnm;

	if (hdl->h_child == NULL) {
		return (DDI_SUCCESS);
	}
	ndi_devi_enter(hdl->h_parent, &circ);
	if (i_ddi_node_state(hdl->h_child) < DS_INITIALIZED) {
		rv = ddi_remove_child(hdl->h_child, 0);
	} else {
		devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(hdl->h_child, devnm);
		(void) devfs_clean(hdl->h_parent, devnm + 1, DV_CLEAN_FORCE);
		rv = ndi_devi_unconfig_one(hdl->h_parent, devnm + 1, NULL,
		    NDI_DEVI_REMOVE | NDI_UNCONFIG);
		kmem_free(devnm, MAXNAMELEN + 1);
	}
	if (rv == 0) {
		hdl->h_child = NULL;
	}

	ndi_devi_exit(hdl->h_parent, circ);
	return (rv = NDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}

void
bd_xfer_done(bd_xfer_t *xfer, int err)
{
	bd_xfer_impl_t	*xi = (void *)xfer;
	buf_t		*bp = xi->i_bp;
	int		rv = DDI_SUCCESS;
	bd_t		*bd = xi->i_bd;
	size_t		len;

	if (err != 0) {
		bd_runq_exit(xi, err);

		bp->b_resid += xi->i_resid;
		bd_xfer_free(xi);
		bioerror(bp, err);
		biodone(bp);
		return;
	}

	xi->i_cur_win++;
	xi->i_resid -= xi->i_len;

	if (xi->i_resid == 0) {
		/* Job completed succcessfully! */
		bd_runq_exit(xi, 0);

		bd_xfer_free(xi);
		biodone(bp);
		return;
	}

	xi->i_blkno += xi->i_nblks;

	if (bd->d_use_dma) {
		/* More transfer still pending... advance to next DMA window. */
		rv = ddi_dma_getwin(xi->i_dmah, xi->i_cur_win,
		    &xi->i_offset, &len, &xi->i_dmac, &xi->i_ndmac);
	} else {
		/* Advance memory window. */
		xi->i_kaddr += xi->i_len;
		xi->i_offset += xi->i_len;
		len = min(bp->b_bcount - xi->i_offset, bd->d_maxxfer);
	}


	if ((rv != DDI_SUCCESS) ||
	    (P2PHASE(len, (1U << xi->i_blkshift) != 0))) {
		bd_runq_exit(xi, EFAULT);

		bp->b_resid += xi->i_resid;
		bd_xfer_free(xi);
		bioerror(bp, EFAULT);
		biodone(bp);
		return;
	}
	xi->i_len = len;
	xi->i_nblks = len >> xi->i_blkshift;

	/* Submit next window to hardware. */
	rv = xi->i_func(bd->d_private, &xi->i_public);
	if (rv != 0) {
		bd_runq_exit(xi, rv);

		bp->b_resid += xi->i_resid;
		bd_xfer_free(xi);
		bioerror(bp, rv);
		biodone(bp);
	}
}

void
bd_state_change(bd_handle_t hdl)
{
	bd_t		*bd;

	if ((bd = hdl->h_bd) != NULL) {
		bd_update_state(bd);
	}
}

void
bd_mod_init(struct dev_ops *devops)
{
	static struct bus_ops bd_bus_ops = {
		BUSO_REV,		/* busops_rev */
		nullbusmap,		/* bus_map */
		NULL,			/* bus_get_intrspec (OBSOLETE) */
		NULL,			/* bus_add_intrspec (OBSOLETE) */
		NULL,			/* bus_remove_intrspec (OBSOLETE) */
		i_ddi_map_fault,	/* bus_map_fault */
		NULL,			/* bus_dma_map (OBSOLETE) */
		ddi_dma_allochdl,	/* bus_dma_allochdl */
		ddi_dma_freehdl,	/* bus_dma_freehdl */
		ddi_dma_bindhdl,	/* bus_dma_bindhdl */
		ddi_dma_unbindhdl,	/* bus_dma_unbindhdl */
		ddi_dma_flush,		/* bus_dma_flush */
		ddi_dma_win,		/* bus_dma_win */
		ddi_dma_mctl,		/* bus_dma_ctl */
		bd_bus_ctl,		/* bus_ctl */
		ddi_bus_prop_op,	/* bus_prop_op */
		NULL,			/* bus_get_eventcookie */
		NULL,			/* bus_add_eventcall */
		NULL,			/* bus_remove_eventcall */
		NULL,			/* bus_post_event */
		NULL,			/* bus_intr_ctl (OBSOLETE) */
		NULL,			/* bus_config */
		NULL,			/* bus_unconfig */
		NULL,			/* bus_fm_init */
		NULL,			/* bus_fm_fini */
		NULL,			/* bus_fm_access_enter */
		NULL,			/* bus_fm_access_exit */
		NULL,			/* bus_power */
		NULL,			/* bus_intr_op */
	};

	devops->devo_bus_ops = &bd_bus_ops;

	/*
	 * NB: The device driver is free to supply its own
	 * character entry device support.
	 */
}

void
bd_mod_fini(struct dev_ops *devops)
{
	devops->devo_bus_ops = NULL;
}
