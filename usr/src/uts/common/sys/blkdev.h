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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_BLKDEV_H
#define	_SYS_BLKDEV_H

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This describes a fairly simple block device.  The idea here is that
 * these things want to take advantage of the common labelling support,
 * but do not need all the capabilities of SCSA.  So we make quite a few
 * simplifications:
 *
 * 1) Device block size is a power of 2 greater or equal to 512 bytes.
 *    An optional physical block size can be reported if the underlying
 *    device uses larger block sizes internally, so that writes can be
 *    aligned properly.
 *
 * 2) Non-rotating media.  We assume a simple linear layout.
 *
 * 3) Fixed queue depth, for each device.  The adapter driver reports
 *    the queue depth at registration.  We don't have any form of
 *    dynamic flow control.
 *
 * 4) Negligible power management support.  The framework does not support
 *    fine grained power management.  If the adapter driver wants to use
 *    such, it will need to manage power on its own.
 *
 * 5) Suspend/resume support managed by the adapter driver.  We don't
 *    support suspend/resume directly.  The adapter device driver will
 *    need to manage this on its own behalf.
 *
 * 6) No request priorities.  Transfers are assumed to execute in
 *    roughly FIFO order.  The adapter driver may reorder them, but the
 *    submitter has no control over that.
 *
 * 7) No request cancellation.  Once submitted, the job completes or
 *    fails.  It cannot be canceled.
 *
 * 8) Limited support for removable media.  There is no support for
 *    locking bay doors or mechanised media bays.  This could be
 *    added, but at present the only such interesting devices are
 *    covered by the SCSI disk driver.
 */

typedef struct bd_handle *bd_handle_t;
typedef struct bd_xfer bd_xfer_t;
typedef struct bd_drive bd_drive_t;
typedef struct bd_media bd_media_t;
typedef struct bd_ops bd_ops_t;


struct bd_xfer {
	/*
	 * NB: If using DMA the br_ndmac will be non-zero.  Otherwise
	 * the br_kaddr will be non-NULL.
	 */
	diskaddr_t		x_blkno;
	size_t			x_nblks;
	ddi_dma_handle_t	x_dmah;
	ddi_dma_cookie_t	x_dmac;
	unsigned		x_ndmac;
	caddr_t			x_kaddr;
	unsigned		x_flags;
};

#define	BD_XFER_POLL		(1U << 0)	/* no interrupts (dump) */

struct bd_drive {
	uint32_t		d_qsize;
	uint32_t		d_maxxfer;
	boolean_t		d_removable;
	boolean_t		d_hotpluggable;
	int			d_target;
	int			d_lun;
	size_t			d_vendor_len;
	char			*d_vendor;
	size_t			d_product_len;
	char			*d_product;
	size_t			d_model_len;
	char			*d_model;
	size_t			d_serial_len;
	char			*d_serial;
	size_t			d_revision_len;
	char			*d_revision;
	uint8_t			d_eui64[8];
};

struct bd_media {
	/*
	 * NB: The block size must be a power of two not less than
	 * DEV_BSIZE (512).  Other values of the block size will
	 * simply not function and the media will be rejected.
	 *
	 * The block size must also divide evenly into the device's
	 * d_maxxfer field.  If the maxxfer is a power of two larger
	 * than the block size, then this will automatically be
	 * satisfied.
	 *
	 * The physical block size (m_pblksize) must be 0 or a power
	 * of two not less than the block size.
	 */
	uint64_t		m_nblks;
	uint32_t		m_blksize;
	boolean_t		m_readonly;
	boolean_t		m_solidstate;
	uint32_t		m_pblksize;
};

#define	BD_INFO_FLAG_REMOVABLE		(1U << 0)
#define	BD_INFO_FLAG_HOTPLUGGABLE	(1U << 1)
#define	BD_INFO_FLAG_READ_ONLY		(1U << 2)

struct bd_ops {
	int	o_version;
	void	(*o_drive_info)(void *, bd_drive_t *);
	int	(*o_media_info)(void *, bd_media_t *);
	int	(*o_devid_init)(void *, dev_info_t *, ddi_devid_t *);
	int	(*o_sync_cache)(void *, bd_xfer_t *);
	int	(*o_read)(void *, bd_xfer_t *);
	int	(*o_write)(void *, bd_xfer_t *);
};

#define	BD_OPS_VERSION_0		0

struct bd_errstats {
	/* these are managed by blkdev itself */
	kstat_named_t	bd_softerrs;
	kstat_named_t	bd_harderrs;
	kstat_named_t	bd_transerrs;
	kstat_named_t	bd_model;
	kstat_named_t	bd_vid;
	kstat_named_t	bd_pid;
	kstat_named_t	bd_revision;
	kstat_named_t	bd_serial;
	kstat_named_t	bd_capacity;

	/* the following are updated on behalf of the HW driver */
	kstat_named_t	bd_rq_media_err;
	kstat_named_t	bd_rq_ntrdy_err;
	kstat_named_t	bd_rq_nodev_err;
	kstat_named_t	bd_rq_recov_err;
	kstat_named_t	bd_rq_illrq_err;
	kstat_named_t	bd_rq_pfa_err;
};

#define	BD_ERR_MEDIA	0
#define	BD_ERR_NTRDY	1
#define	BD_ERR_NODEV	2
#define	BD_ERR_RECOV	3
#define	BD_ERR_ILLRQ	4
#define	BD_ERR_PFA	5

/*
 * Note, one handler *per* address.  Drivers with multiple targets at
 * different addresses must use separate handles.
 */
bd_handle_t	bd_alloc_handle(void *, bd_ops_t *, ddi_dma_attr_t *, int);
void		bd_free_handle(bd_handle_t);
int		bd_attach_handle(dev_info_t *, bd_handle_t);
int		bd_detach_handle(bd_handle_t);
void		bd_state_change(bd_handle_t);
void		bd_xfer_done(bd_xfer_t *, int);
void		bd_error(bd_xfer_t *, int);
void		bd_mod_init(struct dev_ops *);
void		bd_mod_fini(struct dev_ops *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BLKDEV_H */
