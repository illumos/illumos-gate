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
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AGPMASTER_IO_H
#define	_SYS_AGPMASTER_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AGPMASTER_NAME		"agpmaster"
#define	AGPMASTER_DEVLINK	"/dev/agp/agpmaster"

/* macros for layered ioctls */
#define	AGPMASTERIOC_BASE		'M'
#define	DEVICE_DETECT		_IOR(AGPMASTERIOC_BASE, 10, int)
#define	I8XX_GET_INFO		_IOR(AGPMASTERIOC_BASE, 11, igd_info_t)
#define	I810_SET_GTT_BASE	_IOW(AGPMASTERIOC_BASE, 12, uint32_t)
#define	I8XX_ADD2GTT		_IOW(AGPMASTERIOC_BASE, 13, igd_gtt_seg_t)
#define	I8XX_REM_GTT		_IOW(AGPMASTERIOC_BASE, 14, igd_gtt_seg_t)
#define	I8XX_UNCONFIG		_IO(AGPMASTERIOC_BASE, 16)
#define	AGP_MASTER_GETINFO	_IOR(AGPMASTERIOC_BASE, 20, agp_info_t)
#define	AGP_MASTER_SETCMD	_IOW(AGPMASTERIOC_BASE, 21, uint32_t)

/* used for IGD to bind/unbind gtt entries */
typedef struct igd_gtt_seg {
	uint32_t	igs_pgstart;
	uint32_t	igs_npage;
	uint32_t	*igs_phyaddr; /* pointer to address array */
	uint32_t	igs_type; /* reserved for other memory type */
} igd_gtt_seg_t;

/* used for IGD to get info */
typedef struct igd_info {
	uint32_t	igd_devid;
	uint32_t	igd_aperbase;
	size_t		igd_apersize; /* in MB */
} igd_info_t;

typedef struct gtt_impl {
	ddi_acc_handle_t	gtt_mmio_handle; /* mmaped graph registers */
	caddr_t			gtt_mmio_base; /* pointer to register base */
	ddi_acc_handle_t	gtt_handle; /* GTT table */
	caddr_t			gtt_addr; /* pointer to gtt */
	igd_info_t		gtt_info; /* for I8XX_GET_INFO ioctl */
} gtt_impl_t;

typedef struct agp_master_softc {
	uint32_t		agpm_id; /* agp master device id */
	ddi_acc_handle_t	agpm_acc_hdl; /* agp master pci conf handle */
	int			agpm_dev_type; /* which agp device type */
	union {
		off_t		agpm_acaptr; /* AGP capability reg pointer */
		gtt_impl_t	agpm_gtt; /* for gtt table */
	} agpm_data;
} agp_master_softc_t;

extern int agpmaster_attach(dev_info_t *, agp_master_softc_t **,
    ddi_acc_handle_t, minor_t);
extern void agpmaster_detach(agp_master_softc_t **);
extern int agpmaster_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *cred, int *rval, agp_master_softc_t *softc);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AGPMASTER_IO_H */
