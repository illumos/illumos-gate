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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DDIFM_H
#define	_DDIFM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dditypes.h>
#include <sys/va_list.h>

extern int ddi_system_fmcap;

/* Fault Management error handling */

/* Error handling return status */
#define	DDI_FM_OK		0
#define	DDI_FM_FATAL	-1
#define	DDI_FM_NONFATAL	-2
#define	DDI_FM_UNKNOWN	-3

/* Driver fault management capabilities */
#define	DDI_FM_NOT_CAPABLE	0x00000000
#define	DDI_FM_EREPORT_CAPABLE	0x00000001
#define	DDI_FM_ACCCHK_CAPABLE	0x00000002
#define	DDI_FM_DMACHK_CAPABLE	0x00000004
#define	DDI_FM_ERRCB_CAPABLE	0x00000008

#define	DDI_FM_DEFAULT_CAP(cap)	(cap == DDI_FM_NOT_CAPABLE)
#define	DDI_FM_EREPORT_CAP(cap)	(cap & DDI_FM_EREPORT_CAPABLE)
#define	DDI_FM_ACC_ERR_CAP(cap)	(cap & DDI_FM_ACCCHK_CAPABLE)
#define	DDI_FM_DMA_ERR_CAP(cap)	(cap & DDI_FM_DMACHK_CAPABLE)
#define	DDI_FM_ERRCB_CAP(cap)	(cap & DDI_FM_ERRCB_CAPABLE)

/* error expectation values */
#define	DDI_FM_ERR_UNEXPECTED	0
#define	DDI_FM_ERR_EXPECTED	1
#define	DDI_FM_ERR_POKE		2
#define	DDI_FM_ERR_PEEK		3

#ifdef _KERNEL

typedef struct ddi_fm_error {
	int fme_version;			/* version of this structure */
	int fme_status;				/* status for this error */
	int fme_flag;				/* error expectation flag */
	uint64_t fme_ena;			/* ENA for this error */
	ddi_acc_handle_t fme_acc_handle;	/* optional acc handle */
	ddi_dma_handle_t fme_dma_handle;	/* optional dma handle */
	void *fme_bus_specific;			/* optional bus specific err */
	int fme_bus_type;			/* optional bus type */
} ddi_fm_error_t;

#define	DDI_FME_VER0	0
#define	DDI_FME_VER1	1
#define	DDI_FME_VERSION	DDI_FME_VER1

#define	DDI_FME_BUS_TYPE_DFLT	0		/* bus type = default */
#define	DDI_FME_BUS_TYPE_PCI	1		/* bus type = pci/pcix/pcie */

typedef int (*ddi_err_func_t)(dev_info_t *, ddi_fm_error_t *, const void *);

/*
 * DDI for error handling and ereport generation
 */

/*
 * ereport generation: [ddi|ndi]_fm_ereport_post
 */
extern void ddi_fm_ereport_post(dev_info_t *, const char *, uint64_t, int, ...);
extern void ndi_fm_ereport_post(dev_info_t *, const char *, uint64_t, int, ...);

/*
 * service changes:
 *
 * After a hardened driver raises an ereport (or after pci_ereport_post() has
 * raised an ereport for an event which implecated one of a driver's access or
 * dma handles), the driver should always determine the service impact and
 * report it.
 */
extern void ddi_fm_service_impact(dev_info_t *, int);

/* error handling */
extern void ddi_fm_handler_register(dev_info_t *, ddi_err_func_t, void *);
extern void ddi_fm_handler_unregister(dev_info_t *);

/* fault management initialization and clean-up */
extern void ddi_fm_init(dev_info_t *, int *, ddi_iblock_cookie_t *);
extern void ddi_fm_fini(dev_info_t *);
extern int ddi_fm_capable(dev_info_t *dip);

/* access and dma handle error protection */
extern void ddi_fm_dma_err_get(ddi_dma_handle_t, ddi_fm_error_t *, int);
extern void ddi_fm_acc_err_get(ddi_acc_handle_t, ddi_fm_error_t *, int);
extern void ddi_fm_dma_err_clear(ddi_dma_handle_t, int);
extern void ddi_fm_acc_err_clear(ddi_acc_handle_t, int);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _DDIFM_H */
