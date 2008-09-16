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

#ifndef	_SYS_IOMMULIB_H
#define	_SYS_IOMMULIB_H

#pragma ident	"@(#)iommulib.h	1.3	08/08/31 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_impldefs.h>

#ifdef	_KERNEL

typedef enum {
	INVALID_VENDOR = 0,
	AMD_IOMMU,
	INTEL_IOMMU
} iommulib_vendor_t;

typedef enum {
	IOMMU_OPS_VERSION_INVALID = 0,
	IOMMU_OPS_VERSION_1 = 1
} iommulib_opsversion_t;

#define	IOMMU_OPS_VERSION IOMMU_OPS_VERSION_1

typedef struct iommulib_ops {
	iommulib_opsversion_t	ilops_vers;
	iommulib_vendor_t	ilops_vendor;
	char			*ilops_id;
	void			*ilops_data;

	int	(*ilops_probe)(dev_info_t *rdip);

	int	(*ilops_dma_allochdl)(iommulib_handle_t handle,
	    dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
	    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *dma_handlep);

	int	(*ilops_dma_freehdl)(iommulib_handle_t handle,
	    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);

	int	(*ilops_dma_bindhdl)(iommulib_handle_t handle, dev_info_t *dip,
	    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
	    struct ddi_dma_req *dmareq, ddi_dma_cookie_t *cookiep,
	    uint_t *ccountp);

	int	(*ilops_dma_unbindhdl)(iommulib_handle_t handle,
	    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);

	int	(*ilops_dma_sync)(iommulib_handle_t handle, dev_info_t *dip,
	    dev_info_t *rdip, ddi_dma_handle_t dma_handle, off_t off,
	    size_t len, uint_t cache_flags);

	int	(*ilops_dma_win)(iommulib_handle_t handle, dev_info_t *dip,
	    dev_info_t *rdip, ddi_dma_handle_t dma_handle, uint_t win,
	    off_t *offp, size_t *lenp, ddi_dma_cookie_t *cookiep,
	    uint_t *ccountp);


	/* Obsolete DMA routines */

	int	(*ilops_dma_map)(iommulib_handle_t handle, dev_info_t *dip,
	    dev_info_t *rdip, struct ddi_dma_req *dmareq,
	    ddi_dma_handle_t *dma_handle);

	int	(*ilops_dma_mctl)(iommulib_handle_t handle, dev_info_t *dip,
	    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
	    enum ddi_dma_ctlops request, off_t *offp, size_t *lenp,
	    caddr_t *objpp, uint_t cache_flags);

} iommulib_ops_t;

#define	IOMMU_USED(dip)	(DEVI(dip)->devi_iommulib_handle != NULL)

typedef enum {
	IOMMU_NEXOPS_VERSION_INVALID = 0,
	IOMMU_NEXOPS_VERSION_1 = 1
} iommulib_nexops_version_t;

#define	IOMMU_NEXOPS_VERSION IOMMU_NEXOPS_VERSION_1

typedef struct iommulib_nexops {
	iommulib_nexops_version_t	nops_vers;
	char			*nops_id;
	void			*nops_data;

	int (*nops_dma_allochdl)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_attr_t *attr, int (*waitfp)(caddr_t), caddr_t arg,
	    ddi_dma_handle_t *handlep);

	int (*nops_dma_freehdl)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle);

	int (*nops_dma_bindhdl)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
	    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

	int (*nops_dma_unbindhdl)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle);

	void (*nops_dma_reset_cookies)(dev_info_t *dip,
	    ddi_dma_handle_t handle);

	int (*nops_dma_get_cookies)(dev_info_t *dip, ddi_dma_handle_t handle,
	    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

	int (*nops_dma_sync)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags);

	int (*nops_dma_win)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, uint_t win, off_t *offp, size_t *lenp,
	    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

	int (*nops_dma_map)(dev_info_t *dip, dev_info_t *rdip,
	    struct ddi_dma_req *dmareq, ddi_dma_handle_t *handlep);

	int (*nops_dma_mctl)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, enum ddi_dma_ctlops request, off_t *offp,
	    size_t *lenp, caddr_t *objpp, uint_t cache_flags);
} iommulib_nexops_t;

struct iommulib_nex;
typedef struct iommulib_nex *iommulib_nexhandle_t;

/*
 * Interfaces for nexus drivers - typically rootnex
 */

int iommulib_nexus_register(dev_info_t *dip, iommulib_nexops_t *nexops,
    iommulib_nexhandle_t *handle);

int iommulib_nexus_unregister(iommulib_nexhandle_t handle);

int iommulib_nex_open(dev_info_t *rdip, uint_t *errorp);
void iommulib_nex_close(dev_info_t *rdip);

int iommulib_nexdma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr, int (*waitfp)(caddr_t),
    caddr_t arg, ddi_dma_handle_t *dma_handlep);

int iommulib_nexdma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle);

int iommulib_nexdma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_nexdma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle);

int iommulib_nexdma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, off_t off, size_t len,
    uint_t cache_flags);

int iommulib_nexdma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, uint_t win, off_t *offp, size_t *lenp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_nexdma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareq, ddi_dma_handle_t *dma_handle);

int iommulib_nexdma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objpp, uint_t cache_flags);

/*
 * Interfaces for IOMMU drivers provided by IOMMULIB
 */

int iommulib_iommu_register(dev_info_t *dip, iommulib_ops_t *ops,
    iommulib_handle_t *handle);

int iommulib_iommu_unregister(iommulib_handle_t handle);

int iommulib_iommu_getunitid(iommulib_handle_t handle, uint64_t *unitidp);

dev_info_t *iommulib_iommu_getdip(iommulib_handle_t handle);

iommulib_ops_t *iommulib_iommu_getops(iommulib_handle_t handle);

void *iommulib_iommu_getdata(iommulib_handle_t handle);


/* Interfaces for IOMMU drivers provided by NEXUS drivers (typically rootnex) */

int iommulib_iommu_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep);

int iommulib_iommu_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle);

int iommulib_iommu_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_iommu_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle);

void iommulib_iommu_dma_reset_cookies(dev_info_t *dip, ddi_dma_handle_t handle);

int iommulib_iommu_dma_get_cookies(dev_info_t *dip, ddi_dma_handle_t handle,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_iommu_dma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags);

int iommulib_iommu_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp, size_t *lenp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_iommu_dma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareq, ddi_dma_handle_t *handlep);

int iommulib_iommu_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request, off_t *offp,
    size_t *lenp, caddr_t *objpp, uint_t cache_flags);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOMMULIB_H */
