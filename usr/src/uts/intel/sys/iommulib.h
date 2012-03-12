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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

#ifndef	_SYS_IOMMULIB_H
#define	_SYS_IOMMULIB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_impldefs.h>
#include <sys/smbios.h>

#ifdef	_KERNEL

typedef enum {
	INVALID_VENDOR = 0,
	AMD_IOMMU,
	INTEL_IOMMU
} iommulib_vendor_t;

typedef enum {
	IOMMU_OPS_VERSION_INVALID = 0,
	IOMMU_OPS_VERSION_1 = 1,
	IOMMU_OPS_VERSION_2 = 2,
	IOMMU_OPS_VERSION_3 = 3
} iommulib_opsversion_t;

#define	IOMMU_OPS_VERSION IOMMU_OPS_VERSION_3

typedef struct iommulib_ops {
	iommulib_opsversion_t	ilops_vers;
	iommulib_vendor_t	ilops_vendor;
	char			*ilops_id;
	void			*ilops_data;

	int	(*ilops_probe)(iommulib_handle_t handle, dev_info_t *rdip);

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

	int	(*ilops_dma_mapobject)(iommulib_handle_t handle,
	    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle,
	    struct ddi_dma_req *dmareq, ddi_dma_obj_t *dmao);

	int	(*ilops_dma_unmapobject)(iommulib_handle_t handle,
	    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle,
	    ddi_dma_obj_t *dmao);

} iommulib_ops_t;

/*
 * Fake pointer value to indicate that a device will not use an IOMMU
 * for DMA (it's either set up for passthrough or uses a unity mapping).
 */
#define	IOMMU_HANDLE_UNUSED	(void *)-1

/*
 * IOMMU_UNITIALIZED() is true if it has not been determined whether
 * a device uses an IOMMU for DMA or not. After it has been determined,
 * the USED and UNUSED macros may be used to see if an IOMMU is being
 * used or not.
 *
 * IOMMU_USED() is true if a device uses an IOMMU for DMA
 *
 * IOMMU_UNUSED() is true if a device does not use an IOMMU for DMA
 */
#define	IOMMU_USED(dip) \
	(DEVI(dip)->devi_iommulib_handle != NULL && \
	DEVI(dip)->devi_iommulib_handle != IOMMU_HANDLE_UNUSED)
#define	IOMMU_UNUSED(dip) \
	(DEVI(dip)->devi_iommulib_handle == IOMMU_HANDLE_UNUSED)
#define	IOMMU_UNITIALIZED(dip) \
	(DEVI(dip)->devi_iommulib_handle == NULL)

typedef enum {
	IOMMU_NEXOPS_VERSION_INVALID = 0,
	IOMMU_NEXOPS_VERSION_1 = 1,
	IOMMU_NEXOPS_VERSION_2 = 2,
	IOMMU_NEXOPS_VERSION_3 = 3
} iommulib_nexops_version_t;

#define	IOMMU_NEXOPS_VERSION IOMMU_NEXOPS_VERSION_3

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
	    ddi_dma_cookie_t **cookiepp, uint_t *ccountp);

	int (*nops_dma_set_cookies)(dev_info_t *dip, ddi_dma_handle_t handle,
	    ddi_dma_cookie_t *cookiep, uint_t ccount);

	int (*nops_dma_clear_cookies)(dev_info_t *dip, ddi_dma_handle_t handle);

	int (*nops_dma_get_sleep_flags)(ddi_dma_handle_t handle);

	int (*nops_dma_sync)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags);

	int (*nops_dma_win)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, uint_t win, off_t *offp, size_t *lenp,
	    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

	int (*nops_dmahdl_setprivate)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle, void *priv);

	void * (*nops_dmahdl_getprivate)(dev_info_t *dip, dev_info_t *rdip,
	    ddi_dma_handle_t handle);
} iommulib_nexops_t;

/*
 * struct iommu_dip_private
 *   private iommu structure hook on dev_info
 */
typedef struct iommu_private {
	/* pci seg, bus, dev, func */
	int		idp_seg;
	int		idp_bus;
	int		idp_devfn;

	/* ppb information */
	boolean_t	idp_is_bridge;
	int		idp_bbp_type;
	int		idp_sec;
	int		idp_sub;

	/* identifier for special devices */
	boolean_t	idp_is_display;
	boolean_t	idp_is_lpc;

	/* domain ptr */
	void		*idp_intel_domain;
} iommu_private_t;

#define	INTEL_IOMMU_PRIVATE(i)	(dmar_domain_state_t *)(i)

typedef struct gfx_entry {
	int g_ref;
	dev_info_t *g_dip;
	struct gfx_entry *g_prev;
	struct gfx_entry *g_next;
} gfx_entry_t;

/*
 * Interfaces for nexus drivers - typically rootnex
 */

int iommulib_nexus_register(dev_info_t *dip, iommulib_nexops_t *nexops,
    iommulib_nexhandle_t *handle);

int iommulib_nexus_unregister(iommulib_nexhandle_t handle);

int iommulib_nex_open(dev_info_t *dip, dev_info_t *rdip);
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

int iommulib_nexdma_mapobject(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, struct ddi_dma_req *dmareq,
    ddi_dma_obj_t *dmao);
int iommulib_nexdma_unmapobject(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, ddi_dma_obj_t *dmao);

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
    ddi_dma_cookie_t **cookiepp, uint_t *ccountp);

int iommulib_iommu_dma_set_cookies(dev_info_t *dip, ddi_dma_handle_t handle,
    ddi_dma_cookie_t *cookiep, uint_t ccount);

int iommulib_iommu_dma_clear_cookies(dev_info_t *dip, ddi_dma_handle_t handle);

int iommulib_iommu_dma_get_sleep_flags(dev_info_t *dip,
    ddi_dma_handle_t handle);

int iommulib_iommu_dma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags);

int iommulib_iommu_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp, size_t *lenp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);

int iommulib_iommu_dmahdl_setprivate(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, void *priv);

void *iommulib_iommu_dmahdl_getprivate(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle);


/*
 * For SMBIOS access from IOMMU drivers
 */
extern smbios_hdl_t *iommulib_smbios;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOMMULIB_H */
