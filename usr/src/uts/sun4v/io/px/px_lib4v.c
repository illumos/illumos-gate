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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/vmem.h>
#include <sys/intr.h>
#include <sys/ivintr.h>
#include <sys/errno.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#include <px_obj.h>
#include <sys/machsystm.h>
#include <sys/sunndi.h>
#include <sys/pcie_impl.h>
#include "px_lib4v.h"
#include "px_err.h"
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgacc_4v.h>


/* mask for the ranges property in calculating the real PFN range */
uint_t px_ranges_phi_mask = ((1 << 28) -1);

/*
 * Hypervisor VPCI services information for the px nexus driver.
 */
static	uint64_t	px_vpci_maj_ver; /* Negotiated VPCI API major version */
static	uint64_t	px_vpci_min_ver; /* Negotiated VPCI API minor version */
static	uint_t		px_vpci_users = 0; /* VPCI API users */
static	hsvc_info_t px_hsvc_vpci = {
	HSVC_REV_1, NULL, HSVC_GROUP_VPCI, PX_VPCI_MAJOR_VER,
	PX_VPCI_MINOR_VER, "PX"
};

/*
 * Hypervisor SDIO services information for the px nexus driver.
 */
static	uint64_t	px_sdio_min_ver; /* Negotiated SDIO API minor version */
static	uint_t		px_sdio_users = 0; /* SDIO API users */
static	hsvc_info_t px_hsvc_sdio = {
	HSVC_REV_1, NULL, HSVC_GROUP_SDIO, PX_SDIO_MAJOR_VER,
	PX_SDIO_MINOR_VER, "PX"
};

/*
 * Hypervisor SDIO ERR services information for the px nexus driver.
 */
static	uint64_t	px_sdio_err_min_ver; /* Negotiated SDIO ERR API */
						/* minor version */
static	uint_t		px_sdio_err_users = 0; /* SDIO ERR API users */
static	hsvc_info_t px_hsvc_sdio_err = {
	HSVC_REV_1, NULL, HSVC_GROUP_SDIO_ERR, PX_SDIO_ERR_MAJOR_VER,
	PX_SDIO_ERR_MINOR_VER, "PX"
};

#define	CHILD_LOANED	"child_loaned"
static int px_lib_count_waiting_dev(dev_info_t *);

int
px_lib_dev_init(dev_info_t *dip, devhandle_t *dev_hdl)
{
	px_nexus_regspec_t	*rp;
	uint_t			reglen;
	int			ret;
	px_t			*px_p = DIP_TO_STATE(dip);
	uint64_t mjrnum;
	uint64_t mnrnum;

	DBG(DBG_ATTACH, dip, "px_lib_dev_init: dip 0x%p\n", dip);

	/*
	 * Check HV intr group api versioning.
	 * This driver uses the old interrupt routines which are supported
	 * in old firmware in the CORE API group and in newer firmware in
	 * the INTR API group.  Support for these calls will be dropped
	 * once the INTR API group major goes to 2.
	 */
	if ((hsvc_version(HSVC_GROUP_INTR, &mjrnum, &mnrnum) == 0) &&
	    (mjrnum > 1)) {
		cmn_err(CE_WARN, "px: unsupported intr api group: "
		    "maj:0x%lx, min:0x%lx", mjrnum, mnrnum);
		return (ENOTSUP);
	}

	ret = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (uchar_t **)&rp, &reglen);
	if (ret != DDI_PROP_SUCCESS) {
		DBG(DBG_ATTACH, dip, "px_lib_dev_init failed ret=%d\n", ret);
		return (DDI_FAILURE);
	}

	/*
	 * Initilize device handle. The device handle uniquely identifies
	 * a SUN4V device. It consists of the lower 28-bits of the hi-cell
	 * of the first entry of the SUN4V device's "reg" property as
	 * defined by the SUN4V Bus Binding to Open Firmware.
	 */
	*dev_hdl = (devhandle_t)((rp->phys_addr >> 32) & DEVHDLE_MASK);
	ddi_prop_free(rp);

	/*
	 * hotplug implementation requires this property to be associated with
	 * any indirect PCI config access services
	 */
	(void) ddi_prop_update_int(makedevice(ddi_driver_major(dip),
	    PCI_MINOR_NUM(ddi_get_instance(dip), PCI_DEVCTL_MINOR)), dip,
	    PCI_BUS_CONF_MAP_PROP, 1);

	DBG(DBG_ATTACH, dip, "px_lib_dev_init: dev_hdl 0x%llx\n", *dev_hdl);

	/*
	 * If a /pci node has a pci-intx-not-supported property, this property
	 * represents that the fabric doesn't support fixed interrupt.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pci-intx-not-supported")) {
		DBG(DBG_ATTACH, dip, "px_lib_dev_init: "
		    "pci-intx-not-supported is not found, dip=0x%p\n", dip);
		px_p->px_supp_intr_types |= DDI_INTR_TYPE_FIXED;
	}

	/*
	 * Negotiate the API version for VPCI hypervisor services.
	 */
	if (px_vpci_users == 0) {
		if ((ret = hsvc_register(&px_hsvc_vpci, &px_vpci_min_ver))
		    == 0) {
			px_vpci_maj_ver = px_hsvc_vpci.hsvc_major;
			goto hv_negotiation_complete;
		}
		/*
		 * Negotiation with the latest known VPCI hypervisor services
		 * failed.  Fallback to version 1.0.
		 */
		px_hsvc_vpci.hsvc_major = PX_HSVC_MAJOR_VER_1;
		px_hsvc_vpci.hsvc_minor = PX_HSVC_MINOR_VER_0;

		if ((ret = hsvc_register(&px_hsvc_vpci, &px_vpci_min_ver))
		    == 0) {
			px_vpci_maj_ver = px_hsvc_vpci.hsvc_major;
			goto hv_negotiation_complete;
		}

		cmn_err(CE_WARN, "%s: cannot negotiate hypervisor services "
		    "group: 0x%lx major: 0x%lx minor: 0x%lx errno: %d\n",
		    px_hsvc_vpci.hsvc_modname, px_hsvc_vpci.hsvc_group,
		    px_hsvc_vpci.hsvc_major, px_hsvc_vpci.hsvc_minor, ret);

		return (DDI_FAILURE);
	}
hv_negotiation_complete:

	px_vpci_users++;

	DBG(DBG_ATTACH, dip, "px_lib_dev_init: negotiated VPCI API version, "
	    "major 0x%lx minor 0x%lx\n", px_vpci_maj_ver,
	    px_vpci_min_ver);

	/*
	 * Negotiate the API version for SDIO hypervisor services.
	 */
	if ((px_sdio_users == 0) &&
	    ((ret = hsvc_register(&px_hsvc_sdio, &px_sdio_min_ver)) != 0)) {
		DBG(DBG_ATTACH, dip, "%s: cannot negotiate hypervisor "
		    "services group: 0x%lx major: 0x%lx minor: 0x%lx "
		    "errno: %d\n", px_hsvc_sdio.hsvc_modname,
		    px_hsvc_sdio.hsvc_group, px_hsvc_sdio.hsvc_major,
		    px_hsvc_sdio.hsvc_minor, ret);
	} else {
		px_sdio_users++;
		DBG(DBG_ATTACH, dip, "px_lib_dev_init: negotiated SDIO API"
		    "version, major 0x%lx minor 0x%lx\n",
		    px_hsvc_sdio.hsvc_major, px_sdio_min_ver);
	}

	/*
	 * Negotiate the API version for SDIO ERR hypervisor services.
	 */
	if ((px_sdio_err_users == 0) &&
	    ((ret = hsvc_register(&px_hsvc_sdio_err,
	    &px_sdio_err_min_ver)) != 0)) {
		DBG(DBG_ATTACH, dip, "%s: cannot negotiate SDIO ERR hypervisor "
		    "services group: 0x%lx major: 0x%lx minor: 0x%lx "
		    "errno: %d\n", px_hsvc_sdio_err.hsvc_modname,
		    px_hsvc_sdio_err.hsvc_group, px_hsvc_sdio_err.hsvc_major,
		    px_hsvc_sdio_err.hsvc_minor, ret);
	} else {
		px_sdio_err_users++;
		DBG(DBG_ATTACH, dip, "px_lib_dev_init: negotiated SDIO ERR API "
		    "version, major 0x%lx minor 0x%lx\n",
		    px_hsvc_sdio_err.hsvc_major, px_sdio_err_min_ver);
	}

	/*
	 * Find out the number of dev we need to wait under this RC
	 * before we issue fabric sync hypercall
	 */
	px_p->px_plat_p = (void *)(uintptr_t)px_lib_count_waiting_dev(dip);
	DBG(DBG_ATTACH, dip, "Found %d bridges need waiting under RC %p",
	    (int)(uintptr_t)px_p->px_plat_p, dip);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_dev_fini(dev_info_t *dip)
{
	DBG(DBG_DETACH, dip, "px_lib_dev_fini: dip 0x%p\n", dip);

	(void) ddi_prop_remove(makedevice(ddi_driver_major(dip),
	    PCI_MINOR_NUM(ddi_get_instance(dip), PCI_DEVCTL_MINOR)), dip,
	    PCI_BUS_CONF_MAP_PROP);

	if (--px_vpci_users == 0)
		(void) hsvc_unregister(&px_hsvc_vpci);

	if (--px_sdio_users == 0)
		(void) hsvc_unregister(&px_hsvc_sdio);

	if (--px_sdio_err_users == 0)
		(void) hsvc_unregister(&px_hsvc_sdio_err);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_devino_to_sysino(dev_info_t *dip, devino_t devino,
    sysino_t *sysino)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_devino_to_sysino: dip 0x%p "
	    "devino 0x%x\n", dip, devino);

	if ((ret = hvio_intr_devino_to_sysino(DIP_TO_HANDLE(dip),
	    devino, sysino)) != H_EOK) {
		DBG(DBG_LIB_INT, dip,
		    "hvio_intr_devino_to_sysino failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_devino_to_sysino: sysino 0x%llx\n",
	    *sysino);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_getvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t *intr_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getvalid: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_getvalid(sysino,
	    (int *)intr_valid_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_getvalid failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getvalid: intr_valid_state 0x%x\n",
	    *intr_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_setvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t intr_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_setvalid: dip 0x%p sysino 0x%llx "
	    "intr_valid_state 0x%x\n", dip, sysino, intr_valid_state);

	if ((ret = hvio_intr_setvalid(sysino, intr_valid_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_setvalid failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_getstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t *intr_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getstate: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_getstate(sysino, (int *)intr_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_getstate failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getstate: intr_state 0x%x\n",
	    *intr_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_setstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t intr_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_setstate: dip 0x%p sysino 0x%llx "
	    "intr_state 0x%x\n", dip, sysino, intr_state);

	if ((ret = hvio_intr_setstate(sysino, intr_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_setstate failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_gettarget(dev_info_t *dip, sysino_t sysino, cpuid_t *cpuid)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_gettarget: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_gettarget(sysino, cpuid)) != H_EOK) {
		DBG(DBG_LIB_INT, dip,
		    "hvio_intr_gettarget failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_gettarget: cpuid 0x%x\n", *cpuid);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_settarget(dev_info_t *dip, sysino_t sysino, cpuid_t cpuid)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_settarget: dip 0x%p sysino 0x%llx "
	    "cpuid 0x%x\n", dip, sysino, cpuid);

	ret = hvio_intr_settarget(sysino, cpuid);
	if (ret == H_ECPUERROR) {
		cmn_err(CE_PANIC,
		    "px_lib_intr_settarget: hvio_intr_settarget failed, "
		    "ret = 0x%lx, cpuid = 0x%x, sysino = 0x%lx\n", ret,
		    cpuid, sysino);
	} else if (ret != H_EOK) {
		DBG(DBG_LIB_INT, dip,
		    "hvio_intr_settarget failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_reset(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_ino_t	*ino_p;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_reset: dip 0x%p\n", dip);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	/* Reset all Interrupts */
	for (ino_p = ib_p->ib_ino_lst; ino_p; ino_p = ino_p->ino_next_p) {
		if (px_lib_intr_setstate(dip, ino_p->ino_sysino,
		    INTR_IDLE_STATE) != DDI_SUCCESS)
			return (BF_FATAL);
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);

	return (BF_NONE);
}

/*ARGSUSED*/
int
px_lib_iommu_map(dev_info_t *dip, tsbid_t tsbid, pages_t pages,
    io_attributes_t attr, void *addr, size_t pfn_index, int flags)
{
	tsbnum_t	tsb_num = PCI_TSBID_TO_TSBNUM(tsbid);
	tsbindex_t	tsb_index = PCI_TSBID_TO_TSBINDEX(tsbid);
	io_page_list_t	*pfns, *pfn_p;
	pages_t		ttes_mapped = 0;
	int		i, err = DDI_SUCCESS;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_map: dip 0x%p tsbid 0x%llx "
	    "pages 0x%x attr 0x%llx addr 0x%p pfn_index 0x%llx flags 0x%x\n",
	    dip, tsbid, pages, attr, addr, pfn_index, flags);

	if ((pfns = pfn_p = kmem_zalloc((pages * sizeof (io_page_list_t)),
	    KM_NOSLEEP)) == NULL) {
		DBG(DBG_LIB_DMA, dip, "px_lib_iommu_map: kmem_zalloc failed\n");
		return (DDI_FAILURE);
	}

	for (i = 0; i < pages; i++)
		pfns[i] = MMU_PTOB(PX_ADDR2PFN(addr, pfn_index, flags, i));

	/*
	 * If HV VPCI version is 2.0 and higher, pass BDF, phantom function,
	 * and relaxed ordering attributes. Otherwise, pass only read or write
	 * attribute.
	 */
	if ((px_vpci_maj_ver == PX_HSVC_MAJOR_VER_1) &&
	    (px_vpci_min_ver == PX_HSVC_MINOR_VER_0))
		attr = attr & (PCI_MAP_ATTR_READ | PCI_MAP_ATTR_WRITE);

	while ((ttes_mapped = pfn_p - pfns) < pages) {
		uintptr_t	ra = va_to_pa(pfn_p);
		pages_t		ttes2map;
		uint64_t	ret;

		ttes2map = (MMU_PAGE_SIZE - P2PHASE(ra, MMU_PAGE_SIZE)) >> 3;
		ra = MMU_PTOB(MMU_BTOP(ra));

		for (ttes2map = MIN(ttes2map, pages - ttes_mapped); ttes2map;
		    ttes2map -= ttes_mapped, pfn_p += ttes_mapped) {

			ttes_mapped = 0;
			if ((ret = hvio_iommu_map(DIP_TO_HANDLE(dip),
			    PCI_TSBID(tsb_num, tsb_index + (pfn_p - pfns)),
			    ttes2map, attr, (io_page_list_t *)(ra |
			    ((uintptr_t)pfn_p & MMU_PAGE_OFFSET)),
			    &ttes_mapped)) != H_EOK) {
				DBG(DBG_LIB_DMA, dip, "hvio_iommu_map failed "
				    "ret 0x%lx\n", ret);

				ttes_mapped = pfn_p - pfns;
				err = DDI_FAILURE;
				goto cleanup;
			}

			DBG(DBG_LIB_DMA, dip, "px_lib_iommu_map: tsb_num 0x%x "
			    "tsb_index 0x%lx ttes_to_map 0x%lx attr 0x%llx "
			    "ra 0x%p ttes_mapped 0x%x\n", tsb_num,
			    tsb_index + (pfn_p - pfns), ttes2map, attr,
			    ra | ((uintptr_t)pfn_p & MMU_PAGE_OFFSET),
			    ttes_mapped);
		}
	}

cleanup:
	if ((err == DDI_FAILURE) && ttes_mapped)
		(void) px_lib_iommu_demap(dip, tsbid, ttes_mapped);

	kmem_free(pfns, pages * sizeof (io_page_list_t));
	return (err);
}

/*ARGSUSED*/
int
px_lib_iommu_demap(dev_info_t *dip, tsbid_t tsbid, pages_t pages)
{
	tsbnum_t	tsb_num = PCI_TSBID_TO_TSBNUM(tsbid);
	tsbindex_t	tsb_index = PCI_TSBID_TO_TSBINDEX(tsbid);
	pages_t		ttes2demap, ttes_demapped = 0;
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_demap: dip 0x%p tsbid 0x%llx "
	    "pages 0x%x\n", dip, tsbid, pages);

	for (ttes2demap = pages; ttes2demap;
	    ttes2demap -= ttes_demapped, tsb_index += ttes_demapped) {
		if ((ret = hvio_iommu_demap(DIP_TO_HANDLE(dip),
		    PCI_TSBID(tsb_num, tsb_index), ttes2demap,
		    &ttes_demapped)) != H_EOK) {
			DBG(DBG_LIB_DMA, dip, "hvio_iommu_demap failed, "
			    "ret 0x%lx\n", ret);

			return (DDI_FAILURE);
		}

		DBG(DBG_LIB_DMA, dip, "px_lib_iommu_demap: tsb_num 0x%x "
		    "tsb_index 0x%lx ttes_to_demap 0x%lx ttes_demapped 0x%x\n",
		    tsb_num, tsb_index, ttes2demap, ttes_demapped);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_iommu_getmap(dev_info_t *dip, tsbid_t tsbid, io_attributes_t *attr_p,
    r_addr_t *r_addr_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getmap: dip 0x%p tsbid 0x%llx\n",
	    dip, tsbid);

	if ((ret = hvio_iommu_getmap(DIP_TO_HANDLE(dip), tsbid,
	    attr_p, r_addr_p)) != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "hvio_iommu_getmap failed, ret 0x%lx\n", ret);

		return ((ret == H_ENOMAP) ? DDI_DMA_NOMAPPING:DDI_FAILURE);
	}

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getmap: attr 0x%llx "
	    "r_addr 0x%llx\n", *attr_p, *r_addr_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_iommu_detach(px_t *px_p)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
uint64_t
px_get_rng_parent_hi_mask(px_t *px_p)
{
	return (PX_RANGE_PROP_MASK);
}

/*
 * Checks dma attributes against system bypass ranges
 * A sun4v device must be capable of generating the entire 64-bit
 * address in order to perform bypass DMA.
 */
/*ARGSUSED*/
int
px_lib_dma_bypass_rngchk(dev_info_t *dip, ddi_dma_attr_t *attr_p,
    uint64_t *lo_p, uint64_t *hi_p)
{
	if ((attr_p->dma_attr_addr_lo != 0ull) ||
	    (attr_p->dma_attr_addr_hi != UINT64_MAX)) {

		return (DDI_DMA_BADATTR);
	}

	*lo_p = 0ull;
	*hi_p = UINT64_MAX;

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
int
px_lib_iommu_getbypass(dev_info_t *dip, r_addr_t ra, io_attributes_t attr,
    io_addr_t *io_addr_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getbypass: dip 0x%p ra 0x%llx "
	    "attr 0x%llx\n", dip, ra, attr);
	/*
	 * If HV VPCI version is 2.0 and higher, pass BDF, phantom function,
	 * and relaxed ordering attributes. Otherwise, pass only read or write
	 * attribute.
	 */
	if ((px_vpci_maj_ver == PX_HSVC_MAJOR_VER_1) &&
	    (px_vpci_min_ver == PX_HSVC_MINOR_VER_0))
		attr &= PCI_MAP_ATTR_READ | PCI_MAP_ATTR_WRITE;

	if ((ret = hvio_iommu_getbypass(DIP_TO_HANDLE(dip), ra,
	    attr, io_addr_p)) != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "hvio_iommu_getbypass failed, ret 0x%lx\n", ret);
		return (ret == H_ENOTSUPPORTED ? DDI_ENOTSUP : DDI_FAILURE);
	}

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getbypass: io_addr 0x%llx\n",
	    *io_addr_p);

	return (DDI_SUCCESS);
}

/*
 * Returns any needed IO address bit(s) for relaxed ordering in IOMMU
 * bypass mode.
 */
/* ARGSUSED */
uint64_t
px_lib_ro_bypass(dev_info_t *dip, io_attributes_t attr, uint64_t ioaddr)
{
	return (ioaddr);
}

/*ARGSUSED*/
int
px_lib_dma_sync(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
    off_t off, size_t len, uint_t cache_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	uint64_t sync_dir;
	size_t bytes_synced;
	int end, idx;
	off_t pg_off;
	devhandle_t hdl = DIP_TO_HANDLE(dip); /* need to cache hdl */

	DBG(DBG_LIB_DMA, dip, "px_lib_dma_sync: dip 0x%p rdip 0x%p "
	    "handle 0x%llx off 0x%x len 0x%x flags 0x%x\n",
	    dip, rdip, handle, off, len, cache_flags);

	if (!(mp->dmai_flags & PX_DMAI_FLAGS_INUSE)) {
		cmn_err(CE_WARN, "%s%d: Unbound dma handle %p.",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), (void *)mp);
		return (DDI_FAILURE);
	}

	if (mp->dmai_flags & PX_DMAI_FLAGS_NOSYNC)
		return (DDI_SUCCESS);

	if (!len)
		len = mp->dmai_size;

	if (mp->dmai_rflags & DDI_DMA_READ)
		sync_dir = HVIO_DMA_SYNC_DIR_FROM_DEV;
	else
		sync_dir = HVIO_DMA_SYNC_DIR_TO_DEV;

	off += mp->dmai_offset;
	pg_off = off & MMU_PAGEOFFSET;

	DBG(DBG_LIB_DMA, dip, "px_lib_dma_sync: page offset %x size %x\n",
	    pg_off, len);

	/* sync on page basis */
	end = MMU_BTOPR(off + len - 1);
	for (idx = MMU_BTOP(off); idx < end; idx++,
	    len -= bytes_synced, pg_off = 0) {
		size_t bytes_to_sync = bytes_to_sync =
		    MIN(len, MMU_PAGESIZE - pg_off);

		if (hvio_dma_sync(hdl, MMU_PTOB(PX_GET_MP_PFN(mp, idx)) +
		    pg_off, bytes_to_sync, sync_dir, &bytes_synced) != H_EOK)
			break;

		DBG(DBG_LIB_DMA, dip, "px_lib_dma_sync: Called hvio_dma_sync "
		    "ra = %p bytes to sync = %x bytes synced %x\n",
		    MMU_PTOB(PX_GET_MP_PFN(mp, idx)) + pg_off, bytes_to_sync,
		    bytes_synced);

		if (bytes_to_sync != bytes_synced)
			break;
	}

	return (len ? DDI_FAILURE : DDI_SUCCESS);
}


/*
 * MSIQ Functions:
 */

/*ARGSUSED*/
int
px_lib_msiq_init(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	r_addr_t	ra;
	size_t		msiq_size;
	uint_t		rec_cnt;
	int		i, err = DDI_SUCCESS;
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_init: dip 0x%p\n", dip);

	msiq_size = msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t);

	/* sun4v requires all EQ allocation to be on q size boundary */
	if ((msiq_state_p->msiq_buf_p = contig_mem_alloc_align(
	    msiq_state_p->msiq_cnt * msiq_size, msiq_size)) == NULL) {
		DBG(DBG_LIB_MSIQ, dip,
		    "px_lib_msiq_init: Contig alloc failed\n");

		return (DDI_FAILURE);
	}

	for (i = 0; i < msiq_state_p->msiq_cnt; i++) {
		msiq_state_p->msiq_p[i].msiq_base_p = (msiqhead_t *)
		    ((caddr_t)msiq_state_p->msiq_buf_p + (i * msiq_size));

		ra = (r_addr_t)va_to_pa((caddr_t)msiq_state_p->msiq_buf_p +
		    (i * msiq_size));

		if ((ret = hvio_msiq_conf(DIP_TO_HANDLE(dip),
		    (i + msiq_state_p->msiq_1st_msiq_id),
		    ra, msiq_state_p->msiq_rec_cnt)) != H_EOK) {
			DBG(DBG_LIB_MSIQ, dip,
			    "hvio_msiq_conf failed, ret 0x%lx\n", ret);
			err = DDI_FAILURE;
			break;
		}

		if ((err = px_lib_msiq_info(dip,
		    (i + msiq_state_p->msiq_1st_msiq_id),
		    &ra, &rec_cnt)) != DDI_SUCCESS) {
			DBG(DBG_LIB_MSIQ, dip,
			    "px_lib_msiq_info failed, ret 0x%x\n", err);
			err = DDI_FAILURE;
			break;
		}

		DBG(DBG_LIB_MSIQ, dip,
		    "px_lib_msiq_init: ra 0x%p rec_cnt 0x%x\n", ra, rec_cnt);
	}

	return (err);
}

/*ARGSUSED*/
int
px_lib_msiq_fini(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	size_t		msiq_size;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_fini: dip 0x%p\n", dip);
	msiq_size = msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t);

	if (msiq_state_p->msiq_buf_p != NULL)
		contig_mem_free(msiq_state_p->msiq_buf_p,
		    msiq_state_p->msiq_cnt * msiq_size);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_info(dev_info_t *dip, msiqid_t msiq_id, r_addr_t *ra_p,
    uint_t *msiq_rec_cnt_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_msiq_info: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_info(DIP_TO_HANDLE(dip),
	    msiq_id, ra_p, msiq_rec_cnt_p)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_info failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_msiq_info: ra_p 0x%p msiq_rec_cnt 0x%x\n",
	    ra_p, *msiq_rec_cnt_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_getvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getvalid: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_getvalid(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getvalid: msiq_valid_state 0x%x\n",
	    *msiq_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_setvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_setvalid: dip 0x%p msiq_id 0x%x "
	    "msiq_valid_state 0x%x\n", dip, msiq_id, msiq_valid_state);

	if ((ret = hvio_msiq_setvalid(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_getstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getstate: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_getstate(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_getstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getstate: msiq_state 0x%x\n",
	    *msiq_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_setstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_setstate: dip 0x%p msiq_id 0x%x "
	    "msiq_state 0x%x\n", dip, msiq_id, msiq_state);

	if ((ret = hvio_msiq_setstate(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_setstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_gethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t *msiq_head_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gethead: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_gethead(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_head_p)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_gethead failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	*msiq_head_p =  (*msiq_head_p / sizeof (msiq_rec_t));

	DBG(DBG_LIB_MSIQ, dip, "px_msiq_gethead: msiq_head 0x%x\n",
	    *msiq_head_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_sethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t msiq_head)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_sethead: dip 0x%p msiq_id 0x%x "
	    "msiq_head 0x%x\n", dip, msiq_id, msiq_head);

	if ((ret = hvio_msiq_sethead(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_head * sizeof (msiq_rec_t))) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_sethead failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_gettail(dev_info_t *dip, msiqid_t msiq_id,
    msiqtail_t *msiq_tail_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gettail: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_gettail(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_tail_p)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_gettail failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	*msiq_tail_p =  (*msiq_tail_p / sizeof (msiq_rec_t));
	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gettail: msiq_tail 0x%x\n",
	    *msiq_tail_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
px_lib_get_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p,
    msiq_rec_t *msiq_rec_p)
{
	msiq_rec_t	*curr_msiq_rec_p = (msiq_rec_t *)msiq_head_p;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_get_msiq_rec: dip 0x%p\n", dip);

	if (!curr_msiq_rec_p->msiq_rec_type) {
		/* Set msiq_rec_type to zero */
		msiq_rec_p->msiq_rec_type = 0;

		return;
	}

	*msiq_rec_p = *curr_msiq_rec_p;
}

/*ARGSUSED*/
void
px_lib_clr_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p)
{
	msiq_rec_t	*curr_msiq_rec_p = (msiq_rec_t *)msiq_head_p;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_clr_msiq_rec: dip 0x%p\n", dip);

	/* Zero out msiq_rec_type field */
	curr_msiq_rec_p->msiq_rec_type  = 0;
}

/*
 * MSI Functions:
 */

/*ARGSUSED*/
int
px_lib_msi_init(dev_info_t *dip)
{
	DBG(DBG_LIB_MSI, dip, "px_lib_msi_init: dip 0x%p\n", dip);

	/* Noop */
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t *msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getmsiq: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getmsiq(DIP_TO_HANDLE(dip),
	    msi_num, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getmsiq: msiq_id 0x%x\n",
	    *msiq_id);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t msiq_id, msi_type_t msitype)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setmsiq: dip 0x%p msi_num 0x%x "
	    "msq_id 0x%x\n", dip, msi_num, msiq_id);

	if ((ret = hvio_msi_setmsiq(DIP_TO_HANDLE(dip),
	    msi_num, msiq_id, msitype)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getvalid: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getvalid(DIP_TO_HANDLE(dip),
	    msi_num, msi_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getvalid: msiq_id 0x%x\n",
	    *msi_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setvalid: dip 0x%p msi_num 0x%x "
	    "msi_valid_state 0x%x\n", dip, msi_num, msi_valid_state);

	if ((ret = hvio_msi_setvalid(DIP_TO_HANDLE(dip),
	    msi_num, msi_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t *msi_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getstate: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getstate(DIP_TO_HANDLE(dip),
	    msi_num, msi_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getstate: msi_state 0x%x\n",
	    *msi_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t msi_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setstate: dip 0x%p msi_num 0x%x "
	    "msi_state 0x%x\n", dip, msi_num, msi_state);

	if ((ret = hvio_msi_setstate(DIP_TO_HANDLE(dip),
	    msi_num, msi_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * MSG Functions:
 */

/*ARGSUSED*/
int
px_lib_msg_getmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_getmsiq: dip 0x%p msg_type 0x%x\n",
	    dip, msg_type);

	if ((ret = hvio_msg_getmsiq(DIP_TO_HANDLE(dip),
	    msg_type, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_getmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msg_getmsiq: msiq_id 0x%x\n",
	    *msiq_id);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_setmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_setmsiq: dip 0x%p msg_type 0x%x "
	    "msq_id 0x%x\n", dip, msg_type, msiq_id);

	if ((ret = hvio_msg_setmsiq(DIP_TO_HANDLE(dip),
	    msg_type, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_setmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_getvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_getvalid: dip 0x%p msg_type 0x%x\n",
	    dip, msg_type);

	if ((ret = hvio_msg_getvalid(DIP_TO_HANDLE(dip), msg_type,
	    msg_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msg_getvalid: msg_valid_state 0x%x\n",
	    *msg_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_setvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_setvalid: dip 0x%p msg_type 0x%x "
	    "msg_valid_state 0x%x\n", dip, msg_type, msg_valid_state);

	if ((ret = hvio_msg_setvalid(DIP_TO_HANDLE(dip), msg_type,
	    msg_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Suspend/Resume Functions:
 * Currently unsupported by hypervisor and all functions are noops.
 */
/*ARGSUSED*/
int
px_lib_suspend(dev_info_t *dip)
{
	DBG(DBG_ATTACH, dip, "px_lib_suspend: Not supported\n");

	/* Not supported */
	return (DDI_FAILURE);
}

/*ARGSUSED*/
void
px_lib_resume(dev_info_t *dip)
{
	DBG(DBG_ATTACH, dip, "px_lib_resume: Not supported\n");

	/* Noop */
}

/*
 * Misc Functions:
 * Currently unsupported by hypervisor and all functions are noops.
 */
/*ARGSUSED*/
static int
px_lib_config_get(dev_info_t *dip, pci_device_t bdf, pci_config_offset_t off,
    uint8_t size, pci_cfg_data_t *data_p)
{
	uint64_t	ret;

	DBG(DBG_LIB_CFG, dip, "px_lib_config_get: dip 0x%p, bdf 0x%llx "
	    "off 0x%x size 0x%x\n", dip, bdf, off, size);

	if ((ret = hvio_config_get(DIP_TO_HANDLE(dip), bdf, off,
	    size, data_p)) != H_EOK) {
		DBG(DBG_LIB_CFG, dip,
		    "hvio_config_get failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}
	DBG(DBG_LIB_CFG, dip, "px_config_get: data 0x%x\n", data_p->dw);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
px_lib_config_put(dev_info_t *dip, pci_device_t bdf, pci_config_offset_t off,
    uint8_t size, pci_cfg_data_t data)
{
	uint64_t	ret;

	DBG(DBG_LIB_CFG, dip, "px_lib_config_put: dip 0x%p, bdf 0x%llx "
	    "off 0x%x size 0x%x data 0x%llx\n", dip, bdf, off, size, data.qw);

	if ((ret = hvio_config_put(DIP_TO_HANDLE(dip), bdf, off,
	    size, data)) != H_EOK) {
		DBG(DBG_LIB_CFG, dip,
		    "hvio_config_put failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static uint32_t
px_pci_config_get(ddi_acc_impl_t *handle, uint32_t *addr, int size)
{
	px_config_acc_pvt_t *px_pvt = (px_config_acc_pvt_t *)
	    handle->ahi_common.ah_bus_private;
	pcie_bus_t *busp = NULL;
	dev_info_t *cdip = NULL;
	uint32_t pci_dev_addr = px_pvt->raddr;
	uint32_t vaddr = px_pvt->vaddr;
	uint16_t off = (uint16_t)(uintptr_t)(addr - vaddr) & 0xfff;
	uint64_t rdata = 0;

	if (px_lib_config_get(px_pvt->dip, pci_dev_addr, off,
	    size, (pci_cfg_data_t *)&rdata) != DDI_SUCCESS)
		/* XXX update error kstats */
		return (0xffffffff);

	if (cdip = pcie_find_dip_by_bdf(px_pvt->dip, pci_dev_addr >> 8))
		busp = PCIE_DIP2BUS(cdip);
	/*
	 * This can be called early, before busp or busp->bus_dom has
	 * been initialized, so check both before invoking
	 * PCIE_IS_ASSIGNED.
	 */
	if (busp && PCIE_BUS2DOM(busp) && PCIE_IS_ASSIGNED(busp)) {
		if (off == PCI_CONF_VENID && size == 2)
			rdata = busp->bus_dev_ven_id & 0xffff;
		else if (off == PCI_CONF_DEVID && size == 2)
			rdata = busp->bus_dev_ven_id >> 16;
		else if (off == PCI_CONF_VENID && size == 4)
			rdata = busp->bus_dev_ven_id;
	}
	return ((uint32_t)rdata);
}

static void
px_pci_config_put(ddi_acc_impl_t *handle, uint32_t *addr,
    int size, pci_cfg_data_t wdata)
{
	px_config_acc_pvt_t *px_pvt = (px_config_acc_pvt_t *)
	    handle->ahi_common.ah_bus_private;
	uint32_t pci_dev_addr = px_pvt->raddr;
	uint32_t vaddr = px_pvt->vaddr;
	uint16_t off = (uint16_t)(uintptr_t)(addr - vaddr) & 0xfff;

	if (px_lib_config_put(px_pvt->dip, pci_dev_addr, off,
	    size, wdata) != DDI_SUCCESS) {
		/*EMPTY*/
		/* XXX update error kstats */
	}
}

static uint8_t
px_pci_config_get8(ddi_acc_impl_t *handle, uint8_t *addr)
{
	return ((uint8_t)px_pci_config_get(handle, (uint32_t *)addr, 1));
}

static uint16_t
px_pci_config_get16(ddi_acc_impl_t *handle, uint16_t *addr)
{
	return ((uint16_t)px_pci_config_get(handle, (uint32_t *)addr, 2));
}

static uint32_t
px_pci_config_get32(ddi_acc_impl_t *handle, uint32_t *addr)
{
	return ((uint32_t)px_pci_config_get(handle, (uint32_t *)addr, 4));
}

static uint64_t
px_pci_config_get64(ddi_acc_impl_t *handle, uint64_t *addr)
{
	uint32_t rdatah, rdatal;

	rdatal = (uint32_t)px_pci_config_get(handle, (uint32_t *)addr, 4);
	rdatah = (uint32_t)px_pci_config_get(handle,
	    (uint32_t *)((char *)addr+4), 4);
	return (((uint64_t)rdatah << 32) | rdatal);
}

static void
px_pci_config_put8(ddi_acc_impl_t *handle, uint8_t *addr, uint8_t data)
{
	pci_cfg_data_t wdata = { 0 };

	wdata.qw = (uint8_t)data;
	px_pci_config_put(handle, (uint32_t *)addr, 1, wdata);
}

static void
px_pci_config_put16(ddi_acc_impl_t *handle, uint16_t *addr, uint16_t data)
{
	pci_cfg_data_t wdata = { 0 };

	wdata.qw = (uint16_t)data;
	px_pci_config_put(handle, (uint32_t *)addr, 2, wdata);
}

static void
px_pci_config_put32(ddi_acc_impl_t *handle, uint32_t *addr, uint32_t data)
{
	pci_cfg_data_t wdata = { 0 };

	wdata.qw = (uint32_t)data;
	px_pci_config_put(handle, (uint32_t *)addr, 4, wdata);
}

static void
px_pci_config_put64(ddi_acc_impl_t *handle, uint64_t *addr, uint64_t data)
{
	pci_cfg_data_t wdata = { 0 };

	wdata.qw = (uint32_t)(data & 0xffffffff);
	px_pci_config_put(handle, (uint32_t *)addr, 4, wdata);
	wdata.qw = (uint32_t)((data >> 32) & 0xffffffff);
	px_pci_config_put(handle, (uint32_t *)((char *)addr+4), 4, wdata);
}

static void
px_pci_config_rep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get8(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get8(handle, dev_addr);
}

/*
 * Function to rep read 16 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get16(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get16(handle, dev_addr);
}

/*
 * Function to rep read 32 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get32(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get32(handle, dev_addr);
}

/*
 * Function to rep read 64 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get64(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = px_pci_config_get64(handle, dev_addr);
}

/*
 * Function to rep write 8 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			px_pci_config_put8(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			px_pci_config_put8(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 16 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			px_pci_config_put16(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			px_pci_config_put16(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 32 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			px_pci_config_put32(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			px_pci_config_put32(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 64 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
px_pci_config_rep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			px_pci_config_put64(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			px_pci_config_put64(handle, dev_addr, *host_addr++);
}

/*
 * Provide a private access handle to route config access calls to Hypervisor.
 * Beware: Do all error checking for config space accesses before calling
 * this function. ie. do error checking from the calling function.
 * Due to a lack of meaningful error code in DDI, the gauranteed return of
 * DDI_SUCCESS from here makes the code organization readable/easier from
 * the generic code.
 */
/*ARGSUSED*/
int
px_lib_map_vconfig(dev_info_t *dip,
    ddi_map_req_t *mp, pci_config_offset_t off,
    pci_regspec_t *rp, caddr_t *addrp)
{
	int fmcap;
	ndi_err_t *errp;
	on_trap_data_t *otp;
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *ap;
	uchar_t busnum;	/* bus number */
	uchar_t devnum;	/* device number */
	uchar_t funcnum; /* function number */
	px_config_acc_pvt_t *px_pvt;

	hp = (ddi_acc_hdl_t *)mp->map_handlep;
	ap = (ddi_acc_impl_t *)hp->ah_platform_private;

	/* Check for mapping teardown operation */
	if ((mp->map_op == DDI_MO_UNMAP) ||
	    (mp->map_op == DDI_MO_UNLOCK)) {
		/* free up memory allocated for the private access handle. */
		px_pvt = (px_config_acc_pvt_t *)hp->ah_bus_private;
		kmem_free((void *)px_pvt, sizeof (px_config_acc_pvt_t));

		/* unmap operation of PCI IO/config space. */
		return (DDI_SUCCESS);
	}

	fmcap = ddi_fm_capable(dip);
	if (DDI_FM_ACC_ERR_CAP(fmcap)) {
		errp = ((ddi_acc_impl_t *)hp)->ahi_err;
		otp = (on_trap_data_t *)errp->err_ontrap;
		otp->ot_handle = (void *)(hp);
		otp->ot_prot = OT_DATA_ACCESS;
		errp->err_status = DDI_FM_OK;
		errp->err_expected = DDI_FM_ERR_UNEXPECTED;
		errp->err_cf = px_err_cfg_hdl_check;
	}

	ap->ahi_get8 = px_pci_config_get8;
	ap->ahi_get16 = px_pci_config_get16;
	ap->ahi_get32 = px_pci_config_get32;
	ap->ahi_get64 = px_pci_config_get64;
	ap->ahi_put8 = px_pci_config_put8;
	ap->ahi_put16 = px_pci_config_put16;
	ap->ahi_put32 = px_pci_config_put32;
	ap->ahi_put64 = px_pci_config_put64;
	ap->ahi_rep_get8 = px_pci_config_rep_get8;
	ap->ahi_rep_get16 = px_pci_config_rep_get16;
	ap->ahi_rep_get32 = px_pci_config_rep_get32;
	ap->ahi_rep_get64 = px_pci_config_rep_get64;
	ap->ahi_rep_put8 = px_pci_config_rep_put8;
	ap->ahi_rep_put16 = px_pci_config_rep_put16;
	ap->ahi_rep_put32 = px_pci_config_rep_put32;
	ap->ahi_rep_put64 = px_pci_config_rep_put64;

	/* Initialize to default check/notify functions */
	ap->ahi_fault = 0;
	ap->ahi_fault_check = i_ddi_acc_fault_check;
	ap->ahi_fault_notify = i_ddi_acc_fault_notify;

	/* allocate memory for our private handle */
	px_pvt = (px_config_acc_pvt_t *)
	    kmem_zalloc(sizeof (px_config_acc_pvt_t), KM_SLEEP);
	hp->ah_bus_private = (void *)px_pvt;

	busnum = PCI_REG_BUS_G(rp->pci_phys_hi);
	devnum = PCI_REG_DEV_G(rp->pci_phys_hi);
	funcnum = PCI_REG_FUNC_G(rp->pci_phys_hi);

	/* set up private data for use during IO routines */

	/* addr needed by the HV APIs */
	px_pvt->raddr = busnum << 16 | devnum << 11 | funcnum << 8;
	/*
	 * Address that specifies the actual offset into the 256MB
	 * memory mapped configuration space, 4K per device.
	 * First 12bits form the offset into 4K config space.
	 * This address is only used during the IO routines to calculate
	 * the offset at which the transaction must be performed.
	 * Drivers bypassing DDI functions to access PCI config space will
	 * panic the system since the following is a bogus virtual address.
	 */
	px_pvt->vaddr = busnum << 20 | devnum << 15 | funcnum << 12 | off;
	px_pvt->dip = dip;

	DBG(DBG_LIB_CFG, dip, "px_config_setup: raddr 0x%x, vaddr 0x%x\n",
	    px_pvt->raddr, px_pvt->vaddr);
	*addrp = (caddr_t)(uintptr_t)px_pvt->vaddr;
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
px_lib_map_attr_check(ddi_map_req_t *mp)
{
}

/*
 * px_lib_log_safeacc_err:
 * Imitate a cpu/mem trap call when a peek/poke fails.
 * This will initiate something similar to px_fm_callback.
 */
static void
px_lib_log_safeacc_err(px_t *px_p, ddi_acc_handle_t handle, int fme_flag,
    r_addr_t addr)
{
	uint32_t	addr_high, addr_low;
	pcie_req_id_t	bdf = PCIE_INVALID_BDF;
	pci_ranges_t	*ranges_p;
	int		range_len, i;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;
	ddi_fm_error_t derr;

	if (px_fm_enter(px_p) != DDI_SUCCESS)
		return;

	derr.fme_status = DDI_FM_NONFATAL;
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_flag = fme_flag;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_acc_handle = handle;
	if (hp)
		hp->ahi_err->err_expected = DDI_FM_ERR_EXPECTED;

	addr_high = (uint32_t)(addr >> 32);
	addr_low = (uint32_t)addr;

	/*
	 * Make sure this failed load came from this PCIe port.  Check by
	 * matching the upper 32 bits of the address with the ranges property.
	 */
	range_len = px_p->px_ranges_length / sizeof (pci_ranges_t);
	i = 0;
	for (ranges_p = px_p->px_ranges_p; i < range_len; i++, ranges_p++) {
		if (ranges_p->parent_high == addr_high) {
			switch (ranges_p->child_high & PCI_ADDR_MASK) {
			case PCI_ADDR_CONFIG:
				bdf = (pcie_req_id_t)(addr_low >> 12);
				break;
			default:
				bdf = PCIE_INVALID_BDF;
				break;
			}
			break;
		}
	}

	(void) px_rp_en_q(px_p, bdf, addr, 0);
	(void) px_scan_fabric(px_p, px_p->px_dip, &derr);
	px_fm_exit(px_p);
}


#ifdef  DEBUG
int	px_peekfault_cnt = 0;
int	px_pokefault_cnt = 0;
#endif  /* DEBUG */

/*
 * Do a safe write to a device.
 *
 * When this function is given a handle (cautious access), all errors are
 * suppressed.
 *
 * When this function is not given a handle (poke), only Unsupported Request
 * and Completer Abort errors are suppressed.
 *
 * In all cases, all errors are returned in the function return status.
 */

int
px_lib_ctlops_poke(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;

	size_t repcount = in_args->repcount;
	size_t size = in_args->size;
	uintptr_t dev_addr = in_args->dev_addr;
	uintptr_t host_addr = in_args->host_addr;

	int err	= DDI_SUCCESS;
	uint64_t hvio_poke_status;
	uint32_t wrt_stat;

	r_addr_t ra;
	uint64_t pokeval;
	pcie_req_id_t bdf;

	ra = (r_addr_t)va_to_pa((void *)dev_addr);
	for (; repcount; repcount--) {

		switch (size) {
		case sizeof (uint8_t):
			pokeval = *(uint8_t *)host_addr;
			break;
		case sizeof (uint16_t):
			pokeval = *(uint16_t *)host_addr;
			break;
		case sizeof (uint32_t):
			pokeval = *(uint32_t *)host_addr;
			break;
		case sizeof (uint64_t):
			pokeval = *(uint64_t *)host_addr;
			break;
		default:
			DBG(DBG_MAP, px_p->px_dip,
			    "poke: invalid size %d passed\n", size);
			err = DDI_FAILURE;
			goto done;
		}

		/*
		 * Grab pokefault mutex since hypervisor does not guarantee
		 * poke serialization.
		 */
		if (hp) {
			i_ndi_busop_access_enter(hp->ahi_common.ah_dip,
			    (ddi_acc_handle_t)hp);
			pec_p->pec_safeacc_type = DDI_FM_ERR_EXPECTED;
		} else {
			mutex_enter(&pec_p->pec_pokefault_mutex);
			pec_p->pec_safeacc_type = DDI_FM_ERR_POKE;
		}

		if (pcie_get_bdf_from_dip(rdip, &bdf) != DDI_SUCCESS) {
			err = DDI_FAILURE;
			goto done;
		}

		hvio_poke_status = hvio_poke(px_p->px_dev_hdl, ra, size,
		    pokeval, bdf << 8, &wrt_stat);

		if ((hvio_poke_status != H_EOK) || (wrt_stat != H_EOK)) {
			err = DDI_FAILURE;
#ifdef  DEBUG
			px_pokefault_cnt++;
#endif
			/*
			 * For CAUTIOUS and POKE access, notify FMA to
			 * cleanup.  Imitate a cpu/mem trap call like in sun4u.
			 */
			px_lib_log_safeacc_err(px_p, (ddi_acc_handle_t)hp,
			    (hp ? DDI_FM_ERR_EXPECTED :
			    DDI_FM_ERR_POKE), ra);

			pec_p->pec_ontrap_data = NULL;
			pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
			if (hp) {
				i_ndi_busop_access_exit(hp->ahi_common.ah_dip,
				    (ddi_acc_handle_t)hp);
			} else {
				mutex_exit(&pec_p->pec_pokefault_mutex);
			}
			goto done;
		}

		pec_p->pec_ontrap_data = NULL;
		pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
		if (hp) {
			i_ndi_busop_access_exit(hp->ahi_common.ah_dip,
			    (ddi_acc_handle_t)hp);
		} else {
			mutex_exit(&pec_p->pec_pokefault_mutex);
		}

		host_addr += size;

		if (in_args->flags == DDI_DEV_AUTOINCR) {
			dev_addr += size;
			ra = (r_addr_t)va_to_pa((void *)dev_addr);
		}
	}

done:
	return (err);
}


/*ARGSUSED*/
int
px_lib_ctlops_peek(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args, void *result)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;

	size_t repcount = in_args->repcount;
	uintptr_t dev_addr = in_args->dev_addr;
	uintptr_t host_addr = in_args->host_addr;

	r_addr_t ra;
	uint32_t read_status;
	uint64_t hvio_peek_status;
	uint64_t peekval;
	int err = DDI_SUCCESS;

	result = (void *)in_args->host_addr;

	ra = (r_addr_t)va_to_pa((void *)dev_addr);
	for (; repcount; repcount--) {

		/* Lock pokefault mutex so read doesn't mask a poke fault. */
		if (hp) {
			i_ndi_busop_access_enter(hp->ahi_common.ah_dip,
			    (ddi_acc_handle_t)hp);
			pec_p->pec_safeacc_type = DDI_FM_ERR_EXPECTED;
		} else {
			mutex_enter(&pec_p->pec_pokefault_mutex);
			pec_p->pec_safeacc_type = DDI_FM_ERR_PEEK;
		}

		hvio_peek_status = hvio_peek(px_p->px_dev_hdl, ra,
		    in_args->size, &read_status, &peekval);

		if ((hvio_peek_status != H_EOK) || (read_status != H_EOK)) {
			err = DDI_FAILURE;

			/*
			 * For CAUTIOUS and PEEK access, notify FMA to
			 * cleanup.  Imitate a cpu/mem trap call like in sun4u.
			 */
			px_lib_log_safeacc_err(px_p, (ddi_acc_handle_t)hp,
			    (hp ? DDI_FM_ERR_EXPECTED :
			    DDI_FM_ERR_PEEK), ra);

			/* Stuff FFs in host addr if peek. */
			if (hp == NULL) {
				int i;
				uint8_t *ff_addr = (uint8_t *)host_addr;
				for (i = 0; i < in_args->size; i++)
					*ff_addr++ = 0xff;
			}
#ifdef  DEBUG
			px_peekfault_cnt++;
#endif
			pec_p->pec_ontrap_data = NULL;
			pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
			if (hp) {
				i_ndi_busop_access_exit(hp->ahi_common.ah_dip,
				    (ddi_acc_handle_t)hp);
			} else {
				mutex_exit(&pec_p->pec_pokefault_mutex);
			}
			goto done;

		}
		pec_p->pec_ontrap_data = NULL;
		pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
		if (hp) {
			i_ndi_busop_access_exit(hp->ahi_common.ah_dip,
			    (ddi_acc_handle_t)hp);
		} else {
			mutex_exit(&pec_p->pec_pokefault_mutex);
		}

		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)host_addr = (uint8_t)peekval;
			break;
		case sizeof (uint16_t):
			*(uint16_t *)host_addr = (uint16_t)peekval;
			break;
		case sizeof (uint32_t):
			*(uint32_t *)host_addr = (uint32_t)peekval;
			break;
		case sizeof (uint64_t):
			*(uint64_t *)host_addr = (uint64_t)peekval;
			break;
		default:
			DBG(DBG_MAP, px_p->px_dip,
			    "peek: invalid size %d passed\n",
			    in_args->size);
			err = DDI_FAILURE;
			goto done;
		}

		host_addr += in_args->size;

		if (in_args->flags == DDI_DEV_AUTOINCR) {
			dev_addr += in_args->size;
			ra = (r_addr_t)va_to_pa((void *)dev_addr);
		}
	}
done:
	return (err);
}


/* add interrupt vector */
int
px_err_add_intr(px_fault_t *px_fault_p)
{
	px_t	*px_p = DIP_TO_STATE(px_fault_p->px_fh_dip);

	DBG(DBG_LIB_INT, px_p->px_dip,
	    "px_err_add_intr: calling add_ivintr");

	VERIFY(add_ivintr(px_fault_p->px_fh_sysino, PX_ERR_PIL,
	    (intrfunc)px_fault_p->px_err_func, (caddr_t)px_fault_p, NULL,
	    (caddr_t)&px_fault_p->px_intr_payload[0]) == 0);

	DBG(DBG_LIB_INT, px_p->px_dip,
	    "px_err_add_intr: ib_intr_enable ");

	px_ib_intr_enable(px_p, intr_dist_cpuid(), px_fault_p->px_intr_ino);

	return (DDI_SUCCESS);
}

/* remove interrupt vector */
void
px_err_rem_intr(px_fault_t *px_fault_p)
{
	px_t	*px_p = DIP_TO_STATE(px_fault_p->px_fh_dip);

	px_ib_intr_disable(px_p->px_ib_p, px_fault_p->px_intr_ino,
	    IB_INTR_WAIT);

	VERIFY(rem_ivintr(px_fault_p->px_fh_sysino, PX_ERR_PIL) == 0);
}

void
px_cb_intr_redist(void *arg)
{
	px_t	*px_p = (px_t *)arg;
	px_ib_intr_dist_en(px_p->px_dip, intr_dist_cpuid(),
	    px_p->px_inos[PX_INTR_XBC], B_FALSE);
}

int
px_cb_add_intr(px_fault_t *f_p)
{
	px_t	*px_p = DIP_TO_STATE(f_p->px_fh_dip);

	DBG(DBG_LIB_INT, px_p->px_dip,
	    "px_err_add_intr: calling add_ivintr");

	VERIFY(add_ivintr(f_p->px_fh_sysino, PX_ERR_PIL,
	    (intrfunc)f_p->px_err_func, (caddr_t)f_p, NULL,
	    (caddr_t)&f_p->px_intr_payload[0]) == 0);

	intr_dist_add(px_cb_intr_redist, px_p);

	DBG(DBG_LIB_INT, px_p->px_dip,
	    "px_err_add_intr: ib_intr_enable ");

	px_ib_intr_enable(px_p, intr_dist_cpuid(), f_p->px_intr_ino);

	return (DDI_SUCCESS);
}

void
px_cb_rem_intr(px_fault_t *f_p)
{
	intr_dist_rem(px_cb_intr_redist, DIP_TO_STATE(f_p->px_fh_dip));
	px_err_rem_intr(f_p);
}

#ifdef FMA
void
px_fill_rc_status(px_fault_t *px_fault_p, pciex_rc_error_regs_t *rc_status)
{
	px_pec_err_t	*err_pkt;

	err_pkt = (px_pec_err_t *)px_fault_p->px_intr_payload;

	/* initialise all the structure members */
	rc_status->status_valid = 0;

	if (err_pkt->pec_descr.P) {
		/* PCI Status Register */
		rc_status->pci_err_status = err_pkt->pci_err_status;
		rc_status->status_valid |= PCI_ERR_STATUS_VALID;
	}

	if (err_pkt->pec_descr.E) {
		/* PCIe Status Register */
		rc_status->pcie_err_status = err_pkt->pcie_err_status;
		rc_status->status_valid |= PCIE_ERR_STATUS_VALID;
	}

	if (err_pkt->pec_descr.U) {
		rc_status->ue_status = err_pkt->ue_reg_status;
		rc_status->status_valid |= UE_STATUS_VALID;
	}

	if (err_pkt->pec_descr.H) {
		rc_status->ue_hdr1 = err_pkt->hdr[0];
		rc_status->status_valid |= UE_HDR1_VALID;
	}

	if (err_pkt->pec_descr.I) {
		rc_status->ue_hdr2 = err_pkt->hdr[1];
		rc_status->status_valid |= UE_HDR2_VALID;
	}

	/* ue_fst_err_ptr - not available for sun4v?? */


	if (err_pkt->pec_descr.S) {
		rc_status->source_id = err_pkt->err_src_reg;
		rc_status->status_valid |= SOURCE_ID_VALID;
	}

	if (err_pkt->pec_descr.R) {
		rc_status->root_err_status = err_pkt->root_err_status;
		rc_status->status_valid |= CE_STATUS_VALID;
	}
}
#endif

/*ARGSUSED*/
int
px_lib_pmctl(int cmd, px_t *px_p)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
uint_t
px_pmeq_intr(caddr_t arg)
{
	return (DDI_INTR_CLAIMED);
}

/*
 * fetch the config space base addr of the root complex
 * note this depends on px structure being initialized
 */
uint64_t
px_lib_get_cfgacc_base(dev_info_t *dip)
{
	int		instance = DIP_TO_INST(dip);
	px_t		*px_p = INST_TO_STATE(instance);

	return (px_p->px_dev_hdl);
}

void
px_panic_domain(px_t *px_p, pcie_req_id_t bdf)
{
	uint64_t	ret;
	dev_info_t	*dip = px_p->px_dip;

	DBG(DBG_ERR_INTR, dip, "px_panic_domain: handle 0x%lx, ino %d, "
	    "bdf<<8 0x%lx\n",
	    (uint64_t)DIP_TO_HANDLE(dip), px_p->px_cb_fault.px_intr_ino,
	    (pci_device_t)bdf << 8);
	if ((ret = pci_error_send(DIP_TO_HANDLE(dip),
	    px_p->px_cb_fault.px_intr_ino, (pci_device_t)bdf << 8)) != H_EOK) {
		DBG(DBG_ERR_INTR, dip, "pci_error_send failed, ret 0x%lx\n",
		    ret);
	} else
		DBG(DBG_ERR_INTR, dip, "pci_error_send worked\n");
}

/*ARGSUSED*/
int
px_lib_hotplug_init(dev_info_t *dip, void *arg)
{
	return (DDI_ENOTSUP);
}

/*ARGSUSED*/
void
px_lib_hotplug_uninit(dev_info_t *dip)
{
}

/*ARGSUSED*/
void
px_hp_intr_redist(px_t *px_p)
{
}

/* Dummy cpr add callback */
/*ARGSUSED*/
void
px_cpr_add_callb(px_t *px_p)
{
}

/* Dummy cpr rem callback */
/*ARGSUSED*/
void
px_cpr_rem_callb(px_t *px_p)
{
}

/*ARGSUSED*/
boolean_t
px_lib_is_in_drain_state(px_t *px_p)
{
	return (B_FALSE);
}

/*
 * There is no IOAPI to get the BDF of the pcie root port nexus at this moment.
 * Assume it is 0x0000, until otherwise noted.  For now, all sun4v platforms
 * have programmed the BDF to be 0x0000.
 */
/*ARGSUSED*/
pcie_req_id_t
px_lib_get_bdf(px_t *px_p)
{
	return (0x0000);
}

int
px_lib_get_root_complex_mps(px_t *px_p, dev_info_t *dip, int *mps)
{
	pci_device_t	bdf = px_lib_get_bdf(px_p);

	if (hvio_get_rp_mps_cap(DIP_TO_HANDLE(dip), bdf, mps) == H_EOK)
		return (DDI_SUCCESS);
	else
		return (DDI_FAILURE);
}

int
px_lib_set_root_complex_mps(px_t *px_p,  dev_info_t *dip, int mps)
{
	pci_device_t	bdf = px_lib_get_bdf(px_p);

	if (hvio_set_rp_mps(DIP_TO_HANDLE(dip), bdf, mps) == H_EOK)
		return (DDI_SUCCESS);
	else
		return (DDI_FAILURE);
}

static int
px_lib_do_count_waiting_dev(dev_info_t *dip, void *arg)
{
	int *count = (int *)arg;
	dev_info_t *cdip = ddi_get_child(dip);

	while (cdip != NULL) {
		/* check if this is an assigned device */
		if (ddi_prop_exists(DDI_DEV_T_NONE, cdip, DDI_PROP_DONTPASS,
		    "ddi-assigned")) {
			DBG(DBG_ATTACH, dip, "px_lib_do_count_waiting_dev: "
			    "Found an assigned dev %p, under bridge %p",
			    cdip, dip);

			/*
			 * Mark this bridge as needing waiting for
			 * CHILD_LOANED will be removed after bridge reports
			 * its readyness back to px driver
			 */
			if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
			    CHILD_LOANED, 1) == DDI_PROP_SUCCESS)
				(*count)++;
			break;
		}
		cdip = ddi_get_next_sibling(cdip);
	}

	return (DDI_WALK_CONTINUE);
}

static int
px_lib_count_waiting_dev(dev_info_t *dip)
{
	int count = 0;

	/* No need to continue if this system is not SDIO capable */
	if (px_sdio_users == 0)
		return (0);

	/* see if px iteslf has assigned children */
	(void) px_lib_do_count_waiting_dev(dip, &count);

	/* scan dev under this px */
	ndi_devi_enter(dip);
	ddi_walk_devs(ddi_get_child(dip), px_lib_do_count_waiting_dev, &count);
	ndi_devi_exit(dip);
	return (count);
}

/* Called from px/bridge driver directly to report its readyness */
int
px_lib_fabric_sync(dev_info_t *dip)
{
	px_t *px;
	dev_info_t *rcdip;
	int waitdev;

	/* No need to continue if this system is not SDIO capable */
	if (px_sdio_users == 0)
		return (DDI_SUCCESS);

	/* a valid bridge w/ assigned dev under it? */
	if (ddi_prop_remove(DDI_DEV_T_NONE, dip, CHILD_LOANED) !=
	    DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	/* find out RC dip */
	for (rcdip = dip; rcdip != NULL; rcdip = ddi_get_parent(rcdip)) {
		if (PCIE_DIP2BUS(rcdip) && PCIE_IS_RC(PCIE_DIP2BUS(rcdip)))
			break;
	}
	if ((rcdip == NULL) || ((px = (px_t *)DIP_TO_STATE(rcdip)) == NULL))
		return (DDI_FAILURE);

	/* are we ready? */
	waitdev = (int)(uintptr_t)px->px_plat_p;
	ASSERT(waitdev);
	DBG(DBG_CTLOPS, rcdip, "px_lib_fabric_sync: "
	    "Px/bridge %p is ready, %d left", rcdip, waitdev - 1);
	--waitdev;
	px->px_plat_p = (void *)(uintptr_t)waitdev;
	if (waitdev != 0)
		return (DDI_SUCCESS);

	/* notify hpyervisor */
	DBG(DBG_CTLOPS, rcdip, "px_lib_fabric_sync: "
	    "Notifying HV that RC %p is ready users=%d", rcdip, px_sdio_users);

	if (pci_iov_root_configured(px->px_dev_hdl) != H_EOK)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}
