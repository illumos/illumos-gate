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

#ifndef _SYS_PX_LIB4V_H
#define	_SYS_PX_LIB4V_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fasttrap numbers for VPCI hypervisor functions.
 */

#define	HVIO_IOMMU_MAP		0xb0
#define	HVIO_IOMMU_DEMAP	0xb1
#define	HVIO_IOMMU_GETMAP	0xb2
#define	HVIO_IOMMU_GETBYPASS	0xb3

#define	HVIO_CONFIG_GET		0xb4
#define	HVIO_CONFIG_PUT		0xb5

#define	HVIO_PEEK		0xb6
#define	HVIO_POKE		0xb7

#define	HVIO_DMA_SYNC		0xb8

#define	HVIO_MSIQ_CONF		0xc0
#define	HVIO_MSIQ_INFO		0xc1
#define	HVIO_MSIQ_GETVALID	0xc2
#define	HVIO_MSIQ_SETVALID	0xc3
#define	HVIO_MSIQ_GETSTATE	0xc4
#define	HVIO_MSIQ_SETSTATE	0xc5
#define	HVIO_MSIQ_GETHEAD	0xc6
#define	HVIO_MSIQ_SETHEAD	0xc7
#define	HVIO_MSIQ_GETTAIL	0xc8

#define	HVIO_MSI_GETVALID	0xc9
#define	HVIO_MSI_SETVALID	0xca
#define	HVIO_MSI_GETMSIQ	0xcb
#define	HVIO_MSI_SETMSIQ	0xcc
#define	HVIO_MSI_GETSTATE	0xcd
#define	HVIO_MSI_SETSTATE	0xce

#define	HVIO_MSG_GETMSIQ	0xd0
#define	HVIO_MSG_SETMSIQ	0xd1
#define	HVIO_MSG_GETVALID	0xd2
#define	HVIO_MSG_SETVALID	0xd3

#ifndef _ASM

/*
 * The device handle uniquely identifies a SUN4V device.
 * It consists of the lower 28-bits of the hi-cell of the
 * first entry of the SUN4V device's "reg" property as
 * defined by the SUN4V Bus Binding to Open Firmware.
 */
#define	DEVHDLE_MASK	0xFFFFFFF

/* PX BDF Shift in a Phyiscal Address - used FMA Fabric only */
#define	PX_RA_BDF_SHIFT			8

#define	PX_ADDR2PFN(addr, index, flags, i) \
	((flags & MMU_MAP_PFN) ? \
	PX_GET_MP_PFN((ddi_dma_impl_t *)(addr), (index + i)) : \
	hat_getpfnum(kas.a_hat, ((caddr_t)addr + (MMU_PAGE_SIZE * i))))

/*
 * VPCI API versioning.
 *
 * Currently PX nexus driver supports VPCI API version 1.1
 */
#define	PX_VPCI_MAJOR_VER_1	0x1ull
#define	PX_VPCI_MAJOR_VER	PX_VPCI_MAJOR_VER_1

#define	PX_VPCI_MINOR_VER_0	0x0ull
#define	PX_VPCI_MINOR_VER_1	0x1ull
#define	PX_VPCI_MINOR_VER	PX_VPCI_MINOR_VER_1

extern uint64_t hvio_config_get(devhandle_t dev_hdl, pci_device_t bdf,
    pci_config_offset_t off, pci_config_size_t size, pci_cfg_data_t *data_p);
extern uint64_t hvio_config_put(devhandle_t dev_hdl, pci_device_t bdf,
    pci_config_offset_t off, pci_config_size_t size, pci_cfg_data_t data);

extern uint64_t hvio_iommu_map(devhandle_t dev_hdl, tsbid_t tsbid,
    pages_t pages, io_attributes_t attr, io_page_list_t *io_page_list_p,
    pages_t *pages_mapped);
extern uint64_t hvio_iommu_demap(devhandle_t dev_hdl, tsbid_t tsbid,
    pages_t pages, pages_t *pages_demapped);
extern uint64_t hvio_iommu_getmap(devhandle_t dev_hdl, tsbid_t tsbid,
    io_attributes_t *attr_p, r_addr_t *r_addr_p);
extern uint64_t hvio_iommu_getbypass(devhandle_t dev_hdl, r_addr_t ra,
    io_attributes_t attr, io_addr_t *io_addr_p);
extern uint64_t hvio_dma_sync(devhandle_t dev_hdl, r_addr_t ra,
    size_t num_bytes, io_sync_direction_t io_sync_direction,
    size_t *bytes_synched);

/*
 * MSIQ Functions:
 */
extern uint64_t hvio_msiq_conf(devhandle_t dev_hdl, msiqid_t msiq_id,
    r_addr_t ra, uint_t msiq_rec_cnt);
extern uint64_t hvio_msiq_info(devhandle_t dev_hdl, msiqid_t msiq_id,
    r_addr_t *ra_p, uint_t *msiq_rec_cnt_p);
extern uint64_t hvio_msiq_getvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state);
extern uint64_t hvio_msiq_setvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state);
extern uint64_t hvio_msiq_getstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state);
extern uint64_t hvio_msiq_setstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state);
extern uint64_t hvio_msiq_gethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t *msiq_head);
extern uint64_t hvio_msiq_sethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t msiq_head);
extern uint64_t hvio_msiq_gettail(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqtail_t *msiq_tail);

/*
 * MSI Functions:
 */
extern uint64_t hvio_msi_getmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t *msiq_id);
extern uint64_t hvio_msi_setmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t msiq_id, msi_type_t msitype);
extern uint64_t hvio_msi_getvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state);
extern uint64_t hvio_msi_setvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state);
extern uint64_t hvio_msi_getstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t *msi_state);
extern uint64_t hvio_msi_setstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t msi_state);

/*
 * MSG Functions:
 */
extern uint64_t hvio_msg_getmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id);
extern uint64_t hvio_msg_setmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t msiq_id);
extern uint64_t hvio_msg_getvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state);
extern uint64_t hvio_msg_setvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state);

typedef struct px_config_acc_pvt {
	dev_info_t *dip;
	uint32_t raddr;
	uint32_t vaddr;
} px_config_acc_pvt_t;

/*
 * Peek/poke functionality:
 */

extern uint64_t hvio_peek(devhandle_t dev_hdl, r_addr_t ra, size_t size,
    uint32_t *status, uint64_t *data_p);
extern uint64_t hvio_poke(devhandle_t dev_hdl, r_addr_t ra, size_t size,
    uint64_t data, pci_device_t bdf, uint32_t *wrt_stat);
extern uint64_t hvio_get_rp_mps_cap(devhandle_t dev_hdl, pci_device_t bdf,
    int32_t *mps_cap);
extern uint64_t hvio_set_rp_mps(devhandle_t dev_hdl, pci_device_t bdf,
    int32_t mps);

/*
 * Priviledged physical access:
 */
extern uint64_t hv_ra2pa(uint64_t ra);
extern uint64_t hv_hpriv(void *func, uint64_t arg1, uint64_t arg2,
    uint64_t arg3);
extern int px_phys_acc_4v(uint64_t dummy, uint64_t from_addr, uint64_t to_addr);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_LIB4V_H */
