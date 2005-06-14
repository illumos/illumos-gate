/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PX_LIB4V_H
#define	_SYS_PX_LIB4V_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SUN4V IO API - Version 1.11
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The device handle uniquely identifies a SUN4V device.
 * It consists of the lower 28-bits of the hi-cell of the
 * first entry of the SUN4V device's "reg" property as
 * defined by the SUN4V Bus Binding to Open Firmware.
 */
#define	DEVHDLE_MASK	0xFFFFFFF

extern uint64_t hvio_config_get(devhandle_t dev_hdl, pci_device_t bdf,
    pci_config_offset_t off, pci_config_size_t size, pci_cfg_data_t *data_p);
extern uint64_t hvio_config_put(devhandle_t dev_hdl, pci_device_t bdf,
    pci_config_offset_t off, pci_config_size_t size, pci_cfg_data_t data);

extern uint64_t hvio_iommu_map(devhandle_t dev_hdl, tsbid_t tsbid,
    pages_t pages, io_attributes_t io_attributes,
    io_page_list_t *io_page_list_p, pages_t *pages_mapped);
extern uint64_t hvio_iommu_demap(devhandle_t dev_hdl, tsbid_t tsbid,
    pages_t pages, pages_t *pages_demapped);
extern uint64_t hvio_iommu_getmap(devhandle_t dev_hdl, tsbid_t tsbid,
    io_attributes_t *attributes_p, r_addr_t *r_addr_p);
extern uint64_t hvio_iommu_getbypass(devhandle_t dev_hdl, r_addr_t ra,
    io_attributes_t io_attributes, io_addr_t *io_addr_p);
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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_LIB4V_H */
