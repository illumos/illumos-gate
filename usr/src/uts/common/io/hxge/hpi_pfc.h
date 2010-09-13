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

#ifndef _HPI_PFC_H
#define	_HPI_PFC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <hpi.h>
#include <hxge_common.h>
#include <hxge_pfc_hw.h>
#include <hxge_pfc.h>

typedef enum _tcam_op {
	TCAM_RWC_STAT	= 0x1,
	TCAM_RWC_MATCH	= 0x2
} tcam_op_t;

/*
 * HPI PFC ERROR Codes
 */
#define	HPI_PFC_BLK_CODE	PFC_BLK_ID << 8
#define	HPI_PFC_ERROR		(HPI_FAILURE | HPI_PFC_BLK_CODE)
#define	HPI_TCAM_ERROR		0x10
#define	HPI_FCRAM_ERROR		0x20
#define	HPI_GEN_PFC		0x30
#define	HPI_PFC_SW_PARAM_ERROR	0x40
#define	HPI_PFC_HW_ERROR	0x80

#define	HPI_PFC_RESET_ERROR	(HPI_PFC_ERROR | HPI_GEN_PFC | RESET_FAILED)
#define	HPI_PFC_TCAM_WR_ERROR		\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | WRITE_FAILED)
#define	HPI_PFC_ASC_RAM_RD_ERROR	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | READ_FAILED)
#define	HPI_PFC_ASC_RAM_WR_ERROR	\
	(HPI_PFC_ERROR | HPI_TCAM_ERROR | WRITE_FAILED)

#define	TCAM_CLASS_INVALID		\
	(HPI_PFC_SW_PARAM_ERROR | 0xb)
/* have only 0xc, 0xd, 0xe and 0xf left for sw error codes */
#define	HPI_PFC_TCAM_HW_ERROR		\
	(HPI_PFC_ERROR | HPI_PFC_HW_ERROR | HPI_TCAM_ERROR)

#define	PFC_N_VLAN_MEMBERS		0x20

#define	PFC_N_MAC_ADDRESSES		16
#define	PFC_MAX_DMA_CHANNELS		4
#define	PFC_MAC_ADDR_STEP		8

#define	PFC_HASH_STEP			0x08

#define	PFC_L2_CLASS_CONFIG_STEP	0x08

#define	PFC_L3_CLASS_CONFIG_STEP	0x08

#define	PFC_N_TCAM_ENTRIES		42

#define	PFC_VLAN_REG_OFFSET(vlan_id) \
	((((vlan_id_t)(vlan_id / PFC_N_VLAN_MEMBERS)) * 8) + PFC_VLAN_TABLE)
#define	PFC_VLAN_BIT_OFFSET(vlan_id) \
	(vlan_id % PFC_N_VLAN_MEMBERS)
#define	PFC_MAC_ADDRESS(slot) \
	((slot * PFC_MAC_ADDR_STEP) + PFC_MAC_ADDR)
#define	PFC_MAC_ADDRESS_MASK(slot) \
	((slot * PFC_MAC_ADDR_STEP) + PFC_MAC_ADDR_MASK)
#define	PFC_HASH_ADDR(slot) \
	((slot * PFC_HASH_STEP) + PFC_HASH_TABLE)

#define	PFC_L2_CONFIG(slot) \
	((slot * PFC_L2_CLASS_CONFIG_STEP) + PFC_L2_CLASS_CONFIG)
#define	PFC_L3_CONFIG(slot) \
	(((slot - TCAM_CLASS_TCP_IPV4) * PFC_L3_CLASS_CONFIG_STEP) + \
	PFC_L3_CLASS_CONFIG)

typedef uint16_t vlan_id_t;

/*
 * PFC Control Register Functions
 */
hpi_status_t hpi_pfc_set_tcam_enable(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_l2_hash(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_cksum(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_default_dma(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_mac_addr_enable(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_mac_addr_disable(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_set_force_csum(hpi_handle_t, boolean_t);

/*
 * PFC vlan Functions
 */
hpi_status_t hpi_pfc_cfg_vlan_table_clear(hpi_handle_t);
hpi_status_t hpi_pfc_cfg_vlan_table_entry_clear(hpi_handle_t, vlan_id_t);
hpi_status_t hpi_pfc_cfg_vlan_table_entry_set(hpi_handle_t, vlan_id_t);
hpi_status_t hpi_pfc_cfg_vlan_control_set(hpi_handle_t, boolean_t,
    boolean_t, vlan_id_t);
hpi_status_t hpi_pfc_get_vlan_parity_log(hpi_handle_t,
    pfc_vlan_par_err_log_t *);

/*
 * PFC Mac Address Functions
 */
hpi_status_t hpi_pfc_set_mac_address(hpi_handle_t, uint32_t, uint64_t);
hpi_status_t hpi_pfc_clear_mac_address(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_clear_multicast_hash_table(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_set_multicast_hash_table(hpi_handle_t, uint32_t,
    uint64_t);

/*
 * PFC L2 and L3 Config Functions.
 */
hpi_status_t hpi_pfc_set_l2_class_slot(hpi_handle_t, uint16_t, boolean_t, int);
hpi_status_t hpi_pfc_get_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t *cfg);
hpi_status_t hpi_pfc_set_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t cfg);

/*
 * PFC TCAM Functions
 */
hpi_status_t hpi_pfc_tcam_invalidate_all(hpi_handle_t);
hpi_status_t hpi_pfc_tcam_entry_invalidate(hpi_handle_t, uint32_t);
hpi_status_t hpi_pfc_tcam_entry_write(hpi_handle_t, uint32_t,
    hxge_tcam_entry_t *);
hpi_status_t hpi_pfc_tcam_entry_read(hpi_handle_t, uint32_t,
    hxge_tcam_entry_t *);
hpi_status_t hpi_pfc_tcam_asc_ram_entry_read(hpi_handle_t handle,
    uint32_t location, uint64_t *ram_data);
hpi_status_t hpi_pfc_tcam_asc_ram_entry_write(hpi_handle_t handle,
    uint32_t location, uint64_t ram_data);
hpi_status_t hpi_pfc_get_tcam_parity_log(hpi_handle_t,
    pfc_tcam_par_err_log_t *);
hpi_status_t hpi_pfc_get_tcam_auto_init(hpi_handle_t,
    pfc_auto_init_t *);

/*
 * PFC TCP Control
 */
hpi_status_t hpi_pfc_set_tcp_control_discard(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_fin(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_syn(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_rst(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_psh(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_ack(hpi_handle_t, boolean_t);
hpi_status_t hpi_pfc_set_tcp_control_urg(hpi_handle_t, boolean_t);

/*
 * PFC Hash Seed Value
 */
hpi_status_t hpi_pfc_set_hash_seed_value(hpi_handle_t, uint32_t);

/*
 * PFC Interrupt Management Functions
 */
hpi_status_t hpi_pfc_get_interrupt_status(hpi_handle_t, pfc_int_status_t *);
hpi_status_t hpi_pfc_clear_interrupt_status(hpi_handle_t);
hpi_status_t hpi_pfc_set_interrupt_mask(hpi_handle_t, boolean_t,
    boolean_t, boolean_t);

/*
 * PFC Packet Logs
 */
hpi_status_t hpi_pfc_get_drop_log(hpi_handle_t, pfc_drop_log_t *);
hpi_status_t hpi_pfc_set_drop_log_mask(hpi_handle_t, boolean_t,
    boolean_t, boolean_t, boolean_t, boolean_t);
hpi_status_t hpi_pfc_get_bad_csum_counter(hpi_handle_t, uint64_t *);
hpi_status_t hpi_pfc_get_drop_counter(hpi_handle_t, uint64_t *);

hpi_status_t hpi_pfc_get_number_mac_addrs(hpi_handle_t handle,
    uint32_t *n_of_addrs);
hpi_status_t hpi_pfc_mac_addr_get_i(hpi_handle_t handle, uint8_t *data,
    int slot);
hpi_status_t hpi_pfc_num_macs_get(hpi_handle_t handle, uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif /* !_HPI_PFC_H */
