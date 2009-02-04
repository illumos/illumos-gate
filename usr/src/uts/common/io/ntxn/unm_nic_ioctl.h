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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __UNM_NIC_IOCTL_H__
#define	__UNM_NIC_IOCTL_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ioctl's dealing with PCI read/writes */
#define	UNM_CMD_START 0
#define	UNM_NIC_CMD  (UNM_CMD_START + 1)
#define	UNM_NIC_NAME (UNM_CMD_START + 2)

typedef enum {
		unm_nic_cmd_none = 0,
		unm_nic_cmd_pci_read,
		unm_nic_cmd_pci_write,
		unm_nic_cmd_pci_mem_read,
		unm_nic_cmd_pci_mem_write,
		unm_nic_cmd_pci_config_read,
		unm_nic_cmd_pci_config_write,
		unm_nic_cmd_get_stats,
		unm_nic_cmd_clear_stats,
		unm_nic_cmd_get_version,
		unm_nic_cmd_get_phy_type,
		unm_nic_cmd_efuse_chip_id,

		unm_nic_cmd_flash_read = 50,
		unm_nic_cmd_flash_write,
		unm_nic_cmd_flash_se
} unm_nic_ioctl_cmd_t;

#pragma pack(1)

typedef struct {
		__uint32_t cmd;
		__uint32_t unused1;
		__uint64_t off;
		__uint32_t size;
		__uint32_t rv;
		char uabc[64];
		void *ptr;
} unm_nic_ioctl_data_t;

struct unm_statistics {
	__uint64_t rx_packets;
	__uint64_t tx_packets;
	__uint64_t rx_bytes;
	__uint64_t rx_errors;
	__uint64_t tx_bytes;
	__uint64_t tx_errors;
	__uint64_t rx_CRC_errors;
	__uint64_t rx_short_length_error;
	__uint64_t rx_long_length_error;
	__uint64_t rx_MAC_errors;
};

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* !__UNM_NIC_IOCTL_H__ */
