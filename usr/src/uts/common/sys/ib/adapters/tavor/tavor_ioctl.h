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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_IOCTL_H
#define	_SYS_IB_ADAPTERS_TAVOR_IOCTL_H

#include <sys/cred.h>

/*
 * tavor_ioctl.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for all ioctl access into the driver.  This includes everything
 *    necessary for updating firmware, accessing the tavor flash device,
 *    providing interfaces for VTS.
 */

#ifdef __cplusplus
extern "C" {
#endif

int tavor_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);

/*
 * Enumerated type for the Tavor ioctl() interface types
 */
#define	TAVOR_IOCTL		('t' << 8)
#ifdef	DEBUG
typedef enum {
	TAVOR_IOCTL_FLASH_READ		= TAVOR_IOCTL | 0x00,
	TAVOR_IOCTL_FLASH_WRITE		= TAVOR_IOCTL | 0x01,
	TAVOR_IOCTL_FLASH_ERASE		= TAVOR_IOCTL | 0x02,
	TAVOR_IOCTL_FLASH_INIT		= TAVOR_IOCTL | 0x03,
	TAVOR_IOCTL_FLASH_FINI		= TAVOR_IOCTL | 0x04,
	TAVOR_IOCTL_REG_WRITE		= TAVOR_IOCTL | 0x10,
	TAVOR_IOCTL_REG_READ		= TAVOR_IOCTL | 0x11,
	TAVOR_IOCTL_LOOPBACK		= TAVOR_IOCTL | 0x20,
	TAVOR_IOCTL_INFO		= TAVOR_IOCTL | 0x21,
	TAVOR_IOCTL_PORTS		= TAVOR_IOCTL | 0x22,
	TAVOR_IOCTL_DDR_READ		= TAVOR_IOCTL | 0x23
} tavor_ioctl_enum_t;
#else
typedef enum {
	TAVOR_IOCTL_FLASH_READ		= TAVOR_IOCTL | 0x00,
	TAVOR_IOCTL_FLASH_WRITE		= TAVOR_IOCTL | 0x01,
	TAVOR_IOCTL_FLASH_ERASE		= TAVOR_IOCTL | 0x02,
	TAVOR_IOCTL_FLASH_INIT		= TAVOR_IOCTL | 0x03,
	TAVOR_IOCTL_FLASH_FINI		= TAVOR_IOCTL | 0x04,
	TAVOR_IOCTL_LOOPBACK		= TAVOR_IOCTL | 0x20,
	TAVOR_IOCTL_INFO		= TAVOR_IOCTL | 0x21,
	TAVOR_IOCTL_PORTS		= TAVOR_IOCTL | 0x22,
	TAVOR_IOCTL_DDR_READ		= TAVOR_IOCTL | 0x23
} tavor_ioctl_enum_t;
#endif	/* DEBUG */

/*
 * Specific operations for each of the flash ioctl interfaces
 */
#define	TAVOR_FLASH_READ_SECTOR			0x01
#define	TAVOR_FLASH_READ_QUADLET		0x02
#define	TAVOR_FLASH_WRITE_SECTOR		0x01
#define	TAVOR_FLASH_WRITE_BYTE			0x02
#define	TAVOR_FLASH_ERASE_SECTOR		0x01
#define	TAVOR_FLASH_ERASE_CHIP			0x02

/*
 * Default values for the flash (overridden by CFI info, if available)
 */
#define	TAVOR_FLASH_SECTOR_SZ_DEFAULT		0x10000
#define	TAVOR_FLASH_DEVICE_SZ_DEFAULT		0x400000

/*
 * CFI (Common Flash Interface) initialization
 */
#define	TAVOR_FLASH_CFI_INIT			0x98

/*
 * Needed for compatability
 */
#define	TAVOR_FLASH_CFI_SIZE			0x4c
#define	TAVOR_FLASH_CFI_SIZE_QUADLET		TAVOR_FLASH_CFI_SIZE >> 2

/*
 * Expand CFI data size to support the Intel Expanded Command Set.
 */
#define	TAVOR_CFI_INFO_SIZE 			0x100
#define	TAVOR_CFI_INFO_QSIZE			TAVOR_CFI_INFO_SIZE >> 2

/*
 * Mellanox uses two different parallel Flash devices for their
 * HCAs that tavor supports. They are the AMD AM29LV033C and the
 * Intel 28F320J3C. The AM29LV033C utilizes the AMD Standard CFI
 * command set while the 28F320J3C utliizes the Intel Extended
 * CFI command set.
 */
#define	TAVOR_FLASH_INTEL_CMDSET		0x0001
#define	TAVOR_FLASH_AMD_CMDSET			0x0002
#define	TAVOR_FLASH_UNKNOWN_CMDSET		0XFFFF

/*
 * The firmware version structure used in TAVOR_IOCTL_INFO and
 * TAVOR_IOCTL_FLASH_INIT interfaces.  The structure consists of major,
 * minor and subminor portions for firmware revision number.
 */
typedef struct tavor_fw_info_ioctl_s {
	uint32_t	tfi_maj;
	uint32_t	tfi_min;
	uint32_t	tfi_sub;
} tavor_fw_info_ioctl_t;

/*
 * structure used for read, write, and erase flash routines
 * Supported fields for each type:
 * read_sector:  tf_type, tf_sector, tf_sector_num
 * read_quadlet: tf_type, tf_addr, tf_quadlet
 * write_sector: tf_type, tf_sector, tf_sector_num
 * write_byte:   tf_type, tf_addr, tf_byte
 * erase_sector: tf_type, tf_sector_num
 * erase_chip:   tf_type
 *
 * The 'tf_sector' field must point to a sector sized portion of memory, as
 * all sector read/write ioctl calls are done as one complete sector only.
 */
typedef struct tavor_flash_ioctl_s {
	uint32_t	tf_type;
	caddr_t		tf_sector;
	uint32_t	tf_sector_num;
	uint32_t	tf_addr;
	uint32_t	tf_quadlet;
	uint8_t		tf_byte;
} tavor_flash_ioctl_t;

/* Structure used for flash init interface */
typedef struct tavor_flash_init_ioctl_s {
	uint32_t		tf_hwrev;
	tavor_fw_info_ioctl_t	tf_fwrev;
	uint32_t		tf_cfi_info[TAVOR_FLASH_CFI_SIZE_QUADLET];
	char			tf_hwpn[64];
	int			tf_pn_len;
} tavor_flash_init_ioctl_t;

/*
 * The structure used for Tavor register read/write interface.
 * The "trg_reg_set" field indicates the register set (the BAR) from which
 * the access is desired (TAVOR_CMD_BAR, TAVOR_UAR_BAR, or TAVOR_DDR_BAR).
 * The "trg_offset" and "trg_data" fields indicate the register and either
 * the destination or source of the data to be read/written.
 */
typedef struct tavor_reg_ioctl_s {
	uint_t		trg_reg_set;
	uint_t		trg_offset;
	uint32_t	trg_data;
} tavor_reg_ioctl_t;


/*
 * Tavor VTS IOCTL revision number.  This revision number is currently
 * expected to be passed in all Tavor VTS ioctl interfaces.
 */
#define	TAVOR_VTS_IOCTL_REVISION	1

/*
 * The port structure used in TAVOR_IOCTL_PORTS interface.
 * Each port has an associated guid, port number, and IBA-defined
 * logical port state.
 */
typedef struct tavor_stat_port_ioctl_s {
	uint64_t	tsp_guid;
	uint32_t	tsp_port_num;
	uint32_t	tsp_state;
} tavor_stat_port_ioctl_t;

/*
 * The structure used for the TAVOR_IOCTL_PORTS interface.
 * The number of ports and a buffer large enough for 256
 * port structures will be supplied by the caller.  The
 * revision should be set to TAVOR_VTS_IOCTL_REVISION.  The
 * number of ports ("tp_num_ports") is always returned,
 * regardless of success or failure otherwise.
 */
typedef struct tavor_ports_ioctl_s {
	uint_t			tp_revision;
	tavor_stat_port_ioctl_t	*tp_ports;
	uint8_t			tp_num_ports;
} tavor_ports_ioctl_t;

/*
 * The structure used for TAVOR_IOCTL_DDR_READ interface.
 * It includes byte offset within DDR from which to read
 * a 32-bit value (offset will be rounded off to 32-bit
 * alignment).
 */
typedef struct tavor_ddr_read_ioctl_s {
	uint_t		tdr_revision;
	uint_t		tdr_offset;
	uint32_t	tdr_data;
} tavor_ddr_read_ioctl_t;

/*
 * These are the status codes that can be returned by the
 * TAVOR_IOCTL_LOOPBACK test.  They are returned as part of
 * the tavor_loopback_ioctl_t struct (below).
 */
typedef enum {
	TAVOR_LOOPBACK_SUCCESS,
	TAVOR_LOOPBACK_INVALID_REVISION,
	TAVOR_LOOPBACK_INVALID_PORT,
	TAVOR_LOOPBACK_PROT_DOMAIN_ALLOC_FAIL,
	TAVOR_LOOPBACK_SEND_BUF_INVALID,
	TAVOR_LOOPBACK_SEND_BUF_MEM_REGION_ALLOC_FAIL,
	TAVOR_LOOPBACK_SEND_BUF_COPY_FAIL,
	TAVOR_LOOPBACK_RECV_BUF_MEM_REGION_ALLOC_FAIL,
	TAVOR_LOOPBACK_XMIT_SEND_CQ_ALLOC_FAIL,
	TAVOR_LOOPBACK_XMIT_RECV_CQ_ALLOC_FAIL,
	TAVOR_LOOPBACK_XMIT_QP_ALLOC_FAIL,
	TAVOR_LOOPBACK_RECV_SEND_CQ_ALLOC_FAIL,
	TAVOR_LOOPBACK_RECV_RECV_CQ_ALLOC_FAIL,
	TAVOR_LOOPBACK_RECV_QP_ALLOC_FAIL,
	TAVOR_LOOPBACK_XMIT_QP_INIT_FAIL,
	TAVOR_LOOPBACK_XMIT_QP_RTR_FAIL,
	TAVOR_LOOPBACK_XMIT_QP_RTS_FAIL,
	TAVOR_LOOPBACK_RECV_QP_INIT_FAIL,
	TAVOR_LOOPBACK_RECV_QP_RTR_FAIL,
	TAVOR_LOOPBACK_RECV_QP_RTS_FAIL,
	TAVOR_LOOPBACK_WQE_POST_FAIL,
	TAVOR_LOOPBACK_CQ_POLL_FAIL,
	TAVOR_LOOPBACK_SEND_RECV_COMPARE_FAIL
} tavor_loopback_error_t;

/*
 * The structure used for TAVOR_IOCTL_LOOPBACK interface.
 * It defines the port number, number of iterations, wait duration,
 * number of retries and the data pattern to be sent.  Upon return,
 * the driver will supply the number of iterations succesfully
 * completed, and the kind of failure (if any, along with the failing
 * data pattern).
 */
typedef struct tavor_loopback_ioctl_s {
	uint_t			tlb_revision;
	caddr_t			tlb_send_buf;
	caddr_t			tlb_fail_buf;
	uint_t			tlb_buf_sz;
	uint_t			tlb_num_iter;
	uint_t			tlb_pass_done;
	uint_t			tlb_timeout;
	tavor_loopback_error_t	tlb_error_type;
	uint8_t			tlb_port_num;
	uint8_t			tlb_num_retry;
} tavor_loopback_ioctl_t;

/*
 * The structure used for the TAVOR_IOCTL_INFO interface.  It
 * includes firmware version, hardware version, accessable
 * range of adapter DDR memory, and adapter flash memory size.
 */
typedef struct tavor_info_ioctl_s {
	uint_t			ti_revision;
	tavor_fw_info_ioctl_t	ti_fw_rev;
	uint32_t		ti_hw_rev;
	uint_t			ti_flash_sz;
	uint_t			ti_mem_start_offset;
	uint_t			ti_mem_end_offset;
} tavor_info_ioctl_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_IOCTL_H */
