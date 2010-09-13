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

#ifndef	_SYS_IB_ADAPTERS_HERMON_IOCTL_H
#define	_SYS_IB_ADAPTERS_HERMON_IOCTL_H

#include <sys/cred.h>

/*
 * hermon_ioctl.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for all ioctl access into the driver.  This includes everything
 *    necessary for updating firmware, accessing the hermon flash device,
 *    providing interfaces for VTS.
 */

#ifdef __cplusplus
extern "C" {
#endif

int hermon_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);

/*
 * Enumerated type for the Hermon ioctl() interface types
 */
/*
 * originally, to make a unique set of IOCTLs but now share the actual
 * value w/ tavor & arbel (memfree) to make VTS consistent & simpler
 *
 *	#define	HERMON_IOCTL		('h' << 8)
 */
#define	HERMON_IOCTL		('t' << 8)

#ifdef	DEBUG
typedef enum {
	HERMON_IOCTL_FLASH_READ		= HERMON_IOCTL | 0x00,
	HERMON_IOCTL_FLASH_WRITE		= HERMON_IOCTL | 0x01,
	HERMON_IOCTL_FLASH_ERASE		= HERMON_IOCTL | 0x02,
	HERMON_IOCTL_FLASH_INIT		= HERMON_IOCTL | 0x03,
	HERMON_IOCTL_FLASH_FINI		= HERMON_IOCTL | 0x04,
	HERMON_IOCTL_REG_WRITE		= HERMON_IOCTL | 0x10,
	HERMON_IOCTL_REG_READ		= HERMON_IOCTL | 0x11,
	HERMON_IOCTL_LOOPBACK		= HERMON_IOCTL | 0x20,
	HERMON_IOCTL_INFO			= HERMON_IOCTL | 0x21,
	HERMON_IOCTL_PORTS			= HERMON_IOCTL | 0x22,
	HERMON_IOCTL_DDR_READ		= HERMON_IOCTL | 0x23,
	HERMON_IOCTL_WRITE_BOOT_ADDR	= HERMON_IOCTL | 0x24
} hermon_ioctl_enum_t;
#else
typedef enum {
	HERMON_IOCTL_FLASH_READ		= HERMON_IOCTL | 0x00,
	HERMON_IOCTL_FLASH_WRITE		= HERMON_IOCTL | 0x01,
	HERMON_IOCTL_FLASH_ERASE		= HERMON_IOCTL | 0x02,
	HERMON_IOCTL_FLASH_INIT		= HERMON_IOCTL | 0x03,
	HERMON_IOCTL_FLASH_FINI		= HERMON_IOCTL | 0x04,
	HERMON_IOCTL_LOOPBACK		= HERMON_IOCTL | 0x20,
	HERMON_IOCTL_INFO		= HERMON_IOCTL | 0x21,
	HERMON_IOCTL_PORTS		= HERMON_IOCTL | 0x22,
	HERMON_IOCTL_DDR_READ		= HERMON_IOCTL | 0x23,
	HERMON_IOCTL_WRITE_BOOT_ADDR	= HERMON_IOCTL | 0x24
} hermon_ioctl_enum_t;
#endif	/* DEBUG */

/*
 * Specific operations for each of the flash ioctl interfaces
 */
#define	HERMON_FLASH_READ_SECTOR			0x01
#define	HERMON_FLASH_READ_QUADLET		0x02
#define	HERMON_FLASH_WRITE_SECTOR		0x01
#define	HERMON_FLASH_WRITE_BYTE			0x02
#define	HERMON_FLASH_ERASE_SECTOR		0x01
#define	HERMON_FLASH_ERASE_CHIP			0x02

/*
 * Default values for the flash (overridden by CFI info, if available)
 */
#define	HERMON_FLASH_SECTOR_SZ_DEFAULT		0x10000
#define	HERMON_FLASH_DEVICE_SZ_DEFAULT		0x400000
#define	HERMON_FLASH_SPI_LOG_SECTOR_SIZE		0x10
#define	HERMON_FLASH_SPI_SECTOR_SIZE		0x10000
#define	HERMON_FLASH_SPI_DEVICE_SIZE		0x200000

/*
 * CFI (Common Flash Interface) initialization
 */
#define	HERMON_FLASH_CFI_INIT			0x98

/* For compatability */
#define	HERMON_FLASH_CFI_SIZE			0x4C
#define	HERMON_FLASH_CFI_SIZE_QUADLET		HERMON_FLASH_CFI_SIZE >> 2

/*
 * Expand CFI data size to support the Intel Expanded Command Set.
 */
#define	HERMON_CFI_INFO_SIZE 			0x100
#define	HERMON_CFI_INFO_QSIZE			HERMON_CFI_INFO_SIZE >> 2

/*
 * Mellanox uses two different parallel Flash devices for Hermon
 * HCAs: the AMD AM29LV033C and the Intel 28F320J3C. The AM29LV033C
 * utilizes the AMD Standard CFI command set while the 28F320J3C
 * utliizes the Intel Extended CFI command set. Additionally, serial
 * SPI flash is supported, such as the STMicroelectronics M25Pxx family
 * of SPI Flash parts.
 */
#define	HERMON_FLASH_INTEL_CMDSET		0x0001
#define	HERMON_FLASH_AMD_CMDSET			0x0002
#define	HERMON_FLASH_SPI_CMDSET			0x0003
#define	HERMON_FLASH_UNKNOWN_CMDSET		0XFFFF

/*
 * The firmware version structure used in HERMON_IOCTL_INFO and
 * HERMON_IOCTL_FLASH_INIT interfaces.  The structure consists of major,
 * minor and subminor portions for firmware revision number.
 */
typedef struct hermon_fw_info_ioctl_s {
	uint32_t	afi_maj;
	uint32_t	afi_min;
	uint32_t	afi_sub;
} hermon_fw_info_ioctl_t;

/*
 * structure used for read, write, and erase flash routines
 * Supported fields for each type:
 * read_sector:  af_type, af_sector, af_sector_num
 * read_quadlet: af_type, af_addr, af_quadlet
 * write_sector: af_type, af_sector, af_sector_num
 * write_byte:   af_type, af_addr, af_byte
 * erase_sector: af_type, af_sector_num
 * erase_chip:   af_type
 *
 * The 'tf_sector' field must point to a sector sized portion of memory, as
 * all sector read/write ioctl calls are done as one complete sector only.
 */
typedef struct hermon_flash_ioctl_s {
	uint32_t	af_type;
	caddr_t		af_sector;
	uint32_t	af_sector_num;
	uint32_t	af_addr;
	uint32_t	af_quadlet;
	uint8_t		af_byte;
} hermon_flash_ioctl_t;

/* Structure used for flash init interface */
typedef struct hermon_flash_init_ioctl_s {
	uint32_t		af_hwrev;
	hermon_fw_info_ioctl_t	af_fwrev;
	uint32_t		af_cfi_info[HERMON_FLASH_CFI_SIZE_QUADLET];
	char			af_hwpn[64];
	int			af_pn_len;
} hermon_flash_init_ioctl_t;

/*
 * The structure used for Hermon register read/write interface.
 * The "trg_reg_set" field indicates the register set (the BAR) from which
 * the access is desired (HERMON_CMD_BAR, HERMON_UAR_BAR, or HERMON_DDR_BAR).
 * The "trg_offset" and "trg_data" fields indicate the register and either
 * the destination or source of the data to be read/written.
 */
typedef struct hermon_reg_ioctl_s {
	uint_t		arg_reg_set;
	uint_t		arg_offset;
	uint32_t	arg_data;
} hermon_reg_ioctl_t;


/*
 * Hermon VTS IOCTL revision number.  This revision number is currently
 * expected to be passed in all Hermon VTS ioctl interfaces.
 */
#define	HERMON_VTS_IOCTL_REVISION	1

/*
 * The port structure used in HERMON_IOCTL_PORTS interface.
 * Each port has an associated guid, port number, and IBA-defined
 * logical port state.
 */
typedef struct hermon_stat_port_ioctl_s {
	uint64_t	asp_guid;
	uint32_t	asp_port_num;
	uint32_t	asp_state;
} hermon_stat_port_ioctl_t;

/*
 * The structure used for the HERMON_IOCTL_PORTS interface.
 * The number of ports and a buffer large enough for 256
 * port structures will be supplied by the caller.  The
 * revision should be set to HERMON_VTS_IOCTL_REVISION.  The
 * number of ports ("tp_num_ports") is always returned,
 * regardless of success or failure otherwise.
 */
typedef struct hermon_ports_ioctl_s {
	uint_t			ap_revision;
	hermon_stat_port_ioctl_t	*ap_ports;
	uint8_t			ap_num_ports;
} hermon_ports_ioctl_t;

/*
 * These are the status codes that can be returned by the
 * HERMON_IOCTL_LOOPBACK test.  They are returned as part of
 * the hermon_loopback_ioctl_t struct (below).
 */
typedef enum {
	HERMON_LOOPBACK_SUCCESS,
	HERMON_LOOPBACK_INVALID_REVISION,
	HERMON_LOOPBACK_INVALID_PORT,
	HERMON_LOOPBACK_PROT_DOMAIN_ALLOC_FAIL,
	HERMON_LOOPBACK_SEND_BUF_INVALID,
	HERMON_LOOPBACK_SEND_BUF_MEM_REGION_ALLOC_FAIL,
	HERMON_LOOPBACK_SEND_BUF_COPY_FAIL,
	HERMON_LOOPBACK_RECV_BUF_MEM_REGION_ALLOC_FAIL,
	HERMON_LOOPBACK_XMIT_SEND_CQ_ALLOC_FAIL,
	HERMON_LOOPBACK_XMIT_RECV_CQ_ALLOC_FAIL,
	HERMON_LOOPBACK_XMIT_QP_ALLOC_FAIL,
	HERMON_LOOPBACK_RECV_SEND_CQ_ALLOC_FAIL,
	HERMON_LOOPBACK_RECV_RECV_CQ_ALLOC_FAIL,
	HERMON_LOOPBACK_RECV_QP_ALLOC_FAIL,
	HERMON_LOOPBACK_XMIT_QP_INIT_FAIL,
	HERMON_LOOPBACK_XMIT_QP_RTR_FAIL,
	HERMON_LOOPBACK_XMIT_QP_RTS_FAIL,
	HERMON_LOOPBACK_RECV_QP_INIT_FAIL,
	HERMON_LOOPBACK_RECV_QP_RTR_FAIL,
	HERMON_LOOPBACK_RECV_QP_RTS_FAIL,
	HERMON_LOOPBACK_WQE_POST_FAIL,
	HERMON_LOOPBACK_CQ_POLL_FAIL,
	HERMON_LOOPBACK_SEND_RECV_COMPARE_FAIL
} hermon_loopback_error_t;

/*
 * The structure used for HERMON_IOCTL_LOOPBACK interface.
 * It defines the port number, number of iterations, wait duration,
 * number of retries and the data pattern to be sent.  Upon return,
 * the driver will supply the number of iterations succesfully
 * completed, and the kind of failure (if any, along with the failing
 * data pattern).
 */
typedef struct hermon_loopback_ioctl_s {
	uint_t			alb_revision;
	caddr_t			alb_send_buf;
	caddr_t			alb_fail_buf;
	uint_t			alb_buf_sz;
	uint_t			alb_num_iter;
	uint_t			alb_pass_done;
	uint_t			alb_timeout;
	hermon_loopback_error_t	alb_error_type;
	uint8_t			alb_port_num;
	uint8_t			alb_num_retry;
} hermon_loopback_ioctl_t;

/*
 * The structure used for the HERMON_IOCTL_INFO interface.  It
 * includes firmware version, hardware version, accessable
 * range of adapter DDR memory, and adapter flash memory size.
 */
typedef struct hermon_info_ioctl_s {
	uint_t			ai_revision;
	hermon_fw_info_ioctl_t	ai_fw_rev;
	uint32_t		ai_hw_rev;
	uint_t			ai_flash_sz;
	uint_t			rsvd1; /* DDR start */
	uint_t			rsvd2; /* DDR end   */
} hermon_info_ioctl_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_IOCTL_H */
