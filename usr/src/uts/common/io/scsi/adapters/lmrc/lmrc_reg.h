/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Racktop Systems, Inc.
 */
#ifndef _LMRC_REG_H
#define	_LMRC_REG_H

#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#include <sys/scsi/adapters/mfi/mfi.h>

typedef struct lmrc_raid_mfa_io_req_desc	lmrc_raid_mfa_io_req_desc_t;
typedef union lmrc_atomic_req_desc		lmrc_atomic_req_desc_t;
typedef union lmrc_req_desc			lmrc_req_desc_t;

#include "lmrc_raid.h"

/* PCI device IDs of Gen 3.5 Controllers */
#define	LMRC_VENTURA		0x0014
#define	LMRC_CRUSADER		0x0015
#define	LMRC_HARPOON		0x0016
#define	LMRC_TOMCAT		0x0017
#define	LMRC_VENTURA_4PORT	0x001B
#define	LMRC_CRUSADER_4PORT	0x001C
#define	LMRC_AERO_10E0		0x10E0
#define	LMRC_AERO_10E1		0x10E1
#define	LMRC_AERO_10E2		0x10E2
#define	LMRC_AERO_10E3		0x10E3
#define	LMRC_AERO_10E4		0x10E4
#define	LMRC_AERO_10E5		0x10E5
#define	LMRC_AERO_10E6		0x10E6
#define	LMRC_AERO_10E7		0x10E7

/*
 * Message Frame Defines
 */
#define	LMRC_SENSE_LEN		96

#define	LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE	256

#define	LMRC_SPECIFIC_MPI2_FUNCTION(x)		\
	(MPI2_FUNCTION_MIN_PRODUCT_SPECIFIC + (x))
#define	LMRC_MPI2_FUNCTION_PASSTHRU_IO_REQUEST	LMRC_SPECIFIC_MPI2_FUNCTION(0)
#define	LMRC_MPI2_FUNCTION_LD_IO_REQUEST	LMRC_SPECIFIC_MPI2_FUNCTION(1)


#define	LMRC_MAX_MFI_CMDS			16
#define	LMRC_MAX_IOCTL_CMDS			3

/*
 * Firmware Status Register
 * For Ventura and Aero controllers, this is outbound scratch pad register 0.
 */
#define	LMRC_FW_RESET_REQUIRED(reg)		(bitx32((reg), 0, 0) != 0)
#define	LMRC_FW_RESET_ADAPTER(reg)		(bitx32((reg), 1, 1) != 0)
#define	LMRC_FW_MAX_CMD(reg)			bitx32((reg), 15, 0)
#define	LMRC_FW_MSIX_ENABLED(reg)		(bitx32((reg), 26, 26) != 0)
#define	LMRC_FW_STATE(reg)			bitx32((reg), 31, 28)

/* outbound scratch pad register 1 */
#define	LMRC_MAX_CHAIN_SIZE(reg)		bitx32((reg), 9, 5)
#define	LMRC_MAX_REPLY_QUEUES_EXT(reg)		bitx32((reg), 21, 14)
#define	LMRC_EXT_CHAIN_SIZE_SUPPORT(reg)	(bitx32((reg), 22, 22) != 0)
#define	LMRC_RDPQ_MODE_SUPPORT(reg)		(bitx32((reg), 23, 23) != 0)
#define	LMRC_SYNC_CACHE_SUPPORT(reg)		(bitx32((reg), 24, 24) != 0)
#define	LMRC_ATOMIC_DESCRIPTOR_SUPPORT(reg)	(bitx32((reg), 24, 24) != 0)
#define	LMRC_64BIT_DMA_SUPPORT(reg)		(bitx32((reg), 25, 25) != 0)
#define	LMRC_INTR_COALESCING_SUPPORT(reg)	(bitx32((reg), 26, 26) != 0)

#define	LMRC_256K_IO				128
#define	LMRC_1MB_IO				(LMRC_256K_IO * 4)

/* outbound scratch pad register 2 */
#define	LMRC_MAX_RAID_MAP_SZ(reg)		bitx32((reg), 24, 16)

/* outbound scratch pad register 3 */
#define	LMRC_NVME_PAGE_SHIFT(reg)		bitx32((reg), 7, 0)
#define	LMRC_DEFAULT_NVME_PAGE_SHIFT		12

/*
 * FW posts its state in the upper 4 bits of the status register, extracted
 * with LMRC_FW_STATE(reg).
 */
#define	LMRC_FW_STATE_UNDEFINED			0x0
#define	LMRC_FW_STATE_BB_INIT			0x1
#define	LMRC_FW_STATE_FW_INIT			0x4
#define	LMRC_FW_STATE_WAIT_HANDSHAKE		0x6
#define	LMRC_FW_STATE_FW_INIT_2			0x7
#define	LMRC_FW_STATE_DEVICE_SCAN		0x8
#define	LMRC_FW_STATE_BOOT_MSG_PENDING		0x9
#define	LMRC_FW_STATE_FLUSH_CACHE		0xa
#define	LMRC_FW_STATE_READY			0xb
#define	LMRC_FW_STATE_OPERATIONAL		0xc
#define	LMRC_FW_STATE_FAULT			0xf

#define	LMRC_MAX_PD_CHANNELS		1
#define	LMRC_MAX_LD_CHANNELS		1
#define	LMRC_MAX_DEV_PER_CHANNEL	256
#define	LMRC_MAX_PD			\
	(LMRC_MAX_PD_CHANNELS * LMRC_MAX_DEV_PER_CHANNEL)
#define	LMRC_MAX_LD			\
	(LMRC_MAX_LD_CHANNELS * LMRC_MAX_DEV_PER_CHANNEL)
#define	LMRC_MAX_TM_TARGETS		(LMRC_MAX_PD + LMRC_MAX_LD)

#define	LMRC_DEFAULT_INIT_ID		-1
#define	LMRC_MAX_LUN			8
#define	LMRC_DEFAULT_CMD_PER_LUN	256

#define	LMRC_MAX_REPLY_POST_HOST_INDEX	16


/* By default, the firmware programs for 8k of memory */
#define	LMRC_MFI_MIN_MEM	4096
#define	LMRC_MFI_DEF_MEM	8192
#define	LMRC_MFI_MAX_CMD	16


#pragma pack(1)

/*
 * MPT RAID MFA IO Descriptor.
 *
 * Note: The use of the lowest 8 bits for flags implies that an alignment
 * of 256 bytes is required for the physical address.
 */
struct lmrc_raid_mfa_io_req_desc {
	uint32_t RequestFlags:8;
	uint32_t MessageAddress1:24;	/* bits 31:8 */
	uint32_t MessageAddress2;	/* bits 61:32 */
};

/*
 * unions of Request Descriptors
 */
union lmrc_atomic_req_desc {
	Mpi26AtomicRequestDescriptor_t rd_atomic;
	uint32_t rd_reg;
};

union lmrc_req_desc {
	uint64_t	rd_reg;

	struct {
		uint32_t	rd_reg_lo;
		uint32_t	rd_reg_hi;
	};

	lmrc_atomic_req_desc_t		rd_atomic;
	lmrc_raid_mfa_io_req_desc_t	rd_mfa_io;
};

#pragma pack(0)

/*
 * Request descriptor types, in addition to those defined by mpi2.h
 *
 * FreeBSD and Linux drivers shift these, while mpi2.h defines them
 * pre-shifted. The latter seems more sensible.
 *
 * XXX: LMRC_REQ_DESCRIPT_FLAGS_MFA has the same value as
 * MPI2_REQ_DESCRIPT_FLAGS_SCSI_TARGET. Why?
 */
#define	LMRC_REQ_DESCRIPT_FLAGS_MFA		0x02
#define	LMRC_REQ_DESCRIPT_FLAGS_NO_LOCK		0x04
#define	LMRC_REQ_DESCRIPT_FLAGS_LD_IO		0x0e

#define	MPI2_TYPE_CUDA				0x2

#endif /* _LMRC_REG_H */
