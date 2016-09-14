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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SMRT_SCSI_H
#define	_SMRT_SCSI_H

#include <sys/types.h>

#include <sys/scsi/adapters/smrt/smrt_ciss.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* CISS LUN Addressing MODEs */
#define	PERIPHERIAL_DEV_ADDR 			0x0
#define	LOGICAL_VOL_ADDR 			0x1
#define	MASK_PERIPHERIAL_DEV_ADDR 		0x3
#define	CISS_PHYS_MODE 				0x0

/*
 * Vendor-specific SCSI Commands
 *
 * These command opcodes are for use in the opcode byte of the CDB in a request
 * of type CISS_TYPE_CMD.  They are custom SCSI commands, using the
 * vendor-specific part of the opcode space; i.e., 0xC0 through 0xFF.
 */
#define	CISS_SCMD_REPORT_LOGICAL_LUNS		0xC2
#define	CISS_SCMD_REPORT_PHYSICAL_LUNS		0xC3

/*
 * CISS Messages
 *
 * The CISS specification describes several directives that do not behave like
 * SCSI commands.  They are sent in requests of type CISS_TYPE_MSG.
 *
 * The Abort, Reset, and Nop, messages are defined in "8. Messages" in the CISS
 * Specification.
 */
#define	CISS_MSG_ABORT				0x0
#define	CISS_ABORT_TASK				0x0
#define	CISS_ABORT_TASKSET			0x1

#define	CISS_MSG_RESET				0x1
#define	CISS_RESET_CTLR				0x0
#define	CISS_RESET_BUS				0x1
#define	CISS_RESET_TGT				0x3
#define	CISS_RESET_LUN				0x4

#define	CISS_MSG_NOP				0x3

/*
 * The following packed structures are used to ease the manipulation of SCSI
 * commands sent to, and status information returned from, the controller.
 */
#pragma pack(1)

typedef struct smrt_report_logical_lun_ent {
	LogDevAddr_t smrle_addr;
} smrt_report_logical_lun_ent_t;

typedef struct smrt_report_logical_lun_extent {
	LogDevAddr_t smrle_addr;
	uint8_t smrle_wwn[16];
} smrt_report_logical_lun_extent_t;

typedef struct smrt_report_logical_lun {
	uint32_t smrll_datasize; /* Big Endian */
	uint8_t smrll_extflag;
	uint8_t smrll_reserved1[3];
	union {
		smrt_report_logical_lun_ent_t ents[SMRT_MAX_LOGDRV];
		smrt_report_logical_lun_extent_t extents[SMRT_MAX_LOGDRV];
	} smrll_data;
} smrt_report_logical_lun_t;

typedef struct smrt_report_logical_lun_req {
	uint8_t smrllr_opcode;
	uint8_t smrllr_extflag;
	uint8_t smrllr_reserved1[4];
	uint32_t smrllr_datasize; /* Big Endian */
	uint8_t smrllr_reserved2;
	uint8_t smrllr_control;
} smrt_report_logical_lun_req_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SMRT_SCSI_H */
