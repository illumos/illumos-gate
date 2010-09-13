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
 */
#ifndef	_STMF_DEFINES_H
#define	_STMF_DEFINES_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	BIT_0	0x1
#define	BIT_1	0x2
#define	BIT_2	0x4
#define	BIT_3	0x8
#define	BIT_4	0x10
#define	BIT_5	0x20
#define	BIT_6	0x40
#define	BIT_7	0x80
#define	BIT_8	0x100
#define	BIT_9	0x200
#define	BIT_10	0x400
#define	BIT_11	0x800
#define	BIT_12	0x1000
#define	BIT_13	0x2000
#define	BIT_14	0x4000
#define	BIT_15	0x8000
#define	BIT_16	0x10000
#define	BIT_17	0x20000
#define	BIT_18	0x40000
#define	BIT_19	0x80000
#define	BIT_20	0x100000
#define	BIT_21	0x200000
#define	BIT_22	0x400000
#define	BIT_23	0x800000
#define	BIT_24	0x1000000
#define	BIT_25	0x2000000
#define	BIT_26	0x4000000
#define	BIT_27	0x8000000
#define	BIT_28	0x10000000
#define	BIT_29	0x20000000
#define	BIT_30	0x40000000
#define	BIT_31	0x80000000

/*
 * stmf status definitions
 */
typedef	uint64_t		stmf_status_t;
#define	STMF_SUCCESS		((uint64_t)0)
#define	STMF_FAILURE		((uint64_t)0x1000000000000000)
#define	STMF_TARGET_FAILURE	((uint64_t)0x2000000000000000)
#define	STMF_LU_FAILURE		((uint64_t)0x3000000000000000)
#define	STMF_FSC(x)		(((uint64_t)(x)) << 32)
#define	STMF_GET_FSC(x)		((((uint64_t)(x)) >> 32) & 0xFFFFFF)
#define	STMF_RETRY_BIT		((uint64_t)0x0080000000000000)
#define	STMF_BUSY		(STMF_FAILURE | STMF_RETRY_BIT | STMF_FSC(0))
#define	STMF_NOT_FOUND		(STMF_FAILURE | STMF_FSC(1))
#define	STMF_INVALID_ARG	(STMF_FAILURE | STMF_FSC(2))
#define	STMF_LUN_TAKEN		(STMF_FAILURE | STMF_FSC(3))
#define	STMF_ABORTED		(STMF_FAILURE | STMF_FSC(5))
#define	STMF_ABORT_SUCCESS	(STMF_FAILURE | STMF_FSC(6))
#define	STMF_ALLOC_FAILURE	(STMF_FAILURE | STMF_FSC(7))
#define	STMF_ALREADY		(STMF_FAILURE | STMF_FSC(8))
#define	STMF_TIMEOUT		(STMF_FAILURE | STMF_FSC(9))
#define	STMF_NOT_SUPPORTED	(STMF_FAILURE | STMF_FSC(10))
#define	STMF_BADSTATE		(STMF_FAILURE | STMF_FSC(11))

#define	GET_BYTE_OFFSET(ptr, off)	(((uint8_t *)(ptr)) + (off))
#define	GET_STRUCT_SIZE(s)		((sizeof (s) + 7) & 0xfffffff8)
#define	READ_SCSI16(addr, type)		((((type)(((uint8_t *)(addr))[0])) \
								<< 8) |\
					((type)(((uint8_t *)(addr))[1])))
#define	READ_SCSI21(addr, type)		((((type)(((uint8_t *)(addr))[0] & \
								0x1F)) << 16)\
					    | (READ_SCSI16(addr+1, type)))
#define	READ_SCSI32(addr, type)		(((READ_SCSI16(addr, type)) << 16) |\
					    (READ_SCSI16((addr+2), type)))
#define	READ_SCSI64(addr, type)		(((READ_SCSI32(addr, type)) << 32) |\
					    (READ_SCSI32((addr+4), type)))
#define	PTR2INT(p, t)	((t)((ulong_t)(p)))
#define	INT2PTR(i, t)	((t)((ulong_t)(i)))

/*
 * CDB definitions that don't exist in commands.h
 */
#define	SCMD_SYNCHRONIZE_CACHE_G4		0x91

/*
 * Common key, asc, ascq for stmf_scsilib_send_status
 */
#define	STMF_SAA_MEDIUM_NOT_PRESENT		0X023A00
#define	STMF_SAA_LU_NO_ACCESS_TRANSITION	0X02040A
#define	STMF_SAA_LU_NO_ACCESS_STANDBY		0X02040B
#define	STMF_SAA_LU_NO_ACCESS_UNAVAIL		0X02040C
#define	STMF_SAA_WRITE_ERROR			0x030C00
#define	STMF_SAA_READ_ERROR			0x031100
#define	STMF_SAA_OPERATION_IN_PROGRESS		0x050016
#define	STMF_SAA_INVALID_FIELD_IN_CMD_IU	0x050E03
#define	STMF_SAA_PARAM_LIST_LENGTH_ERROR	0x051A00
#define	STMF_SAA_INVALID_OPCODE			0x052000
#define	STMF_SAA_INVALID_LU			0x052009
#define	STMF_SAA_LBA_OUT_OF_RANGE		0x052100
#define	STMF_SAA_INVALID_FIELD_IN_CDB		0x052400
#define	STMF_SAA_INVALID_FIELD_IN_PARAM_LIST	0x052600
#define	STMF_SAA_INVALID_RELEASE_OF_PR		0x052604
#define	STMF_SAA_MEDIUM_REMOVAL_PREVENTED	0x055302
#define	STMF_SAA_INSUFFICIENT_REG_RESOURCES	0x055504
#define	STMF_SAA_POR				0x062900
#define	STMF_SAA_MODE_PARAMETERS_CHANGED	0x062A01
#define	STMF_SAA_ASYMMETRIC_ACCESS_CHANGED	0x062A06
#define	STMF_SAA_CAPACITY_DATA_HAS_CHANGED	0x062A09
#define	STMF_SAA_REPORT_LUN_DATA_HAS_CHANGED	0x063F0E
#define	STMF_SAA_WRITE_PROTECTED		0X072700

struct stmf_lu_provider;
struct stmf_lu;
struct stmf_port_provider;
struct stmf_local_port;
struct stmf_remote_port;
struct stmf_scsi_session;
struct scsi_task;
struct scsi_devid_desc;
struct scsi_transport_id;
struct stmf_data_buf;
struct stmf_lun_map;
struct scsi_devid_desc;

#ifdef	__cplusplus
}
#endif

#endif	/* _STMF_DEFINES_H */
