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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_RSM_RSM_COMMON_H
#define	_SYS_RSM_RSM_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	RSM_VERSION	5

/* Return values for RSMAPI */
#define	RSM_SUCCESS 0
#define	RSMERR_BAD_LIBRARY_VERSION		1
#define	RSMERR_BAD_TOPOLOGY_PTR			2
#define	RSMERR_BAD_CTLR_HNDL			3
#define	RSMERR_CTLR_NOT_PRESENT			4
#define	RSMERR_BAD_SEG_HNDL			5
#define	RSMERR_SEG_ALREADY_PUBLISHED		6
#define	RSMERR_SEG_NOT_PUBLISHED		7
#define	RSMERR_SEG_NOT_PUBLISHED_TO_NODE	8
#define	RSMERR_SEG_ALREADY_MAPPED		9
#define	RSMERR_SEG_STILL_MAPPED			10
#define	RSMERR_SEG_NOT_MAPPED			11
#define	RSMERR_NOT_CREATOR			12
#define	RSMERR_BAD_BARRIER_PTR			13
#define	RSMERR_BAD_SGIO				14
#define	RSMERR_BAD_LOCALMEM_HNDL		15
#define	RSMERR_BAD_ADDR				16
#define	RSMERR_BAD_MEM_ALIGNMENT		17
#define	RSMERR_BAD_OFFSET			18
#define	RSMERR_MISALIGNED_OFFSET		19
#define	RSMERR_BAD_LENGTH			20
#define	RSMERR_BAD_ACL				21
#define	RSMERR_BAD_SEGID			22
#define	RSMERR_RESERVED_SEGID			23
#define	RSMERR_SEGID_IN_USE			24
#define	RSMERR_BAD_MODE				25
#define	RSMERR_BAD_PERMS			26
#define	RSMERR_PERM_DENIED			27
#define	RSMERR_LOCKS_NOT_SUPPORTED		28
#define	RSMERR_LOCKS_NOT_ENABLED		29
#define	RSMERR_REBIND_NOT_ALLOWED		30
#define	RSMERR_INSUFFICIENT_RESOURCES		31
#define	RSMERR_INSUFFICIENT_MEM			32
#define	RSMERR_MAP_FAILED			33
#define	RSMERR_POLLFD_IN_USE			34
#define	RSMERR_BARRIER_UNINITIALIZED		35
#define	RSMERR_BARRIER_OPEN_FAILED		36
#define	RSMERR_BARRIER_NOT_OPENED		37
#define	RSMERR_BARRIER_FAILURE			38
#define	RSMERR_REMOTE_NODE_UNREACHABLE		39
#define	RSMERR_CONN_ABORTED			40
#define	RSMERR_INTERRUPTED			41
#define	RSMERR_TIMEOUT				42
#define	RSMERR_BAD_APPID			43
#define	RSMERR_BAD_CONF				44
#define	RSMERR_SEG_NOT_CONNECTED		45

/* Additional return values for RSMPI */
#define	RSMERR_BAD_DRIVER_VERSION		101
#define	RSMERR_UNSUPPORTED_VERSION		102
#define	RSMERR_DRIVER_NAME_IN_USE		103
#define	RSMERR_DRIVER_NOT_REGISTERED		104
#define	RSMERR_DRIVER_THREAD_RUNNING		105
#define	RSMERR_NEED_THREAD_INIT			106
#define	RSMERR_THREAD_NOT_INITED		107
#define	RSMERR_CTLRS_REGISTERED			108
#define	RSMERR_CTLR_NOT_REGISTERED		109
#define	RSMERR_CTLR_ALREADY_REGISTERED		110
#define	RSMERR_CTLR_IN_USE			111
#define	RSMERR_NAME_TOO_LONG			112
#define	RSMERR_SEG_PUBLISHED			113
#define	RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR	114
#define	RSMERR_SEG_IN_USE			115
#define	RSMERR_BAD_SENDQ_HNDL			116
#define	RSMERR_BAD_ARGS_ERRORS			117
#define	RSMERR_BAD_MSTYPE			118
#define	RSMERR_NO_BACKING_MEM			119
#define	RSMERR_NOT_MEM				120
#define	RSMERR_MEM_ALREADY_BOUND		121
#define	RSMERR_MEM_NOT_BOUND			122
#define	RSMERR_HANDLER_NOT_REGISTERED		123
#define	RSMERR_NO_HANDLER			124
#define	RSMERR_UNBIND_REBIND_NOT_ALLOWED	125
#define	RSMERR_CALLBACKS_NOT_SUPPORTED		126
#define	RSMERR_UNSUPPORTED_OPERATION		127
#define	RSMERR_RSM_ADDR_UNREACHABLE		128
#define	RSMERR_UNKNOWN_RSM_ADDR			129
#define	RSMERR_BAD_BARRIER_HNDL			130
#define	RSMERR_COMM_ERR_MAYBE_DELIVERED		131
#define	RSMERR_COMM_ERR_NOT_DELIVERED		132
#define	RSMERR_QUEUE_FENCE_UP			133
#define	RSMERR_QUEUE_FULL			134

#define	RSMERR_INTERNAL_ERROR			100

/*
 * Partition segment id and service id space
 * users should only create segments or register handlers
 * using segment and service id's from the correct range below
 * RSM_DRIVER_PRIVATE enforced in rsm_memseg_export_publish
 * and rsm_memseg_import_connect
 */

#define	RSM_DRIVER_PRIVATE_ID_BASE	0
#define	RSM_DRIVER_PRIVATE_ID_END	0x0FFFFF

#define	RSM_CLUSTER_TRANSPORT_ID_BASE	0x100000
#define	RSM_CLUSTER_TRANSPORT_ID_END	0x1FFFFF
#define	RSM_RSMLIB_ID_BASE		0x200000
#define	RSM_RSMLIB_ID_END		0x2FFFFF
#define	RSM_DLPI_ID_BASE		0x300000
#define	RSM_DLPI_ID_END			0x3FFFFF
#define	RSM_HPC_ID_BASE			0x400000
#define	RSM_HPC_ID_END			0x4FFFFF
#define	RSM_OPS_ID_BASE			0x500000
#define	RSM_OPS_ID_END			0x5FFFFF

#define	RSM_USER_APP_ID_BASE		0x80000000
#define	RSM_USER_APP_ID_END		0xFFFFFFFF

/*
 * The following definitions and typedef are used to describe the
 * permissions associated with all or part of a memory segment.
 */
#define	RSM_PERM_NONE				0
#define	RSM_PERM_READ				0400
#define	RSM_PERM_WRITE				0200
#define	RSM_PERM_RDWR				(RSM_PERM_READ|RSM_PERM_WRITE)

/* Maximum io_request_count value in rsm_scat_gath_t */
#define	RSM_MAX_SGIOREQS	16

/*
 * Direct access sizes bits
 */
typedef enum {
	RSM_DAS8	=	1,
	RSM_DAS16	=	2,
	RSM_DAS32	=	4,
	RSM_DAS64	=	8
}rsm_access_size_t;

typedef uint64_t rsm_addr_t;
typedef uint32_t rsm_node_id_t;
typedef uint32_t rsm_memseg_id_t;
typedef uint32_t rsm_permission_t;

struct __rsm_memseg_import_handle;
typedef struct __rsm_memseg_import_handle *rsm_memseg_import_handle_t;

struct __rsm_memseg_export_handle;
typedef struct __rsm_memseg_export_handle *rsm_memseg_export_handle_t;

typedef enum {
	RSM_BARRIER_SEGMENT = 0x01,
	RSM_BARRIER_NODE    = 0x02,
	RSM_BARRIER_SEGMENT_THREAD = 0x11,
	RSM_BARRIER_NODE_THREAD = 0x12
}rsm_barrier_type_t;

typedef union {
	uint64_t u64;
	int64_t i64;
	uint32_t u32[2];
	int32_t i32[2];
	uint16_t u16[4];
	int16_t i16[4];
	uint8_t u8[8];
	int8_t i8[8];
	uchar_t uc[8];
	char c[8];
	void *vp;
} rsm_barrier_component_t;

typedef struct {
	rsm_barrier_component_t comp[4];
} rsm_barrier_t;

typedef enum {
	RSM_BARRIER_MODE_EXPLICIT, RSM_BARRIER_MODE_IMPLICIT
} rsm_barrier_mode_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_RSM_RSM_COMMON_H */
