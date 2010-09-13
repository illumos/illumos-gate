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

#ifndef _DR_CPU_H
#define	_DR_CPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPU DR Control Protocol
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CPU DR Message Header
 */
typedef struct {
	uint64_t	req_num;	/* request number */
	uint32_t	msg_type;	/* message type */
	uint32_t	num_records;	/* number of records */
} dr_cpu_hdr_t;

/*
 * CPU command and response messages
 */

#define	DR_CPU_DS_ID		"dr-cpu"

#define	DR_CPU_CONFIGURE	('C')
#define	DR_CPU_UNCONFIGURE	('U')
#define	DR_CPU_FORCE_UNCONFIG	('F')
#define	DR_CPU_STATUS		('S')

#define	DR_CPU_OK		('o')
#define	DR_CPU_ERROR		('e')

/*
 * Response Message
 */
typedef struct {
	uint32_t	cpuid;		/* virtual CPU ID */
	uint32_t	result;		/* result of the operation */
	uint32_t	status;		/* status of the CPU */
	uint32_t	string_off;	/* informational string offset */
} dr_cpu_stat_t;

/*
 * Result Codes
 */
#define	DR_CPU_RES_OK			0x0	/* operation succeeded */
#define	DR_CPU_RES_FAILURE		0x1	/* operation failed */
#define	DR_CPU_RES_BLOCKED		0x2	/* operation was blocked */
#define	DR_CPU_RES_CPU_NOT_RESPONDING	0x3	/* CPU was not responding */
#define	DR_CPU_RES_NOT_IN_MD		0x4	/* CPU not defined in MD */

/*
 * Status Codes
 */
#define	DR_CPU_STAT_NOT_PRESENT		0x0	/* CPU ID not in MD */
#define	DR_CPU_STAT_UNCONFIGURED	0x1	/* CPU unconfigured */
#define	DR_CPU_STAT_CONFIGURED		0x2	/* CPU configured */

/*
 * Macros to access arrays that follow message header
 */
#define	DR_CPU_CMD_CPUIDS(_hdr)		((uint32_t *)((_hdr) + 1))
#define	DR_CPU_RESP_STATS(_hdr)		((dr_cpu_stat_t *)((_hdr) + 1))

#ifdef __cplusplus
}
#endif

#endif /* _DR_CPU_H */
