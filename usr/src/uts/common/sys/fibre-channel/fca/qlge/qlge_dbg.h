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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#ifndef _QLGE_DBG_H
#define	_QLGE_DBG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Driver debug definitions in makefile.
 */

#define	QL_DEBUG_LEVELS 0x2

#define	DBG_NVRAM	0x01	/* Registers, PCI */
#define	DBG_INIT 	0x02
#define	DBG_GLD 	0x04
#define	DBG_MBX		0x08
#define	DBG_FLASH	0x08
#define	DBG_RX 		0x10
#define	DBG_RX_RING	0x20
#define	DBG_TX 		0x40
#define	DBG_STATS 	0x80
#define	DBG_INTR	0x100

#ifdef QL_DUMPFW
#define	QLA_CORE_DUMP(qlge)		ql_core_dump(qlge);
#define	QLA_DUMP_CRASH_RECORD(qlge)	ql_dump_crash_record(qlge)
#else
#define	QLA_CORE_DUMP(qlge)
#define	QLA_DUMP_CRASH_RECORD(qlge)
#endif

#if QL_DEBUG

#define	QL_DUMP_BUFFER(a, b, c, d) \
	ql_dump_buf((char *)a, (uint8_t *)b, (uint8_t)c, (uint32_t)d)

#define	QL_PRINT_1(x)		ql_printf x

#define	QL_PRINT(dbg_level, x) \
		if (qlge->ql_dbgprnt & dbg_level) ql_printf x
#define	QL_DUMP(dbg_level, a, b, c, d)	\
		if (qlge->ql_dbgprnt & dbg_level) QL_DUMP_BUFFER(a, b, c, d)

#define	QL_DUMP_REQ_PKT(qlge, pkt, oal, num)	if (qlge->ql_dbgprnt & DBG_TX) \
					ql_dump_req_pkt(qlge, pkt, oal, num)

#define	QL_DUMP_CQICB(qlge, cqicb) if (qlge->ql_dbgprnt & DBG_INIT) \
					ql_dump_cqicb(qlge, cqicb)

#define	QL_DUMP_WQICB(qlge, wqicb) if (qlge->ql_dbgprnt & DBG_INIT) \
					ql_dump_wqicb(qlge, wqicb)

#else

#define	QLA_HOST_PCI_REGS(qlge)

#define	QL_DUMP_BUFFER(a, b, c, d)
#define	QL_DUMP(dbg_level, a, b, c, d)
#define	QL_DEBUG_PRINT(x)
#define	QL_PRINT(dbg_level, x)
#define	QL_DUMP_REQ_PKT(qlge, pkt, oal, num)
#define	QL_DUMP_CQICB
#define	QL_DUMP_WQICB

#endif	/* QLGE_DEBUG */

/*
 * Error and Extended Logging Macros.
 */
#define	QL_BANG		"!"
#define	QL_QUESTION	"?"
#define	QL_CAROT	"^"

#ifdef __cplusplus
}
#endif

#endif /* _QLGE_DBG_H */
