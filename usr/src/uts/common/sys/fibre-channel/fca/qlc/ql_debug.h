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

/* Copyright 2009 QLogic Corporation */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_QL_DEBUG_H
#define	_QL_DEBUG_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2009 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Driver debug definitions in makefile.
 *
 * QL_DEBUG_LEVEL_1=0x1
 * QL_DEBUG_LEVEL_2=0x2		Output error msgs.
 * QL_DEBUG_LEVEL_3=0x4		Output function trace msgs.
 * QL_DEBUG_LEVEL_4=0x8		Output NVRAM trace msgs.
 * QL_DEBUG_LEVEL_5=0x10	Output ring trace msgs.
 * QL_DEBUG_LEVEL_6=0x20	Output WATCHDOG timer trace.
 * QL_DEBUG_LEVEL_7=0x40
 * QL_DEBUG_LEVEL_8=0x80	Output ring staturation msgs.
 * QL_DEBUG_LEVEL_9=0x100	Output IOCTL trace.
 * QL_DEBUG_LEVEL_10=0x200
 * QL_DEBUG_LEVEL_11=0x400
 * QL_DEBUG_LEVEL_12=0x1000
 * QL_DEBUG_LEVEL_13=0x2000
 * QL_DEBUG_LEVEL_14=0x4000
 * QL_DEBUG_LEVEL_15=0x8000
 */

void ql_dump_buffer(uint8_t *, uint8_t, uint32_t);
void ql_el_msg(ql_adapter_state_t *, const char *, int, ...);
void ql_dbg_msg(const char *, int, ...);
int ql_flash_errlog(ql_adapter_state_t *, uint16_t, uint16_t, uint16_t,
    uint16_t);
void ql_dump_el_trace_buffer(ql_adapter_state_t *);

#if (QL_DEBUG & 0xffff)
#define	QL_DEBUG_ROUTINES
#define	QL_BANG
#define	QL_QUESTION
#define	QL_CAROT
#else
#define	QL_BANG		"!"
#define	QL_QUESTION	"?"
#define	QL_CAROT	"^"
#endif

/*
 * Macros.
 */
#define	GLOBAL_EL_LOCK()	mutex_enter(&ql_global_el_mutex)
#define	GLOBAL_EL_UNLOCK()	mutex_exit(&ql_global_el_mutex)

#define	TRACE_BUFFER_LOCK(ha)	mutex_enter(&ha->el_trace_desc->mutex)
#define	TRACE_BUFFER_UNLOCK(ha)	mutex_exit(&ha->el_trace_desc->mutex)

#define	EL(ha, ...) 		ql_el_msg(ha, __func__, CE_CONT, __VA_ARGS__);

#define	ER(s)			cmn_err(CE_CONT, QL_BANG "%s", s);
#define	ERV(s, ...)		cmn_err(CE_CONT, QL_BANG s, __VA_ARGS__);

#define	EL_BUFFER_RESERVE	256
#define	DEBUG_STK_DEPTH		24

#if QL_DEBUG & 1
#define	QL_DEBUG_LEVEL_1
#define	QL_PRINT_1(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_1(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_1(...)
#define	QL_DUMP_1(bp, wdsize, count)
#endif

#ifdef QL_DEBUG_ROUTINES
#define	QL_DEBUG_LEVEL_2
#define	QL_PRINT_2(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_2(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_2(...)
#define	QL_DUMP_2(bp, wdsize, count)
#endif

#if QL_DEBUG & 4
#define	QL_DEBUG_LEVEL_3
#define	QL_PRINT_3(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_3(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_3(...)
#define	QL_DUMP_3(bp, wdsize, count)
#endif

#if QL_DEBUG & 8
#define	QL_DEBUG_LEVEL_4
#define	QL_PRINT_4(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_4(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_4(...)
#define	QL_DUMP_4(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x10
#define	QL_DEBUG_LEVEL_5
#define	QL_PRINT_5(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_5(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_5(...)
#define	QL_DUMP_5(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x20
#define	QL_DEBUG_LEVEL_6
#define	QL_PRINT_6(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_6(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_6(...)
#define	QL_DUMP_6(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x40
#define	QL_DEBUG_LEVEL_7
#define	QL_PRINT_7(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_7(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_7(...)
#define	QL_DUMP_7(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x80
#define	QL_DEBUG_LEVEL_8
#define	QL_PRINT_8(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_8(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_8(...)
#define	QL_DUMP_8(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x104
#define	QL_PRINT_9(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_9(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_9(...)
#define	QL_DUMP_9(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x200
#define	QL_DEBUG_LEVEL_10
#define	QL_PRINT_10(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_10(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_10(...)
#define	QL_DUMP_10(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x400
#define	QL_DEBUG_LEVEL_11
#define	QL_PRINT_11(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_11(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_11(...)
#define	QL_DUMP_11(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x800
#define	QL_DEBUG_LEVEL_12
#define	QL_PRINT_12(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_12(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_12(...)
#define	QL_DUMP_12(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x1000
#define	QL_DEBUG_LEVEL_13
#define	QL_PRINT_13(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_13(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_13(...)
#define	QL_DUMP_13(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x2000
#define	QL_DEBUG_LEVEL_14
#define	QL_PRINT_14(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_14(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_14(...)
#define	QL_DUMP_14(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x4000
#define	QL_DEBUG_LEVEL_15
#define	QL_PRINT_15(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_15(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_15(...)
#define	QL_DUMP_15(bp, wdsize, count)
#endif

#if QL_DEBUG & 0x8000
#define	QL_DEBUG_LEVEL_16
#define	QL_PRINT_16(ce, ...)	ql_dbg_msg(__func__, ce, __VA_ARGS__)
#define	QL_DUMP_16(bp, wdsize, count) \
	ql_dump_buffer((uint8_t *)bp, (uint8_t)wdsize, (uint32_t)count)
#else
#define	QL_PRINT_16(...)
#define	QL_DUMP_16(bp, wdsize, count)
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _QL_DEBUG_H */
