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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DB21554_DEBUG_H
#define	_SYS_DB21554_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(DEBUG)

/* driver modload functions */
#define	DB_INIT			0x10
#define	DB_FINI			0x11
#define	DB_INFO			0x12
#define	DB_GETINFO		0x13
/* driver initialization functions */
#define	DB_INIT_FUNCS		0x100
#define	DB_ATTACH		0x100
#define	DB_DETACH		0x101

/* driver child initialization functions */
#define	DB_CTLOPS		0x1000
#define	DB_INITCHILD		0x1001
#define	DB_REMOVECHILD		0x1002
#define	DB_INTR_OPS		0x1003

/* child driver services invoked during runtime */
#define	DB_PCI_MAP		0x10000

/* CPR functions */
#define	DB_SAVE_CONF_REGS	0x100000
#define	DB_REST_CONF_REGS	0x100001

/* interrupt function */
#define	DB_INTR			0x1000000

/* application call functions */
#define	DB_OPEN			0x10000000
#define	DB_CLOSE		0x10000001
#define	DB_IOCTL		0x10000002

/* DVMA functions */
#define	DB_DVMA			0x100000000

/* Function types, to be assigned to db_debug_funcs variable below. */
#define	DB_MODLOAD_FUNCS	0x10
#define	DB_CHILD_FUNCS		0x1000
#define	DB_PCI_MEM_FUNCS	0x10000
#define	DB_CPR_FUNCS		0x100000
#define	DB_INTR_FUNCS		0x1000000
#define	DB_APPL_FUNCS		0x10000000
#define	DB_DVMA_FUNCS		0x100000000

/*
 * db_debug_funcs indicates the function types from which the debug messages
 * are to be displayed.
 * For example: Set db_debug_funcs = DB_CHILD_FUNCS | DB_PCI_MEM_FUNCS;
 * to display debug statements in memory map function (DB_PCI_MEM_FUNCS) and
 * child driver initialization function (DB_CHILD_FUNCS).
 *
 * See above for a list of all function types that can be assigned.
 */
static uint64_t	db_debug_funcs = 0;

/*
 * the following flag can be used to the first argument of db_debug
 * when dip information need not be displayed along with the actual
 * function debug message. By default it is always displayed.
 */
#define	DB_DONT_DISPLAY_DIP	0x1000000000000000

#define	DB_DEBUG0(func_id, dip, fmt)	\
	db_debug(func_id, dip, fmt, 0, 0, 0, 0, 0);
#define	DB_DEBUG1(func_id, dip, fmt, a1)	\
	db_debug(func_id, dip, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DB_DEBUG2(func_id, dip, fmt, a1, a2)	\
	db_debug(func_id, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DB_DEBUG3(func_id, dip, fmt, a1, a2, a3)	\
	db_debug(func_id, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#define	DB_DEBUG4(func_id, dip, fmt, a1, a2, a3, a4)	\
	db_debug(func_id, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), \
		(uintptr_t)(a4), 0);
#define	DB_DEBUG5(func_id, dip, fmt, a1, a2, a3, a4, a5)	\
	db_debug(func_id, dip, fmt, (uintptr_t)(a1),	\
		(uintptr_t)(a2), (uintptr_t)(a3), \
		(uintptr_t)(a4), (uintptr_t)(a5));

#else

#define	DB_DEBUG0(func_id, dip, fmt)
#define	DB_DEBUG1(func_id, dip, fmt, a1)
#define	DB_DEBUG2(func_id, dip, fmt, a1, a2)
#define	DB_DEBUG3(func_id, dip, fmt, a1, a2, a3)
#define	DB_DEBUG4(func_id, dip, fmt, a1, a2, a3, a4)
#define	DB_DEBUG5(func_id, dip, fmt, a1, a2, a3, a4, a5)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DB21554_DEBUG_H */
