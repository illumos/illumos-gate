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
 * Copyright 1985 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _sparc_trap_h
#define	_sparc_trap_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Trap type values.
 */
#define TT(X)			((X)<<4)

/*
 * The Coprocessor bit.
 */
#define CP_BIT 0x20

/*
 * Hardware traps.
 */
#define T_RESET			0x00
#define T_TEXT_FAULT		0x01
#define T_UNIMP_INSTR		0x02
#define T_PRIV_INSTR		0x03
#define T_FP_DISABLED		0x04
#define T_CP_DISABLED		(0x4 | CP_BIT)
#define T_WIN_OVERFLOW		0x05
#define T_WIN_UNDERFLOW		0x06
#define T_ALIGNMENT		0x07
#define T_FP_EXCEPTION		0x08
#define T_CP_EXCEPTION		(0x8 | CP_BIT)
#define T_DATA_FAULT		0x09
#define T_TAG_OVERFLOW		0x0A
#define	T_INT			0x10
#define	T_INT_LEVEL		0x0F
#define T_INT_LEVEL_1		0x11
#define T_INT_LEVEL_2		0x12
#define T_INT_LEVEL_3		0x13
#define T_INT_LEVEL_4		0x14
#define T_INT_LEVEL_5		0x15
#define T_INT_LEVEL_6		0x16
#define T_INT_LEVEL_7		0x17
#define T_INT_LEVEL_8		0x18
#define T_INT_LEVEL_9		0x19
#define T_INT_LEVEL_10		0x1A
#define T_INT_LEVEL_11		0x1B
#define T_INT_LEVEL_12		0x1C
#define T_INT_LEVEL_13		0x1D
#define T_INT_LEVEL_14		0x1E
#define T_INT_LEVEL_15		0x1F

/*
 * Software traps (ticc instructions).
 */
#define ST_SYSCALL		0x00
#define ST_BREAKPOINT		0x01
#define ST_DIV0			0x02
#define ST_FLUSH_WINDOWS	0x03
#define ST_CLEAN_WINDOWS	0x04
#define ST_RANGE_CHECK		0x05
#define ST_FIX_ALIGN		0x06
#define ST_INT_OVERFLOW		0x07

#define ST_GETCC		0x20
#define ST_SETCC		0x21
#define ST_MON_BREAKPOINT	0x7F

/*
 * Software trap vectors 16 - 31 are reserved for use by the user
 * and will not be usurped by Sun.
 */

/*
 * Software trap type values.
 */
#define T_SOFTWARE_TRAP		0x80
#define T_ESOFTWARE_TRAP	0xFF
#define T_SYSCALL		(T_SOFTWARE_TRAP + ST_SYSCALL)
#define T_BREAKPOINT		(T_SOFTWARE_TRAP + ST_BREAKPOINT)
#define T_DIV0			(T_SOFTWARE_TRAP + ST_DIV0)
#define T_FLUSH_WINDOWS		(T_SOFTWARE_TRAP + ST_FLUSH_WINDOWS)
#define T_CLEAN_WINDOWS		(T_SOFTWARE_TRAP + ST_CLEAN_WINDOWS)
#define T_RANGE_CHECK		(T_SOFTWARE_TRAP + ST_RANGE_CHECK)
#define T_FIX_ALIGN		(T_SOFTWARE_TRAP + ST_FIX_ALIGN)
#define T_INT_OVERFLOW		(T_SOFTWARE_TRAP + ST_INT_OVERFLOW)

#define T_GETCC			(T_SOFTWARE_TRAP + ST_GETCC)
#define T_SETCC			(T_SOFTWARE_TRAP + ST_SETCC)

/*
 * Pseudo traps.
 */
#define T_INTERRUPT		0x100
#define T_SPURIOUS		(T_INTERRUPT | T_INT)
#define T_FAULT			0x200
#define T_AST			0x400
#define T_ZERO			0x00

#endif /* !_sparc_trap_h */
