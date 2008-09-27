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

#ifndef	_SYS_TRAP_H
#define	_SYS_TRAP_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This file is machine specific as is.
 * Some trap types could be made common
 * for all sparcs, but that is a project
 * in and of itself.
 */

/*
 * Software traps (ticc instructions).
 */
#define	ST_OSYSCALL		0x00
#define	ST_BREAKPOINT		0x01
#define	ST_DIV0			0x02
#define	ST_FLUSH_WINDOWS	0x03
#define	ST_CLEAN_WINDOWS	0x04
#define	ST_RANGE_CHECK		0x05
#define	ST_FIX_ALIGN		0x06
#define	ST_INT_OVERFLOW		0x07
#define	ST_SYSCALL		0x08
#define	ST_TRANSACTION_FAILURE	0x0F

/*
 * Software trap vectors 16 - 31 are reserved for use by the user
 * and will not be usurped by Sun.
 */

#define	ST_GETCC		0x20
#define	ST_SETCC		0x21
#define	ST_GETPSR		0x22
#define	ST_SETPSR		0x23
#define	ST_GETHRTIME		0x24
#define	ST_GETHRVTIME		0x25
#define	ST_SELFXCALL		0x26
#define	ST_GETHRESTIME		0x27
#define	ST_SETV9STACK		0x28
#define	ST_GETLGRP		0x29

/*
 * DTrace traps used for user-land tracing.
 */
#define	ST_DTRACE_PID		0x38
#define	ST_DTRACE_PROBE		0x39
#define	ST_DTRACE_RETURN	0x3a

#define	ST_KMDB_TRAP		0x7d
#define	ST_KMDB_BREAKPOINT	0x7e
#define	ST_MON_BREAKPOINT	0x7f

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAP_H */
