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
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_FTRACE_H
#define	_SYS_FTRACE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Constants used by both asm and non-asm code.
 */

/*
 * Flags determining the state of tracing -
 *   both for the "ftrace_state" variable, and for the per-CPU variable
 *   "cpu[N]->cpu_ftrace_state".
 */
#define	FTRACE_READY	0x00000001
#define	FTRACE_ENABLED	0x00000002

#include <sys/types.h>
#include <sys/sdt.h>

/*
 * The record of a single event.
 * ftrace_record_t;
 */

#define	FTRACE_0(fmt)						\
	DTRACE_PROBE1(ftrace0, char *, fmt)
#define	FTRACE_1(fmt, d1) 					\
	DTRACE_PROBE2(ftrace1, char *, fmt, uintptr_t, d1)

// #define	FTRACE_START()	ftrace_start()
// #define	FTRACE_STOP()	ftrace_stop()

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FTRACE_H */
