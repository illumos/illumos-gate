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
 * Copyright (c) 1991-1993,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_NEXUSDEBUG_H
#define	_SYS_NEXUSDEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Debugging macros
 *
 * The DPRINTF macro can be used by setting the debug_print_level to the
 * appropriate debugging level.  The debug levels are defined in each source
 * file where this header file is included.  The scoping of debug_info,
 * and debug_print_level is to the file which included the header file.
 * If multiple levels need to be output, the values can be 'ored'
 * together into debug_print_level.  If debug_print_line's bit 1 is set, the
 * line number of the debugging statement is printed out. If it has
 * bit 2 set, the macro will drop into either the debugger or the OBP PROM.
 */

#ifdef  DEBUG
#include <sys/promif.h>

extern void debug_enter(char *);

static int debug_info = 1;
static int debug_print_level = 0;

#define	PRINT_LINE_NUMBER	0x1
#define	ENTER_MON		0x2

#define	_PRINTF prom_printf	/* For logging to the console */

#define	DPRINTF(print_flag, args)			\
	if (debug_print_level & (print_flag) && debug_info & \
	    PRINT_LINE_NUMBER) \
		_PRINTF("%s line %d:\n", __FILE__, __LINE__);	\
	if (debug_print_level & (print_flag)) {	\
		_PRINTF args;				\
	if (debug_info & ENTER_MON)			\
		debug_enter("");				\
	}

#else
#define	DPRINTF(print_flag, args)
#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NEXUSDEBUG_H */
