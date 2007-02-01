/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_debug.c							*
 *									*
 * Abstract:								*
 *									*
 *   This driver runs on the following hardware:			*
 *   - Wiseman based PCI gigabit ethernet adapters			*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */
#ifdef GCC
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#define	_SYS_VARARGS_H
#endif

#include "e1000g_sw.h"
#include "e1000g_debug.h"

void
e1000g_log(struct e1000g *Adapter, int level, char *fmt, ...)
{
	auto char name[NAMELEN];
	auto char buf[BUFSZ];
	va_list ap;

	if (Adapter != NULL) {
		(void) sprintf(name, "%s - e1000g[%d] ",
		    ddi_get_name(Adapter->dip), ddi_get_instance(Adapter->dip));
	} else {
		(void) sprintf(name, "e1000g");
	}
#ifdef GCC
	/*
	 * va_start uses built in macro __builtin_va_alist from the
	 * compiler libs which requires compiler system to have
	 * __BUILTIN_VA_ARG_INCR defined.
	 */
	/*
	 * Many compilation systems depend upon the use of special functions
	 * built into the the compilation system to handle variable argument
	 * lists and stack allocations.  The method to obtain this in SunOS
	 * is to define the feature test macro "__BUILTIN_VA_ARG_INCR" which
	 * enables the following special built-in functions:
	 *	__builtin_alloca
	 *	__builtin_va_alist
	 *	__builtin_va_arg_incr
	 * It is intended that the compilation system define this feature test
	 * macro, not the user of the system.
	 *
	 * The tests on the processor type are to provide a transitional period
	 * for existing compilation systems, and may be removed in a future
	 * release.
	 */
	/*
	 * Using GNU gcc compiler it doesn't expand to va_start....
	 */
	va_start(ap, fmt);
#else
	va_start(ap, fmt);
#endif	/* GCC */
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	switch (level) {
	case CE_CONT:
	case CE_NOTE:
	case CE_WARN:
	case CE_PANIC:
		if (e1000g_display_only == 1 && e1000g_print_only == 1) {
			cmn_err(level, "%s: %s", name, buf);
			break;
		}
		if (e1000g_display_only == 1) {
			cmn_err(level, "^%s: %s", name, buf);
			break;
		}
		if (e1000g_print_only == 1) {
			cmn_err(level, "!%s: %s", name, buf);
			break;
		}
		/*
		 * if they are not set properly then do both
		 */
		cmn_err(level, "%s: %s", name, buf);
		break;

#ifdef e1000g_DEBUG
	case e1000g_DDI_LEVEL:	/* 256 or 0x100 */
		if (e1000g_debug != e1000g_DDI_LEVEL)
			break;

	case e1000g_INT_LEVEL:	/* 128 or 0x080 */
		if ((e1000g_debug != e1000g_INT_LEVEL) &&
		    (e1000g_debug < e1000g_INT_LEVEL))
			break;

	case e1000g_SEND_LEVEL:	/* 64 or 0x040 */
		if ((e1000g_debug != e1000g_SEND_LEVEL) &&
		    (e1000g_debug < e1000g_SEND_LEVEL))
			break;

	case e1000g_RECV_LEVEL:	/* 32 or 0x020 */
		if ((e1000g_debug != e1000g_RECV_LEVEL) &&
		    (e1000g_debug < e1000g_RECV_LEVEL))
			break;

	case e1000g_CALLTRACE_LEVEL:	/* 8 or 0x008 */
		if ((e1000g_debug != e1000g_CALLTRACE_LEVEL) &&
		    (e1000g_debug < e1000g_CALLTRACE_LEVEL))
			break;

	case e1000g_INFO_LEVEL:	/* 4 or 0x004 */
		if ((e1000g_debug != e1000g_INFO_LEVEL) &&
		    (e1000g_debug < e1000g_INFO_LEVEL))
			break;

	case e1000g_VERBOSE_LEVEL:	/* 16 or 0x010 */
#endif
	default:
		if (e1000g_display_only == 1 && e1000g_print_only == 1) {
			cmn_err(CE_CONT, "%s:\t%s", name, buf);
			break;
		}

		if (e1000g_display_only == 1) {
			cmn_err(CE_CONT, "^%s:\t%s", name, buf);
			break;
		}

		if (e1000g_print_only == 1) {
			cmn_err(CE_CONT, "!%s:\t%s", name, buf);
			break;
		}

		/*
		 * if they are not set properly then do both
		 */
		cmn_err(CE_CONT, "%s:\t%s", name, buf);
		break;
	}
}

void
e1000g_log_hw(char *msg, void *cptr, int length)
{
	int i = 0, j;
	char buf[BUFSZ];
	char *cp = cptr;

	bzero(buf, BUFSZ);
	for (i = 0; i < length; i++) {
		/*
		 * make sure there is room for longest %x (i.e. 8 for a
		 * negative number) plus space (1) plus zero (1)
		 */
		if ((j = strlen(buf)) >= (BUFSZ - 10)) {
			buf[BUFSZ - 2] = '>';
			buf[BUFSZ - 1] = 0;
			break;
		}

		(void) sprintf(&buf[j], "%x ", cp[i]);
	}
	cmn_err(CE_CONT, "^%s: %s\n", msg, buf);
}
