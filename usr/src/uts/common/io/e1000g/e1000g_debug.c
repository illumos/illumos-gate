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
 * 	e1000g_debug.c							*
 *									*
 * Abstract:								*
 *	This module includes the debug routines				*
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

#include "e1000g_debug.h"
#include "e1000g_sw.h"

#ifdef E1000G_DEBUG
int e1000g_debug = E1000G_WARN_LEVEL;
#endif
int e1000g_log_mode = E1000G_LOG_PRINT;

void
e1000g_log(void *instance, int level, char *fmt, ...)
{
	struct e1000g *Adapter = (struct e1000g *)instance;
	auto char name[NAMELEN];
	auto char buf[BUFSZ];
	va_list ap;

	switch (level) {
#ifdef E1000G_DEBUG
	case E1000G_VERBOSE_LEVEL:	/* 16 or 0x010 */
		if (e1000g_debug < E1000G_VERBOSE_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_TRACE_LEVEL:	/* 8 or 0x008 */
		if (e1000g_debug < E1000G_TRACE_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_INFO_LEVEL:		/* 4 or 0x004 */
		if (e1000g_debug < E1000G_INFO_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_WARN_LEVEL:		/* 2 or 0x002 */
		if (e1000g_debug < E1000G_WARN_LEVEL)
			return;
		level = CE_CONT;
		break;

	case E1000G_ERRS_LEVEL:		/* 1 or 0x001 */
		level = CE_CONT;
		break;
#else
	case CE_CONT:
	case CE_NOTE:
	case CE_WARN:
	case CE_PANIC:
		break;
#endif
	default:
		level = CE_CONT;
		break;
	}

	if (Adapter != NULL) {
		(void) sprintf(name, "%s - e1000g[%d] ",
		    ddi_get_name(Adapter->dip), ddi_get_instance(Adapter->dip));
	} else {
		(void) sprintf(name, "e1000g");
	}
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
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	if ((e1000g_log_mode & E1000G_LOG_ALL) == E1000G_LOG_ALL)
		cmn_err(level, "%s: %s", name, buf);
	else if (e1000g_log_mode & E1000G_LOG_DISPLAY)
		cmn_err(level, "^%s: %s", name, buf);
	else if (e1000g_log_mode & E1000G_LOG_PRINT)
		cmn_err(level, "!%s: %s", name, buf);
	else /* if they are not set properly then do both */
		cmn_err(level, "%s: %s", name, buf);
}
