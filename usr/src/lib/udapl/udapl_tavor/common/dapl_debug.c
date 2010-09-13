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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dapl_debug.h"
#include "dapl.h"
#include <stdarg.h>
#include <stdlib.h>

#ifdef DAPL_DBG
DAPL_DBG_TYPE g_dapl_dbg_type;		/* initialized in dapl_init.c */
DAPL_DBG_DEST g_dapl_dbg_dest;		/* initialized in dapl_init.c */

void
dapl_internal_dbg_log(DAPL_DBG_TYPE type, const char *fmt, ...)
{
	va_list		args;

	if (type & g_dapl_dbg_type) {
		va_start(args, fmt);

		if (DAPL_DBG_DEST_STDOUT & g_dapl_dbg_dest) {
			(void) dapl_os_vprintf(fmt, args);
		}

		if (DAPL_DBG_DEST_SYSLOG & g_dapl_dbg_dest) {
			dapl_os_syslog(fmt, args);
		}
		va_end(args);
	}
}
#endif
