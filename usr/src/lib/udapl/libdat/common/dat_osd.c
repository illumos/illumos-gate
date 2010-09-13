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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * MODULE: dat_osd.c
 *
 * PURPOSE: Operating System Dependent layer
 * Description:
 *	Provide OS dependent functions with a canonical DAPL
 *	interface. Designed to be portable and hide OS specific quirks
 *	of common functions.
 *
 * $Id: dat_osd.c,v 1.8 2003/08/15 20:09:52 jlentini Exp $
 */

#include "dat_osd.h"


/*
 *
 * Constants
 *
 */

#define	DAT_DBG_TYPE_ENV 	"DAT_DBG_TYPE"
#define	DAT_DBG_DEST_ENV 	"DAT_DBG_DEST"


/*
 *
 * Enumerations
 *
 */

typedef int 			DAT_OS_DBG_DEST;

typedef enum
{
    DAT_OS_DBG_DEST_STDOUT  		= 0x1,
    DAT_OS_DBG_DEST_SYSLOG  		= 0x2,
    DAT_OS_DBG_DEST_ALL  		= 0x3
} DAT_OS_DBG_DEST_TYPE;


/*
 *
 * Global Variables
 *
 */

static DAT_OS_DBG_TYPE_VAL 	g_dbg_type = 0;
static DAT_OS_DBG_DEST 		g_dbg_dest = DAT_OS_DBG_DEST_STDOUT;


/*
 * Function: dat_os_dbg_init
 */

void
dat_os_dbg_init(void)
{
	char *dbg_type;
	char *dbg_dest;

	if (NULL != (dbg_type = dat_os_getenv(DAT_DBG_TYPE_ENV))) {
		g_dbg_type = dat_os_strtol(dbg_type, NULL, 0);
	}

	if (NULL != (dbg_dest = dat_os_getenv(DAT_DBG_DEST_ENV))) {
		g_dbg_dest = dat_os_strtol(dbg_dest, NULL, 0);
	}
}


/*
 * Function: dat_os_dbg_print
 */

void
dat_os_dbg_print(
	DAT_OS_DBG_TYPE_VAL		type,
	const char			*fmt,
	...)
{
	if ((DAT_OS_DBG_TYPE_ERROR == type) || (type & g_dbg_type)) {
		va_list args;

		va_start(args, fmt);

		if (DAT_OS_DBG_DEST_STDOUT & g_dbg_dest) {
			(void) vfprintf(stdout, fmt, args);
			(void) fflush(stdout);
		}

		if (DAT_OS_DBG_DEST_SYSLOG & g_dbg_dest) {
			vsyslog(LOG_USER | LOG_DEBUG, fmt, args);
		}

		va_end(args);
	}
}


/*
 * Function: dat_os_library_load
 */

DAT_RETURN
dat_os_library_load(
    const char 			*library_path,
    DAT_OS_LIBRARY_HANDLE 	*library_handle_ptr)
{
	DAT_OS_LIBRARY_HANDLE	library_handle;

	if (NULL != (library_handle = dlopen(library_path, RTLD_NOW))) {
		if (NULL != library_handle_ptr) {
			*library_handle_ptr = library_handle;
		}

		return (DAT_SUCCESS);
	} else {
		dat_os_dbg_print(DAT_OS_DBG_TYPE_ERROR,
		    "DAT: library load failure: %s\n",
		    dlerror());
		return (DAT_INTERNAL_ERROR);
	}
}


/*
 * Function: dat_os_library_unload
 */

DAT_RETURN
dat_os_library_unload(
	const DAT_OS_LIBRARY_HANDLE library_handle)
{
	if (0 != dlclose(library_handle)) {
		return (DAT_INTERNAL_ERROR);
	} else {
		return (DAT_SUCCESS);
	}
}
