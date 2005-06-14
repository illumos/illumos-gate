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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the message strings for the data store error
 * return codes.
 */

#include <dhcp_svc_public.h>
#include <locale.h>

/*
 * Note: must be kept in sync with error codes in <dhcp_svc_public.h>
 */
static char *errmsgs[DSVC_NERR] = {
/*  0 DSVC_SUCCESS */		"Success",
/*  1 DSVC_EXISTS */		"Already exists",
/*  2 DSVC_ACCESS */		"Access denied",
/*  3 DSVC_NO_CRED */		"No underlying service credential",
/*  4 DSVC_NOENT */		"Entry does not exist",
/*  5 DSVC_BUSY */		"Busy",
/*  6 DSVC_INVAL */		"Invalid arguments",
/*  7 DSVC_INTERNAL */		"Internal error",
/*  8 DSVC_UNAVAILABLE */	"Underlying service required by "
				"public module is unavailable",
/*  9 DSVC_COLLISION */		"Update collision",
/* 10 DSVC_UNSUPPORTED */	"Operation unsupported",
/* 11 DSVC_NO_MEMORY */		"Virtual memory exhausted",
/* 12 DSVC_NO_RESOURCES */	"Non-memory resources unavailable",
/* 13 DSVC_BAD_RESOURCE */	"Malformed/missing RESOURCE setting",
/* 14 DSVC_BAD_PATH */		"Malformed/missing PATH setting",
/* 15 DSVC_MODULE_VERSION */	"Public module version mismatch",
/* 16 DSVC_MODULE_ERR */	"Error in public module",
/* 17 DSVC_MODULE_LOAD_ERR */	"Error loading public module",
/* 18 DSVC_MODULE_UNLOAD_ERR */	"Error unloading public module",
/* 19 DSVC_MODULE_CFG_ERR */	"Module-specific configuration failed",
/* 20 DSVC_SYNCH_ERR */		"Error in synchronization protocol",
/* 21 DSVC_NO_LOCKMGR */	"Cannot contact lock manager",
/* 22 DSVC_NO_LOCATION */	"Location does not exist",
/* 23 DSVC_BAD_CONVER */	"Malformed/missing CONVER setting",
/* 24 DSVC_NO_TABLE */		"Table does not exist",
/* 25 DSVC_TABLE_EXISTS */	"Table already exists"
};

/*
 * Return the appropriate error message for a given DSVC error.
 */
const char *
dhcpsvc_errmsg(unsigned int index)
{
	if (index >= DSVC_NERR)
		return (dgettext(TEXT_DOMAIN, "<unknown error>"));

	return (dgettext(TEXT_DOMAIN, errmsgs[index]));
}
