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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <svm.h>

/*
 * FUNCTION: get modid
 *	Given a module name returns module id.
 *
 * INPUT: module name
 *
 * RETURN VALUES:
 *		> 0 SUCCESS
 *              -1 FAIL
 */

static int
get_modid(char *modname)
{
	struct modinfo modinfo;
	int id;
	int rval = RET_ERROR;

	id = -1; /* look for all modules */

	modinfo.mi_id = modinfo.mi_nextid = id;
	modinfo.mi_info = MI_INFO_ALL | MI_INFO_NOBASE;

	do {
		if (modctl(MODINFO, id, &modinfo) < 0)
			break;

		modinfo.mi_name[MODMAXNAMELEN - 1] = '\0';
		/* if we find a match break out */
		if (strcmp(modinfo.mi_name, modname) == 0) {
			rval = modinfo.mi_id;
			break;
		}
	/* LINTED */
	} while (1);

	return (rval);
}

/*
 * FUNCTION: mod_unload
 *	unload a module.
 *
 * INPUT: module name
 *
 * RETURN VALUES:
 *	0 - SUCCESS
 *	!0 - FAIL
 *		> 0 errno
 *		-1
 * NOTE: If we fail to get the module id because the module is not
 * currently loaded we still want to try to force a reload of the
 * .conf file when it does load.
 */
int
mod_unload(char *modname)
{
	int id;
	major_t major;
	int	rval = RET_SUCCESS;

	id = get_modid(modname);

	if (id != -1) {
		if (modctl(MODUNLOAD, id) < 0) {
			rval = errno;
		}
	}

	if ((modctl(MODGETMAJBIND, modname, strlen(modname) + 1,
	    &major)) != 0) {
		return (errno);
	}

	if ((modctl(MODUNLOADDRVCONF, major) != 0) ||
	    (modctl(MODLOADDRVCONF, major) != 0)) {
		return (errno);
	}

	return (rval);
}
