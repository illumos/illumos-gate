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
 *	Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<string.h>
#include	"_conv.h"
#include	"dl_msg.h"

#define	MODESZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_RTLD_LAZY_SIZE + \
		MSG_RTLD_NOLOAD_SIZE + \
		MSG_RTLD_GLOBAL_SIZE + \
		MSG_RTLD_PARENT_SIZE + \
		MSG_RTLD_GROUP_SIZE + \
		MSG_RTLD_WORLD_SIZE + \
		MSG_RTLD_NODELETE_SIZE + \
		MSG_RTLD_FIRST_SIZE + \
		MSG_RTLD_CONFGEN_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for dlopen() attributes.
 */
const char *
conv_dlmode_str(int mode, int fabricate)
{
	static	char	string[MODESZ] = { '\0' };

	(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

	if (mode & RTLD_NOW)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_NOW));
	else if (fabricate)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_LAZY));

	if (mode & RTLD_NOLOAD)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_NOLOAD));

	if (mode & RTLD_GLOBAL)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_GLOBAL));
	else if (fabricate)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_LOCAL));

	if (mode & RTLD_PARENT)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_PARENT));
	if (mode & RTLD_GROUP)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_GROUP));
	if (mode & RTLD_WORLD)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_WORLD));
	if (mode & RTLD_NODELETE)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_NODELETE));
	if (mode & RTLD_FIRST)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_FIRST));
	if (mode & RTLD_CONFGEN)
		(void) strcat(string, MSG_ORIG(MSG_RTLD_CONFGEN));

	(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

	return ((const char *)string);
}

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_RTLD_REL_RELATIVE_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_EXEC_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_DEPENDS_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_PRELOAD_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_SELF_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_WEAK_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_MEMORY_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_STRIP_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_NOHEAP_SIZE + \
		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_CONFSET_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for dldump() flags.
 * crle(1) uses this routine to generate update information, and in this case
 * we build a "|" separated string.
 */
const char *
conv_dlflag_str(int flags, int separator)
{
	static	char	string[FLAGSZ] = { '\0' };
	int		element = 0;

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	if (separator)
		(void) strcpy(string, MSG_ORIG(MSG_GBL_QUOTE));
	else
		(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

	if ((flags & RTLD_REL_ALL) == RTLD_REL_ALL) {
		(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_ALL));
		element++;
	} else {
		if (flags & RTLD_REL_RELATIVE) {
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_RELATIVE));
			element++;
		}
		if (flags & RTLD_REL_EXEC) {
			if (separator && element++)
				(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_EXEC));
		}
		if (flags & RTLD_REL_DEPENDS) {
			if (separator && element++)
				(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_DEPENDS));
		}
		if (flags & RTLD_REL_PRELOAD) {
			if (separator && element++)
				(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_PRELOAD));
		}
		if (flags & RTLD_REL_SELF) {
			if (separator && element++)
				(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_SELF));
		}
		if (flags & RTLD_REL_WEAK) {
			if (separator && element++)
				(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
			(void) strcat(string, MSG_ORIG(MSG_RTLD_REL_WEAK));
		}
	}

	if (flags & RTLD_MEMORY) {
		if (separator && element++)
			(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
		(void) strcat(string, MSG_ORIG(MSG_RTLD_MEMORY));
	}
	if (flags & RTLD_STRIP) {
		if (separator && element++)
			(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
		(void) strcat(string, MSG_ORIG(MSG_RTLD_STRIP));
	}
	if (flags & RTLD_NOHEAP) {
		if (separator && element++)
			(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
		(void) strcat(string, MSG_ORIG(MSG_RTLD_NOHEAP));
	}
	if (flags & RTLD_CONFSET) {
		if (separator && element++)
			(void) strcat(string, MSG_ORIG(MSG_GBL_SEP));
		(void) strcat(string, MSG_ORIG(MSG_RTLD_CONFSET));
	}

	if (separator)
		(void) strcat(string, MSG_ORIG(MSG_GBL_QUOTE));
	else
		(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

	return ((const char *)string);
}
