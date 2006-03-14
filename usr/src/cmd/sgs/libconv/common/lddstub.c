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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include	<unistd.h>
#include	<strings.h>
#include	<limits.h>
#include	<dlfcn.h>
#include	"_conv.h"
#include	"lddstub_msg.h"

static int
originlddstub(char *buffer, const char *orgfile)
{
	int	len;

	if (dlinfo(RTLD_SELF, RTLD_DI_ORIGIN, (void *)buffer) == -1)
		return (-1);
	if (strlcat(buffer, orgfile, PATH_MAX) >= PATH_MAX)
		return (-1);
	if ((len = resolvepath(buffer, buffer, (PATH_MAX - 1))) == -1)
		return (-1);
	buffer[len] = '\0';
	if (access(buffer, X_OK) == -1)
		return (-1);

	return (1);
}

static char	orgstub[PATH_MAX], orgstub64[PATH_MAX];
static int	orgflag, orgflag64;

/*
 * Determine what lddstub to run.
 */
const char *
conv_lddstub(int class)
{
	const char *stub;

	/*
	 * Establish defaults.
	 */
	if (class == ELFCLASS32)
		stub = MSG_ORIG(MSG_PTH_LDDSTUB);
	else
		stub = MSG_ORIG(MSG_PTH_LDDSTUB_64);

	/*
	 * Provided we're not secure, determine lddstub's location from our
	 * own origin.
	 */
	if (geteuid()) {
		if ((class == ELFCLASS32) && (orgflag != -1)) {
			if (orgflag == 0) {
				if ((orgflag = originlddstub(orgstub,
				    MSG_ORIG(MSG_ORG_LDDSTUB))) == -1)
					return (stub);
			}
			stub = (const char *)orgstub;
		}
		if ((class == ELFCLASS64) && (orgflag64 != -1)) {
			if (orgflag64 == 0) {
				if ((orgflag64 = originlddstub(orgstub64,
				    MSG_ORIG(MSG_ORG_LDDSTUB_64))) == -1)
					return (stub);
			}
			stub = (const char *)orgstub64;
		}
	}
	return (stub);
}
