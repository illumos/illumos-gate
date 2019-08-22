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
 *
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <deflt.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <compat.h>

#define	DEFAULT_IP_LINE		DEFAULT_IP"="

/*
 * Code to handle /etc/default/ file for IPv4 command output compatibility
 *
 * Note: Handles BOTH the same as IP_VERSION6.
 *
 * Returns 1 if IP_VERSION4; 0 for other versions.
 * Returns -1 if the value of DEFAULT_IP found in /etc/default/inet_type is
 * invalid.
 */
int
get_compat_flag(char **value)
{
	if (defopen(INET_DEFAULT_FILE) == 0) {
		char	*cp;
		int	flags;

		/*
		 * ignore case
		 */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if ((cp = defread(DEFAULT_IP_LINE)) != NULL)
			*value = strdup(cp);

		/* close */
		(void) defopen((char *)NULL);

		if (*value != NULL) {
			if (strcasecmp(*value, "IP_VERSION4") == 0) {
				return (DEFAULT_PROT_V4_ONLY);
			} else if (strcasecmp(*value, "BOTH") == 0 ||
			    strcasecmp(*value, "IP_VERSION6") == 0) {
				return (DEFAULT_PROT_BOTH);
			} else {
				return (DEFAULT_PROT_BAD_VALUE);
			}
		}
	}
	/* No value set */
	return (DEFAULT_PROT_BOTH);
}
