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

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * Return a character string in buf,buflen representing the running
 * version of the firmware. Systems that have no concept of such a
 * string may return the string "unknown".
 *
 * Return the actual length of the string, including the NULL terminator.
 * Copy at most buflen bytes into the caller's buffer, always providing
 * NULL termination.
 *
 * Returns the actual length of the string, plus copies data in the callers
 * buf copying at most buflen bytes.  Returns -1 if an internal error occurs.
 */

int
prom_version_name(char *buf, int buflen)
{
	pnode_t nodeid;
	int proplen;
	char *unknown = "unknown";

	*buf = *(buf + buflen - 1) = (char)0;	/* Force NULL termination */

	/*
	 * On sun4u systems, the /openprom "version" property
	 * contains the running version of the prom. Some older
	 * pre-FCS proms may not have the "version" property, so
	 * in that case we just return "unknown".
	 */

	nodeid = prom_finddevice("/openprom");
	if (nodeid == (pnode_t)-1)
		return (-1);

	proplen = prom_bounded_getprop(nodeid, "version", buf, buflen - 1);
	if (proplen <= 0) {
		(void) prom_strncpy(buf, unknown, buflen - 1);
		return (prom_strlen(unknown) + 1);
	}

	return (proplen);
}
