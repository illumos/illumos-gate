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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains NISPLUS-specific routines in support of the exported
 * interfaces.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libinetutil.h>
#include "nisplus_impl.h"
#include <string.h>

/*
 * Convert the nisplus form of a dhcp network container name to dotted ascii
 * internet form.
 *
 * Returns 0 for success, nonzero otherwise.
 */
int
dn_to_ip(const char *container_name, char *bufp, int len)
{
	const char	*op;
	char 		*tp;
	struct in_addr	ip;

	if (len < INET_ADDRSTRLEN)
		return (-1);

	for (op = &container_name[sizeof (TMPLT_PFX) - 1], tp = bufp;
	    *op != '\0'; op++, tp++) {
		if (*op == '_')
			*tp = '.';
		else
			*tp = *op;
	}
	return (inet_pton(AF_INET, (const char *)bufp, (void *)&ip) == 0);
}

/*
 * Convert the ascii dotted internet form of a network to the nisplus
 * dhcp network container name.
 *
 * Returns 0 for success, nonzero otherwise.
 */
int
ip_to_dn(const char *ip_name, char *bufp, int len)
{
	char	*tp;

	if (len < sizeof (TMPLT_DN))
		return (-1);

	(void) snprintf(bufp, len, TMPLT_PFX "%s", ip_name);

	for (tp = &bufp[sizeof (TMPLT_PFX)]; *tp != '\0'; tp++) {
		if (*tp == '.')
			*tp = '_';
	}
	return (0);
}
