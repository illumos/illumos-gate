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
 * This file contains implementation functions internal to the nisplus0
 * module.
 */

#include <stdlib.h>
#include "nisplus_impl.h"
#include <string.h>
#include <ctype.h>

/*
 * Validates the nisplus form of a dhcp network table: YYY_YYY_YYY_YYY,
 * where YYY is a integer from 0-255. Returns TRUE for success, false
 * otherwise.
 */
boolean_t
dsvcnis_valid_ip(const char *container)
{
	int	i = 0, t, count = 0;
	char	*tp, *wp, *sp = NULL;

	if ((tp = strdup(container)) == NULL)
		return (B_FALSE); /* no memory */

	for (wp = strtok_r(tp, "_", &sp), i = 0; wp != NULL && i < 4;
	    wp = strtok_r(sp, "_", &sp), i++) {
		if (isdigit(*wp) && (t = atoi(wp)) >= 0 && t < 256)
			count++;
	}
	free(tp);
	return (count == 4);
}

/*
 * Convert the nisplus form of a dhcp network table name from one form
 * to another. See macros in nisplus_impl.h. No validation is done...
 */
char *
dsvcnis_convert_form(char *network, char from, char to)
{
	char	*tp;

	for (tp = network; *tp != '\0'; tp++) {
		if (*tp == from)
			*tp = to;
	}
	return (network);
}
