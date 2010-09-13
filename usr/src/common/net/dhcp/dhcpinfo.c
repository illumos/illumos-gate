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

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include "dhcp_impl.h"

/*
 * Fetch a copy of the DHCP-supplied value of the parameter requested
 * by code in value, and the parameter value length in *vallenp.
 *
 * Return values:
 *
 *      B_FALSE         If invalid code, or no parameter value.
 *
 *      B_TRUE          Valid code which has a parameter value.
 *                      *vallenp is set to the parameter value length.
 *                      If the parameter value length is less than or
 *                      equal to *vallenp, value is set to the parameter
 *                      value.
 */

boolean_t
dhcp_getinfo_pl(PKT_LIST *pl, uchar_t optcat, uint16_t code, uint16_t optsize,
    void *value, size_t *vallenp)
{

	if (pl == NULL)
		return (B_FALSE);

	if (optcat == DSYM_STANDARD) {
		if (code > DHCP_LAST_OPT)
			return (B_FALSE);

		if (pl->opts[code] == NULL)
			return (B_FALSE);

		if (*vallenp < pl->opts[code]->len) {
			*vallenp = pl->opts[code]->len;
			return (B_TRUE);
		}

		bcopy(pl->opts[code]->value, value, pl->opts[code]->len);
		*vallenp = pl->opts[code]->len;

	} else if (optcat == DSYM_VENDOR) {
		if (code > VS_OPTION_END)
			return (B_FALSE);

		if (pl->vs[code] == NULL)
			return (B_FALSE);

		if (*vallenp < pl->vs[code]->len) {
			*vallenp = pl->vs[code]->len;
			return (B_TRUE);
		}

		bcopy(pl->vs[code]->value, value, pl->vs[code]->len);
		*vallenp = pl->vs[code]->len;

	} else if (optcat == DSYM_FIELD) {
		if (code + optsize > sizeof (PKT))
			return (B_FALSE);

		if (*vallenp < optsize) {
			*vallenp = optsize;
			return (B_TRUE);
		}

		*vallenp = optsize;
		bcopy((caddr_t)pl->pkt + code, value, optsize);

	} else
		return (B_FALSE);

	return (B_TRUE);
}
