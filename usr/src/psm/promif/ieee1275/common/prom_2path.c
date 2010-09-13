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
 * Copyright 1991-1994,1998,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

static int token2path(char *svc, uint_t token, char *buf, uint_t len);

int
prom_ihandle_to_path(ihandle_t instance, char *buf, uint_t len)
{
	return (token2path("instance-to-path", (uint_t)instance, buf, len));
}

int
prom_phandle_to_path(phandle_t package, char *buf, uint_t len)
{
	return (token2path("package-to-path", (uint_t)package, buf, len));
}

static int
token2path(char *service, uint_t token, char *buf, uint_t len)
{
	cell_t ci[7];
	int rv;
#ifdef PROM_32BIT_ADDRS
	char *obuf = NULL;

	if ((uintptr_t)buf > (uint32_t)-1) {
		obuf = buf;
		buf = promplat_alloc(len);
		if (buf == NULL) {
			return (-1);
		}
	}
#endif

	promif_preprom();

	ci[0] = p1275_ptr2cell(service);	/* Service name */
	ci[1] = 3;				/* #argument cells */
	ci[2] = 1;				/* #return cells */
	ci[3] = p1275_uint2cell(token);		/* Arg1: ihandle/phandle */
	ci[4] = p1275_ptr2cell(buf);		/* Arg2: Result buffer */
	ci[5] = p1275_uint2cell(len);		/* Arg3: Buffer len */
	rv = p1275_cif_handler(&ci);

	promif_postprom();

#ifdef PROM_32BIT_ADDRS
	if (obuf != NULL) {
		promplat_bcopy(buf, obuf, len);
		promplat_free(buf, len);
	}
#endif

	if (rv != 0)
		return (-1);
	return (p1275_cell2int(ci[6]));		/* Res1: Actual length */
}
