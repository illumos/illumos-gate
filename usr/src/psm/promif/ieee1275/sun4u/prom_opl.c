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

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This file implements promif routines for OPL-specific OBP client
 * interfaces defined in FWARC/2005/268.
 */

/*
 * prom_opl_get_tod - this function gets time-of-day and stick value from OBP.
 * Please, see "The OPL OBP functional specification" for details.
 */

void
prom_opl_get_tod(time_t *time, int64_t *stickval)
{
	cell_t	ci[5];

	ci[0] = p1275_ptr2cell("FJSV,get-tod");	/* Service name */
	ci[1] = (cell_t)0;			/* #argument cells */
	ci[2] = (cell_t)2;			/* #result cells */
	ci[3] = (cell_t)0;			/* The result: STICK */
	ci[4] = (cell_t)0;			/* The result: time */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	*stickval = ci[3];
	*time = ci[4];
}

/*
 * prom_opl_set_diff - this function updates time difference
 * w.r.t. SP/OBP reference time.
 * Please, see "The OPL OBP functional specification" for details.
 */

void
prom_opl_set_diff(int64_t diff)
{
	cell_t	ci[4];

	ci[0] = p1275_ptr2cell("FJSV,set-domain-time"); /* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	ci[3] = (cell_t)diff;			/* Arg1: time diff */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}

int
prom_attach_notice(int boardnum)
{
	int rv;
	cell_t	ci[5];

	ci[0] = p1275_ptr2cell("FJSV,attach-notice");
	ci[1] = (cell_t)1;
	ci[2] = (cell_t)1;
	ci[3] = (cell_t)boardnum;

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	return ((rv) ? -1 : p1275_cell2int(ci[4]));
}

int
prom_detach_notice(int boardnum)
{
	int rv;
	cell_t	ci[5];

	ci[0] = p1275_ptr2cell("FJSV,detach-notice");
	ci[1] = (cell_t)1;
	ci[2] = (cell_t)1;
	ci[3] = (cell_t)boardnum;

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	return ((rv) ? -1 : p1275_cell2int(ci[4]));
}

int
prom_opl_switch_console(int lsb_id)
{
	cell_t	ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("FJSV,switch-console");	/* name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	/* target tty-port# */
	ci[3] = p1275_int2cell(lsb_id);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0) {
		return (rv);
	}
	return (p1275_cell2int(ci[4]));	/* Res1: Catch result */
}
