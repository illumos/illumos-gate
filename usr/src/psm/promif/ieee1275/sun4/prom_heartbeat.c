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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * Provide 10 millisecond heartbeat for the PROM. A client that has taken over
 * the trap table and clock interrupts, but is not quite ready to take over the
 * function of polling the input-device for an abort sequence (L1/A or BREAK)
 * may use this function to instruct the PROM to poll the keyboard. If used,
 * this function should be called every 10 milliseconds.
 */
int
prom_heartbeat(int msecs)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("SUNW,heartbeat");	/* Service name */
	ci[1] = (cell_t)1;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_int2cell(msecs);			/* Arg1: msecs */
	ci[4] = (cell_t)0;				/* Prime the result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[4]));			/* Res1: abort-flag */
}
