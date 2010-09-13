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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/serengeti.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cheetahregs.h>
#include <sys/cpuvar.h>

/*
 * When an ECC error occurs on an E$ DIMM, the error handling code requests a
 * unum to provide a human-readable physical location to the part that
 * experienced the error.
 *
 * Previously, on Serengeti and LW8, a prom call was made to get this
 * information.  However, calling COBP to do a simple string format is
 * inefficient.  All the necessary information is now kept here.
 *
 * Since this data is now kept in two places (COBP and here), care must be
 * taken so that the two locations are kept the same.  Any changes to the
 * jnumber array will require a change to COBP code so that the two arrays
 * match.  Any changes to the unum string format will require changes in both
 * the COBP code (to match the code here) and plat_ecc_unum.c (to read the
 * new format).  These changes should not be necessary, except to reflect a
 * new cpu or board type.
 */

/*
 * The following array holds the jnumbers for Ecache DIMMs.  The first index
 * is the proc position on the board (0 through 3) and the second index is
 * the DIMM number (0 or 1).
 */
static int sg_j_number[SG_MAX_CMPS_PER_BD][SG_NUM_ECACHE_DIMMS_PER_CPU] = {
	{ 4400, 4300 },
	{ 5400, 5300 },
	{ 6400, 6300 },
	{ 7400, 7300 }
};

/*
 * Generate the unum for the specified cpuid and physical address.  Put the
 * unum in buf, which is of size buflen.  Return the length of the string in
 * lenp.
 *
 * Return 0 if successful, and an error number otherwise.
 */
int
sg_get_ecacheunum(int cpuid, uint64_t physaddr, char *buf, uint_t buflen,
    int *lenp)
{
	int node = SG_PORTID_TO_NODEID(cpuid);
	int board = SG_CPU_BD_PORTID_TO_BD_NUM(cpuid);
	int proc = SG_PORTID_TO_CPU_POSN(cpuid);
	int dimm;

	/*
	 * node and dimm will always be valid.  board and proc may be -1 if
	 * an invalid cpuid is passed in.
	 */
	if ((board == -1) || (proc == -1)) {
		return (EINVAL);
	}

	/* Find the DIMM number (0 or 1) based on the value of physaddr bit 4 */
	if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation) ||
	    IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		dimm = (physaddr & SG_ECACHE_DIMM_MASK) ? 0 : 1;
	else
		dimm = (physaddr & SG_ECACHE_DIMM_MASK) ? 1 : 0;

	*lenp = snprintf(buf, buflen, "/N%d/SB%d/P%d/E%d J%d",
	    node, board, proc, dimm, sg_j_number[proc][dimm]);

	return (0);
}
