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
%/*
% * Copyright (c) 1987, 1991 by Sun Microsystems, Inc.
% */

%/* from spray.x */

#ifdef RPC_HDR
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
#endif

/*
 * Spray a server with packets
 * Useful for testing flakiness of network interfaces
 */

const SPRAYMAX = 8845;	/* max amount can spray */

/*
 * GMT since 0:00, 1 January 1970
 */
struct spraytimeval {
	unsigned int sec;
	unsigned int usec;
};

/*
 * spray statistics
 */
struct spraycumul {
	unsigned int counter;
	spraytimeval clock;
};

/*
 * spray data
 */
typedef opaque sprayarr<SPRAYMAX>;

program SPRAYPROG {
	version SPRAYVERS {
		/*
		 * Just throw away the data and increment the counter
		 * This call never returns, so the client should always 
		 * time it out.
		 */
		void
		SPRAYPROC_SPRAY(sprayarr) = 1;

		/*
		 * Get the value of the counter and elapsed time  since
		 * last CLEAR.
		 */
		spraycumul	
		SPRAYPROC_GET(void) = 2;

		/*
		 * Clear the counter and reset the elapsed time
		 */
		void
		SPRAYPROC_CLEAR(void) = 3;
	} = 1;
} = 100012;
