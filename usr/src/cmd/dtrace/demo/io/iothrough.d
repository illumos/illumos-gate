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

#pragma D option quiet

io:::start
{
	start[args[0]->b_edev, args[0]->b_blkno] = timestamp;
}

io:::done
/start[args[0]->b_edev, args[0]->b_blkno]/
{
	/*
	 * We want to get an idea of our throughput to this device in KB/sec.
	 * What we have, however, is nanoseconds and bytes.  That is we want
	 * to calculate:
	 *
	 *                        bytes / 1024
	 *                  ------------------------
	 *                  nanoseconds / 1000000000
	 *
	 * But we can't calculate this using integer arithmetic without losing
	 * precision (the denomenator, for one, is between 0 and 1 for nearly
	 * all I/Os).  So we restate the fraction, and cancel:
	 * 
	 *     bytes      1000000000         bytes        976562
	 *   --------- * -------------  =  --------- * -------------  
	 *      1024      nanoseconds          1        nanoseconds
	 *
	 * This is easy to calculate using integer arithmetic; this is what
	 * we do below.
	 */
	this->elapsed = timestamp - start[args[0]->b_edev, args[0]->b_blkno];
	@[args[1]->dev_statname, args[1]->dev_pathname] =
	    quantize((args[0]->b_bcount * 976562) / this->elapsed);
	start[args[0]->b_edev, args[0]->b_blkno] = 0;
}

END
{
	printa("  %s (%s)\n%@d\n", @);
}
