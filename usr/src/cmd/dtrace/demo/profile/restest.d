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

profile-5000
{
	/*
	 * We divide by 1,000,000 to convert nanoseconds to milliseconds, and
	 * then we take the value mod 10 to get the current millisecond within
	 * a 10 millisecond window.  On platforms that do not support truly
	 * arbitrary resolution profile probes, all of the profile-5000 probes
	 * will fire on roughly the same millisecond.  On platforms that
	 * support a truly arbitrary resolution, the probe firings will be
	 * evenly distributed across the milliseconds.
	 */
	@ms = lquantize((timestamp / 1000000) % 10, 0, 10, 1);
}

tick-1sec
/i++ >= 10/
{
	exit(0);
}
