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

dtrace:::BEGIN
{
	start = timestamp;
}

sched:::on-cpu
/execname == $$1/
{
	self->ts = timestamp;
}

sched:::off-cpu
/self->ts/
{
	@[cpu] = sum(timestamp - self->ts);
	self->ts = 0;
}

profile:::tick-1sec
/++x == 10/
{
	exit(0);
}
        
dtrace:::END
{
	printf("CPU distribution over %d seconds:\n\n",
	    (timestamp - start) / 1000000000);
	printf("CPU microseconds\n--- ------------\n");
	normalize(@, 1000);
	printa("%3d %@d\n", @);
}
