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

sched:::preempt
{
	self->preempt = 1;
}

sched:::remain-cpu
/self->preempt/
{
	self->preempt = 0;
}

sched:::off-cpu
/self->preempt/
{
	/*
	 * If we were told to preempt ourselves, see who we ended up giving
	 * the CPU to.
	 */
	@[stringof(args[1]->pr_fname), args[0]->pr_pri, execname,
	    curlwpsinfo->pr_pri] = count();
	self->preempt = 0;
}

END
{
	printf("%30s %3s %30s %3s %5s\n", "PREEMPTOR", "PRI",
	    "PREEMPTED", "PRI", "#");
	printa("%30s %3d %30s %3d %5@d\n", @);
}
