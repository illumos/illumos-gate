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

sched:::off-cpu
/curlwpsinfo->pr_state == SSLEEP/
{
	/*
	 * We're sleeping.  Track our sobj type.
	 */
	self->sobj = curlwpsinfo->pr_stype;
	self->bedtime = timestamp;
}

sched:::off-cpu
/curlwpsinfo->pr_state == SRUN/
{
	self->bedtime = timestamp;
}

sched:::on-cpu
/self->bedtime && !self->sobj/
{
	@["preempted"] = quantize(timestamp - self->bedtime);
	self->bedtime = 0;
}

sched:::on-cpu
/self->sobj/
{
	@[self->sobj == SOBJ_MUTEX ? "kernel-level lock" :
	    self->sobj == SOBJ_RWLOCK ? "rwlock" :
	    self->sobj == SOBJ_CV ? "condition variable" :
	    self->sobj == SOBJ_SEMA ? "semaphore" :
	    self->sobj == SOBJ_USER ? "user-level lock" :
	    self->sobj == SOBJ_USER_PI ? "user-level prio-inheriting lock" :
	    self->sobj == SOBJ_SHUTTLE ? "shuttle" : "unknown"] =
	    quantize(timestamp - self->bedtime);

	self->sobj = 0;
	self->bedtime = 0;
}
