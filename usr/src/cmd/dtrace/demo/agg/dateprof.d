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

syscall::exec:return,
syscall::exece:return
/execname == "date"/
{
	self->start = vtimestamp;
}

syscall:::entry
/self->start/
{
	/*
	 * We linearly quantize on the current virtual time minus our
	 * process's start time.  We divide by 1000 to yield microseconds
	 * rather than nanoseconds.  The range runs from 0 to 10 milliseconds
	 * in steps of 100 microseconds; we expect that no date(1) process
	 * will take longer than 10 milliseconds to complete.
	 */
	@["system calls over time"] =
	    lquantize((vtimestamp - self->start) / 1000, 0, 10000, 100);
}

syscall::rexit:entry
/self->start/
{
	self->start = 0;
}
