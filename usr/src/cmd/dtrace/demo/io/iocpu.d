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

sched:::on-cpu
/execname == "soffice.bin"/
{
	self->on = vtimestamp;
}

sched:::off-cpu
/self->on/
{
	@time["<on cpu>"] = sum(vtimestamp - self->on);
	self->on = 0;
}

io:::wait-start
/execname == "soffice.bin"/
{
	self->wait = timestamp;
}

io:::wait-done
/self->wait/
{
	@io[args[2]->fi_name] = sum(timestamp - self->wait);
	@time["<I/O wait>"] = sum(timestamp - self->wait);
	self->wait = 0;
}

END
{
	printf("Time breakdown (milliseconds):\n");
	normalize(@time, 1000000);
	printa("  %-50s %15@d\n", @time);

	printf("\nI/O wait breakdown (milliseconds):\n");
	normalize(@io, 1000000);
	printa("  %-50s %15@d\n", @io);
}
