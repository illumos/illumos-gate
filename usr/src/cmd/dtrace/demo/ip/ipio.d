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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	printf(" %3s %10s %15s    %15s %8s %6s\n", "CPU", "DELTA(us)",
	    "SOURCE", "DEST", "INT", "BYTES");
	last = timestamp;
}

ip:::send
{
	this->elapsed = (timestamp - last) / 1000;
	printf(" %3d %10d %15s -> %15s %8s %6d\n", cpu, this->elapsed,
	    args[2]->ip_saddr, args[2]->ip_daddr, args[3]->if_name,
	    args[2]->ip_plength);
	last = timestamp;
}

ip:::receive
{
	this->elapsed = (timestamp - last) / 1000;
	printf(" %3d %10d %15s <- %15s %8s %6d\n", cpu, this->elapsed,
	    args[2]->ip_daddr, args[2]->ip_saddr, args[3]->if_name,
	    args[2]->ip_plength);
	last = timestamp;
}
