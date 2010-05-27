#!/usr/sbin/dtrace -s
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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#pragma D option quiet

udp:::receive
{
	@bytes[args[2]->ip_saddr, args[4]->udp_dport] =
	    sum(args[4]->udp_length);
}

udp:::send
{
	@bytes[args[2]->ip_daddr, args[4]->udp_sport] =
	    sum(args[4]->udp_length);
}

profile:::tick-1sec
{
	printf("\n   %-32s %16s\n", "HOST", "BYTES/s");
	printa("   %-32s %@16d\n", @bytes);
	trunc(@bytes);
}
