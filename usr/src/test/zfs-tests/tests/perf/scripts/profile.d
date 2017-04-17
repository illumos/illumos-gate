#!/usr/sbin/dtrace -s

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma D option stackframes=100

/*
 * @stacks: The number of times a stack has been recorded
 */

profile-997
/ arg0 /
{
	@stacks[stack()] = count();
}

ERROR
{
    trace(arg1);
    trace(arg2);
    trace(arg3);
    trace(arg4);
    trace(arg5);
}
