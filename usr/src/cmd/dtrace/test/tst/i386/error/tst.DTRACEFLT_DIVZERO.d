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
 * Copyright (c) 2016, Joyent, Inc. All rights reserved.
 */

BEGIN
{
	v = 0x8000000000000000LL;
	print((long)v % -1);
}

ERROR
/arg4 == DTRACEFLT_DIVZERO/
{
	exit(0);
}

ERROR
{
	printf("unexpected error code %d", arg4);
	exit(1);
}

BEGIN
{
	printf("did not get expected error");
	exit(1);
}
