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

struct callinfo {
	uint64_t ts;      /* timestamp of last syscall entry */
	uint64_t elapsed; /* total elapsed time in nanoseconds */
	uint64_t calls;   /* number of calls made */
	size_t maxbytes;  /* maximum byte count argument */
};

struct callinfo i[string];	/* declare i as an associative array */

syscall::read:entry, syscall::write:entry
/pid == $1/
{
	i[probefunc].ts = timestamp;
	i[probefunc].calls++;
	i[probefunc].maxbytes = arg2 > i[probefunc].maxbytes ?
		arg2 : i[probefunc].maxbytes;
}

syscall::read:return, syscall::write:return
/i[probefunc].ts != 0 && pid == $1/
{
	i[probefunc].elapsed += timestamp - i[probefunc].ts;
}

END
{
	printf("        calls  max bytes  elapsed nsecs\n");
	printf("------  -----  ---------  -------------\n");
	printf("  read  %5d  %9d  %d\n",
	    i["read"].calls, i["read"].maxbytes, i["read"].elapsed);
	printf(" write  %5d  %9d  %d\n",
	    i["write"].calls, i["write"].maxbytes, i["write"].elapsed);
}
