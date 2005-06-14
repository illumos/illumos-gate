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

#!/usr/sbin/dtrace -Fs

syscall::open:entry,
syscall::open64:entry
{
	/*
	 * The call to speculation() creates a new speculation.  If this fails,
	 * dtrace(1M) will generate an error message indicating the reason for
	 * the failed speculation(), but subsequent speculative tracing will be
	 * silently discarded.
	 */
	self->spec = speculation();
	speculate(self->spec);

	/*
	 * Because this printf() follows the speculate(), it is being 
	 * speculatively traced; it will only appear in the data buffer if the
	 * speculation is subsequently commited.
	 */
	printf("%s", stringof(copyinstr(arg0)));
}

fbt:::
/self->spec/
{
	/*
	 * A speculate() with no other actions speculates the default action:
	 * tracing the EPID.
	 */
	speculate(self->spec);
}

syscall::open:return,
syscall::open64:return
/self->spec/
{
	/*
	 * To balance the output with the -F option, we want to be sure that
	 * every entry has a matching return.  Because we speculated the
	 * open entry above, we want to also speculate the open return.
	 * This is also a convenient time to trace the errno value.
	 */
	speculate(self->spec);
	trace(errno);
}

syscall::open:return,
syscall::open64:return
/self->spec && errno != 0/
{
	/*
	 * If errno is non-zero, we want to commit the speculation.
	 */
	commit(self->spec);
	self->spec = 0;
}

syscall::open:return,
syscall::open64:return
/self->spec && errno == 0/
{
	/*
	 * If errno is not set, we discard the speculation.
	 */
	discard(self->spec);
	self->spec = 0;
}
