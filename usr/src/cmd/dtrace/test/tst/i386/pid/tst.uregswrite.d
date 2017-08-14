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
 * Copyright 2017 Joyent, Inc.
 */


#pragma D option quiet
#pragma D option destructive

pid$1:a.out:startup_wait:entry
{
	this->val = (int *)alloca(sizeof (int));
	*this->val = 0;
	copyout(this->val, arg0, sizeof (int));
}

pid$1:a.out:baz:return
{
	uregs[R_EAX] = 1;
}

pid$1:a.out:bar:return
/(uregs[R_EAX] % 2) != 0/
{
	uregs[R_EAX] += 1;
}

syscall::rexit:entry
/pid == $1/
{
	exit(arg0);
}
