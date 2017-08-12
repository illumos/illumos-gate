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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * User-level dtrace for fksmbcl
 * Usage: dtrace -s Watch-fksmbcl.d -p $PID
 */

self int trace;

/*
 * Trace almost everything
 */
pid$target:fksmbcl::entry
{
  self->trace++;
}

pid$target:fksmbcl::return
{
  self->trace--;
}

/*
 * If traced, print entry/return
 */
pid$target:fksmbcl::entry,
pid$target:libsmbfs.so.1::entry,
pid$target:libfksmbfs.so.1::entry,
pid$target:libfknsmb.so.1::entry,
pid$target:libfakekernel.so.1::entry
/self->trace > 0/
{
  printf("\t0x%x", arg0);
  printf("\t0x%x", arg1);
  printf("\t0x%x", arg2);
  printf("\t0x%x", arg3);
  printf("\t0x%x", arg4);
  printf("\t0x%x", arg5);
}

pid$target:fksmbcl::return,
pid$target:libsmbfs.so.1::return,
pid$target:libfksmbfs.so.1::return,
pid$target:libfknsmb.so.1::return,
pid$target:libfakekernel.so.1::entry
/self->trace > 0/
{
  printf("\t0x%x", arg1);
}

pid$target::smbfslookup:entry
{
	printf("\tname = %s\n", copyinstr(arg1));
}

pid$target:libfknsmb.so.1:smb_dtrace2:entry
/copyinstr(arg0) == "debugmsg2"/
{
	this->f = copyinstr(arg1);
	this->m = copyinstr(arg2);
	printf("\n\t debugmsg2: %s: %s ", this->f, this->m);
}

pid$target:libfknsmb.so.1:smb_dtrace3:entry
/copyinstr(arg0) == "debugmsg3"/
{
	this->f = copyinstr(arg1);
	this->m = copyinstr(arg2);
	printf("\n\t debugmsg3: %s: %s ", this->f, this->m);
	trace(arg3);
}
