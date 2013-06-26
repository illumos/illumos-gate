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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>

/*
 * See: DTRACE_PROBE... in smb_kproto.h
 */

int fksmbd_dtrace_log = 0;

void
smb_dtrace1(const char *f, const char *n,
	    const char *t1, long v1)
{
	if (fksmbd_dtrace_log) {
		cmn_err(CE_CONT, "dtrace1:%s:%s,"
		    " (%s) 0x%lx\n",
		    f, n, t1, v1);
	}
}

void
smb_dtrace2(const char *f, const char *n,
	    const char *t1, long v1,
	    const char *t2, long v2)
{
	if (fksmbd_dtrace_log) {
		cmn_err(CE_CONT, "dtrace2:%s:%s,"
		    " (%s) 0x%lx, (%s) 0x%lx\n",
		    f, n, t1, v1, t2, v2);
	}
}

void
smb_dtrace3(const char *f, const char *n,
	    const char *t1, long v1,
	    const char *t2, long v2,
	    const char *t3, long v3)
{
	if (fksmbd_dtrace_log) {
		cmn_err(CE_CONT, "dtrace3:%s:%s,"
		    " (%s) 0x%lx, (%s) 0x%lx, (%s) 0x%lx\n",
		    f, n, t1, v1, t2, v2, t3, v3);
	}
}
