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

#include <sys/cmn_err.h>
#include <sys/sdt.h>

/*
 * See: DTRACE_PROBE... in sys/sdt.h
 */

int fknsmb_dtrace_log = 0;

void
smb_dtrace1(const char *n, long v1)
{
	if (fknsmb_dtrace_log) {
		cmn_err(CE_CONT, "dtrace1: %s,"
		    " 0x%lx\n", n, v1);
	}
}

void
smb_dtrace2(const char *n, long v1, long v2)
{
	if (fknsmb_dtrace_log) {
		cmn_err(CE_CONT, "dtrace2: %s,"
		    " 0x%lx, 0x%lx\n", n, v1, v2);
	}
}

void
smb_dtrace3(const char *n, long v1, long v2, long v3)
{
	if (fknsmb_dtrace_log) {
		cmn_err(CE_CONT, "dtrace3: %s,"
		    " 0x%lx, 0x%lx, 0x%lx\n", n, v1, v2, v3);
	}
}
