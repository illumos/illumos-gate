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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dtrace.h>

/*
 * Not currently providing name equivalents of dtrace_errno, only the error
 * message provided by libdtrace (which cannot be localized).  The reason is
 * that the EDT_ enumeration is still private.  The DTRACEFLT_ values are
 * public, however, so the API provides string equivalents for runtime faults
 * encountered in the error handler (see dtrace_handle_err()).  The API provides
 * the error as a string rather than an integer so that user applications do not
 * break if the integer values change.
 */

const char *
dtj_get_fault_name(int fault)
{
	const char *name = NULL;

	switch (fault) {
	case DTRACEFLT_BADADDR:
		name = "DTRACEFLT_BADADDR";
		break;
	case DTRACEFLT_BADALIGN:
		name = "DTRACEFLT_BADALIGN";
		break;
	case DTRACEFLT_ILLOP:
		name = "DTRACEFLT_ILLOP";
		break;
	case DTRACEFLT_DIVZERO:
		name = "DTRACEFLT_DIVZERO";
		break;
	case DTRACEFLT_NOSCRATCH:
		name = "DTRACEFLT_NOSCRATCH";
		break;
	case DTRACEFLT_KPRIV:
		name = "DTRACEFLT_KPRIV";
		break;
	case DTRACEFLT_UPRIV:
		name = "DTRACEFLT_UPRIV";
		break;
	case DTRACEFLT_TUPOFLOW:
		name = "DTRACEFLT_TUPOFLOW";
		break;
	case DTRACEFLT_BADSTACK:
		name = "DTRACEFLT_BADSTACK";
		break;
	case DTRACEFLT_LIBRARY:
		name = "DTRACEFLT_LIBRARY";
		break;
	default:
		name = NULL;
	}

	return (name);
}
