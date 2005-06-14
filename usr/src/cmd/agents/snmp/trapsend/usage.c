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
 *
 * Copyright 1997 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sea_i18n.h"

void
usage()
{
	fprintf(stderr, FGET("%s\n"),
		MGET("Usage:"));

	fprintf(stderr, FGET("%s\n"),
		MGET("  trapsend"));
	fprintf(stderr, FGET("%s\t\t%s\n"),
		MGET("  [-h host]"),
		MGET("(default = localhost)"));
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-c community]"),
		MGET("(default = public)")); 
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-e enterprise | -E enterprise_str]"),
		MGET("(default = 1.3.6.1.4.1.42)"));
	fprintf(stderr, FGET("%s\t\t%s\n"),
		MGET("  [-g generic#]"),
		MGET("(range 0..6, default = 6)"));
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-s specific#]"),
		MGET("(default = 1)"));
	fprintf(stderr, FGET("%s\t\t%s\n"),
		MGET("  [-i ipaddr]"),
		MGET("(default = localhost)"));
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-p trap_port]"),
		MGET("(default = 162)"));
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-t timestamp]"),
		MGET("(a time in unix-time format, default is uptime)"));
	fprintf(stderr, FGET("%s\n"),
		MGET("  -a \"object-id object-type ( object-value )\""));
	fprintf(stderr, FGET("%s\t%s\n"),
		MGET("  [-T trace-level]"),
		MGET("(range 0..4, default = 0)\n")); 
	fprintf(stderr, FGET("%s\n"),
		MGET("  Note: Valid object types are:"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           STRING"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           INTEGER"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           COUNTER"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           GAUGE"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           TIMETICKS"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           OBJECTID"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           IPADDRESS"));
	fprintf(stderr, FGET("%s\n"),
		MGET("           OPAQUE"));

    exit(1);
}  /* usage */


