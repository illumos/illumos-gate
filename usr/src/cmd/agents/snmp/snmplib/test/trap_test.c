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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "error.h"
#include "trace.h"
#include "snmp.h"
#include "trap.h"


main()
{
	trace_flags = 0xFFF;

	if(trap_destinator_add("panda", error_label))
	{
		fprintf(stderr, "trap_destinator_add() failed: %s\n",
			error_label);
		exit(1);
	}

	if(trap_send_to_all_destinators(NULL, SNMP_TRAP_WARMSTART, 0, NULL, error_label))
	{
		fprintf(stderr, "trap_send_to_alldestinators() failed: %s\n",
			error_label);
		exit(1);
	}

	exit(0);
}
