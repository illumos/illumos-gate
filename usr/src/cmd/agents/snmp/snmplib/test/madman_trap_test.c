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
#include "madman_trap.h"



#define BUF_SZ		1000


static Subid agents_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 1 };
static Oid sysObjectID_value = { agents_subids, 10 };


/******************************************************************/

void test1()
{
	char buffer[BUF_SZ + 1];
	int i, j;


	for(i = 500; i < BUF_SZ; i++)
	{
		for(j = 0; j < i; j++)
		{
			buffer[j] = 'a';
		}
		buffer[i] = '\0';

		send_trap_appl_alarm(99, "toto application name",
			i, SEVERITY_LOW, buffer);
	}
}


/******************************************************************/

void test2()
{
	int i;


	for(i = 0; i < 10000; i++)
	{
		fprintf(stderr, "%d\n", i);
		send_trap_appl_alarm(1, "Solstice X.400 MTA:",
			i, SEVERITY_LOW, "Just a test message");
	}
}


/******************************************************************/

void test3()
{
	send_trap_appl_alarm(1, "Solstice X.400 MTA:",
		1, SEVERITY_LOW, "Just a test message: LOW");
	sleep(5);

	send_trap_appl_alarm(1, "Solstice X.400 MTA:",
		2, SEVERITY_MEDIUM, "Just a test message: MEDIUM");
	sleep(5);

	send_trap_appl_alarm(1, "Solstice X.400 MTA:",
		3, SEVERITY_HIGH, "Just a test message: HIGH");
}


/******************************************************************/

main()
{
/*
	trace_flags = 0xFFF;
*/

	if(trap_init(&sysObjectID_value, error_label))
	{
		fprintf(stderr, "trap_init() failed: %s\n", error_label);
		exit(1);
	}

	if(trap_destinator_add("panda", error_label))
	{
		fprintf(stderr, "trap_destinator_add() failed: %s\n",
			error_label);
		exit(1);
	}

	test3();

	exit(0);
}
