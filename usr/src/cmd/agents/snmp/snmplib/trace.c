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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include "snmp_msg.h"
#include "error.h"
#include "trace.h"


/***** GLOBAL VARIABLES *****/

int trace_level = 0;
uint32_t trace_flags = 0;


/***** STATIC VARIABLES *****/

static FILE *trace_stream = stdout;


/******************************************************************/

void trace(char *format, ...)
{
	va_list ap;

	if(trace_stream == NULL)
	{
		return;
	}

	va_start(ap, format);
	(void)vfprintf(trace_stream, format, ap);
	va_end(ap);
}


/******************************************************************/

int trace_set(int level, char *error_label)
{
	error_label[0] = '\0';

	if(level < 0 || level > TRACE_LEVEL_MAX)
	{
		sprintf(error_label, ERR_MSG_BAD_TRACE_LEVEL,
			level, TRACE_LEVEL_MAX);
		return (-1);
	}

	trace_level = level;

	if(trace_level > 0)
		trace_flags = trace_flags | TRACE_TRAFFIC;
	else
		trace_flags = trace_flags & (~TRACE_TRAFFIC);

	if(trace_level > 2)
		trace_flags = trace_flags | TRACE_PDU;
	else
		trace_flags = trace_flags & (~TRACE_PDU);

	if(trace_level > 3)
		trace_flags = trace_flags | TRACE_PACKET;
	else
		trace_flags = trace_flags & (~TRACE_PACKET);

	return (0);
}


/******************************************************************/

void trace_reset()
{
	(void)trace_set(0, error_label);
}


/******************************************************************/

void trace_increment()
{
	if(trace_level < TRACE_LEVEL_MAX)
		(void)trace_set(trace_level + 1, error_label);

}


/******************************************************************/

void trace_decrement()
{
	if(trace_level > 0)
		(void)trace_set(trace_level - 1, error_label);
}
