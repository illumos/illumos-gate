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


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libgen.h>


#include "snmp_msg.h"
#include "impl.h"
#include "trace.h"
#include "error.h"


int error_size = DEFAULT_ERROR_SIZE;

char error_label[1000] = "";


static char *application_name = NULL;
static void (*application_end)() = NULL;


/*
 *	this function will exit on any error
 */

void error_init(char *name, void end())
{
	char *ptr;


	if(name == NULL)
	{
		(void)fprintf(stderr, "BUG: error_init(): name is NULL");
		exit(1);
	}

	ptr = basename(name);
	if(ptr == NULL)
	{
		(void)fprintf(stderr, "error_init(): bad application name: %s",
			name);
		exit(1);
	}

	application_name = strdup(ptr);
	if(application_name == NULL)
	{
		(void)fprintf(stderr, ERR_MSG_ALLOC);
		exit(1);
	}

	if(end == NULL)
	{
		(void)fprintf(stderr, "BUG: error_init(): end is NULL");
		exit(1);
	}

	application_end = end;

	openlog(name, LOG_CONS, LOG_DAEMON);
}


/* ARGSUSED */
void error_open(char *filename)
{
	return;
}


void error_close_stderr()
{
	return;
}

void error(char *format, ...)
{
	va_list ap;
	int32_t len;
	char static_buffer[4096];

	va_start(ap, format);

	/* remove '\n's at the end of format */
	/* LINTED */
	len = (int32_t)strlen(format);
	while((len > 0) && (format[len - 1] == '\n')) {
		format[len - 1] = '\0';
		len--;
	}

	(void) vsnprintf(static_buffer, sizeof (static_buffer), format, ap);
	va_end(ap);

	if(trace_level > 0)
		trace("%s", static_buffer);

	syslog(LOG_ERR, "%s", static_buffer);
}


void error_exit(char *format, ...)
{
	va_list ap;
	int32_t len;
	char static_buffer[4096];
	
	va_start(ap, format);

	/* remove '\n's at the end of format */
	/* LINTED */
	len = (int32_t)strlen(format);
	while((len > 0) && (format[len - 1] == '\n')) {
		format[len - 1] = '\0';
		len--;
	}

	(void) vsnprintf(static_buffer, sizeof (static_buffer), format, ap);
	va_end(ap);

	application_end();

	if(trace_level > 0)
		trace("%s", static_buffer);

	syslog(LOG_ERR, "%s", static_buffer);

	exit(1);
}


char *errno_string()
{
	static char buffer[100];

	sprintf(buffer, "[errno: %s(%d)]",
		strerror(errno), errno);

	return buffer;
}


char *h_errno_string()
{
	static char buffer[100];
	char *ptr = NULL;

	switch(h_errno)
	{
		case HOST_NOT_FOUND:
			ptr = "host not found";
			break;
		case TRY_AGAIN:
			ptr = "try again";
			break;
		case NO_RECOVERY:
			ptr = "no recovery";
			break;
		case NO_DATA:
			ptr = "no data";
			break;
		default:
			ptr = "???";
			break;
	}

	sprintf(buffer, "[h_errno: %s(%d)]",
		ptr, h_errno);

	return buffer;
}


