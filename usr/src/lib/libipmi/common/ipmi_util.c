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

#include <libipmi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "ipmi_impl.h"

/*
 * Error handling
 */
int
ipmi_set_error(ipmi_handle_t *ihp, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	ihp->ih_errno = error;
	if (fmt == NULL)
		ihp->ih_errmsg[0] = '\0';
	else
		(void) vsnprintf(ihp->ih_errmsg, sizeof (ihp->ih_errmsg),
		    fmt, ap);
	va_end(ap);

	return (-1);
}

int
ipmi_errno(ipmi_handle_t *ihp)
{
	return (ihp->ih_errno);
}

static struct {
	int		err;
	const char	*msg;
} errno_table[] = {
	{ EIPMI_NOMEM,			"memory allocation failure" },
	{ EIPMI_BMC_OPEN_FAILED,	"failed to open /dev/bmc" },
	{ EIPMI_BMC_PUTMSG,		"failed to send message to /dev/bmc" },
	{ EIPMI_BMC_GETMSG,
	    "failed to read response from /dev/bmc" },
	{ EIPMI_BMC_RESPONSE,
	    "failed to read response from /dev/bmc" },
	{ EIPMI_INVALID_COMMAND,	"invalid command" },
	{ EIPMI_COMMAND_TIMEOUT,	"command timed out" },
	{ EIPMI_DATA_LENGTH_EXCEEDED,	"maximum data length exceeded" },
	{ EIPMI_SEND_FAILED,		"failed to send BMC request" },
	{ EIPMI_UNSPECIFIED,		"unspecified BMC error" },
	{ EIPMI_BAD_RESPONSE_LENGTH,
	    "unexpected command response data length" },
	{ EIPMI_INVALID_RESERVATION,	"invalid or cancelled reservation" },
	{ EIPMI_NOT_PRESENT,		"request entity not present" },
	{ EIPMI_INVALID_REQUEST,	"malformed request data" },
	{ EIPMI_BUSY,			"service processor is busy" },
	{ EIPMI_NOSPACE,		"service processor is out of space" },
	{ EIPMI_UNAVAILABLE,		"service processor is unavailable" },
	{ EIPMI_ACCESS,			"insufficient privileges" }
};

/* ARGSUSED */
const char *
ipmi_errmsg(ipmi_handle_t *ihp)
{
	int i;
	const char *str;

	str = NULL;
	for (i = 0; i < sizeof (errno_table) / sizeof (errno_table[0]); i++) {
		if (errno_table[i].err == ihp->ih_errno) {
			str = errno_table[i].msg;
			break;
		}
	}

	if (str == NULL && (str = strerror(ihp->ih_errno)) == NULL)
		str = "unknown failure";

	if (ihp->ih_errmsg[0] == '\0')
		return (str);

	(void) snprintf(ihp->ih_errbuf, sizeof (ihp->ih_errbuf),
	    "%s: %s", str, ihp->ih_errmsg);
	return (ihp->ih_errbuf);
}

/*
 * Memory allocation
 */

void *
ipmi_alloc(ipmi_handle_t *ihp, size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

void *
ipmi_zalloc(ipmi_handle_t *ihp, size_t size)
{
	void *ptr;

	if ((ptr = calloc(size, 1)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

char *
ipmi_strdup(ipmi_handle_t *ihp, const char *str)
{
	char *ptr;

	if ((ptr = strdup(str)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

/* ARGSUSED */
void
ipmi_free(ipmi_handle_t *ihp, void *ptr)
{
	free(ptr);
}
