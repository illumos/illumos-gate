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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <boot_http.h>

#ifndef _BOOT
extern	const char *hstrerror(int);
#endif

static const char *errlist[] = {
	/* EHTTP_BADARG */	"One or more arguments are not valid",
	/* EHTTP_NOMEM */	"Insufficient memory",
	/* EHTTP_CONCLOSED */	"SSL connection is closed (but maybe not the"
				" underlying connection)",
	/* EHTTP_UNEXPECTED */	"SSL connection returned unexpected error",
	/* EHTTP_EOFERR */	"Unexpected/premature EOF",
	/* EHTTP_NOCERT */	"No certificate was presented",
	/* EHTTP_NOMATCH */	"'Peername' doesn't match 'host' or no "
				"matching entry",
	/* EHTTP_NODATA */	"No data was returned",
	/* EHTTP_NOT_1_1 */	"Not a HTTP/1.1 server",
	/* EHTTP_BADHDR */	"Invalid header",
	/* EHTTP_OORANGE */	"Request header line out of range",
	/* EHTTP_NORESP */	"No response or partial response received",
	/* EHTTP_BADRESP */	"Bad response or error response returned",
	/* EHTTP_NOHEADER */	"Chunked header expected but not found",
	/* EHTTP_NOBOUNDARY */	"Boundary line expected but not found",
	/* EHTTP_NOTMULTI */	"This is not a multipart transfer",
	/* EHTTP_BADSIZE */	"Could not determine msg body size"
};
static int	nerrs = { sizeof (errlist) / sizeof (errlist[0]) };

/*
 * http_errorstr - print the error associated with the source and errorcode
 *
 * Arguments:
 *   errsrc	- Which library caused the error (as returned by
 *		  http_get_lasterr())
 *   error	- The error code returned
 *
 * Returns:
 *   Pointer to error string for this error.
 */
char const *
http_errorstr(uint_t errsrc, ulong_t error)
{
	char const *msg = NULL;
#ifdef _BOOT
	static char message[128];
#endif
	switch (errsrc) {
	case ERRSRC_SYSTEM:
		msg = strerror(error);
		if (msg == NULL)
			msg = "Unknown system error";
		break;
	case ERRSRC_LIBHTTP:
		if (error == 0 || error > nerrs)
			msg = "Unknown libhttp error";
		else
			msg = errlist[error - 1];
		break;
	case ERRSRC_RESOLVE:
#ifdef _BOOT
		(void) sprintf(message, "Host retrieval error %lu\n", error);
		msg = message;
#else
		msg = hstrerror(error);
#endif
		break;
	case ERRSRC_VERIFERR:
		msg = X509_verify_cert_error_string(error);
		break;
	case ERRSRC_LIBSSL:
		msg = ERR_error_string(error, NULL);
		break;
	default:
		msg = "Unknown error";
		break;
	}

	return (msg);
}
