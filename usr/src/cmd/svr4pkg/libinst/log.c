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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/* unix system includes */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <sys/param.h>
#include <instzones_api.h>

/*
 * consolidation pkg command library includes
 */

#include "pkglib.h"

/*
 * local pkg command library includes
 */

#include "install.h"
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

/* Should be defined by cc -D */
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/* local static data */

static boolean_t	verbose = B_FALSE;

/*
 * Name:	log_msg
 * Description:	Outputs messages to logging facility.
 * Scope:	public
 * Arguments:	a_type - the severity of the message
 *		a_format - the printf format, plus its arguments
 * Returns:	none
 */

/*PRINTFLIKE2*/
void
log_msg(LogMsgType a_type, const char *a_format, ...)
{
	FILE	*out;
	char	*rstr = (char *)NULL;
	char	bfr[1];
	char	*prefix;
	size_t	vres = 0;
	va_list	ap;
	char	*p = get_prog_name();

	/* process message based on type */

	switch (a_type) {
	case LOG_MSG_ERR:
	default:	/* treat unknown type as LOG_MSG_ERR */
		out = stderr;
		prefix = MSG_LOG_ERROR;
		break;
	case LOG_MSG_WRN:	/* warning message */
		out = stderr;
		prefix = MSG_LOG_WARNING;
		break;
	case LOG_MSG_INFO:	/* information message */
		out = stdout;
		prefix = NULL;
		break;
	case LOG_MSG_DEBUG:	/* debugging message */
		if (!log_get_verbose()) {
			/* no debug messages if not verbose mode */
			return;
		}

		out = stderr;
		prefix = NULL;

		/* output debug prefix to match echoDebug() format */

		(void) fprintf(stderr, "# [%6d %3d", getpid(), getzoneid());

		if ((p != (char *)NULL) && (*p != '\0')) {
			fprintf(stderr, " %-11s", p);
		}

		(void) fprintf(stderr, "] ");
		break;
	}

	/* output prefix if specified */

	if (prefix != NULL) {
		(void) fprintf(out, "%s: ", prefix);
	}

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	/* allocate storage to hold the message */

	rstr = (char *)malloc(vres+2);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(rstr, vres+1, a_format, ap);
	va_end(ap);

	/* output formatted message to appropriate destination */

	if (fprintf(out, "%s\n", rstr) < 0) {
		if (out != stderr) {
			/*
			 * nothing output, try stderr as a
			 * last resort
			 */
			(void) fprintf(stderr, ERR_LOG_FAIL, a_format);
		}
	}

	/* free temporary message storage */

	free(rstr);
}

/*
 * Name:	set_verbose
 * Description:	Turns on verbose output
 * Scope:	public
 * Arguments:	verbose = B_TRUE indicates verbose mode
 * Returns:	none
 */

void
log_set_verbose(boolean_t setting)
{
	verbose = setting;
}

/*
 * Name:	get_verbose
 * Description:	Returns whether or not to output verbose messages
 * Scope:	public
 * Arguments:	none
 * Returns:	B_TRUE - verbose messages should be output
 */

boolean_t
log_get_verbose()
{
	return (verbose);
}
