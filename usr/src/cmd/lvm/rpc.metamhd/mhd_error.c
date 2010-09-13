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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

#include <syslog.h>

/*
 * debug stuff
 */
#ifdef	MHD_DEBUG
int	mhd_debug = MHD_DEBUG;
#endif

/*
 * free and clear error
 */
void
mhd_clrerror(
	mhd_error_t	*mhep
)
{
	if (mhep->name != NULL)
		Free(mhep->name);
	(void) memset(mhep, 0, sizeof (*mhep));
}

/*
 * setup error
 */
int
mhd_error(
	mhd_error_t	*mhep,
	int		errnum,
	char		*name
)
{
	mhd_clrerror(mhep);
	if (errnum != 0) {
		mhep->errnum = errnum;
		if (name != NULL)
			mhep->name = Strdup(name);
		return (-1);
	}
	return (0);
}

/*
 * mhd_error_t to string
 */
static char *
mhd_strerror(
	mhd_error_t	*mhep
)
{
	static char	buf[1024];
	char		*emsg;

	switch (mhep->errnum) {
	case MHD_E_MAJORITY:
		return ("could not get any reservations");
	case MHD_E_RESERVED:
		return ("disk is reserved");
	default:
		if ((emsg = strerror(mhep->errnum)) != NULL)
			return (emsg);
		(void) sprintf(buf, "errno %d out of range", errno);
		return (buf);
	}
}

/*
 * printf-like log
 */
static void
mhd_vprintf(
	const char	*fmt,
	va_list		ap
)
{
	if (isatty(fileno(stderr))) {
		static mutex_t	stderr_mx = DEFAULTMUTEX;

		mhd_mx_lock(&stderr_mx);
		(void) vfprintf(stderr, fmt, ap);
		(void) fflush(stderr);
		(void) fsync(fileno(stderr));
		mhd_mx_unlock(&stderr_mx);
	}
	vsyslog(LOG_ERR, fmt, ap);
}

/*PRINTFLIKE1*/
void
mhd_eprintf(
	const char	*fmt,
	...
)
{
	va_list		ap;

	va_start(ap, fmt);
	mhd_vprintf(fmt, ap);
	va_end(ap);
}

/*
 * printf-like perror() log
 */
/*PRINTFLIKE2*/
static void
mhd_vperror(
	mhd_error_t	*mhep,
	const char	*fmt,
	va_list		ap
)
{
	char		buf[1024];
	char		*p = buf;
	size_t		len = sizeof (buf);
	int		n;

	if ((mhep->name != NULL) && (mhep->name[0] != '\0')) {
		n = snprintf(p, len, "%s: ", mhep->name);
		p += n;
		len -= n;
	}
	if ((fmt != NULL) && (*fmt != '\0')) {
		n = vsnprintf(p, len, fmt, ap);
		p += n;
		len -= n;
		n = snprintf(p, len, ": ");
		p += n;
		len -= n;
	}
	(void) snprintf(p, len, "%s", mhd_strerror(mhep));
	mhd_eprintf("%s\n", buf);
}

/*PRINTFLIKE2*/
void
mhde_perror(
	mhd_error_t	*mhep,
	const char	*fmt,
	...
)
{
	va_list		ap;

	va_start(ap, fmt);
	mhd_vperror(mhep, fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
mhd_perror(
	const char	*fmt,
	...
)
{
	va_list		ap;
	mhd_error_t	status = mhd_null_error;

	(void) mhd_error(&status, errno, NULL);
	va_start(ap, fmt);
	mhd_vperror(&status, fmt, ap);
	va_end(ap);
	mhd_clrerror(&status);
}
