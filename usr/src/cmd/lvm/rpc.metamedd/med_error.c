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

#include "med_local.h"

#include <syslog.h>

/*
 * debug stuff
 */
#define	MED_DEBUG 0
#ifdef	MED_DEBUG
static	int	med_debug = MED_DEBUG;
#endif

/*
 * free and clear error
 */
static void
med_clrerror(
	med_err_t	*medep
)
{
	if (medep->med_node != NULL)
		Free(medep->med_node);
	if (medep->med_misc != NULL)
		Free(medep->med_misc);
	(void) memset(medep, 0, sizeof (*medep));
}

/*
 * Exported Entry Points
 */

/*
 * setup error
 */
int
med_error(
	med_err_t	*medep,
	int		errnum,
	char		*misc
)
{
	med_clrerror(medep);
	if (errnum != 0) {
		medep->med_errno = errnum;
		if (med_debug && misc != NULL)
			medep->med_misc = Strdup(misc);
		medep->med_node = Strdup(mynode());
		return (-1);
	}
	return (0);
}

/*
 * med_err_t to string
 */
static char *
med_strerror(
	med_err_t	*medep
)
{
	static char	buf[1024];
	char		*p = buf;
	char		*emsg;

	if (medep->med_errno < 0) {
		if ((emsg = med_errnum_to_str(medep->med_errno)) != NULL)
			return (emsg);
		(void) sprintf(p,
		    "unknown mediator errno %d\n", medep->med_errno);
		return (buf);
	} else {
		if ((emsg = strerror(medep->med_errno)) != NULL)
			return (emsg);
		(void) sprintf(p,
		    "errno %d out of range", medep->med_errno);
		return (buf);
	}
}

/*
 * printf-like log
 */
static void
med_vprintf(
	const char	*fmt,
	va_list		ap
)
{
	if (isatty(fileno(stderr))) {
#ifdef	_REENTRANT
		static mutex_t	stderr_mx = DEFAULTMUTEX;

		med_mx_lock(&stderr_mx);
#endif	/* _REENTRANT */
		(void) vfprintf(stderr, fmt, ap);
		(void) fflush(stderr);
		(void) fsync(fileno(stderr));
#ifdef	_REENTRANT
		med_mx_unlock(&stderr_mx);
#endif	/* _REENTRANT */
	}
	vsyslog(LOG_ERR, fmt, ap);
}

/*PRINTFLIKE1*/
void
med_eprintf(
	const char	*fmt,
	...
)
{
	va_list		ap;

	va_start(ap, fmt);
	med_vprintf(fmt, ap);
	va_end(ap);
}

/*
 * printf-like perror() log
 */
/*PRINTFLIKE2*/
static void
med_vperror(
	med_err_t	*medep,
	const char	*fmt,
	va_list		ap
)
{
	char		buf[1024];
	char		*p = buf;
	size_t		len = sizeof (buf);
	int		n;

	if ((medep->med_node != NULL) && (medep->med_node[0] != '\0')) {
		n = snprintf(p, len, "%s: ", medep->med_node);
		p += n;
		len -= n;
	}
	if ((medep->med_misc != NULL) && (medep->med_misc[0] != '\0')) {
		n = snprintf(p, len, "%s: ", medep->med_misc);
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
	(void) snprintf(p, len, "%s", med_strerror(medep));
	med_eprintf("%s\n", buf);
}

/*PRINTFLIKE2*/
void
medde_perror(
	med_err_t	*medep,
	const char	*fmt,
	...
)
{
	va_list		ap;

	va_start(ap, fmt);
	med_vperror(medep, fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
med_perror(
	const char	*fmt,
	...
)
{
	va_list		ap;
	med_err_t	status = med_null_err;

	(void) med_error(&status, errno, NULL);
	va_start(ap, fmt);
	med_vperror(&status, fmt, ap);
	va_end(ap);
	med_clrerror(&status);
}
