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

#ifndef	_DHCPMSG_H
#define	_DHCPMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>		/* since consumers may want to 0 errno */

/*
 * dhcpmsg.[ch] comprise the interface used to log messages, either to
 * syslog(3C), or to the screen, depending on the debug level.  see
 * dhcpmsg.c for documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * the syslog levels, while useful, do not provide enough flexibility
 * to do everything we want.  consequently, we introduce another set
 * of levels, which map to a syslog level, but also potentially add
 * additional behavior.
 */

enum {
	MSG_DEBUG,		/* LOG_DEBUG, only if debug_level is 1 */
	MSG_DEBUG2,		/* LOG_DEBUG, only if debug_level is 1 or 2 */
	MSG_INFO,		/* LOG_INFO */
	MSG_VERBOSE,		/* LOG_INFO, only if is_verbose is true */
	MSG_NOTICE,		/* LOG_NOTICE */
	MSG_WARNING,		/* LOG_WARNING */
	MSG_ERR,		/* LOG_ERR, use errno if nonzero */
	MSG_ERROR,		/* LOG_ERR */
	MSG_CRIT		/* LOG_CRIT */
};

/* PRINTFLIKE2 */
extern void	dhcpmsg(int, const char *, ...);
extern void	dhcpmsg_init(const char *, boolean_t, boolean_t, int);
extern void	dhcpmsg_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCPMSG_H */
