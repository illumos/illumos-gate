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

#ifndef _BOOTLOG_H
#define	_BOOTLOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * bootlog - error notification and progress reporting interface
 *          for WAN boot components
 * XXX some of this stuff should be split out into a bootlog_impl.h file.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * code translation struct for use in processing config file
 */
struct code {
	char	*c_name;
	int	c_val;
};

#define	BOOTLOG_CONN_RETRIES	3	/* max http connect retries */
#define	BOOTLOG_HTTP_TIMEOUT	10	/* http read timeout */

#define	BOOTLOG_MAX_URL 1024		/* max bootlog URL len */
#define	BOOTLOG_QS_MAX	1024		/* max unencoded len of query string */

#define	BOOTLOG_MSG_MAX_LEN 80		/* maximum message body length */

/*
 * severity codes
 */
typedef enum {
	BOOTLOG_EMERG =	1,	/* panic condition */
	BOOTLOG_ALERT,		/* condition that should be corrected now */
	BOOTLOG_CRIT,		/* critical condition - e.g. network errors */
	BOOTLOG_WARNING,	/* warning messages */
	BOOTLOG_INFO,		/* informational messages */
	BOOTLOG_PROGRESS,	/* progress reports */
	BOOTLOG_DEBUG,		/* debug messages */
	BOOTLOG_VERBOSE,	/* verbose mode messages */
	NOPRI			/* 'no-priority' priority */
} bootlog_severity_t;


/* PRINTFLIKE3 */
extern void bootlog(const char *, bootlog_severity_t, char *, ...);
/* PRINTFLIKE2 */
extern void libbootlog(bootlog_severity_t, char *, ...);

#ifdef __cplusplus
}
#endif

#endif /* _BOOTLOG_H */
