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
 * PPPoE Server-mode daemon logging functions.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef PPPOE_LOGGING_H
#define	PPPOE_LOGGING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	LOGLVL_DBG	3
#define	LOGLVL_INFO	2
#define	LOGLVL_WARN	1
#define	LOGLVL_ERR	0

/* Functions in logging.c */
extern void logdbg(const char *fmt, ...);
extern void loginfo(const char *fmt, ...);
extern void logwarn(const char *fmt, ...);
extern void logerr(const char *fmt, ...);
extern void logstrerror(const char *emsg);
extern void log_for_service(const char *fname, int dbglvl);
extern void log_to_stderr(int dbglvl);
extern void close_log_files(void);
extern void reopen_log(void);

/* Data in logging.c */
extern const char *prog_name;
extern int log_level;

/* Functions in options.c */
extern void global_logging(void);

/* A handy macro. */
#ifndef	Dim
#define	Dim(x)	(sizeof (x) / sizeof (*(x)))
#endif

#ifdef	__cplusplus
}
#endif

#endif /* PPPOE_LOGGING_H */
