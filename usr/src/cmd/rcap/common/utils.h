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

#ifndef	_UTILS_H
#define	_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <libintl.h>
#include <stdarg.h>
#include <time.h>
#include <libzonecfg.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

/*
 * Message filter levels by priority
 */
typedef enum rcm_level {
	RCM_NONE = 0,			/* No messages */
	RCM_ERR,			/* Errors only */
	RCM_WARN,			/* Warnings */
	RCM_INFO,			/* Information */
	RCM_DEBUG,			/* Everything */
	RCM_DEBUG_HIGH			/* Fire hose */
} rcm_level_t;

/*
 * Message destinations
 */
typedef enum rcm_dst {
	RCD_STD = 1,			/* Standard output/error, depending */
					/* on level */
	RCD_SYSLOG			/* syslog() daemon facility */
} rcm_dst_t;

typedef struct zone_entry {
	zoneid_t	zid;
	char		zname[ZONENAME_MAX];
} zone_entry_t;

#define	LINELEN		256		/* max. message length */

#ifdef DEBUG
#undef ASSERT
#define	ASSERT(x)	(assert(x))
#else /* !DEBUG */
#undef ASSERT
#define	ASSERT(x)	((void)0)
#endif /* DEBUG */

#ifdef DEBUG_MSG
extern void debug(char *, ...);
extern void debug_high(char *, ...);
#else /* !DEBUG_MSG */
/*LINTED: static unused*/
static void debug(char *format, ...) /*ARGSUSED*/ {}
/*LINTED: static unused*/
static void debug_high(char *format, ...) /*ARGSUSED*/ {}
#endif /* DEBUG_MSG */

extern void die(char *, ...);
extern void info(char *, ...);
extern rcm_level_t get_message_priority(void);
extern rcm_level_t set_message_priority(rcm_level_t);
extern rcm_dst_t set_message_destination(rcm_dst_t);
extern char *setprogname(char *);
extern void warn(const char *, ...);
extern int valid_abspath(char *);
extern void vdprintfe(int, const char *, va_list);
extern void dprintfe(int, char *, ...);
extern void hrt2ts(hrtime_t, timestruc_t *);
extern int xatoi(char *);
extern int get_running_zones(uint_t *, zone_entry_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILS_H */
