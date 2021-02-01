/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * posix syslog interface definitions
 */

#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <stdarg.h>

#define LOG_PRIBITS	3	/* priority bits			*/
#define LOG_FACBITS	7	/* facility bits			*/

#define LOG_PRIMASK	((1<<LOG_PRIBITS)-1)
#define LOG_FACMASK	(((1<<LOG_FACBITS)-1)<<LOG_PRIBITS)

#define LOG_PRI(p)	((p)&((1<<LOG_PRIBITS)-1))
#define LOG_FAC(p)	(((p)>>LOG_PRIBITS)&((1<<LOG_FACBITS)-1))

#define LOG_MAKEPRI(f,p) (((f)<<LOG_PRIBITS)|(p))

/* syslog priority severity levels */

#define LOG_EMERG	0	/* panic condition			*/
#define LOG_ALERT	1	/* should be corrected immediately	*/
#define LOG_CRIT	2	/* critical condition			*/
#define LOG_ERR		3	/* error condition			*/
#define LOG_WARNING	4	/* warning condition			*/
#define LOG_NOTICE	5	/* no error but may need intervention	*/
#define LOG_INFO	6	/* informational message		*/
#define LOG_DEBUG	7	/* debug message			*/

/* setlogmask masks */

#define	LOG_MASK(s)	(1<<(s))	/* individual severity s	*/
#define	LOG_UPTO(s)	((1<<((s)+1))-1)/* up to and including s	*/

/* syslog facilities */

#define LOG_KERN	(0<<LOG_PRIBITS) /* kernel			*/
#define LOG_USER	(1<<LOG_PRIBITS) /* user process -- default	*/
#define LOG_MAIL	(2<<LOG_PRIBITS) /* mail			*/
#define LOG_DAEMON	(3<<LOG_PRIBITS) /* daemon			*/
#define LOG_AUTH	(4<<LOG_PRIBITS) /* security/authorization	*/
#define LOG_SYSLOG	(5<<LOG_PRIBITS) /* syslog internal		*/
#define LOG_LPR		(6<<LOG_PRIBITS) /* line printer		*/
#define LOG_NEWS	(7<<LOG_PRIBITS) /* network news		*/
#define LOG_UUCP	(8<<LOG_PRIBITS) /* uucp			*/
#define LOG_CRON	(9<<LOG_PRIBITS) /* cron			*/
#define LOG_AUDIT	(13<<LOG_PRIBITS) /* audit daemon		*/
#define LOG_LFMT	(14<<LOG_PRIBITS) /* logalert			*/
#define LOG_LOCAL0	(16<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL1	(17<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL2	(18<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL3	(19<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL4	(20<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL5	(21<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL6	(22<<LOG_PRIBITS) /* reserved for local use	*/
#define LOG_LOCAL7	(23<<LOG_PRIBITS) /* reserved for local use	*/

#define LOG_NFACILITIES	24

/* openlog flags */

#define	LOG_PID		0x01	/* log the pid with each message	*/
#define	LOG_CONS	0x02	/* log to console if errors in sending	*/
#define LOG_NDELAY	0x08	/* open right now			*/
#define	LOG_ODELAY	0x04	/* delay open until syslog() is called	*/
#define LOG_NOWAIT	0x10	/* don't wait() for any child processes	*/
#define LOG_PERROR	0x20	/* log to stderr too			*/
#define LOG_LEVEL	0x40	/* tag messages with facility/level	*/

#ifdef LOG_TABLES

/* encoding support */

#include <ast_namval.h>

#define log_facility	_log_facility
#define log_severity	_log_severity

#define LOG_FACILITY(p)	LOG_FAC(p)	/* get facility index from pri	*/
#define LOG_SEVERITY(p)	LOG_PRI(p)	/* get severity from pri	*/

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern const Namval_t	log_facility[];
extern const Namval_t	log_severity[];

#undef	extern

#endif

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern void	closelog(void);
extern void	openlog(const char*, int, int);
extern int	setlogmask(int);
extern void	syslog(int, const char*, ...);
extern void	vsyslog(int, const char*, va_list);

#undef	extern

#endif
