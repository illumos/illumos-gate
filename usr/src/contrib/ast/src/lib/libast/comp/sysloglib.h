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
 * posix syslog implementation definitions
 */

#ifndef _SYSLOGLIB_H
#define _SYSLOGLIB_H

#include <syslog.h>

#define log		_log_info_
#define sendlog		_log_send_

/*
 * NOTE: syslog() has a static initializer for Syslog_state_t log
 */

typedef struct
{
	int		facility;	/* openlog facility		*/
	int		fd;		/* log to this fd		*/
	int		flags;		/* openlog flags		*/
	unsigned int	mask;		/* setlogmask mask		*/
	int		attempt;	/* logfile attempt state	*/
	char		ident[64];	/* openlog ident		*/
	char		host[64];	/* openlog host name		*/
} Syslog_state_t;

extern Syslog_state_t	log;

extern void		sendlog(const char*);

#endif
