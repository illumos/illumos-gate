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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_STRLOG_H
#define	_SYS_STRLOG_H

#include <sys/types.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Streams Log Driver Interface Definitions
 */

/*
 * structure of control portion of log message
 */
typedef struct log_ctl {
	short	mid;
	short	sid;
	char 	level;		/* level of message for tracing */
	short	flags;		/* message disposition */
#if defined(_LP64) || defined(_I32LPx)
	clock32_t ltime;	/* time in machine ticks since boot */
	time32_t ttime;		/* time in seconds since 1970 */
#else
	clock_t	ltime;
	time_t	ttime;
#endif
	int	seq_no;		/* sequence number */
	int	pri;		/* priority = (facility|level) */
} log_ctl_t;

/*
 * Public flags for log messages
 */
#define	SL_FATAL	0x01	/* indicates fatal error */
#define	SL_NOTIFY	0x02	/* logger must notify administrator */
#define	SL_ERROR	0x04	/* include on the error log */
#define	SL_TRACE	0x08	/* include on the trace log */
#define	SL_CONSOLE	0x10	/* include on the console log */
#define	SL_WARN		0x20	/* warning message */
#define	SL_NOTE		0x40	/* notice message */

/*
 * Private flags for log messages -- used by internal implementation only
 */
#define	SL_CONSONLY	0x1000	/* send message only to /dev/console */
#define	SL_LOGONLY	0x2000	/* send message only to /var/adm/messages */
#define	SL_USER		0x4000	/* send message to user's terminal */
#define	SL_PANICMSG	0x8000	/* message was created while panicking */

/*
 * Structure defining ids and levels desired by the tracer (I_TRCLOG).
 */
typedef struct trace_ids {
	short	ti_mid;
	short	ti_sid;
	int8_t	ti_level;
} trace_ids_t;

/*
 * Log Driver I_STR ioctl commands
 */

#define	LOGCTL		(('L')<<8)
#define	I_TRCLOG	(LOGCTL|1)	/* process is tracer */
#define	I_ERRLOG	(LOGCTL|2)	/* process is error logger */
#define	I_CONSLOG	(LOGCTL|3)	/* process is console logger */

#define	STRLOG_MAKE_MSGID(fmt, msgid)					\
{									\
	uchar_t *__cp = (uchar_t *)fmt;					\
	uchar_t __c;							\
	uint32_t __id = 0;						\
	while ((__c = *__cp++) != '\0')					\
		if (__c >= ' ')						\
			__id = (__id >> 5) + (__id << 27) + __c;	\
	msgid = (__id % 899981) + 100000;				\
}

#ifdef _KERNEL

#ifndef _ASM
#include <sys/va_list.h>
#endif

/*PRINTFLIKE5*/
extern int strlog(short, short, char, unsigned short, char *, ...)
	__KPRINTFLIKE(5);
extern int vstrlog(short, short, char, unsigned short, char *, __va_list)
	__KVPRINTFLIKE(5);

/*
 * STRLOG(mid,sid,level,flags,fmt,args) should be used for those trace
 * calls that are only to be made during debugging.
 */
#if defined(DEBUG) || defined(__lint)
#define	STRLOG	strlog
#else
#define	STRLOG	0 && strlog
#endif	/* DEBUG || __lint */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRLOG_H */
