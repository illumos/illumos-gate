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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include "lint.h"
#include <sys/types.h>
#include <signal.h>

#undef	_sys_nsig
#undef	_sys_siglist
#define	OLDNSIG	34

const int _sys_nsig = OLDNSIG;

static const char	STR_SIG_UNK[]	= "UNKNOWN SIGNAL";
static const char	STR_SIGHUP[]	= "Hangup";
static const char	STR_SIGINT[]	= "Interrupt";
static const char	STR_SIGQUIT[]	= "Quit";
static const char	STR_SIGILL[]	= "Illegal Instruction";
static const char	STR_SIGTRAP[]	= "Trace/Breakpoint Trap";
static const char	STR_SIGABRT[]	= "Abort";
static const char	STR_SIGEMT[]	= "Emulation Trap";
static const char	STR_SIGFPE[]	= "Arithmetic Exception";
static const char	STR_SIGKILL[]	= "Killed";
static const char	STR_SIGBUS[]	= "Bus Error";
static const char	STR_SIGSEGV[]	= "Segmentation Fault";
static const char	STR_SIGSYS[]	= "Bad System Call";
static const char	STR_SIGPIPE[]	= "Broken Pipe";
static const char	STR_SIGALRM[]	= "Alarm Clock";
static const char	STR_SIGTERM[]	= "Terminated";
static const char	STR_SIGUSR1[]	= "User Signal 1";
static const char	STR_SIGUSR2[]	= "User Signal 2";
static const char	STR_SIGCLD[]	= "Child Status Changed";
static const char	STR_SIGPWR[]	= "Power-Fail/Restart";
static const char	STR_SIGWINCH[]	= "Window Size Change";
static const char	STR_SIGURG[]	= "Urgent Socket Condition";
static const char	STR_SIGPOLL[]	= "Pollable Event";
static const char	STR_SIGSTOP[]	= "Stopped (signal)";
static const char	STR_SIGTSTP[]	= "Stopped (user)";
static const char	STR_SIGCONT[]	= "Continued";
static const char	STR_SIGTTIN[]	= "Stopped (tty input)";
static const char	STR_SIGTTOU[]	= "Stopped (tty output)";
static const char	STR_SIGVTALRM[]	= "Virtual Timer Expired";
static const char	STR_SIGPROF[]	= "Profiling Timer Expired";
static const char	STR_SIGXCPU[]	= "Cpu Limit Exceeded";
static const char	STR_SIGXFSZ[]	= "File Size Limit Exceeded";
static const char	STR_SIGWAITING[]	= "No runnable lwp";
static const char	STR_SIGLWP[]	= "Inter-lwp signal";

const char *_sys_siglist[OLDNSIG] = {
	STR_SIG_UNK,	STR_SIGHUP,	STR_SIGINT,	STR_SIGQUIT,
	STR_SIGILL,	STR_SIGTRAP,	STR_SIGABRT,	STR_SIGEMT,
	STR_SIGFPE,	STR_SIGKILL,	STR_SIGBUS,	STR_SIGSEGV,
	STR_SIGSYS,	STR_SIGPIPE,	STR_SIGALRM,	STR_SIGTERM,
	STR_SIGUSR1,	STR_SIGUSR2,	STR_SIGCLD,	STR_SIGPWR,
	STR_SIGWINCH,	STR_SIGURG,	STR_SIGPOLL,	STR_SIGSTOP,
	STR_SIGTSTP,	STR_SIGCONT,	STR_SIGTTIN,	STR_SIGTTOU,
	STR_SIGVTALRM,	STR_SIGPROF,	STR_SIGXCPU,	STR_SIGXFSZ,
	STR_SIGWAITING,	STR_SIGLWP,
};

static const char *_sys_siglist_data[NSIG] = {
	STR_SIG_UNK,	STR_SIGHUP,	STR_SIGINT,	STR_SIGQUIT,
	STR_SIGILL,	STR_SIGTRAP,	STR_SIGABRT,	STR_SIGEMT,
	STR_SIGFPE,	STR_SIGKILL,	STR_SIGBUS,	STR_SIGSEGV,
	STR_SIGSYS,	STR_SIGPIPE,	STR_SIGALRM,	STR_SIGTERM,
	STR_SIGUSR1,	STR_SIGUSR2,	STR_SIGCLD,	STR_SIGPWR,
	STR_SIGWINCH,	STR_SIGURG,	STR_SIGPOLL,	STR_SIGSTOP,
	STR_SIGTSTP,	STR_SIGCONT,	STR_SIGTTIN,	STR_SIGTTOU,
	STR_SIGVTALRM,	STR_SIGPROF,	STR_SIGXCPU,	STR_SIGXFSZ,
	STR_SIGWAITING,	STR_SIGLWP,
		"Checkpoint Freeze",			/* SIGFREEZE	*/
		"Checkpoint Thaw",			/* SIGTHAW	*/
		"Thread Cancellation",			/* SIGCANCEL	*/
		"Resource Lost",			/* SIGLOST	*/
		"Resource Control Exceeded",		/* SIGXRES	*/
		"Reserved for JVM 1",			/* SIGJVM1	*/
		"Reserved for JVM 2",			/* SIGJVM2	*/
		"Information Request",			/* SIGINFO	*/
		"First Realtime Signal",		/* SIGRTMIN	*/
		"Second Realtime Signal",		/* SIGRTMIN+1	*/
		"Third Realtime Signal",		/* SIGRTMIN+2	*/
		"Fourth Realtime Signal",		/* SIGRTMIN+3	*/
		"Fifth Realtime Signal",		/* SIGRTMIN+4	*/
		"Sixth Realtime Signal",		/* SIGRTMIN+5	*/
		"Seventh Realtime Signal",		/* SIGRTMIN+6	*/
		"Eighth Realtime Signal",		/* SIGRTMIN+7	*/
		"Ninth Realtime Signal",		/* SIGRTMIN+8	*/
		"Tenth Realtime Signal",		/* SIGRTMIN+9	*/
		"Eleventh Realtime Signal",		/* SIGRTMIN+10	*/
		"Twelfth Realtime Signal",		/* SIGRTMIN+11	*/
		"Thirteenth Realtime Signal",		/* SIGRTMIN+12	*/
		"Fourteenth Realtime Signal",		/* SIGRTMIN+13	*/
		"Fifteenth Realtime Signal",		/* SIGRTMIN+14	*/
		"Sixteenth Realtime Signal",		/* SIGRTMIN+15	*/
		"Sixteenth Last Realtime Signal",	/* SIGRTMAX-15	*/
		"Fifteenth Last Realtime Signal",	/* SIGRTMAX-14	*/
		"Fourteenth Last Realtime Signal",	/* SIGRTMAX-13	*/
		"Thirteenth Last Realtime Signal",	/* SIGRTMAX-12	*/
		"Twelfth Last Realtime Signal",		/* SIGRTMAX-11	*/
		"Eleventh Last Realtime Signal",	/* SIGRTMAX-10	*/
		"Tenth Last Realtime Signal",		/* SIGRTMAX-9	*/
		"Ninth Last Realtime Signal",		/* SIGRTMAX-8	*/
		"Eighth Last Realtime Signal",		/* SIGRTMAX-7	*/
		"Seventh Last Realtime Signal",		/* SIGRTMAX-6	*/
		"Sixth Last Realtime Signal",		/* SIGRTMAX-5	*/
		"Fifth Last Realtime Signal",		/* SIGRTMAX-4	*/
		"Fourth Last Realtime Signal",		/* SIGRTMAX-3	*/
		"Third Last Realtime Signal",		/* SIGRTMAX-2	*/
		"Second Last Realtime Signal",		/* SIGRTMAX-1	*/
		"Last Realtime Signal"			/* SIGRTMAX	*/
};

const int	_sys_siglistn = sizeof (_sys_siglist_data) / sizeof (char *);
const char	**_sys_siglistp = _sys_siglist_data;
