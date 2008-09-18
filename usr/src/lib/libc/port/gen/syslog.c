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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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


/*
 * SYSLOG -- print message on log file
 *
 * This routine looks a lot like printf, except that it
 * outputs to the log file instead of the standard output.
 * Also:
 *	adds a timestamp,
 *	prints the module name in front of the message,
 *	has some other formatting types (or will sometime),
 *	adds a newline on the end of the message.
 *
 * The output of this routine is intended to be read by /etc/syslogd.
 */

#pragma weak _syslog = syslog

#include "lint.h"
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/mman.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/log.h>		/* for LOG_MAXPS */
#include <stdlib.h>
#include <procfs.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <sys/door.h>
#include <sys/stat.h>
#include <stropts.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include "libc.h"

#define	MAXLINE		1024		/* max message size (but see below) */

#define	PRIMASK(p)	(1 << ((p) & LOG_PRIMASK))
#define	PRIFAC(p)	(((p) & LOG_FACMASK) >> 3)
#define	IMPORTANT 	LOG_ERR

#ifndef FALSE
#define	FALSE 	0
#endif

#ifndef TRUE
#define	TRUE	1
#endif

#define	logname		"/dev/conslog"
#define	ctty		"/dev/syscon"
#define	sysmsg		"/dev/sysmsg"

#define	DOORFILE	"/var/run/syslog_door"

static struct __syslog {
	int	_LogFile;
	int	_LogStat;
	const char *_LogTag;
	int	_LogMask;
	char	*_SyslogHost;
	int	_LogFacility;
	int	_LogFileInvalid;
	int	_OpenLogCalled;
	dev_t   _LogDev;
	char	_ProcName[PRFNSZ + 1];
} __syslog = {
	-1,		/* fd for log */
	0,		/* status bits, set by openlog() */
	"syslog",	/* string to tag the entry with */
	0xff,		/* mask of priorities to be logged */
	NULL,
	LOG_USER,	/* default facility code */
	FALSE,		/* check for validity of fd for log */
	0,		/* openlog has not yet been called */
};

#define	LogFile (__syslog._LogFile)
#define	LogStat (__syslog._LogStat)
#define	LogTag (__syslog._LogTag)
#define	LogMask (__syslog._LogMask)
#define	SyslogHost (__syslog._SyslogHost)
#define	LogFacility (__syslog._LogFacility)
#define	LogFileInvalid (__syslog._LogFileInvalid)
#define	OpenLogCalled (__syslog._OpenLogCalled)
#define	LogDev (__syslog._LogDev)
#define	ProcName (__syslog._ProcName)

static int syslogd_ok(void);

/*
 * Regrettably, there are several instances inside libc where
 * syslog() is called from the bottom of a deep call stack
 * and a critical lock was acquired near the top of the stack.
 *
 * Because syslog() uses stdio (and it is called from within stdio)
 * it runs the danger of deadlocking, perhaps with an interposed
 * malloc() when fork() is occurring concurrently, perhaps with
 * some other lock within libc.
 *
 * The only fix for this problem is to restructure libc not to do
 * this thing and always to call syslog() with no locks held.
 * This restructuring will require a substantial effort.
 *
 * Meanwhile, we just hope that on the rare occasion that syslog()
 * is called from within libc (such occurrences should "never happen")
 * that we don't get caught in a race condition deadlock.
 */
void
syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}


void
vsyslog(int pri, const char *fmt, va_list ap)
{
	char *b, *f, *o;
	char c;
	int clen;
	char buf[MAXLINE + 2];
	char outline[MAXLINE + 256];  /* pad to allow date, system name... */
	time_t now;
	pid_t pid;
	struct log_ctl hdr;
	struct strbuf dat;
	struct strbuf ctl;
	char timestr[26];	/* hardwired value 26 due to Posix */
	size_t taglen;
	int olderrno = errno;
	struct stat statbuff;
	int procfd;
	char procfile[32];
	psinfo_t p;
	int showpid;
	uint32_t msgid;
	char *msgid_start, *msgid_end;
	int nowait;

/*
 * Maximum tag length is 256 (the pad in outline) minus the size of the
 * other things that can go in the pad.
 */
#define	MAX_TAG		230

	/* see if we should just throw out this message */
	if (pri < 0 || PRIFAC(pri) >= LOG_NFACILITIES ||
	    (PRIMASK(pri) & LogMask) == 0)
		return;

	if (LogFileInvalid)
		return;

	/*
	 * if openlog() has not been called by the application,
	 * try to get the name of the application and set it
	 * as the ident string for messages. If unable to get
	 * it for any reason, fall back to using the default
	 * of syslog. If we succeed in getting the name, also
	 * turn on LOG_PID, to provide greater detail.
	 */
	showpid = 0;
	if (OpenLogCalled == 0) {
		(void) sprintf(procfile, "/proc/%d/psinfo", (int)getpid());
		if ((procfd = open(procfile, O_RDONLY)) >= 0) {
			if (read(procfd, &p, sizeof (psinfo_t)) >= 0) {
				(void) strncpy(ProcName, p.pr_fname, PRFNSZ);
				LogTag = (const char *) &ProcName;
				showpid = LOG_PID;
			}
			(void) close(procfd);
		}
	}
	if (LogFile < 0)
		openlog(LogTag, LogStat|LOG_NDELAY|showpid, 0);

	if ((fstat(LogFile, &statbuff) != 0) ||
	    (!S_ISCHR(statbuff.st_mode)) || (statbuff.st_rdev != LogDev)) {
		LogFileInvalid = TRUE;
		return;
	}

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the header */
	hdr.pri = pri;
	hdr.flags = SL_CONSOLE;
	hdr.level = 0;

	/* build the message */
	/*
	 * To avoid potential security problems, bounds checking is done
	 * on outline and buf.
	 * The following code presumes that the header information will
	 * fit in 250-odd bytes, as was accounted for in the buffer size
	 * allocation.  This is dependent on the assumption that the LogTag
	 * and the string returned by sprintf() for getpid() will return
	 * be less than 230-odd characters combined.
	 */
	o = outline;
	(void) time(&now);
	(void) sprintf(o, "%.15s ", ctime_r(&now, timestr, 26) + 4);
	o += strlen(o);

	if (LogTag) {
		taglen = strlen(LogTag) < MAX_TAG ? strlen(LogTag) : MAX_TAG;
		(void) strncpy(o, LogTag, taglen);
		o[taglen] = '\0';
		o += strlen(o);
	}
	if (LogStat & LOG_PID) {
		(void) sprintf(o, "[%d]", (int)getpid());
		o += strlen(o);
	}
	if (LogTag) {
		(void) strcpy(o, ": ");
		o += 2;
	}

	STRLOG_MAKE_MSGID(fmt, msgid);
	(void) sprintf(o, "[ID %u FACILITY_AND_PRIORITY] ", msgid);
	o += strlen(o);

	b = buf;
	f = (char *)fmt;
	while ((c = *f++) != '\0' && b < &buf[MAXLINE]) {
		char *errmsg;
		if (c != '%') {
			*b++ = c;
			continue;
		}
		if ((c = *f++) != 'm') {
			*b++ = '%';
			*b++ = c;
			continue;
		}
		if ((errmsg = strerror(olderrno)) == NULL)
			(void) snprintf(b, &buf[MAXLINE] - b, "error %d",
			    olderrno);
		else {
			while (*errmsg != '\0' && b < &buf[MAXLINE]) {
				if (*errmsg == '%') {
					(void) strcpy(b, "%%");
					b += 2;
				}
				else
					*b++ = *errmsg;
				errmsg++;
			}
			*b = '\0';
		}
		b += strlen(b);
	}
	if (b > buf && *(b-1) != '\n')	/* ensure at least one newline */
		*b++ = '\n';
	*b = '\0';
	/* LINTED variable format specifier */
	(void) vsnprintf(o, &outline[sizeof (outline)] - o, buf, ap);
	clen  = (int)strlen(outline) + 1;	/* add one for NULL byte */
	if (clen > MAXLINE) {
		clen = MAXLINE;
		outline[MAXLINE-1] = '\0';
	}

	/*
	 * 1136432 points out that the underlying log driver actually
	 * refuses to accept (ERANGE) messages longer than LOG_MAXPS
	 * bytes.  So it really doesn't make much sense to putmsg a
	 * longer message..
	 */
	if (clen > LOG_MAXPS) {
		clen = LOG_MAXPS;
		outline[LOG_MAXPS-1] = '\0';
	}

	/* set up the strbufs */
	ctl.maxlen = sizeof (struct log_ctl);
	ctl.len = sizeof (struct log_ctl);
	ctl.buf = (caddr_t)&hdr;
	dat.maxlen = sizeof (outline);
	dat.len = clen;
	dat.buf = outline;

	/* output the message to the local logger */
	if ((putmsg(LogFile, &ctl, &dat, 0) >= 0) && syslogd_ok())
		return;
	if (!(LogStat & LOG_CONS))
		return;

	/*
	 * Output the message to the console directly.  To reduce visual
	 * clutter, we strip out the message ID.
	 */
	if ((msgid_start = strstr(outline, "[ID ")) != NULL &&
	    (msgid_end = strstr(msgid_start, "] ")) != NULL)
		(void) strcpy(msgid_start, msgid_end + 2);

	clen = strlen(outline) + 1;

	nowait = (LogStat & LOG_NOWAIT);
	pid = forkx(nowait? 0 : (FORK_NOSIGCHLD | FORK_WAITPID));
	if (pid == -1)
		return;

	if (pid == 0) {
		sigset_t sigs;
		int fd;

		(void) sigset(SIGALRM, SIG_DFL);
		(void) sigemptyset(&sigs);
		(void) sigaddset(&sigs, SIGALRM);
		(void) sigprocmask(SIG_UNBLOCK, &sigs, NULL);
		(void) alarm(5);
		if (((fd = open(sysmsg, O_WRONLY)) >= 0) ||
		    (fd = open(ctty, O_WRONLY)) >= 0) {
			(void) alarm(0);
			outline[clen - 1] = '\r';
			(void) write(fd, outline, clen);
			(void) close(fd);
		}
		_exit(0);
	}
	if (!nowait)
		while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			continue;
}

/*
 * Use a door call to syslogd to see if it's alive.
 */
static int
syslogd_ok(void)
{
	int d;
	int s;
	door_arg_t darg;
	door_info_t info;

	if ((d = open(DOORFILE, O_RDONLY)) < 0)
		return (0);
	/*
	 * see if our pid matches the pid of the door server.
	 * If so, syslogd has called syslog(), probably as
	 * a result of some name service library error, and
	 * we don't want to let syslog continue and possibly
	 * fork here.
	 */
	info.di_target = 0;
	if (__door_info(d, &info) < 0 || info.di_target == getpid()) {
		(void) close(d);
		return (0);
	}
	darg.data_ptr = NULL;
	darg.data_size = 0;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = NULL;
	darg.rsize = 0;
	s = __door_call(d, &darg);
	(void) close(d);
	if (s < 0)
		return (0);		/* failure - syslogd dead */
	else
		return (1);
}

/*
 * OPENLOG -- open system log
 */

void
openlog(const char *ident, int logstat, int logfac)
{
	struct	stat	statbuff;

	OpenLogCalled = 1;
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0)
		LogFacility = logfac & LOG_FACMASK;

	/*
	 * if the fstat(2) fails or the st_rdev has changed
	 * then we must open the file
	 */
	if ((fstat(LogFile, &statbuff) == 0) &&
	    (S_ISCHR(statbuff.st_mode)) && (statbuff.st_rdev == LogDev))
		return;

	if (LogStat & LOG_NDELAY) {
		LogFile = open(logname, O_WRONLY);
		(void) fcntl(LogFile, F_SETFD, 1);
		(void) fstat(LogFile, &statbuff);
		LogDev = statbuff.st_rdev;
	}
}

/*
 * CLOSELOG -- close the system log
 */

void
closelog(void)
{
	struct	stat	statbuff;

	OpenLogCalled = 0;

	/* if the LogFile is invalid it can not be closed */
	if (LogFileInvalid)
		return;

	/*
	 * if the fstat(2) fails or the st_rdev has changed
	 * then we can not close the file
	 */
	if ((fstat(LogFile, &statbuff) == 0) && (statbuff.st_rdev == LogDev)) {
		(void) close(LogFile);
		LogFile = -1;
		LogStat = 0;
	}
}

/*
 * SETLOGMASK -- set the log mask level
 */
int
setlogmask(int pmask)
{
	int omask = 0;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}
