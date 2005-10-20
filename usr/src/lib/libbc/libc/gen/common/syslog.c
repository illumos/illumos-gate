/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 *
 * Author: Eric Allman
 * Modified to use UNIX domain IPC by Ralph Campbell
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <netdb.h>
#include <strings.h>
#include <stdarg.h>
#include <vfork.h>
#include <stdio.h>
#include <errno.h>
#include <malloc.h>


#define	MAXLINE	1024			/* max message size */

#define	PRIMASK(p)	(1 << ((p) & LOG_PRIMASK))
#define	PRIFAC(p)	(((p) & LOG_FACMASK) >> 3)
#define	IMPORTANT 	LOG_ERR

static char	*logname = "/dev/log";
static char	*ctty = "/dev/console";
static char	*sysmsg = "/dev/sysmsg";

static struct _syslog {
	int	_LogFile;
	int	_LogStat;
	char	*_LogTag;
	int	_LogMask;
	struct 	sockaddr _SyslogAddr;
	char	*_SyslogHost;
	int	_LogFacility;
} *_syslog;
#define	LogFile (_syslog->_LogFile)
#define	LogStat (_syslog->_LogStat)
#define	LogTag (_syslog->_LogTag)
#define	LogMask (_syslog->_LogMask)
#define	SyslogAddr (_syslog->_SyslogAddr)
#define	SyslogHost (_syslog->_SyslogHost)
#define	LogFacility (_syslog->_LogFacility)


extern char *strerror(int);
extern time_t time();

void	vsyslog(int, char *, va_list);
void	openlog(char *, int, int);
static int	snprintf(char *, size_t, char *, ...);
static int	vsnprintf(char *, size_t, char *, va_list ap);

static int
allocstatic(void)
{
	_syslog = (struct _syslog *)calloc(1, sizeof (struct _syslog));
	if (_syslog == 0)
		return (0);	/* can't do it */
	LogFile = -1;		/* fd for log */
	LogStat	= 0;		/* status bits, set by openlog() */
	LogTag = "syslog";	/* string to tag the entry with */
	LogMask = 0xff;		/* mask of priorities to be logged */
	LogFacility = LOG_USER;	/* default facility code */
	return (1);
}

void
syslog(int pri, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

void
vsyslog(int pri, char *fmt, va_list ap)
{
	char buf[MAXLINE + 1], outline[MAXLINE + 1];
	char *b, *f, *o;
	int c;
	long now;
	int pid, olderrno = errno;
	int retsiz, outsiz = MAXLINE + 1;
	int taglen;
/*
 * Maximum tag length is 256 (the pad in outline) minus the size of the
 * other things that can go in the pad.
 */
#define	MAX_TAG	230


	if (_syslog == 0 && !allocstatic())
		return;

	/* see if we should just throw out this message */
	if (pri <= 0 || PRIFAC(pri) >= LOG_NFACILITIES ||
	    (PRIMASK(pri) & LogMask) == 0)
		return;
	if (LogFile < 0)
		openlog(LogTag, LogStat | LOG_NDELAY, 0);

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the message */
	o = outline;
	(void) time(&now);
	(void) sprintf(o, "<%d>%.15s ", pri, ctime(&now) + 4);
	o += strlen(o);

	if (LogTag) {
		taglen = strlen(LogTag) < MAX_TAG ? strlen(LogTag) : MAX_TAG;
		strncpy(o, LogTag, taglen);
		o[taglen] = '\0';
		o += strlen(o);
	}
	if (LogStat & LOG_PID) {
		(void) sprintf(o, "[%d]", getpid());
		o += strlen(o);
	}
	if (LogTag) {
		(void) strcpy(o, ": ");
		o += 2;
	}

	b = buf;
	f = fmt;
	while ((c = *f++) != '\0' && c != '\n' && b < &buf[MAXLINE]) {
		char *errstr;

		if (c != '%') {
			*b++ = c;
			continue;
		}
		if ((c = *f++) != 'm') {
			*b++ = '%';
			*b++ = c;
			continue;
		}
		if ((errstr = strerror(olderrno)) == NULL)
			(void) snprintf(b, &buf[MAXLINE] - b, "error %d",
			    olderrno);
		else {
			while (*errstr != '\0' && b < &buf[MAXLINE]) {
				if (*errstr == '%') {
					strcpy(b, "%%");
					b += 2;
				}
				else
					*b++ = *errstr;
				errstr++;
			}
			*b = '\0';
		}
		b += strlen(b);
	}
	if (b > buf && *(b-1) != '\n')	/* ensure at least one newline */
		*b++ = '\n';
	*b = '\0';
	(void) vsnprintf(o, &outline[sizeof (outline)] - o, buf, ap);
	c = strlen(outline) + 1;	/* add one for NULL byte */
	if (c > MAXLINE) {
		c = MAXLINE;
		outline[MAXLINE-1] = '\0';
	}

	/* output the message to the local logger */
	if (sendto(LogFile, outline, c, 0, &SyslogAddr,
	    sizeof (SyslogAddr)) >= 0)
		return;
	if (!(LogStat & LOG_CONS))
		return;

	/* output the message to the console */
	pid = vfork();
	if (pid == -1)
		return;
	if (pid == 0) {
		int fd;

		(void) signal(SIGALRM, SIG_DFL);
		(void) sigsetmask(sigblock(0) & ~sigmask(SIGALRM));
		(void) alarm(5);
		if (((fd = open(sysmsg, O_WRONLY)) >= 0) ||
		    (fd = open(ctty, O_WRONLY)) >= 0) {
			(void) alarm(0);
			if (outsiz > 2) {	/* Just in case */
				(void) strcat(o, "\r\n");
				c += 2;
			}
			o = index(outline, '>') + 1;
			(void) write(fd, o, c - (o - outline));
			(void) close(fd);
		} else
			(void) alarm(0);
		_exit(0);
	}
	if (!(LogStat & LOG_NOWAIT))
		while ((c = wait((int *)0)) > 0 && c != pid)
			;
}

/*
 * OPENLOG -- open system log
 */
void
openlog(char *ident, int logstat, int logfac)
{
	if (_syslog == 0 && !allocstatic())
		return;
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0)
		LogFacility = logfac & LOG_FACMASK;
	if (LogFile >= 0)
		return;
	SyslogAddr.sa_family = AF_UNIX;
	(void) strncpy(SyslogAddr.sa_data, logname,
	    sizeof (SyslogAddr.sa_data));
	if (LogStat & LOG_NDELAY) {
		LogFile = socket(AF_UNIX, SOCK_DGRAM, 0);
		(void) fcntl(LogFile, F_SETFD, 1);
	}
}

/*
 * CLOSELOG -- close the system log
 */
void
closelog(void)
{

	if (_syslog == 0)
		return;
	(void) close(LogFile);
	LogFile = -1;
}

/*
 * SETLOGMASK -- set the log mask level
 */
int
setlogmask(int pmask)
{
	int omask;

	if (_syslog == 0 && !allocstatic())
		return (-1);
	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}

/*
 * snprintf/vsnprintf -- These routines are here
 * temporarily to solve bugid 1220257. Perhaps
 * they could become a public interface at some
 * point but not for now.
 */

extern int _doprnt();

static int
snprintf(char *string, size_t n, char *format, ...)
{
	int count;
	FILE siop;
	va_list ap;

	if (n == 0)
		return (0);
	siop._cnt = n - 1;
	siop._base = siop._ptr = (unsigned char *)string;
	siop._flag = _IOWRT+_IOSTRG;
	va_start(ap, format);
	count = _doprnt(format, ap, &siop);
	va_end(ap);
	*siop._ptr = '\0';	/* plant terminating null character */
	return (count);
}

static int
vsnprintf(char *string, size_t n, char *format, va_list ap)
{
	int count;
	FILE siop;

	if (n == 0)
		return (0);
	siop._cnt = n - 1;
	siop._base = siop._ptr = (unsigned char *)string;
	siop._flag = _IOWRT+_IOSTRG;
	count = _doprnt(format, ap, &siop);
	*siop._ptr = '\0';	/* plant terminating null character */
	return (count);
}
