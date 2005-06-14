/*
 * Copyright 1996,1999,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * msyslog - either send a message to the terminal or print it on
 *	     the standard output.
 *
 * Converted to use varargs, much better ... jks
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>
#include <errno.h>

/* alternative, as Solaris 2.x defines __STDC__ as 0 in a largely standard
   conforming environment
   #if __STDC__ || (defined(SYS_SOLARIS) && defined(__STDC__))
*/
#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#include "ntp_types.h"
#include "ntp_string.h"
#include "ntp_stdlib.h"
#include "ntp_syslog.h"

#ifdef SYS_WINNT
# include "log.h"
# include "messages.h"
#endif

int syslogit = 1;

FILE *syslog_file = NULL;

u_long ntp_syslogmask =  ~ (u_long) 0;

#ifndef VMS
#ifndef SYS_WINNT
extern	int errno;
#else
HANDLE  hEventSource;
LPTSTR lpszStrings[1];
static WORD event_type[] = {
	EVENTLOG_ERROR_TYPE, EVENTLOG_ERROR_TYPE, EVENTLOG_ERROR_TYPE, EVENTLOG_ERROR_TYPE,
	EVENTLOG_WARNING_TYPE,
	EVENTLOG_INFORMATION_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_INFORMATION_TYPE,
};
#endif /* SYS_WINNT */
#endif /* VMS */
extern	char *progname;

#if defined(__STDC__)
void msyslog(int level, const char *fmt, ...)
#else
/*VARARGS*/
void msyslog(va_alist)
	va_dcl
#endif
{
#ifndef __STDC__
	int level;
	const char *fmt;
#endif
	va_list ap;
	char buf[1025], nfmt[256];
#if !defined(VMS)
	char xerr[50];
#endif
	register int c;
	register char *n, *prog;
	register const char *f;
#ifdef CHAR_SYS_ERRLIST
	extern int sys_nerr;
	extern char *sys_errlist[];
#endif
	register int l;
	int olderrno;
	const char *err;


#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);

	level = va_arg(ap, int);
	fmt = va_arg(ap, char *);
#endif

#ifdef SYS_SOLARIS
	if (syslogit) {
		vsyslog(level, fmt, ap);
		va_end(ap);
		return;
	}
#endif

	olderrno = errno;
	n = nfmt;
	f = fmt;
	while ((c = *f++) != '\0' && c != '\n' && n < &nfmt[252]) {
		if (c != '%') {
			*n++ = c;
			continue;
		}
		if ((c = *f++) != 'm') {
			*n++ = '%';
			*n++ = c;
			continue;
		}
		err = 0;
#if !defined(VMS) && !defined(SYS_WINNT) && !defined (SYS_VXWORKS)
		if ((unsigned)olderrno > sys_nerr)
			sprintf((char *)(err = xerr), "error %d", olderrno);
		else
			err = sys_errlist[olderrno];
#elif defined(VMS) || defined (SYS_VXWORKS)
		err = strerror(olderrno);
#else  /* SYS_WINNT */
		err = xerr;
 		FormatMessage( 
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
			(LPTSTR) err,
			sizeof(xerr),
			NULL);

#endif /* VMS && SYS_WINNT */
		if (n + (l = strlen(err)) < &nfmt[254]) {
			strcpy(n, err);
			n += strlen(err);
		}
	}
#if !defined(VMS)
	if (!syslogit)
#endif /* VMS */
	  *n++ = '\n';
	*n = '\0';

	(void) vsnprintf(buf, sizeof(buf), nfmt, ap);
#if !defined(VMS) && !defined (SYS_VXWORKS)
	if (syslogit)
#ifndef SYS_WINNT
		syslog(level, "%s", buf);
#else
	{
		lpszStrings[0] = buf;
 
		switch (event_type[level])
		{
		case EVENTLOG_ERROR_TYPE       :
			{
			reportAnEEvent(NTP_ERROR,1,lpszStrings);
			break;
			}
		case EVENTLOG_INFORMATION_TYPE :
			{
			reportAnIEvent(NTP_INFO,1,lpszStrings);
			break;
			}  
		case EVENTLOG_WARNING_TYPE     :
			{
			reportAnWEvent(NTP_WARNING,1,lpszStrings);
			break;
			}
		} /* switch end */

	} 
#endif /* SYS_WINNT */
	else {
#else
	{
#endif /* VMS  && SYS_VXWORKS*/
		extern char * humanlogtime P((void));

	        FILE *out_file = syslog_file ? syslog_file
  	                                  : level <= LOG_ERR ? stderr : stdout;
  	        /* syslog() provides the timestamp, so if we're not using
  	           syslog, we must provide it. */
		prog = strrchr(progname, '/');
		if (prog == NULL)
		  prog = progname;
		else
		  prog++;
		(void) fprintf(out_file, "%s ", humanlogtime ());
                (void) fprintf(out_file, "%s[%d]: %s", prog, (int)getpid(), buf);
		fflush (out_file);
	}
	va_end(ap);
}
