/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <nl_types.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>

#include <syslog.h>
#include <portable.h>
/* #include <lthread.h> */
#include <pthread.h>
#include <thread.h>

#include "log.h"

#define	LDAP_DEBUG_ANY	0xffff

static pthread_mutex_t	log_mutex;
static char		logfile[PATH_MAX] =
					"/var/opt/SUNWconn/ldap/log/slapd.log";
static int		logsize = 512000;
static int		logtime = 1;
static FILE		*logfd = NULL;
static int		syslogopen = 0;
pthread_mutex_t		systime_mutex;
nl_catd			sundscat;
static int		log_debug = LDAP_DEBUG_STATS;

typedef struct _logctx {
	char		*logfile;
	int		syslogopen;
	int		logsize;
	pthread_mutex_t	log_mutex;
	int		log_debug;
	int		log_syslog;

} LogCtx;

void
ldaplogconfig(char *logf, int size)
{
	strcpy(logfile, logf);
	logsize = size * 1024;
}

void
ldaplogconfigf(FILE *fd)
{
	logfd = fd;
	logsize = 0;
}

void
ldaploginit(char *name, int facility)
{
	openlog(name, OPENLOG_OPTIONS, facility);
	syslogopen = 1;
	pthread_mutex_init(&log_mutex, NULL);
}

void
ldaploginitlevel(char *name, int facility, int level)
{
	ldaploginit(name, facility);
	log_debug = level;
}

LogCtx *
sundsloginit(char *name, int facility, int debug_level, int syslog_level)
{
	LogCtx *returnCtx = NULL;

	if ((returnCtx = (LogCtx *)malloc(sizeof (LogCtx))) == NULL)
		return (NULL);
	if ((returnCtx->logfile = strdup(name)) == NULL) {
		free(returnCtx);
		return (NULL);
	}
	openlog(returnCtx->logfile, OPENLOG_OPTIONS, facility);
	returnCtx->syslogopen = 1;
	pthread_mutex_init(&(returnCtx->log_mutex), NULL);
	returnCtx->log_debug = debug_level;
	returnCtx->log_syslog = syslog_level;
	return (returnCtx);
}

static char timestr[128];
static time_t timelast = 0;

/*VARARGS*/
void
ldaplog(int level, char *fmt, ...)
{
	va_list ap;
	struct stat statbuf = {0};
	char newlog1[PATH_MAX];
	char newlog2[PATH_MAX];
	time_t now;
	int i;

	if (!(log_debug & level))
		return;

	va_start(ap, fmt);

	if (level == LDAP_DEBUG_ANY) {
		/*
		 * this message is probably an error message, send it to syslog
		 */
		if (syslogopen) {
			vsyslog(LOG_ERR, fmt, ap);
		} /* end if */
		/* and sent it also on stderr */
		vfprintf(stderr, fmt, ap);
	} /* end if */

	/*
	 * check that the log file is not already too big
	 */
	pthread_mutex_lock(&log_mutex);
	if ((logsize > 0) && (stat(logfile, &statbuf) == 0 &&
					statbuf.st_size > logsize)) {
		for (i = 9; i > 1; i--) {
			(void) sprintf(newlog1, "%s.%d", logfile, i-1);
			(void) sprintf(newlog2, "%s.%d", logfile, i);
			(void) rename(newlog1, newlog2);
		} /* end for */
		if (logfd) {
			fclose(logfd);
			logfd = NULL;
		} /* end if */
		(void) rename(logfile, newlog1);
	} /* end if */
	/*
	 * send the message into a regular log file
	 */
	if (!logfd) {
		logfd = fopen(logfile, "aF");
	} /* end if */
	/*
	 * finally write the message into the log file
	 */
	if (logfd) {
		if (logtime) {
			time(&now);
			if (now-timelast > 60) {
				pthread_mutex_lock(&systime_mutex);
				timelast = now;
				ctime_r(&now, timestr, 128);
				pthread_mutex_unlock(&systime_mutex);
			} /* end if */
			fprintf(logfd, "%.16s : ", timestr);
		} /* end if */
		vfprintf(logfd, fmt, ap);
		fflush(logfd);
	} /* end if */
	pthread_mutex_unlock(&log_mutex);
	va_end(ap);
}
