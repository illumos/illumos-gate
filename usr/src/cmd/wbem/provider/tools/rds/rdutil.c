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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/resource.h>
#include <sys/time.h>
#include <stdlib.h>
#include <libintl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <poll.h>
#include <unistd.h>
#include <project.h>
#include <pwd.h>
#include <pthread.h>

#include "rdfile.h"
#include "rdimpl.h"
#include "rdutil.h"

static char PRG_FMT[] = "%s: ";
static char ERR_FMT[] = ": %s\n";
static char *modulname = "srm provider";

extern jmp_buf  dm_jmpbuffer;
extern char errmsg[];
extern void monitor_stop();

extern pthread_mutex_t logLock;

/*PRINTFLIKE1*/
void
format_err(char *format, ...)
{
	int pos = 0;
	va_list alist;
	pos += sprintf(errmsg, PRG_FMT, modulname);
	va_start(alist, format);
	pos += vsprintf(errmsg + pos, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) sprintf(errmsg + pos, "\n");
}

/*PRINTFLIKE1*/
void
format_errno(char *format, ...)
{
	int err = errno, pos = 0;
	va_list alist;
	pos += sprintf(errmsg, PRG_FMT, modulname);
	va_start(alist, format);
	pos += vsprintf(errmsg + pos, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		pos += sprintf(errmsg + pos, ERR_FMT,
				(err != 0) ? strerror(err) : "");
}

/*PRINTFLIKE1*/
void
dmerror(char *format, ...)
{
	int err = errno, pos = 0;
	va_list alist;

	pos += sprintf(errmsg, PRG_FMT, modulname);
	va_start(alist, format);
	pos += vsprintf(errmsg + pos, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		pos += sprintf(errmsg + pos, ERR_FMT, strerror(err));
	longjmp(dm_jmpbuffer, 1);
}

void *
Realloc(void *ptr, size_t size)
{
	int	cnt = 0;
	void    *sav = ptr;

eagain: if ((ptr = realloc(ptr, size)))
		return (ptr);

	log_err("realloc(ptr=0x%p, size=%u)", (void *)ptr, (uint_t)size);
	if ((++cnt <= 3) && (errno == EAGAIN)) {
		napms(5000); /* wait for 5 seconds */
		ptr = sav;
		goto eagain;
	}
	ptr = sav;
	dmerror("not enough memory");
	/*NOTREACHED*/
	return (NULL);	/* keep gcc happy */
}

void *
Malloc(size_t size)
{
	return (Realloc(NULL, size));
}

void *
Zalloc(size_t size)
{
	return (memset(Realloc(NULL, size), 0, size));
}

void
Free(void *ptr)
{
	free(ptr);
}

int
Setrlimit()
{
	struct rlimit rlim;
	int rv, fd_limit;

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		dmerror("getrlimit failed");
	fd_limit = (int)rlim.rlim_cur;

	rlim.rlim_cur = rlim.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
	    rv = fd_limit;
	else
	    rv = (int)rlim.rlim_cur;

	log_msg("fd_limit set to %d\n", rv);

	return (rv);
}

void
list_alloc(list_t *list, int size)
{
	if (size > 0) {
		list->l_size = size;
		list->l_ptrs = Zalloc(sizeof (void *) * (size + 1));
	}
}

void
list_init(list_t *list, int type)
{
	if (list == NULL)
		return;

	list->l_type = type;

	list->l_type = type;
}


void
getusrname(int uid, char *name, int length)
{
	struct passwd *pwd;

	if ((pwd = getpwuid(uid)) == NULL) {
		log_err("getpwuid(uid=%d,..)", uid);
		(void) snprintf(name, length, "%d", uid);
	} else {
		(void) snprintf(name, length, "%s", pwd->pw_name);
	}
}

void
getprojname(projid_t projid, char *str, int len)
{
	struct project proj;
	char projbuf[PROJECT_BUFSZ];

	if (getprojbyid(projid, &proj, projbuf, PROJECT_BUFSZ) != NULL) {
	    (void) snprintf(str, len, "%s", proj.pj_name);
	} else {
	    log_err("getprojbyid(projid=%ld,..)", (long)projid);
	    (void) snprintf(str, len, "%-6ld", (long)projid);
	}

}


void
napms(int ms)
{

	(void) poll(NULL, 0, ms);
}

longlong_t get_timestamp() {
	struct timeval tv;
	struct timezone tz;

	(void) gettimeofday(&tv, &tz);
	return (tv.tv_usec  + ((longlong_t)tv.tv_sec * MICROSEC));
}


static FILE *logf = NULL;
static char buf[RDS_MAXLINE];
static hrtime_t hrt_base = 0;
static int call_cnt = 0;
static int bytes_written = 0;

void
log_open(char *file)
{
	if (strcmp(file, "stderr") == 0)
		logf = stderr;
	else
		logf = fopen(file, "w+");
}


void
log_close()
{
	if (logf != NULL && logf != stderr)
		(void) fclose(logf);
}


/*PRINTFLIKE1*/
void
log_msg(char *fmt, ...)
{
	va_list	ap;
	int n;
	hrtime_t hrt;

	if (logf == NULL)
		return;
	if (pthread_mutex_lock(&logLock) == 0) {
	    if (logf != stderr && bytes_written > RDS_MAXLOG_FILE) {
		bytes_written = 0;
		rewind(logf);
	    }

	    if (hrt_base == 0)
		hrt_base =  gethrtime() / 1000000;

	    hrt = gethrtime() / 1000000;
	    va_start(ap, fmt);
	    (void) vsnprintf(buf, RDS_MAXLINE, fmt, ap);
	    if ((n = fprintf(logf, "%4d:%08lld ms:%s",
			call_cnt++, hrt - hrt_base, buf)) != -1)
		bytes_written += n;
	    (void) fflush(logf);
	    va_end(ap);

	    if (pthread_mutex_unlock(&logLock) != 0)
		perror("log pthread_mutex_unlock");

	} else
	    perror("log pthread_mutex_lock");
}

/*PRINTFLIKE1*/
void
log_err(char *fmt, ...)
{
	va_list	ap;
	int n;
	hrtime_t hrt;
	int err = errno;

	if (logf == NULL)
		return;
	if (pthread_mutex_lock(&logLock) == 0) {
	    if (logf != stderr && bytes_written > RDS_MAXLOG_FILE) {
		    bytes_written = 0;
		    rewind(logf);
	    }

	    if (hrt_base == 0)
		    hrt_base =  gethrtime() / 1000000;

	    hrt = gethrtime() / 1000000;
	    va_start(ap, fmt);
	    (void) vsnprintf(buf, RDS_MAXLINE, fmt, ap);
	    if ((n = fprintf(logf, "%4d:%08lld ms:ERROR: %s: (errno %d), %s\n",
			    call_cnt++, hrt - hrt_base, buf, err,
			    (err != 0) ? strerror(err) : "")) != -1)
		    bytes_written += n;
	    (void) fflush(logf);
	    va_end(ap);

	    if (pthread_mutex_unlock(&logLock) != 0)
		perror("log pthread_mutex_unlock");

	} else
	    perror("log pthread_mutex_lock");
}
