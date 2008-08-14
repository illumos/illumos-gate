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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <pthread.h>
#include <limits.h>
#include <ctype.h>
#include "mms_strapp.h"
#include "mms_trace.h"
#include <sys/wait.h>

#define	MMS_LN_MAX 1000	/* max num of chars in a trace line before newline */
#define	MMS_LN_MIN 500	/* min num of chars for pretty line */

static	char		*_SrcFile = __FILE__;
static	char		mms_trace_filename[256];
static	int		mms_trace_fd = -1;
static	mms_trace_id_t	mms_trace_id;
static	mms_trace_sev_t	mms_trace_sev = MMS_SEV_ERROR;
static	uint64_t	mms_trace_size = 0;
static	uint64_t	mms_trace_rot_size = 10485760;	/* 10M */
static	pthread_mutex_t	mms_trace_mutex;
static	int		mms_conf = 1;
static	int		mms_aborting = 0;

static	char    *mms_trace_sevstr[] = {
	"EMERG", "ALERT", "CRIT", "OPER", "ERROR", "WARN", "NOTICE",
	"INFO", "DEBUG", "DEVP", NULL
};

static	char    *mms_trace_idstr[] = {
	"MM", "LM", "DM ", "DMD", "WCR", "API", "LM_ND", "CLI", NULL
};

static	char	*mms_trace_level[] = {
	"emergency", "alert", "critical", "operational", "error",
	"warning", "notice", "information", "debug", "developer", NULL
};

static	int	mms_trace_sig[] = {
	SIGILL,
	SIGFPE,
	SIGBUS,
	SIGSEGV,
	SIGSYS,
	0,
};

static void
mms_trace_setup_logadm()
{
	pid_t	shpid;
	char	size[20];

	(void) snprintf(size, sizeof (size), "%lldb", mms_trace_rot_size);
	if ((shpid = fork()) < 0) {
		mms_trace(MMS_DEBUG,
		    "mms_trace_setup_logadm: fork failed");
		return;
	} else if (shpid == 0) { /* child */
		int	fd;
		fd = open(MMS_LOGADM_CONF, O_RDWR);
		if (fd >= 0) {
			(void) lockf(fd, F_LOCK, 1);
		}
		(void) execl(MMS_LOGADM, MMS_LOGADM,
		    "-f", MMS_LOGADM_CONF,
		    "-s", size,
		    "-w", mms_trace_filename,
		    mms_trace_filename,
		    (char *)0);
		exit(1);
	}
	if (waitpid(shpid, NULL, 0) < 0) /* parent */
		mms_trace(MMS_DEBUG,
		    "mms_trace_setup_logadm: wait failed");
}

static void
mms_trace_signal(int sig, void (*handler)())
{
	/*
	 * Setup to catch signals
	 */
	struct sigaction	act, oact;

	(void) memset(&act, 0, sizeof (act));
	act.sa_sigaction = handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sig != SIGALRM) {
		/*
		 * Allow alarm signal to interrupt
		 */
		act.sa_flags |= SA_RESTART;
	}
	(void) sigaction(sig, &act, &oact);
}

/*
 * Catch the signals caused by programming error here and flush
 * the mms_trace buffer before aborting.
 */
static void
mms_trace_sighandler(int sig)
{
	syslog(LOG_ERR, "mms mms_trace_sighandler >>>>> Caught Signal %d, "
	    "Aborting <<<<<", sig);
	mms_trace_flush();
	mms_aborting = 1;
	mms_trace_close();
	abort();
}

/*
 * Open mms_trace file with id prefix.
 */
/*
 * function name:
 *	mms_trace_open
 *
 * Parameters:
 *	filename	trace file name
 *	id		id of the component
 *	severity	severity above which will be traced
 *	rot_size	rotation size
 *	sig		1 - if trace will cat abort signals
 *			0 - if trace will not catch signals
 *	conf		1 - if dm_trace_close will remove trace entry from
 *				logadm.conf
 *			0 - 	if dm_trace_close will not remove trace entry
 *				from logadm.conf
 *
 * Description:
 *	open a trace file
 *
 * Note:
 *
 *
 */

int
mms_trace_open(char *filename, mms_trace_id_t id, int severity,
    int64_t rot_size, int sig, int conf)
{
	int		oflags = O_CREAT | O_RDWR | O_APPEND;
	int		i;
	struct stat	buf;

	/* Make sure that mms_trace_open has not already been */
	/* opened */

	mms_conf = conf;

	if (mms_trace_get_fd() != -1) {
		return (1);
	}

	if (filename == NULL) {
		return (1);
	}

	if (severity != -1 &&
	    (severity < MMS_SEV_EMERG || severity > MMS_SEV_DEVP)) {
		return (1);
	}

	if (sig != 0) {
		for (i = 0; mms_trace_sig[i] != 0; i++) {
			mms_trace_signal(mms_trace_sig[i],
			    mms_trace_sighandler);
		}
	}

	if (pthread_mutex_init(&mms_trace_mutex, NULL) != 0) {
		return (1);
	}

	if (stat(filename, &buf) != 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
			char	name[128];
			char	*p;

			(void) strncpy(name, filename, sizeof (name));
			if ((p = strrchr(name, '/')) != NULL) {
				*p = '\0';
				if (stat(name, &buf) != 0)
					(void) mkdir(name, 0777);
			}
		}
	}

	if (id == MMS_ID_ND) {
		mms_trace_fd = STDERR_FILENO;
	} else if (id >= MMS_ID_MM && id <= MMS_ID_CLI) {
		if ((mms_trace_fd = open(filename, oflags, 0644)) < 0) {
			return (-1);
		}
	} else {
		return (1);
	}

	mms_trace_id = id;
	if (rot_size != -1)
		mms_trace_rot_size = rot_size;
	if (severity != -1)
		(void) mms_trace_filter(severity);

	/* Save mms_trace's filename for when file rotation takes place */
	(void) strcpy(mms_trace_filename, filename);
	/* Obtain initial size of mms_trace file for rotation */
	if (fstat(mms_trace_fd, &buf) == 0)
		mms_trace_size = buf.st_size;

	/*
	 * Setup mms_logadm.conf for this file
	 */
	if (conf) {
		mms_trace_setup_logadm();
	}

	return (0);
}

/*
 * Return mms_trace file descriptor.
 */
int
mms_trace_get_fd(void)
{
	return (mms_trace_fd);
}

/*
 * Function name:
 *	mms_trace_close
 *
 *
 * Parameters:
 *	none
 *
 *
 * Description:
 *	close a trace file.
 *	if mms_conf is 1 (set in mms_trace_open) then entry in logadm.conf
 *	for this trace file will be removed.
 *	If mms_trace_close is called during an abort from
 *	mms_trace_sighandler don't call mms_strapp,
 *	the malloc maydead lock if another thread aborted
 *	inside of malloc
 *
 * Note:
 *
 *
 */
void
mms_trace_close(void)
{
	pid_t	shpid;

	if (!mms_aborting && mms_conf) {
		if ((shpid = fork()) < 0) {
			mms_trace(MMS_DEBUG,
			    "mms_trace_close: fork failed");
			(void) close(mms_trace_fd);
			mms_trace_fd = -1;
			return;
		} else if (shpid == 0) { /* child */
			int	fd;
			fd = open(MMS_LOGADM_CONF, O_RDWR);
			if (fd >= 0) {
				(void) lockf(fd, F_LOCK, 1);
			}
			(void) execl(MMS_LOGADM, MMS_LOGADM,
			    "-f", MMS_LOGADM_CONF,
			    "-r", mms_trace_filename,
			    mms_trace_filename,
			    (char *)0);
			exit(1);
		}
		if (waitpid(shpid, NULL, 0) < 0) /* parent */
			mms_trace(MMS_DEBUG,
			    "mms_trace_close: wait failed");
	}
	(void) close(mms_trace_fd);
	mms_trace_fd = -1;
}

/*
 * Set mms_trace id prefix.
 */
void
mms_trace_set_id(mms_trace_id_t id)
{
	if (id < MMS_ID_MM || id > MMS_ID_CLI) {
		return;
	}
	mms_trace_id = id;
}

/*
 * Get mms_trace id prefix.
 */
mms_trace_id_t
mms_trace_get_id(void)
{
	return (mms_trace_id);
}

/*
 * Get mms_trace serverity setting.
 */
mms_trace_sev_t
mms_trace_get_severity(void)
{
	return (mms_trace_sev);
}

/*
 * Write variable number of args to mms_trace file.
 */
void
mms_trace(mms_trace_sev_t severity, char *file, int line, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	mms_trace_va(severity, file, line, fmt, args);
	va_end(args);
}

/*
 * Write arg list to mms_trace file.
 */
void
mms_trace_va(mms_trace_sev_t severity, char *file, int line,
    const char *fmt, va_list args)
{
	char		date[100];
	time_t		tm;
	char		*buf;
	char		*str;
	struct iovec	 iov[IOV_MAX];
	int		len;
	int		num_iov;
	int		off;
	int		i;
	const char	*newline = "\n";
	int		 oflags = O_CREAT | O_RDWR | O_APPEND;
	struct tm	 ltime;
	pid_t		shpid;
	char		size[20];

	if (severity < MMS_SEV_EMERG || severity > MMS_SEV_DEVP) {
		return;		/* invalid severity */
	}
	if (severity > mms_trace_sev) {
		return;		/* not tracing this severity level */
	}

	if (pthread_mutex_lock(&mms_trace_mutex) != 0)
		return;

	/*
	 * Put mms_trace info into a write buffer
	 */
	(void) time(&tm);
	(void) localtime_r(&tm, &ltime);
	(void) strftime(date, 100, "%Y/%m/%d %H:%M:%S", &ltime);
	if ((buf = mms_strnew("%s %s %s [%d,%d] %s:%d ", date,
	    mms_trace_idstr[mms_trace_id], mms_trace_sevstr[severity],
	    getpid(), pthread_self(), file, line)) == NULL) {
		(void) pthread_mutex_unlock(&mms_trace_mutex);
		return;
	}

	if ((str = mms_vstrapp(buf, fmt, args)) == NULL) {
		free(buf);
		(void) pthread_mutex_unlock(&mms_trace_mutex);
		return;
	}
	buf = str;
	len = strlen(buf);
	if (buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
		len--;
	}
	num_iov = 2 * (IOV_MAX / 2);

	for (off = 0; off < len; ) {
		for (i = 0; i < num_iov && off < len;
		    i += 2, off += MMS_LINE_SIZE) {
			iov[i].iov_base = (caddr_t)buf + off;
			if ((len - off) >= MMS_LINE_SIZE) {
				iov[i].iov_len = MMS_LINE_SIZE;
			} else {
				iov[i].iov_len = len - off;
			}
			iov[i+1].iov_base = (caddr_t)newline;
			iov[i+1].iov_len = strlen(newline);
		}
		(void) writev(mms_trace_fd, iov, i);
	}

	mms_trace_size += len;

	free(buf);

	if (mms_trace_size > mms_trace_rot_size) {
		mms_trace_flush();
		(void) close(mms_trace_fd);
		if ((shpid = fork()) < 0) {
			mms_trace(MMS_DEBUG,
			    "mms_trace_va: fork failed");
			return;
		} else if (shpid == 0) { /* child */
			(void) snprintf(size, sizeof (size), "%lldb",
			    mms_trace_rot_size);
			(void) execl(MMS_LOGADM, MMS_LOGADM,
			    "-f", MMS_LOGADM_CONF,
			    "-s", size,
			    mms_trace_filename,
			    (char *)0);
			exit(1);
		}
		if (waitpid(shpid, NULL, 0) < 0) /* parent */
			mms_trace(MMS_DEBUG,
			    "mms_trace_va: wait failed");

		mms_trace_size = 0;
		mms_trace_fd = open(mms_trace_filename, oflags, 0644);
	}
	(void) pthread_mutex_unlock(&mms_trace_mutex);
}

/*
 * Set tracing severity level.
 */
int
mms_trace_filter(mms_trace_sev_t severity)
{
	if (severity < MMS_SEV_EMERG || severity > MMS_SEV_DEVP) {
		mms_trace(MMS_ERR, "Invalid mms_trace serverity: %d", severity);
		return (1);	/* invalid severity */
	}

	if (severity < MMS_SEV_ERROR)
			/* Cannot mask levels EMERG through OPER */
		mms_trace_sev = MMS_SEV_OPER;
	else
		mms_trace_sev = severity;
	return (0);
}

/*
 * Set tracing severity level.
 */
int
mms_trace_str_filter(char *level)
{
	mms_trace_sev_t	severity;

	if (level == NULL) {
		return (1);
	} else if (strcmp(level, "emergency") == 0) {
		severity = MMS_SEV_EMERG;
	} else if (strcmp(level, "alert") == 0) {
		severity = MMS_SEV_ALERT;
	} else if (strcmp(level, "critical") == 0) {
		severity = MMS_SEV_CRIT;
	} else if (strcmp(level, "operational") == 0) {
		severity = MMS_SEV_OPER;
	} else if (strcmp(level, "error") == 0) {
		severity = MMS_SEV_ERROR;
	} else if (strcmp(level, "warning") == 0) {
		severity = MMS_SEV_WARN;
	} else if (strcmp(level, "notice") == 0) {
		severity = MMS_SEV_NOTICE;
	} else if (strcmp(level, "information") == 0) {
		severity = MMS_SEV_INFO;
	} else if (strcmp(level, "debug") == 0) {
		severity = MMS_SEV_DEBUG;
	} else if (strcmp(level, "developer") == 0) {
		severity = MMS_SEV_DEVP;
	} else {
		return (1);
	}
	return (mms_trace_filter(severity));
}

int
mms_trace_str2sev(char *level, mms_trace_sev_t *severity)
{
	int	rc = 0;

	if (level == NULL) {
		*severity = MMS_SEV_DEBUG;
		rc = 1;
	} else if (strcmp(level, "emergency") == 0) {
		*severity = MMS_SEV_EMERG;
	} else if (strcmp(level, "alert") == 0) {
		*severity = MMS_SEV_ALERT;
	} else if (strcmp(level, "critical") == 0) {
		*severity = MMS_SEV_CRIT;
	} else if (strcmp(level, "operational") == 0) {
		*severity = MMS_SEV_OPER;
	} else if (strcmp(level, "error") == 0) {
		*severity = MMS_SEV_ERROR;
	} else if (strcmp(level, "warning") == 0) {
		*severity = MMS_SEV_WARN;
	} else if (strcmp(level, "notice") == 0) {
		*severity = MMS_SEV_NOTICE;
	} else if (strcmp(level, "information") == 0) {
		*severity = MMS_SEV_INFO;
	} else if (strcmp(level, "debug") == 0) {
		*severity = MMS_SEV_DEBUG;
	} else if (strcmp(level, "developer") == 0) {
		*severity = MMS_SEV_DEVP;
	} else {
		*severity = MMS_SEV_DEBUG;
		rc = 1;
	}
	return (rc);
}

char *
mms_trace_sev2str(mms_trace_sev_t severity)
{
	char	*level;

	if (severity < MMS_SEV_EMERG || severity > MMS_SEV_DEVP) {
		level = NULL;
	} else {
		level = mms_trace_level[severity];
	}
	return (level);
}

/* This routine is used to obtain the severity level for the */
/* MMS internal message scheme. When MM sends a private command */
/* to set or change the message levels that a LM or DM will send, */
/* it sends it in a string. This routine converts that string into */
/* an enumeration associated with the string. By default it sets */
/* the the level to ERROR */

mms_msg_sev_t
mms_msg_get_severity(char *level)
{

	if (level == NULL) {
		mms_trace(MMS_DEBUG,
		    "mms_msg_get_severity: null string filter");
		return (MMS_MSG_SEV_ERROR);
	} else if (strcmp(level, "emergency") == 0) {
		return (MMS_MSG_SEV_EMERG);
	} else if (strcmp(level, "alert") == 0) {
		return (MMS_MSG_SEV_ALERT);
	} else if (strcmp(level, "critical") == 0) {
		return (MMS_MSG_SEV_CRIT);
	} else if (strcmp(level, "error") == 0) {
		return (MMS_MSG_SEV_ERROR);
	} else if (strcmp(level, "warning") == 0) {
		return (MMS_MSG_SEV_WARN);
	} else if (strcmp(level, "notice") == 0) {
		return (MMS_MSG_SEV_NOTICE);
	} else if (strcmp(level, "information") == 0) {
		return (MMS_MSG_SEV_INFO);
	} else if (strcmp(level, "debug") == 0) {
		return (MMS_MSG_SEV_DEBUG);
	} else if (strcmp(level, "developer") == 0) {
		return (MMS_MSG_SEV_DEVP);
	} else {
		mms_trace(MMS_DEBUG,
		    "mms_msg_get_severity, invalid string filter: "
		    "%s", level);
		return (MMS_MSG_SEV_ERROR);
	}
}

/*
 * Dump content of memory into a bufer
 */
char *
mms_trace_dump(char *buf, int inlen, char *out, int outlen)
{
	uchar_t	*inbuf = (uchar_t *)buf;
	int	off = 0;
	int	off_start;
	int	bytes;
	uchar_t	*ip;
	int	i;
	int	j;

	ip = inbuf;
	while ((inlen > 0) && ((outlen - off) >  MMS_DUMP_LINE_SIZE)) {
		off_start = off;
		(void) memset(out + off, ' ', MMS_DUMP_LINE_SIZE);
		bytes = inlen > MMS_CHAR_PER_LINE ?
		    MMS_CHAR_PER_LINE : inlen;
		off += sprintf(out + off, "%5.5d ", ip - inbuf);
		for (i = 0; i < bytes; ) {
			for (j = 0; j < 4; j++, i++) {
				off += sprintf(out + off, "%2.2x", ip[i]);
			}
			off += sprintf(out + off, " ");
		}
		out[off] = ' ';
		off = off_start + MMS_CHAR_OFFSET;
		for (i = 0; i < bytes; i++) {
			out[off++] = isprint(ip[i]) ? ip[i] : '.';
		}
		out[off++] = '\n';
		out[off] = '\0';

		inlen -= bytes;
		ip += bytes;
	}
	return (out);
}

/*
 * Flush the mms_trace buffer to disk
 */
void
mms_trace_flush(void)
{
	(void) fsync(mms_trace_fd);
}

#define	MMS_KILO (uint64_t)(1024LL)
#define	MMS_MEGA (uint64_t)(1024LL * 1024)
#define	MMS_GIGA (uint64_t)(1024LL * 1024 * 1024)
#define	MMS_TERA (uint64_t)(1024LL * 1024 * 1024 * 1024)
#define	MMS_PETA (uint64_t)(1024LL * 1024 * 1024 * 1024 * 1024)
#define	MMS_EXA  (uint64_t)(1024LL * 1024 * 1024 * 1024 * 1024 * 1024)

/*
 *	Parse string to get file size.
 */
int
mms_trace_str_to_fsize(
char *string,
uint64_t *size)
{
	char	*p;
	int64_t value;
	double	conv;
	double	frac;

	*size = 0;
	if (*string == '0' && (*(string+1) == 'x' || *(string+1) == 'X' ||
	    isdigit(*(string+1)))) {
		/*
		 * Do hex/octal.
		 */
		errno = 0;
		value = strtoll(string, &p, 0);
		if (*p == '\0' && errno == 0 && value >= 0) {
			*size = value;
			return (0);
		}
		goto err;
	}
	errno = 0;
	conv = strtod(string, &p);
	if (errno != 0 || p == string || conv < 0) {
		goto err;
	}
	value = (int64_t)conv;
	frac = conv - (double)value;
	if (*p == 'K') {
		p++;
		value *= MMS_KILO;
		frac  *= MMS_KILO;
	} else if (*p == 'M') {
		p++;
		value *= MMS_MEGA;
		frac  *= MMS_MEGA;
	} else if (*p == 'G') {
		p++;
		value *= MMS_GIGA;
		frac  *= MMS_GIGA;
	} else if (frac > .09) {
		goto err;
	}
	if (*p != '\0') {
		goto err;
	}
	*size = value + (int64_t)frac;
	return (0);

err:
	if (errno == 0) {
		errno = EINVAL;
	}
	return (-1);
}

/*
 * Set mms_trace file rotation size.
 */
int
mms_trace_set_fsize(
char *size)
{
	uint64_t value;

	if (mms_trace_str_to_fsize(size, &value) == -1) {
		mms_trace(MMS_ERR,
		    "mms_trace_set_fsize: Invalid mms_trace size - %s\n",
		    size);
		return (1);
	} else {
		mms_trace_rot_size = value;
		mms_trace(MMS_DEBUG,
		    "mms_trace_set_fsize: Set mms_trace rotation size to "
		    "%s - %lld\n", size, value);
		mms_trace_setup_logadm();
		return (0);
	}
}
