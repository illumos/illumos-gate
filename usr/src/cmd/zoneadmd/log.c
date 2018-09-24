/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * zoneadmd logging
 *
 * zoneadmd logs to log files under <zonepath>/logs.  Each log entry is a json
 * structure of the form:
 *
 *   {
 *     "log": "some message\n",
 *     "stream": "stderr",
 *     "time": "2018-03-28T13:25:02.670423000Z"
 *   }
 *
 * Unlike the example above, the entries in the log file are not pretty-printed.
 * Messages are processed so that they have the proper json escapes for
 * problematic characters.  Excessively long messages may be truncated.
 *
 * To use these interfaces:
 *
 *	int logid;
 *
 *	logstream_init(zlogp);
 *
 *	logid = logstream_open("stdio.log", "stdout", flags);
 *	...
 *	logstream_write(logid, buf, len);
 *	...
 *	logstream_close(logid);
 *
 * logstream_init() needs to be called only once.
 *
 * logstream_open() opens a log file (if not already open) and associates the
 * specified stream with it.
 *
 * The following flag is supported:
 *
 *   LS_LINE_BUFFERED	Buffer writes until a newline is encountered or the
 *			buffer fills.  This should only be used with streams
 *			that are written to by a single thread.  The timestamp
 *			on log messages are the time that the log entry was
 *			written to the log file.  This means the timestamp is
 *			the time when the console user hits enter, not the time
 *			that the prompt was printed.
 *
 * Line buffering is particularly useful for bhyve console logging because
 * bhyve's UART emulation causes read() calls in zcons.c to return far fewer
 * than 10 characters at a time.  Without line buffering, a small number of
 * logged characters are accompanied by about 64 characters of timestamp and
 * other overhead.  Line buffering saves quite a lot of space and makes the log
 * much easier to read.
 *
 *
 * Log rotation
 *
 * Two attributes, zlog-max-size and zlog-keep-rotated are used for automatic
 * log rotation.  zlog-max-size is the approximate maximum size of a log before
 * it is automatically rotated.  Rotated logs are renamed as
 * <log>.<iso-8601-stamp>.  If zlog-keep-rotated is specified and is an integer
 * greater than zero, only that number of rotated logs will be retained.
 *
 * If zlog-max-size is not specified, log rotation will not happen
 * automatically.  An external log rotation program may rename the log file(s),
 * then send SIGHUP to zoneadmd.
 *
 * Log rotation can be forced with SIGUSR1.  In this case, the log will be
 * rotated as though it hit the maximum size and will be subject to retention
 * rules described above.
 *
 *
 * Locking strategy
 *
 * Callers need not worry about locking.  In the interest of simplicity, a
 * single global lock is used to protect the state of the log files and the
 * associated streams.  Locking is necessary because reboots and log rotations
 * can cause various state changes.  Without locking, races could cause log
 * entries to be directed to the wrong file descriptors.
 *
 * The simplistic global lock complicates error reporting within logging
 * routines.  zerror() must not be called while holding logging_lock.  Rather,
 * logstream_err() should be used to log via syslog.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <synch.h>
#include <syslog.h>
#include <time.h>
#include <thread.h>
#include <unistd.h>

#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/varargs.h>

#include "zoneadmd.h"

/*
 * Currently we only expect stdout, stderr, zoneadmd, and console.  Increase
 * MAX_ZLOG_STREAMS if more streams are added.  If the count increases
 * significantly, logfile_t and logstream_t elements should be dynamically
 * allocated and the algorithms associated with opening and closing them should
 * become more efficient.
 */
#define	MAX_LOG_STREAMS 4

#define	ZLOG_MAXSZ	"zlog-max-size"		/* zonecfg attr */
#define	ZLOG_MAXSZ_MIN	(1024 * 1024)		/* min size for autorotate */
#define	ZLOG_KEEP	"zlog-keep-rotated"	/* zonecfg attr */
#define	ZLOG_KEEP_MAX	1000			/* number of log files */

typedef struct logfile {
	char	lf_path[MAXPATHLEN];	/* log file name (absolute path) */
	char	lf_name[MAXNAMELEN];	/* tail of log file name */
	int	lf_fd;			/* file descriptor */
	size_t	lf_size;		/* Current size */
	boolean_t lf_write_err;		/* Avoid spamming console via logsys */
	boolean_t lf_closing;		/* Avoid rotation recursion */
} logfile_t;

typedef struct logstream {
	char		ls_stream[MAXNAMELEN];	/* stdout, stderr, etc. */
	char		ls_buf[BUFSIZ * 2];	/* Not-yet written data, json */
	int		ls_buflen;
	logstream_flags_t ls_flags;
	logfile_t	*ls_logfile;		/* N streams per log file */
} logstream_t;

typedef struct jsonpair {
	const char *jp_key;
	const char *jp_val;
} jsonpair_t;

boolean_t logging_poisoned = B_FALSE;

/*
 * MAX_LOG_STREAMS is a small number so we allocate in the simplest way.
 */
static logstream_t streams[MAX_LOG_STREAMS];
static logfile_t logfiles[MAX_LOG_STREAMS];

static boolean_t logging_initialized = B_FALSE;
static uint64_t logging_rot_size;		/* See ZLOG_MAXSZ */
static uint64_t logging_rot_keep;		/* See ZLOG_KEEP */
static int logging_pending_sig = 0;		/* Signal recvd while logging */
static mutex_t logging_lock;			/* The global logging lock */

static void logstream_flush_all(logfile_t *);
static void logstream_sighandler(int);
static void rotate_log(logfile_t *);
static size_t make_json(jsonpair_t *, int, char *, size_t);
static void logfile_write(logfile_t *, const char *, size_t);

/*
 * If errors are encountered while logging_lock is held, we can't use zerror().
 */
static void
logstream_err(boolean_t use_strerror, const char *fmt, ...)
{
	va_list alist;
	char buf[MAXPATHLEN * 2];
	char *bp;
	int saved_errno = errno;

	(void) snprintf(buf, sizeof (buf), "[zone %s] ", zone_name);

	bp = &buf[strlen(buf)];

	va_start(alist, fmt);
	(void) vsnprintf(bp, sizeof (buf) - (bp - buf), fmt, alist);
	va_end(alist);

	if (use_strerror) {
		bp = &buf[strlen(buf)];
		(void) snprintf(bp, sizeof (buf) - (bp - buf), ": %s",
		    strerror(saved_errno));
	}
	syslog(LOG_ERR, "%s", buf);

	errno = saved_errno;
}

static void
logstream_lock(void)
{
	int ret;

	assert(logging_initialized && !logging_poisoned);

	ret = mutex_lock(&logging_lock);
	assert(ret == 0);
}

static void
logstream_unlock(void)
{
	int ret;
	int err = errno;
	int sig = logging_pending_sig;

	logging_pending_sig = 0;
	ret = mutex_unlock(&logging_lock);
	assert(ret == 0);

	/*
	 * If a signal arrived while this thread was holding the lock, call the
	 * handler.
	 */
	if (sig != 0) {
		logstream_sighandler(sig);
	}

	errno = err;
}

static void
logfile_write_event(logfile_t *lfp, const char *stream, const char *event)
{
	char buf[BUFSIZ];
	size_t len;
	jsonpair_t pairs[] = {
		{ "event", event },
		{ "stream", stream }
	};

	len = make_json(pairs, ARRAY_SIZE(pairs), buf, sizeof (buf));
	if (len >= sizeof (buf)) {
		logstream_err(B_FALSE, "%s: buffer too small. Need %llu bytes, "
		    "have %llu bytes", __func__, len + 1, sizeof (buf));
		return;
	}

	logfile_write(lfp, buf, len);
}

static void
close_log(logfile_t *lfp, const char *why)
{
	int err;

	assert(MUTEX_HELD(&logging_lock));

	/*
	 * Something may have gone wrong during log rotation, leading to a
	 * zombie log.
	 */
	if (lfp->lf_fd == -1) {
		return;
	}

	lfp->lf_closing = B_TRUE;

	logstream_flush_all(lfp);

	logfile_write_event(lfp, "logfile", why);

	err = close(lfp->lf_fd);
	assert(err == 0);

	lfp->lf_size = 0;
	lfp->lf_fd = -1;
}

static void
open_log(logfile_t *lfp, const char *why)
{
	struct stat64 sb;
	int err;

	assert(MUTEX_HELD(&logging_lock));
	assert(lfp->lf_fd == -1);

	lfp->lf_fd = open(lfp->lf_path,
	    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (lfp->lf_fd == -1) {
		logstream_err(B_TRUE, "Cannot open log file %s",
		    lfp->lf_path);
		lfp->lf_write_err = B_TRUE;
		return;
	}

	err = fstat64(lfp->lf_fd, &sb);
	assert(err == 0);
	lfp->lf_size = sb.st_size;
	lfp->lf_write_err = B_FALSE;
	lfp->lf_closing = B_FALSE;

	logfile_write_event(lfp, "logfile", why);
}

static void
logstream_sighandler(int sig)
{
	int i;

	/*
	 * Protect against recursive mutex enters when a signal comes during
	 * logging.  This will cause this function to be called again just after
	 * this thread drops the lock.
	 */
	if (MUTEX_HELD(&logging_lock)) {
		logging_pending_sig = sig;
		return;
	}

	logstream_lock();
	if (logging_poisoned) {
		logstream_unlock();
		return;
	}

	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		/* Inactive logfile slot */
		if (logfiles[i].lf_name[0] == '\0') {
			continue;
		}

		switch (sig) {
		case SIGHUP:
			close_log(&logfiles[i], "close-rotate");
			open_log(&logfiles[i], "open-rotate");
			break;
		case SIGUSR1:
			rotate_log(&logfiles[i]);
			break;
		default:
			logstream_err(B_FALSE, "unhandled signal %d", sig);
		}
	}

	logstream_unlock();
}

static void
get_attr_uint64(zlog_t *zlogp, zone_dochandle_t handle, const char *name,
    uint64_t max, uint64_t *valp)
{
	struct zone_attrtab tab = { 0 };
	char *p;
	uint64_t val;

	ASSERT(!MUTEX_HELD(&logging_lock));

	(void) strlcpy(tab.zone_attr_name, name, sizeof (tab.zone_attr_name));
	if (zonecfg_lookup_attr(handle, &tab) != Z_OK) {
		return;
	}

	errno = 0;
	val = strtol(tab.zone_attr_value, &p, 10);
	if (errno != 0 && *p == '\0') {
		zerror(zlogp, errno != 0, "Bad value '%s' for 'attr name=%s'",
		    tab.zone_attr_value, tab.zone_attr_name);
		return;
	}
	if (val > max) {
		zerror(zlogp, B_FALSE, "Value of attr '%s' is too large. "
		    "Reducing to %llu", name, max);
		val = max;
	}

	*valp = val;
}

static void
logstream_atfork_prepare(void)
{
	logstream_lock();
}

static void
logstream_atfork_parent(void)
{
	logstream_unlock();
}

/*
 * logstream_*() should never be called in a child process, so we make sure this
 * code is never called there.
 *
 * zerror() in a child process is still safe: it knows to check for poisoning,
 * and in such a case will redirect its output to stderr on the presumption it
 * is a pipe to the parent.
 */
static void
logstream_atfork_child(void)
{
	logging_poisoned = B_TRUE;
	logging_pending_sig = 0;
	logstream_unlock();
}

void
logstream_init(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	int err;
	int i;

	assert(!logging_initialized);

	err = mutex_init(&logging_lock, USYNC_THREAD | LOCK_ERRORCHECK, 0);
	assert(err == 0);

	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		logfiles[i].lf_fd = -1;
	}

	err = pthread_atfork(logstream_atfork_prepare,
	    logstream_atfork_parent, logstream_atfork_child);
	assert(err == 0);

	logging_initialized = B_TRUE;

	/* Now it is safe to use zlogp */

	if ((handle = zonecfg_init_handle()) == NULL ||
	    zonecfg_get_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "failed to open zone configuration "
		    "while initializing logging");
	} else {
		get_attr_uint64(zlogp, handle, ZLOG_MAXSZ, UINT64_MAX,
		    &logging_rot_size);
		if (logging_rot_size != 0 &&
		    logging_rot_size < ZLOG_MAXSZ_MIN) {
			zerror(zlogp, B_FALSE, "%s value %llu is too small. "
			    "Setting to %d", ZLOG_MAXSZ, logging_rot_size,
			    ZLOG_MAXSZ_MIN);
			logging_rot_size = ZLOG_MAXSZ_MIN;
		}
		get_attr_uint64(zlogp, handle, ZLOG_KEEP, ZLOG_KEEP_MAX,
		    &logging_rot_keep);
	}

	zonecfg_fini_handle(handle);

	/*
	 * This thread should receive SIGHUP so that it can close the log
	 * file and reopen it during log rotation.  SIGUSR1 can be used to force
	 * a log rotation.
	 */
	sigset(SIGHUP, logstream_sighandler);
	sigset(SIGUSR1, logstream_sighandler);
}

/*
 * Rotate a single log file.  The global lock must be held while this is called.
 */
static void
rotate_log(logfile_t *lfp)
{
	time_t t;
	struct tm gtm;
	char path[MAXPATHLEN];
	int64_t i;
	size_t len;
	glob_t glb = { 0 };
	int err;

	assert(MUTEX_HELD(&logging_lock));

	if (lfp->lf_closing) {
		return;
	}

	if ((t = time(NULL)) == (time_t)-1 || gmtime_r(&t, &gtm) == NULL) {
		logstream_err(B_TRUE, "failed to format time");
		return;
	}

	(void) snprintf(path, sizeof (path), "%s.%04d%02d%02dT%02d%02d%02dZ",
	    lfp->lf_path, gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday,
	    gtm.tm_hour, gtm.tm_min, gtm.tm_sec);

	if (rename(lfp->lf_path, path) != 0) {
		logstream_err(B_TRUE, "failed to rotate log file "
		    "'%s' to '%s'", lfp->lf_path, path);
	}

	close_log(lfp, "close-rotate");
	open_log(lfp, "open-rotate");

	if (logging_rot_keep == 0) {
		return;
	}

	/*
	 * Remove old logs.
	 */
	len = snprintf(path, sizeof (path),
	    /* <lf_path>.YYYYmmdd */
	    "%s.[12][0-9][0-9][0-9][01][0-9][0-3][0-9]"
	    /* THHMMSSZ */
	    "T[012][0-9][0-5][0-9][0-6][0-9]Z", lfp->lf_path);
	if (len >= sizeof (path)) {
		logstream_err(B_FALSE, "log rotation glob too long");
		return;
	}

	if ((err = glob(path, GLOB_LIMIT, NULL, &glb)) != 0) {
		if (err != GLOB_NOMATCH) {
			logstream_err(B_TRUE, "glob terminated with error %d",
			    err);
		}
		globfree(&glb);
		return;
	}

	if (glb.gl_pathc <= logging_rot_keep) {
		globfree(&glb);
		return;
	}

	for (i = glb.gl_pathc - logging_rot_keep - 1; i >= 0; i--) {
		if (unlink(glb.gl_pathv[i]) != 0) {
			logstream_err(B_TRUE, "log rotation could not remove "
			    "%s", glb.gl_pathv[i]);
		}
	}
	globfree(&glb);
}

/*
 * Modify the input string with json escapes. Since the destination can thus
 * be larger than the source, multiple calls may be required to fully convert
 * sbuf to json.
 *
 *   sbuf, slen		Source buffer and the number of bytes in it to process
 *   dbuf, dlen		Destination buffer and its size.  On return, the result
 *			is always null terminated.
 *   scntp		On return, *scntp stores number of scnt bytes consumed
 *   dcntp		On return, *dcntp stores number of bytes stored in dcnt,
 *			excluding trailing nul.
 *   flushp		If non-NULL, line-buffered mode is enabled.  Processing
 *			will stop at the first newline or when obuf is full and
 *			*flushp will be set to B_TRUE.
 *
 * This function makes no attempt to handle wide characters properly because
 * the messages that come in may be using any character encoding.  Since
 * characters other than 7-bit ASCII are not directly readable in the log
 * anyway, it is better to log the raw data and leave it to specialized log
 * readers to interpret non-ASCII data.
 */
static void
escape_json(const char *sbuf, int slen, char *dbuf, int dlen, int *scntp,
    int *dcntp, boolean_t *flushp)
{
	int i;
	char c;
	const char *save_sbuf = sbuf;
	const char *sbuf_end = sbuf + slen - 1;
	char append_buf[7];			/* "\\u0000\0" */
	const char *append;
	int len;

	if (flushp != NULL) {
		*flushp = B_FALSE;
	}

	i = 0;
	while (i < (dlen - 1) && sbuf <= sbuf_end) {
		c = sbuf[0];

		switch (c) {
		case '\\':
			append = "\\\\";
			break;

		case '"':
			append = "\\\"";
			break;

		case '\b':
			append = "\\b";
			break;

		case '\f':
			append = "\\f";
			break;

		case '\n':
			append = "\\n";
			if (flushp != NULL) {
				*flushp = B_TRUE;
			}
			break;

		case '\r':
			append = "\\r";
			break;

		case '\t':
			append = "\\t";
			break;

		default:
			if (c >= 0x20 && c < 0x7f) {
				append_buf[0] = c;
				append_buf[1] = '\0';
			} else {
				len = snprintf(append_buf, sizeof (append_buf),
				    "\\u%04x", (int)(0xff & c));
				assert(len < sizeof (append_buf));
			}
			append = append_buf;
			break;
		}

		len = strlcpy(&dbuf[i], append, dlen - i);
		if (len >= dlen - i) {
			if (flushp != NULL) {
				*flushp = B_TRUE;
			}
			break;
		} else {
			sbuf++;
			i += len;
		}
		if (flushp != NULL && *flushp) {
			break;
		}
	}

	dbuf[i] = '\0';

	*dcntp = i;
	*scntp = sbuf - save_sbuf;

	assert(*dcntp < dlen);
	assert(*scntp <= slen);

	/* Buffer is too full to append "\\n". Force a flush. */
	if (flushp != NULL && i >= dlen - 2) {
		*flushp = B_TRUE;
	}
}

/*
 * Like write(2), but to a logfile_t and with retries on short writes.
 */
static void
logfile_write(logfile_t *lfp, const char *buf, size_t buflen)
{
	ssize_t wlen;
	size_t wanted = buflen;

	while (buflen > 0) {
		wlen = write(lfp->lf_fd, buf, buflen);
		if (wlen == -1) {
			if (lfp->lf_write_err) {
				lfp->lf_write_err = B_TRUE;
				logstream_err(B_TRUE, "log file fd %d '%s': "
				    "failed to write %llu of %llu bytes",
				    lfp->lf_fd, lfp->lf_path, buflen, wanted);
			}
			return;
		}
		buf += wlen;
		buflen -= wlen;
		lfp->lf_size += wlen;

		lfp->lf_write_err = B_FALSE;
	}

	if (logging_rot_size != 0 && lfp->lf_size > logging_rot_size) {
		rotate_log(lfp);
	}
}

/*
 * Convert the json pairs into a json object.  A "time" element is added to
 * every object.  Returns the number of bytes that would have been written to
 * buf if bufsz had buf been sufficiently large (excluding the terminating null
 * byte).  Like snprintf().
 */
static size_t
make_json(jsonpair_t *pairs, int npairs, char *buf, size_t bufsz)
{
	struct tm gtm;
	struct timeval tv;
	char ts[32];
	size_t len = 0;
	int i;
	const char *key, *val, *start, *end;

	assert(npairs > 0);

	if (gettimeofday(&tv, NULL) != 0 ||
	    gmtime_r(&tv.tv_sec, &gtm) == NULL) {
		logstream_err(B_TRUE, "failed to get time of day");
		abort();
	}

	if (snprintf(ts, sizeof (ts), "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
	    gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday,
	    gtm.tm_hour, gtm.tm_min, gtm.tm_sec, tv.tv_usec * 1000) >=
	    sizeof (ts)) {
		logstream_err(B_FALSE, "timestamp buffer too small");
		abort();
	}

	start = "{";
	end = "";
	for (i = 0; i <= npairs; i++) {
		if (i < npairs) {
			key = pairs[i].jp_key;
			val = pairs[i].jp_val;
		} else {
			key = "time";
			val = ts;
			end = "}\n";
		}

		len += snprintf(bufsz > len ? buf + len : NULL,
		    bufsz > len ? bufsz - len : 0, "%s\"%s\":\"%s\"%s",
		    start, key, val, end);

		start = ",";
	}

	return (len);
}

static void
logstream_write_json(logstream_t *lsp)
{
	char obuf[sizeof (lsp->ls_buf) + sizeof (lsp->ls_stream) + 64];
	size_t len;
	jsonpair_t pairs[] = {
		{ "log", lsp->ls_buf },
		{ "stream", lsp->ls_stream },
	};

	if (lsp->ls_buflen == 0) {
		return;
	}

	len = make_json(pairs, ARRAY_SIZE(pairs), obuf, sizeof (obuf));
	lsp->ls_buflen = 0;
	if (len >= sizeof (obuf)) {
		logstream_err(B_FALSE, "%s: buffer too small. Need %llu bytes, "
		    "have %llu bytes", __func__, len + 1, sizeof (obuf));
		return;
	}

	logfile_write(lsp->ls_logfile, obuf, len);
}

/*
 * We output to the log file as json.
 * ex. for string 'msg\n' on the zone's stdout:
 *    {"log":"msg\n","stream":"stdout","time":"2014-10-24T20:12:11.101973117Z"}
 *
 * We use ns in the last field of the timestamp for compatibility.
 *
 * We keep track of the size of the log file and rotate it when we exceed
 * the log size limit (if one is set).
 */
void
logstream_write(int ls, char *buf, int len)
{
	logstream_t *lsp;
	int scnt, dcnt;
	boolean_t newline;
	boolean_t buffered;

	if (ls == -1 || len == 0) {
		return;
	}
	assert(ls >= 0 && ls < ARRAY_SIZE(streams));

	logstream_lock();

	lsp = &streams[ls];
	if (lsp->ls_stream[0] == '\0' || lsp->ls_logfile == NULL) {
		logstream_unlock();
		return;
	}

	buffered = !!(lsp->ls_flags & LS_LINE_BUFFERED);

	do {
		escape_json(buf, len, lsp->ls_buf + lsp->ls_buflen,
		    sizeof (lsp->ls_buf) - lsp->ls_buflen,
		    &scnt, &dcnt, buffered ? &newline : NULL);

		lsp->ls_buflen += dcnt;
		buf += scnt;
		len -= scnt;

		if (!buffered || newline) {
			logstream_write_json(lsp);
		}
	} while (len > 0 && (!buffered || newline));

	logstream_unlock();
}

static void
logstream_flush(int ls)
{
	logstream_t *lsp;

	assert(MUTEX_HELD(&logging_lock));

	lsp = &streams[ls];
	if (lsp->ls_stream[0] == '\0' || lsp->ls_logfile == NULL) {
		return;
	}
	logstream_write_json(lsp);
}

static void
logstream_flush_all(logfile_t *lfp)
{
	int i;

	assert(MUTEX_HELD(&logging_lock));

	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (streams[i].ls_logfile == lfp) {
			logstream_flush(i);
		}
	}
}

int
logstream_open(const char *logname, const char *stream, logstream_flags_t flags)
{
	int ls = -1;
	int i;
	logstream_t *lsp;
	logfile_t *lfp = NULL;

	assert(strlen(logname) < sizeof (lfp->lf_name));
	assert(strlen(stream) < sizeof (lsp->ls_stream));

	logstream_lock();

	/*
	 * Find an empty logstream_t and verify that the stream is not already
	 * open.
	 */
	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (ls == -1 && streams[i].ls_stream[0] == '\0') {
			assert(streams[i].ls_logfile == NULL);
			ls = i;
			continue;
		}
		if (strcmp(stream, streams[i].ls_stream) == 0) {
			logstream_unlock();
			logstream_err(B_FALSE, "log stream %s already open",
			    stream);
			return (-1);
		}
	}
	assert(ls != -1);

	/* Find an existing or available logfile_t */
	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		if (lfp == NULL && logfiles[i].lf_name[0] == '\0') {
			lfp = &logfiles[i];
		}
		if (strcmp(logname, logfiles[i].lf_name) == 0) {
			lfp = &logfiles[i];
			break;
		}
	}
	if (lfp->lf_name[0] == '\0') {
		(void) strlcpy(lfp->lf_name, logname, sizeof (lfp->lf_name));
		(void) snprintf(lfp->lf_path, sizeof (lfp->lf_path), "%s/logs",
		    zonepath);
		(void) mkdir(lfp->lf_path, 0700);

		(void) snprintf(lfp->lf_path, sizeof (lfp->lf_path),
		    "%s/logs/%s", zonepath, logname);

		open_log(lfp, "open");
		if (lfp->lf_fd == -1) {
			logstream_unlock();
			return (-1);
		}
	}

	lsp = &streams[ls];
	(void) strlcpy(lsp->ls_stream, stream, sizeof (lsp->ls_stream));

	lsp->ls_flags = flags;
	lsp->ls_logfile = lfp;

	logstream_unlock();

	return (ls);
}

void
logstream_close(int ls)
{
	logstream_t *lsp;
	logfile_t *lfp;
	int i;

	if (ls == -1) {
		return;
	}
	assert(ls >= 0 && ls < ARRAY_SIZE(streams));

	logstream_lock();
	logstream_flush(ls);

	lsp = &streams[ls];
	lfp = lsp->ls_logfile;

	assert(lsp->ls_stream[0] != '\0');
	assert(lfp != NULL);

	(void) memset(lsp, 0, sizeof (*lsp));

	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (streams[i].ls_logfile == lfp) {
			logstream_unlock();
			return;
		}
	}

	/* No more streams using this log file so return to initial state */

	close_log(lfp, "close");

	(void) memset(lfp, 0, sizeof (*lfp));
	lfp->lf_fd = -1;

	logstream_unlock();
}
