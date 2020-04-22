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
 * Copyright 2020 Joyent, Inc.
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <libcustr.h>
#include <netdb.h>
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

/*
 * While we could get the numeric value of BUNYAN_LOG_INFO from bunyan.h,
 * the log version is internal to the library, so we just define the values
 * we need here.
 */
#define	BUNYAN_VERSION		0
#define	BUNYAN_LOG_LEVEL	30	/* info */

typedef struct logfile {
	char	lf_path[MAXPATHLEN];	/* log file name (absolute path) */
	char	lf_name[MAXNAMELEN];	/* tail of log file name */
	char	lf_buf[BUFSIZ];		/* Buffer for event messages */
	custr_t	*lf_cus;		/* custr_t wrapper for lf_buf */
	int	lf_fd;			/* file descriptor */
	size_t	lf_size;		/* Current size */
	boolean_t lf_write_err;		/* Avoid spamming console via logsys */
	boolean_t lf_closing;		/* Avoid rotation recursion */
} logfile_t;

/* Large enough to hold BUFSIZ bytes with some escaping */
#define	LS_BUFSZ	(BUFSIZ * 2)

/* Large enough to hold LS_BUF contents + bunyan mandatory properties */
#define	LS_OBUFSZ	(LS_BUFSZ + MAXNAMELEN + 128)

typedef struct logstream {
	char		ls_stream[MAXNAMELEN];	/* stdout, stderr, etc. */
	char		ls_buf[LS_BUFSZ];	/* Not-yet written data, json */
	char		ls_obuf[LS_OBUFSZ];	/* Buffer to form output json */
	custr_t		*ls_cusbuf;	/* custr_t wrapper to ls_buf */
	custr_t		*ls_cusobuf;	/* custr_t wrapper to ls_ofbuf */
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

static char host[MAXHOSTNAMELEN];
static char pidstr[10];

static boolean_t logging_initialized = B_FALSE;
static uint64_t logging_rot_size;		/* See ZLOG_MAXSZ */
static uint64_t logging_rot_keep;		/* See ZLOG_KEEP */
static int logging_pending_sig = 0;		/* Signal recvd while logging */
static mutex_t logging_lock = ERRORCHECKMUTEX;	/* The global logging lock */

static void logstream_flush_all(logfile_t *);
static void logstream_sighandler(int);
static void rotate_log(logfile_t *);
static size_t make_json(jsonpair_t *, size_t, custr_t *);
static void logfile_write(logfile_t *, custr_t *);

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
	VERIFY(logging_initialized);
	VERIFY(!logging_poisoned);

	mutex_enter(&logging_lock);
}

static void
logstream_unlock(void)
{
	int sig = logging_pending_sig;

	logging_pending_sig = 0;
	mutex_exit(&logging_lock);

	/*
	 * If a signal arrived while this thread was holding the lock, call the
	 * handler.
	 */
	if (sig != 0) {
		logstream_sighandler(sig);
	}
}

static void
logfile_write_event(logfile_t *lfp, const char *stream, const char *event)
{
	size_t len;
	jsonpair_t pairs[] = {
		{ "stream", stream },
		{ "msg", event }
	};

	len = make_json(pairs, ARRAY_SIZE(pairs), lfp->lf_cus);
	if (len >= sizeof (lfp->lf_buf)) {
		logstream_err(B_FALSE, "%s: buffer too small. Need %zu bytes, "
		    "have %zu bytes", __func__, len + 1, sizeof (lfp->lf_buf));
		return;
	}

	logfile_write(lfp, lfp->lf_cus);
}

static void
close_log(logfile_t *lfp, const char *why, boolean_t ign_err)
{
	int err;

	VERIFY(MUTEX_HELD(&logging_lock));

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
	if (!ign_err)
		VERIFY0(err);

	lfp->lf_size = 0;
	lfp->lf_fd = -1;
}

static void
open_log(logfile_t *lfp, const char *why)
{
	struct stat64 sb;

	VERIFY(MUTEX_HELD(&logging_lock));
	VERIFY3S(lfp->lf_fd, ==, -1);

	lfp->lf_fd = open(lfp->lf_path,
	    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (lfp->lf_fd == -1) {
		logstream_err(B_TRUE, "Cannot open log file %s",
		    lfp->lf_path);
		lfp->lf_write_err = B_TRUE;
		return;
	}

	VERIFY0(fstat64(lfp->lf_fd, &sb));
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
			close_log(&logfiles[i], "close-rotate", B_FALSE);
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
	(void) snprintf(pidstr, sizeof (pidstr), "%d", getpid());
	logstream_unlock();
}

void
logstream_init(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	int i;

	VERIFY(!logging_initialized);

	VERIFY0(gethostname(host, sizeof (host)));
	(void) snprintf(pidstr, sizeof (pidstr), "%d", getpid());

	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		logfile_t *lfp = &logfiles[i];

		lfp->lf_fd = -1;
		if (custr_alloc_buf(&lfp->lf_cus, lfp->lf_buf,
		    sizeof (lfp->lf_buf)) != 0) {
			(void) fprintf(stderr, "failed to allocate custr_t for "
			    "log file\n");
			abort();
		}
	}

	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		logstream_t *lsp = &streams[i];

		if (custr_alloc_buf(&lsp->ls_cusbuf, lsp->ls_buf,
		    sizeof (lsp->ls_buf)) != 0 ||
		    custr_alloc_buf(&lsp->ls_cusobuf, lsp->ls_obuf,
		    sizeof (lsp->ls_obuf)) != 0) {
			(void) fprintf(stderr, "failed to allocate custr_t for "
			    "log stream\n");
			abort();
		}
	}

	VERIFY0(pthread_atfork(logstream_atfork_prepare,
	    logstream_atfork_parent, logstream_atfork_child));

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
	(void) sigset(SIGHUP, logstream_sighandler);
	(void) sigset(SIGUSR1, logstream_sighandler);
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

	VERIFY(MUTEX_HELD(&logging_lock));

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

	close_log(lfp, "close-rotate", B_FALSE);
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
 *   dest		Destination custr_t containing escaped JSON.
 *   scntp		On return, *scntp stores number of scnt bytes consumed
 *   flushp		If non-NULL, line-buffered mode is enabled.  Processing
 *			will stop at the first newline or when dest is full and
 *			*flushp will be set to B_TRUE.
 *
 * This function makes no attempt to handle wide characters properly because
 * the messages that come in may be using any character encoding.  Since
 * characters other than 7-bit ASCII are not directly readable in the log
 * anyway, it is better to log the raw data and leave it to specialized log
 * readers to interpret non-ASCII data.
 */
static void
escape_json(const char *sbuf, size_t slen, custr_t *dest, size_t *scntp,
    boolean_t *flushp)
{
	char c;
	const char *save_sbuf = sbuf;
	const char *sbuf_end = sbuf + slen - 1;
	char append_buf[7];			/* "\\u0000\0" */
	const char *append;
	int len;

	if (slen == 0) {
		*scntp = 0;
		return;
	}

	if (flushp != NULL) {
		*flushp = B_FALSE;
	}

	while (sbuf <= sbuf_end) {
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
				VERIFY3S(len, <, sizeof (append_buf));
			}
			append = append_buf;
			break;
		}

		if (custr_append(dest, append) != 0) {
			VERIFY3S(errno, ==, EOVERFLOW);
			if (flushp != NULL) {
				*flushp = B_TRUE;
			}
			break;
		}

		sbuf++;

		if (flushp != NULL && *flushp) {
			break;
		}
	}

	*scntp = sbuf - save_sbuf;

	VERIFY3U(*scntp, <=, slen);
}

/*
 * Like write(2), but to a logfile_t and with retries on short writes.
 */
static void
logfile_write(logfile_t *lfp, custr_t *cus)
{
	const char *buf = custr_cstr(cus);
	size_t buflen = custr_len(cus);
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

static void
add_bunyan_preamble(custr_t *cus)
{
	struct tm gtm;
	struct timeval tv;
	/* Large enough for YYYY-MM-DDTHH:MM:SS.000000000Z + NUL */
	char timestr[32] = { 0 };
	size_t len;

	if (gettimeofday(&tv, NULL) != 0 ||
	    gmtime_r(&tv.tv_sec, &gtm) == NULL) {
		logstream_err(B_TRUE, "failed to get time of day");
		abort();
	}

	len = strftime(timestr, sizeof (timestr) - 1, "%FT%T", &gtm);
	VERIFY3U(len, >, 0);
	VERIFY3U(len, <, sizeof (timestr) - 1);

	VERIFY0(custr_append_printf(cus, "\"time\": \"%s.%09ldZ\", ",
	    timestr, tv.tv_usec * 1000));
	VERIFY0(custr_append_printf(cus, "\"v\": %d, ", BUNYAN_VERSION));
	VERIFY0(custr_append_printf(cus, "\"hostname\": \"%s\", ", host));
	VERIFY0(custr_append(cus, "\"name\": \"zoneadmd\","));
	VERIFY0(custr_append_printf(cus, "\"pid\": %s, ", pidstr));
	VERIFY0(custr_append_printf(cus, "\"level\": %d", BUNYAN_LOG_LEVEL));
}

/*
 * Convert the json pairs into a json object. The properties required for
 * bunyan-formatted json objects are added to every object.
 * Returns the number of bytes that would have been written to
 * buf if bufsz had buf been sufficiently large (excluding the terminating null
 * byte).  Like snprintf().
 */
static size_t
make_json(jsonpair_t *pairs, size_t npairs, custr_t *cus)
{
	int i;
	const char *key, *val;
	const char *start = ", ";

	VERIFY3S(npairs, >, 0);

	custr_reset(cus);

	VERIFY0(custr_append(cus, "{ "));

	add_bunyan_preamble(cus);

	for (i = 0; i < npairs; i++) {
		size_t len;

		key = pairs[i].jp_key;
		val = pairs[i].jp_val;

		/* The total number of bytes we're adding to cus */
		len = 3 + strlen(key) + 3 + strlen(val) + 1;
		if (custr_append_printf(cus, "%s\"%s\":\"%s\"",
		    start, key, val) != 0) {
			VERIFY3S(errno, ==, EOVERFLOW);
			return (custr_len(cus) + len);
		}
	}

	if (custr_append(cus, " }\n") != 0) {
		return (custr_len(cus) + 3);
	}

	return (custr_len(cus));
}

static void
logstream_write_json(logstream_t *lsp)
{
	size_t len;
	jsonpair_t pairs[] = {
		{ "msg", lsp->ls_buf },
		{ "stream", lsp->ls_stream },
	};

	if (custr_len(lsp->ls_cusbuf) == 0) {
		return;
	}

	len = make_json(pairs, ARRAY_SIZE(pairs), lsp->ls_cusobuf);

	custr_reset(lsp->ls_cusbuf);
	if (len >= sizeof (lsp->ls_obuf)) {
		logstream_err(B_FALSE, "%s: buffer too small. Need %llu bytes, "
		    "have %llu bytes", __func__, len + 1,
		    sizeof (lsp->ls_obuf));
		return;
	}

	logfile_write(lsp->ls_logfile, lsp->ls_cusobuf);
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
	size_t scnt;
	boolean_t newline;
	boolean_t buffered;

	if (ls == -1 || len == 0) {
		return;
	}
	VERIFY3S(ls, >=, 0);
	VERIFY3S(ls, <, ARRAY_SIZE(streams));

	logstream_lock();

	lsp = &streams[ls];
	if (lsp->ls_stream[0] == '\0' || lsp->ls_logfile == NULL) {
		logstream_unlock();
		return;
	}

	buffered = !!(lsp->ls_flags & LS_LINE_BUFFERED);

	do {
		escape_json(buf, len, lsp->ls_cusbuf, &scnt,
		    buffered ? &newline : NULL);

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

	VERIFY(MUTEX_HELD(&logging_lock));

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

	VERIFY(MUTEX_HELD(&logging_lock));

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

	VERIFY3U(strlen(logname), <, sizeof (lfp->lf_name));
	VERIFY3U(strlen(stream), <, sizeof (lsp->ls_stream));

	logstream_lock();

	/*
	 * Find an empty logstream_t and verify that the stream is not already
	 * open.
	 */
	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (ls == -1 && streams[i].ls_stream[0] == '\0') {
			VERIFY3P(streams[i].ls_logfile, ==, NULL);
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
	VERIFY3S(ls, !=, -1);

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
logstream_close(int ls, boolean_t abrupt)
{
	logstream_t *lsp;
	logfile_t *lfp;
	int i;

	if (ls == -1) {
		return;
	}
	VERIFY3S(ls, >=, 0);
	VERIFY3S(ls, <, ARRAY_SIZE(streams));

	logstream_lock();
	logstream_flush(ls);

	lsp = &streams[ls];
	lfp = lsp->ls_logfile;

	VERIFY(lsp->ls_stream[0] != '\0');
	VERIFY3P(lfp, !=, NULL);

	(void) memset(lsp, 0, sizeof (*lsp));

	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (streams[i].ls_logfile == lfp) {
			logstream_unlock();
			return;
		}
	}

	/* No more streams using this log file so return to initial state */

	close_log(lfp, "close", abrupt);

	(void) memset(lfp, 0, sizeof (*lfp));
	lfp->lf_fd = -1;

	logstream_unlock();
}
