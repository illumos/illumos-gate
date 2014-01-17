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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <alloca.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <dirent.h>
#include <pthread.h>

#include <fmdump.h>

#define	FMDUMP_EXIT_SUCCESS	0
#define	FMDUMP_EXIT_FATAL	1
#define	FMDUMP_EXIT_USAGE	2
#define	FMDUMP_EXIT_ERROR	3

const char *g_pname;
ulong_t g_errs;
ulong_t g_recs;
char *g_root;

struct topo_hdl *g_thp;
fmd_msg_hdl_t *g_msg;

/*PRINTFLIKE2*/
void
fmdump_printf(FILE *fp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (vfprintf(fp, format, ap) < 0) {
		(void) fprintf(stderr, "%s: failed to print record: %s\n",
		    g_pname, strerror(errno));
		g_errs++;
	}

	va_end(ap);
}

void
fmdump_vwarn(const char *format, va_list ap)
{
	int err = errno;

	(void) fprintf(stderr, "%s: warning: ", g_pname);
	(void) vfprintf(stderr, format, ap);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));

	g_errs++;
}

/*PRINTFLIKE1*/
void
fmdump_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmdump_vwarn(format, ap);
	va_end(ap);
}

static void
fmdump_exit(int err, int exitcode, const char *format, va_list ap)
{
	(void) fprintf(stderr, "%s: ", g_pname);

	(void) vfprintf(stderr, format, ap);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));

	exit(exitcode);
}

/*PRINTFLIKE1*/
static void
fmdump_fatal(const char *format, ...)
{
	int err = errno;

	va_list ap;

	va_start(ap, format);
	fmdump_exit(err, FMDUMP_EXIT_FATAL, format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
fmdump_usage(const char *format, ...)
{

	int err = errno;

	va_list ap;

	va_start(ap, format);
	fmdump_exit(err, FMDUMP_EXIT_USAGE, format, ap);
	va_end(ap);
}

char *
fmdump_date(char *buf, size_t len, const fmd_log_record_t *rp)
{
	if (rp->rec_sec > LONG_MAX) {
		fmdump_warn("record time is too large for 32-bit utility\n");
		(void) snprintf(buf, len, "0x%llx", rp->rec_sec);
	} else {
		time_t tod = (time_t)rp->rec_sec;
		time_t now = time(NULL);
		if (tod > now+60 ||
		    tod < now - 6L*30L*24L*60L*60L) { /* 6 months ago */
			(void) strftime(buf, len, "%b %d %Y %T",
			    localtime(&tod));
		} else {
			size_t sz;
			sz = strftime(buf, len, "%b %d %T", localtime(&tod));
			(void) snprintf(buf + sz, len - sz, ".%4.4llu",
			    rp->rec_nsec / (NANOSEC / 10000));
		}
	}

	return (buf);
}

char *
fmdump_year(char *buf, size_t len, const fmd_log_record_t *rp)
{
#ifdef _ILP32
	if (rp->rec_sec > LONG_MAX) {
		fmdump_warn("record time is too large for 32-bit utility\n");
		(void) snprintf(buf, len, "0x%llx", rp->rec_sec);
	} else {
#endif
		time_t tod = (time_t)rp->rec_sec;
		(void) strftime(buf, len, "%b %d %Y %T", localtime(&tod));
#ifdef _ILP32
	}
#endif
	return (buf);
}

/* BEGIN CSTYLED */
static const char *synopsis =
"Usage: %s [[-e | -i | -I] | -A ] [-f] [-mvVp] [-c class] [-R root]\n"
	"\t      [-t time ][-T time] [-u uuid] [-n name[.name]*[=value]] "
							"[file]...\n    "
    "Log selection: [-e | -i | -I] or one [file]; default is the fault log\n"
	"\t-e  display error log content\n"
	"\t-i  display infolog content\n"
	"\t-I  display the high-value-infolog content\n"
	"\t-R  set root directory for pathname expansions\n    "
    "Command behaviour:\n"
	"\t-A  Aggregate specified [file]s or, if no [file], all known logs\n"
	"\t-f  follow growth of log file by waiting for additional data\n    "
    "Output options:\n"
	"\t-m  display human-readable messages (only for fault logs)\n"
	"\t-v  set verbose mode: display additional event detail\n"
	"\t-V  set very verbose mode: display complete event contents\n"
	"\t-p  Used with -V: apply some output prettification\n"
	"\t-j  Used with -V: emit JSON-formatted output\n    "
    "Selection filters:\n"
	"\t-c  select events that match the specified class\n"
	"\t-t  select events that occurred after the specified time\n"
	"\t-T  select events that occurred before the specified time\n"
	"\t-u  select events that match the specified diagnosis uuid\n"
	"\t-n  select events containing named nvpair (with matching value)\n";
/* END CSTYLED */

static int
usage(FILE *fp)
{
	(void) fprintf(fp, synopsis, g_pname);
	return (FMDUMP_EXIT_USAGE);
}

/*ARGSUSED*/
static int
error(fmd_log_t *lp, void *private)
{
	fmdump_warn("skipping record: %s\n",
	    fmd_log_errmsg(lp, fmd_log_errno(lp)));
	return (0);
}

/*
 * Yet another disgusting argument parsing function (TM).  We attempt to parse
 * a time argument in a variety of strptime(3C) formats, in which case it is
 * interpreted as a local time and is converted to a timeval using mktime(3C).
 * If those formats fail, we look to see if the time is a decimal integer
 * followed by one of our magic suffixes, in which case the time is interpreted
 * as a time delta *before* the current time-of-day (i.e. "1h" = "1 hour ago").
 */
static struct timeval *
gettimeopt(const char *arg)
{
	const struct {
		const char *name;
		hrtime_t mul;
	} suffix[] = {
		{ "ns",		NANOSEC / NANOSEC },
		{ "nsec",	NANOSEC / NANOSEC },
		{ "us",		NANOSEC / MICROSEC },
		{ "usec",	NANOSEC / MICROSEC },
		{ "ms",		NANOSEC / MILLISEC },
		{ "msec",	NANOSEC / MILLISEC },
		{ "s",		NANOSEC / SEC },
		{ "sec",	NANOSEC / SEC },
		{ "m",		NANOSEC * (hrtime_t)60 },
		{ "min",	NANOSEC * (hrtime_t)60 },
		{ "h",		NANOSEC * (hrtime_t)(60 * 60) },
		{ "hour",	NANOSEC * (hrtime_t)(60 * 60) },
		{ "d",		NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "day",	NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ NULL }
	};

	struct timeval *tvp = malloc(sizeof (struct timeval));
	struct timeval tod;
	struct tm tm;
	char *p;

	if (tvp == NULL)
		fmdump_fatal("failed to allocate memory");

	if (gettimeofday(&tod, NULL) != 0)
		fmdump_fatal("failed to get tod");

	/*
	 * First try a variety of strptime() calls.  If these all fail, we'll
	 * try parsing an integer followed by one of our suffix[] strings.
	 */
	if ((p = strptime(arg, "%m/%d/%Y %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%y %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%Y %H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%y %H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%Y", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%y", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%dT%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%dT%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%dT%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%d", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%d", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%Y %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%y %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%Y %H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%y %H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%Y", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%y", &tm)) == NULL &&
	    (p = strptime(arg, "%b %d %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%b %d %H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%H:%M", &tm)) == NULL) {

		hrtime_t nsec;
		int i;

		errno = 0;
		nsec = strtol(arg, (char **)&p, 10);

		if (errno != 0 || nsec == 0 || p == arg || *p == '\0')
			fmdump_usage("illegal time format -- %s\n", arg);

		for (i = 0; suffix[i].name != NULL; i++) {
			if (strcasecmp(suffix[i].name, p) == 0) {
				nsec *= suffix[i].mul;
				break;
			}
		}

		if (suffix[i].name == NULL)
			fmdump_usage("illegal time format -- %s\n", arg);

		tvp->tv_sec = nsec / NANOSEC;
		tvp->tv_usec = (nsec % NANOSEC) / (NANOSEC / MICROSEC);

		if (tvp->tv_sec > tod.tv_sec)
			fmdump_usage("time delta precedes UTC time origin "
			    "-- %s\n", arg);

		tvp->tv_sec = tod.tv_sec - tvp->tv_sec;

	} else if (*p == '\0' || *p == '.') {
		/*
		 * If tm_year is zero, we matched [%b %d] %H:%M[:%S]; use
		 * the result of localtime(&tod.tv_sec) to fill in the rest.
		 */
		if (tm.tm_year == 0) {
			int h = tm.tm_hour;
			int m = tm.tm_min;
			int s = tm.tm_sec;
			int b = tm.tm_mon;
			int d = tm.tm_mday;

			bcopy(localtime(&tod.tv_sec), &tm, sizeof (tm));
			tm.tm_isdst = 0; /* see strptime(3C) and below */

			if (d > 0) {
				tm.tm_mon = b;
				tm.tm_mday = d;
			}

			tm.tm_hour = h;
			tm.tm_min = m;
			tm.tm_sec = s;
		}

		errno = 0;
		tvp->tv_sec = mktime(&tm);
		tvp->tv_usec = 0;

		if (tvp->tv_sec == -1L && errno != 0)
			fmdump_fatal("failed to compose time %s", arg);

		/*
		 * If our mktime() set tm_isdst, adjust the result for DST by
		 * subtracting the offset between the main and alternate zones.
		 */
		if (tm.tm_isdst)
			tvp->tv_sec -= timezone - altzone;

		if (p[0] == '.') {
			arg = p;
			errno = 0;
			tvp->tv_usec =
			    (suseconds_t)(strtod(arg, &p) * (double)MICROSEC);

			if (errno != 0 || p == arg || *p != '\0')
				fmdump_usage("illegal time suffix -- .%s\n",
				    arg);
		}

	} else {
		fmdump_usage("unexpected suffix after time %s -- %s\n", arg, p);
	}

	return (tvp);
}

/*
 * If the -u option is specified in combination with the -e option, we iterate
 * over each record in the fault log with a matching UUID finding xrefs to the
 * error log, and then use this function to iterate over every xref'd record.
 */
int
xref_iter(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	const fmd_log_record_t *xrp = rp->rec_xrefs;
	fmdump_arg_t *dap = arg;
	int i, rv = 0;

	for (i = 0; rv == 0 && i < rp->rec_nrefs; i++, xrp++) {
		if (fmd_log_filter(lp, dap->da_fc, dap->da_fv, xrp))
			rv = dap->da_fmt->do_func(lp, xrp, dap->da_fp);
	}

	return (rv);
}

int
xoff_iter(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	fmdump_lyr_t *dyp = arg;

	fmdump_printf(dyp->dy_fp, "%16llx ", (u_longlong_t)rp->rec_off);
	return (dyp->dy_func(lp, rp, dyp->dy_arg));
}

/*
 * Initialize fmd_log_filter_nvarg_t from -n name=value argument string.
 */
static fmd_log_filter_nvarg_t *
setupnamevalue(char *namevalue)
{
	fmd_log_filter_nvarg_t	*argt;
	char			*value;
	regex_t			*value_regex = NULL;
	char			errstr[128];
	int			rv;

	if ((value = strchr(namevalue, '=')) == NULL) {
		value_regex = NULL;
	} else {
		*value++ = '\0';	/* separate name and value string */

		/*
		 * Skip white space before value to facilitate direct
		 * cut/paste from previous fmdump output.
		 */
		while (isspace(*value))
			value++;

		if ((value_regex = malloc(sizeof (regex_t))) == NULL)
			fmdump_fatal("failed to allocate memory");

		/* compile regular expression for possible string match */
		if ((rv = regcomp(value_regex, value,
		    REG_NOSUB|REG_NEWLINE)) != 0) {
			(void) regerror(rv, value_regex, errstr,
			    sizeof (errstr));
			free(value_regex);
			fmdump_usage("unexpected regular expression in "
			    "%s: %s\n", value, errstr);
		}
	}

	if ((argt = malloc(sizeof (fmd_log_filter_nvarg_t))) == NULL)
		fmdump_fatal("failed to allocate memory");

	argt->nvarg_name = namevalue;		/* now just name */
	argt->nvarg_value = value;
	argt->nvarg_value_regex = value_regex;
	return (argt);
}

/*
 * If the -a option is not present, filter out fault records that correspond
 * to events that the producer requested not be messaged for administrators.
 */
/*ARGSUSED*/
int
log_filter_silent(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	int opt_A = (arg != NULL);
	boolean_t msg;
	char *class;

	/*
	 * If -A was used then apply this filter only to events of list class
	 */
	if (opt_A) {
		if (nvlist_lookup_string(rp->rec_nvl, FM_CLASS, &class) != 0 ||
		    strncmp(class, FM_LIST_EVENT ".",
		    sizeof (FM_LIST_EVENT)) != 0)
			return (1);
	}

	return (nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_SUSPECT_MESSAGE, &msg) != 0 || msg != 0);
}

struct loglink {
	char		*path;
	long		suffix;
	struct loglink	*next;
};

static void
addlink(struct loglink **llp, char *dirname, char *logname, long suffix)
{
	struct loglink *newp;
	size_t len;
	char *str;

	newp = malloc(sizeof (struct loglink));
	len = strlen(dirname) + strlen(logname) + 2;
	str = malloc(len);
	if (newp == NULL || str == NULL)
		fmdump_fatal("failed to allocate memory");

	(void) snprintf(str, len, "%s/%s", dirname, logname);
	newp->path = str;
	newp->suffix = suffix;

	while (*llp != NULL && suffix < (*llp)->suffix)
		llp = &(*llp)->next;

	newp->next = *llp;
	*llp = newp;
}

/*
 * Find and return all the rotated logs.
 */
static struct loglink *
get_rotated_logs(char *logpath)
{
	char dirname[PATH_MAX], *logname, *endptr;
	DIR *dirp;
	struct dirent *dp;
	long len, suffix;
	struct loglink *head = NULL;

	(void) strlcpy(dirname, logpath, sizeof (dirname));
	logname = strrchr(dirname, '/');
	*logname++ = '\0';
	len = strlen(logname);

	if ((dirp = opendir(dirname)) == NULL) {
		fmdump_warn("failed to opendir `%s'", dirname);
		g_errs++;
		return (NULL);
	}

	while ((dp = readdir(dirp)) != NULL) {
		/*
		 * Search the log directory for logs named "<logname>.0",
		 * "<logname>.1", etc and add to the link in the
		 * reverse numeric order.
		 */
		if (strlen(dp->d_name) < len + 2 ||
		    strncmp(dp->d_name, logname, len) != 0 ||
		    dp->d_name[len] != '.')
			continue;

		/*
		 * "*.0-" file normally should not be seen.  It may
		 * exist when user manually run 'fmadm rotate'.
		 * In such case, we put it at the end of the list so
		 * it'll be dumped after all the rotated logs, before
		 * the current one.
		 */
		if (strcmp(dp->d_name + len + 1, "0-") == 0)
			addlink(&head, dirname, dp->d_name, -1);
		else if ((suffix = strtol(dp->d_name + len + 1,
		    &endptr, 10)) >= 0 && *endptr == '\0')
			addlink(&head, dirname, dp->d_name, suffix);
	}

	(void) closedir(dirp);

	return (head);
}

/*
 * Aggregate log files.  If ifiles is not NULL then one or more files
 * were listed on the command line, and we will merge just those files.
 * Otherwise we will merge all known log file types, and include the
 * rotated logs for each type (you can suppress the inclusion of
 * some logtypes through use of FMDUMP_AGGREGATE_IGNORE in the process
 * environment, setting it to a comma-separated list of log labels and/or
 * log filenames to ignore).
 *
 * We will not attempt to perform a chronological sort across all log records
 * of all files.  Indeed, we won't even sort individual log files -
 * we will not re-order events differently to how they appeared in their
 * original log file.  This is because log files are already inherently
 * ordered by the order in which fmd receives and processes events.
 * So we determine the output order by comparing the "next" record
 * off the top of each log file.
 *
 * We will construct a number of log record source "pipelines".  As above,
 * the next record to render in the overall output is that from the
 * pipeline with the oldest event.
 *
 * For the case that input logfiles were listed on the command line, each
 * pipeline will process exactly one of those logfiles.  Distinct pipelines
 * may process logfiles of the same "type" - eg if two "error" logs and
 * one "fault" logs are specified then there'll be two pipelines producing
 * events from "error" logs.
 *
 * If we are merging all known log types then we will construct exactly
 * one pipeline for each known log type - one for error, one for fault, etc.
 * Each pipeline will process first the rotated logs of that type and then
 * move on to the current log of that type.
 *
 * The output from all pipelines flows into a serializer which selects
 * the next record once all pipelines have asserted their output state.
 * The output state of a pipeline is one of:
 *
 *	- record available: the next record from this pipeline is available
 *	  for comparison and consumption
 *
 *	- done: this pipeline will produce no more records
 *
 *	- polling: this pipeline is polling for new records and will
 *	  make them available as output if/when any are observed
 *
 *	- processing: output state will be updated shortly
 *
 * A pipeline iterates over each file queued to it using fmd_log_xiter.
 * We do this in a separate thread for each pipeline.  The callback on
 * each iteration must update the serializer to let it know that
 * a new record is available.  In the serializer thread we decide whether
 * we have all records expected have arrived and it is time to choose
 * the next output record.
 */

/*
 * A pipeline descriptor.  The pl_cv condition variable is used together
 * with pl_lock for initial synchronisation, and thereafter with the
 * lock for the serializer for pausing and continuing this pipeline.
 */
struct fmdump_pipeline {
	pthread_mutex_t pl_lock;	/* used only in pipeline startup */
	int pl_started;			/* sync with main thread on startup */
	pthread_t pl_thr;		/* our processing thread */
	pthread_cond_t pl_cv;		/* see above */
	struct loglink *pl_rotated;	/* rotated logs to process first */
	char *pl_logpath;		/* target path to process */
	char *pl_processing;		/* path currently being processed */
	struct fmdump_srlzer *pl_srlzer;	/* link to serializer */
	int pl_srlzeridx;		/* serializer index for this pipeline */
	const fmdump_ops_t *pl_ops;	/* ops for the log type we're given */
	int pl_fmt;			/* FMDUMP_{SHORT,VERB1,VERB2,PRETTY} */
	boolean_t pl_follow;		/* go into poll mode at log end */
	fmdump_arg_t pl_arg;		/* arguments */
};

enum fmdump_pipestate {
	FMDUMP_PIPE_PROCESSING = 0x1000,
	FMDUMP_PIPE_RECORDAVAIL,
	FMDUMP_PIPE_POLLING,
	FMDUMP_PIPE_DONE
};

/*
 * Each pipeline has an associated output slot in the serializer.  This
 * must be updated with the serializer locked.  After update evaluate
 * whether there are enough slots decided that we should select a
 * record to output.
 */
struct fmdump_srlzer_slot {
	enum fmdump_pipestate ss_state;
	uint64_t ss_sec;
	uint64_t ss_nsec;
};

/*
 * All pipelines are linked to a single serializer.  The serializer
 * structure must be updated under the ds_lock; this mutex is also
 * paired with the pl_cv of individual pipelines (one mutex, many condvars)
 * in pausing and continuing individual pipelines.
 */
struct fmdump_srlzer {
	struct fmdump_pipeline *ds_pipearr;	/* pipeline array */
	pthread_mutex_t ds_lock;		/* see above */
	uint32_t ds_pipecnt;			/* number of pipelines */
	uint32_t ds_pollcnt;			/* pipelines in poll mode */
	uint32_t ds_nrecordavail;		/* pipelines with a record */
	uint32_t ds_ndone;			/* completed pipelines */
	struct fmdump_srlzer_slot *ds_slot;	/* slot array */
};

/*
 * All known log types.  When aggregation is requested an no file list
 * is provided we will process the logs identified here (if lt_enabled
 * is true and not over-ridden by environment settings).  We also
 * use this in determining the appropriate ops structure for each distinct
 * label.
 */
static struct fmdump_logtype {
	const char *lt_label;		/* label from log header */
	boolean_t lt_enabled;		/* include in merge? */
	const char *lt_logname;		/* var/fm/fmd/%s */
	const fmdump_ops_t *lt_ops;
} logtypes[] = {
	{
		"error",
		B_TRUE,
		"errlog",
		&fmdump_err_ops
	},
	{
		"fault",
		B_TRUE,
		"fltlog",
		&fmdump_flt_ops
	},
	{
		"info",
		B_TRUE,
		"infolog",
		&fmdump_info_ops
	},
	{
		"info",
		B_TRUE,
		"infolog_hival",
		&fmdump_info_ops
	},
	{
		"asru",
		B_FALSE,		/* not included unless in file list */
		NULL,
		&fmdump_asru_ops	/* but we need ops when it is */
	}
};

/*
 * Disable logtypes per environment setting.  Does not apply when a list
 * of logs is provided on the command line.
 */
static void
do_disables(void)
{
	char *env = getenv("FMDUMP_AGGREGATE_IGNORE");
	char *dup, *start, *tofree;
	int i;

	if (env == NULL)
		return;

	tofree = dup = strdup(env);

	while (dup != NULL) {
		start = strsep(&dup, ",");
		for (i = 0; i < sizeof (logtypes) / sizeof (logtypes[0]); i++) {
			if (logtypes[i].lt_logname == NULL)
				continue;

			if (strcmp(start, logtypes[i].lt_label) == 0 ||
			    strcmp(start, logtypes[i].lt_logname) == 0) {
				logtypes[i].lt_enabled = B_FALSE;
			}
		}
	}

	free(tofree);
}

static void
srlzer_enter(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;

	(void) pthread_mutex_lock(&srlzer->ds_lock);
}

static void
srlzer_exit(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));
	(void) pthread_mutex_unlock(&srlzer->ds_lock);
}

static struct fmdump_pipeline *
srlzer_choose(struct fmdump_srlzer *srlzer)
{
	struct fmdump_srlzer_slot *slot, *oldest;
	int oldestidx = -1;
	int first = 1;
	int i;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));

	for (i = 0, slot = &srlzer->ds_slot[0]; i < srlzer->ds_pipecnt;
	    i++, slot++) {
		if (slot->ss_state != FMDUMP_PIPE_RECORDAVAIL)
			continue;

		if (first) {
			oldest = slot;
			oldestidx = i;
			first = 0;
			continue;
		}

		if (slot->ss_sec < oldest->ss_sec ||
		    slot->ss_sec == oldest->ss_sec &&
		    slot->ss_nsec < oldest->ss_nsec) {
			oldest = slot;
			oldestidx = i;
		}
	}

	return (oldestidx >= 0 ? &srlzer->ds_pipearr[oldestidx] : NULL);
}

static void
pipeline_stall(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));
	(void) pthread_cond_wait(&pl->pl_cv, &srlzer->ds_lock);
}

static void
pipeline_continue(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));
	(void) pthread_cond_signal(&srlzer->ds_pipearr[pl->pl_srlzeridx].pl_cv);
}

/*
 * Called on each pipeline record iteration to make a new record
 * available for input to the serializer.  Returns 0 to indicate that
 * the caller must stall the pipeline, or 1 to indicate that the
 * caller should go ahead and render their record.  If this record
 * addition fills the serializer then choose a pipeline that must
 * render output.
 */
static int
pipeline_output(struct fmdump_pipeline *pl, const fmd_log_record_t *rp)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;
	struct fmdump_srlzer_slot *slot;
	struct fmdump_pipeline *wpl;
	int thisidx = pl->pl_srlzeridx;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));

	slot = &srlzer->ds_slot[thisidx];
	slot->ss_state = FMDUMP_PIPE_RECORDAVAIL;
	slot->ss_sec = rp->rec_sec;
	slot->ss_nsec = rp->rec_nsec;
	srlzer->ds_nrecordavail++;

	/*
	 * Once all pipelines are polling we just render in arrival order.
	 */
	if (srlzer->ds_pollcnt == srlzer->ds_pipecnt)
		return (1);

	/*
	 * If not all pipelines have asserted an output yet then the
	 * caller must block.
	 */
	if (srlzer->ds_nrecordavail + srlzer->ds_ndone +
	    srlzer->ds_pollcnt < srlzer->ds_pipecnt)
		return (0);

	/*
	 * Right so it's time to turn the crank by choosing which of the
	 * filled line of slots should produce output.  If it is the slot
	 * for our caller then return their index to them, otherwise return
	 * -1 to the caller to make them block and cv_signal the winner.
	 */
	wpl = srlzer_choose(srlzer);
	ASSERT(wpl != NULL);

	if (wpl == pl)
		return (1);

	/* Wake the oldest, and return 0 to put the caller to sleep */
	pipeline_continue(wpl);

	return (0);
}

static void
pipeline_mark_consumed(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;

	ASSERT(MUTEX_HELD(&srlzer->ds_lock));
	srlzer->ds_slot[pl->pl_srlzeridx].ss_state = FMDUMP_PIPE_PROCESSING;
	srlzer->ds_nrecordavail--;
}

static void
pipeline_done(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;
	struct fmdump_pipeline *wpl;

	srlzer_enter(pl);

	srlzer->ds_slot[pl->pl_srlzeridx].ss_state = FMDUMP_PIPE_DONE;
	srlzer->ds_ndone++;
	wpl = srlzer_choose(srlzer);
	if (wpl != NULL)
		pipeline_continue(wpl);

	srlzer_exit(pl);
}

static void
pipeline_pollmode(struct fmdump_pipeline *pl)
{
	struct fmdump_srlzer *srlzer = pl->pl_srlzer;
	struct fmdump_pipeline *wpl;

	if (srlzer->ds_slot[pl->pl_srlzeridx].ss_state == FMDUMP_PIPE_POLLING)
		return;

	srlzer_enter(pl);

	srlzer->ds_slot[pl->pl_srlzeridx].ss_state = FMDUMP_PIPE_POLLING;
	if (++srlzer->ds_pollcnt + srlzer->ds_nrecordavail ==
	    srlzer->ds_pipecnt && (wpl = srlzer_choose(srlzer)) != NULL)
		pipeline_continue(wpl);

	srlzer_exit(pl);
}

static int
pipeline_err(fmd_log_t *lp, void *arg)
{
	struct fmdump_pipeline *pl = (struct fmdump_pipeline *)arg;

	fmdump_warn("skipping record in %s: %s\n", pl->pl_processing,
	    fmd_log_errmsg(lp, fmd_log_errno(lp)));
	g_errs++;

	return (0);
}

static int
pipeline_cb(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	struct fmdump_pipeline *pl = (struct fmdump_pipeline *)arg;
	int rc;

	fmd_log_rec_f *func = pl->pl_arg.da_fmt->do_func;

	srlzer_enter(pl);

	if (!pipeline_output(pl, rp))
		pipeline_stall(pl);

	rc = func(lp, rp, pl->pl_arg.da_fp);
	pipeline_mark_consumed(pl);

	srlzer_exit(pl);

	return (rc);
}

static void
pipeline_process(struct fmdump_pipeline *pl, char *logpath, boolean_t follow)
{
	fmd_log_header_t log;
	fmd_log_t *lp;
	int err;
	int i;

	pl->pl_processing = logpath;

	if ((lp = fmd_log_open(FMD_LOG_VERSION, logpath, &err)) == NULL) {
		fmdump_warn("failed to open %s: %s\n",
		    logpath, fmd_log_errmsg(NULL, err));
		g_errs++;
		return;
	}

	fmd_log_header(lp, &log);
	for (i = 0; i < sizeof (logtypes) / sizeof (logtypes[0]); i++) {
		if (strcmp(log.log_label, logtypes[i].lt_label) == 0) {
			pl->pl_ops = logtypes[i].lt_ops;
			pl->pl_arg.da_fmt =
			    &pl->pl_ops->do_formats[pl->pl_fmt];
			break;
		}
	}

	if (pl->pl_ops == NULL) {
		fmdump_warn("unknown log type %s for %s\n",
		    log.log_label, logpath);
		g_errs++;
		return;
	}

	do {
		if (fmd_log_xiter(lp, FMD_LOG_XITER_REFS, pl->pl_arg.da_fc,
		    pl->pl_arg.da_fv, pipeline_cb, pipeline_err, (void *)pl,
		    NULL) != 0) {
			fmdump_warn("failed to dump %s: %s\n",
			    logpath, fmd_log_errmsg(lp, fmd_log_errno(lp)));
			g_errs++;
			fmd_log_close(lp);
			return;
		}

		if (follow) {
			pipeline_pollmode(pl);
			(void) sleep(1);
		}

	} while (follow);

	fmd_log_close(lp);
}

static void *
pipeline_thr(void *arg)
{
	struct fmdump_pipeline *pl = (struct fmdump_pipeline *)arg;
	struct loglink *ll;

	(void) pthread_mutex_lock(&pl->pl_lock);
	pl->pl_started = 1;
	(void) pthread_mutex_unlock(&pl->pl_lock);
	(void) pthread_cond_signal(&pl->pl_cv);

	for (ll = pl->pl_rotated; ll != NULL; ll = ll->next)
		pipeline_process(pl, ll->path, B_FALSE);

	pipeline_process(pl, pl->pl_logpath, pl->pl_follow);
	pipeline_done(pl);

	return (NULL);
}


static int
aggregate(char **ifiles, int n_ifiles, int opt_f,
    fmd_log_filter_t *fv, uint_t fc,
    int opt_v, int opt_V, int opt_p, int opt_j)
{
	struct fmdump_pipeline *pipeline, *pl;
	struct fmdump_srlzer srlzer;
	uint32_t npipe;
	int fmt;
	int i;

	if (ifiles != NULL) {
		npipe = n_ifiles;
		pipeline = calloc(npipe, sizeof (struct fmdump_pipeline));
		if (!pipeline)
			fmdump_fatal("failed to allocate memory");

		for (i = 0; i < n_ifiles; i++)
			pipeline[i].pl_logpath = ifiles[i];
	} else {
		pipeline = calloc(sizeof (logtypes) / sizeof (logtypes[0]),
		    sizeof (struct fmdump_pipeline));
		if (!pipeline)
			fmdump_fatal("failed to allocate memory");

		do_disables();

		npipe = 0;
		for (i = 0; i < sizeof (logtypes) / sizeof (logtypes[0]); i++) {
			struct fmdump_logtype *ltp = &logtypes[i];
			char *logpath;

			if (ltp->lt_enabled == B_FALSE)
				continue;

			if ((logpath = malloc(PATH_MAX)) == NULL)
				fmdump_fatal("failed to allocate memory");

			(void) snprintf(logpath, PATH_MAX,
			    "%s/var/fm/fmd/%s",
			    g_root ? g_root : "", ltp->lt_logname);

			pipeline[npipe].pl_rotated =
			    get_rotated_logs(logpath);

			pipeline[npipe++].pl_logpath = logpath;
		}
	}

	if (opt_V)
		fmt = opt_p ? FMDUMP_PRETTY : opt_j ? FMDUMP_JSON :
		    FMDUMP_VERB2;
	else if (opt_v)
		fmt = FMDUMP_VERB1;
	else
		fmt = FMDUMP_SHORT;

	bzero(&srlzer, sizeof (srlzer));
	srlzer.ds_pipearr = pipeline;
	srlzer.ds_pipecnt = npipe;
	srlzer.ds_slot = calloc(npipe, sizeof (struct fmdump_srlzer_slot));
	if (!srlzer.ds_slot)
		fmdump_fatal("failed to allocate memory");
	(void) pthread_mutex_init(&srlzer.ds_lock, NULL);

	for (i = 0, pl = &pipeline[0]; i < npipe; i++, pl++) {
		(void) pthread_mutex_init(&pl->pl_lock, NULL);
		(void) pthread_cond_init(&pl->pl_cv, NULL);
		srlzer.ds_slot[i].ss_state = FMDUMP_PIPE_PROCESSING;
		pl->pl_srlzer = &srlzer;
		pl->pl_srlzeridx = i;
		pl->pl_follow = opt_f ? B_TRUE : B_FALSE;
		pl->pl_fmt = fmt;
		pl->pl_arg.da_fv = fv;
		pl->pl_arg.da_fc = fc;
		pl->pl_arg.da_fp = stdout;

		(void) pthread_mutex_lock(&pl->pl_lock);

		if (pthread_create(&pl->pl_thr, NULL,
		    pipeline_thr, (void *)pl) != 0)
			fmdump_fatal("pthread_create for pipeline %d failed",
			    i);
	}

	for (i = 0, pl = &pipeline[0]; i < npipe; i++, pl++) {
		while (!pl->pl_started)
			(void) pthread_cond_wait(&pl->pl_cv, &pl->pl_lock);

		(void) pthread_mutex_unlock(&pl->pl_lock);
	}

	for (i = 0, pl = &pipeline[0]; i < npipe; i++, pl++)
		(void) pthread_join(pl->pl_thr, NULL);

	if (ifiles == NULL) {
		for (i = 0; i < npipe; i++)
			free(pipeline[i].pl_logpath);
	}

	free(srlzer.ds_slot);

	free(pipeline);

	return (FMDUMP_EXIT_SUCCESS);
}

static void
cleanup(char **ifiles, int n_ifiles)
{
	int i;

	if (ifiles == NULL)
		return;

	for (i = 0; i < n_ifiles; i++) {
		if (ifiles[i] != NULL) {
			free(ifiles[i]);
			ifiles[i] = NULL;
		}
	}

	free(ifiles);
}

int
main(int argc, char *argv[])
{
	int opt_a = 0, opt_e = 0, opt_f = 0, opt_H = 0, opt_m = 0, opt_p = 0;
	int opt_u = 0, opt_v = 0, opt_V = 0, opt_j = 0;
	int opt_i = 0, opt_I = 0;
	int opt_A = 0;
	char **ifiles = NULL;
	char *ifile = NULL;
	int n_ifiles;
	int ifileidx = 0;
	int iflags = 0;

	fmdump_arg_t arg;
	fmdump_lyr_t lyr;
	const fmdump_ops_t *ops;
	fmd_log_filter_t *filtv;
	uint_t filtc;

	fmd_log_filter_t *errfv, *fltfv, *allfv;
	uint_t errfc = 0, fltfc = 0, allfc = 0;

	fmd_log_header_t log;
	fmd_log_rec_f *func;
	void *farg;
	fmd_log_t *lp;
	int c, err;
	off64_t off = 0;
	ulong_t recs;
	struct loglink *rotated_logs = NULL, *llp;

	g_pname = argv[0];

	errfv = alloca(sizeof (fmd_log_filter_t) * argc);
	fltfv = alloca(sizeof (fmd_log_filter_t) * argc);
	allfv = alloca(sizeof (fmd_log_filter_t) * argc);

	while (optind < argc) {
		while ((c =
		    getopt(argc, argv, "Aac:efHiIjmn:O:pR:t:T:u:vV")) != EOF) {
			switch (c) {
			case 'A':
				opt_A++;
				break;
			case 'a':
				opt_a++;
				break;
			case 'c':
				errfv[errfc].filt_func = fmd_log_filter_class;
				errfv[errfc].filt_arg = optarg;
				allfv[allfc++] = errfv[errfc++];
				break;
			case 'e':
				if (opt_i)
					return (usage(stderr));
				opt_e++;
				break;
			case 'f':
				opt_f++;
				break;
			case 'H':
				opt_H++;
				break;
			case 'i':
				if (opt_e || opt_I)
					return (usage(stderr));
				opt_i++;
				break;
			case 'I':
				if (opt_e || opt_i)
					return (usage(stderr));
				opt_I++;
				break;
			case 'j':
				if (opt_p)
					return (usage(stderr));
				opt_j++;
				break;
			case 'm':
				opt_m++;
				break;
			case 'O':
				off = strtoull(optarg, NULL, 16);
				iflags |= FMD_LOG_XITER_OFFS;
				break;
			case 'p':
				if (opt_j)
					return (usage(stderr));
				opt_p++;
				break;
			case 'R':
				g_root = optarg;
				break;
			case 't':
				errfv[errfc].filt_func = fmd_log_filter_after;
				errfv[errfc].filt_arg = gettimeopt(optarg);
				allfv[allfc++] = errfv[errfc++];
				break;
			case 'T':
				errfv[errfc].filt_func = fmd_log_filter_before;
				errfv[errfc].filt_arg = gettimeopt(optarg);
				allfv[allfc++] = errfv[errfc++];
				break;
			case 'u':
				fltfv[fltfc].filt_func = fmd_log_filter_uuid;
				fltfv[fltfc].filt_arg = optarg;
				allfv[allfc++] = fltfv[fltfc++];
				opt_u++;
				opt_a++; /* -u implies -a */
				break;
			case 'n': {
				fltfv[fltfc].filt_func = fmd_log_filter_nv;
				fltfv[fltfc].filt_arg = setupnamevalue(optarg);
				allfv[allfc++] = fltfv[fltfc++];
				break;
			}
			case 'v':
				opt_v++;
				break;
			case 'V':
				opt_V++;
				break;
			default:
				return (usage(stderr));
			}
		}

		if (opt_A && (opt_e || opt_i || opt_I || opt_m || opt_u))
			fmdump_usage("-A excludes all of "
			    "-e, -i, -I, -m and -u\n");

		if (optind < argc) {
			char *dest;

			if (ifiles == NULL) {
				n_ifiles = argc - optind;
				ifiles = calloc(n_ifiles, sizeof (char *));
				if (ifiles == NULL) {
					fmdump_fatal(
					    "failed to allocate memory for "
					    "%d input file%s", n_ifiles,
					    n_ifiles > 1 ? "s" : "");
				}
			}

			if (ifileidx > 0 && !opt_A)
				fmdump_usage("illegal argument -- %s\n",
				    argv[optind]);

			if ((dest = malloc(PATH_MAX)) == NULL)
				fmdump_fatal("failed to allocate memory");

			(void) strlcpy(dest, argv[optind++], PATH_MAX);
			ifiles[ifileidx++] = dest;
		}
	}

	if (opt_A) {
		int rc;

		if (!opt_a) {
			fltfv[fltfc].filt_func = log_filter_silent;
			fltfv[fltfc].filt_arg = (void *)1;
			allfv[allfc++] = fltfv[fltfc++];
		}

		rc = aggregate(ifiles, n_ifiles, opt_f,
		    allfv, allfc,
		    opt_v, opt_V, opt_p, opt_j);

		cleanup(ifiles, n_ifiles);
		return (rc);
	} else {
		if (ifiles == NULL) {
			if ((ifile = calloc(1, PATH_MAX)) == NULL)
				fmdump_fatal("failed to allocate memory");
		} else {
			ifile = ifiles[0];
		}
	}


	if (*ifile == '\0') {
		const char *pfx, *sfx;

		if (opt_u || (!opt_e && !opt_i && !opt_I)) {
			pfx = "flt";
			sfx = "";
		} else {
			if (opt_e) {
				pfx = "err";
				sfx = "";
			} else {
				pfx = "info";
				sfx = opt_I ? "_hival" : "";
			}
		}

		(void) snprintf(ifile, PATH_MAX, "%s/var/fm/fmd/%slog%s",
		    g_root ? g_root : "", pfx, sfx);
		/*
		 * logadm may rotate the logs.  When no input file is specified,
		 * we try to dump all the rotated logs as well in the right
		 * order.
		 */
		if (!opt_H && off == 0)
			rotated_logs = get_rotated_logs(ifile);
	} else if (g_root != NULL) {
		fmdump_usage("-R option is not appropriate "
		    "when file operand is present\n");
	}

	if ((g_msg = fmd_msg_init(g_root, FMD_MSG_VERSION)) == NULL)
		fmdump_fatal("failed to initialize libfmd_msg");

	if ((lp = fmd_log_open(FMD_LOG_VERSION, ifile, &err)) == NULL) {
		fmdump_fatal("failed to open %s: %s\n", ifile,
		    fmd_log_errmsg(NULL, err));
	}

	if (opt_H) {
		fmd_log_header(lp, &log);

		(void) printf("EXD_CREATOR = %s\n", log.log_creator);
		(void) printf("EXD_HOSTNAME = %s\n", log.log_hostname);
		(void) printf("EXD_FMA_LABEL = %s\n", log.log_label);
		(void) printf("EXD_FMA_VERSION = %s\n", log.log_version);
		(void) printf("EXD_FMA_OSREL = %s\n", log.log_osrelease);
		(void) printf("EXD_FMA_OSVER = %s\n", log.log_osversion);
		(void) printf("EXD_FMA_PLAT = %s\n", log.log_platform);
		(void) printf("EXD_FMA_UUID = %s\n", log.log_uuid);

		return (FMDUMP_EXIT_SUCCESS);
	}

	if (off != 0 && fmd_log_seek(lp, off) != 0) {
		fmdump_fatal("failed to seek %s: %s\n", ifile,
		    fmd_log_errmsg(lp, fmd_log_errno(lp)));
	}

	if (opt_e && opt_u)
		ops = &fmdump_err_ops;
	else if (strcmp(fmd_log_label(lp), fmdump_flt_ops.do_label) == 0)
		ops = &fmdump_flt_ops;
	else if (strcmp(fmd_log_label(lp), fmdump_asru_ops.do_label) == 0)
		ops = &fmdump_asru_ops;
	else if (strcmp(fmd_log_label(lp), fmdump_info_ops.do_label) == 0)
		ops = &fmdump_info_ops;
	else
		ops = &fmdump_err_ops;

	if (!opt_a && ops == &fmdump_flt_ops) {
		fltfv[fltfc].filt_func = log_filter_silent;
		fltfv[fltfc].filt_arg = NULL;
		allfv[allfc++] = fltfv[fltfc++];
	}

	if (opt_V) {
		arg.da_fmt =
		    &ops->do_formats[opt_p ? FMDUMP_PRETTY :
		    opt_j ? FMDUMP_JSON : FMDUMP_VERB2];
		iflags |= FMD_LOG_XITER_REFS;
	} else if (opt_v) {
		arg.da_fmt = &ops->do_formats[FMDUMP_VERB1];
	} else if (opt_m) {
		arg.da_fmt = &ops->do_formats[FMDUMP_MSG];
	} else
		arg.da_fmt = &ops->do_formats[FMDUMP_SHORT];

	if (opt_m && arg.da_fmt->do_func == NULL) {
		fmdump_usage("-m mode is not supported for "
		    "log of type %s: %s\n", fmd_log_label(lp), ifile);
	}

	arg.da_fv = errfv;
	arg.da_fc = errfc;
	arg.da_fp = stdout;

	if (iflags & FMD_LOG_XITER_OFFS)
		fmdump_printf(arg.da_fp, "%16s ", "OFFSET");

	if (arg.da_fmt->do_hdr && !(opt_V && ops == &fmdump_flt_ops))
		fmdump_printf(arg.da_fp, "%s\n", arg.da_fmt->do_hdr);

	if (opt_e && opt_u) {
		iflags |= FMD_LOG_XITER_REFS;
		func = xref_iter;
		farg = &arg;
		filtc = fltfc;
		filtv = fltfv;
	} else {
		func = arg.da_fmt->do_func;
		farg = arg.da_fp;
		filtc = allfc;
		filtv = allfv;
	}

	if (iflags & FMD_LOG_XITER_OFFS) {
		lyr.dy_func = func;
		lyr.dy_arg = farg;
		lyr.dy_fp = arg.da_fp;
		func = xoff_iter;
		farg = &lyr;
	}

	for (llp = rotated_logs; llp != NULL; llp = llp->next) {
		fmd_log_t *rlp;

		if ((rlp = fmd_log_open(FMD_LOG_VERSION, llp->path, &err))
		    == NULL) {
			fmdump_warn("failed to open %s: %s\n",
			    llp->path, fmd_log_errmsg(NULL, err));
			g_errs++;
			continue;
		}

		recs = 0;
		if (fmd_log_xiter(rlp, iflags, filtc, filtv,
		    func, error, farg, &recs) != 0) {
			fmdump_warn("failed to dump %s: %s\n", llp->path,
			    fmd_log_errmsg(rlp, fmd_log_errno(rlp)));
			g_errs++;
		}
		g_recs += recs;

		fmd_log_close(rlp);
	}

	do {
		recs = 0;
		if (fmd_log_xiter(lp, iflags, filtc, filtv,
		    func, error, farg, &recs) != 0) {
			fmdump_warn("failed to dump %s: %s\n", ifile,
			    fmd_log_errmsg(lp, fmd_log_errno(lp)));
			g_errs++;
		}
		g_recs += recs;

		if (opt_f)
			(void) sleep(1);

	} while (opt_f);

	if (!opt_f && g_recs == 0 && isatty(STDOUT_FILENO))
		fmdump_warn("%s is empty\n", ifile);

	if (g_thp != NULL)
		topo_close(g_thp);

	fmd_log_close(lp);
	fmd_msg_fini(g_msg);

	if (ifiles == NULL)
		free(ifile);
	else
		cleanup(ifiles, n_ifiles);

	return (g_errs ? FMDUMP_EXIT_ERROR : FMDUMP_EXIT_SUCCESS);
}
