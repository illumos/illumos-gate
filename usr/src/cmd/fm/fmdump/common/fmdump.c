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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static int
usage(FILE *fp)
{
	(void) fprintf(fp, "Usage: %s [-efvV] [-c class] [-R root] [-t time] "
	    "[-T time] [-u uuid] [file]\n", g_pname);

	(void) fprintf(fp,
	    "\t-c  select events that match the specified class\n"
	    "\t-e  display error log content instead of fault log content\n"
	    "\t-f  follow growth of log file by waiting for additional data\n"
	    "\t-R  set root directory for pathname expansions\n"
	    "\t-t  select events that occurred after the specified time\n"
	    "\t-T  select events that occurred before the specified time\n"
	    "\t-u  select events that match the specified uuid\n"
	    "\t-v  set verbose mode: display additional event detail\n"
	    "\t-V  set very verbose mode: display complete event contents\n");

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
		{ "ns", 	NANOSEC / NANOSEC },
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

	if (tvp == NULL) {
		(void) fprintf(stderr, "%s: failed to allocate memory: %s\n",
		    g_pname, strerror(errno));
		exit(FMDUMP_EXIT_FATAL);
	}

	if (gettimeofday(&tod, NULL) != 0) {
		(void) fprintf(stderr, "%s: failed to get tod: %s\n",
		    g_pname, strerror(errno));
		exit(FMDUMP_EXIT_FATAL);
	}

	/*
	 * First try a variety of strptime() calls.  If these all fail, we'll
	 * try parsing an integer followed by one of our suffix[] strings.
	 * NOTE: any form using %y must appear *before* the equivalent %Y form;
	 * otherwise %Y will accept the two year digits but infer century zero.
	 * Any form ending in %y must additionally check isdigit(*p) to ensure
	 * that it does not inadvertently match 2 digits of a 4-digit year.
	 *
	 * Beware: Any strptime() sequence containing consecutive %x sequences
	 * may fall victim to SCCS expanding it as a keyword!  If this happens
	 * we use separate string constant that ANSI C will concatenate.
	 */
	if ((p = strptime(arg, "%m/%d/%y" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%Y" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%y" "%t" "%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%m/%d/%Y" "%t" "%H:%M", &tm)) == NULL &&
	    ((p = strptime(arg, "%m/%d/%y", &tm)) == NULL || isdigit(*p)) &&
	    (p = strptime(arg, "%m/%d/%Y", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%dT%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%dT%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%dT%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%y-%m-%d", &tm)) == NULL &&
	    (p = strptime(arg, "%Y-%m-%d", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%y" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%Y" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%y" "%t" "%H:%M", &tm)) == NULL &&
	    (p = strptime(arg, "%d%b%Y" "%t" "%H:%M", &tm)) == NULL &&
	    ((p = strptime(arg, "%d%b%y", &tm)) == NULL || isdigit(*p)) &&
	    (p = strptime(arg, "%d%b%Y", &tm)) == NULL &&
	    (p = strptime(arg, "%b%t%d" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%b%t%d" "%t" "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%H:%M:%S", &tm)) == NULL &&
	    (p = strptime(arg, "%H:%M", &tm)) == NULL) {

		hrtime_t nsec;
		int i;

		errno = 0;
		nsec = strtol(arg, (char **)&p, 10);

		if (errno != 0 || nsec == 0 || p == arg || *p == '\0') {
			(void) fprintf(stderr, "%s: illegal time "
			    "format -- %s\n", g_pname, arg);
			exit(FMDUMP_EXIT_USAGE);
		}

		for (i = 0; suffix[i].name != NULL; i++) {
			if (strcasecmp(suffix[i].name, p) == 0) {
				nsec *= suffix[i].mul;
				break;
			}
		}

		if (suffix[i].name == NULL) {
			(void) fprintf(stderr, "%s: illegal time "
			    "format -- %s\n", g_pname, arg);
			exit(FMDUMP_EXIT_USAGE);
		}

		tvp->tv_sec = nsec / NANOSEC;
		tvp->tv_usec = (nsec % NANOSEC) / (NANOSEC / MICROSEC);

		if (tvp->tv_sec > tod.tv_sec) {
			(void) fprintf(stderr, "%s: time delta precedes "
			    "UTC time origin -- %s\n", g_pname, arg);
			exit(FMDUMP_EXIT_USAGE);
		}

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

		if (tvp->tv_sec == -1L && errno != 0) {
			(void) fprintf(stderr, "%s: failed to compose "
			    "time %s: %s\n", g_pname, arg, strerror(errno));
			exit(FMDUMP_EXIT_ERROR);
		}

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

			if (errno != 0 || p == arg || *p != '\0') {
				(void) fprintf(stderr, "%s: illegal time "
				    "suffix -- .%s\n", g_pname, arg);
				exit(FMDUMP_EXIT_USAGE);
			}
		}

	} else {
		(void) fprintf(stderr, "%s: unexpected suffix after "
		    "time %s -- %s\n", g_pname, arg, p);
		exit(FMDUMP_EXIT_USAGE);
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
 * If the -a option is not present, filter out fault records that correspond
 * to events that the producer requested not be messaged for administrators.
 */
/*ARGSUSED*/
int
log_filter_silent(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	boolean_t msg;

	return (nvlist_lookup_boolean_value(rp->rec_nvl,
	    FM_SUSPECT_MESSAGE, &msg) != 0 || msg != 0);
}

int
main(int argc, char *argv[])
{
	int opt_a = 0, opt_e = 0, opt_f = 0, opt_H = 0;
	int opt_u = 0, opt_v = 0, opt_V = 0;

	char ifile[PATH_MAX] = "";
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

	g_pname = argv[0];

	errfv = alloca(sizeof (fmd_log_filter_t) * argc);
	fltfv = alloca(sizeof (fmd_log_filter_t) * argc);
	allfv = alloca(sizeof (fmd_log_filter_t) * argc);

	while (optind < argc) {
		while ((c = getopt(argc, argv, "ac:efHO:R:t:T:u:vV")) != EOF) {
			switch (c) {
			case 'a':
				opt_a++;
				break;
			case 'c':
				errfv[errfc].filt_func = fmd_log_filter_class;
				errfv[errfc].filt_arg = optarg;
				allfv[allfc++] = errfv[errfc++];
				break;
			case 'e':
				opt_e++;
				break;
			case 'f':
				opt_f++;
				break;
			case 'H':
				opt_H++;
				break;
			case 'O':
				off = strtoull(optarg, NULL, 16);
				iflags |= FMD_LOG_XITER_OFFS;
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

		if (optind < argc) {
			if (*ifile != '\0') {
				(void) fprintf(stderr, "%s: illegal "
				    "argument -- %s\n", g_pname, argv[optind]);
				return (FMDUMP_EXIT_USAGE);
			} else {
				(void) strlcpy(ifile,
				    argv[optind++], sizeof (ifile));
			}
		}
	}

	if (*ifile == '\0') {
		(void) snprintf(ifile, sizeof (ifile), "%s/var/fm/fmd/%slog",
		    g_root ? g_root : "", opt_e && !opt_u ? "err" : "flt");
	} else if (g_root != NULL) {
		(void) fprintf(stderr, "%s: -R option is not appropriate "
		    "when file operand is present\n", g_pname);
		return (FMDUMP_EXIT_USAGE);
	}

	if ((lp = fmd_log_open(FMD_LOG_VERSION, ifile, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to open %s: %s\n",
		    g_pname, ifile, fmd_log_errmsg(NULL, err));
		return (FMDUMP_EXIT_FATAL);
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
		(void) fprintf(stderr, "%s: failed to seek %s: %s\n",
		    g_pname, ifile, fmd_log_errmsg(lp, fmd_log_errno(lp)));
		return (FMDUMP_EXIT_FATAL);
	}

	if (opt_e && opt_u)
		ops = &fmdump_err_ops;
	else if (strcmp(fmd_log_label(lp), fmdump_flt_ops.do_label) == 0)
		ops = &fmdump_flt_ops;
	else if (strcmp(fmd_log_label(lp), fmdump_asru_ops.do_label) == 0)
		ops = &fmdump_asru_ops;
	else
		ops = &fmdump_err_ops;

	if (!opt_a && ops == &fmdump_flt_ops) {
		fltfv[fltfc].filt_func = log_filter_silent;
		fltfv[fltfc].filt_arg = NULL;
		allfv[allfc++] = fltfv[fltfc++];
	}

	if (opt_V) {
		arg.da_fmt = &ops->do_formats[FMDUMP_VERB2];
		iflags |= FMD_LOG_XITER_REFS;
	} else if (opt_v) {
		arg.da_fmt = &ops->do_formats[FMDUMP_VERB1];
	} else
		arg.da_fmt = &ops->do_formats[FMDUMP_SHORT];

	arg.da_fv = errfv;
	arg.da_fc = errfc;
	arg.da_fp = stdout;

	if (iflags & FMD_LOG_XITER_OFFS)
		fmdump_printf(arg.da_fp, "%16s ", "OFFSET");

	if (arg.da_fmt->do_hdr)
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

	do {
		if (fmd_log_xiter(lp, iflags, filtc, filtv,
		    func, error, farg, &g_recs) != 0) {
			(void) fprintf(stderr,
			    "%s: failed to dump %s: %s\n", g_pname, ifile,
			    fmd_log_errmsg(lp, fmd_log_errno(lp)));
			g_errs++;
		}

		if (opt_f)
			(void) sleep(1);

	} while (opt_f);

	if (!opt_f && g_recs == 0 && isatty(STDOUT_FILENO))
		(void) fprintf(stderr, "%s: %s is empty\n", g_pname, ifile);

	fmd_log_close(lp);
	return (g_errs ? FMDUMP_EXIT_ERROR : FMDUMP_EXIT_SUCCESS);
}
