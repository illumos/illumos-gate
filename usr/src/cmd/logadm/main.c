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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 *
 * logadm/main.c -- main routines for logadm
 *
 * this program is 90% argument processing, 10% actions...
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/filio.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <utime.h>
#include "err.h"
#include "lut.h"
#include "fn.h"
#include "opts.h"
#include "conf.h"
#include "glob.h"
#include "kw.h"

/* forward declarations for functions in this file */
static void usage(const char *msg);
static void commajoin(const char *lhs, void *rhs, void *arg);
static void doaftercmd(const char *lhs, void *rhs, void *arg);
static void dologname(struct fn *fnp, struct opts *clopts);
static boolean_t rotatelog(struct fn *fnp, struct opts *opts);
static void rotateto(struct fn *fnp, struct opts *opts, int n,
    struct fn *recentlog, boolean_t isgz);
static void do_delayed_gzip(const char *lhs, void *rhs, void *arg);
static void expirefiles(struct fn *fnp, struct opts *opts);
static void dorm(struct opts *opts, const char *msg, struct fn *fnp);
static void docmd(struct opts *opts, const char *msg, const char *cmd,
    const char *arg1, const char *arg2, const char *arg3);
static void docopytruncate(struct opts *opts, const char *file,
    const char *file_copy);

/* our configuration file, unless otherwise specified by -f */
static char *Default_conffile = "/etc/logadm.conf";
/* our timestamps file, unless otherwise specified by -F */
static char *Default_timestamps = "/var/logadm/timestamps";

/* default pathnames to the commands we invoke */
static char *Sh = "/bin/sh";
static char *Mv = "/bin/mv";
static char *Rm = "/bin/rm";
static char *Touch = "/bin/touch";
static char *Chmod = "/bin/chmod";
static char *Chown = "/bin/chown";
static char *Gzip = "/bin/gzip";
static char *Mkdir = "/bin/mkdir";

/* return from time(0), gathered early on to avoid slewed timestamps */
time_t Now;

/* list of before commands that have been executed */
static struct lut *Beforecmds;

/* list of after commands to execute before exiting */
static struct lut *Aftercmds;

/* list of conffile entry names that are considered "done" */
static struct lut *Donenames;

/* A list of names of files to be gzipped */
static struct lut *Gzipnames = NULL;

/*
 * only the "FfhnVv" options are allowed in the first form of this command,
 * so this defines the list of options that are an error in they appear
 * in the first form.  In other words, it is not allowed to run logadm
 * with any of these options unless at least one logname is also provided.
 */
#define	OPTIONS_NOT_FIRST_FORM	"eNrwpPsabcglmoRtzACEST"

/* text that we spew with the -h flag */
#define	HELP1 \
"Usage: logadm [options]\n"\
"       (processes all entries in /etc/logadm.conf or conffile given by -f)\n"\
"   or: logadm [options] logname...\n"\
"       (processes the given lognames)\n"\
"\n"\
"General options:\n"\
"        -e mailaddr     mail errors to given address\n"\
"        -F timestamps   use timestamps instead of /var/logadm/timestamps\n"\
"        -f conffile     use conffile instead of /etc/logadm.conf\n"\
"        -h              display help\n"\
"        -N              not an error if log file nonexistent\n"\
"        -n              show actions, don't perform them\n"\
"        -r              remove logname entry from conffile\n"\
"        -V              ensure conffile entries exist, correct\n"\
"        -v              print info about actions happening\n"\
"        -w entryname    write entry to config file\n"\
"\n"\
"Options which control when a logfile is rotated:\n"\
"(default is: -s1b -p1w if no -s or -p)\n"\
"        -p period       only rotate if period passed since last rotate\n"\
"        -P timestamp    used to store rotation date in conffile\n"\
"        -s size         only rotate if given size or greater\n"\
"\n"
#define	HELP2 \
"Options which control how a logfile is rotated:\n"\
"(default is: -t '$file.$n', owner/group/mode taken from log file)\n"\
"        -a cmd          execute cmd after taking actions\n"\
"        -b cmd          execute cmd before taking actions\n"\
"        -c              copy & truncate logfile, don't rename\n"\
"        -g group        new empty log file group\n"\
"        -l              rotate log file with local time rather than UTC\n"\
"        -m mode         new empty log file mode\n"\
"        -M cmd          execute cmd to rotate the log file\n"\
"        -o owner        new empty log file owner\n"\
"        -R cmd          run cmd on file after rotate\n"\
"        -t template     template for naming old logs\n"\
"        -z count        gzip old logs except most recent count\n"\
"\n"\
"Options which control the expiration of old logfiles:\n"\
"(default is: -C10 if no -A, -C, or -S)\n"\
"        -A age          expire logs older than age\n"\
"        -C count        expire old logs until count remain\n"\
"        -E cmd          run cmd on file to expire\n"\
"        -S size         expire until space used is below size \n"\
"        -T pattern      pattern for finding old logs\n"

/*
 * main -- where it all begins
 */
/*ARGSUSED*/
int
main(int argc, char *argv[])
{
	struct opts *clopts;		/* from parsing command line */
	const char *conffile;		/* our configuration file */
	const char *timestamps;		/* our timestamps file */
	struct fn_list *lognames;	/* list of lognames we're processing */
	struct fn *fnp;
	char *val;
	char *buf;
	int status;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"	/* only used if Makefiles don't define it */
#endif

	(void) textdomain(TEXT_DOMAIN);

	/* we only print times into the timestamps file, so make them uniform */
	(void) setlocale(LC_TIME, "C");

	/* give our name to error routines & skip it for arg parsing */
	err_init(*argv++);
	(void) setlinebuf(stdout);

	if (putenv("PATH=/bin"))
		err(EF_SYS, "putenv PATH");
	if (putenv("TZ=UTC"))
		err(EF_SYS, "putenv TZ");
	tzset();

	(void) umask(0);

	Now = time(0);

	/* check for (undocumented) debugging environment variables */
	if (val = getenv("_LOGADM_DEFAULT_CONFFILE"))
		Default_conffile = val;
	if (val = getenv("_LOGADM_DEFAULT_TIMESTAMPS"))
		Default_timestamps = val;
	if (val = getenv("_LOGADM_DEBUG"))
		Debug = atoi(val);
	if (val = getenv("_LOGADM_SH"))
		Sh = val;
	if (val = getenv("_LOGADM_MV"))
		Mv = val;
	if (val = getenv("_LOGADM_RM"))
		Rm = val;
	if (val = getenv("_LOGADM_TOUCH"))
		Touch = val;
	if (val = getenv("_LOGADM_CHMOD"))
		Chmod = val;
	if (val = getenv("_LOGADM_CHOWN"))
		Chown = val;
	if (val = getenv("_LOGADM_GZIP"))
		Gzip = val;
	if (val = getenv("_LOGADM_MKDIR"))
		Mkdir = val;

	opts_init(Opttable, Opttable_cnt);

	/* parse command line arguments */
	if (SETJMP)
		usage("bailing out due to command line errors");
	else
		clopts = opts_parse(NULL, argv, OPTF_CLI);

	if (Debug) {
		(void) fprintf(stderr, "command line opts:");
		opts_print(clopts, stderr, NULL);
		(void) fprintf(stderr, "\n");
	}

	/*
	 * There are many moods of logadm:
	 *
	 *	1. "-h" for help was given.  We spew a canned help
	 *	   message and exit, regardless of any other options given.
	 *
	 *	2. "-r" or "-w" asking us to write to the conffile.  Lots
	 *	   of argument checking, then we make the change to conffile
	 *	   and exit.  (-r processing actually happens in dologname().)
	 *
	 *	3. "-V" to search/verify the conffile was given.  We do
	 *	   the appropriate run through the conffile and exit.
	 *	   (-V processing actually happens in dologname().)
	 *
	 *	4. No lognames were given, so we're being asked to go through
	 *	   every entry in conffile.  We verify that only the options
	 *	   that make sense for this form of the command are present
	 *	   and fall into the main processing loop below.
	 *
	 *	5. lognames were given, so we fall into the main processing
	 *	   loop below to work our way through them.
	 *
	 * The last two cases are where the option processing gets more
	 * complex.  Each time around the main processing loop, we're
	 * in one of these cases:
	 *
	 *	A. No cmdargs were found (we're in case 4), the entry
	 *	   in conffile supplies no log file names, so the entry
	 *	   name itself is the logfile name (or names, if it globs
	 *	   to multiple file names).
	 *
	 *	B. No cmdargs were found (we're in case 4), the entry
	 *	   in conffile gives log file names that we then loop
	 *	   through and rotate/expire.  In this case, the entry
	 *	   name is specifically NOT one of the log file names.
	 *
	 *	C. We're going through the cmdargs (we're in case 5),
	 *	   the entry in conffile either doesn't exist or it exists
	 *	   but supplies no log file names, so the cmdarg itself
	 *	   is the log file name.
	 *
	 *	D. We're going through the cmdargs (we're in case 5),
	 *	   a matching entry in conffile supplies log file names
	 *	   that we then loop through and rotate/expire.  In this
	 *	   case the entry name is specifically NOT one of the log
	 *	   file names.
	 *
	 * As we're doing all this, any options given on the command line
	 * override any found in the conffile, and we apply the defaults
	 * for rotation conditions and expiration conditions, etc. at the
	 * last opportunity, when we're sure they haven't been overridden
	 * by an option somewhere along the way.
	 *
	 */

	/* help option overrides anything else */
	if (opts_count(clopts, "h")) {
		(void) fputs(HELP1, stderr);
		(void) fputs(HELP2, stderr);
		err_done(0);
		/*NOTREACHED*/
	}

	/* detect illegal option combinations */
	if (opts_count(clopts, "rwV") > 1)
		usage("Only one of -r, -w, or -V may be used at a time.");
	if (opts_count(clopts, "cM") > 1)
		usage("Only one of -c or -M may be used at a time.");

	/* arrange for error output to be mailed if clopts includes -e */
	if (opts_count(clopts, "e"))
		err_mailto(opts_optarg(clopts, "e"));

	/* this implements the default conffile and timestamps */
	if ((conffile = opts_optarg(clopts, "f")) == NULL)
		conffile = Default_conffile;
	if ((timestamps = opts_optarg(clopts, "F")) == NULL)
		timestamps = Default_timestamps;
	if (opts_count(clopts, "v"))
		(void) out("# loading %s\n", conffile);
	status = conf_open(conffile, timestamps, clopts);
	if (!status && opts_count(clopts, "V"))
		err_done(0);

	/* handle conffile write option */
	if (opts_count(clopts, "w")) {
		if (Debug)
			(void) fprintf(stderr,
			    "main: add/replace conffile entry: <%s>\n",
			    opts_optarg(clopts, "w"));
		conf_replace(opts_optarg(clopts, "w"), clopts);
		conf_close(clopts);
		err_done(0);
		/*NOTREACHED*/
	}

	/*
	 * lognames is either a list supplied on the command line,
	 * or every entry in the conffile if none were supplied.
	 */
	lognames = opts_cmdargs(clopts);
	if (fn_list_empty(lognames)) {
		/*
		 * being asked to do all entries in conffile
		 *
		 * check to see if any options were given that only
		 * make sense when lognames are given specifically
		 * on the command line.
		 */
		if (opts_count(clopts, OPTIONS_NOT_FIRST_FORM))
			usage("some options require logname argument");
		if (Debug)
			(void) fprintf(stderr,
			    "main: run all entries in conffile\n");
		lognames = conf_entries();
	}

	/* foreach logname... */
	fn_list_rewind(lognames);
	while ((fnp = fn_list_next(lognames)) != NULL) {
		buf = fn_s(fnp);
		if (buf != NULL && lut_lookup(Donenames, buf) != NULL) {
			if (Debug)
				(void) fprintf(stderr,
				    "main: logname already done: <%s>\n",
				    buf);
			continue;
		}
		if (buf != NULL && SETJMP)
			err(EF_FILE, "bailing out on logname \"%s\" "
			    "due to errors", buf);
		else
			dologname(fnp, clopts);
	}

	/* execute any after commands */
	lut_walk(Aftercmds, doaftercmd, clopts);

	/* execute any gzip commands */
	lut_walk(Gzipnames, do_delayed_gzip, clopts);

	/* write out any conffile changes */
	conf_close(clopts);

	err_done(0);
	/*NOTREACHED*/
	return (0);	/* for lint's little mind */
}

/* spew a message, then a usage message, then exit */
static void
usage(const char *msg)
{
	if (msg)
		err(0, "%s\nUse \"logadm -h\" for help.", msg);
	else
		err(EF_RAW, "Use \"logadm -h\" for help.\n");
}

/* helper function used by doaftercmd() to join mail addrs with commas */
/*ARGSUSED1*/
static void
commajoin(const char *lhs, void *rhs, void *arg)
{
	struct fn *fnp = (struct fn *)arg;
	char *buf;

	buf = fn_s(fnp);
	if (buf != NULL && *buf)
		fn_putc(fnp, ',');
	fn_puts(fnp, lhs);
}

/* helper function used by main() to run "after" commands */
static void
doaftercmd(const char *lhs, void *rhs, void *arg)
{
	struct opts *opts = (struct opts *)arg;
	struct lut *addrs = (struct lut *)rhs;

	if (addrs) {
		struct fn *fnp = fn_new(NULL);

		/*
		 * addrs contains list of email addrs that should get
		 * the error output when this after command is executed.
		 */
		lut_walk(addrs, commajoin, fnp);
		err_mailto(fn_s(fnp));
	}

	docmd(opts, "-a cmd", Sh, "-c", lhs, NULL);
}

/* perform delayed gzip */

static void
do_delayed_gzip(const char *lhs, void *rhs, void *arg)
{
	struct opts *opts = (struct opts *)arg;

	if (rhs == NULL) {
		if (Debug) {
			(void) fprintf(stderr, "do_delayed_gzip: not gzipping "
			    "expired file <%s>\n", lhs);
		}
		return;
	}
	docmd(opts, "compress old log (-z flag)", Gzip, "-f", lhs, NULL);
}


/* main logname processing */
static void
dologname(struct fn *fnp, struct opts *clopts)
{
	const char *logname = fn_s(fnp);
	struct opts *cfopts;
	struct opts *allopts;
	struct fn_list *logfiles;
	struct fn_list *globbedfiles;
	struct fn *nextfnp;

	/* look up options set by config file */
	cfopts = conf_opts(logname);

	if (opts_count(clopts, "v"))
		(void) out("# processing logname: %s\n", logname);

	if (Debug) {
		if (logname != NULL)
			(void) fprintf(stderr, "dologname: logname <%s>\n",
			    logname);
		(void) fprintf(stderr, "conffile opts:");
		opts_print(cfopts, stderr, NULL);
		(void) fprintf(stderr, "\n");
	}

	/* handle conffile lookup option */
	if (opts_count(clopts, "V")) {
		/* lookup an entry in conffile */
		if (Debug)
			(void) fprintf(stderr,
			    "dologname: lookup conffile entry\n");
		if (conf_lookup(logname)) {
			opts_printword(logname, stdout);
			opts_print(cfopts, stdout, NULL);
			(void) out("\n");
		} else
			err_exitcode(1);
		return;
	}

	/* handle conffile removal option */
	if (opts_count(clopts, "r")) {
		if (Debug)
			(void) fprintf(stderr,
			    "dologname: remove conffile entry\n");
		if (conf_lookup(logname))
			conf_replace(logname, NULL);
		else
			err_exitcode(1);
		return;
	}

	/* generate combined options */
	allopts = opts_merge(cfopts, clopts);

	/* arrange for error output to be mailed if allopts includes -e */
	if (opts_count(allopts, "e"))
		err_mailto(opts_optarg(allopts, "e"));
	else
		err_mailto(NULL);

	/* this implements the default rotation rules */
	if (opts_count(allopts, "sp") == 0) {
		if (opts_count(clopts, "v"))
			(void) out(
			    "#     using default rotate rules: -s1b -p1w\n");
		(void) opts_set(allopts, "s", "1b");
		(void) opts_set(allopts, "p", "1w");
	}

	/* this implements the default expiration rules */
	if (opts_count(allopts, "ACS") == 0) {
		if (opts_count(clopts, "v"))
			(void) out("#     using default expire rule: -C10\n");
		(void) opts_set(allopts, "C", "10");
	}

	/* this implements the default template */
	if (opts_count(allopts, "t") == 0) {
		if (opts_count(clopts, "v"))
			(void) out("#     using default template: $file.$n\n");
		(void) opts_set(allopts, "t", "$file.$n");
	}

	if (Debug) {
		(void) fprintf(stderr, "merged opts:");
		opts_print(allopts, stderr, NULL);
		(void) fprintf(stderr, "\n");
	}

	/*
	 * if the conffile entry supplied log file names, then
	 * logname is NOT one of the log file names (it was just
	 * the entry name in conffile).
	 */
	logfiles = opts_cmdargs(cfopts);
	if (Debug) {
		char *buf;
		(void) fprintf(stderr, "dologname: logfiles from cfopts:\n");
		fn_list_rewind(logfiles);
		while ((nextfnp = fn_list_next(logfiles)) != NULL) {
			buf = fn_s(nextfnp);
			if (buf != NULL)
				(void) fprintf(stderr, "    <%s>\n", buf);
		}
	}
	if (fn_list_empty(logfiles))
		globbedfiles = glob_glob(fnp);
	else
		globbedfiles = glob_glob_list(logfiles);

	/* go through the list produced by glob expansion */
	fn_list_rewind(globbedfiles);
	while ((nextfnp = fn_list_next(globbedfiles)) != NULL)
		if (rotatelog(nextfnp, allopts))
			expirefiles(nextfnp, allopts);

	fn_list_free(globbedfiles);
	opts_free(allopts);
}


/* absurdly long buffer lengths for holding user/group/mode strings */
#define	TIMESTRMAX	100
#define	MAXATTR		100

/* rotate a log file if necessary, returns true if ok to go on to expire step */
static boolean_t
rotatelog(struct fn *fnp, struct opts *opts)
{
	char *fname = fn_s(fnp);
	struct stat stbuf;
	char nowstr[TIMESTRMAX];
	struct fn *recentlog = fn_new(NULL);	/* for -R cmd */
	char ownerbuf[MAXATTR];
	char groupbuf[MAXATTR];
	char modebuf[MAXATTR];
	const char *owner;
	const char *group;
	const char *mode;

	if (Debug && fname != NULL)
		(void) fprintf(stderr, "rotatelog: fname <%s>\n", fname);

	if (opts_count(opts, "p") && opts_optarg_int(opts, "p") == OPTP_NEVER)
		return (B_TRUE);	/* "-p never" forced no rotate */

	/* prepare the keywords */
	kw_init(fnp, NULL);
	if (Debug > 1) {
		(void) fprintf(stderr, "rotatelog keywords:\n");
		kw_print(stderr);
	}

	if (lstat(fname, &stbuf) < 0) {
		if (opts_count(opts, "N"))
			return (1);
		err(EF_WARN|EF_SYS, "%s", fname);
		return (B_FALSE);
	}

	if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
		err(EF_WARN, "%s is a symlink", fname);
		return (B_FALSE);
	}

	if ((stbuf.st_mode & S_IFMT) != S_IFREG) {
		err(EF_WARN, "%s is not a regular file", fname);
		return (B_FALSE);
	}

	/* even if size condition is not met, this entry is "done" */
	if (opts_count(opts, "s") &&
	    stbuf.st_size < opts_optarg_int(opts, "s")) {
		Donenames = lut_add(Donenames, fname, "1");
		return (B_TRUE);
	}

	/* see if age condition is present, and return if not met */
	if (opts_count(opts, "p")) {
		off_t when = opts_optarg_int(opts, "p");
		struct opts *cfopts;

		/* unless rotate forced by "-p now", see if period has passed */
		if (when != OPTP_NOW) {
			/*
			 * "when" holds the number of seconds that must have
			 * passed since the last time this log was rotated.
			 * of course, running logadm can take a little time
			 * (typically a second or two, but longer if the
			 * conffile has lots of stuff in it) and that amount
			 * of time is variable, depending on system load, etc.
			 * so we want to allow a little "slop" in the value of
			 * "when".  this way, if a log should be rotated every
			 * week, and the number of seconds passed is really a
			 * few seconds short of a week, we'll go ahead and
			 * rotate the log as expected.
			 *
			 */
			if (when >= 60 * 60)
				when -= 59;

			/*
			 * last rotation is recorded as argument to -P,
			 * but if logname isn't the same as log file name
			 * then the timestamp would be recorded on a
			 * separate line in the timestamp file.  so if we
			 * haven't seen a -P already, we check to see if
			 * it is part of a specific entry for the log
			 * file name.  this handles the case where the
			 * logname is "apache", it supplies a log file
			 * name like "/var/apache/logs/[a-z]*_log",
			 * which expands to multiple file names.  if one
			 * of the file names is "/var/apache/logs/access_log"
			 * the the -P will be attached to a line with that
			 * logname in the timestamp file.
			 */
			if (opts_count(opts, "P")) {
				off_t last = opts_optarg_int(opts, "P");

				/* return if not enough time has passed */
				if (Now - last < when)
					return (B_TRUE);
			} else if ((cfopts = conf_opts(fname)) != NULL &&
			    opts_count(cfopts, "P")) {
				off_t last = opts_optarg_int(cfopts, "P");

				/*
				 * just checking this means this entry
				 * is now "done" if we're going through
				 * the entire conffile
				 */
				Donenames = lut_add(Donenames, fname, "1");

				/* return if not enough time has passed */
				if (Now - last < when)
					return (B_TRUE);
			}
		}
	}

	if (Debug)
		(void) fprintf(stderr, "rotatelog: conditions met\n");
	if (opts_count(opts, "l")) {
		/* Change the time zone to local time zone */
		if (putenv("TZ="))
			err(EF_SYS, "putenv TZ");
		tzset();
		Now = time(0);

		/* rename the log file */
		rotateto(fnp, opts, 0, recentlog, B_FALSE);

		/* Change the time zone to UTC */
		if (putenv("TZ=UTC"))
			err(EF_SYS, "putenv TZ");
		tzset();
		Now = time(0);
	} else {
		/* rename the log file */
		rotateto(fnp, opts, 0, recentlog, B_FALSE);
	}

	/* determine owner, group, mode for empty log file */
	if (opts_count(opts, "o"))
		(void) strlcpy(ownerbuf, opts_optarg(opts, "o"), MAXATTR);
	else {
		(void) snprintf(ownerbuf, MAXATTR, "%ld", stbuf.st_uid);
	}
	owner = ownerbuf;
	if (opts_count(opts, "g"))
		group = opts_optarg(opts, "g");
	else {
		(void) snprintf(groupbuf, MAXATTR, "%ld", stbuf.st_gid);
		group = groupbuf;
	}
	(void) strlcat(ownerbuf, ":", MAXATTR - strlen(ownerbuf));
	(void) strlcat(ownerbuf, group, MAXATTR - strlen(ownerbuf));
	if (opts_count(opts, "m"))
		mode = opts_optarg(opts, "m");
	else {
		(void) snprintf(modebuf, MAXATTR,
		    "%03lo", stbuf.st_mode & 0777);
		mode = modebuf;
	}

	/* create the empty log file */
	docmd(opts, NULL, Touch, fname, NULL, NULL);
	docmd(opts, NULL, Chown, owner, fname, NULL);
	docmd(opts, NULL, Chmod, mode, fname, NULL);

	/* execute post-rotation command */
	if (opts_count(opts, "R")) {
		struct fn *rawcmd = fn_new(opts_optarg(opts, "R"));
		struct fn *cmd = fn_new(NULL);

		kw_init(recentlog, NULL);
		(void) kw_expand(rawcmd, cmd, 0, B_FALSE);
		docmd(opts, "-R cmd", Sh, "-c", fn_s(cmd), NULL);
		fn_free(rawcmd);
		fn_free(cmd);
	}
	fn_free(recentlog);

	/*
	 * add "after" command to list of after commands.  we also record
	 * the email address, if any, where the error output of the after
	 * command should be sent.  if the after command is already on
	 * our list, add the email addr to the list the email addrs for
	 * that command (the after command will only be executed once,
	 * so the error output gets mailed to every address we've come
	 * across associated with this command).
	 */
	if (opts_count(opts, "a")) {
		const char *cmd = opts_optarg(opts, "a");
		struct lut *addrs = (struct lut *)lut_lookup(Aftercmds, cmd);
		if (opts_count(opts, "e"))
			addrs = lut_add(addrs, opts_optarg(opts, "e"), NULL);
		Aftercmds = lut_add(Aftercmds, opts_optarg(opts, "a"), addrs);
	}

	/* record the rotation date */
	(void) strftime(nowstr, sizeof (nowstr),
	    "%a %b %e %T %Y", gmtime(&Now));
	if (opts_count(opts, "v") && fname != NULL)
		(void) out("#     recording rotation date %s for %s\n",
		    nowstr, fname);
	conf_set(fname, "P", STRDUP(nowstr));
	Donenames = lut_add(Donenames, fname, "1");
	return (B_TRUE);
}

/* rotate files "up" according to current template */
static void
rotateto(struct fn *fnp, struct opts *opts, int n, struct fn *recentlog,
    boolean_t isgz)
{
	struct fn *template = fn_new(opts_optarg(opts, "t"));
	struct fn *newfile = fn_new(NULL);
	struct fn *dirname;
	int hasn;
	struct stat stbuf;
	char *buf1;
	char *buf2;

	/* expand template to figure out new filename */
	hasn = kw_expand(template, newfile, n, isgz);

	buf1 = fn_s(fnp);
	buf2 = fn_s(newfile);

	if (Debug)
		if (buf1 != NULL && buf2 != NULL) {
			(void) fprintf(stderr, "rotateto: %s -> %s (%d)\n",
			    buf1, buf2, n);
		}
	/* if filename is there already, rotate "up" */
	if (hasn && lstat(buf2, &stbuf) != -1)
		rotateto(newfile, opts, n + 1, recentlog, isgz);
	else if (hasn && opts_count(opts, "z")) {
		struct fn *gzfnp = fn_dup(newfile);
		/*
		 * since we're compressing old files, see if we
		 * about to rotate into one.
		 */
		fn_puts(gzfnp, ".gz");
		if (lstat(fn_s(gzfnp), &stbuf) != -1)
			rotateto(gzfnp, opts, n + 1, recentlog, B_TRUE);
		fn_free(gzfnp);
	}

	/* first time through run "before" cmd if not run already */
	if (n == 0 && opts_count(opts, "b")) {
		const char *cmd = opts_optarg(opts, "b");

		if (lut_lookup(Beforecmds, cmd) == NULL) {
			docmd(opts, "-b cmd", Sh, "-c", cmd, NULL);
			Beforecmds = lut_add(Beforecmds, cmd, "1");
		}
	}

	/* ensure destination directory exists */
	dirname = fn_dirname(newfile);
	docmd(opts, "verify directory exists", Mkdir, "-p",
	    fn_s(dirname), NULL);
	fn_free(dirname);

	/* do the rename */
	if (n == 0 && opts_count(opts, "c") != 0) {
		docopytruncate(opts, fn_s(fnp), fn_s(newfile));
	} else if (n == 0 && opts_count(opts, "M")) {
		struct fn *rawcmd = fn_new(opts_optarg(opts, "M"));
		struct fn *cmd = fn_new(NULL);

		/* use specified command to mv the log file */
		kw_init(fnp, newfile);
		(void) kw_expand(rawcmd, cmd, 0, B_FALSE);
		docmd(opts, "-M cmd", Sh, "-c", fn_s(cmd), NULL);
		fn_free(rawcmd);
		fn_free(cmd);
	} else
		/* common case: we call "mv" to handle the actual rename */
		docmd(opts, "rotate log file", Mv, "-f",
		    fn_s(fnp), fn_s(newfile));

	/* first time through, gather interesting info for caller */
	if (n == 0)
		fn_renew(recentlog, fn_s(newfile));
}

/* expire phase of logname processing */
static void
expirefiles(struct fn *fnp, struct opts *opts)
{
	char *fname = fn_s(fnp);
	struct fn *template;
	struct fn *pattern;
	struct fn_list *files;
	struct fn *nextfnp;
	off_t count;
	off_t size;

	if (Debug && fname != NULL)
		(void) fprintf(stderr, "expirefiles: fname <%s>\n", fname);

	/* return if no potential expire conditions */
	if (opts_count(opts, "zAS") == 0 && opts_optarg_int(opts, "C") == 0)
		return;

	kw_init(fnp, NULL);
	if (Debug > 1) {
		(void) fprintf(stderr, "expirefiles keywords:\n");
		kw_print(stderr);
	}

	/* see if pattern was supplied by user */
	if (opts_count(opts, "T")) {
		template = fn_new(opts_optarg(opts, "T"));
		pattern = glob_to_reglob(template);
	} else {
		/* nope, generate pattern based on rotation template */
		template = fn_new(opts_optarg(opts, "t"));
		pattern = fn_new(NULL);
		(void) kw_expand(template, pattern, -1,
		    opts_count(opts, "z") != 0);
	}

	/* match all old log files (hopefully not any others as well!) */
	files = glob_reglob(pattern);

	if (Debug) {
		char *buf;

		buf = fn_s(pattern);
		if (buf != NULL) {
			(void) fprintf(stderr, "expirefiles: pattern <%s>\n",
			    buf);
		}
		fn_list_rewind(files);
		while ((nextfnp = fn_list_next(files)) != NULL) {
			buf = fn_s(nextfnp);
			if (buf != NULL)
				(void) fprintf(stderr, "    <%s>\n", buf);
		}
	}

	/* see if count causes expiration */
	if ((count = opts_optarg_int(opts, "C")) > 0) {
		int needexpire = fn_list_count(files) - count;

		if (Debug)
			(void) fprintf(stderr, "expirefiles: needexpire %d\n",
			    needexpire);

		while (needexpire > 0 &&
		    ((nextfnp = fn_list_popoldest(files)) != NULL)) {
			dorm(opts, "expire by count rule", nextfnp);
			fn_free(nextfnp);
			needexpire--;
		}
	}

	/* see if total size causes expiration */
	if (opts_count(opts, "S") && (size = opts_optarg_int(opts, "S")) > 0) {
		while (fn_list_totalsize(files) > size &&
		    ((nextfnp = fn_list_popoldest(files)) != NULL)) {
			dorm(opts, "expire by size rule", nextfnp);
			fn_free(nextfnp);
		}
	}

	/* see if age causes expiration */
	if (opts_count(opts, "A")) {
		int mtime = (int)time(0) - (int)opts_optarg_int(opts, "A");

		while ((nextfnp = fn_list_popoldest(files)) != NULL) {
			if (fn_getstat(nextfnp)->st_mtime < mtime) {
				dorm(opts, "expire by age rule", nextfnp);
				fn_free(nextfnp);
			} else {
				fn_list_addfn(files, nextfnp);
				break;
			}
		}
	}

	/* record old log files to be gzip'ed according to -z count */
	if (opts_count(opts, "z")) {
		int zcount = (int)opts_optarg_int(opts, "z");
		int fcount = fn_list_count(files);

		while (fcount > zcount &&
		    (nextfnp = fn_list_popoldest(files)) != NULL) {
			if (!fn_isgz(nextfnp)) {
				/*
				 * Don't gzip the old log file yet -
				 * it takes too long. Just remember that we
				 * need to gzip.
				 */
				if (Debug) {
					(void) fprintf(stderr,
					    "will compress %s count %d\n",
					    fn_s(nextfnp), fcount);
				}
				Gzipnames = lut_add(Gzipnames,
				    fn_s(nextfnp), "1");
			}
			fn_free(nextfnp);
			fcount--;
		}
	}

	fn_free(template);
	fn_list_free(files);
}

/* execute a command to remove an expired log file */
static void
dorm(struct opts *opts, const char *msg, struct fn *fnp)
{
	if (opts_count(opts, "E")) {
		struct fn *rawcmd = fn_new(opts_optarg(opts, "E"));
		struct fn *cmd = fn_new(NULL);

		/* user supplied cmd, expand $file */
		kw_init(fnp, NULL);
		(void) kw_expand(rawcmd, cmd, 0, B_FALSE);
		docmd(opts, msg, Sh, "-c", fn_s(cmd), NULL);
		fn_free(rawcmd);
		fn_free(cmd);
	} else
		docmd(opts, msg, Rm, "-f", fn_s(fnp), NULL);
	Gzipnames = lut_add(Gzipnames, fn_s(fnp), NULL);
}

/* execute a command, producing -n and -v output as necessary */
static void
docmd(struct opts *opts, const char *msg, const char *cmd,
    const char *arg1, const char *arg2, const char *arg3)
{
	int pid;
	int errpipe[2];

	/* print info about command if necessary */
	if (opts_count(opts, "vn")) {
		const char *simplecmd;

		if ((simplecmd = strrchr(cmd, '/')) == NULL)
			simplecmd = cmd;
		else
			simplecmd++;
		(void) out("%s", simplecmd);
		if (arg1)
			(void) out(" %s", arg1);
		if (arg2)
			(void) out(" %s", arg2);
		if (arg3)
			(void) out(" %s", arg3);
		if (msg)
			(void) out(" # %s", msg);
		(void) out("\n");
	}

	if (opts_count(opts, "n"))
		return;		/* -n means don't really do it */

	/*
	 * run the cmd and see if it failed.  this function is *not* a
	 * generic command runner -- we depend on some knowledge we
	 * have about the commands we run.  first of all, we expect
	 * errors to spew something to stderr, and that something is
	 * typically short enough to fit into a pipe so we can wait()
	 * for the command to complete and then fetch the error text
	 * from the pipe.  we also expect the exit codes to make sense.
	 * notice also that we only allow a command name which is an
	 * absolute pathname, and two args must be supplied (the
	 * second may be NULL, or they may both be NULL).
	 */
	if (pipe(errpipe) < 0)
		err(EF_SYS, "pipe");

	if ((pid = fork()) < 0)
		err(EF_SYS, "fork");
	else if (pid) {
		int wstat;
		int count;

		/* parent */
		(void) close(errpipe[1]);
		if (waitpid(pid, &wstat, 0) < 0)
			err(EF_SYS, "waitpid");

		/* check for stderr output */
		if (ioctl(errpipe[0], FIONREAD, &count) >= 0 && count) {
			err(EF_WARN, "command failed: %s%s%s%s%s%s%s",
			    cmd,
			    (arg1) ? " " : "",
			    (arg1) ? arg1 : "",
			    (arg2) ? " " : "",
			    (arg2) ? arg2 : "",
			    (arg3) ? " " : "",
			    (arg3) ? arg3 : "");
			err_fromfd(errpipe[0]);
		} else if (WIFSIGNALED(wstat))
			err(EF_WARN,
			    "command died, signal %d: %s%s%s%s%s%s%s",
			    WTERMSIG(wstat),
			    cmd,
			    (arg1) ? " " : "",
			    (arg1) ? arg1 : "",
			    (arg2) ? " " : "",
			    (arg2) ? arg2 : "",
			    (arg3) ? " " : "",
			    (arg3) ? arg3 : "");
		else if (WIFEXITED(wstat) && WEXITSTATUS(wstat))
			err(EF_WARN,
			    "command error, exit %d: %s%s%s%s%s%s%s",
			    WEXITSTATUS(wstat),
			    cmd,
			    (arg1) ? " " : "",
			    (arg1) ? arg1 : "",
			    (arg2) ? " " : "",
			    (arg2) ? arg2 : "",
			    (arg3) ? " " : "",
			    (arg3) ? arg3 : "");

		(void) close(errpipe[0]);
	} else {
		/* child */
		(void) dup2(errpipe[1], fileno(stderr));
		(void) close(errpipe[0]);
		(void) execl(cmd, cmd, arg1, arg2, arg3, 0);
		perror(cmd);
		_exit(1);
	}
}

/* do internal atomic file copy and truncation */
static void
docopytruncate(struct opts *opts, const char *file, const char *file_copy)
{
	int fi, fo;
	char buf[128 * 1024];
	struct stat s;
	struct utimbuf times;
	off_t written = 0, rem, last = 0, thresh = 1024 * 1024;
	ssize_t len;

	/* print info if necessary */
	if (opts_count(opts, "vn") != 0) {
		(void) out("# log rotation via atomic copy and truncation"
		    " (-c flag):\n");
		(void) out("# copy %s to %s\n", file, file_copy);
		(void) out("# truncate %s\n", file);
	}

	if (opts_count(opts, "n"))
		return;		/* -n means don't really do it */

	/* open log file to be rotated and remember its chmod mask */
	if ((fi = open(file, O_RDWR)) < 0) {
		err(EF_SYS, "cannot open file %s", file);
		return;
	}

	if (fstat(fi, &s) < 0) {
		err(EF_SYS, "cannot access: %s", file);
		(void) close(fi);
		return;
	}

	/* create new file for copy destination with correct attributes */
	if ((fo = open(file_copy, O_CREAT|O_TRUNC|O_WRONLY, s.st_mode)) < 0) {
		err(EF_SYS, "cannot create file: %s", file_copy);
		(void) close(fi);
		return;
	}

	(void) fchown(fo, s.st_uid, s.st_gid);

	/*
	 * Now we'll loop, reading the log file and writing it to our copy
	 * until the bytes remaining are beneath our atomicity threshold -- at
	 * which point we'll lock the file and copy the remainder atomically.
	 * The body of this loop is non-atomic with respect to writers, the
	 * rationale being that total atomicity (that is, locking the file for
	 * the entire duration of the copy) comes at too great a cost for a
	 * large log file, as the writer (i.e., the daemon whose log is being
	 * rolled) can be blocked for an unacceptable duration.  (For one
	 * particularly loquacious daemon, this period was observed to be
	 * several minutes in length -- a time so long that it induced
	 * additional failures in dependent components.)  Note that this means
	 * that if the log file is not always appended to -- if it is opened
	 * without O_APPEND or otherwise truncated outside of logadm -- this
	 * will result in our log snapshot being incorrect.  But of course, in
	 * either of these cases, the use of logadm at all is itself
	 * suspect...
	 */
	do {
		if (fstat(fi, &s) < 0) {
			err(EF_SYS, "cannot stat: %s", file);
			(void) close(fi);
			(void) close(fo);
			(void) remove(file_copy);
			return;
		}

		if ((rem = s.st_size - written) < thresh) {
			if (rem >= 0)
				break;

			/*
			 * If the file became smaller, something fishy is going
			 * on; we'll truncate our copy, reset our seek offset
			 * and break into the atomic copy.
			 */
			(void) ftruncate(fo, 0);
			(void) lseek(fo, 0, SEEK_SET);
			(void) lseek(fi, 0, SEEK_SET);
			break;
		}

		if (written != 0 && rem > last) {
			/*
			 * We're falling behind -- this file is getting bigger
			 * faster than we're able to write it; break out and
			 * lock the file to block the writer.
			 */
			break;
		}

		last = rem;

		while (rem > 0) {
			if ((len = read(fi, buf, MIN(sizeof (buf), rem))) <= 0)
				break;

			if (write(fo, buf, len) == len) {
				rem -= len;
				written += len;
				continue;
			}

			err(EF_SYS, "cannot write into file %s", file_copy);
			(void) close(fi);
			(void) close(fo);
			(void) remove(file_copy);
			return;
		}
	} while (len >= 0);

	/* lock log file so that nobody can write into it before we are done */
	if (fchmod(fi, s.st_mode|S_ISGID) < 0)
		err(EF_SYS, "cannot set mandatory lock bit for: %s", file);

	if (lockf(fi, F_LOCK, 0) == -1)
		err(EF_SYS, "cannot lock file %s", file);

	/* do atomic copy and truncation */
	while ((len = read(fi, buf, sizeof (buf))) > 0)
		if (write(fo, buf, len) != len) {
			err(EF_SYS, "cannot write into file %s", file_copy);
			(void) lockf(fi, F_ULOCK, 0);
			(void) fchmod(fi, s.st_mode);
			(void) close(fi);
			(void) close(fo);
			(void) remove(file_copy);
			return;
		}

	(void) ftruncate(fi, 0);

	/* unlock log file */
	if (lockf(fi, F_ULOCK, 0) == -1)
		err(EF_SYS, "cannot unlock file %s", file);

	if (fchmod(fi, s.st_mode) < 0)
		err(EF_SYS, "cannot reset mandatory lock bit for: %s", file);

	(void) close(fi);
	(void) close(fo);

	/* keep times from original file */
	times.actime = s.st_atime;
	times.modtime = s.st_mtime;
	(void) utime(file_copy, &times);
}
