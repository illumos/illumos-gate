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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <apptrace.h>
#include <libintl.h>
#include <locale.h>

#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif
#define	TRUE  1
#define	FALSE 0

/* Various list pointers */
static char *fromlist;
static char *fromexcl;
static char *tolist;
static char *toexcl;

static char *iflist;
static char *ifexcl;
static char *viflist;
static char *vifexcl;

/* The supported options */
static char const *optlet = "F:fo:T:t:v:";
/* basename(argv[0]) */
static char const *command;

/* The environment variables that'll get picked up by apptrace.so.1 */
static char const *APPTRACE_BINDTO = "APPTRACE_BINDTO=";
static char const *APPTRACE_BINDTO_EXCLUDE = "APPTRACE_BINDTO_EXCLUDE=";
static char const *APPTRACE_BINDFROM = "APPTRACE_BINDFROM=";
static char const *APPTRACE_BINDFROM_EXCLUDE = "APPTRACE_BINDFROM_EXCLUDE=";
static char const *APPTRACE_OUTPUT = "APPTRACE_OUTPUT=";
static char const *APPTRACE_PID = "APPTRACE_PID=";
static char const *APPTRACE_INTERFACES = "APPTRACE_INTERFACES=";
static char const *APPTRACE_INTERFACES_EXCLUDE = "APPTRACE_INTERFACES_EXCLUDE=";
static char const *APPTRACE_VERBOSE = "APPTRACE_VERBOSE=";
static char const *APPTRACE_VERBOSE_EXCLUDE = "APPTRACE_VERBOSE_EXCLUDE=";

/* Some default values for the above */
static char *LD_AUDIT = "LD_AUDIT=/usr/lib/abi/apptrace.so.1";
#if	defined(sparc) || defined(__sparcv9)
static char *LD_AUDIT_64 =
	"LD_AUDIT_64=/usr/lib/abi/sparcv9/apptrace.so.1";
#elif	defined(i386) || defined(__amd64)
static char *LD_AUDIT_64 =
	"LD_AUDIT_64=/usr/lib/abi/amd64/apptrace.so.1";
#else
#error Unsupported Platform
#endif

static char const *one = "1";

/* The local support functions */
static void usage(char const *);
static void stuffenv(char const *, char const *);
static char *buildlist(char **, char const *);

int
main(int argc, char **argv)
{
	int	opt;
	int	fflag = FALSE;
	int	errflg = FALSE;
	char	*outfile = NULL;
	int	stat_loc;
	pid_t	wret, pid;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);


	/* Squirrel the basename of the command name away. */
	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, optlet)) != EOF) {
		switch (opt) {
		case 'F':
			if (*optarg == '!')
				(void) buildlist(&fromexcl, optarg + 1);
			else
				(void) buildlist(&fromlist, optarg);
			break;
		case 'f':
			fflag = TRUE;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'T':
			if (*optarg == '!')
				(void) buildlist(&toexcl, optarg + 1);
			else
				(void) buildlist(&tolist, optarg);
			break;
		case 't':
			if (*optarg == '!')
				(void) buildlist(&ifexcl, optarg + 1);
			else
				(void) buildlist(&iflist, optarg);
			break;
		case 'v':
			if (*optarg == '!')
				(void) buildlist(&vifexcl, optarg + 1);
			else
				(void) buildlist(&viflist, optarg);
			break;
		default:
			errflg = TRUE;
			break;
		}
	}

	/*
	 * Whack the argument vector so that the remainder will be
	 * ready for passing to exec
	 */
	argc -= optind;
	argv += optind;

	/*
	 * If there was a problem with the options, or there was no command
	 * to be run, then give the usage message and bugout.
	 */
	if (errflg || argc <= 0) {
		usage(command);
		exit(EXIT_FAILURE);
	}

	/*
	 * This is where the environment gets setup.
	 */
	if (fflag == TRUE)
		stuffenv(APPTRACE_PID, one);

	if (fromexcl != NULL)
		stuffenv(APPTRACE_BINDFROM_EXCLUDE, fromexcl);
	if (fromlist != NULL)
		stuffenv(APPTRACE_BINDFROM, fromlist);

	if (tolist != NULL)
		stuffenv(APPTRACE_BINDTO, tolist);
	if (toexcl != NULL)
		stuffenv(APPTRACE_BINDTO_EXCLUDE, toexcl);

	if (iflist != NULL)
		stuffenv(APPTRACE_INTERFACES, iflist);
	if (ifexcl != NULL)
		stuffenv(APPTRACE_INTERFACES_EXCLUDE, ifexcl);

	if (viflist != NULL)
		stuffenv(APPTRACE_VERBOSE, viflist);
	if (vifexcl != NULL)
		stuffenv(APPTRACE_VERBOSE_EXCLUDE, vifexcl);

	if (outfile != NULL)
		stuffenv(APPTRACE_OUTPUT, outfile);

	/*
	 * It is the setting of the LD_AUDIT environment variable
	 * that tells ld.so.1 to enable link auditing when the child
	 * is exec()ed.
	 */
	(void) putenv(LD_AUDIT);
	(void) putenv(LD_AUDIT_64);

	/*
	 * The environment is now all setup.
	 * For those about to rock, we salute you!
	 */
	pid = fork();
	switch (pid) {
		/* Error */
	case -1:
		(void) fprintf(stderr, gettext("%s: fork failed: %s\n"),
		    command, strerror(errno));
		exit(EXIT_FAILURE);
		break;
		/* Child */
	case 0:
		/*
		 * Usual failure is argv[0] does not exist or is
		 * not executable.
		 */
		if (execvp(argv[0], argv)) {
			(void) fprintf(stderr, gettext("%s: %s: %s\n"),
			    command, argv[0], strerror(errno));
			_exit(EXIT_FAILURE);
		}
		break;
		/* Parent */
	default:
		wret = waitpid(pid, &stat_loc, 0);
		if (wret == -1) {
			(void) fprintf(stderr,
			    gettext("%s: waitpid failed: %s\n"),
			    command, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (wret != pid) {
			(void) fprintf(stderr,
			    gettext("%s: "
			    "waitpid returned %ld when child pid was %ld\n"),
			    command, wret, pid);
			exit(EXIT_FAILURE);
		}

		if (WIFSIGNALED(stat_loc)) {
			(void) fprintf(stderr, gettext("\n%s: %s: %s"),
			    command, argv[0], strsignal(WTERMSIG(stat_loc)));
			if (WCOREDUMP(stat_loc)) {
				(void) fputs(gettext("(Core dump)"), stderr);
#ifdef DEBUG
				(void) fputs(gettext("\nRunning pstack:\n"),
				    stderr);
				(void) putenv("LD_AUDIT=");
				(void) putenv("LD_AUDIT_64=");
				(void) system("/usr/proc/bin/pstack core");
#endif
			}
			(void) putc('\n', stderr);
		}

		/* Normal return from main() */
		return (WEXITSTATUS(stat_loc));
	}
	return (0);
	/* NOTREACHED */
}

/*
 * Take a string in the form "VAR=" and another in the
 * form "value" and paste them together.
 */
static void
stuffenv(char const *var, char const *val)
{
	int lenvar, lenval;
	char *stuff;

	lenvar = strlen(var);
	lenval = strlen(val);

	if ((stuff = malloc(lenvar + lenval + 1)) == NULL) {
		(void) fprintf(stderr, gettext("%s: malloc failed\n"), command);
		exit(EXIT_FAILURE);
	}
	(void) sprintf(stuff, "%s%s", var, val);
	(void) putenv(stuff);
}

/*
 * If *dst is empty, use strdup to duplicate src.
 * Otherwise:  dst = dst + "," + src;
 */
static char *
buildlist(char **dst, char const *src)
{
	int len;
	char *p;

	/*
	 * If dst is still empty then dup,
	 * if dup succeeds set dst.
	 */
	if (*dst == NULL) {
		p = strdup(src);
		if (p == NULL)
			goto error;
		*dst = p;
		return (p);
	}

	len = strlen(*dst);

	/* +2 because of the comma we add below */
	if ((p = realloc(*dst, len + strlen(src) + 2)) == NULL)
		goto error;

	*dst = p;

	*(*dst + len) = ',';
	(void) strcpy((*dst + len + 1), src);

	return (*dst);

error:
	(void) fprintf(stderr, gettext("%s: allocation failed: %s\n"),
	    command, strerror(errno));
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

static void
usage(char const *prog)
{
	(void) fprintf(stderr, gettext("Usage: %s [-f][-F [!]tracefromlist]"
	    "[-T [!]tracetolist][-o outputfile]\n"
	    "	[-t calls][-v calls] prog [prog arguments]\n"

	    "	-F <bindfromlist>\n"
	    "		A comma separated list of libraries that are to be\n"
	    "		traced.  Only calls from these libraries will be\n"
	    "		traced.  The default is to trace calls from the\n"
	    "		main executable.\n"
	    "		If <bindfromlist> begins with a ! then it defines\n"
	    "		a list of libraries to exclude from the trace.\n"
	    "	-T <bindtolist>\n"
	    "		A comma separated list of libraries that are to be\n"
	    "		traced.  Only calls to these libraries will be\n"
	    "		traced.  The default is to trace all calls.\n"
	    "		If <bindtolist> begins with a ! then it defines\n"
	    "		a list of libraries to exclude from the trace.\n"
	    "	-o <outputfile>\n"
	    "		%s output will be directed to 'outputfile'.\n"
	    "		by default it is placed on stderr\n"
	    "	-f\n"
	    "		Follow all children created by fork() and also\n"
	    "		print apptrace output for the children.  This also\n"
	    "		causes a 'pid' to be added to each output line\n"
	    "	-t <tracelist>\n"
	    "		A comma separated list of interfaces to trace.\n"
	    "		A list preceded by ! is an exlusion list.\n"
	    "	-v <verboselist>\n"
	    "		A comma separated list of interfaces to trace\n"
	    "		verbosely.\n"
	    "		A list preceded by ! is an exclusion list.\n"
	    "		Interfaces matched in -v do not also need to be\n"
	    "		named by -t\n"
	    "	All lists may use shell style wild cards.\n"
	    "	Leading path components or suffixes are not required when\n"
	    "	listing libraries (ie. libc will match /usr/lib/libc.so.1).\n"),
	    prog, prog);
}
