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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/systeminfo.h>

#include <tnf/tnfctl.h>

#include "set.h"
#include "cmd.h"
#include "spec.h"
#include "expr.h"
#include "source.h"
#include "list.h"
#include "prbk.h"

/*
 * Defines - Project private interfaces
 */

#define	DEBUG_ENTRY		"tnf_probe_debug"
#ifdef TESTING
#define	EMPTY_ENTRY		"tnf_probe_empty"
#endif

#define	USER_OUTSIZE		(4*1024*1024)
#define	KERNEL_OUTSIZE		(384*1024)

#if defined(__sparc)
#define	PREX32DIR	"/sparcv7/"
#elif defined(__i386) || defined(__amd64)
#define	PREX32DIR	"/i86/"
#endif
#define	PREX32EXEC	"/usr/bin" PREX32DIR "prex"

/*
 * Globals
 */

char			**g_argv;	/* copy of argv pointer */
tnfctl_handle_t		*g_hndl;	/* handle on target or kernel */

static int		g_verbose;	/* debugging to stderr */
static char		*g_cmdname;	/* target command name */
static char		**g_cmdargs;	/* target command args */
static pid_t		g_targetpid;	/* target process id */
static volatile boolean_t g_getcmds;	/* accept input flag */
static boolean_t	g_testflag;	/* asserted in test mode */
static char		*g_preload;	/* objects to preload */
static char		*g_outname;	/* tracefile name */
static char		*tracefile;	/* tracefile name used by list cmd */
int			g_outsize;	/* tracefile size */
boolean_t		g_kernelmode;	/* -k flag: kernel mode */
static int		prex_dmodel;	/* prex data model */
/*
 * Local Declarations
 */

static void usage(char **argv, const char *msg);
static void scanargs(int argc, char **argv);
static int set_signal(void);
static int get_data_model(pid_t pid);
static int get_elf_class(char *filename);
static int get_executable(char *);
static void prex_isaexec(char **argv, char **envp);
static void check_pid_model(char **argv, char **envp);
static void check_exec_model(char **argv, char **envp);

/* #### - FIXME - need to put this in a private header file */
extern void err_fatal(char *s, ...);

extern int	  yyparse(void);

static tnfctl_errcode_t check_trace_error(tnfctl_handle_t *hndl);
static void set_default_cmd(void);
static void get_commands(void);
static tnfctl_errcode_t set_tracefile(tnfctl_handle_t *hndl);
static tnfctl_errcode_t set_probe_discovery_callback(tnfctl_handle_t *hndl);
static void * perprobe(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_p);
static tnfctl_errcode_t perprobe2(tnfctl_handle_t *hndl,
	tnfctl_probe_t *probe_p, void *ignored);
static tnfctl_errcode_t percmd(expr_t *expr_p, cmd_kind_t kind, fcn_t *fcn_p,
	boolean_t isnew, void *calldata_p);
void quit(boolean_t killtarget, boolean_t runtarget);
void cmd_listtracefile();


/*
 * usage() - gives a description of the arguments, and exits
 */

static void
usage(char *argv[], const char *msg)
{
	if (msg)
		(void) fprintf(stderr,
			gettext("%s: %s\n"), argv[0], msg);

	(void) fprintf(stderr, gettext(
		"usage: %s [options] <cmd> [cmd-args...]\n"), argv[0]);
	(void) fprintf(stderr, gettext(
		"usage: %s [options] -p <pid>\n"), argv[0]);
	(void) fprintf(stderr, gettext(
		"usage: %s -s <kbytes-size> -k\n"), argv[0]);
	(void) fprintf(stderr, gettext(
		"options:\n"));
	(void) fprintf(stderr, gettext(
		"	-o <outfilename>   set trace output file name\n"));
	(void) fprintf(stderr, gettext(
		"	-s <kbytes-size>   set trace file size\n"));
	(void) fprintf(stderr, gettext(
		"	-l <sharedobjs>    shared objects to "
		"be preloaded (cmd only)\n"));

	exit(1);
}


/*
 * main() -
 */

int
main(int argc, char **argv, char **envp)
{
	tnfctl_errcode_t	err = TNFCTL_ERR_NONE;
	int			sys_err;
	tnfctl_trace_attrs_t	trace_attrs;
	tnfctl_event_t		event = TNFCTL_EVENT_EINTR;
	pid_t			prex_pid;

	/* internationalization stuff */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	g_argv = argv;

	prex_pid = getpid();
#if defined(DEBUG)
	fprintf(stderr, "### prex_pid = %d ###\n", prex_pid);
#endif
	prex_dmodel = get_data_model(prex_pid);
#if defined(DEBUG)
	fprintf(stderr, "### prex_dmodel = %d ###\n", prex_dmodel);
#endif
	scanargs(argc, argv);

	if (g_kernelmode) {
		/* prexing the kernel */
		err = tnfctl_kernel_open(&g_hndl);
		if (err) {
			err_fatal(gettext(
				"%s: trouble attaching to the kernel: %s\n"),
				argv[0], tnfctl_strerror(err));
		}
	} else {
		/* prexing a user process */
		if (g_targetpid != 0) {
			/* check data model */
			check_pid_model(argv, envp);
			/* attach case */
			err = tnfctl_pid_open(g_targetpid, &g_hndl);
			if (err == TNFCTL_ERR_NOLIBTNFPROBE) {
				err_fatal(gettext(
					"%s: missing symbols, is "
					"libtnfprobe.so loaded in target?\n"),
					argv[0], tnfctl_strerror(err));
			} else if (err) {
				err_fatal(gettext(
					"%s: trouble attaching to target "
					"process: %s\n"),
					argv[0], tnfctl_strerror(err));
			}
		} else {
			/* check elf class model */
			check_exec_model(argv, envp);
			/* exec case */
			err = tnfctl_exec_open(g_cmdname, g_cmdargs, NULL,
					g_preload, NULL, &g_hndl);
			if (err == TNFCTL_ERR_NONE)
				err = tnfctl_trace_attrs_get(g_hndl,
						&trace_attrs);
			if (err) {
				err_fatal(gettext(
					"%s: trouble creating target process: "
					"%s\n"),
					argv[0], tnfctl_strerror(err));
			}
			g_targetpid = trace_attrs.targ_pid;
		}

		sys_err = set_signal();
		if (sys_err)
			err_fatal(gettext(
				"%s: trouble setting up signal handler: %s\n"),
				argv[0], strerror(err));
	}

	/* initialize the source stack for the parser */
	source_init();

	if (!g_kernelmode) {
		/* set the tracefile name and size */
		err = set_tracefile(g_hndl);
		if (err) {
			(void) fprintf(stderr, gettext(
				"%s: trouble initializing tracefile: %s\n"),
				argv[0], tnfctl_strerror(err));
			goto Cleanup;
		}
		err = check_trace_error(g_hndl);
		if (err) {
			(void) fprintf(stderr, gettext(
				"%s: cannot read tracing status : %s\n"),
				argv[0], tnfctl_strerror(err));
			goto Cleanup;
		}
	}

	/* accept commands from stdin the first time through */
	g_getcmds = B_TRUE;

	/* set up default aliases */
	set_default_cmd();

	/* set up creator/destructor function to call for new probes */
	err = set_probe_discovery_callback(g_hndl);
	if (err) {
		(void) fprintf(stderr, gettext(
			"%s: error in probe discovery : %s\n"),
			argv[0], tnfctl_strerror(err));
		goto Cleanup;
	}

	if (g_kernelmode) {
		prbk_warn_pfilter_empty();
	}

	while (err == TNFCTL_ERR_NONE) {

		if (g_kernelmode || g_getcmds) {
			g_getcmds = B_FALSE;
			get_commands();
		}

		if (!g_kernelmode && (g_getcmds == B_FALSE)) {
		    err = tnfctl_continue(g_hndl, &event, NULL);
		    if (err) {
			(void) fprintf(stderr, gettext(
				"%s: cannot continue target : %s\n"),
				argv[0], tnfctl_strerror(err));
			goto Cleanup;
		    }
		}
		err = check_trace_error(g_hndl);
		if (err) {
			(void) fprintf(stderr, gettext(
				"%s: cannot read tracing status : %s\n"),
				argv[0], tnfctl_strerror(err));
			goto Cleanup;
		}
		if (!g_kernelmode) {
			if (event == TNFCTL_EVENT_EXEC) {
			    (void) printf(gettext(
				"Target process exec'd\n"));
			    quit(B_FALSE, B_TRUE);	/* quit resume */
			} else if (event == TNFCTL_EVENT_EXIT) {
			    /* target exited */
			    (void) fprintf(stderr, gettext(
				"%s: target process exited\n"),
				g_argv[0]);
			    goto Cleanup;
			} else if (event == TNFCTL_EVENT_TARGGONE) {
				/* target terminated */
			    (void) fprintf(stderr,
	gettext("%s: target process disappeared (without calling exit)\n"),
				g_argv[0]);
			    goto Cleanup;
			}
		}
	}

Cleanup:
	err = tnfctl_close(g_hndl, TNFCTL_TARG_DEFAULT);
	if (err)
		(void) fprintf(stderr, gettext(
			"%s: error on closing : %s\n"),
			argv[0], tnfctl_strerror(err));

	exit(0);

	return (0);

}

/*
 * check_trace_error() - checks whether there was an error in tracing
 */
static tnfctl_errcode_t
check_trace_error(tnfctl_handle_t *hndl)
{
	tnfctl_trace_attrs_t	trace_attrs;
	tnfctl_errcode_t	err;

	err = tnfctl_trace_attrs_get(hndl, &trace_attrs);
	if (err)
		return (err);

	if (trace_attrs.trace_buf_state == TNFCTL_BUF_BROKEN) {
		(void) printf(gettext("Tracing shut down in target program "
			"due to an internal error - Please restart prex "
			"and target\n"));
	}

	return (TNFCTL_ERR_NONE);
}

/*
 * set_default_cmd() - set the default debug entry and $all
 */
static void
set_default_cmd(void)
{
	if (!g_kernelmode)
		fcn(strdup("debug"), DEBUG_ENTRY);
#ifdef TESTING
	fcn(strdup("empty"), EMPTY_ENTRY);
#endif
	(void) set(strdup("all"), expr(spec(strdup("keys"), SPEC_EXACT),
				spec(strdup(".*"), SPEC_REGEXP)));

}

/*
 * process() - enable and disable selected probes
 */

typedef struct {
	tnfctl_probe_t	*probe_p;
	tnfctl_handle_t	*hndl;
} process_args_t;

static tnfctl_errcode_t
percmd(expr_t *expr_p, cmd_kind_t kind, fcn_t *fcn_p, boolean_t isnew,
	void *calldata_p)
{
	process_args_t *args_p = (process_args_t *)calldata_p;
	tnfctl_handle_t	*hndl = args_p->hndl;
	tnfctl_probe_t	*probe_p = args_p->probe_p;
	tnfctl_errcode_t err = TNFCTL_ERR_NONE;
	char *attrs;

	attrs = list_getattrs(probe_p);

	if (expr_match(expr_p, attrs)) {
#if defined(DEBUG) || defined(lint)
		if (g_verbose) {
			char		   *cmdstr[] = {
				"enable", "disable",
				"connect", "clear",
				"trace", "untrace"};

			(void) fprintf(stderr, ": %s command: %s ",
				(isnew) ? "new" : "old", cmdstr[kind]);
			expr_print(stderr, expr_p);
		}
#endif

		switch (kind) {
		case CMD_ENABLE:
			err = tnfctl_probe_enable(hndl, probe_p, NULL);
			break;
		case CMD_DISABLE:
			err = tnfctl_probe_disable(hndl, probe_p, NULL);
			break;
		case CMD_TRACE:
			err = tnfctl_probe_trace(hndl, probe_p, NULL);
			break;
		case CMD_UNTRACE:
			err = tnfctl_probe_untrace(hndl, probe_p, NULL);
			break;
		case CMD_CONNECT:
			err = tnfctl_probe_connect(hndl, probe_p, NULL,
				fcn_p->entry_name_p);
			break;
		case CMD_CLEAR:
			err = tnfctl_probe_disconnect_all(hndl, probe_p, NULL);
			break;
		}

#if defined(DEBUG) || defined(lint)
		if (g_verbose)
			(void) fprintf(stderr, "\n");
#endif

	}
	if (attrs)
		free(attrs);

	return (err);

}

/*ARGSUSED*/
static void *
perprobe(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_p)
{
	process_args_t  args;
	tnfctl_errcode_t err;

	args.probe_p = probe_p;
	args.hndl = hndl;
	err = cmd_traverse(percmd, &args);
	if (err) {
		(void) fprintf(stderr, gettext(
				"%s: error on new (dlopened) probe : %s\n"),
				g_argv[0], tnfctl_strerror(err));
	}
	return (NULL);
}

static tnfctl_errcode_t
set_probe_discovery_callback(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t err;

	err = tnfctl_register_funcs(hndl, perprobe, NULL);
	if (err)
		return (err);

	return (TNFCTL_ERR_NONE);
}

static tnfctl_errcode_t
perprobe2(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_p, void *cd)
{
	cmd_t		*cmd = cd;
	process_args_t  args;
	tnfctl_errcode_t err;

	args.probe_p = probe_p;
	args.hndl = hndl;
	err = cmd_callback(cmd, percmd, &args);
	if (err) {
		(void) fprintf(stderr, gettext(
				"%s: error on probe operation: %s\n"),
				g_argv[0], tnfctl_strerror(err));
	}
	return (err);
}

void
process_cmd(tnfctl_handle_t *hndl, cmd_t *cmd)
{
#if defined(DEBUG) || defined(lint)
	if (g_verbose)
		(void) fprintf(stderr, "processing commands\n");
#endif
	(void) tnfctl_probe_apply(hndl, perprobe2, cmd);
}

/*
 * get_commands() - process commands from stdin
 */
static void
get_commands(void)
{
	/* Read commands from STDIN */
	if (g_kernelmode) {
		(void) printf(gettext("Type \"help\" for help ...\n"));
	} else {
		if (g_testflag)
			(void) printf("prex(%ld), target(%ld): ",
					getpid(), g_targetpid);
		(void) printf(gettext("Target process stopped\n"));
		(void) printf(gettext(
			"Type \"continue\" to resume the target, "
			"\"help\" for help ...\n"));
	}

	while (yyparse());
}


/*
 * quit() - called to quit the controlling process. The boolean argument
 * specifies whether to terminate the target as well.
 */

void
quit(boolean_t killtarget, boolean_t runtarget)
{
	tnfctl_errcode_t err;

	if (killtarget && runtarget)
		err = tnfctl_close(g_hndl, TNFCTL_TARG_DEFAULT);
	else if (killtarget && !runtarget)
		err = tnfctl_close(g_hndl, TNFCTL_TARG_KILL);
	else if (!killtarget && runtarget)
		err = tnfctl_close(g_hndl, TNFCTL_TARG_RESUME);
	else if (!killtarget && !runtarget)
		err = tnfctl_close(g_hndl, TNFCTL_TARG_SUSPEND);
	if (err) {
		(void) fprintf(stderr, gettext(
				"%s: trouble quitting : %s\n"),
				g_argv[0], tnfctl_strerror(err));
		exit(1);
	}
	exit(0);
}


/*
 * scanargs() - processes the command line arguments
 */

#define	strneq(s1, s2, n) 	(strncmp(s1, s2, n) == 0)

static void
scanargs(int argc,
	char **argv)
{
	int			 c;
#if defined(DEBUG) || defined(lint)
	char		   *optstr = "l:o:p:s:tkv:";	/* debugging options */
#else
	char		   *optstr = "l:o:p:s:tk";	/* production options */
#endif

	/* set up some defaults */
	g_targetpid = 0;
	g_cmdname = NULL;
	g_cmdargs = NULL;
	g_preload = NULL;
	g_outname = NULL;
	g_outsize = -1;

	while ((c = getopt(argc, argv, optstr)) != EOF) {
		switch (c) {
		case 'l':	/* preload objects */
			g_preload = optarg;
			break;
		case 'o':	/* tracefile name */
			g_outname = optarg;
			break;
		case 'p':	/* target pid (attach case) */
			g_targetpid = atoi(optarg);
			break;
		case 's':	/* tracefile size */
			g_outsize = atoi(optarg) * 1024;
			break;
		case 't':	/* test flag */
			g_testflag = B_TRUE;
			(void) setvbuf(stdout, NULL, _IOLBF, 0);
			break;
		case 'k':	/* kernel mode */
			g_kernelmode = B_TRUE;
			break;
#if defined(DEBUG) || defined(lint)
		case 'v':	/* verbose flag */
			g_verbose = atoi(optarg);
			break;
#endif
		case '?':	/* error case */
			usage(argv, gettext("unrecognized argument"));
		}
	}

	if (optind < argc) {
		g_cmdname = strdup(argv[optind]);
		g_cmdargs = &argv[optind];
	}
	/* sanity clause */
	if (!g_kernelmode && (g_cmdname == NULL && g_targetpid == 0))
		usage(argv, gettext("need to specify cmd or pid"));
	if (g_cmdname != NULL && g_targetpid != 0)
		usage(argv, gettext("can't specify both cmd and pid"));
	if (g_targetpid && g_preload)
		usage(argv, gettext("can't use preload option with attach"));
	if (g_kernelmode) {
		if (g_outname)
			usage(argv, "can't specify a filename in kernel mode");
		if (g_cmdname)
			usage(argv, "can't specify a command in kernel mode");
		if (g_targetpid)
			usage(argv, "can't specify pid in kernel mode");
		if (g_preload)
			usage(argv, "can't use preload option in kernel mode");
	}
	/* default output size */
	if (g_outsize == -1)
		g_outsize = g_kernelmode ? KERNEL_OUTSIZE : USER_OUTSIZE;

#ifdef OLD
	int			 i;

	for (i = 1; i < argc; i++) {
		if (strneq(argv[i], "-v", 2)) {
			int			 vlevel;

			vlevel = (strlen(argv[i]) > 2)? atoi(&argv[i][2]) : 1;
			g_verbose = B_TRUE;
			prb_verbose_set(vlevel);
		} else if (strneq(argv[i], "-pid", 2)) {
			if (++i >= argc)
				usage(argv, gettext("missing pid argument"));
			g_targetpid = atoi(argv[i]);
		} else if (strneq(argv[i], "-t", 2)) {
			g_testflag = B_TRUE;
			(void) setvbuf(stdout, NULL, _IOLBF, 0);
		} else if (argv[i][0] != '-') {
			g_cmdname = strdup(argv[i]);
			if (!g_cmdname) {
				err_fatal(gettext(
					"%s: out of memory"), argv[0]);
			}
			if (g_verbose >= 2) {
				(void) fprintf(stderr,
					"cmdname=%s\n", g_cmdname);
			}
			/*
			 * rest of arguments are the args to the executable -
			 * by convention argv[0] should be name of
			 * executable, so we don't increment i
			 */
			g_cmdargs = &argv[i];
			break;
		} else {
			usage(argv, gettext("unrecognized argument"));
		}
	}
#endif

}				/* end scanargs */


/*
 * sig_handler() - cleans up if a signal is received
 */

/*ARGSUSED*/
static void
sig_handler(int signo)
{
	g_getcmds = B_TRUE;
}				/* end sig_handler */


/*
 * set_signal() -  sets up function to call for clean up
 */

static int
set_signal(void)
{
	struct sigaction newact;

	newact.sa_handler = sig_handler;
	(void) sigemptyset(&newact.sa_mask);
	newact.sa_flags = 0;
	if (sigaction(SIGINT, &newact, NULL) < 0) {
		return (errno);
	}
	return (0);
}


/*
 * set_tracefile() - initializes tracefile, sets the tracefile name and size
 */
static tnfctl_errcode_t
set_tracefile(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	err;
	tnfctl_trace_attrs_t	attrs;
	size_t			minoutsize;
	char			path[MAXPATHLEN];
	char			*outfile_name;
	char			*tmpdir;

	/* Init tracefile name used by list cmd */
	tracefile = NULL;
	err = tnfctl_trace_attrs_get(hndl, &attrs);
	if (err)
		return (err);

	if (attrs.trace_buf_state == TNFCTL_BUF_BROKEN)
		return (TNFCTL_ERR_BUFBROKEN);
	if (attrs.trace_buf_state == TNFCTL_BUF_OK) {
		/* trace file set already - can't change it */
		return (TNFCTL_ERR_NONE);
	}

	minoutsize = attrs.trace_min_size;
	if (g_outsize < minoutsize)	{
		(void) fprintf(stderr,
			gettext("specified tracefile size smaller then "
				"minimum; setting to %d kbytes\n"),
				minoutsize / 1024);
		g_outsize = minoutsize;
	}

	/* where is $TMPDIR? */
	tmpdir = getenv("TMPDIR");
	if (!tmpdir || *tmpdir == '\0') {
		tmpdir = "/tmp";
	}

	/* do we have an absolute, relative or no pathname specified? */
	if (g_outname == NULL) {
		/* default, no tracefile specified */
		if ((strlen(tmpdir) + 1 + 20) > (size_t)MAXPATHLEN) {
			(void) fprintf(stderr, gettext(
				"%s: $TMPDIR too long\n"), g_argv[0]);
			exit(1);
		}
		(void) sprintf(path, "%s/trace-%ld", tmpdir, g_targetpid);
		outfile_name = path;
	} else {
		/* filename specified */
		outfile_name = g_outname;
	}
	tracefile = strdup(outfile_name);
	if (tracefile == NULL) {
		if ((errno == ENOMEM) || (errno == EAGAIN)) {
			return (TNFCTL_ERR_ALLOCFAIL);
		} else {
			return (TNFCTL_ERR_INTERNAL);
		}
	}

#if defined(DEBUG) || defined(lint)
	if (g_verbose)
		(void) fprintf(stderr,
			"setting tracefile name=\"%s\", size=%d\n",
			path, g_outsize);
#endif
	err = tnfctl_buffer_alloc(hndl, outfile_name, g_outsize);
	return (err);
}
/*
 * get_data_model() - get the process data model from psinfo
 *		      structure.
 */
#define	PROCFORMAT	"/proc/%d"
static int
get_data_model(pid_t pid)
{
	char	path[MAXPATHLEN];
	int	fd, dmodel = -1;
	prpsinfo_t	psinfo;

	(void) sprintf(path, PROCFORMAT, (int)pid);
	fd = open(path, O_RDONLY);
	if (fd == -1)
	    return (dmodel);
	if ((dmodel = ioctl(fd, PIOCPSINFO, &psinfo)) == -1)
	    return (dmodel);
	return ((int)psinfo.pr_dmodel);
}
/*
 * get_executable - return file descriptor for PATH-resolved
 *		    target file.
 *
 */
static int
get_executable(char *name) {
    int fd = -1;

    if (name != NULL) {
	char path[PATH_MAX + 1];
	char line[MAX_INPUT + 1];
	char *p = line;
	char *fname = name;
	int N = sizeof (line);
	struct stat file_att;

	while (*fname == ' ') fname++;
	if (fname[0] == '-' || strchr(fname, '/')) {
	    fd = open(fname, O_RDONLY);
	} else {
	    int len = strlen(fname);
	    char *dirlist = getenv("PATH");
	    char *dir = NULL;

	    if (dirlist != NULL) {
		dirlist = strdup(dirlist);
		dir = strtok(dirlist, ":");
	    }
	    while (fd < 0 && dir != NULL) {
		if ((strlen(dir) + len + 1) < sizeof (path)) {
		    strcat(strcat(strcpy(path, dir), "/"), fname);
		    fd = open(path, O_RDONLY);
		}
		dir = strtok(NULL, ":");
	    }
	    if (dirlist != NULL) free(dirlist);
	}
	if (fstat(fd, &file_att) || !S_ISREG(file_att.st_mode)) {
	    if (fd >= 0)
		close(fd);
	    return (-1);
	}
	if (read(fd, p, 2) && p[0] == '#' && p[1] == '!') {
	    while (N-- > 1 && read(fd, p, 1) && *p != '\n')
		p++;
	    *p = '\0';
	    close(fd);
	    return (get_executable(line));
	}
	if (fd >= 0) lseek(fd, 0, SEEK_SET);
	} /* %$#@! cstyle complaint */
    return (fd);
}

/*
 * get_elf_class - get the target executable elf class
 *                 i.e. ELFCLASS64 or ELFCLASS32.
 */
static int
get_elf_class(char *filename)
{
	int	elfclass = -1;
	int	elffd = get_executable(filename);
	Elf	*elf;
	size_t	size;
	char	*ident;
	GElf_Ehdr	ehdr;

	if (elffd < 0)
		return (elfclass);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) close(elffd);
		return (elfclass);
	}
	elf = elf_begin(elffd, ELF_C_READ, (Elf *) 0);
	/*
	 * verify information in file header
	 */
	if (gelf_getehdr(elf, &ehdr) == (GElf_Ehdr *) 0) {
		close(elffd);
		return (elfclass);
	}
	ident = elf_getident(elf, &size);
	if (ident[EI_CLASS] == ELFCLASS32)
		elfclass = ELFCLASS32;
	if (ident[EI_CLASS] == ELFCLASS64)
		elfclass = ELFCLASS64;
	close(elffd);
	return (elfclass);
}
/*
 * check_exec_model() - check the consistency between prex data model
 *                      and target elf class and act accordingly
 */
static void
check_exec_model(char **argv, char **envp)
{
	int	elfclass;

	elfclass = get_elf_class(g_cmdname);
	if (((elfclass == ELFCLASS32) && (prex_dmodel == PR_MODEL_ILP32)) ||
	    ((elfclass == ELFCLASS64) && (prex_dmodel == PR_MODEL_LP64)))
	    return;
	if ((prex_dmodel == PR_MODEL_ILP32) &&
	    (elfclass == ELFCLASS64)) {
	    (void) fprintf(stderr, gettext(
		"Error: 32 bit prex can not exec 64 bit target\n"));
	    exit(1);
	}
	if ((prex_dmodel == PR_MODEL_LP64) &&
	    (elfclass == ELFCLASS32))
	    prex_isaexec(argv, envp);
}

/*
 * check_pid_model() - check the consistency between prex data model
 *                     and target data model and act accordingly
 */
static void
check_pid_model(char **argv, char **envp)
{
	int	dmodel;

	dmodel = get_data_model(g_targetpid);
	if (prex_dmodel == dmodel)
		return;
	if ((prex_dmodel == PR_MODEL_ILP32) &&
		(dmodel == PR_MODEL_LP64)) {
		(void) fprintf(stderr, gettext(
		    "Error: 32 bit prex can not exec 64 bit target\n"));
		exit(1);
	}
	if ((prex_dmodel == PR_MODEL_LP64) &&
		(dmodel == PR_MODEL_ILP32))
		prex_isaexec(argv, envp);
}
/*
 * prex_isaexec() - there is only one case this function get called
 *                  64 bit prex, 32 bit target, need to exec 32 bit
 *                  prex here.
 */
static void
prex_isaexec(char **argv, char **envp)
{
	char path[PATH_MAX + sizeof (PREX32DIR)];
	strcat(strcat(strcpy(path, dirname(dirname(argv[0]))), PREX32DIR),
	    basename(argv[0]));
	if (get_elf_class(path) != ELFCLASS32)
	    strcpy(path, PREX32EXEC);
	argv[0] = path;
	(void) execve(path, argv, envp);
	(void) fprintf(stderr,
	    gettext("%s: execve(\"%s\") failed\n"),
	    argv[0], path);
	exit(1);
}
void
cmd_listtracefile()
{

	if (g_kernelmode) {
	    (void) fprintf(stderr,
		    gettext("There is no trace file in kernel mode!\n"));
	} else {
	    (void) printf(gettext("Current trace file is: %s\n"), tracefile);
	}
}
