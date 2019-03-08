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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * alias.c is a C version of the alias.sh wrapper (which links ksh
 * builtins to commands in /usr/bin/, e.g. calling this wrapper as
 * /usr/bin/alias will call the ksh "alias" builtin, running it as
 * /usr/bin/cut will call the ksh "cut" builtin etc.
 */

#include <shell.h>
#include <nval.h>
#include <cmdext.h>
#include <stdio.h>

typedef struct {
	const char *name;
	int (* func)(int, char **, void *);
} bfastpathrec;

/*
 * We've disabled the "fastpath" codepath for some commands below
 * because it causes a paradoxon for large input files (as used by
 * ON PerfPIT for testing). For /usr/bin/rev (where the issue was
 * first discovered) it looks like this:
 * - for small files like /etc/profile the fastpath is faster in a loop
 *   with 1000 iterations (8 seconds with fastpath, 14 seconds without
 *   fastpath)
 * - for large files (/usr/pub/UTF-8 replicated until the test file
 *   reaches 24884706 bytes) the benchmark reverses: The fastpath now
 *   needs 40 seconds and without fastpath it needs 30 seconds (for 100
 *   iterations).
 */
#if 0
#define	ENABLE_PERFORMANCE_PARADOXON 1
#endif

/*
 * List of libcmd builtins which do not require a |Shell_t| context.
 * This list was automatically generated from <ast/cmdext.h>
 */
static const
bfastpathrec fastpath_builtins[] =
{
	/* This list must be alphabetically sorted for |strcmp()| usage */
	{ "basename",	b_basename	},
	{ "cat",	b_cat		},
	{ "chmod",	b_chmod		},
#ifdef ENABLE_PERFORMANCE_PARADOXON
	{ "cksum",	b_cksum		},
#endif /* ENABLE_PERFORMANCE_PARADOXON */
	{ "cmp",	b_cmp		},
	{ "comm",	b_comm		},
	{ "cp",		b_cp		},
	{ "cut",	b_cut		},
	{ "date",	b_date		},
	{ "dirname",	b_dirname	},
	{ "egrep",	b_egrep		},
	{ "expr",	b_expr		},
	{ "fds",	b_fds		},
	{ "fgrep",	b_fgrep		},
	{ "fmt",	b_fmt		},
	{ "fold",	b_fold		},
	{ "getconf",	b_getconf	},
	{ "grep",	b_grep		},
	{ "head",	b_head		},
	{ "id",		b_id		},
	{ "join",	b_join		},
	{ "ln",		b_ln		},
	{ "logname",	b_logname	},
	{ "md5sum",	b_md5sum	},
	{ "mkdir",	b_mkdir		},
	{ "mkfifo",	b_mkfifo	},
	{ "mktemp",	b_mktemp	},
	{ "mv",		b_mv		},
	{ "paste",	b_paste		},
	{ "pathchk",	b_pathchk	},
	{ "pids",	b_pids		},
	{ "readlink",	b_readlink	},
#ifdef ENABLE_PERFORMANCE_PARADOXON
	{ "rev",	b_rev		},
#endif /* ENABLE_PERFORMANCE_PARADOXON */
	{ "rm",		b_rm		},
	{ "rmdir",	b_rmdir		},
	{ "stty",	b_stty		},
#ifdef ENABLE_PERFORMANCE_PARADOXON
	{ "sum",	b_sum		},
#endif /* ENABLE_PERFORMANCE_PARADOXON */
	{ "sync",	b_sync		},
	{ "tail",	b_tail		},
	{ "tee",	b_tee		},
	{ "tty",	b_tty		},
	{ "uname",	b_uname		},
	{ "uniq",	b_uniq		},
	{ "wc",		b_wc		},
	{ "xgrep",	b_xgrep		},
	{ NULL,		(int (*)(int, char **, void *))NULL }
};

static inline
const bfastpathrec *
find_bfastpathrec(const char *name)
{
	unsigned int i;
	signed int cmpres;
	for (i = 0; fastpath_builtins[i].name != NULL; i++) {
		cmpres = strcmp(fastpath_builtins[i].name, name);
		if (cmpres == 0)
			return (&fastpath_builtins[i]);
		else if (cmpres > 0)
			return (NULL);

	}
	return (NULL);
}

static inline
int
fastpath_builtin_main(const bfastpathrec *brec, int argc, char *argv[])
{
	setlocale(LC_ALL, ""); /* calls |_ast_setlocale()| */

	return ((*brec->func)(argc, argv, NULL));
}


/* Builtin script, original derived from alias.sh */
static const char *script = "\n"
/* Get name of builtin */
"typeset cmd=\"${0##*/}\"\n"
/*
 * If the requested command is not an alias load it explicitly
 * to make sure it is not bound to a path (those built-ins which
 * are mapped via shell aliases point to commands which are
 * "special shell built-ins" which cannot be bound to a specific
 * PATH element) - otherwise we may execute the wrong command
 * if an executable with the same name sits in a PATH element
 * before /usr/bin (e.g. /usr/xpg4/bin/ls would be executed
 * before /usr/bin/ls if the path was something like
 * PATH=/usr/xpg4/bin:/usr/bin).
 */
"if [[ \"${cmd}\" != ~(Elr)(alias|unalias|command) ]] && "
	"! alias \"${cmd}\" >/dev/null 2>&1 ; then\n"
	"PATH='' builtin \"${cmd}\"\n"
"fi\n"
/* command is a keyword and needs to be handled separately */
"if [[ \"${cmd}\" == \"command\" ]] ; then\n"
	"command \"$@\"\n"
"else\n"
#ifdef WORKAROUND_FOR_ALIAS_CRASH
/*
 * Work around a crash in /usr/bin/alias when invalid options are
 * passed (e.g. $ /usr/bin/alias -c #). The shell code will call
 * an error handler which does a |longjmp()| but somehow the code
 * failed to do the |setjmp()| before this point.
 * Putting the "alias" command in a subshell avoids the crash.
 * Real cause of the issue is under investigation and a fix be
 * delivered with the next ast-ksh update.
 */
	"( \"${cmd}\" \"$@\" )\n"
#else
	"\"${cmd}\" \"$@\"\n"
#endif /* WORKAROUND_FOR_ALIAS_CRASH */
"fi\n"
"exitval=$?";


static inline
int
script_builtin_main(int argc, char *argv[])
{
	int i;
	Shell_t *shp;
	Namval_t *np;
	int exitval;

	/*
	 * Create copy of |argv| array shifted by one position to
	 * emulate $ /usr/bin/sh <scriptname> <args1> <arg2> ... #.
	 * First position is set to "/usr/bin/sh" since other
	 * values may trigger special shell modes (e.g. *rsh* will
	 * trigger "restricted" shell mode etc.).
	 */
	char *xargv[argc+2];
	xargv[0] = "/usr/bin/sh";
	xargv[1] = "scriptname";
	for (i = 0; i < argc; i++) {
		xargv[i+1] = argv[i];
	}
	xargv[i+1] = NULL;

	shp = sh_init(argc+1, xargv, 0);
	if (!shp)
		error(ERROR_exit(1), "shell initialisation failed.");
	(void) sh_trap(script, 0);

	np = nv_open("exitval", shp->var_tree, 0);
	if (!np)
		error(ERROR_exit(1), "variable %s not found.", "exitval");
	exitval = (int)nv_getnum(np);
	nv_close(np);

	return (exitval);
}

int
main(int argc, char *argv[])
{
	const char *progname;
	const bfastpathrec *brec;
	char execnamebuff[PATH_MAX+1];

	/* Get program name */
	if (pathprog(argv[0], execnamebuff, sizeof (execnamebuff)) <= 0)
		error(ERROR_exit(1), "could not determinate exec name.");

	progname = (const char *)strrchr(execnamebuff, '/');
	if (progname != NULL) {
		progname++;
	}
	else
	{
		progname = execnamebuff;
	}

	/* Execute command... */
	if (brec = find_bfastpathrec(progname)) {
		/* ... either via a fast path (calling the code directly) ... */
		return (fastpath_builtin_main(brec, argc, argv));
	}
	else
	{
		/* ... or from within a full shell. */
		return (script_builtin_main(argc, argv));
	}
}
