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
 *	Copyright (c) 1995 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <sys/param.h>

#include "genmsg.h"

#define	MSG_SUFFIX	".msg"
#define	NEW_SUFFIX	".new"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"genmsg"
#endif

/*
 * External functions.
 */
extern void write_msgfile(char *);	/* from util.c */
extern int read_projfile(char *);	/* from util.c */
extern void write_projfile(char *);	/* from util.c */
extern void read_msgfile(char *);	/* from util.c */
extern int is_writable(char *);		/* from util.c */
extern int file_copy(char *, char *);	/* from util.c */
extern void init_lex(void);		/* from genmsg.l */
extern void init_linemsgid(void);	/* from genmsg.l */

/* Program name. */
char *program;

/* File pointer for auto-message-numbering. */
FILE *newfp = NULL;

/* Input source file. */
char *srcfile;

/* Tag for message comments. */
char *mctag = NULL;

/* Tag for set number comments. */
char *sctag = NULL;

/* Mode mask to define the genmsg tasks. */
Mode active_mode = NoMode;

/*
 * This flag will be TRUE if a catgets() call is found
 * in the input file.
 */
int is_cat_found = FALSE;

/* Suppress an error message if this flag is TRUE. */
int suppress_error = FALSE;

/* Prefix and suffix of messages for testing. */
char *premsg = NULL;
char *sufmsg = NULL;

static void usage(void);
static void validate_options(void);

int
main(int argc, char **argv)
{
	int c;
	extern char *optarg;	/* from getopt */
	extern int optind;	/* from getopt */
	extern FILE *yyin;	/* from lex */
	extern int yyparse(void);
	char *msgfile = NULL;
	char *projfile = NULL;
	char *newprojfile = NULL;
	char *cpppath = NULL;
	int do_msgfile = FALSE;
	int tmpfd = -1;

	program = basename(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "arndfg:o:l:p:c:s:m:M:txvb")) != EOF) {
		switch (c) {
		case 'o':
			SetActiveMode(MessageMode);
			msgfile = optarg;
			break;
		case 'a':
			SetActiveMode(AppendMode);
			break;
		case 'l':
			projfile = optarg;
			SetActiveMode(AutoNumMode);
			break;
		case 'r':
			SetActiveMode(ReverseMode);
			break;
		case 'p':
			cpppath = optarg;
			SetActiveMode(PreProcessMode);
			break;
		case 'g':
			newprojfile = optarg;
			suppress_error = TRUE;
			SetActiveMode(ProjectMode);
			break;
		case 'c':
			mctag = optarg;
			SetActiveMode(MsgCommentMode);
			break;
		case 's':
			sctag = optarg;
			SetActiveMode(SetCommentMode);
			break;
		case 'b':
			SetActiveMode(BackCommentMode);
			break;
		case 'n':
			SetActiveMode(LineInfoMode);
			break;
		case 'm':
			premsg = optarg;
			SetActiveMode(PrefixMode);
			break;
		case 'M':
			sufmsg = optarg;
			SetActiveMode(SuffixMode);
			break;
		case 't':
			SetActiveMode(TripleMode);
			break;
		case 'd':
			SetActiveMode(DoubleLineMode);
			break;
		case 'f':
			SetActiveMode(OverwriteMode);
			break;
		case 'x':
			suppress_error = TRUE;
			SetActiveMode(NoErrorMode);
			break;
		case 'v':
			(void) printf("genmsg version %s\n", "%I%");
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			break;
		}
	}

	if (optind >= argc) {
		usage();
	}

	validate_options();

	if (IsActiveMode(AutoNumMode)) {
		int len;
		char *tmp;
		if (read_projfile(projfile)) {
			tmp = basename(projfile);
			len = strlen(tmp);
			if ((newprojfile = malloc(len + sizeof (NEW_SUFFIX)))
				== NULL) {
				prg_err(gettext("fatal: out of memory"));
				exit(EXIT_FAILURE);
			}
			(void) sprintf(newprojfile, "%s%s", tmp, NEW_SUFFIX);
		} else {
			newprojfile = basename(projfile);
		}
	}

	if ((IsActiveMode(AutoNumMode) || IsActiveMode(ProjectMode)) &&
		(is_writable(IsActiveMode(OverwriteMode) ?
				projfile : newprojfile) == FALSE)) {
		prg_err(gettext("cannot write \"%s\": permission denied"),
			IsActiveMode(OverwriteMode) ? projfile : newprojfile);
		exit(EXIT_FAILURE);
	}

	if (IsActiveMode(AppendMode) && msgfile) {
		read_msgfile(msgfile);
	}

	if (!msgfile) {
		char *tmp = basename(argv[optind]);
		int len = strlen(tmp);
		if ((msgfile = malloc(len + sizeof (MSG_SUFFIX)))
			== NULL) {
			prg_err(gettext("fatal: out of memory"));
			exit(EXIT_FAILURE);
		}
		(void) sprintf(msgfile, "%s%s", tmp, MSG_SUFFIX);
	}

	while (optind < argc) {
		is_cat_found = FALSE;
		srcfile = argv[optind];

		if (IsActiveMode(AutoNumMode) || IsActiveMode(ReverseMode)) {
			init_linemsgid();
		}

		if (IsActiveMode(PreProcessMode)) {
			char cmd[MAXPATHLEN];
			(void) sprintf(cmd, "%s %s", cpppath, srcfile);
			if ((yyin = (FILE *) popen(cmd, "r")) == NULL) {
				prg_err(
				gettext("fatal: cannot execute \"%s\""),
				cpppath);
				exit(EXIT_FAILURE);
			}
		} else {
			if ((yyin = fopen(srcfile, "r")) == NULL) {
				prg_err(/* stupid cstyle */
				gettext("cannot open \"%s\""), srcfile);
				goto end;
			}
		}

		init_lex();
		yyparse();

		if (IsActiveMode(PreProcessMode)) {
			if (pclose(yyin) != 0) {
				prg_err(gettext("\"%s\" failed for \"%s\""),
					cpppath, srcfile);
				goto end;
			}
		}

		if (is_cat_found == FALSE) {
			if (!IsActiveMode(PreProcessMode)) {
				(void) fclose(yyin);
			}
			goto end;
		}

		if (!do_msgfile) {
			do_msgfile = TRUE;
		}

		if (IsActiveMode(AutoNumMode) || IsActiveMode(ReverseMode)) {
			char *tmp = basename(srcfile);
			char newfile[MAXPATHLEN];
			char tmpfile[32];

			if (IsActiveMode(OverwriteMode)) {
				(void) sprintf(newfile, "%s", srcfile);
			} else {
				(void) sprintf(newfile, "%s%s",
						tmp, NEW_SUFFIX);
			}

			if (is_writable(newfile) == FALSE) {
				prg_err(
			gettext("cannot create \"%s\": permission denied"),
					newfile);
				goto end;
			}

			(void) sprintf(tmpfile, "%s", "/tmp/gensmg.XXXXXX");
			if ((tmpfd = mkstemp(tmpfile)) == -1) {
				prg_err(/* stupid cstyle */
				gettext("cannot create \"%s\""), tmpfile);
				if (!IsActiveMode(PreProcessMode)) {
					(void) fclose(yyin);
				}
					goto end;
			}
			(void) close(tmpfd);
			if ((newfp = fopen(tmpfile, "w")) == NULL) {
				prg_err(/* stupid cstyle */
				gettext("cannot create \"%s\""), tmpfile);
				if (!IsActiveMode(PreProcessMode)) {
					(void) fclose(yyin);
				}
				(void) unlink(tmpfile);
				goto end;
			}

			if (IsActiveMode(PreProcessMode)) {
				if ((yyin = fopen(srcfile, "r")) == NULL) {
					prg_err(/* stupid cstyle */
				gettext("cannot open \"%s\""), srcfile);
					(void) unlink(tmpfile);
					goto end;
				}
			} else {
				rewind(yyin);
			}

			SetActiveMode(ReplaceMode);
			init_lex();
			yyparse();
			ResetActiveMode(ReplaceMode);

			(void) fclose(newfp);
			newfp = NULL;

			(void) fclose(yyin);

			(void) file_copy(tmpfile, newfile);

			(void) unlink(tmpfile);

			goto end;
		}

		if (!IsActiveMode(PreProcessMode)) {
			(void) fclose(yyin);
		}

end:
		optind++;
	}

	if (!do_msgfile) { /* no more business. */
		return (EXIT_SUCCESS);
	}

	if (!IsActiveMode(ReverseMode) && !IsActiveMode(ProjectMode)) {
		write_msgfile(msgfile);
	}

	if (IsActiveMode(AutoNumMode) || IsActiveMode(ProjectMode)) {
		write_projfile(IsActiveMode(OverwriteMode) ?
				projfile : newprojfile);
	}
	return (EXIT_SUCCESS);
}

static void
validate_options(void)
{
	/* -r doesn't work with either -a or -l. */
	if (IsActiveMode(ReverseMode) &&
		(IsActiveMode(AutoNumMode) || IsActiveMode(AppendMode))) {
		usage();
	}
	/* -b should be accompanied with -c, -s, -d, and -n. */
	if (IsActiveMode(BackCommentMode) &&
		(!IsActiveMode(MsgCommentMode) &&
		!IsActiveMode(SetCommentMode) &&
		!IsActiveMode(DoubleLineMode) &&
		!IsActiveMode(LineInfoMode))) {
		usage();
	}
	if (IsActiveMode(ProjectMode) &&
		(IsActiveMode(AutoNumMode) || IsActiveMode(ReverseMode) ||
		IsActiveMode(AppendMode) || IsActiveMode(MsgCommentMode) ||
		IsActiveMode(LineInfoMode) || IsActiveMode(OverwriteMode) ||
		IsActiveMode(PrefixMode) || IsActiveMode(SuffixMode) ||
		IsActiveMode(TripleMode) || IsActiveMode(DoubleLineMode) ||
		IsActiveMode(MessageMode) || IsActiveMode(NoErrorMode))) {
		usage();
	}
}

static void
usage(void)
{
	(void) fprintf(stderr,
	gettext("Usage: %s [-o message-file] [-a] [-d] [-p preprocessor]\n"
		"          [-s set-tag] [-c message-tag] [-b] [-n]\n"
		"          [-l project-file] [-r] [-f] [-g project-file]\n"
		"          [-m prefix] [-M suffix] [-t] [-x] files ...\n"),
		program);
	exit(EXIT_FAILURE);
}
