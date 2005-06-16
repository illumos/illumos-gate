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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file comprises the main driver for this tool.
 * Upon parsing the command verbs from user input, it
 * branches to the appropriate modules to perform the
 * requested task.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <libgen.h>
#include <errno.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/*
 * The verbcmd construct allows genericizing information about a verb so
 * that it is easier to manipulate.  Makes parsing code easier to read,
 * fix, and extend with new verbs.
 */
typedef struct verbcmd_s {
	char	*verb;
	int	(*action)(int, char *[]);
	int	mode;
	char	*synopsis;
} verbcmd;

/* External declarations for supported verb actions. */
extern int	pk_setpin(int argc, char *argv[]);
extern int	pk_list(int argc, char *argv[]);
extern int	pk_delete(int argc, char *argv[]);
extern int	pk_import(int argc, char *argv[]);
extern int	pk_export(int argc, char *argv[]);
extern int	pk_tokens(int argc, char *argv[]);

/* Forward declarations for "built-in" verb actions. */
static int	pk_help(int argc, char *argv[]);

/* Command structure for verbs and their actions.  Do NOT i18n/l10n. */
static verbcmd	cmds[] = {
	{ "tokens",	pk_tokens,	0,	"tokens" },
	{ "setpin",	pk_setpin,	0,	"setpin" },
	{ "list",	pk_list,	0,	"list [-p] [-P] [-l <label>]"
	    "\n\t\tor list [--public] [--private] [--label[=]<label>]" },
	{ "delete",	pk_delete,	0,
	    "delete { [-p] [-P] [-l <label>] }"
	    "\n\t\tor delete { [--public] [--private] [--label[=]<label>] }" },
	{ "import",	pk_import,	0,	"import <file>" },
	{ "export",	pk_export,	0,	"export <file>" },
	{ "-?",		pk_help,	0,	"--help\t(help and usage)" },
};
static int	num_cmds = sizeof (cmds) / sizeof (verbcmd);

static char	*prog;
static void	usage(void);

/*
 * Usage information.  This function must be updated when new verbs or
 * options are added.
 */
static void
usage(void)
{
	int	i;

	cryptodebug("inside usage");

	/* Display this block only in command-line mode. */
	(void) fprintf(stdout, gettext("Usage:\n"));
	(void) fprintf(stdout, gettext("\t%s -?\t(help and usage)\n"), prog);
	(void) fprintf(stdout, gettext("\t%s subcommand [options...]\n"), prog);
	(void) fprintf(stdout, gettext("where subcommands may be:\n"));

	/* Display only those verbs that match the current tool mode. */
	for (i = 0; i < num_cmds; i++) {
		/* Do NOT i18n/l10n. */
		(void) fprintf(stdout, "\t%s\n", cmds[i].synopsis);
	}
}

/*
 * Provide help, in the form of displaying the usage.
 */
static int
pk_help(int argc, char *argv[])
/* ARGSUSED */
{
	cryptodebug("inside pk_help");

	usage();
	return (0);
}

/*
 * MAIN() -- where all the action is
 */
int
main(int argc, char *argv[], char *envp[])
/* ARGSUSED2 */
{
	int	i, found = -1;
	int	rv;
	int	pk_argc = 0;
	char	**pk_argv = NULL;
	int	save_errno = 0;

	/* Set up for i18n/l10n. */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Get program base name and move pointer over 0th arg. */
	prog = basename(argv[0]);
	argv++, argc--;

	/* Set up for debug and error output. */
	cryptodebug_init(prog);

	if (argc == 0) {
		usage();
		return (1);
	}

	/* Check for help options.  For CLIP-compliance. */
	if (argc == 1 && argv[0][0] == '-') {
		switch (argv[0][1]) {
		case '?':
			return (pk_help(argc, argv));
		default:
			usage();
			return (1);
		}
	}

	/* Always turns off Metaslot so that we can see softtoken. */
	cryptodebug("disabling Metaslot");
	if (setenv("METASLOT_ENABLED", "false", 1) < 0) {
		save_errno = errno;
		cryptoerror(LOG_STDERR,
		    gettext("Disabling Metaslot failed (%s)."),
		    strerror(save_errno));
		return (1);
	}

	/* Begin parsing command line. */
	cryptodebug("begin parsing command line");
	pk_argc = argc;
	pk_argv = argv;

	/* Check for valid verb (or an abbreviation of it). */
	found = -1;
	for (i = 0; i < num_cmds; i++) {
		if (strcmp(cmds[i].verb, pk_argv[0]) == 0) {
			if (found < 0) {
				cryptodebug("found cmd %s", cmds[i].verb);
				found = i;
				break;
			} else {
				cryptodebug("also found cmd %s, skipping",
				    cmds[i].verb);
			}
		}
	}
	/* Stop here if no valid verb found. */
	if (found < 0) {
		cryptoerror(LOG_STDERR, gettext("Invalid verb: %s"),
		    pk_argv[0]);
		return (1);
	}

	/* Get to work! */
	cryptodebug("begin executing cmd action");
	rv = (*cmds[found].action)(pk_argc, pk_argv);
	cryptodebug("end executing cmd action");
	switch (rv) {
	case PK_ERR_NONE:
		cryptodebug("subcommand succeeded");
		break;		/* Command succeeded, do nothing. */
	case PK_ERR_USAGE:
		cryptodebug("usage error detected");
		usage();
		break;
	case PK_ERR_QUIT:
		cryptodebug("quit command received");
		exit(0);
		/* NOTREACHED */
	case PK_ERR_PK11:
		cryptoerror(LOG_STDERR, "%s",
		    gettext("Command failed due to PKCS#11 error."));
		break;
	case PK_ERR_SYSTEM:
		cryptoerror(LOG_STDERR, "%s",
		    gettext("Command failed due to system error."));
		break;
	case PK_ERR_OPENSSL:
		cryptoerror(LOG_STDERR, "%s",
		    gettext("Command failed due to OpenSSL error."));
		break;
	default:
		cryptoerror(LOG_STDERR, "%s (%d).",
		    gettext("Unknown error value"), rv);
		break;
	}
	return (rv);
}
