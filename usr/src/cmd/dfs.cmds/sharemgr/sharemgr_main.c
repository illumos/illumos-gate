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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <libshare.h>
#include "sharemgr.h"
#include <libintl.h>
#include <locale.h>

char *protocol = NULL;
static int help = 0;

static int run_command(char *, int, char **, char *, sa_handle_t);
extern sa_command_t *sa_lookup(char *, char *);
extern void sub_command_help(char *proto);

static void
global_help()
{
	(void) printf(gettext("usage: sharemgr [-h | <command> [options]]\n"));
	sub_command_help(NULL);
}

int
main(int argc, char *argv[])
{
	int c;
	int rval;
	char *command = NULL;
	sa_handle_t handle;

	/*
	 * make sure locale and gettext domain is setup
	 */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * parse enough of command line to get protocol, if any.
	 * Note that options need to come "after" the subcommand.
	 */
	command = basename(argv[0]);
	if (strcmp(command, "share") != 0 && strcmp(command, "unshare") != 0) {
		while ((c = getopt(argc, argv, "h?")) != EOF) {
			switch (c) {
			default:
			case 'h':
			case '?':
				help = 1;
				break;
			}
		}
		if (argc == 1)
			help = 1;
	}

	if (strcmp(command, "sharemgr") == 0) {
		command = argv[optind];
		argv++;
		argc--;
	}

	if (help) {
		/* no subcommand */
		global_help();
		exit(SA_OK);
	}

	/*
	 * now have enough to parse rest of command line
	 *
	 * First, initialize the plugin architecture.
	 * Plugins are needed in the event of a global help
	 * request.
	 *
	 * reset optind to 1 so the parsing that takes place in
	 * sa_init() will work correctly.
	 */

	optind = 1;
	handle = sa_init(SA_INIT_SHARE_API);

	/*
	 * reset optind again since we will start parsing all over in
	 * the sub-commands.
	 */
	optind = 1;
	rval = run_command(command, argc, argv, protocol, handle);

	sa_fini(handle);
	return (rval);
}

static int
run_command(char *command, int argc, char *argv[], char *proto,
		sa_handle_t handle)
{
	sa_command_t *cmdvec;
	int ret;

	/*
	 * To get here, we know there should be a command due to the
	 * preprocessing done earlier.  Need to find the protocol
	 * that is being affected. If no protocol, then it is ALL
	 * protocols.
	 *
	 * We don't currently use the protocol here at this point. It
	 * is left in as a placeholder for the future addition of
	 * protocol specific sub-commands.
	 *
	 * Known sub-commands are handled at this level. An unknown
	 * command will be passed down to the shared object that
	 * actually implements it. We can do this since the semantics
	 * of the common sub-commands is well defined.
	 */

	cmdvec = sa_lookup(command, proto);
	if (cmdvec == NULL) {
		(void) printf(gettext("command %s not found\n"), command);
		exit(1);
	}
	/*
	 * need to check priviledges and restrict what can be done
	 * based on least priviledge and sub-command so pass this in
	 * as a flag.
	 */
	ret = cmdvec->cmdfunc(handle, cmdvec->priv, argc, argv);
	return (ret);
}
