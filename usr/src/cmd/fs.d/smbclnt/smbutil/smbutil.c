/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <sysexits.h>
#include <locale.h>
#include <libintl.h>

#include <netsmb/smb_lib.h>

#include "common.h"

#ifndef EX_DATAERR
#define	EX_DATAERR 1
#endif

static void help(void) __NORETURN;

typedef int cmd_fn_t (int argc, char *argv[]);
typedef void cmd_usage_t (void);

#define	CMDFL_NO_KMOD	0x0001

static struct commands {
	const char	*name;
	cmd_fn_t	*fn;
	cmd_usage_t	*usage;
	int		flags;
} commands[] = {
	{"crypt",	cmd_crypt,	NULL, CMDFL_NO_KMOD},
	{"help",	cmd_help,	help_usage, CMDFL_NO_KMOD},
	{"info",	cmd_info,	info_usage, 0},
	{"login",	cmd_login,	login_usage, 0},
	{"logout",	cmd_logout,	logout_usage, 0},
	{"logoutall",	cmd_logoutall,	logoutall_usage, 0},
	{"lookup",	cmd_lookup,	lookup_usage, CMDFL_NO_KMOD},
	{"print",	cmd_print,	print_usage, 0},
	{"status",	cmd_status,	status_usage, CMDFL_NO_KMOD},
	{"view",	cmd_view,	view_usage, 0},
	{NULL, NULL, NULL, 0}
};

static struct commands *
lookupcmd(const char *name)
{
	struct commands *cmd;

	for (cmd = commands; cmd->name; cmd++) {
		if (strcmp(cmd->name, name) == 0)
			return (cmd);
	}
	return (NULL);
}

int
cmd_crypt(int argc, char *argv[])
{
	char *cp, *psw;

	if (argc < 2)
		psw = getpassphrase(gettext("Password:"));
	else
		psw = argv[1];
	/* XXX Better to embed malloc/free in smb_simplecrypt? */
	cp = malloc(4 + 2 * strlen(psw));
	if (cp == NULL)
		errx(EX_DATAERR, gettext("out of memory"));
	smb_simplecrypt(cp, psw);
	printf("%s\n", cp);
	free(cp);
	return (0);
}

int
cmd_help(int argc, char *argv[])
{
	struct commands *cmd;
	char *cp;

	if (argc < 2)
		help_usage();
	cp = argv[1];
	cmd = lookupcmd(cp);
	if (cmd == NULL)
		errx(EX_DATAERR, gettext("unknown command %s"), cp);
	if (cmd->usage == NULL)
		errx(EX_DATAERR,
		    gettext("no specific help for command %s"), cp);
	cmd->usage();
	return (0);
}

int
main(int argc, char *argv[])
{
	struct commands *cmd;
	char *cp;
	int err, opt;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

#ifdef APPLE
	dropsuid(); /* see libsmbfs */
#endif

	if (argc < 2)
		help();

	while ((opt = getopt(argc, argv, "dhv")) != EOF) {
		switch (opt) {
		case 'd':
			smb_debug++;
			break;
		case 'h':
			help();
			/* NOTREACHED */
		case 'v':
			smb_verbose++;
			break;
		default:
			help();
			/* NOTREACHED */
		}
	}
	if (optind >= argc)
		help();

	cp = argv[optind];
	cmd = lookupcmd(cp);
	if (cmd == NULL)
		errx(EX_DATAERR, gettext("unknown command %s"), cp);

	if ((cmd->flags & CMDFL_NO_KMOD) == 0 && smb_lib_init() != 0)
		exit(1);

	argc -= optind;
	argv += optind;
	optind = 1;
	err = cmd->fn(argc, argv);
	return ((err) ? 1 : 0);
}

static void
help(void) {
	printf("\n");
	printf(gettext("usage: %s [-hv] subcommand [args]\n"), __progname);
	printf(gettext("where subcommands are:\n"
	" crypt		slightly obscure password\n"
	" help		display help on specified subcommand\n"
	/* " lc		display active connections\n" */
	" info		display server type and version\n"
	" login		login to specified host\n"
	" logout	logout from specified host\n"
	" logoutall	logout all users (requires privilege)\n"
	" lookup	resolve NetBIOS name to IP address\n"
	" print		print file to the specified remote printer\n"
	" status	resolve IP address or DNS name to NetBIOS names\n"
	" view		list resources on specified host\n"
	"\n"));
	exit(1);
}

void
help_usage(void) {
	printf(gettext("usage: smbutil help command\n"));
	exit(1);
}
