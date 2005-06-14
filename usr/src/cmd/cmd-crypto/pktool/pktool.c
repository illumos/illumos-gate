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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file comprises the main driver for this tool.
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
	int	mode;			/* reserved */
	char	*synopsis;		/* reserved */
} verbcmd;

/* External declarations for supported verb actions. */
extern int	pk_setpin(int argc, char *argv[]);

/* Command structure for verbs and their actions.  Do NOT i18n/l10n. */
static verbcmd	cmds[] = {
	{ "setpin",	pk_setpin,	0,	"" },
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
	(void) fprintf(stderr, gettext("Usage:\n"));
	(void) fprintf(stderr, gettext("\t%s setpin\n"), prog);
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

	/* There must be one remaining arg at this point */
	if (argc == 0) {
		usage();
		return (1);
	}

	/*
	 * By default, metaslot is enabled, and pkcs11_softtoken is
	 * the keystore, so, pkcs11_softtoken is hidden.
	 * Always turns off Metaslot so that we can see pkcs11_softtoken.
	 */
	if (setenv("METASLOT_ENABLED", "false", 1) < 0) {
		pk11_errno = errno;
		cryptoerror(LOG_STDERR,
		    gettext("Disabling metaslot failed: %s"),
		    strerror(pk11_errno));
		return (1);
	}

	/* Begin parsing command line. */
	pk_argc = argc;
	pk_argv = argv;

	/* Check for valid verb */
	found = -1;
	for (i = 0; i < num_cmds; i++) {
		if (strcmp(cmds[i].verb, pk_argv[0]) == 0) {
			if (found < 0) {
				found = i;
				break;
			}
		}
	}

	/* Stop here if no valid verb found. */
	if (found < 0) {
		cryptoerror(LOG_STDERR,
			gettext("Invalid verb: %s"), pk_argv[0]);
		return (1);
	}

	/* Get to work! */
	rv = (*cmds[found].action)(pk_argc, pk_argv);
	switch (rv) {
	case PK_ERR_NONE:
		break;		/* Command succeeded, do nothing. */
	case PK_ERR_USAGE:
		usage();
		break;
	case PK_ERR_QUIT:
		exit(0);
		/* NOTREACHED */
	case PK_ERR_PK11INIT:
		cryptoerror(LOG_STDERR, "%s (%s)",
		    gettext("Unable to initialize PKCS#11"),
		    pkcs11_strerror(pk11_errno));
		cryptodebug("C_Initialize failed (%s)",
		    pkcs11_strerror(pk11_errno));
		break;
	case PK_ERR_PK11SLOTS:
		cryptoerror(LOG_STDERR, "%s (%s)",
		    gettext("Failed to find PKCS#11 slots"),
		    pkcs11_strerror(pk11_errno));
		cryptodebug("C_GetSlotList failed (%s)",
		    pkcs11_strerror(pk11_errno));
		break;
	case PK_ERR_PK11SESSION:
		cryptoerror(LOG_STDERR, "%s (%s)",
		    gettext("Unable to open PKCS#11 session"),
		    pkcs11_strerror(pk11_errno));
		cryptodebug("C_OpenSession failed (%s)",
		    pkcs11_strerror(pk11_errno));
		break;
	case PK_ERR_PK11LOGIN:
		if (pk11_errno == CKR_PIN_INCORRECT)
			cryptoerror(LOG_STDERR, "%s", gettext("Incorrect PIN"));
		else {
			cryptoerror(LOG_STDERR, "%s (%s)",
			    gettext("PKCS#11 authentication failed"),
			    pkcs11_strerror(pk11_errno));
			cryptodebug("C_Login failed (%s)",
			    pkcs11_strerror(pk11_errno));
		}
		break;
	case PK_ERR_PK11SETPIN:
		cryptoerror(LOG_STDERR, "%s (%s)",
		    gettext("Set PIN failed"), pkcs11_strerror(pk11_errno));
		break;
	case PK_ERR_NOSLOTS:
		cryptoerror(LOG_STDERR, "%s", gettext("No slots were found"));
		break;
	case PK_ERR_NOMEMORY:
		cryptoerror(LOG_STDERR, "%s", gettext("Out of memory"));
		break;
	case PK_ERR_NOTFOUND:
		cryptoerror(LOG_STDERR, "%s", gettext("Token name not found"));
		break;
	case PK_ERR_PASSPHRASE:
		cryptoerror(LOG_STDERR, "%s",
		    gettext("Unable to get token PIN"));
		break;
	case PK_ERR_NEWPIN:
		cryptoerror(LOG_STDERR, "%s", gettext("Failed to get new PIN"));
		break;
	case PK_ERR_PINCONFIRM:
		cryptoerror(LOG_STDERR, "%s",
		    gettext("Failed to confirm new PIN"));
		break;
	case PK_ERR_PINMATCH:
		cryptoerror(LOG_STDERR, "%s", gettext("PINs do not match"));
		break;
	case PK_ERR_CHANGEPIN:
		cryptoerror(LOG_STDERR, "%s", gettext("PIN must be changed"));
		break;
	default:
		cryptoerror(LOG_STDERR, "%s (%d)",
		    gettext("Unknown error value"), rv);
		break;
	}
	return (rv);
}
