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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acctctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>

#include "utils.h"
#include "aconf.h"
#include "res.h"

static const char USAGE[] = "\
Usage:\n\
    acctadm [ {process | task | flow} ]\n\
    acctadm -u\n\
    acctadm -r [ {process | task | flow} ]\n\
    acctadm -x|-E|-D {process | task | flow}\n\
    acctadm -f filename {process | task | flow}\n\
    acctadm -e resources -d resources {process | task | flow}\n";

static const char OPTS[] = "ruxf:e:d:ED";
static const char PATH_CONFIG[] = "/etc/acctadm.conf";

static void
usage()
{
	(void) fprintf(stderr, gettext(USAGE));
	exit(E_USAGE);
}

int
main(int argc, char *argv[])
{
	int c;			/* options character */
	int type = 0;		/* type of accounting */
	int modified = 0;	/* have we modified the /etc/acctadm.conf? */
	acctconf_t ac;		/* current configuration */
	char *typestr = NULL;	/* type of accounting argument string */
	char *enabled = NULL;	/* enabled resources string */
	char *disabled = NULL;	/* disabled resources string */
	char *file = NULL;
	int Eflg = 0;
	int Dflg = 0;
	int rflg = 0;
	int uflg = 0;
	int xflg = 0;
	int optcnt = 0;
	int state;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) setprogname(argv[0]);

	for (; optind < argc; optind++) {
		while ((c = getopt(argc, argv, OPTS)) != (int)EOF) {
			switch (c) {
			case 'd':
				disabled = optarg;
				break;
			case 'e':
				enabled = optarg;
				break;
			case 'D':
				Dflg = 1;
				optcnt++;
				break;
			case 'E':
				Eflg = 1;
				optcnt++;
				break;
			case 'f':
				file = optarg;
				optcnt++;
				break;
			case 'r':
				rflg = 1;
				optcnt++;
				break;
			case 'u':
				uflg = 1;
				optcnt++;
				break;
			case 'x':
				xflg = 1;
				optcnt++;
				break;
			case '?':
			default:
				usage();
			}
		}
		if (optind < argc) {
			if (typestr != NULL) {
				warn(gettext("illegal argument -- %s\n"),
				    argv[optind]);
				usage();
			} else {
				typestr = argv[optind];
			}
		}
	}
	if (typestr != NULL) {
		if (strcmp(typestr, "process") == 0 ||
		    strcmp(typestr, "proc") == 0)
			type |= AC_PROC;
		else if (strcmp(typestr, "task") == 0)
			type |= AC_TASK;
		else if (strcmp(typestr, "flow") == 0)
			type |= AC_FLOW;
		else {
			warn(gettext("unknown accounting type -- %s\n"),
			    typestr);
			usage();
		}
	} else
		type = AC_PROC | AC_TASK | AC_FLOW;

	/*
	 * check for invalid options
	 */
	if (optcnt > 1)
		usage();

	if ((enabled || disabled) && (rflg || Dflg || uflg || xflg || Eflg))
		usage();

	if ((file || xflg || Dflg || Eflg || enabled || disabled) &&
	    !typestr) {
		warn(gettext("accounting type must be specified\n"));
		usage();
	}

	if ((file || enabled || disabled || xflg || uflg || Dflg || Eflg) &&
	    geteuid() != 0)
		die(gettext("must be root to change extended "
		    "accounting configuration\n"));

	if (rflg) {
		printgroups(type);
		return (E_SUCCESS);
	}

	/*
	 * If no arguments has been passed then just print out the current
	 * state, save it in the configuration file and exit.
	 */
	if (!enabled && !disabled && !file &&
	    !Eflg && !rflg && !Dflg && !uflg && !xflg) {
		aconf_init(&ac);
		aconf_print(&ac, stdout, type);
		return (E_SUCCESS);
	}

	if (uflg) {
		if (aconf_open(&ac, PATH_CONFIG) == -1)
			return (E_ERROR);
		if (aconf_setup(&ac) == -1)
			exit(E_ERROR);
		modified++;
	}

	if (xflg) {
		/*
		 * Turn off the specified accounting and close its file
		 */
		state = AC_OFF;
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot disable accounting"));
		if (aconf_str2enable(&ac, AC_STR_NO, type) == -1)
			die(gettext("cannot modify configuration file\n"));
		if (acctctl(type | AC_FILE_SET, NULL, 0) == -1)
			die(gettext("cannot close accounting file"));
		if (aconf_str2file(&ac, AC_STR_NONE, type) == -1)
			die(gettext("cannot modify configuration file\n"));
		modified++;
	}

	if (enabled || disabled) {
		char *tracked, *untracked;
		ac_res_t *buf;

		/*
		 * Enable/disable resources
		 */
		if ((buf = malloc(AC_BUFSIZE)) == NULL)
			die(gettext("not enough memory\n"));
		(void) memset(buf, 0, AC_BUFSIZE);
		if (acctctl(type | AC_RES_GET, buf, AC_BUFSIZE) == -1) {
			free(buf);
			die(gettext("cannot obtain list of resources\n"));
		}
		if (disabled)
			str2buf(buf, disabled, AC_OFF, type);
		if (enabled)
			str2buf(buf, enabled, AC_ON, type);
		if (acctctl(type | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
			free(buf);
			die(gettext("cannot enable or disable resources\n"));
		}
		tracked = buf2str(buf, AC_BUFSIZE, AC_ON, type);
		untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, type);
		if (aconf_str2tracked(&ac, tracked, type) == -1 ||
		    aconf_str2untracked(&ac, untracked, type)) {
			free(buf);
			free(tracked);
			free(untracked);
			die(gettext("cannot modify configuration file\n"));
		}
		free(tracked);
		free(untracked);
		free(buf);
		modified++;
	}

	if (file) {
		/*
		 * Open new accounting file
		 */
		state = AC_ON;
		if (aconf_str2file(&ac, file, type) == -1)
			die(gettext("cannot modify configuration file"));
		if (acctctl(type | AC_FILE_SET, file, strlen(file) + 1) == -1)
			die(gettext("cannot open accounting file"));
		if (aconf_str2enable(&ac, AC_STR_YES, type) == -1)
			die(gettext("cannot modify configuration file"));
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot enable accounting"));
		modified++;
	}

	if (Dflg) {
		/*
		 * Disable accounting
		 */
		state = AC_OFF;
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot disable accounting"));
		if (aconf_str2enable(&ac, AC_STR_NO, type) == -1)
			die(gettext("cannot modify configuration file"));
		modified++;
	}

	if (Eflg) {
		/*
		 * Enable accounting
		 */
		state = AC_ON;
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot enable accounting"));
		if (aconf_str2enable(&ac, AC_STR_YES, type) == -1)
			die(gettext("cannot modify configuration file"));
		modified++;
	}

	if (modified) {
		/*
		 * If we're modifying the configuration, then write out
		 * the new configuration file
		 */
		if (aconf_create(&ac, PATH_CONFIG) == -1)
			return (E_ERROR);
		aconf_init(&ac);
		if (aconf_write(&ac) == -1)
			return (E_ERROR);
	}

	if (aconf_close(&ac) == -1)
		die(gettext("failed to close configuration file"));
	return (E_SUCCESS);
}
