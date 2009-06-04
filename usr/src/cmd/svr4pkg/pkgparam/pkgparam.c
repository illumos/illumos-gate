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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <locale.h>
#include <libintl.h>

#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

extern char	*pkgfile;

#define	ERR_ROOT_SET	"Could not set install root from the environment."
#define	ERR_ROOT_CMD	"Command line install root contends with environment."
#define	ERR_MESG	"unable to locate parameter information for \"%s\""
#define	ERR_FLT		"parsing error in parameter file"
#define	ERR_USAGE	"usage:\n" \
			"\t%s [-v] [-d device] pkginst [param [param ...]]\n" \
			"\t%s [-v] -f file [param [param ...]]\n"
#define	HASHSIZE	151
#define	BSZ		4


static char	*device = NULL;
static int	errflg = 0;
static int	vflag = 0;

static void	print_entry(char *, char *);

static void
usage(void)
{
	char	*prog = get_prog_name();

	(void) fprintf(stderr, gettext(ERR_USAGE), prog, prog);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *value, *pkginst;
	char *param, parambuf[128];
	int c;

	pkgfile = NULL;

	/* initialize locale mechanism */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* determine program name */

	(void) set_prog_name(argv[0]);

	/* establish installation root directory */

	if (!set_inst_root(getenv("PKG_INSTALL_ROOT"))) {
		progerr(gettext(ERR_ROOT_SET));
		exit(1);
	}

	while ((c = getopt(argc, argv, "R:vd:f:?")) != EOF) {
		switch (c) {
		    case 'v':
			vflag++;
			break;

		    case 'f':
			/* -f could specify filename to get parameters from */
			pkgfile = optarg;
			break;

		    case 'd':
			/* -d could specify stream or mountable device */
			device = flex_device(optarg, 1);
			break;

		    case 'R':
			if (!set_inst_root(optarg)) {
				progerr(gettext(ERR_ROOT_CMD));
				exit(1);
			}
			break;

		    default:
		    case '?':
			usage();
		}
	}

	set_PKGpaths(get_inst_root());

	if (pkgfile) {
		if (device)
			usage();
		pkginst = pkgfile;
	} else {
		if ((optind+1) > argc)
			usage();

		if (pkghead(device))
			return (1); /* couldn't obtain info about device */
		pkginst = argv[optind++];
	}

	/* If a filename was specified or install db does not exist */
	do {
		param = argv[optind];
		if (!param) {
			param = parambuf;
			*param = '\0';
		}
		value = pkgparam(pkginst, param);
		if (value == NULL) {
			if (errno == EFAULT) {
				progerr(gettext(ERR_FLT));
				errflg++;
				break;
			} else if (errno != EINVAL) {
				/*
				 * some other error besides no value for this
				 * particular parameter
				 */
				progerr(gettext(ERR_MESG), pkginst);
				errflg++;
				break;
			}
			if (!argv[optind])
				break;
			continue;
		}

		print_entry(param, value);

	} while (!argv[optind] || (++optind < argc));
	(void) pkgparam(NULL, NULL); /* close open FDs so umount won't fail */

	(void) pkghead(NULL);
	return (errflg ? 1 : 0);
}

static void
print_entry(char *param, char *value)
{
	if (vflag) {
		(void) printf("%s='", param);
		while (*value) {
			if (*value == '\'') {
				(void) printf("'\"'\"'");
				value++;
			} else
				(void) putchar(*value++);
		}
		(void) printf("'\n");
	} else
		(void) printf("%s\n", value);
}

void
quit(int retval)
{
	exit(retval);
}
