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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is a user command which dumps each entry in a yp data base.  It gets
 * the stuff using the normal ypclnt package; the user doesn't get to choose
 * which server gives them the input.  Usage is:
 *	ypcat [-k] [-d domain] [-t] map
 *	ypcat -x
 * where the -k switch will dump keys followed by a single blank space
 * before the value, and the -d switch can be used to specify a domain other
 * than the default domain. -t switch inhibits nickname translation of map
 * names. -x is to dump the nickname translation table from file /var/yp/
 * nicknames.
 *
 */
#ifdef NULL
#undef NULL
#endif
#define	NULL 0
#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static int translate = TRUE;
static int dodump = FALSE;
static int dumpkeys = FALSE;
static char *domain = NULL;
static char default_domain_name[YPMAXDOMAIN];
static char nm[YPMAXMAP+1];
static char *map = NULL;
static char nullstring[] = "";
static char err_usage[] =
"Usage:\n\
	ypcat [-k] [-d domainname] [-t] mapname\n\
	ypcat -x\n\
where\n\
	mapname may be either a mapname or a nickname for a map.\n\
	-t inhibits map nickname translation.\n\
	-k prints keys as well as values.\n\
	-x dumps the map nickname translation table.\n";
static char err_bad_args[] =
	"ypcat:  %s argument is bad.\n";
static char err_cant_get_kname[] =
	"ypcat:  can't get %s back from system call.\n";
static char err_null_kname[] =
	"ypcat:  the %s hasn't been set on this machine.\n";
static char err_bad_mapname[] = "mapname";
static char err_bad_domainname[] = "domainname";
static char err_first_failed[] =
	"ypcat:  can't get first record from yp.  Reason:  %s.\n";
static char err_next_failed[] =
	"ypcat:  can't get next record from yp.  Reason:  %s.\n";

static void get_command_line_args();
static int callback();
static void one_by_one_all();
extern void maketable();
extern int getmapname();
static void getdomain();

/*
 * This is the mainline for the ypcat process.  It pulls whatever arguments
 * have been passed from the command line, and uses defaults for the rest.
 */

int
main(int argc, char ** argv)
{
	int err;
	int fail = 0;
	struct ypall_callback cbinfo;

	get_command_line_args(argc, argv);

	if (dodump) {
		maketable(dodump);
		exit(0);
	}

	if (!domain) {
		getdomain();
	}

	if (translate && (strchr(map, '.') == NULL) &&
		(getmapname(map, nm))) {
		map = nm;
	}

	cbinfo.foreach = callback;
	cbinfo.data = (char *)&fail;
	err = __yp_all_rsvdport(domain, map, &cbinfo);

	if (err == YPERR_VERS) {
		one_by_one_all(domain, map);
	} else if (err) {
		fail = TRUE;
		fprintf(stderr, "%s\n", yperr_string(err));
	}

	exit(fail);
}

/*
 * This does the command line argument processing.
 */
static void
get_command_line_args(argc, argv)
	int argc;
	char **argv;

{

	argv++;

	while (--argc > 0 && (*argv)[0] == '-') {

		switch ((*argv)[1]) {

		case 't':
			translate = FALSE;
			break;

		case 'k':
			dumpkeys = TRUE;
			break;

		case 'x':
			dodump = TRUE;
			break;

		case 'd':

			if (argc > 1) {
				argv++;
				argc--;
				domain = *argv;

				if ((int)strlen(domain) > YPMAXDOMAIN) {
					(void) fprintf(stderr, err_bad_args,
					    err_bad_domainname);
					exit(1);
				}

			} else {
				(void) fprintf(stderr, err_usage);
				exit(1);
			}

			break;

		default:
			(void) fprintf(stderr, err_usage);
			exit(1);
		}
		argv++;
	}

	if (!dodump) {
		map = *argv;
		if (argc < 1) {
			(void) fprintf(stderr, err_usage);
			exit(1);
		}
		if ((int)strlen(map) > YPMAXMAP) {
			(void) fprintf(stderr, err_bad_args, err_bad_mapname);
			exit(1);
		}
	}
}

/*
 * This dumps out the value, optionally the key, and perhaps an error message.
 */
static int
callback(status, key, kl, val, vl, fail)
	int status;
	char *key;
	int kl;
	char *val;
	int vl;
	int *fail;
{
	int e;

	if (status == YP_TRUE) {

		if (dumpkeys)
			(void) printf("%.*s ", kl, key);

		(void) printf("%.*s\n", vl, val);
		return (FALSE);
	} else {

		e = ypprot_err(status);

		if (e != YPERR_NOMORE) {
			(void) fprintf(stderr, "%s\n", yperr_string(e));
			*fail = TRUE;
		}

		return (TRUE);
	}
}

/*
 * This cats the map out by using the old one-by-one enumeration interface.
 * As such, it is prey to the old-style problems of rebinding to different
 * servers during the enumeration.
 */
static void
one_by_one_all(domain, map)
char *domain;
char *map;
{
	char *key;
	int keylen;
	char *outkey;
	int outkeylen;
	char *val;
	int vallen;
	int err;

	key = nullstring;
	keylen = 0;
	val = nullstring;
	vallen = 0;

	if (err = yp_first(domain, map, &outkey, &outkeylen, &val, &vallen)) {

		if (err == YPERR_NOMORE) {
			exit(0);
		} else {
			(void) fprintf(stderr, err_first_failed,
			    yperr_string(err));
			exit(1);
		}
	}

	for (;;) {

		if (dumpkeys) {
			(void) printf("%.*s ", outkeylen, outkey);
		}

		(void) printf("%.*s\n", vallen, val);
		free(val);
		key = outkey;
		keylen = outkeylen;

		if (err = yp_next(domain, map, key, keylen, &outkey, &outkeylen,
		    &val, &vallen)) {

			if (err == YPERR_NOMORE) {
				break;
			} else {
				(void) fprintf(stderr, err_next_failed,
				    yperr_string(err));
				exit(1);
			}
		}

		free(key);
	}
}

/*
 * This gets the local default domainname, and makes sure that it's set
 * to something reasonable.  domain is set here.
 */
static void
getdomain()
{
	if (!getdomainname(default_domain_name, YPMAXDOMAIN)) {
		domain = default_domain_name;
	} else {
		(void) fprintf(stderr, err_cant_get_kname, err_bad_domainname);
		exit(1);
	}

	if ((int)strlen(domain) == 0) {
		(void) fprintf(stderr, err_null_kname, err_bad_domainname);
		exit(1);
	}
}
