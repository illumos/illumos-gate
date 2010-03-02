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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libgen.h>
#include <libintl.h>
#include <libv12n.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/param.h>
#include <uuid/uuid.h>

static char *cmdname;

char *options = "acdpstu";

static void
virtinfo_usage()
{
	(void) fprintf(stderr, gettext("usage: %s [-%s]\n"), cmdname, options);
	exit(1);
}

static char *
virtinfo_cap_to_impl(int cap)
{
	if (cap & V12N_CAP_IMPL_LDOMS)
		return ("LDoms");
	return ("Unknown");
}


int
main(int argc, char *argv[])
{
	int cap;
	int roles;
	size_t rv;
	int opt;
	int errflg = 0;
	int aflg = 0, cflg = 0, dflg = 0, pflg = 0, sflg = 0, tflg = 0,
	    uflg = 0;

	cmdname = basename(argv[0]);

	/* disable getopt error messages */
	opterr = 0;

	while ((opt = getopt(argc, argv, options)) != EOF) {

		switch (opt) {
		case 'a':
			aflg = 1;
			break;
		case 'c':
			cflg = 1;
			break;
		case 'd':
			dflg = 1;
			break;
		case 'p':
			pflg = 1;
			break;
		case 's':
			sflg = 1;
			break;
		case 't':
			tflg = 1;
			break;
		case 'u':
			uflg = 1;
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	}

	if (errflg || optind != argc)
		virtinfo_usage();

	if (aflg) {
		/* aflg -> set all flags except -p */
		cflg = dflg = sflg = tflg = uflg = 1;
	} else if (cflg == 0 && dflg == 0 && sflg == 0 && tflg == 0 &&
	    uflg == 0) {
		/* no flag set, default to '-t' */
		tflg = 1;
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) printf(gettext(
		    "%s can only be run from the global zone\n"), cmdname);
		exit(0);
	}

	cap = v12n_capabilities();
	if ((cap & V12N_CAP_SUPPORTED) == 0) {
		(void) printf(gettext("Virtual machines are not supported\n"));
		exit(0);
	} else if ((cap & V12N_CAP_ENABLED) == 0) {
		(void) printf(gettext(
		    "Virtual machines (%s) are supported but not enabled\n"),
		    virtinfo_cap_to_impl(cap));
		exit(0);
	}

	if (pflg) {
		(void) printf("VERSION 1.0\n");
	}

	if (tflg) {
		char *impl = "", *role = "", *io = "", *service = "",
		    *root = "";

		roles = v12n_domain_roles();

		if (roles == -1 || (cap & V12N_CAP_IMPL_LDOMS) == 0) {
			if (pflg)
				impl = "impl=Unknown";
			else
				impl = "Unknown";
		} else if (pflg) {
			impl = "impl=LDoms";
			role = (roles & V12N_ROLE_CONTROL) ?
			    "|control=true" : "|control=false";
			io = (roles & V12N_ROLE_IO) ?
			    "|io=true" : "|io=false";
			service = (roles & V12N_ROLE_SERVICE) ?
			    "|service=true" : "|service=false";
			root = (roles & V12N_ROLE_ROOT) ?
			    "|root=true" : "|root=false";
		} else {
			impl = "LDoms";
			role = (roles & V12N_ROLE_CONTROL) ?
			    " control" : " guest";
			io = (roles & V12N_ROLE_IO) ?
			    " I/O" : "";
			service = (roles & V12N_ROLE_SERVICE) ?
			    " service" : "";
			root = (roles & V12N_ROLE_ROOT) ?
			    " root" : "";
		}
		(void) printf("%s%s%s%s%s%s\n", pflg ? "DOMAINROLE|" :
		    gettext("Domain role: "), impl, role, io, service, root);
	}

	if (dflg) {
		char domain_name[V12N_NAME_MAX];

		rv = v12n_domain_name(domain_name, sizeof (domain_name));
		if (rv == (size_t)(-1)) {
			(void) strcpy(domain_name, "Unknown");
		}
		(void) printf("%s%s\n", pflg ? "DOMAINNAME|name=" :
		    gettext("Domain name: "), domain_name);
	}

	if (uflg) {
		uuid_t uuid;
		char uuid_str[UUID_PRINTABLE_STRING_LENGTH];

		rv = v12n_domain_uuid(uuid);

		if (rv == (size_t)(-1)) {
			(void) strcpy(uuid_str, "Unknown");
		} else {
			uuid_unparse(uuid, uuid_str);
		}
		(void) printf("%s%s\n", pflg ? "DOMAINUUID|uuid=" :
		    gettext("Domain UUID: "), uuid_str);
	}

	if (cflg) {
		char ctrl_name[V12N_NAME_MAX];

		rv = v12n_ctrl_domain(ctrl_name, sizeof (ctrl_name));

		if (rv == (size_t)(-1)) {
			(void) strcpy(ctrl_name, "Unknown");
		}
		(void) printf("%s%s\n", pflg ? "DOMAINCONTROL|name=" :
		    gettext("Control domain: "), ctrl_name);
	}

	if (sflg) {
		char serial_no[V12N_NAME_MAX];

		rv = v12n_chassis_serialno(serial_no, sizeof (serial_no));

		if (rv == (size_t)(-1)) {
			(void) strcpy(serial_no, "Unknown");
		}
		(void) printf("%s%s\n", pflg ? "DOMAINCHASSIS|serialno=" :
		    gettext("Chassis serial#: "), serial_no);
	}
	return (0);
}
