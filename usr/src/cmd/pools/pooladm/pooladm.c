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

/*
 * pooladm - set, remove, or display active pool configurations.
 */

#include <sys/zone.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>
#include <string.h>
#include <priv.h>
#include <errno.h>
#include <zone.h>
#include <pool.h>
#include <unistd.h>
#include "utils.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static int Cflag;
static int Sflag;
static int Dflag;
static int Eflag;
static int Nflag;
static int Xflag;

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage:\tpooladm [-n] [-s] [-c] [filename]\n"));
	(void) fprintf(stderr,
	    gettext("Usage:\tpooladm [-n] -x\n"));
	(void) fprintf(stderr,
	    gettext("Usage:\tpooladm -d | -e\n"));
	exit(E_USAGE);
}

static void
config_print(pool_conf_t *conf)
{
	char *buf;
	pool_value_t *pv;
	const char *tgt;

	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY)
	    != PO_SUCCESS)
		die(gettext(ERR_OPEN_DYNAMIC), get_errstr());

	if ((pv = pool_value_alloc()) == NULL ||
	    pool_get_property(conf, pool_conf_to_elem(conf), "system.name",
	    pv) == POC_INVAL ||
	    pool_value_get_string(pv, &tgt) != PO_SUCCESS)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());

	if ((buf = pool_conf_info(conf, PO_TRUE)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS), gettext(CONFIGURATION),
		    tgt, get_errstr());
	pool_value_free(pv);
	(void) printf("%s", buf);
	free(buf);
	(void) pool_conf_close(conf);
}

static void
config_destroy(pool_conf_t *conf)
{
	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDWR)
	    != PO_SUCCESS)
		die(gettext(ERR_OPEN_DYNAMIC), get_errstr());
	if (pool_conf_remove(conf) != PO_SUCCESS)
		die(gettext(ERR_REMOVE_DYNAMIC), get_errstr());
}

static void
config_commit(pool_conf_t *conf, const char *static_conf_name)
{
	if (pool_conf_open(conf, static_conf_name, Nflag || !Sflag ?
	    PO_RDONLY : PO_RDWR) != PO_SUCCESS)
		die(gettext(ERR_OPEN_STATIC), static_conf_name, get_errstr());

	if (pool_conf_validate(conf, POV_RUNTIME) != PO_SUCCESS)
		die(gettext(ERR_VALIDATE_RUNTIME), static_conf_name);
	if (!Nflag) {
		if (pool_conf_commit(conf, PO_TRUE) != PO_SUCCESS)
			die(gettext(ERR_COMMIT_DYNAMIC), static_conf_name,
			    get_errstr());
		/*
		 * Dump the updated state to the specified location
		 */
		if (Sflag) {
			if (pool_conf_commit(conf, PO_FALSE) != PO_SUCCESS)
				die(gettext(ERR_COMMIT_STATIC),
				    static_conf_name, get_errstr());
		}
	}
	(void) pool_conf_close(conf);
}

int
main(int argc, char *argv[])
{
	int c;
	pool_conf_t *conf = NULL;
	const char *static_conf_loc;

	(void) getpname(argv[0]);
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);


	while ((c = getopt(argc, argv, "cdensx")) != EOF) {
		switch (c) {
		case 'c':	/* Create (or modify) system configuration */
			Cflag++;
			break;
		case 'd':	/* Disable the pools facility */
			Dflag++;
			break;
		case 'e':	/* Enable the pools facility */
			Eflag++;
			break;
		case 'n':	/* Don't actually do anything */
			Nflag++;
			break;
		case 's':	/* Update the submitted configuration */
			Sflag++;
			break;
		case 'x':	/* Delete current system configuration */
			Xflag++;
			break;
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/*
	 * Not all flags can be used at the same time.
	 */
	if ((Cflag || Sflag || Dflag || Eflag) && Xflag)
		usage();

	if ((Dflag || Eflag) && (Cflag || Sflag || Xflag))
		usage();

	if (Dflag && Eflag)
		usage();

	argc -= optind;
	argv += optind;

	if (! (Cflag || Sflag)) {
		if (argc != 0)
			usage();
	} else {
		if (argc == 0)
			static_conf_loc = pool_static_location();
		else if (argc == 1)
			static_conf_loc = argv[0];
		else
			usage();
	}

	if (!Nflag && (Cflag + Dflag + Eflag + Xflag != 0) &&
	    !priv_ineffect(PRIV_SYS_RES_CONFIG))
		die(gettext(ERR_PERMISSIONS));

	if (Dflag) {
		if (pool_set_status(POOL_DISABLED) != PO_SUCCESS)
			die(gettext(ERR_DISABLE));
	} else if (Eflag) {
		if (pool_set_status(POOL_ENABLED) != PO_SUCCESS) {
			if (errno == EEXIST)
				die(gettext(ERR_ENABLE
				    ": System has active processor sets\n"));
			else
				die(gettext(ERR_ENABLE));
		}
	} else {
		if ((conf = pool_conf_alloc()) == NULL)
			die(gettext(ERR_NOMEM));

		if (Cflag + Sflag + Xflag == 0) {
			/*
			 * No flags means print current system configuration
			 */
			config_print(conf);
		} else if (!Nflag && Xflag) {
			/*
			 * Destroy active pools configuration and
			 * remove the state file.
			 */
			config_destroy(conf);
		} else {
			/*
			 * Commit a new configuration.
			 */
			if (Cflag)
				config_commit(conf, static_conf_loc);
			else {
				/*
				 * Dump the dynamic state to the
				 * specified location
				 */
				if (!Nflag && Sflag) {
					if (pool_conf_open(conf,
					    pool_dynamic_location(), PO_RDONLY)
					!= PO_SUCCESS)
						die(gettext(ERR_OPEN_DYNAMIC),
						get_errstr());
					if (pool_conf_export(conf,
					    static_conf_loc, POX_NATIVE) !=
					    PO_SUCCESS)
						die(gettext(ERR_EXPORT_DYNAMIC),
						static_conf_loc, get_errstr());
					(void) pool_conf_close(conf);
				}
			}
		}
		pool_conf_free(conf);
	}
	return (E_PO_SUCCESS);
}
