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
#ifndef lint
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#endif  lint

/*
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */

/*
 * Fix up the nis+ database, if it's broken.
 */

#include	<stdio.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/param.h>
#include	<dirent.h>
#include	<fcntl.h>
#include	<string.h>
#include	<locale.h>
#include	<libintl.h>

#include	<rpc/rpc.h>
#include	<rpcsvc/nis.h>

#include	"../vold/db_nis.h"

char	*prog_name;
void	usage();

char	*volume_group;

main(int argc, char **argv)
{

	extern char 	*optarg;
	extern int	optind;
	int		c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	if (getuid() != 0) {
		fprintf(stderr, gettext("Must be root to run this program\n"));
		exit(-1);
	}
	/* process arguments */
	while ((c = getopt(argc, argv, "g:")) != EOF) {
		switch (c) {
		case 'g':
			volume_group = optarg;
			break;
		default:
			usage();
			exit(-1);
		}
	}
	volck();
}

void
usage()
{
	fprintf(stderr,
	    gettext("usage: %s [-g volume_group]\n"), prog_name);
}

char	*dtabname;
char	*ctabname;
char	*nis_directory;

volck()
{
	char		namebuf[MAXNAMELEN];
	nis_result	*res;
	nis_object	no;
	table_col	*tc;
	table_obj	*to = &no.zo_data.objdata_u.ta_data;
	entry_col	*ec;
	entry_obj	*eo = &no.zo_data.objdata_u.en_data;

	nis_directory = nis_local_directory();

	if (volume_group == NULL) {
		sprintf(namebuf, "%s.%s", DTABNAME, VOLDIR);
		dtabname = strdup(namebuf);

		sprintf(namebuf, "%s.%s", CTABNAME, VOLDIR);
		ctabname = strdup(namebuf);
	} else {
		sprintf(namebuf, "%s.%s.%s", DTABNAME, volume_group, VOLDIR);
		dtabname = strdup(namebuf);

		sprintf(namebuf, "%s.%s.%s", CTABNAME, volume_group, VOLDIR);
		ctabname = strdup(namebuf);
	}
	/*
	 * Just see if the directory is there
	 * This allows us to print a meaningful message if the user
	 * hasn't created all the right stuff.
	 */
	if (volume_group == NULL)
		sprintf(namebuf, "%s.%s", VOLDIR, nis_directory);
	else
		sprintf(namebuf, "%s.%s.%s",
			volume_group, VOLDIR, nis_directory);
	res = nis_lookup(namebuf, 0);
	if (res->status != NIS_SUCCESS) {
		if (res->status == NIS_NOTFOUND) {
			fprintf(stderr,
				gettext("Nis object %s was not found\n"),
				namebuf);
			nis_freeresult(res);
			return (0);
		} else {
			fprintf(stderr, gettext("Nis error %s on object %s\n"),
				nis_sperrno(res->status), namebuf);
			nis_freeresult(res);
			return (FALSE);
		}
	}
	nis_freeresult(res);

	/* look for the control table */
	sprintf(namebuf, "%s.%s", ctabname, nis_directory);

	res = nis_lookup(namebuf, 0);
	if (res->status == NIS_SUCCESS) {
		found_ctl = 1;
	} else if (res->status == NIS_NOTFOUND) {
		found_ctl = 0;
	} else {
		/* nis returned some horrible error */
		fprintf(stderr, gettext(
		    "nis_db_init lookup control error: nis+ says '%s'\n"),
		    nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}

	nis_freeresult(res);

	/* look for the data table */
	sprintf(namebuf, "%s.%s", dtabname, nis_directory);

	res = nis_lookup(namebuf, 0);
	if (res->status == NIS_SUCCESS) {
		found_dat = 1;
	} else if (res->status == NIS_NOTFOUND) {
		found_dat = 0;
	} else {

		/* nis returned some horrible error */
		fprintf(stderr, gettext(
		    "nis_db_init lookup data error: nis+ says '%s'\n"),
		    nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}

	nis_freeresult(res);

	/*
	 * let them know if we have one but not the other.
	 */
	if (found_ctl != found_dat) {
		fprintf(stderr, "volck: Your %s table was missing, ",
			found_ctl ? "volumes":"control");
		fprintf(stderr, "but your %s table was there.\n"
			found_ctl ? "control":"volumes");
	}

	/* if we have a control table, look it over */
	if (found_ctl) {

	}

	/* Create the data table */
	if (found_dat == 0) {
		sprintf(namebuf, "%s.%s", dtabname, nis_directory);
		memset(&no, 0, sizeof (nis_object));
		tc = (table_col *)calloc(ncols_data, sizeof (table_col));
		no.zo_data.zo_type = NIS_TABLE_OBJ;
		no.zo_access = DEFAULT_RIGHTS;
		no.zo_owner = nis_local_principal();
		to->ta_type = DTABTYPE;
		to->ta_maxcol = ncols_data;
		to->ta_sep = NISSEP;
		to->ta_cols.ta_cols_len = ncols_data;
		to->ta_cols.ta_cols_val = tc;

		for (i = 0; i < ncols_data; i++) {
			tc[i].tc_name = (char *)DT_NAME(i);
			tc[i].tc_flags = DT_TFLAG(i);
			tc[i].tc_rights = DEFAULT_RIGHTS;
		}
		res = nis_add(namebuf, &no);
		if (res->status != NIS_SUCCESS) {
			nis_print_object(&no);
			fprintf(stderr, gettext(
			 "nis_db_init add data table error: nis+ says '%s'\n"),
			    nis_sperrno(res->status));
			nis_freeresult(res);
			free(tc);
			return (FALSE);
		}

	}
	nis_db_initialized = 1;
	(void) db_new(&nis_dbops);
	return (TRUE);


}
