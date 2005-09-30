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
 * nisln.c
 *
 * nis+ link utility
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <stdlib.h>
#include <strings.h>

extern nis_object nis_default_obj;

extern char *nisname_index();
extern int nisname_split(char *, char *, char *, int);


static void
usage()
{
	fprintf(stderr, "usage: nisln [-D defaults] [-L] name linkname\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	char *defstr = 0;
	ulong_t flinks = 0;
	char *name, *lname;
	nis_result *res, *ares;
	nis_object *obj, lobj;
	char oname[NIS_MAXNAMELEN], fbase[NIS_MAXNAMELEN];
	char srch[NIS_MAXNAMELEN], base[NIS_MAXNAMELEN];
	nis_error s;
	ib_request ibr;
	int bad_name;
	int i, j;

	while ((c = getopt(argc, argv, "D:L")) != -1) {
		switch (c) {
		case 'D':
			defstr = optarg;
			break;
		case 'L':
			flinks = FOLLOW_LINKS;
			break;
		default:
			usage();
		}
	}

	if (argc - optind != 2)
		usage();

	name = argv[optind];
	lname = argv[optind+1];

	/*
	 * Get the object to link to.
	 */
	if (nisname_split(name, base, srch, sizeof (base)) || base[0] == 0) {
		nis_perror(NIS_BADNAME, name);
		exit(1);
	}
	res = nis_lookup(base, flinks|MASTER_ONLY|EXPAND_NAME);
	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, base);
		exit(1);
	}
	obj = res->objects.objects_val;

	bad_name = (snprintf(fbase, sizeof (fbase), "%s.", obj->zo_name)
			>= sizeof (fbase));
	if (!bad_name && *(obj->zo_domain) != '.')
		bad_name = (strlcat(fbase, obj->zo_domain, sizeof (fbase)) >=
			sizeof (fbase));

	if (bad_name) {
		nis_perror(NIS_BADNAME, fbase);
		exit(1);
	}

	if (obj->zo_data.zo_type == NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\" is a directory!\n", fbase);
		exit(1);
	}

	if (srch[0]) {
		if (obj->zo_data.zo_type != NIS_TABLE_OBJ) {
			fprintf(stderr, "\"%s\" is not a table!\n", fbase);
			exit(1);
		}

		bad_name = (snprintf(oname, sizeof (oname), "%s,%s",
				srch, fbase) >= sizeof (oname));

		if (bad_name) {
			nis_perror(NIS_BADNAME, oname);
			exit(1);
		}

		s = nis_get_request(oname, 0, 0, &ibr);
		if (s != NIS_SUCCESS) {
			nis_perror(s, oname);
			exit(1);
		}

		for (i = 0; i < ibr.ibr_srch.ibr_srch_len; i++) {
			for (j = 0; j < obj->TA_data.ta_cols.ta_cols_len; j++)
				if
			    (strcmp(ibr.ibr_srch.ibr_srch_val[i].zattr_ndx,
			    obj->TA_data.ta_cols.ta_cols_val[j].tc_name) == 0)
					break;
			if (j == obj->TA_data.ta_cols.ta_cols_len) {
				nis_perror(NIS_BADATTRIBUTE, name);
				exit(1);
			}
		}
	} else {
		memset(&ibr, 0, sizeof (ibr));
		ibr.ibr_name = fbase;
	}

	if (!nis_defaults_init(defstr))
		exit(1);

	/*
	 * Construct link object.
	 */
	lobj = nis_default_obj;
	lobj.zo_data.zo_type = NIS_LINK_OBJ;
	if (srch[0])
		lobj.LI_data.li_rtype = NIS_ENTRY_OBJ;
	else
		lobj.LI_data.li_rtype = obj->zo_data.zo_type;
	lobj.LI_data.li_attrs.li_attrs_len = ibr.ibr_srch.ibr_srch_len;
	lobj.LI_data.li_attrs.li_attrs_val = ibr.ibr_srch.ibr_srch_val;
	lobj.LI_data.li_name = ibr.ibr_name;

	ares = nis_add(lname, &lobj);
	if (ares->status != NIS_SUCCESS) {
		nis_perror(ares->status, "can't add link");
		exit(1);
	}

	return (0);
}
