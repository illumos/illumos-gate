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
 * niscat.c
 *
 * nis+ table cat utility
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <strings.h>
#include <stdlib.h>

extern int 	optind;
extern char	*optarg;


#define	BINARY_STR "*BINARY*"


struct pl_data {
	unsigned flags;
	char ta_sep;
};

#define	PL_BINARY 1

int
print_line(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	register entry_col *ec = ent->EN_data.en_cols.en_cols_val;
	register int ncol = ent->EN_data.en_cols.en_cols_len;
	register struct pl_data *d = (struct pl_data *)udata;
	register int i;
	int len;

	for (i = 0; i < ncol; i++) {
		if (i > 0)
			printf("%c", d->ta_sep);
		len = ec[i].ec_value.ec_value_len;
		if (len != 0) {
			if (ec[i].ec_flags & EN_BINARY) {
				if (d->flags & PL_BINARY) {
					fwrite(ec[i].ec_value.ec_value_val,
						1, len, stdout);
				} else {
					printf(BINARY_STR);
				}
			} else {
				printf("%s", ec[i].ec_value.ec_value_val);
			}
		}
	}
	printf("\n");

	return (0);
}

int
print_object(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	nis_print_object(ent);
	return (0);
}


#define	F_HEADER 1
#define	F_OBJECT 2

void
usage()
{
	fprintf(stderr, "usage: niscat [-LAMhv] [-s sep] tablename ...\n");
	fprintf(stderr, "       niscat [-LPAM] -o name ...\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	unsigned flags = 0;
	char *name;
	nis_result *tres, *eres;
	char tname[NIS_MAXNAMELEN];
	struct pl_data pld;
	int ncol, i;
	ulong_t flinks = 0, fpath = 0, allres = 0, master = 0;
	int error = 0;
	int bad_name;
	ulong_t list_flags;
	nis_object *obj;

	/*
	 * By default, don't print binary data.
	 */
	pld.flags = 0;

	pld.ta_sep = '\0';
	while ((c = getopt(argc, argv, "LPAMohvs:")) != -1) {
		switch (c) {
		case 'L' :
			flinks = FOLLOW_LINKS;
			break;
		case 'P':
			fpath = FOLLOW_PATH;
			break;
		case 'A':
			allres = ALL_RESULTS;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'h':
			flags |= F_HEADER;
			break;
		case 'v':
			pld.flags |= PL_BINARY;
			break;
		case 'o':
			flags |= F_OBJECT;
			break;
		case 's':
			if (strlen(optarg) != 1) {
				fprintf(stderr,
				    "separator must be a single character\n");
				exit(1);
			}
			pld.ta_sep = *optarg;
			break;
		default:
			usage();
		}
	}

	if (optind == argc) /* no table name */
		usage();

	while (optind < argc) {
		name = argv[optind++];

		if (flags & F_OBJECT) {
			if (*name == '[') {
				list_flags = fpath|allres|master|
						FOLLOW_LINKS|EXPAND_NAME;
				tres = nis_list(name, list_flags,
					print_object, 0);
				if ((tres->status != NIS_CBRESULTS) &&
				    (tres->status != NIS_NOTFOUND)) {
					nis_perror(tres->status, name);
					error = 1;
					goto loop;
				}
			} else {
				list_flags = flinks|master|EXPAND_NAME;
				tres = nis_lookup(name, list_flags);
				if (tres->status != NIS_SUCCESS) {
					nis_perror(tres->status, name);
					error = 1;
					goto loop;
				}
				nis_print_object(tres->objects.objects_val);
			}
			goto loop;
		}

		/*
		 * Get the table object using expand name magic.
		 */
		tres = nis_lookup(name, master|FOLLOW_LINKS|EXPAND_NAME);
		if (tres->status != NIS_SUCCESS) {
			nis_perror(tres->status, name);
			error = 1;
			goto loop;
		}

		/*
		 * Construct the name for the table that we found.
		 */
		bad_name = (snprintf(tname, sizeof (tname), "%s.",
					tres->objects.objects_val[0].zo_name)
						>= sizeof (tname));
		if (!bad_name &&
		    *(tres->objects.objects_val[0].zo_domain) != '.')
			bad_name = (strlcat(tname,
				tres->objects.objects_val[0].zo_domain,
				sizeof (tname)) >= sizeof (tname));

		if (bad_name) {
			nis_perror(NIS_BADNAME, "can't list table");
			error = 1;
			goto loop;
		}

		/*
		 * Make sure it's a table object.
		 */
		if (tres->objects.objects_val[0].zo_data.zo_type !=
				NIS_TABLE_OBJ) {
			fprintf(stderr, "%s is not a table!\n", tname);
			error = 1;
			goto loop;
		}

		/*
		 * Use the table's separator character when printing entries.
		 * Unless one was specified w/ -s
		 */
		if (pld.ta_sep == '\0') {
			pld.ta_sep
			    = tres->objects.objects_val[0].TA_data.ta_sep;
		}

		/*
		 * Print column names if F_HEADER is set.
		 */
		if (flags & F_HEADER) {
			obj = &tres->objects.objects_val[0];
			ncol = obj->TA_data.ta_cols.ta_cols_len;
			c = pld.ta_sep;
			printf("# ");
			for (i = 0; i < ncol; i++) {
				if (i > 0)
					printf("%c", c);
				printf("%s",
		obj->TA_data.ta_cols.ta_cols_val[i].tc_name);
			}
			printf("\n");
		}

		/*
		 * Cat the table using a callback function.
		 */
		list_flags = allres|master;
		eres = nis_list(tname, list_flags, print_line, (void *)&(pld));
		if ((eres->status != NIS_CBRESULTS) &&
		    (eres->status != NIS_NOTFOUND)) {
			nis_perror(eres->status, "can't list table");
			error = 1;
		}
		nis_freeresult(eres);

	loop:
		nis_freeresult(tres);
	}

	return (error);
}
