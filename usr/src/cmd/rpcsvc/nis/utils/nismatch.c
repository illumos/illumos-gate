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
 * nismatch.c
 *
 * nis+ table match utility
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <strings.h>
#include <stdlib.h>

extern char	*nisname_index();
extern nis_result * __nis_list_localcb(nis_name, uint_t,
    int (*)(nis_name, nis_object *, void *), void *);
extern int nisname_split(char *, char *, char *, int);


#define	BINARY_STR "*BINARY*"


struct pl_data {
	unsigned flags;
	char ta_sep;
	ulong_t nmatch;
};

#define	PL_BINARY 1
#define	PL_COUNT 2
#define	PL_OBJECT 4

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

	d->nmatch++;
	if (d->flags & PL_COUNT)
		return (0);

	if (d->flags & PL_OBJECT) {
		nis_print_object(ent);
		return (0);
	}

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


#define	EXIT_MATCH 0
#define	EXIT_NOMATCH 1
#define	EXIT_ERROR 2

#define	F_HEADER 1

void
usage()
{
	fprintf(stderr,
		"usage: nismatch [-PAMchvo] [-s sep] key tablename\n");
	fprintf(stderr,
	"       nismatch [-PAMchvo] [-s sep] colname=key ... tablename\n");
	fprintf(stderr,
		"       nismatch [-PAMchvo] [-s sep] indexedname\n");
	exit(EXIT_ERROR);
}

int
main(int argc, char *argv[])
{
	int 		c;
	ulong_t		fpath = 0, allres = 0, master = 0;
	unsigned 	flags = 0;
	char 		*p, *name;
	nis_result 	*tres, *eres;
	nis_object 	*tobj;
	char 		index[NIS_MAXNAMELEN],
			spred[NIS_MAXNAMELEN],
			tname[NIS_MAXNAMELEN],
			sname[NIS_MAXNAMELEN];
	struct pl_data 	pld;
	int 		ncol, i;
	table_col	*tcol;

	/*
	 * By default, don't print binary data to ttys.
	 */
	pld.flags = (isatty(1))?0:PL_BINARY;

	pld.ta_sep = '\0';
	while ((c = getopt(argc, argv, "PAMchvos:")) != -1) {
		switch (c) {
		case 'P':
			fpath = FOLLOW_PATH;
			break;
		case 'A':
			allres = ALL_RESULTS;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'c':
			pld.flags |= PL_COUNT;
			break;
		case 'h':
			flags |= F_HEADER;
			break;
		case 'v' :
			pld.flags |= PL_BINARY;
			break;
		case 'o' :
			pld.flags |= PL_OBJECT;
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

	if (argc - optind < 1)
		usage();

	/*
	 * build up the search criteria in sname, if a token is
	 * just "hanging" it is assumed to be a value for the
	 * first column. In that case keep it in spred until we
	 * can find the column name from the lookup.
	 */
	sname[0] = 0;
	spred[0] = 0;
	while (optind < (argc - 1)) {
		if (sname[0] == 0)
			strcat(sname, "[");
		p = argv[optind++];
		if (strchr(p, '=')) {
			if ((strlcat(sname, p, sizeof (sname)) >=
					sizeof (sname)) ||
			    (strlcat(sname, ",", sizeof (sname)) >=
					sizeof (sname))) {
				(void) fprintf(stderr,
					"search pattern too big\n");
				exit(EXIT_ERROR);
			}
		} else {
			/* if no "=" sign assume it it implicit */
			if (spred[0]) {
				fprintf(stderr,
				    "only one implicit column name allowed.\n");
				usage(argv[0]);
			}
			if (strlcat(spred, p, sizeof (spred)) >=
					sizeof (spred)) {
				nis_perror(NIS_BADNAME, p);
				exit(EXIT_ERROR);
			}
		}
	}

	/* This should be the last argument in the list */
	name = argv[optind];

	/* Split the name into the indexed part and the table part */
	if (nisname_split(name, tname, index, sizeof (tname))) {
		nis_perror(NIS_BADNAME, name);
		exit(EXIT_ERROR);
	}
	if (index[0] && sname[0]) {
		fprintf(stderr,
			"use either an indexed name or the col=key form.\n");
		usage();
	}

	/*
	 * Get the table object using expand name magic.
	 */
	tres = nis_lookup(tname, master|FOLLOW_LINKS|EXPAND_NAME);
	if (tres->status != NIS_SUCCESS) {
		nis_perror(tres->status, tname);
		exit(EXIT_ERROR);
	}

	/*
	 * Make sure it's a table object.
	 */
	tobj = tres->objects.objects_val;
	(void) snprintf(tname, sizeof (tname), "%s.%s", tobj->zo_name,
		tobj->zo_domain);
	if (__type_of(tobj) != NIS_TABLE_OBJ) {
		fprintf(stderr, "\"%s\" is not a table!\n", tname);
		exit(EXIT_ERROR);
	}
	ncol = tobj->TA_data.ta_cols.ta_cols_len;
	tcol = tobj->TA_data.ta_cols.ta_cols_val;

	/*
	 * Finish the construction of the search criteria if necessary.
	 * At this point we've got three candidates for the search
	 * criteria :
	 *	index - contains indexed name portion on table
	 *	spred - contains "hanging" value, implicitly for the
	 *		first column.
	 *	sname - name=value pairs that were specified on the
	 *		command line.
	 *	tname - the name of our table.
	 * NB: If sname || spred have something in them then index is available
	 * otherwise we use what is in index.
	 */
	if (spred[0]) {
		for (i = 0; i < ncol; i++)
			if (tcol[i].tc_flags & TA_SEARCHABLE)
				break;
		if (i == ncol) {
			fprintf(stderr, "%s: No searchable columns!\n", tname);
			exit(1);
		}
		(void) snprintf(index, sizeof (index), "%s=\"%s\"]",
			tcol[i].tc_name, spred);
		(void) strlcat(sname, index, sizeof (sname));
		(void) strlcpy(index, sname, sizeof (index));
	} else if (sname[0]) {
		sname[strlen(sname) - 1] = 0;
		(void) snprintf(index, sizeof (index), "%s]", sname);
	}
	/*
	 * Construct the search criteria for the table that we found.
	 */
	(void) strlcat(index, ",", sizeof (index));
	(void) strlcat(index, tname, sizeof (index));

	/*
	 * Use the table's separator character when printing entries.
	 * Unless one was specified w/ -s
	 */
	if (pld.ta_sep == '\0') {
		pld.ta_sep = tobj->TA_data.ta_sep;
	}

	/*
	 * Print column names
	 */
	if ((flags & F_HEADER) && !(pld.flags & (PL_COUNT|PL_OBJECT))) {
		c = pld.ta_sep;
		printf("# ");
		for (i = 0; i < ncol; i++) {
			if (i > 0)
				printf("%c", c);
			printf("%s", tcol[i].tc_name);
		}
		printf("\n");
	}

	/*
	 * Cat matching entries from the table using a callback function.
	 */
	pld.nmatch = 0;
	eres = __nis_list_localcb(index, fpath|allres|master,
				    print_line, (void *)&(pld));
	if ((eres->status != NIS_CBRESULTS) &&
	    (eres->status != NIS_NOTFOUND)) {
		nis_perror(eres->status, "can't list table");
		exit(EXIT_ERROR);
	}
	if (pld.flags & PL_COUNT)
		printf("%d\n", pld.nmatch);

	if (pld.nmatch)
		return (EXIT_MATCH);
	else
		return (EXIT_NOMATCH);
}
