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
 * nisgrep.c
 *
 * nis+ table grep utility
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <regex.h>

extern int 	optind;
extern char	*optarg;

extern char	*nisname_index();


#define	BINARY_STR "*BINARY*"
#define	TABLE_COLS(tres) tres->objects.objects_val[0].TA_data.ta_cols

#define	EXIT_MATCH	0
#define	EXIT_NOMATCH	1
#define	EXIT_ERROR	2

struct pl_data {
	unsigned flags;
	char ta_sep;
	ulong_t nmatch;
	regex_t *re_dfa;
	int *dfa_set;		/* dfa_set[i] set if re_dfa[i] is valid */
};

#define	PL_BINARY	1
#define	PL_COUNT	2
#define	PL_OBJECT	4
#define	PL_NOCASE	8

static
char *
strlower(s)
	char *s;
{
	int i;
	int len;
	char *p;

	len = strlen(s) + 1;
	p = malloc(len);
	if (p == NULL) {
		fprintf(stderr, "No memory!\n");
		exit(EXIT_ERROR);
	}
	/* this loop includes the terminating null */
	for (i = 0; i < len; i++) {
		if (isupper(s[i]))
			p[i] = tolower(s[i]);
		else
			p[i] = s[i];
	}

	return (p);
}


int
print_line(tab, ent, udata)
	char *tab;
	nis_object *ent;
	void *udata;
{
	int len;
	char *val;
	int res;
	register entry_col *ec = ent->EN_data.en_cols.en_cols_val;
	register int ncol = ent->EN_data.en_cols.en_cols_len;
	register struct pl_data *d = (struct pl_data *)udata;
	register int i;

	/*
	 * check for matches with all patterns
	 */
	for (i = 0; i < ncol; i++)
		if (d->dfa_set[i]) {
			val = ec[i].ec_value.ec_value_val;
			len = ec[i].ec_value.ec_value_len;
			if (len == 0)
				return (0);
			if (val[len-1] != '\0')
				return (0);

			if (d->flags & PL_NOCASE) {
				val = strlower(val);
				res = regexec(&d->re_dfa[i], val, 0, 0, 0);
				free((void *)val);
			} else {
				res = regexec(&d->re_dfa[i], val, 0, 0, 0);
			}
			switch (res) {
			case REG_ENOSYS:
				return (-1);
			case REG_NOMATCH:
				return (0);
			}
		}

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
		if (ec[i].ec_value.ec_value_len) {
			if ((ec[i].ec_flags & EN_BINARY) &&
			    !(d->flags & PL_BINARY))
				printf(BINARY_STR);
			else
				printf("%s", ec[i].ec_value.ec_value_val);
		}
	}
	printf("\n");

	return (0);
}


#define	F_HEADER 1

void
usage()
{
	fprintf(stderr,
	    "usage: nisgrep [-AMchivo] [-s sep] keypat tablename\n");
	fprintf(stderr,
	"       nisgrep [-AMchivo] [-s sep] colname=keypat ... tablename\n");
	exit(EXIT_ERROR);
}

static void
re_error(char *pattern, int code, regex_t *expr)
{
	char buf[80];

	buf[0] = 0;
	regerror(code, expr, buf, sizeof (buf));
	fprintf(stderr,
		"can't compile regular expression \"%s\": %s\n",
		pattern, buf);
}

int
main(int argc, char *argv[])
{
	int c;
	int st;
	ulong_t allres = 0, master = 0;
	unsigned flags = 0;
	char *p;
	int npat, ncol, i, j;
	char **patstr;
	char *name;
	nis_result *tres, *eres;
	char tname[NIS_MAXNAMELEN];
	struct pl_data pld;
	int re_flags = REG_EXTENDED|REG_NOSUB;

	/*
	 * By default, don't print binary data to ttys.
	 */
	pld.flags = (isatty(1))?0:PL_BINARY;

	pld.ta_sep = '\0';
	while ((c = getopt(argc, argv, "AMchivos:")) != -1) {
		switch (c) {
		case 'A':
			allres = ALL_RESULTS;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'c':
			pld.flags |= PL_COUNT;
			break;
		case 'i':
			pld.flags |= PL_NOCASE;
			break;
		case 'h':
			flags |= F_HEADER;
			break;
		case 'v' :
			pld.flags &= ~PL_BINARY;
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

	if ((npat = argc - optind - 1) < 1)
		usage();
	if ((patstr = (char **)malloc(npat * sizeof (char *))) == 0) {
		fprintf(stderr, "No memory!\n");
		exit(EXIT_ERROR);
	}
	for (i = 0; i < npat; i++) {
		if (pld.flags & PL_NOCASE)
			patstr[i] = strlower(argv[optind++]);
		else
			patstr[i] = argv[optind++];
	}
	name = argv[optind++];

	/*
	 * Get the table object using expand name magic.
	 */
	tres = nis_lookup(name, master|FOLLOW_LINKS|EXPAND_NAME);
	if (tres->status != NIS_SUCCESS) {
		nis_perror(tres->status, name);
		exit(EXIT_ERROR);
	}

	/*
	 * Construct the name for the table that we found.
	 */
	sprintf(tname, "%s.", tres->objects.objects_val[0].zo_name);
	if (*(tres->objects.objects_val[0].zo_domain) != '.')
		strcat(tname, tres->objects.objects_val[0].zo_domain);

	/*
	 * Make sure it's a table object.
	 */
	if (tres->objects.objects_val[0].zo_data.zo_type != NIS_TABLE_OBJ) {
		fprintf(stderr, "%s is not a table!\n", tname);
		exit(EXIT_ERROR);
	}

	/*
	 * Compile the regular expressions.
	 */
	ncol = TABLE_COLS(tres).ta_cols_len;

	if ((pld.re_dfa = (regex_t *)malloc(ncol * sizeof (regex_t))) == 0) {
		fprintf(stderr, "No memory!\n");
		exit(EXIT_ERROR);
	}
	memset(pld.re_dfa, 0, ncol * sizeof (regex_t));

	if ((pld.dfa_set = (int *)malloc(ncol * sizeof (int))) == 0) {
		fprintf(stderr, "No memory!\n");
		exit(EXIT_ERROR);
	}
	memset(pld.dfa_set, 0, ncol * sizeof (int));

	/* XXX  pat could contain '=' */
	if ((npat == 1) && (nisname_index(patstr[0], '=') == 0)) {
		if ((st = regcomp(&pld.re_dfa[0], patstr[0], re_flags)) != 0) {
			re_error(patstr[0], st, &pld.re_dfa[0]);
			exit(EXIT_ERROR);
		}
		pld.dfa_set[0] = 1;
	} else {
		for (i = 0; i < npat; i++) {
			if ((p = nisname_index(patstr[i], '=')) == 0)
				usage();
			*(p++) = 0;
			for (j = 0; j < ncol; j++)
				if (TABLE_COLS(tres).ta_cols_val[j].tc_name &&
				    (strcmp(
					TABLE_COLS(tres).ta_cols_val[j].tc_name,
					patstr[i]) == 0))
					break;
			if (j == ncol) {
				fprintf(stderr, "column not found: %s\n",
					patstr[i]);
				exit(EXIT_ERROR);
			}
			if ((st = regcomp(&pld.re_dfa[j], p, re_flags)) != 0) {
				re_error(p, st, &pld.re_dfa[j]);
				exit(EXIT_ERROR);
			}
			pld.dfa_set[j] = 1;
		}
	}

	/*
	 * Use the table's separator character when printing entries.
	 * Unless one was specified w/ -s
	 */
	if (pld.ta_sep == '\0') {
		pld.ta_sep = tres->objects.objects_val[0].TA_data.ta_sep;
	}

	/*
	 * Print column names
	 */
	if ((flags & F_HEADER) && !(pld.flags & (PL_COUNT|PL_OBJECT))) {
		ncol = TABLE_COLS(tres).ta_cols_len;
		c = pld.ta_sep;
		printf("# ");
		for (i = 0; i < ncol; i++) {
			if (i > 0)
				printf("%c", c);
			printf("%s",
			    TABLE_COLS(tres).ta_cols_val[i].tc_name);
		}
		printf("\n");
	}

	/*
	 * Cat matching entries from the table using a callback function.
	 */
	pld.nmatch = 0;
	eres = nis_list(tname, allres|master, print_line, (void *)&(pld));
	if (eres->status != NIS_CBRESULTS &&
	    eres->status != NIS_NOTFOUND) {
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
