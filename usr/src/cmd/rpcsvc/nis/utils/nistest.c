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
 * nistest.c
 *
 * nis+ object test utility
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

extern int 	optind;
extern char	*optarg;


#define	EXIT_TRUE 0
#define	EXIT_FALSE 1
#define	EXIT_ERROR 2

#define	CMP_LT 0
#define	CMP_LE 1
#define	CMP_EQ 2
#define	CMP_HT 3
#define	CMP_HE 4
#define	CMP_NE 5
#define	CMP_NS 6

struct cmp_key {
	char *key;
	int value;
};

struct cmp_key cmp[] = {
	"<",	CMP_LT,
	"lt",	CMP_LT,
	"<=",	CMP_LE,
	"le",	CMP_LE,
	"=",	CMP_EQ,
	"eq",	CMP_EQ,
	">",	CMP_HT,
	"ht",	CMP_HT,
	"gt",	CMP_HT,
	">=",	CMP_HE,
	"he",	CMP_HE,
	"ge",	CMP_HE,
	"!=",	CMP_NE,
	"ne",	CMP_NE,
	"ns",	CMP_NS,
	NULL, 	0,
};

void
usage()
{
	fprintf(stderr,
	    "usage: nistest [-LPAM] [-t G|D|L|T|E|P] [-a mode] name\n");
	fprintf(stderr,
	    "       nistest -c [dir op dir]\n");
	exit(EXIT_ERROR);
}

#define	TEST_TYPE 1
#define	TEST_ACCESS 2
#define	TEST_CMP 3

unsigned int flags = 0;
zotypes	otype;
ulong_t oaccess;
int dotest_called = 0;

static
void
cmp_list()
{
	struct cmp_key *p;

	printf("Op\tMeaning\n");
	printf("----\t-------\n");
	for (p = cmp; p->key; p++) {
		printf("%s\t", p->key);
		switch (p->value) {
		    case CMP_LT:
			printf("lower than");
			break;
		    case CMP_LE:
			printf("lower than or equal");
			break;
		    case CMP_EQ:
			printf("equal");
			break;
		    case CMP_HT:
			printf("higher than");
			break;
		    case CMP_HE:
			printf("higher than or equal");
			break;
		    case CMP_NE:
			printf("not equal");
			break;
		    case CMP_NS:
			printf("not sequential");
			break;
		}
		printf("\n");
	}
}

static
int
cmp_test(char *d1, char *op, char *d2)
{
	int ret;
	enum name_pos st;
	struct cmp_key *p;

	for (p = cmp; p->key; p++) {
		if (strcasecmp(p->key, op) == 0)
			break;
	}
	if (p->key == NULL) {
		fprintf(stderr, "nistest:  bad op\n");
		return (EXIT_ERROR);
	}

	st = nis_dir_cmp(d1, d2);
	if (st == BAD_NAME) {
		fprintf(stderr, "nistest: bad name\n");
		return (EXIT_ERROR);
	}

	switch (p->value) {
	    case CMP_LT:
		ret = (st == LOWER_NAME);
		break;
	    case CMP_LE:
		ret = (st == LOWER_NAME || st == SAME_NAME);
		break;
	    case CMP_EQ:
		ret = (st == SAME_NAME);
		break;
	    case CMP_HT:
		ret = (st == HIGHER_NAME);
		break;
	    case CMP_HE:
		ret = (st == HIGHER_NAME || st == SAME_NAME);
		break;
	    case CMP_NE:
		ret = !(st == SAME_NAME);
		break;
	    case CMP_NS:
		ret = (st == NOT_SEQUENTIAL);
		break;
	}

	if (ret)
		return (EXIT_TRUE);
	return (EXIT_FALSE);
}

int
dotest(tab, obj, udata)
	char		*tab;
	nis_object	*obj;
	void		*udata;
{
	if ((flags & TEST_TYPE) &&
	    (obj->zo_data.zo_type != otype))
		exit(EXIT_FALSE);

	if ((flags & TEST_ACCESS) &&
	    ((obj->zo_access & oaccess) != oaccess))
		exit(EXIT_FALSE);

	dotest_called = 1;
	return (0); /* Indicates we want any additional objects */
}


int
main(int argc, char *argv[])
{
	int c;
	ulong_t flinks = 0, fpath = 0, allres = 0, master = 0;
	char *name;
	nis_result *ores;

	while ((c = getopt(argc, argv, "LPAMt:a:c")) != -1)
		switch (c) {
		case 'L':
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
		case 't':
			flags |= TEST_TYPE;
			switch (*optarg) {
				case 'G':
					otype = NIS_GROUP_OBJ;
					break;
				case 'D':
					otype = NIS_DIRECTORY_OBJ;
					break;
				case 'T':
					otype = NIS_TABLE_OBJ;
					break;
				case 'L':
					otype = NIS_LINK_OBJ;
					break;
				case 'E':
					otype = NIS_ENTRY_OBJ;
					break;
				case 'P':
					otype = NIS_PRIVATE_OBJ;
					break;
				default:
					usage();
					break;
			}
			break;
		case 'a':
			flags |= TEST_ACCESS;
			oaccess = 0;
			if (!parse_rights(&oaccess, optarg))
				usage();
			break;
		case 'c':
			if (flags == TEST_CMP) {
				fprintf(stderr, "%s: %s\n",
				    "nistest",
				    "-c can only be specified once");
				exit(EXIT_ERROR);
			} else if (flags != 0) {
				fprintf(stderr, "%s: %s\n",
				    "nistest",
				    "-c cannot be combined with other tests");
				exit(EXIT_ERROR);
			}
			flags = TEST_CMP;
			break;
		default:
			usage();
		}

	if (flags == TEST_CMP) {
		switch (argc - optind) {
		    case 0:
			cmp_list();
			exit(EXIT_TRUE);
			break;
		    case 3:
			exit(cmp_test(argv[optind],
				argv[optind+1], argv[optind+2]));
			break;
		    default:
			usage();
			break;
		}
	}

	if (argc - optind != 1)
		usage();

	name = argv[optind];

	/*
	 * Get the object using expand name magic, and test it.
	 */
	if (*name == '[') {
		ores = nis_list(name,
		    fpath|allres|master|FOLLOW_LINKS|EXPAND_NAME, dotest, 0);
		if (ores->status != NIS_CBRESULTS)
			exit(EXIT_FALSE);
	} else {
		ores = nis_lookup(name, flinks|master|EXPAND_NAME);
		if (ores->status != NIS_SUCCESS)
			exit(EXIT_FALSE);
		dotest(0, ores->objects.objects_val, 0);
	}

	if (dotest_called)
		exit(EXIT_TRUE);

	return (EXIT_FALSE);
}
