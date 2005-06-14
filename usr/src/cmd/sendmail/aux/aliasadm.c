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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nisplus.h"

#define	DEFAULT_ALIAS_MAP "mail_aliases.org_dir"

static FILE *fp = NULL;
static char *domain, *alias_map;
static char *match_arg;

static struct nis_mailias alias = {NULL, NULL, NULL, NULL};

typedef enum t_mode {
	AA_NONE,
	AA_ADD,
	AA_CHANGE,
	AA_DELETE,
	AA_EDIT,
	AA_MATCH,
	AA_LIST,
	AA_INIT
} t_mode;

static t_mode mode;

static void argparse();
static void usage();

int
main(argc, argv)
	int argc;
	char **argv;
{
	nis_result *res;

	print_comments = TRUE;

	alias_map = DEFAULT_ALIAS_MAP;

	if ((domain = nis_local_directory()) == NULL) {
		fprintf(stderr, "Can't get current domain\n");
		exit(-1);
	}

	argparse(argc, argv);

	switch (mode) {
	case AA_ADD:
		nis_mailias_add(alias, alias_map, domain);
		break;
	case AA_CHANGE:
		nis_mailias_change(alias, alias_map, domain);
		break;
	case AA_DELETE:
		nis_mailias_delete(alias, alias_map, domain);
		break;
	case AA_MATCH:
		res = nis_mailias_match(match_arg,
					alias_map, domain, ALIAS_COL);
		if (res->status == SUCCESS) {
			int i;
			for (i = 0; i < res->objects.objects_len; i++)
				mailias_print(fp? fp: stdout,
					(&res->objects.objects_val[0])+i);
		}
		break;
	case AA_LIST:
		nis_mailias_list(fp? fp: stdout, alias_map, domain);
		break;
	case AA_INIT:
		nis_mailias_init(alias_map, domain);
		break;
	case AA_EDIT:
		nis_mailias_edit(fp, alias_map, domain);
		break;
	case AA_NONE:
	default:
		usage(argv[0]);
		exit(-1);
		break;
	}
	return (0);
}

static void
argparse(argc, argv)
	int argc;
	char **argv;
{
	int c;
	int narg;
	int ind;

	mode = AA_NONE;

	while ((c = getopt(argc, argv, "D:M:f:a:c:d:m:leIn")) != EOF) {
		/*
		 * optind doesn't seem to be recognized as an extern int
		 * (which it is).  For now, cast it.
		 */
		ind = (int)optind;
		switch (c) {
		case 'a':
			mode = AA_ADD;
			narg = argc - ind + 1;
			if (narg < 2) {
				usage(argv[0]);
				fprintf(stderr, "Invalid argument\n");
				exit(-1);
			}
			alias.name = strdup(optarg);
			alias.expn = strdup(argv[ind]);
			if (narg >= 3 && *argv[ind + 1] != '-')
				alias.comments = strdup(argv[ind + 1]);
			if (narg >= 4 && *argv[ind + 1] != '-' &&
			    *argv[ind + 2] != '-') {
				alias.options = strdup(argv[ind + 2]);
			}
			break;
		case 'c':
			mode = AA_CHANGE;
			narg = argc - ind + 1;
			if (narg < 2) {
				usage(argv[0]);
				fprintf(stderr, "Invalid argument\n");
				exit(-1);
			}
			alias.name = optarg;
			alias.expn = strdup(argv[ind]);
			if (narg >= 3 && *argv[ind + 1] != '-')
				alias.comments = strdup(argv[ind + 1]);
			if (narg >= 4 && *argv[ind + 1] != '-' &&
			    *argv[ind + 2] != '-') {
				alias.options = strdup(argv[ind + 2]);
			}
			break;
		case 'D':
			domain = strdup(optarg);
			break;
		case 'd':
			mode = AA_DELETE;
			alias.name = strdup(optarg);
			break;
		case 'M':
			alias_map = strdup(optarg);
			break;
		case 'm':

			mode = AA_MATCH;
			match_arg = strdup(optarg);
			break;
		case 'n':
			print_comments = FALSE;
			break;
		case 'f':
			fp = fopen(optarg, "a+");
			if (fp == NULL) {
				fprintf(stderr, "%s:", optarg);
				perror("Can not open:");
				exit(-1);
			}
			break;
		case 'e':
			mode = AA_EDIT;
			break;
		case 'l':
			mode = AA_LIST;
			break;
		case 'I':
			mode = AA_INIT;
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

static void
usage(pname)
	char *pname;
{
	fprintf(stderr,
		"usage:\t%s -a alias expansion [comments] [options]\n", pname);
	fprintf(stderr, "\t%s -c alias expansion [comments] [options]\n",
		pname);
	fprintf(stderr, "\t%s -e\n", pname);
	fprintf(stderr, "\t%s -d alias\n", pname);
	fprintf(stderr, "\t%s -m alias\n", pname);
	fprintf(stderr, "\t%s -l\n", pname);
}
