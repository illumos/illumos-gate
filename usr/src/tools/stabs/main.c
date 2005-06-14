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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include "stabs.h"

int debug_level = 0;
int line;

boolean_t error = B_FALSE;
char *program = NULL;

extern void forth_do_sou(struct tdesc *, struct node *);
extern void forth_do_enum(struct tdesc *, struct node *);
extern void forth_do_intrinsic(struct tdesc *, struct node *);
extern void genassym_do_sou(struct tdesc *, struct node *);
extern void genassym_do_enum(struct tdesc *, struct node *);
extern void genassym_do_intrinsic(struct tdesc *, struct node *);
extern void squander_do_sou(struct tdesc *, struct node *);
extern void squander_do_enum(struct tdesc *, struct node *);
extern void squander_do_intrinsic(struct tdesc *, struct node *);

struct model_info models[] = {
	{ "ilp32", 4, 1, 2, 4, 4 },
	{ "lp64",  8, 1, 2, 4, 8 },
	{ NULL, 0, 0, 0 }
};

struct stab_ops {
	char *type;
	void (*do_sou)(struct tdesc *, struct node *);
	void (*do_enum)(struct tdesc *, struct node *);
	void (*do_intrinsic)(struct tdesc *, struct node *);
} ops_table[] = {
	{ "forth",
	    forth_do_sou, forth_do_enum, forth_do_intrinsic },
	{ "genassym",
	    genassym_do_sou, genassym_do_enum, genassym_do_intrinsic },
	{ "squander",
	    squander_do_sou, squander_do_enum, squander_do_intrinsic },
	{ NULL, NULL, NULL }
};

static void get_dbgs(int argc, char **argv);
static void parse_dbg(FILE *sp);
static void printnode(struct node *np);
static struct tdesc *find_member(struct tdesc *tdp, char *name);
static char *namex(char *cp, char **w);
static void addchild(char *cp, struct node *np);
static struct node *getnode(char *cp);

struct stab_ops *ops;
struct model_info *model;

int
main(int argc, char **argv)
{
	char *output_type = NULL;
	char *model_name = NULL;
	int c;

	program = strrchr(argv[0], '/');
	if (program != NULL)
		program++;
	else
		program = argv[0];

	/* defaults */
	output_type = "forth";
	model_name = "ilp32";

	while (!error && ((c = getopt(argc, argv, "dt:m:")) != EOF)) {
		switch (c) {
		case 't':
			output_type = optarg;
			break;
		case 'm':
			model_name = optarg;
			break;
		case 'd':
			debug_level++;
			break;
		case '?':
		default:
			error = B_TRUE;
			break;
		}
	}

	if (!error) {
		/*
		 * Find ops for the specified output type
		 */
		for (ops = ops_table; ops->type != NULL; ops++) {
			if (strcmp(ops->type, output_type) == 0)
				break;
		}
		if (ops->type == NULL)
			error = B_TRUE;
	}

	if (!error) {
		/*
		 * Find model characteristics
		 */
		for (model = models; model->name != NULL; model++) {
			if (strcmp(model->name, model_name) == 0)
				break;
		}
		if (model->name == NULL)
			error = B_TRUE;
	}

	/* skip over previously processed arguments */
	argc -= optind;
	argv += optind;
	if (argc < 1)
		error = B_TRUE;

	if (error) {
		fprintf(stderr, "Usage: %s [-d] {-m datamodel} "
		    "{-t output_type} files\n", program);
		fprintf(stderr, "\tSupported data models:\n");
		for (model = models; model->name != NULL; model++)
			fprintf(stderr, "\t\t%s\n", model->name);
		fprintf(stderr, "\tSupported output types:\n");
		for (ops = ops_table; ops->type != NULL; ops++)
			fprintf(stderr, "\t\t%s\n", ops->type);
		return (1);
	}

	parse_input();

	get_dbgs(argc, argv);

	return (error ? 1 : 0);
}

/*
 * This routine will read the .dbg files and build a list of the structures
 * and fields that user is interested in. Any struct specified will get all
 * its fields included. If nested struct needs to be printed - then the
 * field name and name of struct type needs to be included in the next line.
 */
static void
get_dbgs(int argc, char **argv)
{
	FILE *fp;

	for (; argc != 0; argc--, argv++) {
		if ((fp = fopen(*argv, "r")) == NULL) {
			fprintf(stderr, "Cannot open %s\n", *argv);
			error = B_TRUE;
			return;
		}
		/* add all types in this file to our table */
		parse_dbg(fp);
	}
}

static char *
namex(char *cp, char **w)
{
	char *new, *orig, c;
	int len;

	if (*cp == '\0') {
		*w = NULL;
		return (cp);
	}

	for (c = *cp++; isspace(c); c = *cp++)
		;
	orig = --cp;
	c = *cp++;
	if (isalpha(c) || ispunct(c)) {
		for (c = *cp++; isalnum(c) || ispunct(c); c = *cp++)
			;
		len = cp - orig;
		new = (char *)malloc(len);
		while (orig < cp - 1)
			*new++ = *orig++;
		*new = '\0';
		*w = new - (len - 1);
	} else if (c != '\0') {
		fprintf(stderr, "line %d has bad character %c\n", line, c);
		error = B_TRUE;
	}

	return (cp);
}

/*
 * checks to see if this field in the struct was requested for by user
 * in the .dbg file.
 */
struct child *
find_child(struct node *np, char *w)
{
	struct child *chp;

	for (chp = np->child; chp != NULL; chp = chp->next) {
		if (strcmp(chp->name, w) == 0)
			return (chp);
	}
	return (NULL);
}

static struct tdesc *
find_member(struct tdesc *tdp, char *name)
{
	struct mlist *mlp;

	while (tdp->type == TYPEOF)
		tdp = tdp->data.tdesc;
	if (tdp->type != STRUCT && tdp->type != UNION)
		return (NULL);
	for (mlp = tdp->data.members.forw; mlp != NULL; mlp = mlp->next)
		if (strcmp(mlp->name, name) == 0)
			return (mlp->fdesc);
	return (NULL);
}

/*
 * add this field to our table of structs/fields that the user has
 * requested in the .dbg files
 */
static void
addchild(char *cp, struct node *np)
{
	struct child *chp;
	char *w;

	chp = malloc(sizeof (*chp));
	cp = namex(cp, &w);
	chp->name = w;
	cp = namex(cp, &w);
	if (w == NULL) {
		if (chp->name == NULL) {
			fprintf(stderr, "NULL child name\n");
			exit(1);
		}
		/* XXX - always convert to upper-case? */
		chp->format = uc(chp->name);
	} else {
		chp->format = w;
	}
	chp->next = np->child;
	np->child = chp;
}

/*
 * add this struct to our table of structs/fields that the user has
 * requested in the .dbg files
 */
static struct node *
getnode(char *cp)
{
	char *w;
	struct node *np;

	cp = namex(cp, &w);
	np = malloc(sizeof (*np));
	np->name = w;

	/*
	 * XXX - These positional parameters are a hack
	 * We have two right now for genassym.  The back-ends
	 * can use format and format2 any way they'd like.
	 */
	cp = namex(cp, &w);
	np->format = w;
	if (w != NULL) {
		w = NULL;
		cp = namex(cp, &w);
		np->format2 = w;
	} else {
		np->format2 = NULL;
	}
	np->child = NULL;
	return (np);
}

/*
 * Format for .dbg files should be
 * Ex:
 * seg
 *	as		s_as
 * if you wanted the contents of "s_as" (a pointer) to be printed in
 * the format of a "as"
 */
static void
parse_dbg(FILE *sp)
{
	char *cp;
	struct node *np;
	static char linebuf[MAXLINE];
	int copy_flag = 0;
	int ignore_flag = 0;
	size_t c;

	/* grab each line and add them to our table */
	for (line = 1; (cp = fgets(linebuf, MAXLINE, sp)) != NULL; line++) {
		if (*cp == '\n') {
			if (copy_flag)
				printf("\n");
			continue;
		}
		if (*cp == '\\') {
			if (cp[1] == '#')
				printf("%s", (cp + 1));
			continue;
		}
		if (strcmp(cp, "model_end\n") == 0) {
			if (ignore_flag)
				ignore_flag = 0;
			continue;
		}
		if (ignore_flag)
			continue;
		c = strlen("model_start ");
		if (strncmp(cp, "model_start ", c) == 0) {
			if (strncmp(cp + c, model->name, strlen(model->name))
			    == 0 && *(cp + c + strlen(model->name)) == '\n')
				/* model matches */;
			else
				ignore_flag = 1;
			continue;
		}
		if ((strcmp(cp, "verbatim_begin\n") == 0) ||
		    (strcmp(cp, "forth_start\n") == 0)) {
			copy_flag = 1;
			continue;
		}
		if ((strcmp(cp, "verbatim_end\n") == 0) ||
		    (strcmp(cp, "forth_end\n") == 0)) {
			copy_flag = 0;
			continue;
		}
		if (copy_flag) {
			printf("%s", cp);
			continue;
		}
		np = getnode(cp);
		for (line++;
		    ((cp = fgets(linebuf, MAXLINE, sp)) != NULL) &&
			 *cp != '\n'; line++) {
			/* members of struct, union or enum */
			addchild(cp, np);
		}
		printnode(np);
	}
}

static void
printnode(struct node *np)
{
	struct tdesc *tdp;

	tdp = lookupname(np->name);
	if (tdp == NULL) {
		char *member;
		struct tdesc *ptdp;

		if ((member = strchr(np->name, '.')) != NULL) {
			*member = '\0';
			ptdp = lookupname(np->name);
			if (ptdp != NULL)
				tdp = find_member(ptdp, member + 1);
			*member = '.';
		}
		if (tdp == NULL) {
			fprintf(stderr, "Can't find %s\n", np->name);
			error = B_TRUE;
			return;
		}
	}
again:
	switch (tdp->type) {
	case STRUCT:
	case UNION:
		ops->do_sou(tdp, np);
		break;
	case ENUM:
		ops->do_enum(tdp, np);
		break;
	case TYPEOF:
		tdp = tdp->data.tdesc;
		goto again;
	case INTRINSIC:
		ops->do_intrinsic(tdp, np);
		break;
	default:
		fprintf(stderr, "%s isn't aggregate\n", np->name);
		error = B_TRUE;
		break;
	}
}


char *
convert_format(char *format, char *dfault)
{
	static char dot[3] = ".";

	if (format == NULL)
		return (dfault);
	else if (strlen(format) == 1) {
		dot[1] = *format;
		return (dot);
	} else
		return (format);
}

char *
uc(const char *s)
{
	char *buf;
	int i;

	buf = strdup(s);
	for (i = 0; i < strlen(buf); i++)
		buf[i] = toupper(buf[i]);
	buf[i] = '\0';
	return (buf);
}
