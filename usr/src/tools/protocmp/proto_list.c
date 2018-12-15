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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>

#include "list.h"
#include "proto_list.h"

#define	FS	" \t\n"

static void
error(const char *msg, int lc)
{
	(void) fprintf(stderr, "warning: line %d - %s\n", lc, msg);
}

/*
 * int is_num()
 *
 * returns 1 if the string is entirely numeric - if not it returns 0
 *
 */
static int
is_num(const char *str)
{
	int i;
	int len = strlen(str);

	if (len < 1)
		return (0);

	for (i = 0; i < len; i++)
		if (!isdigit(str[i]))
			return (0);
	return (1);
}

/*
 * void check_line()
 *
 * try and do some sanity/syntax checking against the line just
 * read in - print warning messages as errors are encountered.
 *
 * these are simple checks, but then they catch the simple errors-:)
 *
 */
static void
check_line(char *v[], int lc)
{
	if ((!v[NAME]) || ((int)strlen(v[NAME]) < 1))
		error("bad name", lc);

	if ((!v[SRC]) || ((int)strlen(v[SRC])) < 1)
		error("bad source/symbolic line", lc);

	if ((!v[PERM]) || ((int)strlen(v[PERM]) < 3) || (!is_num(v[PERM])))
		error("bad permissions", lc);

	if ((!v[OWNR]) || ((int)strlen(v[OWNR]) < 2))
		error("bad owner", lc);

	if ((!v[GRP]) || ((int)strlen(v[GRP]) < 2))
		error("bad group", lc);

	if ((!v[INO]) || (!is_num(v[INO])))
		error("bad i-node", lc);

	if ((!v[LCNT]) || (!is_num(v[LCNT])))
		error("bad link-count", lc);

	if ((!v[CODE]) || ((*v[CODE] != 'f') && (*v[CODE] != 'c') &&
	    (*v[CODE] != 'd') && (*v[CODE] != 'b') &&
	    (*v[CODE] != 'v') && (*v[CODE] != 'e') &&
	    (*v[CODE] != 's')) || ((int)strlen(v[CODE]) > 1))
		error("bad type", lc);

	if ((!v[MAJOR]) || ((!is_num(v[MAJOR])) && (*v[MAJOR] != '-')))
		error("bad major number", lc);

	if ((!v[MINOR]) || ((!is_num(v[MINOR])) && (*v[MINOR] != '-')))
		error("bad minor number", lc);
}

static char **
get_line(FILE *fp, char *v[])
{
	char	*rc;
	char	*p;
	int	len;
	int	cont = 1;
	static char	buf[BUFSIZ];
	static int	line_count = 0;

	p = buf;
	p[0] = '\0';

	do {
		rc = fgets(p, BUFSIZ, fp);
		line_count ++;
		/*
		 * check for continuation marks at the end of the
		 * line - if it exists then append the next line at the
		 * end of this one.
		 */
		if (buf[0] == '#') {
			/*
			 * skip comments.
			 */
			continue;
		} else if ((rc != NULL) && ((len = strlen(p)) > 1) &&
		    (p[len - 2] == '\\')) {
			/*
			 * check for continuation marks at the end of the
			 * line - if it exists then append the next line at the
			 * end of this one.
			 */
			p += len - 2;
		} else
			cont = 0;
	} while (cont);

	if (rc == NULL)
		return (NULL);

	/*
	 * breakup the line into the various fields.
	 */
	v[PROTOS] = index(buf, ';');
	if (v[PROTOS])
		*v[PROTOS]++ = '\0';
	v[0]  = strtok(buf, FS);
	for (cont = 1; cont < FIELDS - 1; cont++)
		v[cont] = strtok(NULL, FS);

	check_line(v, line_count);

	return (v);
}

static void
parse_line(char **v, elem *e)
{
	e->flag = 0;
	e->pkgs = NULL;
	e->arch = P_ISA;
	(void) strcpy(e->name, v[NAME]);
	e->perm = strtol(v[PERM], NULL, 8);
	(void) strcpy(e->owner, v[OWNR]);
	(void) strcpy(e->group, v[GRP]);
	e->inode = atoi(v[INO]);
	e->ref_cnt = atoi(v[LCNT]);
	e->file_type = *v[CODE];
	if ((v[MAJOR][0] == '-') && (v[MAJOR][1] == '\0'))
		e->major = -1;
	else
		e->major = atoi(v[MAJOR]);

	if ((v[MINOR][0] == '-') && (v[MINOR][1] == '\0'))
		e->minor = -1;
	else
		e->minor = atoi(v[MINOR]);

	if ((v[SYM][0] == '-') && (v[SYM][1] == '\0'))
		e->symsrc = NULL;
	else {
		e->symsrc = malloc(strlen(v[SYM]) + 1);
		(void) strcpy(e->symsrc, v[SYM]);
		if (e->file_type != SYM_LINK_T)
#if defined(__sparc)
			if (strncmp(e->symsrc, "sun4/", 5) == 0)
				e->arch = P_SUN4;
			else if (strncmp(e->symsrc, "sun4c/", 6) == 0)
				e->arch = P_SUN4c;
			else if (strncmp(e->symsrc, "sun4u/", 6) == 0)
				e->arch = P_SUN4u;
			else if (strncmp(e->symsrc, "sun4d/", 6) == 0)
				e->arch = P_SUN4d;
			else if (strncmp(e->symsrc, "sun4e/", 6) == 0)
				e->arch = P_SUN4e;
			else if (strncmp(e->symsrc, "sun4m/", 6) == 0)
				e->arch = P_SUN4m;
			else if (strncmp(e->symsrc, "sun4v/", 6) == 0)
				e->arch = P_SUN4v;
#elif defined(__i386)
			if (strncmp(e->symsrc, "i86pc/", 6) == 0)
				e->arch = P_I86PC;
#elif defined(__ppc)
			if (strncmp(e->symsrc, "prep/", 5) == 0)
				e->arch = P_PREP;
#else
#error "Unknown instruction set"
#endif
			else {
				(void) fprintf(stderr,
				    "warning: Unknown relocation architecture "
				    "for %s\n", e->symsrc);
			}

	}
}

int
read_in_protolist(const char *pname, elem_list *list, int verbose)
{
	FILE	*proto_fp;
	char	*line_vec[FIELDS];
	int	count = 0;
	static elem	*e = NULL;

	list->type = PROTOLIST_LIST;

	if ((proto_fp = fopen(pname, "r")) == NULL) {
		perror(pname);
		exit(1);
	}

	if (verbose)
		(void) printf("reading in proto_list(%s)...\n", pname);

	count = 0;
	while (get_line(proto_fp, line_vec)) {
		if (!e)
			e = (elem *)calloc(1, sizeof (elem));

		parse_line(line_vec, e);
		if (!find_elem(list, e, FOLLOW_LINK)) {
			add_elem(list, e);
			e = NULL;
			count++;
		}
	}

	if (verbose)
		(void) printf("read in %d lines\n", count);

	(void) fclose(proto_fp);

	return (count);
}
