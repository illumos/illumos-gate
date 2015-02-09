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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 PALO, Richard
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "exception_list.h"
#include "arch.h"

/*
 * This is global so that the protodir reading functions can rely on the
 * exception list to weed out innocuous problems in the IHV gate.
 */
elem_list exception_list;

#define	FS	" \t\n"

static int
parse_exception_line(char *line, elem_list *list)
{
	char	*name, *arch;
	elem	*e;

	if ((name = strtok(line, FS)) == NULL) {
		/* don't complain; this is only a blank line */
		return (0);
	}

	if ((arch = strtok(NULL, FS)) == NULL) {
		arch = "all";
	}

	e = (elem *) malloc(sizeof (elem));
	if (e == NULL) {
		perror("malloc");
		exit(1);
	}

	e->inode = 0;
	e->perm = 0;
	e->ref_cnt = 0;
	e->flag = 0;
	e->major = 0;
	e->minor = 0;
	e->link_parent = NULL;
	e->link_sib = NULL;
	e->symsrc = NULL;
	e->file_type = DIR_T;

	while ((e->arch = assign_arch(arch)) == 0) {
		if ((arch = strtok(NULL, FS)) == NULL) {
			return (0);
		}
	}

	(void) strcpy(e->name, name);
	add_elem(list, e);

	return (1);
}

int
read_in_exceptions(const char *exception_file, int verbose)
{
	FILE	*except_fp;
	char	buf[BUFSIZ];
	int	count = 0;

	exception_file = exception_file ? exception_file : EXCEPTION_FILE;

	if (verbose) {
		(void) printf("reading in exceptions from %s...\n",
		    exception_file);
	}

	if ((except_fp = fopen(exception_file, "r")) == NULL) {
		perror(exception_file);
		return (0);
	}
	while (fgets(buf, BUFSIZ, except_fp)) {
		if (buf[0] != '#')	/* allow for comments */
			count += parse_exception_line(buf, &exception_list);
	}
	if (verbose)
		(void) printf("read in %d exceptions...\n", count);

	return (count);
}
