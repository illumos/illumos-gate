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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include "ypsym.h"

extern void free();
extern char *strdup();

/*
 * Add a name to the list
 */
static listofnames *
newname(str)
char *str;
{
	listofnames *it;
	char *copy;

	if (str == NULL)
		return (NULL);
	copy = strdup(str);
	if (copy == NULL)
		return (NULL);
	it = (listofnames *) malloc(sizeof (listofnames));
	if (it == NULL) {
		free(copy);
		return (NULL);
	}
	it->name = copy;
	it->nextname = NULL;
	return (it);
}

/*
 * Assemble the list of names
 */
listofnames *
names(filename)
char *filename;
{
	listofnames *nameslist;
	listofnames *end;
	listofnames *nname;
	FILE *fyle;
	char line[256];
	char name[256];

	fyle = fopen(filename, "r");
	if (fyle == NULL) {
		return (NULL);
	}
	nameslist = NULL;
	while (fgets(line, sizeof (line), fyle)) {
		if (line[0] == '#') continue;
		if (line[0] == '\0') continue;
		if (line[0] == '\n') continue;
		nname = newname(line);
		if (nname) {
			if (nameslist == NULL) {
					nameslist = nname;
					end = nname;
			} else {
				end->nextname = nname;
				end = nname;
			}
		} else
			fprintf(stderr,
		"file %s bad malloc %s\n", filename, name);
	}
	fclose(fyle);
	return (nameslist);
}

void
free_listofnames(locallist)
listofnames *locallist;
{
	listofnames *next = (listofnames *)NULL;

	for (; locallist; locallist = next) {
		next = locallist->nextname;
		if (locallist->name)
			free(locallist->name);
		free((char *)locallist);
	}
}


#ifdef MAIN
main(argc, argv)
char **argv;
{
	listofnames *list;
	list = names(argv[1]);
#ifdef DEBUG
	print_listofnames(list);
#endif
	free_listofnames(list);
#ifdef DEBUG
	printf("Done\n");
#endif
}
#endif

#ifdef DEBUG
void
print_listofnames(list)
listofnames *list;
{
	if (list == NULL)
		printf("NULL\n");
	for (; list; list = list->nextname)
		printf("%s\n", list->name);
}
#endif
