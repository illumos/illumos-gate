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
#include "stabs.h"

void forth_do_sou(struct tdesc *tdp, struct node *np);
void forth_do_enum(struct tdesc *tdp, struct node *np);
void forth_do_intrinsic(struct tdesc *tdp, struct node *np);

static void switch_on_type(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);

static void print_intrinsic(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_forward(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_pointer(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_array(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_function(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_union(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_enum(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_forward(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_typeof(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_struct(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);
static void print_volatile(struct mlist *mlp, struct tdesc *tdp,
    char *format, int level);

void
forth_do_intrinsic(struct tdesc *tdp, struct node *np)
{
}

void
forth_do_sou(struct tdesc *tdp, struct node *np)
{
	struct mlist *mlp;
	struct child *chp;
	char *format;

	printf("\n");
	printf("vocabulary %s-words\n", np->name);
	printf("h# %x constant %s-sz\n", tdp->size, np->name);
	printf("%x ' %s-words c-struct .%s\n",
		tdp->size, np->name, np->name);
	printf("also %s-words definitions\n\n", np->name);

	/*
	 * Run thru all the fields of a struct and print them out
	 */
	for (mlp = tdp->data.members.back; mlp != NULL; mlp = mlp->prev) {
		/*
		 * If there's a child list, only print those members.
		 */
		if (np->child) {
			if (mlp->name == NULL)
				continue;
			chp = find_child(np, mlp->name);
			if (chp == NULL)
				continue;
			format = chp->format;
		} else
			format = NULL;
		if (mlp->fdesc == NULL)
			continue;
		switch_on_type(mlp, mlp->fdesc, format, 0);
	}
	printf("\nkdbg-words definitions\n");
	printf("previous\n\n");
	printf("\\ end %s section\n\n", np->name);
}

void
forth_do_enum(struct tdesc *tdp, struct node *np)
{
	int nelem = 0;
	struct elist *elp;

	printf("\n");
	for (elp = tdp->data.emem; elp != NULL; elp = elp->next) {
		printf("here ,\" %s\" %x\n", elp->name, elp->number);
		nelem++;
	}
	printf("%x c-enum .%s\n", nelem, np->name);
}

static void
switch_on_type(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	switch (tdp->type) {
	case INTRINSIC:
		print_intrinsic(mlp, tdp, format, level);
		break;
	case POINTER:
		print_pointer(mlp, tdp, format, level);
		break;
	case ARRAY:
		print_array(mlp, tdp, format, level);
		break;
	case FUNCTION:
		print_function(mlp, tdp, format, level);
		break;
	case UNION:
		print_union(mlp, tdp, format, level);
		break;
	case ENUM:
		print_enum(mlp, tdp, format, level);
		break;
	case FORWARD:
		print_forward(mlp, tdp, format, level);
		break;
	case TYPEOF:
		print_typeof(mlp, tdp, format, level);
		break;
	case STRUCT:
		print_struct(mlp, tdp, format, level);
		break;
	case VOLATILE:
		print_volatile(mlp, tdp, format, level);
		break;
	default:
		fprintf(stderr, "Switch to Unknown type\n");
		error = B_TRUE;
		break;
	}
}

static void
print_forward(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	fprintf(stderr, "%s never defined\n", mlp->name);
	error = B_TRUE;
}

static void
print_typeof(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	switch_on_type(mlp, tdp->data.tdesc, format, level);
}

static void
print_volatile(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	switch_on_type(mlp, tdp->data.tdesc, format, level);
}

static void
print_intrinsic(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	format = convert_format(format, ".x");

	if (level != 0) {
		switch (tdp->size) {
		case 1:
			printf("' c@ ' %s", format);
			break;
		case 2:
			printf("' w@ ' %s", format);
			break;
		case 4:
			printf("' l@ ' %s", format);
			break;
		case 8:
			printf("' x@ ' %s", format);
			break;
		}
	/*
	 * Check for bit field.
	 */
	} else if (mlp->size != 0 &&
	    ((mlp->size % 8) != 0 || (mlp->offset % mlp->size) != 0)) {
		int offset, shift, mask;

		offset = (mlp->offset / 32) * 4;
		shift = 32 - ((mlp->offset % 32) + mlp->size);
		mask = ((int)pow(2, mlp->size) - 1) << shift;
		printf("' %s %x %x %x bits-field %s\n",
			format, shift, mask, offset, mlp->name);
	} else if (mlp->name != NULL) {
		switch (tdp->size) {
		case 1:
			printf("' %s %x byte-field %s\n",
				format, mlp->offset / 8, mlp->name);
			break;
		case 2:
			printf("' %s %x short-field %s\n",
				format, mlp->offset / 8, mlp->name);
			break;
		case 4:
			printf("' %s %x long-field %s\n",
				format, mlp->offset / 8, mlp->name);
			break;
		case 8:
			printf("' %s %x ext-field %s\n",
				format, mlp->offset / 8, mlp->name);
			break;
		}
	}
}

static void
print_pointer(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	format = convert_format(format, ".x");
	if (level != 0) {
		switch (tdp->size) {
		case 1:
			printf("' c@ ' %s", format);
			break;
		case 2:
			printf("' w@ ' %s", format);
			break;
		case 4:
			printf("' l@ ' %s", format);
			break;
		case 8:
			printf("' x@ ' %s", format);
			break;
		}
	} else {
		printf("' %s %x ptr-field %s\n",
		    format, mlp->offset / 8, mlp->name);
	}
}

static void
print_array(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	struct ardef *ap = tdp->data.ardef;
	int items, inc, limit;

	if (level > 0) {
		printf("' noop ' .x");
	} else {
		items = ap->indices->range_end - ap->indices->range_start + 1;
		inc = (mlp->size / items) / 8;
		limit = mlp->size / 8;
		switch_on_type(mlp, ap->contents, format, level + 1);
		printf(" %x %x %x array-field", limit, inc, mlp->offset / 8);
		printf(" %s\n", mlp->name);
	}
}

static void
print_function(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	fprintf(stderr, "function in struct %s\n", tdp->name);
	error = B_TRUE;
}

static void
print_struct(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	format = convert_format(format, ".x");
	if (level != 0)
		printf("' noop ' %s", format);
	else {
		printf("' %s %x struct-field %s\n",
			format, mlp->offset / 8, mlp->name);
	}
}

static void
print_union(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	format = convert_format(format, ".x");
	if (level != 0)
		printf("' noop ' %s", format);
	else {
		printf("' %s %x struct-field %s\n",
			format, mlp->offset / 8, mlp->name);
	}
}

static void
print_enum(struct mlist *mlp, struct tdesc *tdp, char *format, int level)
{
	format = convert_format(format, ".d");

	if (level != 0)
		printf("' l@ ' %s", format);
	else
		printf("' %s %x long-field %s\n",
			format, mlp->offset / 8, mlp->name);
}
