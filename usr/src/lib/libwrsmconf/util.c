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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions to support the config file parser.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "util.h"

static void print_source_line(char *file_name, int line, int ch);
static void clean_exit(int code);
static int print_line(char *file_name, int line);

static char *file_name = NULL;
static int charNumber = 0, last_token_len = 0;

#define	print_error(args, fmt, type, line)		\
	va_start(args, fmt); 				\
	if (file_name == NULL) 				\
		(void) fprintf(stderr, "(%d): \t ", line); 	\
	else 						\
		(void) fprintf(stderr, "%s(%d): \t ", file_name, line); \
	(void) fprintf(stderr, "%s: ", type);		\
	(void) vfprintf(stderr, fmt, args);		\
	(void) fprintf(stderr, "\n");			\
	va_end(args); 					\
	if (file_name != NULL) 				\
		print_source_line(file_name, line, charNumber-last_token_len);

/*PRINTFLIKE1*/
void
Error(char *fmt, ...)
{
	va_list args;

	print_error(args, fmt, "Error", lineNumber);
	ErrorCount++;
}

static void
_Internal(char *sourcefile, int sourceline, char *fmt)
{

	(void) fprintf(stderr, "\n%s: \tInternal Compiler Error --\n\t\tFile:"
		"%s\n\t\tLine: %d;\n\t\tMessage: %s\n",
		file_name, sourcefile, sourceline, fmt);
	clean_exit(-1);
}

static void
print_source_line(char *file_name, int line, int ch)
{
	int i;

	if (print_line(file_name, line) == FAILURE)
		return;

	if (ch > 4) {
		for (i = 0; i < ch-4; ++i)
			(void) printf(" ");
		(void) printf("....^\n");
	} else {
		for (i = 0; i < ch; ++i)
			(void) printf(" ");
		(void) printf("^....\n");
	}
}

static int
print_line(char *file_name, int line)
{
	FILE *fp;
	char buf[BUFSIZ];
	int i;

	fp = fopen(file_name, "r");
	if (fp == NULL) {
		Error("Can't read source file `%s'\n", file_name);
		return (FAILURE);
	}
	for (i = 0; i < line; ++ i) {
		if (fgets(buf, BUFSIZ, fp) == NULL)
			return (FAILURE);
	}
	(void) printf("%s", buf);
	return (SUCCESS);
}

void *
my_malloc(unsigned size, char *file, int line)
{
	void * tmp;

	if (size == 0)
		_Internal(file, line, "Zero allocate error");
	tmp = malloc(size);
	if (tmp == NULL) {
		_Internal(file, line, "Out of memory");
		return (NULL);
	}
	return (tmp);
}

void *
my_calloc(unsigned n, unsigned size, char *file, int line)
{
	void * tmp;

	if ((size*n) == 0)
		_Internal(file, line, "Zero allocate error");
	tmp = calloc(n, size);
	if (tmp == NULL) {
		_Internal(file, line, "Out of memory");
		return (NULL);
	}
	return (tmp);
}

void *
my_realloc(void *ptr, unsigned size, char *file, int line)
{
	void *tmp;

	if (size == 0)
		_Internal(file, line, "Zero allocate error");

	if (ptr)
		tmp = realloc(ptr, size);
	else
		tmp = malloc(size);

	if (tmp == NULL) {
		_Internal(file, line, "Out of memory");
		return (NULL);
	}
	return (tmp);
}


static void
clean_exit(int code)
{
	exit(code);
}
