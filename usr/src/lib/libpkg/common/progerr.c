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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "pkglocale.h"

static char	*ProgName = NULL; 	/* Set via set_prog_name() */


static void
error_and_exit(int error_num)
{
	(void) fprintf(stderr, "%d\n", error_num);
	exit(99);
}

static void	(*fatal_err_func)() = &error_and_exit;

char *
set_prog_name(char *name)
{
	if (name == NULL)
		return (NULL);
	if ((name = strdup(name)) == NULL) {
		(void) fprintf(stderr,
		    "set_prog_name(): strdup(name) failed.\n");
		exit(1);
	}
	ProgName = strrchr(name, '/');
	if (!ProgName++)
		ProgName = name;

	return (ProgName);
}

char *
get_prog_name(void)
{
	return (ProgName);
}


/*PRINTFLIKE1*/
void
progerr(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (ProgName && *ProgName)
		(void) fprintf(stderr, pkg_gt("%s: ERROR: "), ProgName);
	else
		(void) fprintf(stderr, pkg_gt(" ERROR: "));

	(void) vfprintf(stderr, fmt, ap);

	va_end(ap);

	(void) fprintf(stderr, "\n");
}

/*
 * set_memalloc_failure_func()
 *	Allows an appliation to specify the function to be called when
 *	a memory allocation function fails.
 * Parameters:
 *	(*alloc_proc)(int)	- specifies the function to call if fatal error
 *			  (such as being unable to allocate memory) occurs.
 * Return:
 *	none
 * Status:
 *	Public
 */
void
set_memalloc_failure_func(void (*alloc_proc)(int))
{
	if (alloc_proc != (void (*)())NULL)
		fatal_err_func = alloc_proc;
}

/*
 * xmalloc()
 * 	Alloc 'size' bytes from heap using malloc()
 * Parameters:
 *	size	- number of bytes to malloc
 * Return:
 *	NULL	- malloc() failure
 *	void *	- pointer to allocated structure
 * Status:
 *	public
 */
void *
xmalloc(size_t size)
{
	void *tmp;

	if ((tmp = (void *) malloc(size)) == NULL) {
		fatal_err_func(errno);
		return (NULL);
	} else
		return (tmp);
}

/*
 * xrealloc()
 *	Calls realloc() with the specfied parameters. xrealloc()
 *	checks for realloc failures and adjusts the return value
 *	automatically.
 * Parameters:
 *	ptr	- pointer to existing data block
 * 	size	- number of bytes additional
 * Return:
 *	NULL	- realloc() failed
 *	void *	- pointer to realloc'd structured
 * Status:
 *	public
 */
void *
xrealloc(void *ptr, size_t size)
{
	void *tmp;

	if ((tmp = (void *)realloc(ptr, size)) == (void *)NULL) {
		fatal_err_func(errno);
		return ((void *)NULL);
	} else
		return (tmp);
}

/*
 * xstrdup()
 *	Allocate space for the string from the heap, copy 'str' into it,
 *	and return a pointer to it.
 * Parameters:
 *	str	- string to duplicate
 * Return:
 *	NULL	- duplication failed or 'str' was NULL
 * 	char *	- pointer to newly allocated/initialized structure
 * Status:
 *	public
 */
char *
xstrdup(char *str)
{
	char *tmp;

	if (str == NULL)
		return ((char *)NULL);

	if ((tmp = strdup(str)) == NULL) {
		fatal_err_func(errno);
		return ((char *)NULL);
	} else
		return (tmp);
}
