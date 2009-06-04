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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Module:	zones_args.c
 * Group:	libinstzones
 * Description:	Private functions used by zones library functions to manipulate
 *		argument lists
 *
 * Public Methods:
 *
 * _z_add_arg - add new argument to argument array for use in exec() calls
 * _z_free_args - free all storage contained in an argument array previously
 * _z_get_argc - return (int) argc count from argument array
 * _z_get_argv - return (char **)argv pointer from argument array
 * _z_new_args - create a new argument array for use in exec() calls
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <stropts.h>
#include <libintl.h>
#include <locale.h>
#include <assert.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

/*
 * Library Function Prototypes
 */

/*
 * Local Function Prototypes
 */

/*
 * Global internal (private) declarations
 */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	_z_add_arg
 * Description:	add new argument to argument array for use in exec() calls
 * Arguments:	a_args - [RO, *RW] - (argArray_t *)
 *			Pointer to argument array (previously allocated via
 *			a call to _z_new_args) to add the argument to
 *		a_format - [RO, *RO] - (char *)
 *			Pointer to "printf(3C)" style format argument
 *		... - [RO, *RO] - (varies)
 *			Arguments as appropriate for format argument specified
 * Returns:	boolean_t
 *			B_TRUE - success
 *			B_FALSE - failure
 * Examples:
 * - to add an argument that specifies a file descriptor:
 *	int fd;
 *	_z_add_arg(aa, "/proc/self/fd/%d", fd);
 * - to add a flag or other known text:
 *	_z_add_arg(aa, "-s")
 * - to add random text:
 *	char *random_text;
 *	_z_add_arg(aa, "%s", random_text);
 */

/*PRINTFLIKE2*/
boolean_t
_z_add_arg(argArray_t *a_args, char *a_format, ...)
{
	char		*rstr = NULL;
	char		bfr[MAX_CANON];
	size_t		vres = 0;
	va_list		ap;

	/* entry assertions */

	assert(a_args != NULL);
	assert(a_format != NULL);
	assert(*a_format != '\0');

	/*
	 * double argument array if array is full
	 */

	if (a_args->_aaNumArgs >= a_args->_aaMaxArgs) {
		int	newMax;
		char	**newArgs;

		newMax = a_args->_aaMaxArgs * 2;
		newArgs = (char **)_z_realloc(a_args->_aaArgs,
		    (newMax+1) * sizeof (char *));
		a_args->_aaArgs = newArgs;
		a_args->_aaMaxArgs = newMax;
	}

	/*
	 * determine size of argument to add to list
	 */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, sizeof (bfr), a_format, ap);
	va_end(ap);

	/*
	 * use the expanded argument if it will fit in the built in buffer,
	 * otherwise, allocate space to hold the argument
	 */

	if (vres < sizeof (bfr)) {
		/* duplicate text already generated in buffer */
		rstr = _z_strdup(bfr);
	} else {
		/* allocate new space for argument to add */

		rstr = (char *)_z_malloc(vres+2);

		/* generate argument to add */

		va_start(ap, a_format);
		vres = vsnprintf(rstr, vres+1, a_format, ap);
		va_end(ap);
	}

	/* add argument to the end of the argument array */

	a_args->_aaArgs[a_args->_aaNumArgs++] = rstr;
	a_args->_aaArgs[a_args->_aaNumArgs] = NULL;

	/* successful - return */

	return (B_TRUE);
}

/*
 * Name:	_z_free_args
 * Description:	free all storage contained in an argument array previously
 *		allocated by a call to _z_new_args
 * Arguments:	a_args - [RO, *RW] - (argArray_t *)
 *			Pointer to argument array (previously allocated via
 *			a call to _z_new_args) to free
 * Returns:	void
 * NOTE:	preserves errno (usually called right after e_execCmd*())
 */

void
_z_free_args(argArray_t *a_args)
{
	int	i;
	int	lerrno = errno;

	/* entry assertions */

	assert(a_args != NULL);
	assert(a_args->_aaArgs != NULL);

	/* free all arguments in the argument array */

	for (i = (a_args->_aaNumArgs-1); i >= 0; i--) {
		assert(a_args->_aaArgs[i] != NULL);
		(void) free(a_args->_aaArgs[i]);
	}

	/* free argument array */

	(void) free(a_args->_aaArgs);

	/* free argument array structure */

	(void) free(a_args);

	/* restore errno */

	errno = lerrno;
}

/*
 * Name:	_z_get_argc
 * Description:	return (int) argc count from argument array
 * Arguments:	a_args - [RO, *RW] - (argArray_t *)
 *			Pointer to argument array (previously allocated via
 *			a call to _z_new_args) to return argc count for
 * Returns:	int
 *			Count of the number of arguments in the argument array
 *			suitable for use in an exec*() call
 */

int
_z_get_argc(argArray_t *a_args)
{
	return (a_args->_aaNumArgs);
}

/*
 * Name:	_z_get_argv
 * Description:	return (char **)argv pointer from argument array
 * Arguments:	a_args - [RO, *RW] - (argArray_t *)
 *			Pointer to argument array (previously allocated via
 *			a call to _z_new_args) to return argv pointer for
 * Returns:	char **
 *			Pointer to (char **)argv pointer suitable for use
 *			in an exec*() call
 * NOTE: the actual character array is always terminated with a NULL
 */

char **
_z_get_argv(argArray_t *a_args)
{
	return (a_args->_aaArgs);
}

/*
 * Name:	_z_new_args
 * Description:	create a new argument array for use in exec() calls
 * Arguments:	initialCount - [RO, *RO] - (int)
 *			Initial number of elements to populate the
 *			argument array with - use best guess
 * Returns:	argArray_t *
 *			Pointer to argument array that can be used in other
 *			functions that accept it as an argument
 *			== (argArray_t *)NULL - error
 * NOTE: you must call _z_free_args() when the returned argument array is
 * no longer needed so that all storage used can be freed up.
 */

argArray_t *
_z_new_args(int initialCount)
{
	argArray_t	*aa;

	/* entry assertions */

	assert(initialCount >= 0);

	/* if no guess on size, then assume 1 */

	if (initialCount == 0) {
		initialCount = 1;
	}

	/* allocate new argument array structure */

	aa = (argArray_t *)_z_calloc(sizeof (argArray_t));

	/* allocate initial argument array */

	aa->_aaArgs = (char **)_z_calloc((initialCount+1) * sizeof (char *));

	/* initialize argument indexes */

	aa->_aaNumArgs = 0;
	aa->_aaMaxArgs = initialCount;

	/* successful - return pointer to argument array created */

	return (aa);
}
