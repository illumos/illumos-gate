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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "vars.h"
#include "misc.h"
#include "utils.h"
#include "stats.h"
#include "eventgen.h"
#include "filebench.h"

static var_t *var_find_dynamic(char *name);

/*
 * The filebench variables consist of var_integers (var_integer_t)
 * and var_strings (var_string_t), which are pointers to integers and
 * strings respectively, and vars (var_t), which are named, typed
 * entities which contain either an integer or a string and can be
 * placed on a linked list. All three of these objects are allocated
 * from interprocess shared memory space.
 *
 * The routines in this module are used to allocate, locate, and
 * manipulate the var_integers, var_strings, and vars. Routines are
 * also included to convert between the component strings and integers
 * of vars, and var_strings and var_integers.
 */

/*
 * Returns the int pointed to by the supplied var_integer_t "v".
 */
int
integer_isset(var_integer_t v)
{
	if (v == NULL)
		return (0);

	return (*v);
}

/*
 * Allocates a var_integer_t from ipc memory space and
 * pre-loads it with the vinteger_t "integer". Returns
 * the var_integer_t on success, NULL on failure.
 */
var_integer_t
integer_alloc(vinteger_t integer)
{
	var_integer_t rtn;

	if ((rtn = (vinteger_t *)ipc_malloc(FILEBENCH_INTEGER)) == NULL) {
		filebench_log(LOG_ERROR, "Alloc integer failed");
		return (NULL);
	}

	*rtn = integer;

	filebench_log(LOG_DEBUG_IMPL, "Alloc integer %lld", integer);

	return (rtn);
}

/*
 * Allocates a string pointer in interprocess shared memory,
 * then allocates and initializes a piece of shared string memory,
 * putting the pointer to it into the just allocated string
 * pointer location. The routine returns a pointer to the
 * string pointer location or returns NULL on error.
 */
var_string_t
string_alloc(char *string)
{
	char **rtn;

	if ((rtn = (char **)ipc_malloc(FILEBENCH_STRING)) == NULL) {
		filebench_log(LOG_ERROR, "Alloc string failed");
		return (NULL);
	}

	*rtn = ipc_stralloc(string);

	filebench_log(LOG_DEBUG_IMPL,
	    "Alloc string %s ptr %zx",
	    string, rtn);

	return (rtn);
}


/*
 * Allocates a var (var_t) from interprocess shared memory.
 * Places the allocated var on the end of the globally shared
 * var_list. Finally, the routine allocates a string containing
 * a copy of the supplied "name" string. If any allocations
 * fails, returns NULL, otherwise it returns a pointer to the
 * newly allocated var.
 */
static var_t *
var_alloc(char *name)
{
	var_t *var = NULL;
	var_t *prev = NULL;
	var_t *newvar;

	if ((newvar = (var_t *)ipc_malloc(FILEBENCH_VARIABLE)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}
	(void) memset(newvar, 0, sizeof (newvar));

	for (var = filebench_shm->var_list; var != NULL; var = var->var_next)
		prev = var; /* Find end of list */
	if (prev != NULL)
		prev->var_next = newvar;
	else
		filebench_shm->var_list = newvar;

	if ((newvar->var_name = ipc_stralloc(name)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}

	return (newvar);
}

/*
 * Allocates a var (var_t) from interprocess shared memory.
 * Places the allocated var on the end of the globally shared
 * var_dyn_list. Finally, the routine allocates a string
 * containing a copy of the supplied "name" string. If any
 * allocations fails, returns NULL, otherwise it returns a
 * pointer to the newly allocated var.
 */
static var_t *
var_alloc_dynamic(char *name)
{
	var_t *var = NULL;
	var_t *prev = NULL;
	var_t *newvar;

	if ((newvar = (var_t *)ipc_malloc(FILEBENCH_VARIABLE)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}
	(void) memset(newvar, 0, sizeof (newvar));

	for (var = filebench_shm->var_dyn_list; var != NULL;
	    var = var->var_next)
		prev = var; /* Find end of list */
	if (prev != NULL)
		prev->var_next = newvar;
	else
		filebench_shm->var_dyn_list = newvar;

	if ((newvar->var_name = ipc_stralloc(name)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}

	return (newvar);
}

/*
 * Searches for var_t with name "name" in the master var_list.
 * If successful, returns a pointer to the var_t, otherwise
 * returns NULL.
 */
static var_t *
var_find(char *name)
{
	var_t *var;

	for (var = filebench_shm->var_list; var != NULL; var = var->var_next) {
		if (strcmp(var->var_name, name) == 0)
			return (var);
	}

	return (NULL);
}

/*
 * Searches for the named var, and, if found, sets its
 * var_integer's value to that of the supplied integer.
 * If not found, the routine allocates a new var and sets
 * its var_integers's value to that of the supplied
 * integer. If the named var cannot be found or allocated
 * the routine returns -1,	otherwise it returns 0.
 */
int
var_assign_integer(char *name, vinteger_t integer)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	var->var_integer = integer;

	filebench_log(LOG_DEBUG_SCRIPT, "Assign integer %s=%lld",
	    name, integer);

	return (0);
}

/*
 * Searches for the named var, and if found returns a pointer
 * to the var's var_integer. If not found, attempts to allocate
 * a var named "name" and returns a  pointer to it's (zeroed)
 * var_integer. If the var cannot be found or allocated, an
 * error is logged and the run is terminated.
 */
vinteger_t *
var_ref_integer(char *name)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if (var == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Invalid variable $%s",
		    name);
		filebench_shutdown(1);
	}

	return (&var->var_integer);

}

/*
 * Searches for the named var, and if found copies the var_string,
 * if it exists, or a decimal number string representation of
 * var_integer, into a malloc'd bit of memory using fb_stralloc().
 * Returns a pointer to the created string, or NULL on failure.
 */
char *
var_to_string(char *name)
{
	var_t *var;
	char tmp[128];

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if (var == NULL)
		return (NULL);

	if (var->var_string)
		return (fb_stralloc(var->var_string));

	(void) snprintf(tmp, sizeof (tmp), "%lld", var->var_integer);

	return (fb_stralloc(tmp));
}

/*
 * Searches for the named var, and if found returns the value,
 * of var_integer. If the var is not found, or the var_integer's
 * value is 0, logs an error and returns 0.
 */
vinteger_t
var_to_integer(char *name)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if ((var != NULL) && (var->var_integer))
		return (var->var_integer);

	filebench_log(LOG_ERROR,
	    "Variable %s referenced before set", name);

	return (0);
}

/*
 * Searches for the var named "name", and if not found
 * allocates it. The then extracts the var_string from
 * the var named "string" and copies it into the var_string
 * of the var "name", after first allocating a piece of
 * interprocess shared string memory. If the var "name"
 * cannot be found or allocated, or the var "string" cannot
 * be found, the routine returns -1, otherwise it returns 0.
 */
int
var_assign_var(char *name, char *string)
{
	var_t *var;
	var_string_t str;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((str = var_ref_string(string)) == NULL)
		return (-1);

	if ((var->var_string = ipc_stralloc(*str)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}
	filebench_log(LOG_VERBOSE, "Assign string %s=%s", name, string);
	return (0);
}

/*
 * Like var_assign_integer, only this routine copies the
 * supplied "string" into the var named "name". If the var
 * named "name" cannot be found then it is first allocated
 * before the copy. Space for the string in the var comes
 * from interprocess shared memory. If the var "name"
 * cannot be found or allocated, or the memory for the
 * var_string copy of "string" cannot be allocated, the
 * routine returns -1, otherwise it returns 0.
 */
int
var_assign_string(char *name, char *string)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((var->var_string = ipc_stralloc(string)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	filebench_log(LOG_DEBUG_SCRIPT, "Assign string %s=%s", name, string);

	return (0);
}

/*
 * Searches for the named var, and if found returns a pointer
 * to the var's var_string. If not found, attempts to allocate
 * a var named "name" and returns a  pointer to it's (empty)
 * var_string. If the var cannot be found or allocated, an
 * error is logged and the run is terminated.
 */
char **
var_ref_string(char *name)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if (var == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot reference variable %s",
		    name);
		filebench_shutdown(1);
	}

	return (&var->var_string);
}

/*
 * Implements a simple path name like scheme for finding values
 * to place in certain specially named vars. The first part of
 * the name is interpreted as a category of either: stats,
 * eventgen, date, script, or host var. If a match is found,
 * the appropriate routine is called to fill in the requested
 * value in the provided var_t, and a pointer to the supplied
 * var_t is returned. If the requested value is not found, NULL
 * is returned.
 */
static var_t *
var_find_internal(var_t *var)
{
	char *n = fb_stralloc(var->var_name);
	char *name = n;
	var_t *rtn = NULL;

	name++;
	if (name[strlen(name) - 1] != '}')
		return (NULL);
	name[strlen(name) - 1] = 0;

	if (strncmp(name, STATS_VAR, strlen(STATS_VAR)) == 0)
		rtn = stats_findvar(var, name + strlen(STATS_VAR));

	if (strcmp(name, EVENTGEN_VAR) == 0)
		rtn = eventgen_ratevar(var);

	if (strcmp(name, DATE_VAR) == 0)
		rtn = date_var(var);

	if (strcmp(name, SCRIPT_VAR) == 0)
		rtn = script_var(var);

	if (strcmp(name, HOST_VAR) == 0)
		rtn = host_var(var);

	free(n);

	return (rtn);
}

/*
 * Calls the C library routine getenv() to obtain the value
 * for the environment variable specified by var->var_name.
 * If found, the value string is returned in var->var_string.
 * If the requested value is not found, NULL is returned.
 */
static var_t *
var_find_environment(var_t *var)
{
	char *n = fb_stralloc(var->var_name);
	char *name = n;

	name++;
	if (name[strlen(name) - 1] != ')')
		return (NULL);
	name[strlen(name) - 1] = 0;

	if ((var->var_string = getenv(name)) != NULL) {
		free(n);
		return (var);
	} else {
		free(n);
		return (NULL);
	}
}

/*
 * Look up special variables. The "name" argument is used to find
 * the desired special var and fill it with an appropriate string
 * value. Looks for an already allocated var of the same name on
 * the var_dyn_list. If not found a new dynamic var is allocated.
 * if the name begins with '{', it is an internal variable, and
 * var_find_internal() is called. If the name begins with '(' it
 * is an environment varable, and var_find_environment() is
 * called. On success, a pointer to the var_t is returned,
 * otherwise, NULL is returned.
 */
static var_t *
var_find_dynamic(char *name)
{
	var_t *var = NULL;
	var_t *v = filebench_shm->var_dyn_list;
	var_t *rtn;

	/*
	 * Lookup a reference to the var handle for this
	 * special var
	 */
	for (v = filebench_shm->var_dyn_list; v != NULL; v = v->var_next) {
		if (strcmp(v->var_name, name) == 0) {
			var = v;
			break;
		}
	}

	if (var == NULL)
		var = var_alloc_dynamic(name);

	/* Internal system control variable */
	if (*name == '{') {
		rtn = var_find_internal(var);
		if (rtn == NULL)
			filebench_log(LOG_ERROR,
			    "Cannot find internal variable %s",
			    var->var_name);
		return (rtn);
	}

	/* Lookup variable in environment */
	if (*name == '(') {
		rtn = var_find_environment(var);
		if (rtn == NULL)
			filebench_log(LOG_ERROR,
			    "Cannot find environment variable %s",
			    var->var_name);
		return (rtn);
	}

	return (NULL);
}
