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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include "fb_random.h"

static var_t *var_find_dynamic(char *name);

/*
 * The filebench variables system has attribute value descriptors (avd_t)
 * where an avd contains a boolean, integer, double, string, random
 * distribution object ptr, boolean ptr, integer ptr, double ptr,
 * string ptr, or variable ptr. The system also has the variables
 * themselves, (var_t), which are named, typed entities which can be
 * allocated, selected and changed using the "set" command and used in
 * attribute assignments. The variables contain either a boolean, an
 * integer, a double, a string or pointer to an associated random
 * distribution object. Both avd_t and var_t entities are allocated
 * from interprocess shared memory space.
 *
 * The attribute descriptors implement delayed binding to variable values,
 * which is necessary because the values of variables may be changed
 * between the time the workload file is loaded and it is actually run,
 * either by further "set" commands in the file or from the command line
 * interface. For random variables, they actually point to the random
 * distribution object, allowing FileBench to invoke the appropriate
 * random distribution function on each access to the attribute. However,
 * for static attributes, the value is just loaded in the descriptor
 * directly, avoiding the need to allocate a variable to hold the static
 * value.
 *
 * The routines in this module are used to allocate, locate, and
 * manipulate the attribute descriptors, and vars. Routines are
 * also included to convert between the component strings, doubles
 * and integers of vars, and said components of avd_t.
 */

/*
 * returns a pointer to a string indicating the type of data contained
 * in the supplied attribute variable descriptor.
 */
static char *
avd_get_type_string(avd_t avd)
{
	switch (avd->avd_type) {
	case AVD_INVALID:
		return ("uninitialized");

	case AVD_VAL_BOOL:
		return ("boolean value");

	case AVD_VARVAL_BOOL:
		return ("points to boolean in var_t");

	case AVD_VAL_INT:
		return ("integer value");

	case AVD_VARVAL_INT:
		return ("points to integer in var_t");

	case AVD_VAL_STR:
		return ("string");

	case AVD_VARVAL_STR:
		return ("points to string in var_t");

	case AVD_VAL_DBL:
		return ("double float value");

	case AVD_VARVAL_DBL:
		return ("points to double float in var_t");

	case AVD_IND_VAR:
		return ("points to a var_t");

	case AVD_IND_RANDVAR:
		return ("points to var_t's random distribution object");

	default:
		return ("illegal avd type");
	}
}

/*
 * returns a pointer to a string indicating the type of data contained
 * in the supplied variable.
 */
static char *
var_get_type_string(var_t *ivp)
{
	switch (ivp->var_type & VAR_TYPE_SET_MASK) {
	case VAR_TYPE_BOOL_SET:
		return ("boolean");

	case VAR_TYPE_INT_SET:
		return ("integer");

	case VAR_TYPE_STR_SET:
		return ("string");

	case VAR_TYPE_DBL_SET:
		return ("double float");

	case VAR_TYPE_RAND_SET:
		return ("random");

	default:
		return ("empty");
	}
}

/*
 * Returns the fbint_t pointed to by the supplied avd_t "avd".
 */
fbint_t
avd_get_int(avd_t avd)
{
	var_t *ivp;
	randdist_t *rndp;

	if (avd == NULL)
		return (0);

	switch (avd->avd_type) {
	case AVD_VAL_INT:
		return (avd->avd_val.intval);

	case AVD_VARVAL_INT:
		if (avd->avd_val.intptr)
			return (*(avd->avd_val.intptr));
		else
			return (0);

	case AVD_IND_VAR:
		if ((ivp = avd->avd_val.varptr) == NULL)
			return (0);

		if (VAR_HAS_INTEGER(ivp))
			return (ivp->var_val.integer);

		if (VAR_HAS_RANDDIST(ivp)) {
			if ((rndp = ivp->var_val.randptr) != NULL)
				return ((fbint_t)rndp->rnd_get(rndp));
		}

		filebench_log(LOG_ERROR,
		    "Attempt to get integer from %s var $%s",
		    var_get_type_string(ivp), ivp->var_name);
		return (0);

	case AVD_IND_RANDVAR:
		if ((rndp = avd->avd_val.randptr) == NULL)
			return (0);
		else
			return ((fbint_t)rndp->rnd_get(rndp));

	default:
		filebench_log(LOG_ERROR,
		    "Attempt to get integer from %s avd",
		    avd_get_type_string(avd));
		return (0);
	}
}

/*
 * Returns the floating point value of a variable pointed to by the
 * supplied avd_t "avd". Intended to get the actual (double) value
 * supplied by the random variable.
 */
double
avd_get_dbl(avd_t avd)
{
	var_t *ivp;
	randdist_t *rndp;

	if (avd == NULL)
		return (0.0);

	switch (avd->avd_type) {
	case AVD_VAL_INT:
		return ((double)avd->avd_val.intval);

	case AVD_VAL_DBL:
		return (avd->avd_val.dblval);

	case AVD_VARVAL_INT:
		if (avd->avd_val.intptr)
			return ((double)(*(avd->avd_val.intptr)));
		else
			return (0.0);

	case AVD_VARVAL_DBL:
		if (avd->avd_val.dblptr)
			return (*(avd->avd_val.dblptr));
		else
			return (0.0);

	case AVD_IND_VAR:
		ivp = avd->avd_val.varptr;

		if (ivp && VAR_HAS_INTEGER(ivp))
			return ((double)ivp->var_val.integer);

		if (ivp && VAR_HAS_DOUBLE(ivp))
			return (ivp->var_val.dbl_flt);

		if (ivp && VAR_HAS_RANDDIST(ivp)) {
			if ((rndp = ivp->var_val.randptr) != NULL)
				return (rndp->rnd_get(rndp));
		}
		filebench_log(LOG_ERROR,
		    "Attempt to get double float from %s var $%s",
		    var_get_type_string(ivp), ivp->var_name);
		return (0.0);

	case AVD_IND_RANDVAR:
		if ((rndp = avd->avd_val.randptr) == NULL) {
			return (0.0);
		} else
			return (rndp->rnd_get(rndp));

	default:
		filebench_log(LOG_ERROR,
		    "Attempt to get floating point from %s avd",
		    avd_get_type_string(avd));
		return (0.0);
	}
}

/*
 * Returns the boolean pointed to by the supplied avd_t "avd".
 */
boolean_t
avd_get_bool(avd_t avd)
{
	var_t *ivp;

	if (avd == NULL)
		return (0);

	switch (avd->avd_type) {
	case AVD_VAL_BOOL:
		return (avd->avd_val.boolval);

	case AVD_VARVAL_BOOL:
		if (avd->avd_val.boolptr)
			return (*(avd->avd_val.boolptr));
		else
			return (FALSE);

	/* for backwards compatibility with old workloads */
	case AVD_VAL_INT:
		if (avd->avd_val.intval != 0)
			return (TRUE);
		else
			return (FALSE);

	case AVD_VARVAL_INT:
		if (avd->avd_val.intptr)
			if (*(avd->avd_val.intptr) != 0)
				return (TRUE);

		return (FALSE);

	case AVD_IND_VAR:
		if ((ivp = avd->avd_val.varptr) == NULL)
			return (0);

		if (VAR_HAS_BOOLEAN(ivp))
			return (ivp->var_val.boolean);

		if (VAR_HAS_INTEGER(ivp)) {
			if (ivp->var_val.boolean)
				return (TRUE);
			else
				return (FALSE);
		}

		filebench_log(LOG_ERROR,
		    "Attempt to get boolean from %s var $%s",
		    var_get_type_string(ivp), ivp->var_name);
		return (FALSE);

	default:
		filebench_log(LOG_ERROR,
		    "Attempt to get boolean from %s avd",
		    avd_get_type_string(avd));
		return (FALSE);
	}
}

/*
 * Returns the string pointed to by the supplied avd_t "avd".
 */
char *
avd_get_str(avd_t avd)
{
	var_t *ivp;

	if (avd == NULL)
		return (NULL);

	switch (avd->avd_type) {
	case AVD_VAL_STR:
		return (avd->avd_val.strval);

	case AVD_VARVAL_STR:
		if (avd->avd_val.strptr)
			return (*avd->avd_val.strptr);
		else
			return (NULL);

	case AVD_IND_VAR:
		ivp = avd->avd_val.varptr;

		if (ivp && VAR_HAS_STRING(ivp))
			return (ivp->var_val.string);

		filebench_log(LOG_ERROR,
		    "Attempt to get string from %s var $%s",
		    var_get_type_string(ivp), ivp->var_name);
		return (NULL);

	default:
		filebench_log(LOG_ERROR,
		    "Attempt to get string from %s avd",
		    avd_get_type_string(avd));
		return (NULL);
	}
}

/*
 * Allocates a avd_t from ipc memory space.
 * logs an error and returns NULL on failure.
 */
static avd_t
avd_alloc_cmn(void)
{
	avd_t rtn;

	if ((rtn = (avd_t)ipc_malloc(FILEBENCH_AVD)) == NULL)
		filebench_log(LOG_ERROR, "Avd alloc failed");

	return (rtn);
}

/*
 * pre-loads the allocated avd_t with the boolean_t "bool".
 * Returns the avd_t on success, NULL on failure.
 */
avd_t
avd_bool_alloc(boolean_t bool)
{
	avd_t avd;

	if ((avd = avd_alloc_cmn()) == NULL)
		return (NULL);

	avd->avd_type = AVD_VAL_BOOL;
	avd->avd_val.boolval = bool;

	filebench_log(LOG_DEBUG_IMPL, "Alloc boolean %d", bool);

	return (avd);
}

/*
 * pre-loads the allocated avd_t with the fbint_t "integer".
 * Returns the avd_t on success, NULL on failure.
 */
avd_t
avd_int_alloc(fbint_t integer)
{
	avd_t avd;

	if ((avd = avd_alloc_cmn()) == NULL)
		return (NULL);

	avd->avd_type = AVD_VAL_INT;
	avd->avd_val.intval = integer;

	filebench_log(LOG_DEBUG_IMPL, "Alloc integer %lld", integer);

	return (avd);
}

/*
 * Gets a avd_t and points it to the var that
 * it will eventually be filled from
 */
static avd_t
avd_alloc_var_ptr(var_t *var)
{
	avd_t avd;

	if (var == NULL)
		return (NULL);

	if ((avd = avd_alloc_cmn()) == NULL)
		return (NULL);

	switch (var->var_type & VAR_TYPE_SET_MASK) {
	case VAR_TYPE_BOOL_SET:
		avd->avd_type = AVD_VARVAL_BOOL;
		avd->avd_val.boolptr = (&var->var_val.boolean);
		break;

	case VAR_TYPE_INT_SET:
		avd->avd_type = AVD_VARVAL_INT;
		avd->avd_val.intptr = (&var->var_val.integer);
		break;

	case VAR_TYPE_STR_SET:
		avd->avd_type = AVD_VARVAL_STR;
		avd->avd_val.strptr = &(var->var_val.string);
		break;

	case VAR_TYPE_DBL_SET:
		avd->avd_type = AVD_VARVAL_DBL;
		avd->avd_val.dblptr = &(var->var_val.dbl_flt);
		break;

	case VAR_TYPE_RAND_SET:
		avd->avd_type = AVD_IND_RANDVAR;
		avd->avd_val.randptr = var->var_val.randptr;
		break;

	default:
		avd->avd_type = AVD_IND_VAR;
		avd->avd_val.varptr = var;
		break;
	}
	return (avd);
}

/*
 * Gets a avd_t, then allocates and initializes a piece of
 * shared string memory, putting the pointer to it into the just
 * allocated string pointer location. The routine returns a pointer
 * to the string pointer location or returns NULL on error.
 */
avd_t
avd_str_alloc(char *string)
{
	avd_t avd;

	if (string == NULL) {
		filebench_log(LOG_ERROR, "No string supplied\n");
		return (NULL);
	}

	if ((avd = avd_alloc_cmn()) == NULL)
		return (NULL);

	avd->avd_type = AVD_VAL_STR;
	avd->avd_val.strval = ipc_stralloc(string);

	filebench_log(LOG_DEBUG_IMPL,
	    "Alloc string %s ptr %zx",
	    string, avd);

	return (avd);
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
var_alloc_cmn(char *name, int var_type)
{
	var_t **var_listp;
	var_t *var = NULL;
	var_t *prev = NULL;
	var_t *newvar;

	if ((newvar = (var_t *)ipc_malloc(FILEBENCH_VARIABLE)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}
	(void) memset(newvar, 0, sizeof (newvar));
	newvar->var_type = var_type;

	if ((newvar->var_name = ipc_stralloc(name)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for variables");
		return (NULL);
	}

	switch (var_type & VAR_TYPE_MASK) {
	case VAR_TYPE_RANDOM:
	case VAR_TYPE_GLOBAL:
		var_listp = &filebench_shm->var_list;
		break;

	case VAR_TYPE_DYNAMIC:
		var_listp = &filebench_shm->var_dyn_list;
		break;

	default:
		var_listp = &filebench_shm->var_list;
		break;
	}

	/* add to the end of list */
	for (var = *var_listp; var != NULL; var = var->var_next)
		prev = var; /* Find end of list */
	if (prev != NULL)
		prev->var_next = newvar;
	else
		*var_listp = newvar;

	return (newvar);
}

/*
 * Allocates a var (var_t) from interprocess shared memory and
 * places the allocated var on the end of the globally shared
 * var_list. If the allocation fails, returns NULL, otherwise
 * it returns a pointer to the newly allocated var.
 */
static var_t *
var_alloc(char *name)
{
	return (var_alloc_cmn(name, VAR_TYPE_GLOBAL));
}

/*
 * Allocates a var (var_t) from interprocess shared memory.
 * Places the allocated var on the end of the globally shared
 * var_dyn_list. If the allocation fails, returns NULL, otherwise
 * it returns a pointer to the newly allocated var.
 */
static var_t *
var_alloc_dynamic(char *name)
{
	return (var_alloc_cmn(name, VAR_TYPE_DYNAMIC));
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
 * var_val.boolean's value to that of the supplied boolean.
 * If not found, the routine allocates a new var and sets
 * its var_val.boolean's value to that of the supplied
 * boolean. If the named var cannot be found or allocated
 * the routine returns -1, otherwise it returns 0.
 */
int
var_assign_boolean(char *name, boolean_t bool)
{
	var_t *var;

	if (name == NULL) {
		filebench_log(LOG_ERROR,
		    "var_assign_boolean: Name not supplied");
		return (0);
	}

	name += 1;

	if ((var = var_find(name)) == NULL) {
			var = var_alloc(name);
	}

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((var->var_type & VAR_TYPE_MASK) == VAR_TYPE_RANDOM) {
		filebench_log(LOG_ERROR,
		    "Cannot assign integer to random variable %s", name);
		return (-1);
	}

	VAR_SET_BOOL(var, bool);

	filebench_log(LOG_DEBUG_SCRIPT, "Assign boolean %s=%d",
	    name, bool);

	return (0);
}

/*
 * Searches for the named var, and, if found, sets its
 * var_integer's value to that of the supplied integer.
 * If not found, the routine allocates a new var and sets
 * its var_integers's value to that of the supplied
 * integer. If the named var cannot be found or allocated
 * the routine returns -1, otherwise it returns 0.
 */
int
var_assign_integer(char *name, fbint_t integer)
{
	var_t *var;

	if (name == NULL) {
		filebench_log(LOG_ERROR,
		    "var_assign_integer: Name not supplied");
		return (0);
	}

	name += 1;

	if ((var = var_find(name)) == NULL) {
			var = var_alloc(name);
	}

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((var->var_type & VAR_TYPE_MASK) == VAR_TYPE_RANDOM) {
		filebench_log(LOG_ERROR,
		    "Cannot assign integer to random variable %s", name);
		return (-1);
	}

	VAR_SET_INT(var, integer);

	filebench_log(LOG_DEBUG_SCRIPT, "Assign integer %s=%lld",
	    name, integer);

	return (0);
}

/*
 * Find a variable, and set it to random type.
 * If it does not have a random extension, allocate one
 */
var_t *
var_find_randvar(char *name)
{
	var_t *newvar;

	name += 1;

	if ((newvar = var_find(name)) == NULL) {
		filebench_log(LOG_ERROR,
		    "failed to locate random variable $%s\n", name);
		return (NULL);
	}

	/* set randdist pointer unless it is already set */
	if (((newvar->var_type & VAR_TYPE_MASK) != VAR_TYPE_RANDOM) ||
	    !VAR_HAS_RANDDIST(newvar)) {
		filebench_log(LOG_ERROR,
		    "Found variable $%s not random\n", name);
		return (NULL);
	}

	return (newvar);
}

/*
 * Allocate a variable, and set it to random type. Then
 * allocate a random extension.
 */
var_t *
var_define_randvar(char *name)
{
	var_t *newvar;
	randdist_t *rndp = NULL;

	name += 1;

	/* make sure variable doesn't already exist */
	if (var_find(name) != NULL) {
		filebench_log(LOG_ERROR,
		    "variable name already in use\n");
		return (NULL);
	}

	/* allocate a random variable */
	if ((newvar = var_alloc_cmn(name, VAR_TYPE_RANDOM)) == NULL) {
		filebench_log(LOG_ERROR,
		    "failed to alloc random variable\n");
		return (NULL);
	}

	/* set randdist pointer */
	if ((rndp = randdist_alloc()) == NULL) {
		filebench_log(LOG_ERROR,
		    "failed to alloc random distribution object\n");
		return (NULL);
	}

	rndp->rnd_var = newvar;
	VAR_SET_RAND(newvar, rndp);

	return (newvar);
}

/*
 * Searches for the named var, and if found returns an avd_t
 * pointing to the var's var_integer, var_string or var_double
 * as appropriate. If not found, attempts to allocate
 * a var named "name" and returns an avd_t to it with
 * no value set. If the var cannot be found or allocated, an
 * error is logged and the run is terminated.
 */
avd_t
var_ref_attr(char *name)
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

	/* allocate pointer to var and return */
	return (avd_alloc_var_ptr(var));
}


/*
 * Searches for the named var, and if found copies the var_val.string,
 * if it exists, a decimal number string representation of
 * var_val.integer, the state of var_val.boolean, or the type of random
 * distribution employed, into a malloc'd bit of memory using fb_stralloc().
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

	if ((var->var_type & VAR_TYPE_MASK) == VAR_TYPE_RANDOM) {
		switch (var->var_val.randptr->rnd_type & RAND_TYPE_MASK) {
		case RAND_TYPE_UNIFORM:
			return (fb_stralloc("uniform random var"));
		case RAND_TYPE_GAMMA:
			return (fb_stralloc("gamma random var"));
		case RAND_TYPE_TABLE:
			return (fb_stralloc("tabular random var"));
		default:
			return (fb_stralloc("unitialized random var"));
		}
	}

	if (VAR_HAS_STRING(var) && var->var_val.string)
		return (fb_stralloc(var->var_val.string));

	if (VAR_HAS_BOOLEAN(var)) {
		if (var->var_val.boolean)
			return (fb_stralloc("true"));
		else
			return (fb_stralloc("false"));
	}

	if (VAR_HAS_INTEGER(var)) {
		(void) snprintf(tmp, sizeof (tmp), "%lld",
		    var->var_val.integer);
		return (fb_stralloc(tmp));
	}

	return (fb_stralloc("No default"));
}

/*
 * Searches for the named var, and if found returns the value,
 * of var_val.boolean. If the var is not found, or a boolean
 * value has not been set, logs an error and returns 0.
 */
boolean_t
var_to_boolean(char *name)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if ((var != NULL) && VAR_HAS_BOOLEAN(var))
		return (var->var_val.boolean);

	filebench_log(LOG_ERROR,
	    "Variable %s referenced before set", name);

	return (0);
}

/*
 * Searches for the named var, and if found returns the value,
 * of var_val.integer. If the var is not found, or the an
 * integer value has not been set, logs an error and returns 0.
 */
fbint_t
var_to_integer(char *name)
{
	var_t *var;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_find_dynamic(name);

	if ((var != NULL) && VAR_HAS_INTEGER(var))
		return (var->var_val.integer);

	filebench_log(LOG_ERROR,
	    "Variable %s referenced before set", name);

	return (0);
}

/*
 * Searches for the named random var, and if found, converts the
 * requested parameter into a string or a decimal number string
 * representation, into a malloc'd bit of memory using fb_stralloc().
 * Returns a pointer to the created string, or calls var_to_string()
 * if a random variable isn't found.
 */
char *
var_randvar_to_string(char *name, int param_name)
{
	var_t *var;
	fbint_t value;

	if ((var = var_find(name + 1)) == NULL)
		return (var_to_string(name));

	if (((var->var_type & VAR_TYPE_MASK) != VAR_TYPE_RANDOM) ||
	    !VAR_HAS_RANDDIST(var))
		return (var_to_string(name));

	switch (param_name) {
	case RAND_PARAM_TYPE:
		switch (var->var_val.randptr->rnd_type & RAND_TYPE_MASK) {
		case RAND_TYPE_UNIFORM:
			return (fb_stralloc("uniform"));
		case RAND_TYPE_GAMMA:
			return (fb_stralloc("gamma"));
		case RAND_TYPE_TABLE:
			return (fb_stralloc("tabular"));
		default:
			return (fb_stralloc("uninitialized"));
		}

	case RAND_PARAM_SRC:
		if (var->var_val.randptr->rnd_type & RAND_SRC_GENERATOR)
			return (fb_stralloc("rand48"));
		else
			return (fb_stralloc("urandom"));

	case RAND_PARAM_SEED:
		value = avd_get_int(var->var_val.randptr->rnd_seed);
		break;

	case RAND_PARAM_MIN:
		value = avd_get_int(var->var_val.randptr->rnd_min);
		break;

	case RAND_PARAM_MEAN:
		value = avd_get_int(var->var_val.randptr->rnd_mean);
		break;

	case RAND_PARAM_GAMMA:
		value = avd_get_int(var->var_val.randptr->rnd_gamma);
		break;

	case RAND_PARAM_ROUND:
		value = avd_get_int(var->var_val.randptr->rnd_round);
		break;

	default:
		return (NULL);

	}

	/* just an integer value if we got here */
	{
		char tmp[128];

		(void) snprintf(tmp, sizeof (tmp), "%lld", value);
		return (fb_stralloc(tmp));
	}
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
var_assign_var(char *name, char *src_name)
{
	var_t *dst_var, *src_var;

	name += 1;
	src_name += 1;

	if ((src_var = var_find(src_name)) == NULL) {
		filebench_log(LOG_ERROR,
		    "Cannot find source variable %s", src_name);
		return (-1);
	}

	if ((dst_var = var_find(name)) == NULL)
		dst_var = var_alloc(name);

	if (dst_var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((dst_var->var_type & VAR_TYPE_MASK) == VAR_TYPE_RANDOM) {
		filebench_log(LOG_ERROR,
		    "Cannot assign var to Random variable %s", name);
		return (-1);
	}

	if (VAR_HAS_BOOLEAN(src_var)) {
		VAR_SET_BOOL(dst_var, src_var->var_val.boolean);
		filebench_log(LOG_VERBOSE,
		    "Assign var %s=%d", name, src_var->var_val.boolean);
	}

	if (VAR_HAS_INTEGER(src_var)) {
		VAR_SET_INT(dst_var, src_var->var_val.integer);
		filebench_log(LOG_VERBOSE,
		    "Assign var %s=%lld", name, src_var->var_val.integer);
	}

	if (VAR_HAS_DOUBLE(src_var)) {
		VAR_SET_DBL(dst_var, src_var->var_val.dbl_flt);
		filebench_log(LOG_VERBOSE,
		    "Assign var %s=%lf", name, src_var->var_val.dbl_flt);
	}

	if (VAR_HAS_STRING(src_var)) {
		char *strptr;

		if ((strptr =
		    ipc_stralloc(src_var->var_val.string)) == NULL) {
			filebench_log(LOG_ERROR,
			    "Cannot assign variable %s",
			    name);
			return (-1);
		}
		VAR_SET_STR(dst_var, strptr);
		filebench_log(LOG_VERBOSE,
		    "Assign var %s=%s", name, src_var->var_val.string);
	}
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
	char *strptr;

	name += 1;

	if ((var = var_find(name)) == NULL)
		var = var_alloc(name);

	if (var == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}

	if ((var->var_type & VAR_TYPE_MASK) == VAR_TYPE_RANDOM) {
		filebench_log(LOG_ERROR,
		    "Cannot assign string to random variable %s", name);
		return (-1);
	}

	if ((strptr = ipc_stralloc(string)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot assign variable %s",
		    name);
		return (-1);
	}
	VAR_SET_STR(var, strptr);

	filebench_log(LOG_DEBUG_SCRIPT,
	    "Var assign string $%s=%s", name, string);

	return (0);
}

/*
 * Tests to see if the supplied variable name without the portion after
 * the last period is that of a random variable. If it is, it returns
 * the number of characters to backspace to skip the period and field
 * name. Otherwise it returns 0.
 */
int
var_is_set4_randvar(char *name)
{
	var_t *var;
	char varname[128];
	int namelength;
	char *sp;

	(void) strncpy(varname, name, 128);
	namelength = strlen(varname);
	sp = varname + namelength;

	while (sp != varname) {
		int c = *sp;

		*sp = 0;
		if (c == '.')
			break;

		sp--;
	}

	/* not a variable name + field? */
	if (sp == varname)
		return (0);

	/* first part not a variable name? */
	if ((var = var_find(varname+1)) == NULL)
		return (0);

	/* Make sure it is a random variable */
	if ((var->var_type & VAR_TYPE_MASK) != VAR_TYPE_RANDOM)
		return (0);

	/* calculate offset from end of random variable name */
	return (namelength - (sp - varname));
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
 * If found, the value string is returned in var->var_val.string.
 * If the requested value is not found, NULL is returned.
 */
static var_t *
var_find_environment(var_t *var)
{
	char *n = fb_stralloc(var->var_name);
	char *name = n;
	char *strptr;

	name++;
	if (name[strlen(name) - 1] != ')') {
		free(n);
		return (NULL);
	}
	name[strlen(name) - 1] = 0;

	if ((strptr = getenv(name)) != NULL) {
		free(n);
		VAR_SET_STR(var, strptr);
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
