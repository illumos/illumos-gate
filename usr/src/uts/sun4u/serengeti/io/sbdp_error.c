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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/promif.h>
#include <sys/sbdp_error.h>
#include <sys/sbdp_priv.h>

/*
 * The purpose if this model is to make it easy to inject error at all
 * decision making points, such that all code paths can be tested, and
 * states arrived are expected and recoverable.
 *
 * Passthru command "inject-error" will be used for injecting
 * errors.  A typical error injection command will look like the
 * following:
 *
 * cfgadm -x passthru -o inject-error=func_name:entry_point:value N0.SB0
 *
 * where "func_name" is the name of the function where error will be
 * injected, "entry_point" is a number in the function to identify which
 * decision making point it is that we are injecting error, and "value"
 * is what we want the check to return.  The last field is ignored,
 * so it can be any valid attachment point.
 *
 * For example, if we want to inject error at the 3rd entry in function
 * sbdp_disconnect_cpu (we start counting at 0), we will issue the
 * following command:
 *
 * cfgadm -x passthru -o inject-error=sbdp_disconnect_cpu:3:-1 N0.SB0
 *
 * To clear the error, change the value to 0, or whatever success
 * corresponds to in the particular function.
 *
 * cfgadm -x passthru -o inject-error=sbdp_disconnect_cpu:3:0 N0.SB0
 *
 * Since this command is mainly for debugging, not all illegal options
 * are rejected.  Non-digit strings are accepted for entry point and
 * value.  They will be translated to 0.
 *
 * Another passthru command "reset-error" is used to clear all errors
 * that have been injected.  The only argument it needs is a valid
 * attachment point as the last field.
 *
 * NOTE: Once implemented, the error injection points should remain
 * relatively stable as QA will be using them for testing.
 */


/*
 * Variable that controls if error injection should be done or not
 */
#ifdef DEBUG
uint_t sbdp_do_inject = 1;

/*
 * Different error injection types that sbdp_ie_type can be
 */
#define	SBDP_IE_RANDOM	0	/* Returns randomly 0 or -1 */
#define	SBDP_IE_FAILURE	1	/* Returns -1 */
#define	SBDP_IE_DEFINED	2	/* Returns value from sbdp_error_matrix */

/*
 * Variable that controls what type of error injection to do
 */
int sbdp_ie_type = SBDP_IE_DEFINED;

/*
 * Basic return values from sbdp_inject_error
 */
#define	SUCCESS	0
#define	FAILURE	-1

/*
 * Maximum number of error injection entry points
 */
#define	SBDP_IE_MAX_ENTRIES		4

typedef struct error_matrix {
	const char	*func_name;
	uint_t		num_entries;
	int		entries[SBDP_IE_MAX_ENTRIES];
} error_matrix_t;

static error_matrix_t sbdp_error_matrix[] =  {
	{ "sbdp_disconnect_cpu",	3,	0, 0, 0, 0 },
	{ "sbdp_connect_cpu",		3,	0, 0, 0, 0 },
	{ "sbdp_cpu_poweron",		2,	0, 0, 0, 0 },
	{ "sbdp_cpu_poweroff",		4,	0, 0, 0, 0 },
	/* Termination entry, must exist */
	{ NULL,				0,	0, 0, 0, 0 },
};

static int sbdp_func_lookup(const char *func_name);

extern int sbdp_strtoi(char *p, char **pos);

/*
 * sbdp error injector.  The argument should be of the following format:
 *
 *	inject_error=func_str:entry_str:value_str
 *
 * Returns ESBD_INVAL if arg is not of the above format,
 * or if any of the fields are invalid.
 *
 * Returns ESBD_NOERROR after setting the correct entry in the error
 * matrix to the value passed in.
 */
int
sbdp_passthru_inject_error(sbdp_handle_t *hp, void *arg)
{
	_NOTE(ARGUNUSED(hp))

	char	*arg_str, *func_str, *entry_str, *value_str;
	int	index, value;
	size_t	len = strlen(arg) + 1;
	uint_t	entry;
	int	rv = ESBD_NOERROR;
	static char *f = "sbdp_passthru_inject_error";

	arg_str = kmem_alloc(len, KM_SLEEP);
	(void) strcpy(arg_str, arg);

	/*
	 * Find '=' in the argument.  Return ESBD_INVAL if '=' is
	 * not found.
	 */
	if ((func_str = strchr(arg_str, '=')) == NULL) {
		rv = ESBD_INVAL;
		goto out;
	}

	/*
	 * Now func_str points to '=' in arg_str.  Increment the pointer
	 * so it points to the begining of the function string.
	 * Find the first ':' in the argument.  Return ESBD_INVAL if
	 * not found.
	 */
	if ((entry_str = strchr(++func_str, ':')) == NULL) {
		rv = ESBD_INVAL;
		goto out;
	}

	/*
	 * Now entry_str points to the first ':' in arg_str.  Set it
	 * to '\0' to NULL terminate func_str.  Increment the
	 * pointer so it points to the begining of the entry string.
	 */
	*entry_str++ = '\0';

	/*
	 * Now entry_str points to the begining of the entry string.
	 * Find the next ':' in the argument.  Return ESBD_INVAL if
	 * ':' is not found.
	 */
	if ((value_str = strchr(entry_str, ':')) == NULL) {
		rv = ESBD_INVAL;
		goto out;
	}

	/*
	 * Now value_str points to the second ':' in arg_str.  Set it
	 * to '\0' to NULL terminate entry_str.  Increment the
	 * pointer so it points to the begining of the value string.
	 * The rest of the arg_str is taken as the value string.
	 */
	*value_str++ = '\0';

	/*
	 * Find this function in the matrix.  Return ESBD_INVAL if
	 * the function name is not found.
	 */
	if ((index = sbdp_func_lookup(func_str)) == -1) {
		rv = ESBD_INVAL;
		goto out;
	}

	/*
	 * To reduce the amount of code we have to write, we tolerate
	 * non-number input for entry point, and translate it to 0.
	 */
	entry = (uint_t)sbdp_strtoi(entry_str, NULL);

	if (entry >= sbdp_error_matrix[index].num_entries) {
		rv = ESBD_INVAL;
		goto out;
	}

	/*
	 * No checking for value.  Non-number string will be translated
	 * to 0.
	 */
	value = sbdp_strtoi(value_str, NULL);

	SBDP_DBG_ERR("%s: index = %d, entry = %d, value = %d\n",
	    f, index, entry, value);

	/*
	 * Set value at the right entry.
	 */
	sbdp_error_matrix[index].entries[entry] = value;

out:
	kmem_free(arg_str, len);
	return (rv);
}

/*
 * Reset all entries to 0.
 */
int
sbdp_passthru_reset_error(sbdp_handle_t *hp, void *arg)
{
	_NOTE(ARGUNUSED(hp))
	_NOTE(ARGUNUSED(arg))

	uint_t	i, j;

	for (i = 0; sbdp_error_matrix[i].func_name != NULL; i++)
		for (j = 0; j < SBDP_IE_MAX_ENTRIES; j++)
			sbdp_error_matrix[i].entries[j] = 0;

	return (ESBD_NOERROR);
}

int
sbdp_inject_error(const char *func_name, uint_t entry)
{
	extern clock_t ddi_get_lbolt(void);
	int	index;
	int	value;
	static char *f = "sbdp_inject_error";

	if (sbdp_do_inject == 0)
		return (SUCCESS);

	switch (sbdp_ie_type) {

	case SBDP_IE_RANDOM:
		/*
		 * Since we usually only need a binary type of return
		 * value, use lbolt to generate the psuedo random
		 * response.
		 */
		value = (-(int)(ddi_get_lbolt() % 2));
		break;

	case SBDP_IE_FAILURE:
		value = FAILURE;
		break;

	case SBDP_IE_DEFINED:
		/*
		 * Don't inject error if can't find the function.
		 */
		if ((index = sbdp_func_lookup(func_name)) == -1) {
			value = SUCCESS;
			break;
		}

		/*
		 * Don't inject error if can't find the entry.
		 */
		if (entry >= sbdp_error_matrix[index].num_entries) {
			value = SUCCESS;
			break;
		}

		value = sbdp_error_matrix[index].entries[entry];
		break;

	default:
		value = SUCCESS;
		break;
	}

	if (value != SUCCESS)
		SBDP_DBG_ERR("%s: function=%s entry=%d value=%d\n",
		    f, func_name, entry, value);

	return (value);
}

static int
sbdp_func_lookup(const char *func_name)
{
	int		i;
	const char	*name;

	/*
	 * Linear search for a match
	 */
	for (i = 0; (name = sbdp_error_matrix[i].func_name) != NULL; i++) {
		if (strcmp(name, func_name) == 0)
			return (i);
	}

	/*
	 * Function name not found in matrix
	 */
	return (-1);
}

#endif /* DEBUG */
