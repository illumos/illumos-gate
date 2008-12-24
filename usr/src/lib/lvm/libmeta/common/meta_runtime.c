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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Return the values of runtime parameters stored in
 * /etc/lvm/runtime.cf, converting them to data
 * types appropriate for use by functions whose behavior
 * is affected by those values.
 */

/*
 * system include files
 */

#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/*
 * SUNWmd include files
 */

#include <meta.h>		/* for MDD_DOMAIN */
#include <meta_runtime.h>	/* external interface definition */
#include <sdssc.h>

/*
 * The following lines define the runtime parameter configuration file.
 */

static const char *param_file_namep = "/etc/lvm/runtime.cf";

/*
 * The runtime parameter configuration file is an ascii text file.
 * Each text line in the file has a maximum length of 80 four-byte
 * wide characters.  The line buffer size defined below accomodates
 * the maximum line length plus the newline character at the end of
 * the line and the null character that fgets() adds at the end of
 * the line when it writes the line to the buffer.
 */

static const int line_buffer_size = 325;

/*
 * The format for parameter entries in the file is "name=value".
 * Each "name=value" string must begin a line of the file.
 * The "name" and "value" tokens may be preceded or followed by
 * spaces.  Lines beginning with "#" are comment lines.
 */

static const char *token_separator_listp = " =";

/*
 * If a runtime parameter that can be set in the file is not set,
 * or is set to an invalid value, or if the file can't be opened,
 * the parameter takes on the default value given in the comments
 * below.
 */

/*
 * The following string constant declarations name the runtime
 * configuration parameters that can be set in the runtime parameter
 * configuration file.  The allowed values of parameters that
 * range over small sets of discrete values are also declared below
 * as string constants.
 *
 * CAUTION: When adding new runtime parameters to the runtime
 *          parameter configuration file, declare their names
 *          as string constants below, and check for conflicts
 *          with the names of existing parameters.
 */

static const char *ownerioctls_namep = "ownerioctls";

/*
 * allowed values:
 */

static const char *ownerioctls_onp = "on"; /* default value */
static const char *ownerioctls_offp = "off";

/*
 * The "ownerioctls" parameter controls whether the metaset -t and
 * metaset -r commands issue the MHIOCTKOWN, MHIOCRELEASE, and
 * MHIOCENFAILFAST ioctls when taking or releasing ownership of disksets.
 * The allowed parameter values are "on" and "off".
 *
 * If the line "ownerioctls=off" appears in the runtime configuration file,
 * the metaset -t command doesn't issue the MHIOCTKOWN ioctl when taking
 * ownership of disksets, and the metaset -r command doesn't issue the
 * MHIOCRELEASE and MHIOCENFAILFAST ioctls when releasing ownership of
 * disksets.
 *
 * If the line "ownerioctls=on" appears in the file, the metaset -t
 * command issues the MHIOCTKOWN ioctl when taking ownership of disksets,
 * and the metaset -r command issues the MHIOCRELEASE AND MHIOCENFAILFAST
 * icotls when releasing ownership of disksets.
 *
 * The default value of "ownerioctls" is "on".
 */

/*
 * The following lines make forward declarations of private functions.
 */

static
char *
meta_get_rt_param(const char *param_namep, boolean_t warn_if_not_found);

/*
 * The following lines define public functions.
 */

boolean_t
do_owner_ioctls(void)
{
	const char	*function_namep = "do_owner_ioctls()";
	char		*param_valuep;
	boolean_t	return_value = B_TRUE; /* default behavior */
	sdssc_version_t	version;

	if ((sdssc_version(&version) == SDSSC_OKAY) && (version.major >= 3)) {
		/*
		 * If we're bound to a cluster machine never do ioctls.
		 * The SC3.0 cluster code will always deal with disk
		 * reservation.
		 */

		return_value = B_FALSE;
	} else {
		param_valuep = meta_get_rt_param(ownerioctls_namep, B_TRUE);
		if (param_valuep != NULL) {
			if (strcmp(param_valuep, ownerioctls_offp) == 0) {
				return_value = B_FALSE;
			} else if (strcmp(param_valuep,
			    ownerioctls_onp) != 0) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: illegal value for %s: %s.\n"),
				    function_namep, ownerioctls_namep,
				    param_valuep);
				syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "%s: illegal value for %s: %s.\n"),
				    function_namep,
				    ownerioctls_namep,
				    param_valuep);
			}
			free(param_valuep);
		}
	}
	return (return_value);
}

/*
 * Retrieve the verbosity level for rpc.mdcommd from the config file.
 * If none is specified, don't print a warning and return 0
 */
uint_t
commd_get_verbosity(void)
{
	char		*param_valuep;
	uint_t retval	= 0;
	param_valuep = meta_get_rt_param("commd_verbosity", B_FALSE);
	if (param_valuep != NULL) {
		retval = (uint_t)strtol(param_valuep, NULL, 16);
		free(param_valuep);
	}
	return (retval);
}

/*
 * Retrieve the debug output file for rpc.mdcommd from the config file.
 * If none is specified, don't print a warning.
 * Note that if returning non-NULL, the caller is responsible for freeing
 * the result pointer.
 */
char *
commd_get_outfile(void)
{
	return (meta_get_rt_param("commd_out_file", B_FALSE));
}

/*
 * This controls what type of RPC errors are sent to syslog().
 * It is used as a bitmask against the clnt_stat list, which defines
 * 0 as RPC_SUCCESS, so likely shouldn't be set.
 *
 * The #define below provides a default of all errors in the list.
 * The default can then be modified to reduce the amount of traffic
 * going to syslog in the event of RPC errors.
 */

#define	DEFAULT_ERRMASK	(UINT_MAX & ~(1 << RPC_SUCCESS))

uint_t
meta_rpc_err_mask(void)
{
	char		*param_valuep;
	uint_t retval   = DEFAULT_ERRMASK;

	param_valuep = meta_get_rt_param("commd_RPC_errors", B_FALSE);
	if (param_valuep != NULL) {
		retval = (uint_t)strtol(param_valuep, NULL, 16);
		free(param_valuep);
	}
	return (retval);
}

/*
 * The following lines define private functions
 */

static char *
meta_get_rt_param(const char *param_namep, boolean_t warn_if_not_found)
{
	const char *function_namep = "meta_get_rt_param()";
	char *line_bufferp = NULL;
	char *newlinep = NULL;
	FILE *param_filep = NULL;
	char *param_name_tokenp = NULL;
	char *param_valuep = NULL;
	char *param_value_tokenp = NULL;

	line_bufferp = (char *)malloc(line_buffer_size);
	if (line_bufferp == NULL) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: malloc failed\n"), function_namep);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "%s: malloc failed\n"),
		    function_namep);
		return (param_valuep);
	}
	param_filep = fopen(param_file_namep, "r");
	if (param_filep == NULL) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: can't open %s\n"), function_namep, param_file_namep);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN, "%s: can't open %s\n"),
		    function_namep, param_file_namep);
		free(line_bufferp);
		return (param_valuep);
	}
	while ((fgets(line_bufferp, line_buffer_size, param_filep) != NULL) &&
	    (param_valuep == NULL)) {

		newlinep = strchr(line_bufferp, '\n');
		if (newlinep != NULL) {
			*newlinep = '\0';
			newlinep = NULL;
		}
		param_name_tokenp = strtok(line_bufferp, token_separator_listp);
		if ((param_name_tokenp != NULL) &&
		    (strcmp(param_namep, param_name_tokenp) == 0)) {

			param_value_tokenp = strtok(NULL,
			    token_separator_listp);
		}
		if (param_value_tokenp != NULL) {
			param_valuep = strdup(param_value_tokenp);
			if (param_valuep == NULL) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: strdup failed\n"),
				    function_namep);
				syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "%s: strdup failed\n"),
				    function_namep);
				free(line_bufferp);
				(void) fclose(param_filep);
				return (param_valuep);
			}
		}
	}
	if ((param_valuep == NULL) && (warn_if_not_found == B_TRUE)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: value of %s not set or error in %s\n"),
		    function_namep, param_namep, param_file_namep);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "%s: value of %s not set or error in %s\n"),
		    function_namep, param_namep, param_file_namep);
	}
	free(line_bufferp);
	(void) fclose(param_filep);
	return (param_valuep);
}
