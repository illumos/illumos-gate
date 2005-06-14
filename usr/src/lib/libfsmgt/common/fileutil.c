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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <thread.h>
#include <synch.h>
#include "libfsmgt.h"

/*
 * Private method declarations
 */
static char *get_first_column_data(char *line);
static char *retrieve_string(FILE *fp, char *line, int buffersize);
static char *trim_trailing_whitespace(char *line);

/*
 * Public methods
 */

void
fileutil_free_string_array(char **arrayp, int num_elements)
{
	if (arrayp != NULL) {
		int	i = 0;

		for (i = 0; i < num_elements && arrayp[i] != NULL; i++) {
			free(arrayp[i]);
		}

		free(arrayp);
	}
} /* fileutil_free_string_array */

char **
fileutil_get_first_column_data(FILE *fp, int *num_elements, int *errp)
{
	char	line[BUFSIZE];
	char	*returned_string;
	char	**return_array = NULL;

	*errp = 0;
	*num_elements = 0;

	while ((returned_string =
		retrieve_string(fp, line, BUFSIZE)) != NULL) {

		char	**tmp_array;

		tmp_array = realloc(return_array,
			(size_t)(((*num_elements) + 1) * sizeof (char *)));
		if (tmp_array == NULL) {
			*errp = errno;
			fileutil_free_string_array(return_array, *num_elements);
			*num_elements = 0;
			return (NULL);
		}
		return_array = tmp_array;

		return_array[(*num_elements)] = strdup(returned_string);
		if (return_array[(*num_elements)] == NULL) {
			*errp = ENOMEM;
			fileutil_free_string_array(return_array, *num_elements);
			free(returned_string);
			*num_elements = 0;
			return (NULL);
		}

		free(returned_string);
		*num_elements = *num_elements + 1;
	}

	/*
	 * Caller must free the space allocated to return_array by calling
	 * fileutil_free_string_array.
	 */
	return (return_array);
} /* fileutil_get_first_column_data */

/*
 * Convenience function for retrieving the default fstype from /etc/fstypes.
 */
char *
fileutil_getfs(FILE *fp)
{
	char *s;
	static char buff[BUFSIZE];	/* line buffer */

	while (s = fgets(buff, BUFSIZE, fp)) {
		while (isspace(*s) || *s != '\0') /* skip leading whitespace */
			++s;
		if (*s != '#') {	/* not a comment */
			char *t = s;
			while (!isspace(*t) && *t != '\0') /* get the token */
				++t;
			*t = '\0';	/* ignore rest of line */
			return (s);
		}
	}
	return (NULL);  /* that's all, folks! */
} /* fileutil_getfs */

char *
fileutil_getline(FILE *fp, char *line, int linesz)
{
	char *share_cmd, *p = line;
	*p = '\0';

	while (fgets(line, linesz, fp) != NULL) {
		share_cmd = fileutil_get_cmd_from_string(line);
		if (share_cmd != NULL)
			return (share_cmd);
	}
	return (NULL);
} /* fileutil_getline */

/*
 * fileutil_get_cmd_from_string - retieves the command string minus any
 * comments from the original string.
 *
 * Parameters:
 * char *input_string - the original string.
 */
char *
fileutil_get_cmd_from_string(char *input_stringp)
{
	/*
	 * Comments begin with '#'.  Strip them off.
	 */

	char *returned_stringp;
	char *start_of_commentp;
	char *current_string;

	if ((input_stringp == NULL) || (strlen(input_stringp) == 0)) {
		return (NULL);
	}

	current_string = strdup(input_stringp);

	if (current_string == NULL) {
		return (NULL);
	}

	start_of_commentp = strchr(current_string, '#');
	if (start_of_commentp != NULL) {
		*start_of_commentp = '\0';
	}

	returned_stringp = trim_trailing_whitespace(current_string);
	free(current_string);
	return (returned_stringp);
}

/*
 * NOTE: the caller of this function is responsible for freeing any
 * memory allocated by calling fileutil_free_string_array()
 *
 * fileutil_add_string_to_array - adds one line to the file image
 *                                   string array
 * Parameters:
 * char ***string_array - reference to the string array
 * char *line - the line to be added to the temporary dfstab
 * int *count - the number of elements in the string array
 * int *err - error pointer for returning any errors encountered
 *
 * Returns:
 * B_TRUE on success, B_FALSE on failure.
 */
boolean_t
fileutil_add_string_to_array(char ***string_array, char *line, int *count,
	int *err)
{
	int i;
	char **ret_val = NULL;
	char **temp_array = NULL;

	temp_array = *string_array;

	ret_val = calloc(((*count) + 1), sizeof (char *));
	if (ret_val != NULL) {
		for (i = 0; i < *count; i ++) {
			ret_val[i] = temp_array[i];
		}
		ret_val[*count] = strdup(line);
		if (ret_val[*count] != NULL) {
			(*count)++;
			if (temp_array != NULL) {
				free(temp_array);
			}
			*string_array = ret_val;
		} else {
			*err = ENOMEM;
			free(ret_val);
			return (B_FALSE);
		}
	} else {
		*err = ENOMEM;
		return (B_FALSE);
	}
	return (B_TRUE);
} /* fileutil_add_string_to_array */

/*
 * Private methods
 */
static char *
get_first_column_data(char *line)
{
	return (strtok(line, "\t "));
} /* get_first_column_data */

static char *
retrieve_string(FILE *fp, char *line, int buffersize)
{
	char    *data;
	char	*returned_string;

	while ((returned_string =
		fileutil_getline(fp, line, buffersize)) != NULL) {

		data = get_first_column_data(returned_string);
		if (data != NULL)
			return (data);
	}

	return (NULL);
} /* retrieve_string */

/*
 * trim_trailing_whitespace - helper function to remove trailing
 * whitespace from a line
 *
 * Parameters:
 * char *input_stringp - the line to be trimed
 */
static char *
trim_trailing_whitespace(char *input_string)
{
	char *last_nonspace;
	char *return_string;
	int string_length;


	if (input_string == NULL) {
		return (NULL);
	}
	string_length = strlen(input_string);

	if (string_length == 0 || *input_string == '\n') {
		return (NULL);
	}

	return_string = strdup(input_string);
	if (return_string == NULL) {
		return (NULL);
	}

	/*
	 * Truncates the last character which will always be '\0'
	 */
	last_nonspace = return_string + (string_length - 1);

	while (isspace(*last_nonspace)) {
		last_nonspace--;
	}
	*(last_nonspace + 1) = '\0';
	return (return_string);
}
