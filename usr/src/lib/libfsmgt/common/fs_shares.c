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

/*
 * Traverses /etc/dfs/sharetab in order to find shared file systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include "libfsmgt.h"
#include <sharefs/share.h>
#include "sharetab.h"

#define	SECMODES 5

/*
 * Private variables
 */
static mutex_t	sharetab_lock = DEFAULTMUTEX;

/*
 * Private method declarations
 */
fs_sharelist_t	*create_sharelist_entry(struct share *sharetab_entry,
					int *errp);

/*
 * Public methods
 */

void
fs_free_share_list(fs_sharelist_t *headp)
{
	fs_sharelist_t	*tmp;

	while (headp != NULL) {
		tmp = headp->next;
		free(headp->path);
		free(headp->resource);
		free(headp->fstype);
		free(headp->options);
		free(headp->description);
		headp->next = NULL;
		free(headp);

		headp = tmp;
	}
}

/*
 * Get a linked list of all the shares on the system from /etc/dfs/dfstab
 */
fs_sharelist_t *
fs_get_share_list(int *errp)
{
	fs_sharelist_t	*newp;
	fs_sharelist_t	*headp;
	fs_sharelist_t	*tailp;
	FILE		*fp;

	headp = NULL;
	tailp = NULL;

	if ((fp = fopen(SHARETAB, "r")) != NULL) {
		struct share	*sharetab_entry;

		(void) mutex_lock(&sharetab_lock);
		while (getshare(fp, &sharetab_entry) > 0) {

			newp = create_sharelist_entry(sharetab_entry, errp);
			if (newp == NULL) {
				/*
				 * Out of memory
				 */
				fs_free_share_list(headp);
				(void) mutex_unlock(&sharetab_lock);
				(void) fclose(fp);
				return (NULL);
			}

			if (headp == NULL) {
				headp = newp;
				tailp = newp;
			} else {
				tailp->next = newp;
				tailp = newp;
			}

		} /* while (getshare(fp, &sharetab_entry) != 0) */
		(void) mutex_unlock(&sharetab_lock);
		(void) fclose(fp);
	} else {
		*errp = errno;
	} /* if ((fp = fopen(SHARETAB, "r")) != NULL) */

	/*
	 * Caller must free the mount list
	 */
	return (headp);
} /* fs_get_share_list */


/*
 * fs_parse_opts_for_sec_modes
 * Get an array of strings of all the security modes of the option string.
 *
 * char *cmd - The option string from the share command.
 * int *count - pointer to the number of elements in the returned array.
 * int *error - error pointer for returning any errors.
 */
char **
fs_parse_opts_for_sec_modes(char *cmd, int *count, int *error)
{
	char *temp_str;
	char **secstringarray;
	char *strptr;

	*count = 0;
	strptr = strdup(cmd);
	if (strptr == NULL) {
		*error = ENOMEM;
		return (NULL);
	}

	temp_str = strptr;

	secstringarray =
	    (char **)calloc((size_t)SECMODES, (size_t)(sizeof (char *)));
	if (secstringarray == NULL) {
		*error = ENOMEM;
		return (NULL);
	}

	if (strstr(strptr, "sec=") != NULL) {
		char *next_str;
		next_str = strptr;

		while (next_str != NULL) {
			next_str = strstr(strptr, "sec=");
			if (next_str != NULL) {
				if (strncmp(strptr, "sec=", 4) != 0) {
					*(next_str - 1) = '\0';
				}
				strptr = next_str;
				next_str = strstr(strptr + 4, "sec=");
				if (next_str != NULL) {
					*(next_str - 1) = '\0';
				}
				secstringarray[*count] = strdup(strptr);
				if (secstringarray[*count] == NULL) {
					*error = ENOMEM;
					if (*count > 0) {
						fileutil_free_string_array(
						    secstringarray, *count);
					} else {
						free(secstringarray);
					}
					free(temp_str);
					return (NULL);
				}
				strptr = next_str;
				(*count)++;
			}
		}
	} else {
		secstringarray[*count] = strdup(temp_str);
		if (secstringarray[*count] == NULL) {
			*error = ENOMEM;
			if (*count > 0) {
				fileutil_free_string_array(
				    secstringarray, *count);
			} else {
				free(secstringarray);
			}
			free(temp_str);
			return (NULL);
		}
		(*count)++;
	}
	free(temp_str);
	return (secstringarray);
}

/*
 * fs_create_array_from_accesslist
 * Takes the colon seperated access list parses the list into an array
 * containing all the elements of the list. The array created is returned
 * and count is set to the number of elements in the array.
 *
 * char *access_list - The string containing the colon sperated access list.
 * int *count - Will contain the number of elements in the array.
 * int *err - any errors encountered.
 */
char **
fs_create_array_from_accesslist(char *access_list, int *count, int *err)
{
	char *delimiter = ":";
	char *server_string;
	char **list_array = NULL;
	char *list_copy;

	*count = 0;
	if (access_list != NULL) {
		list_copy = strdup(access_list);
		if (list_copy != NULL) {
			server_string = strtok(list_copy, delimiter);
			if (server_string != NULL) {
				while (server_string != NULL) {
					if (!fileutil_add_string_to_array(
					    &list_array, server_string, count,
					    err)) {
						fileutil_free_string_array(
						    list_array, *count);
						free(list_copy);
						goto return_err;
					}
					server_string =
					    strtok(NULL, delimiter);
				}
			} else {
				list_array =
				    (char **)calloc(((*count) + 1),
				    sizeof (char *));
				if (list_array == NULL) {
					*err = ENOMEM;
					free(list_copy);
					goto return_err;
				}
				list_array[*count] = strdup(access_list);
				if (list_array[*count] == NULL) {
					*err = ENOMEM;
					free(list_array);
					list_array = NULL;
					goto return_err;
				}
				(*count)++;
			}
			free(list_copy);
		} else {
			*err = ENOMEM;
		}
	}
return_err:
	return (list_array);
} /* fs_create_array_from_accesslist */


/*
 * Private Methods
 */

fs_sharelist_t *
create_sharelist_entry(struct share *sharetab_entry, int *errp)
{

	fs_sharelist_t	*newp;

	newp = (fs_sharelist_t *)calloc((size_t)1,
	    (size_t)sizeof (fs_sharelist_t));

	if (newp == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		return (NULL);
	}

	newp->path = strdup(sharetab_entry->sh_path);
	if (newp->path == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		fs_free_share_list(newp);
		return (NULL);
	}

	newp->resource = strdup(sharetab_entry->sh_res);
	if (newp->path == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		fs_free_share_list(newp);
		return (NULL);
	}

	newp->fstype = strdup(sharetab_entry->sh_fstype);
	if (newp->fstype == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		fs_free_share_list(newp);
		return (NULL);
	}

	newp->options = strdup(sharetab_entry->sh_opts);
	if (newp->options == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		fs_free_share_list(newp);
		return (NULL);
	}

	newp->description = strdup(sharetab_entry->sh_descr);
	if (newp->description == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		fs_free_share_list(newp);
		return (NULL);
	}
	newp->next = NULL;

	return (newp);
} /* create_sharelist_entry */
