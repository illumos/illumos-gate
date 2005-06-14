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
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <thread.h>
#include <synch.h>
#include "libfsmgt.h"

/*
 * Private datastructures.
 */
typedef struct dfstab_entry {
	struct dfstab_entry *next;
	char    *path;
	char    *resource;
	char    *fstype;
	char    *options;
	char    *description;
} dfstab_entry_t;

static const char *whitespace = " \t";
static mutex_t dfstab_lock = DEFAULTMUTEX;

/*
 * Private functions
 */
static dfstab_entry_t *get_dfstab_ents(int *);
static void free_dfstab_list(dfstab_entry_t *);
static dfstab_entry_t *dfstab_line_to_dfstab_entry(char *, int *);
static char *create_share_cmd(dfstab_entry_t *, char *, int *);
static dfstab_entry_t *change_dfstab_ent(dfstab_entry_t *,
	dfstab_entry_t *, int *);
static void add_entry_to_dfstab(dfstab_entry_t *, int *);


static dfstab_entry_t *
get_dfstab_ents(int *err)
{
	dfstab_entry_t *dfstablist, *headptr, *tailptr = NULL;
	FILE *dfp;		/* fp for dfs list */
	static char cmd[BUFSIZE];
	*err = 0;

	if ((dfp = fopen(DFSTAB, "r")) != NULL) {
		char *share_cmd;
		(void) mutex_lock(&dfstab_lock);
		while ((share_cmd =
		    fileutil_getline(dfp, cmd, BUFSIZE)) != NULL) {
			if ((dfstablist =
			    dfstab_line_to_dfstab_entry(share_cmd, err)) !=
			    NULL) {
				if (tailptr == NULL) {
					headptr = dfstablist;
					tailptr = dfstablist;
				} else {
					tailptr->next = dfstablist;
					tailptr = dfstablist;
				}
				dfstablist = dfstablist->next;
			} else {
				free(share_cmd);
				break;
			}
			free(share_cmd);
		}
		if (tailptr == NULL) {
			headptr = tailptr;
		}
		(void) mutex_unlock(&dfstab_lock);
		fclose(dfp);
	} else {
		*err = errno;
		(void) fprintf(stderr, "%s: cannot open %s\n", cmd, DFSTAB);
		headptr = NULL;
	}
	return (headptr);
} /* get_dfstab_ents */

static void
add_entry_to_dfstab(dfstab_entry_t *list, int *err)
{
	FILE *dfp;		/* fp for dfs list */

	if ((dfp = fopen(DFSTAB, "a")) != NULL) {
		char *share_cmd;
		if ((share_cmd = create_share_cmd(list, NULL, err)) != NULL) {
			(void) mutex_lock(&dfstab_lock);
			fprintf(dfp, "%s", share_cmd);
			fclose(dfp);
			(void) mutex_unlock(&dfstab_lock);
			free(share_cmd);
		} else {
			*err = errno;
		}
	} else {
		*err = errno;
	}

} /* add_entry_to_dfstab */

static void
free_dfstab_list(dfstab_entry_t *headp)
{
	dfstab_entry_t *tmp = headp;

	while (headp != NULL) {
		tmp = headp->next;
		if (headp->path != NULL) {
			free(headp->path);
		}
		if (headp->resource != NULL) {
			free(headp->resource);
		}
		if (headp->fstype != NULL) {
			free(headp->fstype);
		}
		if (headp->options != NULL) {
			free(headp->options);
		}
		if (headp->description != NULL) {
			free(headp->description);
		}
		headp->next = NULL;
		free(headp);
		headp = tmp;
	}
} /* free_dfstab_list */

static char *
create_share_cmd(dfstab_entry_t *new_entry, char *temp_line, int *err)
{
	char tempstr[BUFSIZE];
	char *cmd, *ret_val;

	cmd = (char *)calloc((size_t)1, BUFSIZE);
	if (cmd == NULL) {
		*err = errno;
		return (NULL);
	}
	sprintf(cmd, "share ");
	if (new_entry->fstype) {
		sprintf(tempstr, "-F %s ", new_entry->fstype);
		strlcat(cmd, tempstr, BUFSIZE);
	}
	if (new_entry->options) {
		sprintf(tempstr, "-o %s ", new_entry->options);
		strlcat(cmd, tempstr, BUFSIZE);
	}
	if (new_entry->description) {
		sprintf(tempstr, "-d %s ",
		    new_entry->description);
		strlcat(cmd, tempstr, BUFSIZE);
	}
	sprintf(tempstr, "%s\n", new_entry->path);
	strlcat(cmd, tempstr, BUFSIZE);
	if (temp_line != NULL && strchr(temp_line, '#')) {
		sprintf(tempstr, " %s", strchr(temp_line, '#'));
		strlcat(cmd, tempstr, BUFSIZE);
	}
	ret_val = strdup(cmd);
	free(cmd);
	return (ret_val);
} /* create_share_cmd */

/*
 * dfstab_line_to_dfstab_entry - parses a line from dfstab and fills in
 * the fields of a dfstab_entry_t structure
 * Parameters:
 * char *cmd - the share command or dfstab line to be parsed
 * int *err - a pointer for returning any error codes encountered
 */
static dfstab_entry_t *
dfstab_line_to_dfstab_entry(char *cmd, int *err)
{

	dfstab_entry_t *dfstablist;
	extern char *optarg;
	extern int optind;
	int c, argcount = 0;
	char *temp_str;
	char *arglist[LINESZ];

	c = 0;
	optind = 1;

	temp_str = strdup(cmd);
	if (temp_str == NULL) {
		*err = ENOMEM;
		return (NULL);
	}

	for (arglist[argcount] = strtok(temp_str, whitespace);
	    arglist[argcount] != NULL; /* CSTYLED */) {
		arglist[++argcount] = strtok(NULL, whitespace);
	}
	argcount--;
	dfstablist =
	    (dfstab_entry_t *)calloc((size_t)1,
	    sizeof (dfstab_entry_t));
	if (dfstablist == NULL) {
		*err = ENOMEM;
		free(temp_str);
		return (NULL);
	}
	while ((c = getopt(argcount, arglist, "F:d:o:")) != -1) {
		switch (c) {
		case 'F':
					/* file system type */
					/* at most one -F */
			*err |= (dfstablist->fstype != NULL);
			dfstablist->fstype = strdup(optarg);
			if (dfstablist->fstype == NULL) {
				*err = ENOMEM;
				free_dfstab_list(dfstablist);
				free(temp_str);
				return (NULL);
			}
			break;
		case 'd':		/* description */
					/* at most one -d */
			*err |= (dfstablist->description != NULL);
			dfstablist->description = strdup(optarg);
			if (dfstablist->description == NULL) {
				*err = ENOMEM;
				free_dfstab_list(dfstablist);
				free(temp_str);
				return (NULL);
			}
			break;
		case 'o':		/* fs specific options */
					/* at most one - o */
			*err |= (dfstablist->options != NULL);
			dfstablist->options = strdup(optarg);
			if (dfstablist->options == NULL) {
				*err = ENOMEM;
				free_dfstab_list(dfstablist);
				free(temp_str);
				return (NULL);
			}
			break;
		case '?':
			*err = 1;
			break;
		}
	}
	if (dfstablist->fstype == NULL) {
		FILE *fp;

		if ((fp = fopen(DFSTYPES, "r")) == NULL) {
			(void) fprintf(stderr, "%s: cannot open %s\n",
			    cmd, DFSTYPES);
			free_dfstab_list(dfstablist);
			free(temp_str);
			return (NULL);
		}
		(void) mutex_lock(&dfstab_lock);
		dfstablist->fstype = strdup(fileutil_getfs(fp));
		(void) mutex_unlock(&dfstab_lock);
		fclose(fp);
	}
	dfstablist->path = strdup(arglist[argcount]);
	if (dfstablist->path == NULL) {
		*err = ENOMEM;
		free_dfstab_list(dfstablist);
		free(temp_str);
		return (NULL);
	}
	free(temp_str);
	return (dfstablist);
} /* dfstab_line_to_dfstab_entry */

static dfstab_entry_t *
change_dfstab_ent(
	dfstab_entry_t *old_entry,
	dfstab_entry_t *new_entry,
	int *err)
{

	FILE *fp;
	dfstab_entry_t *temp_list, *ret_val;
	char cmd[BUFSIZE];
	char **temp_dfstab = NULL;
	int line_found = 0;

	if ((fp = fopen(DFSTAB, "r")) != NULL) {
		char *share_cmd;
		int count = 0;
		(void) mutex_lock(&dfstab_lock);
		while (fgets(cmd, BUFSIZE, fp) != NULL) {
			if ((share_cmd =
			    fileutil_get_cmd_from_string(cmd)) == NULL) {
				if (!fileutil_add_string_to_array(
				    &temp_dfstab, cmd, &count, err)) {
					ret_val = NULL;
					line_found = 0;
					break;
				}
				continue;
			}
			if ((temp_list =
			    dfstab_line_to_dfstab_entry(share_cmd, err)) ==
			    NULL) {
				free(share_cmd);
				ret_val = NULL;
				break;
			}
			if (strcmp(old_entry->path,
			    temp_list->path) == 0) {
				char *new_cmd = NULL;
				line_found = 1;
				if (new_entry != NULL && (new_cmd =
				    create_share_cmd(new_entry, cmd,
				    err)) != NULL) {
					if (!fileutil_add_string_to_array(
					    &temp_dfstab, new_cmd, &count,
					    err)) {
						ret_val = NULL;
						line_found = 0;
						free(share_cmd);
						free(new_cmd);
						break;
					}
					free(new_cmd);
				}
			} else {
				if (!fileutil_add_string_to_array(
				    &temp_dfstab, cmd, &count, err)) {
					free(share_cmd);
					ret_val = NULL;
					line_found = 0;
					break;
				}
			}
			free_dfstab_list(temp_list);
			free(share_cmd);
		}
		fclose(fp);

		if (line_found && temp_dfstab != NULL) {
			if ((fp = fopen(DFSTAB, "w")) != NULL) {
				int i;
				for (i = 0; i < count; i++) {
					fprintf(fp, "%s", temp_dfstab[i]);
				}
				fclose(fp);
				(void) mutex_unlock(&dfstab_lock);
				ret_val = get_dfstab_ents(err);
				fileutil_free_string_array(temp_dfstab, count);
			} else {
				*err = errno;
				(void) mutex_unlock(&dfstab_lock);
				fileutil_free_string_array(temp_dfstab, count);
				ret_val = NULL;
			}
		} else {
			(void) mutex_unlock(&dfstab_lock);
			if (temp_dfstab != NULL) {
				fileutil_free_string_array(temp_dfstab, count);
			}
			ret_val = NULL;
		}
	} else {
		*err = errno;
		ret_val = NULL;
	}
	return (ret_val);
} /* change_dfstab_ent */

/*
 * Public accessor functions.
 */

/*
 * fs_add_DFStab_ent - adds an entry to dfstab and to the list of dfstab
 * entries. Returns a pointer to the head of the dfstab entry list.
 * Parameters:
 * char *cmd - the same command to be added to dstab
 * int *err - an error pointer for retruning any errors
 */
fs_dfstab_entry_t
fs_add_DFStab_ent(char *cmd, int *err)
{
	dfstab_entry_t *dfstab_ent;

	dfstab_ent = dfstab_line_to_dfstab_entry(cmd, err);
	if (dfstab_ent == NULL) {
		*err = errno;
		return (NULL);
	}
	add_entry_to_dfstab(dfstab_ent, err);
	if (*err != 0) {
		free_dfstab_list(dfstab_ent);
		return (NULL);
	}
	free_dfstab_list(dfstab_ent);
	return (get_dfstab_ents(err));
}

/*
 * set_DFStab_ent - adds an entry to dfstab and to the list of dfstab entries.
 * returns a pointer to the head of the dfstab entry list.
 */
fs_dfstab_entry_t
fs_set_DFStab_ent(
	char *path,
	char *fstype,
	char *options,
	char *description,
	int *err)
{

	dfstab_entry_t *new_entry;
	new_entry = (dfstab_entry_t *)calloc((size_t)1,
	    sizeof (dfstab_entry_t));
	if (new_entry == NULL) {
		*err = ENOMEM;
		return (NULL);
	}
	if (path != NULL) {
		new_entry->path = strdup(path);
	} else {
		*err = EINVAL;
		free_dfstab_list(new_entry);
		return (NULL);
	}
	if (fstype != NULL) {
		new_entry->fstype = strdup(fstype);
	} else {
		FILE *fp;

		if ((fp = fopen(DFSTYPES, "r")) == NULL) {
			/* change this to error handler */
			(void) fprintf(stderr, "cannot open %s\n",
			    DFSTYPES);
			free_dfstab_list(new_entry);
			return (NULL);
		}
		(void) mutex_lock(&dfstab_lock);
		new_entry->fstype = strdup(fileutil_getfs(fp));
		(void) mutex_unlock(&dfstab_lock);
		fclose(fp);
	}
	if (options != NULL) {
		new_entry->options = strdup(options);
	}
	if (description != NULL) {
		new_entry->description = strdup(description);
	}
	add_entry_to_dfstab(new_entry, err);
	if (*err != 0) {
		free_dfstab_list(new_entry);
		return (NULL);
	}
	free_dfstab_list(new_entry);
	return (get_dfstab_ents(err));
} /* set_DFStab_ent */

/*
 * Accessor function for path element of dfstab entry.
 */
char *
fs_get_DFStab_ent_Path(void *entry)
{
	dfstab_entry_t *entryptr = (dfstab_entry_t *)entry;
	if (entryptr == NULL) {
		return (NULL);
	}
	return (entryptr->path);
} /* get_DFStab_ent_Path */

/*
 * Accessor function for fstype element of dfstab entry.
 */
char *
fs_get_DFStab_ent_Fstype(void *entry)
{
	dfstab_entry_t *entryptr = (dfstab_entry_t *)entry;
	if (entryptr == NULL) {
		return (NULL);
	}
	return (entryptr->fstype);
}

/*
 * Accessor function for options element of dfstab entry.
 */
char *
fs_get_DFStab_ent_Options(void *entry)
{
	dfstab_entry_t *entryptr = (dfstab_entry_t *)entry;
	if (entryptr == NULL) {
		return (NULL);
	}
	return (entryptr->options);
}

/*
 * Accessor function for description element of dfstab entry.
 */
char *
fs_get_DFStab_ent_Desc(void *entry)
{
	dfstab_entry_t *entryptr = (dfstab_entry_t *)entry;
	if (entryptr == NULL) {
		return (NULL);
	}
	return (entryptr->description);
}

/*
 * Accessor function for resource element of dfstab entry.
 */
char *
fs_get_DFStab_ent_Res(void *entry)
{
	dfstab_entry_t *entryptr = (dfstab_entry_t *)entry;
	if (entryptr == NULL) {
		return (NULL);
	}
	return (entryptr->resource);
}


/*
 * Calls get_dfstab_ents to create the list of dfstab
 * entries and returns that list.
 */
fs_dfstab_entry_t
fs_get_DFStab_ents(int *err)
{
	dfstab_entry_t *list;
	list = get_dfstab_ents(err);
	return (list);
}

/*
 * Retrives and returns the next entry in the list.
 */
fs_dfstab_entry_t
fs_get_DFStab_ent_Next(void *list)
{
	dfstab_entry_t *listptr = (dfstab_entry_t *)list;
	if (listptr == NULL) {
		return (NULL);
	}
	return (listptr->next);
}

/*
 * Retrives and returns a share command based on the dfstab entry passed in.
 */
char *
fs_get_Dfstab_share_cmd(fs_dfstab_entry_t dfstab_ent, int *err)
{
	char *share_cmd;
	if (dfstab_ent == NULL) {
		return (NULL);
	}
	share_cmd = create_share_cmd((dfstab_entry_t *)dfstab_ent, NULL, err);
	return (share_cmd);
} /* fs_get_Dfstab_share_cmd */

/*
 * edit_DFStab_ent - changes an entry in dfstab.
 */
fs_dfstab_entry_t
fs_edit_DFStab_ent(char *old_cmd, char *new_cmd, int *err)
{
	dfstab_entry_t *old_dfstabent, *new_dfstabent, *ret_val;

	if ((old_dfstabent =
	    dfstab_line_to_dfstab_entry(old_cmd, err)) == NULL) {
		return (NULL);
	}
	if ((new_dfstabent =
	    dfstab_line_to_dfstab_entry(new_cmd, err)) == NULL) {
		return (NULL);
	}
	if ((ret_val =
	    change_dfstab_ent(old_dfstabent, new_dfstabent, err)) == NULL) {
		return (NULL);
	}
	free_dfstab_list(old_dfstabent);
	free_dfstab_list(new_dfstabent);
	return (ret_val);
}

/*
 * del_DFStab_ent - deletes an entry in dfstab.
 */
fs_dfstab_entry_t
fs_del_DFStab_ent(char *del_cmd, int *err)
{
	dfstab_entry_t *del_dfstabent, *ret_val;

	if ((del_dfstabent =
	    dfstab_line_to_dfstab_entry(del_cmd, err)) == NULL) {
		return (NULL);
	}
	if ((ret_val =
	    change_dfstab_ent(del_dfstabent, NULL, err)) == NULL) {
		return (NULL);
	}
	free_dfstab_list(del_dfstabent);
	return (ret_val);
}

/*
 * del_All_DFStab_ents_with_Path - deletes all duplicate entries with
 * the specified path.
 */
fs_dfstab_entry_t
fs_del_All_DFStab_ents_with_Path(char *path, int *err)
{
	dfstab_entry_t del_dfstabent, *ret_val;

	if (path != NULL) {
		if ((del_dfstabent.path = strdup(path)) != NULL) {
			if ((ret_val = change_dfstab_ent(&del_dfstabent,
			    NULL, err)) == NULL) {
				ret_val = NULL;
			}
			free(del_dfstabent.path);
		} else {
			*err = ENOMEM;
			ret_val = NULL;
		}
	} else {
		*err = EINVAL;
		ret_val = NULL;
	}
	return (ret_val);
}


int
fs_check_for_duplicate_DFStab_paths(char *path, int *err)
{
	dfstab_entry_t *dfstablist;
	int count = 0;

	*err = 0;
	if (path == NULL) {
		count = -1;
	}
	dfstablist = get_dfstab_ents(err);
	if (dfstablist != NULL) {
		while (dfstablist != NULL) {
			if (strcmp(dfstablist->path, path) == 0) {
				count++;
			}
			dfstablist = dfstablist->next;
		}

		free_dfstab_list(dfstablist);
	} else {
		if (err != 0)
			count = *err;
		else
			count = 0;
	}
	return (count);
}

void
fs_free_DFStab_ents(void *list)
{
	dfstab_entry_t *headp = (dfstab_entry_t *)list;
	free_dfstab_list(headp);
}

/*
 * used for debugging only
 */
void
fs_print_dfstab_entries(void *list)
{
	while (list != NULL) {

		if (fs_get_DFStab_ent_Fstype(list) != NULL)
			printf("fstype: %s", fs_get_DFStab_ent_Fstype(list));
		if (fs_get_DFStab_ent_Desc(list) != NULL)
			printf(" description: %s",
			    fs_get_DFStab_ent_Desc(list));
		if (fs_get_DFStab_ent_Options(list) != NULL)
			printf(" options: %s",
			    fs_get_DFStab_ent_Options(list));
		if (fs_get_DFStab_ent_Path(list) != NULL)
			printf(" shared path is: %s\n",
			    fs_get_DFStab_ent_Path(list));
		list = (void *)fs_get_DFStab_ent_Next(list);
	}

}
