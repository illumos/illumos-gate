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
 * Traverses /etc/mnttab in order to find mounted file systems.
 */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <strings.h>
#include "libfsmgt.h"

/*
 * Private variables
 */

/*
 * Private method declarations
 */

static fs_mntlist_t	*create_mntlist_entry(struct mnttab mnttab_entry);
static fs_mntlist_t	*create_extmntlist_entry(struct extmnttab mnttab_entry);
static struct mnttab	*create_mnttab_filter(char *resource, char *mountp,
				char *fstype, char *mntopts, char *time);
static void		find_overlayed_filesystems(fs_mntlist_t *mnt_list,
				boolean_t filtered_list, int *errp);
static void		free_mnttab_entry(struct mnttab *mnttab_entry);
static char		*is_option(char *opt_string, char *opt, int *errp);
boolean_t 		is_overlayed(fs_mntlist_t *complete_mnt_list,
				char *mountp);


/*
 * Public methods
 */

void
fs_free_mount_list(fs_mntlist_t *headp) {
	fs_mntlist_t	*tmp;

	while (headp != NULL) {
		tmp = headp->next;
		free(headp->resource);
		free(headp->mountp);
		free(headp->fstype);
		free(headp->mntopts);
		free(headp->time);
		headp->next = NULL;
		free(headp);

		headp = tmp;
	}
} /* fs_free_mount_list */

unsigned long long
fs_get_availablesize(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long long	availablesize;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		availablesize = stvfs.f_bfree;
		availablesize = availablesize * stvfs.f_frsize;
	} else {
		*errp = errno;
		return (0);
	}  /* if (statvfs64(mntpnt, &stvfs) != -1) */

	return (availablesize);
} /* fs_get_availablesize */

unsigned long long
fs_get_avail_for_nonsuperuser_size(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long long	avail_for_nonsu_size;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		avail_for_nonsu_size = stvfs.f_bavail;
		avail_for_nonsu_size = avail_for_nonsu_size * stvfs.f_frsize;
	} else {
		*errp = errno;
		return (0);
	} /* if (statvfs64(mntpnt, &stvfs) != -1) */

	return (avail_for_nonsu_size);
} /* fs_get_avail_for_nonsuperuser_size(char *mntpnt, int *errp) */

unsigned long long
fs_get_blocksize(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long long	blocksize;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		blocksize = stvfs.f_bsize;
	} else {
		*errp = errno;
		return (0);
	} /* if (statvfs64(mntpnt, &stvfs) != -1) */

	return (blocksize);
} /* fs_get_blocksize */

fs_mntlist_t *
fs_get_filtered_mount_list(char *resource, char *mountp, char *fstype,
	char *mntopts, char *time, boolean_t find_overlays, int *errp) {

	fs_mntlist_t	*newp;
	fs_mntlist_t	*headp;
	fs_mntlist_t	*tailp;
	FILE		*fp;

	*errp = 0;
	headp = NULL;
	tailp = NULL;

	if ((fp = fopen(MNTTAB, "r")) != NULL) {
		struct mnttab   mnttab_entry;
		struct mnttab   *search_entry;

		search_entry = create_mnttab_filter(resource, mountp, fstype,
			mntopts, time);
		if (search_entry == NULL) {
			/*
			 * Out of memory
			 */
			fs_free_mount_list(headp);
			(void) fclose(fp);
			*errp = ENOMEM;
			return (NULL);
		}

		while (getmntany(fp, &mnttab_entry, search_entry) == 0) {
			/* Add to list to be returned */
			newp = create_mntlist_entry(mnttab_entry);

			if (newp == NULL) {
				/*
				 * Out of memory
				 */
				fs_free_mount_list(headp);
				(void) fclose(fp);
				*errp = ENOMEM;
				return (NULL);
			}

			if (headp == NULL) {
				headp = newp;
				tailp = newp;
			} else {
				tailp->next = newp;
				tailp = newp;
			}

		}
		free_mnttab_entry(search_entry);
		(void) fclose(fp);
		if (find_overlays == B_TRUE)
			find_overlayed_filesystems(headp, B_TRUE, errp);
	} else {
		*errp = errno;
	} /* if ((fp = fopen(MNTTAB, "r")) != NULL) */

	return (headp);
} /* fs_get_filtered_mount_list */

unsigned long
fs_get_fragsize(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long		fragsize;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		fragsize = stvfs.f_frsize;
	} else {
		*errp = errno;
		return (0);
	} /* (statvfs64(mntpnt, &stvfs) != -1) */

	return (fragsize);
} /* fs_get_fragsize(char *mntpnt, int *errp) */

unsigned long
fs_get_maxfilenamelen(char *mntpnt, int *errp) {
	long int		returned_val;
	unsigned long		maxfilenamelen;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	returned_val = pathconf(mntpnt, _PC_PATH_MAX);
	if (returned_val != -1) {
		maxfilenamelen = (unsigned long)returned_val;
	} else {
		*errp = errno;
		return (0);
	}

	return (maxfilenamelen);
} /* fs_get_maxfilenamelen */

fs_mntlist_t *
fs_get_mounts_by_mntopt(char *mntopt, boolean_t find_overlays, int *errp) {

	fs_mntlist_t	*newp;
	fs_mntlist_t	*headp;
	fs_mntlist_t	*tailp;
	FILE		*fp;

	*errp = 0;
	headp = NULL;
	tailp = NULL;

	if (mntopt == NULL)
		return (NULL);

	if ((fp = fopen(MNTTAB, "r")) != NULL) {
		struct mnttab mnttab_entry;
		char *opt_found;

		while (getmntent(fp, &mnttab_entry) == 0) {
			opt_found = hasmntopt(&mnttab_entry, mntopt);
			if (opt_found != NULL) {
				/*
				 * Add to list to be returned
				 */
				newp = create_mntlist_entry(mnttab_entry);

				if (newp == NULL) {
					/*
					 * Out of memory
					 */
					fs_free_mount_list(headp);
					(void) fclose(fp);
					*errp = ENOMEM;
					return (NULL);
				}

				if (headp == NULL) {
					headp = newp;
					tailp = newp;
				} else {
					tailp->next = newp;
					tailp = newp;
				}
			} /* if (char != NULL) */
		}
		(void) fclose(fp);
		if (find_overlays == B_TRUE)
			find_overlayed_filesystems(headp, B_TRUE, errp);

	} else {
		*errp = errno;
	} /* if ((fp = fopen(MNTTAB, "r")) != NULL) */

	return (headp);
} /* fs_get_mounts_by_mntpnt */

fs_mntlist_t *
fs_get_mount_list(boolean_t find_overlays, int *errp) {
	FILE 		*fp;
	fs_mntlist_t	*headp;
	fs_mntlist_t	*tailp;
	fs_mntlist_t	*newp;

	*errp = 0;
	headp = NULL;
	tailp = NULL;

	if ((fp = fopen(MNTTAB, "r")) != NULL) {
		struct extmnttab	mnttab_entry;

		resetmnttab(fp);

		/*
		 * getextmntent() Is used here so that we can use mnt_major
		 * and mnt_minor to get the fsid. The fsid is used when
		 * getting mount information from kstat.
		 */
		while (getextmntent(fp, &mnttab_entry,
		    sizeof (struct extmnttab)) == 0) {

			newp = create_extmntlist_entry(mnttab_entry);

			if (newp == NULL) {
				/*
				 * Out of memory
				 */
				fs_free_mount_list(headp);
				(void) fclose(fp);
				*errp = ENOMEM;
				return (NULL);
			}

			if (headp == NULL) {
				headp = newp;
				tailp = newp;
			} else {
				tailp->next = newp;
				tailp = newp;
			}

		} /* while (getmntent(fp, &mnttab_entry) == 0) */
		(void) fclose(fp);
		if (find_overlays)
			find_overlayed_filesystems(headp, B_FALSE, errp);
	} else {
		*errp = errno;
	} /* if ((fp = fopen(MNTTAB, "r")) != NULL) */

	/*
	 * Caller must free the mount list
	 */
	return (headp);
} /* fs_get_mount_list */

boolean_t
fs_is_readonly(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	boolean_t		readonly;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (B_FALSE);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		readonly = stvfs.f_flag & ST_RDONLY;
	} else {
		*errp = errno;
		return (B_FALSE);
	}

	return (readonly);
} /* fs_is_readonly */

/*
 * This method will parse the given comma delimited option list (optlist) for
 * the option passed into the function.  If the option (opt) to search for
 * is one that sets a value such as onerror=, the value to the right of the "="
 * character will be returned from the function.  This function expects the
 * opt parameter to have the "=" character appended when searching for options
 * which set a value.
 *
 * If the option is found in the given optlist, the function will return the
 * option as found in the option list.
 * If the option is not found in the given optlist, the function will return
 * NULL.
 * If an error occurs, the function will return NULL and the errp will
 * reflect the error that has occurred.
 *
 * NOTE: The caller must free the space allocated for the return value by using
 * free().
 */
char *
fs_parse_optlist_for_option(char *optlist, char *opt, int *errp) {
	const char	*delimiter = ",";
	char		*token;
	char		*return_value;
	char		*optlist_copy;

	*errp = 0;
	optlist_copy = strdup(optlist);
	if (optlist_copy == NULL) {
		*errp = errno;
		return (NULL);
	}

	token = strtok(optlist_copy, delimiter);
	/*
	 * Check to see if we have found the option.
	 */
	if (token == NULL) {
		free(optlist_copy);
		return (NULL);
	} else if ((return_value = is_option(token, opt, errp)) != NULL) {
		free(optlist_copy);
		return (return_value);
	}

	while (token != NULL) {
		token = NULL;
		token = strtok(NULL, delimiter);
		/*
		 * If token is NULL then then we are at the end of the list
		 * and we can return NULL because the option was never found in
		 * the option list.
		 */
		if (token == NULL) {
			free(optlist_copy);
			return (NULL);
		} else if ((return_value =
			is_option(token, opt, errp)) != NULL) {

			free(optlist_copy);
			return (return_value);

		}
	}
	free(optlist_copy);
	return (NULL);
}

unsigned long long
fs_get_totalsize(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long long 	totalsize;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		totalsize = stvfs.f_blocks;
		totalsize = totalsize * stvfs.f_frsize;

	} else {
		*errp = errno;
		return (0);
	} /* if (statvfs64(mntpnt, &stvfs) != -1) */

	return (totalsize);
} /* fs_get_totalsize */

unsigned long long
fs_get_usedsize(char *mntpnt, int *errp) {
	struct statvfs64	stvfs;
	unsigned long long	usedsize;

	*errp = 0;
	if (mntpnt == NULL) {
		/*
		 * Set errp to invalid parameter - EINVAL
		 */
		*errp = EINVAL;
		return (0);
	}

	if (statvfs64(mntpnt, &stvfs) != -1) {
		usedsize = stvfs.f_blocks - stvfs.f_bfree;
		usedsize = usedsize * stvfs.f_frsize;
	} else {
		*errp = errno;
		return (0);
	} /* if (statvfs64(mntpnt, &stvfs) != -1) */

	return (usedsize);
} /* fs_get_usedsize */

/*
 * Private methods
 */

static fs_mntlist_t *
create_mntlist_entry(struct mnttab mnttab_entry) {

	fs_mntlist_t	*newp;

	newp = (fs_mntlist_t *)calloc((size_t)1,
		(size_t)sizeof (fs_mntlist_t));

	if (newp == NULL) {
		/*
		 * Out of memory
		 */
		return (NULL);
	}

	newp->resource = strdup(mnttab_entry.mnt_special);
	if (newp->resource == NULL) {
		/*
		 *  Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->mountp = strdup(mnttab_entry.mnt_mountp);
	if (newp->mountp == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->fstype = strdup(mnttab_entry.mnt_fstype);
	if (newp->fstype == NULL) {
		/*
		 *  Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->mntopts = strdup(mnttab_entry.mnt_mntopts);
	if (newp->mntopts == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->time = strdup(mnttab_entry.mnt_time);
	if (newp->time == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->next = NULL;

	return (newp);
} /* create_mntlist_entry */

static fs_mntlist_t *
create_extmntlist_entry(struct extmnttab mnttab_entry) {

	fs_mntlist_t	*newp;

	newp = (fs_mntlist_t *)calloc((size_t)1,
		(size_t)sizeof (fs_mntlist_t));

	if (newp == NULL) {
		/*
		 * Out of memory
		 */
		return (NULL);
	}

	newp->resource = strdup(mnttab_entry.mnt_special);
	if (newp->resource == NULL) {
		/*
		 *  Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->mountp = strdup(mnttab_entry.mnt_mountp);
	if (newp->mountp == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->fstype = strdup(mnttab_entry.mnt_fstype);
	if (newp->fstype == NULL) {
		/*
		 *  Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->mntopts = strdup(mnttab_entry.mnt_mntopts);
	if (newp->mntopts == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->time = strdup(mnttab_entry.mnt_time);
	if (newp->time == NULL) {
		/*
		 * Out of memory
		 */
		fs_free_mount_list(newp);
		return (NULL);
	}
	newp->major = mnttab_entry.mnt_major;

	newp->minor = mnttab_entry.mnt_minor;

	newp->next = NULL;

	return (newp);
} /* create_extmntlist_entry */

static struct mnttab *
create_mnttab_filter(char *resource, char *mountp, char *fstype, char *mntopts,
	char *time) {

	struct mnttab	*search_entry;

	search_entry = (struct mnttab *)calloc((size_t)1,
		(size_t)sizeof (struct mnttab));

	if (search_entry == NULL) {
		/*
		 * Out of memory
		 */
		return (NULL);
	}

	if (resource != NULL) {
		search_entry->mnt_special = strdup(resource);
		if (search_entry->mnt_special == NULL) {
			/*
			 * Out of memory
			 */
			free_mnttab_entry(search_entry);
			return (NULL);
		}
	}

	if (mountp != NULL) {
		search_entry->mnt_mountp = strdup(mountp);
		if (search_entry->mnt_mountp == NULL) {
			/*
			 * Out of memory
			 */
			free_mnttab_entry(search_entry);
			return (NULL);
		}
	}

	if (fstype != NULL) {
		search_entry->mnt_fstype = strdup(fstype);
		if (search_entry->mnt_fstype == NULL) {
			/*
			 * Out of memory
			 */
			free_mnttab_entry(search_entry);
			return (NULL);
		}
	}

	if (mntopts != NULL) {
		search_entry->mnt_mntopts = strdup(mntopts);
		if (search_entry->mnt_mntopts == NULL) {
			/*
			 * Out of memory
			 */
			free_mnttab_entry(search_entry);
			return (NULL);
		}
	}

	if (time != NULL) {
		search_entry->mnt_time = strdup(time);
		if (search_entry->mnt_time == NULL) {
			/*
			 * Out of memory
			 */
			free_mnttab_entry(search_entry);
			return (NULL);
		}
	}

	return (search_entry);
} /* create_mnttab_filter */

/*
 * We will go through the /etc/mnttab entries to determine the
 * instances of overlayed file systems.  We do this with the following
 * assumptions:
 *
 * 1.) Entries in mnttab are ordered in the way that the most recent
 * mounts are placed at the bottom of /etc/mnttab.  Contract to be
 * filed:
 * 2.) Mnttab entries that are returned from all mnttab library
 * functions such as getmntent, getextmntent, and getmntany in the order
 * as they are found in /etc/mnttab.  Goes along with assumption #1.
 * 3.) All automounted NFS file systems will have an autofs entry and
 * a NFS entry in /etc/mnttab with the same mount point.  Autofs
 * entries can be ignored.
 * 4.) The device id (dev=) uniquely identifies a mounted file system
 * on a host.
 *
 * Algorithm explanation:
 * ----------------------
 * For each mnt_list entry
 * 1.) Compare it to each /etc/mnttab entry starting at the point in mnttab
 * where the mnt_list entry mount is and look for matching mount points,
 * but ignore all "autofs" entries
 *      If a two entries are found with the same mount point mark the mnt_list
 *	entry as being overlayed.
 */
static void
find_overlayed_filesystems(fs_mntlist_t *mnt_list,
	boolean_t filtered_list, int *errp) {

	boolean_t exit = B_FALSE;
	fs_mntlist_t *mnt_list_to_compare;
	fs_mntlist_t *tmp;

	*errp = 0;
	if (filtered_list == B_TRUE) {
		/*
		 * Get the complete mount list
		 */
		mnt_list_to_compare = fs_get_mount_list(B_FALSE, errp);
		if (mnt_list_to_compare == NULL) {
			/*
			 * If complete_mnt_list is NULL there are two
			 * possibilites:
			 * 1.) There are simply no entries in /etc/mnttab.
			 * 2.) An error was encountered.  errp will reflect
			 * the error.
			 */

			return;
		}
	} else {
		mnt_list_to_compare = mnt_list;
	}

	tmp = mnt_list_to_compare;

	while (mnt_list != NULL) {
		if (!(strcmp(mnt_list->fstype, "autofs") == 0)) {
			char *dev_id;

			dev_id = fs_parse_optlist_for_option(mnt_list->mntopts,
				"dev=", errp);
			if (dev_id == NULL) {
				return;
			}

			exit = B_FALSE;
			while (tmp != NULL && exit == B_FALSE) {
				if (!(strcmp(tmp->fstype, "autofs")) == 0) {
					char *tmp_dev_id;

					tmp_dev_id =
						fs_parse_optlist_for_option(
						tmp->mntopts, "dev=", errp);
					if (tmp_dev_id == NULL) {
						return;
					}

					if (strcmp(tmp_dev_id, dev_id) == 0) {
						/*
						 * Start searching for an
						 * overlay here.
						 */
						mnt_list->overlayed =
							is_overlayed(tmp,
							mnt_list->mountp);
						exit = B_TRUE;
					}
					free(tmp_dev_id);
				}
				tmp = tmp->next;
			} /* while (tmp != NULL && exit == B_FALSE) */
			free(dev_id);
		} /* if (!(strcmp(mnt_list->fstype, "autofs") == 0)) */
		mnt_list = mnt_list->next;
	} /* while (mnt_list != NULL) */

	if (filtered_list == B_TRUE)
		fs_free_mount_list(mnt_list_to_compare);
} /* find_overlayed_filesystems */

static void
free_mnttab_entry(struct mnttab *mnttab_entry) {

	free(mnttab_entry->mnt_special);
	free(mnttab_entry->mnt_mountp);
	free(mnttab_entry->mnt_fstype);
	free(mnttab_entry->mnt_mntopts);
	free(mnttab_entry->mnt_time);

	free(mnttab_entry);

} /* free_mnttab_entry */

char *
is_option(char *opt_string, char *opt, int *errp) {
	char *equalsign = "=";
	char *found_equalsign;
	char *return_val;

	*errp = 0;
	found_equalsign = strstr(opt, equalsign);

	/*
	 * If found_equalsign is NULL then we did not find an equal sign
	 * in the option we are to be looking for.
	 */
	if (found_equalsign == NULL) {
		if (strcmp(opt_string, opt) == 0) {
			/*
			 * We have found the option so return with success.
			 */
			return_val = strdup(opt);
			if (return_val == NULL) {
				*errp = errno;
				return (NULL);
			}
		} else {
			return_val = NULL;
		}
	} else {
		int counter = 0;
		char *opt_found;
		char *value;

		opt_found = strstr(opt_string, opt);

		if (opt_found == NULL) {
			return_val = NULL;
		} else {
			size_t opt_string_len;
			size_t opt_len;
			size_t value_len;

			opt_string_len = strlen(opt_string);
			opt_len = strlen(opt);

			value_len = opt_string_len - opt_len;

			value = (char *)calloc((size_t)(value_len+1),
				(size_t)sizeof (char));

			if (value == NULL) {
				/*
				 * Out of memory
				 */
				*errp = ENOMEM;
				return (NULL);

			}

			while (counter <= (value_len-1)) {
				value[counter] = opt_string[opt_len+counter];
				counter = counter + 1;
			}
			/*
			 * Add the null terminating character.
			 */
			value[counter] = '\0';
			return_val = value;
		}
	} /* else */

	return (return_val);
} /* is_option */


boolean_t
is_overlayed(fs_mntlist_t *mnt_list, char *mountp) {
	boolean_t ret_val = B_FALSE;

	/*
	 * The first entry in the complete_mnt_list is the same mounted
	 * file system as the one we are trying to determine whether it is
	 * overlayed or not.  There is no need to compare these mounts.
	 */
	mnt_list = mnt_list->next;

	while (mnt_list != NULL && ret_val == B_FALSE) {
		if (!(strcmp(mnt_list->fstype, "autofs") == 0)) {
			if (strcmp(mnt_list->mountp, mountp) == 0) {
				ret_val = B_TRUE;
			} else {
				ret_val = B_FALSE;
			}
		}
		mnt_list = mnt_list->next;
	}
	return (ret_val);
} /* is_overlayed */
