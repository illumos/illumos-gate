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
 * Traverses /etc/vfstab in order to find default mount information about
 * file systems on the current host.
 */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/vfstab.h>
#include <sys/types.h>
#include <strings.h>
#include <thread.h>
#include <synch.h>
#include "libfsmgt.h"

/*
 * Private constants
 */

static const char sepstr[] = "\t\n";

/*
 * Private variables
 */
static mutex_t		vfstab_lock = DEFAULTMUTEX;


/*
 * Private method declarations
 */
static int cmp_fields(char *, char *, int);
static fs_mntdefaults_t	*create_mntdefaults_entry(struct vfstab vfstab_entry,
					    int *errp);
static struct vfstab	*create_vfstab_filter(fs_mntdefaults_t *filter,
					    int *errp);
static void		free_vfstab_entry(struct vfstab *vfstab_entry);
static char		*create_vfstab_entry_line(struct vfstab *, int *);
static int		vfstab_line_cmp(fs_mntdefaults_t *, struct vfstab *);

/*
 * Public methods
 */

void fs_free_mntdefaults_list(fs_mntdefaults_t *headp) {
	fs_mntdefaults_t	*tmp;

	while (headp != NULL) {
		tmp = headp->next;
		free(headp->resource);
		free(headp->fsckdevice);
		free(headp->mountp);
		free(headp->fstype);
		free(headp->fsckpass);
		free(headp->mountatboot);
		free(headp->mntopts);
		headp->next = NULL;
		free(headp);

		headp = tmp;
	}
} /* fs_free_mntdefaults_list */

/*
 * Filter by the fields that are filled in on the filter parameter.
 * Fields that aren't used in filtering the defaults will be NULL.
 */
fs_mntdefaults_t *fs_get_filtered_mount_defaults(fs_mntdefaults_t *filter,
    int *errp) {

	fs_mntdefaults_t	*newp;
	fs_mntdefaults_t	*headp;
	fs_mntdefaults_t	*tailp;
	FILE			*fp;

	headp = NULL;
	tailp = NULL;


	if ((fp = fopen(VFSTAB, "r")) != NULL) {
		struct vfstab	vfstab_entry;
		struct vfstab	*search_entry;
		(void) mutex_lock(&vfstab_lock);
		search_entry = create_vfstab_filter(filter, errp);
		if (search_entry == NULL) {
			/*
			 * Out of memory, the error pointer (errp) gets
			 * set in create_vfstab_filter.
			 */
			fs_free_mntdefaults_list(headp);
			(void) mutex_unlock(&vfstab_lock);
			(void) fclose(fp);
			return (NULL);
		}

		while (getvfsany(fp, &vfstab_entry, search_entry) == 0) {
			/*
			 * Add to list to be returned
			 */
			newp = create_mntdefaults_entry(vfstab_entry, errp);
			if (newp == NULL) {
				/*
				 * Out of memory, the error pointer (errp)
				 * gets set in create_mntdefaults_entry.
				 */
				fs_free_mntdefaults_list(headp);
				(void) mutex_unlock(&vfstab_lock);
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
		}
		free_vfstab_entry(search_entry);
		(void) mutex_unlock(&vfstab_lock);
		(void) fclose(fp);

	} else {
		*errp = errno;
	} /* if ((fp = fopen(VFSTAB, "r")) != NULL) */

	return (headp);
} /* fs_get_filtered_mount_defaults */


fs_mntdefaults_t *
fs_get_mount_defaults(int *errp)
{
	fs_mntdefaults_t	*newp;
	fs_mntdefaults_t	*headp;
	fs_mntdefaults_t	*tailp;
	FILE			*fp;

	headp = NULL;
	tailp = NULL;

	if ((fp = fopen(VFSTAB, "r")) != NULL) {
		struct vfstab 	vfstab_entry;
		(void) mutex_lock(&vfstab_lock);
		while (getvfsent(fp, &vfstab_entry) == 0) {
			/*
			 * Add entry to list
			 */
			newp = create_mntdefaults_entry(vfstab_entry, errp);

			if (newp == NULL) {
				/*
				 * Out of memory, the error pointer (errp)
				 * gets set in create_mntdefaults_entry.
				 */
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				fs_free_mntdefaults_list(headp);
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
		(void) fclose(fp);
		(void) mutex_unlock(&vfstab_lock);
	} else {
		*errp = errno;
	} /* if ((fp = fopen(VFSTAB, "r")) != NULL) */

	/*
	 * Caller must free the returned list
	 */
	return (headp);

} /* fs_get_mount_defaults */

fs_mntdefaults_t *
fs_add_mount_default(fs_mntdefaults_t *newp, int *errp) {

	FILE *fp;
	struct vfstab *new_entry;
	fs_mntdefaults_t *ret_val;

	new_entry = create_vfstab_filter(newp, errp);
	if (new_entry != NULL) {
		if ((fp = fopen(VFSTAB, "a")) != NULL) {
			(void) mutex_lock(&vfstab_lock);
			putvfsent(fp, new_entry);
			free_vfstab_entry(new_entry);
			(void) fclose(fp);
			(void) mutex_unlock(&vfstab_lock);
			ret_val = fs_get_mount_defaults(errp);
		} else {
			*errp = errno;
			free_vfstab_entry(new_entry);
			ret_val = NULL;
		}
	} else {
		ret_val = NULL;
	}
	return (ret_val);
} /* fs_add_mount_default */


fs_mntdefaults_t *
fs_edit_mount_defaults(
    fs_mntdefaults_t *old_vfstab_ent,
    fs_mntdefaults_t *new_vfstab_ent,
    int *errp)
{
	FILE *fp;
	fs_mntdefaults_t *ret_val;
	char vfstab_line[VFS_LINE_MAX];
	char **temp_vfstab = NULL;
	char *new_line;
	struct vfstab vfstabp, *new_vfstab;
	int line_found = 0;

	if ((fp = fopen(VFSTAB, "r")) != NULL) {
		char *tmp;
		int count = 0;
		(void) mutex_lock(&vfstab_lock);
		while (fgets(vfstab_line, VFS_LINE_MAX, fp) != NULL) {
			char *charp;
			struct vfstab *vp;
			char *orig_line = strdup(vfstab_line);
			if (orig_line == NULL) {
				*errp = ENOMEM;
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				return (NULL);
			}
			vp = &vfstabp;
			for (charp = vfstab_line;
			    *charp == ' ' || *charp == '\t'; charp++);
			if (*charp == '#' || *charp == '\n') {
				/*
				 * Write comments out to temp vfstab
				 * image
				 */
				if (!fileutil_add_string_to_array(
				    &temp_vfstab, vfstab_line, &count, errp)) {
				    ret_val = NULL;
				    line_found = 0;
					break;
				}
				continue;
			}
			vp->vfs_special = (char *)strtok_r(
			    vfstab_line, sepstr, &tmp);
			vp->vfs_fsckdev = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_mountp = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_fstype = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_fsckpass = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_automnt = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_mntopts = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			if (strtok_r(NULL, sepstr, &tmp) != NULL) {
				/*
				 * Invalid vfstab line.
				 */
				*errp = EINVAL;
				(void) mutex_unlock(&vfstab_lock);
				(void) fclose(fp);
				return (NULL);
			}

			if (vfstab_line_cmp(old_vfstab_ent, vp)) {
				line_found = 1;
				new_vfstab =
				    create_vfstab_filter(
				    new_vfstab_ent, errp);
				new_line =
				    create_vfstab_entry_line(new_vfstab, errp);
				if (!fileutil_add_string_to_array(
				    &temp_vfstab, new_line, &count, errp)) {
					ret_val = NULL;
					line_found = 0;
					free(new_line);
					break;
				}
				free(new_line);
			} else {
				if (!fileutil_add_string_to_array(
				    &temp_vfstab, orig_line, &count, errp)) {
					ret_val = NULL;
					line_found = 0;
					break;
				}
			}
			free(orig_line);
		}
		(void) fclose(fp);

		if (line_found && temp_vfstab != NULL) {
			if ((fp = fopen(VFSTAB, "w")) != NULL) {
				int i;
				for (i = 0; i < count; i++) {
					fprintf(fp, "%s", temp_vfstab[i]);
				}
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				ret_val = fs_get_mount_defaults(errp);
				fileutil_free_string_array(temp_vfstab, count);
			} else {
				*errp = errno;
				(void) mutex_unlock(&vfstab_lock);
				ret_val = NULL;
			}
		} else {
			*errp = errno;
			(void) mutex_unlock(&vfstab_lock);
			ret_val = NULL;
		}
	} else {
		*errp = errno;
		ret_val = NULL;
	}
	return (ret_val);
} /* fs_edit_mount_defaults */

fs_mntdefaults_t *
fs_del_mount_default_ent(fs_mntdefaults_t *old_vfstab_ent, int *errp)
{
	FILE *fp;
	fs_mntdefaults_t *ret_val;
	char vfstab_line[VFS_LINE_MAX];
	struct vfstab vfstabp;
	int line_found = 0;

	if ((fp = fopen(VFSTAB, "r")) != NULL) {
		struct vfstab *vp;
		char *tmp;
		char *charp;
		char *orig_line = NULL;
		char **temp_vfstab = NULL;
		int count = 0;
		vp = &vfstabp;
		(void) mutex_lock(&vfstab_lock);
		while (fgets(vfstab_line, VFS_LINE_MAX, fp) != NULL) {

			orig_line = strdup(vfstab_line);
			if (orig_line == NULL) {
				*errp = ENOMEM;
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				return (NULL);
			}

			for (charp = vfstab_line;
			    *charp == ' ' || *charp == '\t'; charp++);

			if (*charp == '#' || *charp == '\n') {
				/*
				 * Write comments out to temp vfstab
				 * image
				 */
				if (!fileutil_add_string_to_array(
				    &temp_vfstab, vfstab_line, &count, errp)) {
					ret_val = NULL;
					line_found = 0;
					free(orig_line);
					break;
				}
				continue;
			}

			vp->vfs_special = (char *)strtok_r(
			    vfstab_line, sepstr, &tmp);
			vp->vfs_fsckdev = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_mountp = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_fstype = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_fsckpass = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_automnt = (char *)strtok_r(
			    NULL, sepstr, &tmp);
			vp->vfs_mntopts = (char *)strtok_r(
			    NULL, sepstr, &tmp);

			if (strtok_r(NULL, sepstr, &tmp) != NULL) {
				/*
				 * Invalid vfstab line.
				 */
				*errp = EINVAL;
				free(orig_line);
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				return (NULL);
			}

			if (vfstab_line_cmp(old_vfstab_ent, vp)) {
				line_found = 1;
			} else {
				if (!fileutil_add_string_to_array(
				    &temp_vfstab, orig_line, &count, errp)) {
					ret_val = NULL;
					line_found = 0;
					free(orig_line);
					break;
				}
			}
			free(orig_line);
		}

		(void) fclose(fp);

		if (line_found && temp_vfstab != NULL) {
			if ((fp = fopen(VFSTAB, "w")) != NULL) {
				int i;
				for (i = 0; i < count; i++) {
					fprintf(fp, "%s", temp_vfstab[i]);
				}
				(void) fclose(fp);
				(void) mutex_unlock(&vfstab_lock);
				ret_val = fs_get_mount_defaults(errp);
				fileutil_free_string_array(temp_vfstab, count);
			} else {
				*errp = errno;
				(void) mutex_unlock(&vfstab_lock);
				fileutil_free_string_array(temp_vfstab, count);
				ret_val = NULL;
			}
		} else {
			(void) mutex_unlock(&vfstab_lock);
			if (temp_vfstab != NULL) {
				fileutil_free_string_array(temp_vfstab, count);
			}
			ret_val = NULL;
		}
	} else {
		*errp = errno;
		ret_val = NULL;
	}
	return (ret_val);
}

/*
 * Private methods
 */

static fs_mntdefaults_t *
create_mntdefaults_entry(struct vfstab vfstab_entry, int *errp) {
	fs_mntdefaults_t	*newp;

	newp = (fs_mntdefaults_t *)calloc((size_t)1,
	    (size_t)sizeof (fs_mntdefaults_t));

	if (newp == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		return (NULL);
	}


	if (vfstab_entry.vfs_special != NULL) {
		newp->resource = strdup(vfstab_entry.vfs_special);
		if (newp->resource == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}


	if (vfstab_entry.vfs_fsckdev != NULL) {
		newp->fsckdevice = strdup(vfstab_entry.vfs_fsckdev);
		if (newp->fsckdevice == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}

	if (vfstab_entry.vfs_mountp != NULL) {
		newp->mountp = strdup(vfstab_entry.vfs_mountp);
		if (newp->mountp == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}

	if (vfstab_entry.vfs_fstype != NULL) {
		newp->fstype = strdup(vfstab_entry.vfs_fstype);
		if (newp->fstype == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}

	if (vfstab_entry.vfs_fsckpass != NULL) {
		newp->fsckpass = strdup(vfstab_entry.vfs_fsckpass);
		if (newp->fsckpass == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}

	if (vfstab_entry.vfs_automnt != NULL) {
		newp->mountatboot = strdup(vfstab_entry.vfs_automnt);
		if (newp->mountatboot == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}

	if (vfstab_entry.vfs_mntopts != NULL) {
		newp->mntopts = strdup(vfstab_entry.vfs_mntopts);
		if (newp->mntopts == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			fs_free_mntdefaults_list(newp);
			return (NULL);
		}
	}
	newp->next = NULL;

	return (newp);

} /* create_mntdefaults_entry */

static struct vfstab *
create_vfstab_filter(fs_mntdefaults_t *filter, int *errp) {
	struct vfstab *search_entry;

	search_entry = (struct vfstab *)calloc((size_t)1,
	    (size_t)sizeof (struct vfstab));
	if (search_entry == NULL) {
		/*
		 * Out of memory
		 */
		*errp = errno;
		return (NULL);
	}

	/*
	 * Populate the filter criteria
	 */
	if (filter->resource != NULL) {
		search_entry->vfs_special = strdup(filter->resource);
		if (search_entry->vfs_special == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}

	}

	if (filter->fsckdevice != NULL) {
		search_entry->vfs_fsckdev = strdup(filter->fsckdevice);
		if (search_entry->vfs_fsckdev ==  NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	if (filter->mountp != NULL) {
		search_entry->vfs_mountp = strdup(filter->mountp);
		if (search_entry->vfs_mountp == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	if (filter->fstype != NULL) {
		search_entry->vfs_fstype = strdup(filter->fstype);
		if (search_entry->vfs_fstype == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	if (filter->fsckpass != NULL) {
		search_entry->vfs_fsckpass = strdup(filter->fsckpass);
		if (search_entry->vfs_fsckpass == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	if (filter->mountatboot != NULL) {
		search_entry->vfs_automnt = strdup(filter->mountatboot);
		if (search_entry->vfs_automnt == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	if (filter->mntopts != NULL) {
		search_entry->vfs_mntopts = strdup(filter->mntopts);
		if (search_entry->vfs_mntopts == NULL) {
			/*
			 * Out of memory
			 */
			*errp = errno;
			free_vfstab_entry(search_entry);
			return (NULL);
		}
	}

	return (search_entry);
} /* create_vfstab_filter */

static void free_vfstab_entry(struct vfstab *vfstab_entry) {

	free(vfstab_entry->vfs_special);
	free(vfstab_entry->vfs_fsckdev);
	free(vfstab_entry->vfs_mountp);
	free(vfstab_entry->vfs_fstype);
	free(vfstab_entry->vfs_fsckpass);
	free(vfstab_entry->vfs_automnt);
	free(vfstab_entry->vfs_mntopts);

	free(vfstab_entry);
} /* free_vfstab_entry */

static int
vfstab_line_cmp(fs_mntdefaults_t *mntdftp, struct vfstab *vp) {

	int ret_val = 1;

	ret_val = cmp_fields(mntdftp->resource, vp->vfs_special, ret_val);
	ret_val = cmp_fields(mntdftp->mountp, vp->vfs_mountp, ret_val);

	return (ret_val);
} /* vfstab_line_cmp */

/*
 * Helper function for comparing fields in a fs_mntdefaults_t to a
 * vfstab structure. Used in vfstab_line_cmp().
 */
static int
cmp_fields(char *mntdflt_str, char *vfstab_str, int ret_val) {
	if (ret_val != 0) {
		if (mntdflt_str != NULL && vfstab_str != NULL) {
			if (strcmp(mntdflt_str, vfstab_str) != 0) {
				ret_val = 0;
			}
		} else if (mntdflt_str == NULL || vfstab_str == NULL) {
			ret_val = 0;
		}
	}
	return (ret_val);
} /* cmp_fields */

/*
 * Helper fuction used by del_vfstab_ent() and edit_vfstab_ent() to
 * create a vfstab line for writing out to the vfstab file.
 */
char *
create_vfstab_entry_line(struct vfstab *vfstab_ent, int *errp) {
	char *line;
	int line_length;
	line_length = (
	    (vfstab_ent->vfs_special ?
		(strlen(vfstab_ent->vfs_special) +1) : 2) +
	    (vfstab_ent->vfs_fsckdev ?
		(strlen(vfstab_ent->vfs_fsckdev) +1) : 2) +
	    (vfstab_ent->vfs_mountp ?
		(strlen(vfstab_ent->vfs_mountp) +1) : 2) +
	    (vfstab_ent->vfs_fstype ?
		(strlen(vfstab_ent->vfs_fstype) +1) : 2) +
	    (vfstab_ent->vfs_fsckpass ?
		(strlen(vfstab_ent->vfs_fsckpass) +1) : 2) +
	    (vfstab_ent->vfs_automnt ?
		(strlen(vfstab_ent->vfs_automnt) +1) : 2) +
	    (vfstab_ent->vfs_mntopts ?
		(strlen(vfstab_ent->vfs_mntopts) +1) : 2));
	line = (char *)malloc(line_length + 1);
	if (line != NULL) {
		sprintf(line, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		    vfstab_ent->vfs_special ? vfstab_ent->vfs_special : "-",
		    vfstab_ent->vfs_fsckdev ? vfstab_ent->vfs_fsckdev : "-",
		    vfstab_ent->vfs_mountp ? vfstab_ent->vfs_mountp : "-",
		    vfstab_ent->vfs_fstype ? vfstab_ent->vfs_fstype : "-",
		    vfstab_ent->vfs_fsckpass ? vfstab_ent->vfs_fsckpass : "-",
		    vfstab_ent->vfs_automnt ? vfstab_ent->vfs_automnt : "-",
		    vfstab_ent->vfs_mntopts ? vfstab_ent->vfs_mntopts : "-");
	} else {
		*errp = errno;
	}
	return (line);
} /* create_vfstab_entry_line */
