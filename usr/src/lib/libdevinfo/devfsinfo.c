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


#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/modctl.h>
#include <errno.h>
#include <sys/openpromio.h>
#include <ftw.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <limits.h>

#include "device_info.h"

/*
 * #define's
 */

/* alias node searching return values */
#define	NO_MATCH	-1
#define	EXACT_MATCH	1
#define	INEXACT_MATCH	2

/* for prom io operations */
#define	BUFSIZE		4096
#define	MAXPROPSIZE	256
#define	MAXVALSIZE	(BUFSIZE - MAXPROPSIZE - sizeof (uint_t))

/* prom_obp_vers() return values */
#define	OBP_OF			0x4	/* versions OBP 3.x */
#define	OBP_NO_ALIAS_NODE	0x8	/* No alias node */

/* for nftw call */
#define	FT_DEPTH	15

/* default logical and physical device name space */
#define	DEV	"/dev"
#define	DEVICES	"/devices"

/* for boot device identification on x86 */
#define	CREATE_DISKMAP		"/boot/solaris/bin/create_diskmap"
#define	GRUBDISK_MAP		"/var/run/solaris_grubdisk.map"

/*
 * internal structure declarations
 */

/* for prom io functions */
typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} Oppbuf;

/* used to manage lists of devices and aliases */
struct name_list {
	char *name;
	struct name_list *next;
};

/*
 * internal global data
 */

/* global since nftw does not let you pass args to be updated */
static struct name_list **dev_list;

/* global since nftw does not let you pass args to be updated */
static struct boot_dev **bootdev_list;

/* mutex to protect bootdev_list and dev_list */
static mutex_t dev_lists_lk = DEFAULTMUTEX;

/*
 * internal function prototypes
 */

static int prom_open(int);
static void prom_close(int);
static int is_openprom(int);

static int prom_dev_to_alias(char *dev, uint_t options, char ***ret_buf);
static int alias_to_prom_dev(char *alias, char *ret_buf);
static int prom_srch_aliases_by_def(char *, struct name_list **,
    struct name_list **, int);
static int prom_find_aliases_node(int fd);
static int prom_compare_devs(char *prom_dev1, char *prom_dev2);
static int _prom_strcmp(char *s1, char *s2);
static int prom_srch_node(int fd, char *prop_name, char *ret_buf);
static uint_t prom_next_node(int fd, uint_t node_id);
static uint_t prom_child_node(int fd, uint_t node_id);

static int prom_obp_vers(void);

static void parse_name(char *, char **, char **, char **);
static int process_bootdev(const char *, const char *, struct boot_dev ***);
static int process_minor_name(char *dev_path, const char *default_root);
static void options_override(char *prom_path, char *alias_name);
static int devfs_phys_to_logical(struct boot_dev **bootdev_array,
	const int array_size, const char *default_root);
static int check_logical_dev(const char *, const struct stat *, int,
	struct FTW *);
static struct boot_dev *alloc_bootdev(char *);
static void free_name_list(struct name_list *list, int free_name);
static int insert_alias_list(struct name_list **list,
	char *alias_name);
static int get_boot_dev_var(struct openpromio *opp);
static int set_boot_dev_var(struct openpromio *opp, char *bootdev);
static int devfs_prom_to_dev_name(char *prom_path, char *dev_path);
static int devfs_dev_to_prom_names(char *dev_path, char *prom_path, size_t len);

/*
 * frees a list of paths from devfs_get_prom_name_list
 */
static void
prom_list_free(char **prom_list)
{
	int i = 0;

	if (!prom_list)
		return;

	while (prom_list[i]) {
		free(prom_list[i]);
		i++;
	}
	free(prom_list);
}

static int
devfs_get_prom_name_list(const char *dev_name, char ***prom_list)
{
	char *prom_path = NULL;
	int count = 0;		/* # of slots we will need in prom_list */
	int ret, i, len;
	char **list;
	char *ptr;

	if (dev_name == NULL)
		return (DEVFS_INVAL);
	if (*dev_name != '/')
		return (DEVFS_INVAL);
	if (prom_list == NULL)
		return (DEVFS_INVAL);

	/*
	 * make sure we are on a machine which supports a prom
	 * and we have permission to use /dev/openprom
	 */
	if ((ret = prom_obp_vers()) < 0)
		return (ret);
	if ((prom_path = (char *)malloc(MAXVALSIZE)) == NULL)
		return (DEVFS_NOMEM);
	/*
	 * get the prom path name
	 */
	ret = devfs_dev_to_prom_names((char *)dev_name, prom_path, MAXVALSIZE);
	if (ret < 0) {
		free(prom_path);
		return (ret);
	}
	/* deal with list of names */
	for (i = 0; i < ret; i++)
		if (prom_path[i] == '\0')
			count++;

	if ((list = (char **)calloc(count + 1, sizeof (char *))) == NULL) {
		free(prom_path);
		return (DEVFS_NOMEM);
	}

	ptr = prom_path;
	for (i = 0; i < count; i++) {
		len = strlen(ptr) + 1;
		if ((list[i] = (char *)malloc(len)) == NULL) {
			free(prom_path);
			free(list);
			return (DEVFS_NOMEM);
		}
		(void) snprintf(list[i], len, "%s", ptr);
		ptr += len;
	}

	free(prom_path);

	*prom_list = list;
	return (0);
}

/*
 * retrieve the list of prom representations for a given device name
 * the list will be sorted in the following order: exact aliases,
 * inexact aliases, prom device path name.  If multiple matches occur
 * for exact or inexact aliases, then these are sorted in collating
 * order. The list is returned in prom_list
 *
 * the list may be restricted by specifying the correct flags in options.
 */
int
devfs_get_prom_names(const char *dev_name, uint_t options, char ***prom_list)
{
	char *prom_path = NULL;
	int count = 0;		/* # of slots we will need in prom_list */
	char **alias_list = NULL;
	char **list;
	int ret;

	if (dev_name == NULL) {
		return (DEVFS_INVAL);
	}
	if (*dev_name != '/') {
		return (DEVFS_INVAL);
	}
	if (prom_list == NULL) {
		return (DEVFS_INVAL);
	}
	/*
	 * make sure we are on a machine which supports a prom
	 * and we have permission to use /dev/openprom
	 */
	if ((ret = prom_obp_vers()) < 0) {
		return (ret);
	}
	if ((prom_path = (char *)malloc(MAXPATHLEN)) == NULL) {
		return (DEVFS_NOMEM);
	}
	/*
	 * get the prom path name
	 */
	ret = devfs_dev_to_prom_name((char *)dev_name, prom_path);
	if (ret < 0) {
		free(prom_path);
		return (ret);
	}
	/* get the list of aliases (exact and inexact) */
	if ((ret = prom_dev_to_alias(prom_path, options, &alias_list)) < 0) {
		free(prom_path);
		return (ret);
	}
	/* now figure out how big the return array must be */
	if (alias_list != NULL) {
		while (alias_list[count] != NULL) {
			count++;
		}
	}
	if ((options & BOOTDEV_NO_PROM_PATH) == 0) {
		count++;	/* # of slots we will need in prom_list */
	}
	count++;	/* for the null terminator */

	/* allocate space for the list */
	if ((list = (char **)calloc(count, sizeof (char *))) == NULL) {
		count = 0;
		while ((alias_list) && (alias_list[count] != NULL)) {
			free(alias_list[count]);
			count++;
		}
		free(alias_list);
		free(prom_path);
		return (DEVFS_NOMEM);
	}
	/* fill in the array and free the name list of aliases. */
	count = 0;
	while ((alias_list) && (alias_list[count] != NULL)) {
		list[count] = alias_list[count];
		count++;
	}
	if ((options & BOOTDEV_NO_PROM_PATH) == 0) {
		list[count] = prom_path;
	}
	if (alias_list != NULL) {
		free(alias_list);
	}
	*prom_list = list;
	return (0);
}

/*
 * Get a list prom-path translations for a solaris device.
 *
 * Returns the number of and all OBP paths and alias variants that
 * reference the Solaris device path passed in.
 */
int
devfs_get_all_prom_names(const char *solaris_path, uint_t flags,
    struct devfs_prom_path **paths)
{
	int ret, len, i, count = 0;
	char *ptr, *prom_path;
	struct devfs_prom_path *cur = NULL, *new;

	if ((ret = prom_obp_vers()) < 0)
		return (ret);
	if ((prom_path = (char *)malloc(MAXVALSIZE)) == NULL)
		return (DEVFS_NOMEM);

	if ((ret = devfs_dev_to_prom_names((char *)solaris_path,
	    prom_path, MAXVALSIZE)) < 0) {
		free(prom_path);
		return (ret);
	}

	for (i = 0; i < ret; i++)
		if (prom_path[i] == '\0')
			count++;

	*paths = NULL;
	ptr = prom_path;
	for (i = 0; i < count; i++) {
		if ((new = (struct devfs_prom_path *)calloc(
		    sizeof (struct devfs_prom_path), 1)) == NULL) {
			free(prom_path);
			devfs_free_all_prom_names(*paths);
			return (DEVFS_NOMEM);
		}

		if (cur == NULL)
			*paths = new;
		else
			cur->next = new;
		cur = new;

		len = strlen(ptr) + 1;
		if ((cur->obp_path = (char *)calloc(len, 1)) == NULL) {
			free(prom_path);
			devfs_free_all_prom_names(*paths);
			return (DEVFS_NOMEM);
		}

		(void) snprintf(cur->obp_path, len, "%s", ptr);
		ptr += len;
		if ((ret = prom_dev_to_alias(cur->obp_path, flags,
		    &(cur->alias_list))) < 0) {
			free(prom_path);
			devfs_free_all_prom_names(*paths);
			return (ret);
		}
	}

	free(prom_path);
	return (count);
}

void
devfs_free_all_prom_names(struct devfs_prom_path *paths)
{
	int i;

	if (paths == NULL)
		return;

	devfs_free_all_prom_names(paths->next);

	if (paths->obp_path != NULL)
		free(paths->obp_path);

	if (paths->alias_list != NULL) {
		for (i = 0; paths->alias_list[i] != NULL; i++)
			if (paths->alias_list[i] != NULL)
				free(paths->alias_list[i]);

		free(paths->alias_list);
	}

	free(paths);
}

/*
 * Accepts a device name as an input argument.  Uses this to set the
 * boot-device (or like) variable
 *
 * By default, this routine prepends to the list and converts the
 * logical device name to its most compact prom representation.
 * Available options include: converting the device name to a prom
 * path name (but not an alias) or performing no conversion at all;
 * overwriting the existing contents of boot-device rather than
 * prepending.
 */
int
devfs_bootdev_set_list(const char *dev_name, const uint_t options)
{
	char *prom_path;
	char *new_bootdev;
	char *ptr;
	char **alias_list = NULL;
	char **prom_list = NULL;
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int ret, len, i, j;

	if (devfs_bootdev_modifiable() != 0) {
		return (DEVFS_NOTSUP);
	}
	if (dev_name == NULL) {
		return (DEVFS_INVAL);
	}
	if (strlen(dev_name) >= MAXPATHLEN)
		return (DEVFS_INVAL);

	if ((*dev_name != '/') && !(options & BOOTDEV_LITERAL)) {
		return (DEVFS_INVAL);
	}
	if ((options & BOOTDEV_LITERAL) && (options & BOOTDEV_PROMDEV)) {
		return (DEVFS_INVAL);
	}
	/*
	 * if we are prepending, make sure that this obp rev
	 * supports multiple boot device entries.
	 */
	ret = prom_obp_vers();
	if (ret < 0) {
		return (ret);
	}

	if ((prom_path = (char *)malloc(MAXVALSIZE)) == NULL) {
		return (DEVFS_NOMEM);
	}
	if (options & BOOTDEV_LITERAL) {
		(void) strcpy(prom_path, dev_name);
	} else {
		/* need to convert to prom representation */
		ret = devfs_get_prom_name_list(dev_name, &prom_list);
		if (ret < 0) {
			free(prom_path);
			return (ret);
		}

		len = MAXVALSIZE;
		i = 0;
		ptr = prom_path;
		while (prom_list && prom_list[i]) {
			if (!(options & BOOTDEV_PROMDEV)) {
				ret = prom_dev_to_alias(prom_list[i], 0,
				    &alias_list);
				if (ret < 0) {
					free(prom_path);
					prom_list_free(prom_list);
					return (ret);
				}
				if ((alias_list != NULL) &&
				    (alias_list[0] != NULL)) {
					(void) snprintf(ptr, len, "%s ",
					    alias_list[0]);
					for (ret = 0; alias_list[ret] != NULL;
					    ret++)
						free(alias_list[ret]);
				} else {
					(void) snprintf(ptr, len, "%s ",
					    prom_list[i]);
				}
				if (alias_list != NULL)
					free(alias_list);
			} else {
				(void) snprintf(ptr, len, "%s ", prom_list[i]);
			}
			j = strlen(ptr);
			len -= j;
			ptr += j;
			i++;
		}
		ptr--;
		*ptr = 0;

		prom_list_free(prom_list);
	}
	if (options & BOOTDEV_OVERWRITE) {
		new_bootdev = prom_path;
	} else {
		/* retrieve the current value of boot-device */
		ret = get_boot_dev_var(opp);
		if (ret < 0) {
			free(prom_path);
			return (ret);
		}
		/* prepend new entry - deal with duplicates */
		new_bootdev = (char *)malloc(strlen(opp->oprom_array)
		    + strlen(prom_path) + 2);
		if (new_bootdev == NULL) {
			free(prom_path);
			return (DEVFS_NOMEM);
		}
		(void) strcpy(new_bootdev, prom_path);
		if (opp->oprom_size > 0) {
			for (ptr = strtok(opp->oprom_array, " "); ptr != NULL;
			    ptr = strtok(NULL, " ")) {
				/* we strip out duplicates */
				if (strcmp(prom_path, ptr) == 0) {
					continue;
				}
				(void) strcat(new_bootdev, " ");
				(void) strcat(new_bootdev, ptr);
			}
		}
	}

	/* now set the new value */
	ret = set_boot_dev_var(opp, new_bootdev);

	if (options & BOOTDEV_OVERWRITE) {
		free(prom_path);
	} else {
		free(new_bootdev);
		free(prom_path);
	}

	return (ret);
}

/*
 * sets the string bootdev as the new value for boot-device
 */
static int
set_boot_dev_var(struct openpromio *opp, char *bootdev)
{
	int prom_fd;
	int i;
	int ret;
	char *valbuf;
	char *save_bootdev;
	char *bootdev_variables[] = {
		"boot-device",
		"bootdev",
		"boot-from",
		NULL
	};
	int found = 0;
	int *ip = (int *)((void *)opp->oprom_array);

	/* query the prom */
	prom_fd = prom_open(O_RDWR);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	/* get the diagnostic-mode? property */
	(void) strcpy(opp->oprom_array, "diagnostic-mode?");
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) >= 0) {
		if ((opp->oprom_size > 0) &&
		    (strcmp(opp->oprom_array, "true") == 0)) {
			prom_close(prom_fd);
			return (DEVFS_ERR);
		}
	}
	/* get the diag-switch? property */
	(void) strcpy(opp->oprom_array, "diag-switch?");
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) >= 0) {
		if ((opp->oprom_size > 0) &&
		    (strcmp(opp->oprom_array, "true") == 0)) {
			prom_close(prom_fd);
			return (DEVFS_ERR);
		}
	}
	/*
	 * look for one of the following properties in order:
	 *	boot-device
	 *	bootdev
	 *	boot-from
	 *
	 * Use the first one that we find.
	 */
	*ip = 0;
	opp->oprom_size = MAXPROPSIZE;
	while ((opp->oprom_size != 0) && (!found)) {
		opp->oprom_size = MAXPROPSIZE;
		if (ioctl(prom_fd, OPROMNXTOPT, opp) < 0) {
			break;
		}
		for (i = 0; bootdev_variables[i] != NULL; i++) {
			if (strcmp(opp->oprom_array, bootdev_variables[i])
			    == 0) {
				found = 1;
				break;
			}
		}
	}
	if (found) {
		(void) strcpy(opp->oprom_array, bootdev_variables[i]);
		opp->oprom_size = MAXVALSIZE;
		if (ioctl(prom_fd, OPROMGETOPT, opp) < 0) {
			prom_close(prom_fd);
			return (DEVFS_NOTSUP);
		}
	} else {
		prom_close(prom_fd);
		return (DEVFS_NOTSUP);
	}

	/* save the old copy in case we fail */
	if ((save_bootdev = strdup(opp->oprom_array)) == NULL) {
		prom_close(prom_fd);
		return (DEVFS_NOMEM);
	}
	/* set up the new value of boot-device */
	(void) strcpy(opp->oprom_array, bootdev_variables[i]);
	valbuf = opp->oprom_array + strlen(opp->oprom_array) + 1;
	(void) strcpy(valbuf, bootdev);

	opp->oprom_size = strlen(valbuf) + strlen(opp->oprom_array) + 2;

	if (ioctl(prom_fd, OPROMSETOPT, opp) < 0) {
		free(save_bootdev);
		prom_close(prom_fd);
		return (DEVFS_ERR);
	}

	/*
	 * now read it back to make sure it took
	 */
	(void) strcpy(opp->oprom_array, bootdev_variables[i]);
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) >= 0) {
		if (_prom_strcmp(opp->oprom_array, bootdev) == 0) {
			/* success */
			free(save_bootdev);
			prom_close(prom_fd);
			return (0);
		}
		/* deal with setting it to "" */
		if ((strlen(bootdev) == 0) && (opp->oprom_size == 0)) {
			/* success */
			free(save_bootdev);
			prom_close(prom_fd);
			return (0);
		}
	}
	/*
	 * something did not take - write out the old value and
	 * hope that we can restore things...
	 *
	 * unfortunately, there is no way for us to differentiate
	 * whether we exceeded the maximum number of characters
	 * allowable.  The limit varies from prom rev to prom
	 * rev, and on some proms, when the limit is
	 * exceeded, whatever was in the
	 * boot-device variable becomes unreadable.
	 *
	 * so if we fail, we will assume we ran out of room.  If we
	 * not able to restore the original setting, then we will
	 * return DEVFS_ERR instead.
	 */
	ret = DEVFS_LIMIT;
	(void) strcpy(opp->oprom_array, bootdev_variables[i]);
	valbuf = opp->oprom_array + strlen(opp->oprom_array) + 1;
	(void) strcpy(valbuf, save_bootdev);

	opp->oprom_size = strlen(valbuf) + strlen(opp->oprom_array) + 2;

	if (ioctl(prom_fd, OPROMSETOPT, opp) < 0) {
		ret = DEVFS_ERR;
	}
	free(save_bootdev);
	prom_close(prom_fd);
	return (ret);
}
/*
 * retrieve the current value for boot-device
 */
static int
get_boot_dev_var(struct openpromio *opp)
{
	int prom_fd;
	int i;
	char *bootdev_variables[] = {
		"boot-device",
		"bootdev",
		"boot-from",
		NULL
	};
	int found = 0;
	int *ip = (int *)((void *)opp->oprom_array);

	/* query the prom */
	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	/* get the diagnostic-mode? property */
	(void) strcpy(opp->oprom_array, "diagnostic-mode?");
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) >= 0) {
		if ((opp->oprom_size > 0) &&
		    (strcmp(opp->oprom_array, "true") == 0)) {
			prom_close(prom_fd);
			return (DEVFS_ERR);
		}
	}
	/* get the diag-switch? property */
	(void) strcpy(opp->oprom_array, "diag-switch?");
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) >= 0) {
		if ((opp->oprom_size > 0) &&
		    (strcmp(opp->oprom_array, "true") == 0)) {
			prom_close(prom_fd);
			return (DEVFS_ERR);
		}
	}
	/*
	 * look for one of the following properties in order:
	 *	boot-device
	 *	bootdev
	 *	boot-from
	 *
	 * Use the first one that we find.
	 */
	*ip = 0;
	opp->oprom_size = MAXPROPSIZE;
	while ((opp->oprom_size != 0) && (!found)) {
		opp->oprom_size = MAXPROPSIZE;
		if (ioctl(prom_fd, OPROMNXTOPT, opp) < 0) {
			break;
		}
		for (i = 0; bootdev_variables[i] != NULL; i++) {
			if (strcmp(opp->oprom_array, bootdev_variables[i])
			    == 0) {
				found = 1;
				break;
			}
		}
	}
	if (found) {
		(void) strcpy(opp->oprom_array, bootdev_variables[i]);
		opp->oprom_size = MAXVALSIZE;
		if (ioctl(prom_fd, OPROMGETOPT, opp) < 0) {
			prom_close(prom_fd);
			return (DEVFS_ERR);
		}
		/* boot-device exists but contains nothing */
		if (opp->oprom_size == 0) {
			*opp->oprom_array = '\0';
		}
	} else {
		prom_close(prom_fd);
		return (DEVFS_NOTSUP);
	}
	prom_close(prom_fd);
	return (0);
}

#ifndef __sparc
static FILE *
open_diskmap(void)
{
	FILE *fp;
	char cmd[PATH_MAX];

	/* make sure we have a map file */
	fp = fopen(GRUBDISK_MAP, "r");
	if (fp == NULL) {
		(void) snprintf(cmd, sizeof (cmd),
		    "%s > /dev/null", CREATE_DISKMAP);
		(void) system(cmd);
		fp = fopen(GRUBDISK_MAP, "r");
	}
	return (fp);
}

static int
find_x86_boot_device(struct openpromio *opp)
{
	int ret = DEVFS_ERR;
	char *cp, line[MAXVALSIZE + 6];
	FILE *file;

	file = open_diskmap();
	if (file == NULL)
		return (DEVFS_ERR);

	while (fgets(line, MAXVALSIZE + 6, file)) {
		if (strncmp(line, "0 ", 2) != 0)
			continue;
		/* drop new-line */
		line[strlen(line) - 1] = '\0';
		/*
		 * an x86 BIOS only boots a disk, not a partition
		 * or a slice, so hard-code :q (p0)
		 */
		cp = strchr(line + 2, ' ');
		if (cp == NULL)
			break;
		(void) snprintf(opp->oprom_array, MAXVALSIZE,
		    "%s:q", cp + 1);
		opp->oprom_size = MAXVALSIZE;
		ret = 0;
		break;
	}
	(void) fclose(file);
	return (ret);
}
#endif /* ndef __sparc */

/*
 * retrieve the list of entries in the boot-device configuration
 * variable.  An array of boot_dev structs will be created, one entry
 * for each device name in the boot-device variable.  Each entry
 * in the array will contain the logical device representation of the
 * boot-device entry, if any.
 *
 * default_root. if set, is used to locate logical device entries in
 * directories other than /dev
 */
int
devfs_bootdev_get_list(const char *default_root,
    struct boot_dev ***bootdev_list)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int i;
	struct boot_dev **tmp_list;

	if (default_root == NULL) {
		default_root = "";
	} else if (*default_root != '/') {
		return (DEVFS_INVAL);
	}

	if (bootdev_list == NULL) {
		return (DEVFS_INVAL);
	}

	/* get the boot-device variable */
#if defined(sparc)
	i = get_boot_dev_var(opp);
#else
	i = find_x86_boot_device(opp);
#endif
	if (i < 0) {
		return (i);
	}
	/* now try to translate each entry to a logical device. */
	i = process_bootdev(opp->oprom_array, default_root, &tmp_list);
	if (i == 0) {
		*bootdev_list = tmp_list;
		return (0);
	} else {
		return (i);
	}
}

/*
 * loop thru the list of entries in a boot-device configuration
 * variable.
 */
static int
process_bootdev(const char *bootdevice, const char *default_root,
    struct boot_dev ***list)
{
	int i;
	char *entry, *ptr;
	char prom_path[MAXPATHLEN];
	char ret_buf[MAXPATHLEN];
	struct boot_dev **bootdev_array;
	int num_entries = 0;
	int found = 0;
	int vers;

	if ((entry = (char *)malloc(strlen(bootdevice) + 1)) == NULL) {
		return (DEVFS_NOMEM);
	}
	/* count the number of entries */
	(void) strcpy(entry, bootdevice);
	for (ptr = strtok(entry, " "); ptr != NULL;
	    ptr = strtok(NULL, " ")) {
		num_entries++;
	}
	(void) strcpy(entry, bootdevice);

	bootdev_array = (struct boot_dev **)
	    calloc((size_t)num_entries + 1, sizeof (struct boot_dev *));

	if (bootdev_array == NULL) {
		free(entry);
		return (DEVFS_NOMEM);
	}

	vers = prom_obp_vers();
	if (vers < 0) {
		free(entry);
		return (vers);
	}

	/* for each entry in boot-device, do... */
	for (ptr = strtok(entry, " "), i = 0; ptr != NULL;
	    ptr = strtok(NULL, " "), i++) {

		if ((bootdev_array[i] = alloc_bootdev(ptr)) == NULL) {
			devfs_bootdev_free_list(bootdev_array);
			free(entry);
			return (DEVFS_NOMEM);
		}

		/*
		 * prom boot-device may be aliased, so we need to do
		 * the necessary prom alias to dev translation.
		 */
		if (*ptr != '/') {
			if (alias_to_prom_dev(ptr, prom_path) < 0) {
				continue;
			}
		} else {
			(void) strcpy(prom_path, ptr);
		}

		/* now we have a prom device path - convert to a devfs name */
		if (devfs_prom_to_dev_name(prom_path, ret_buf) < 0) {
			continue;
		}

		/* append any default minor names necessary */
		if (process_minor_name(ret_buf, default_root) < 0) {
			continue;
		}
		found = 1;

		/*
		 * store the physical device path for now - when
		 * we are all done with the entries, we will convert
		 * these to their logical device name equivalents
		 */
		bootdev_array[i]->bootdev_trans[0] = strdup(ret_buf);
	}
	/*
	 * Convert all of the boot-device entries that translated to a
	 * physical device path in /devices to a logical device path
	 * in /dev (note that there may be several logical device paths
	 * associated with a single physical device path - return them all
	 */
	if (found) {
		if (devfs_phys_to_logical(bootdev_array, num_entries,
		    default_root) < 0) {
			devfs_bootdev_free_list(bootdev_array);
			bootdev_array = NULL;
		}
	}
	free(entry);
	*list = bootdev_array;
	return (0);
}

/*
 * We may get a device path from the prom that has no minor name
 * information included in it.  Since this device name will not
 * correspond directly to a physical device in /devices, we do our
 * best to append what the default minor name should be and try this.
 *
 * For sparc: we append slice 0 (:a).
 * For x86: we append fdisk partition 0 (:q).
 */
static int
process_minor_name(char *dev_path, const char *root)
{
	char *cp;
#if defined(sparc)
	const char *default_minor_name = "a";
#else
	const char *default_minor_name = "q";
#endif
	int n;
	struct stat stat_buf;
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "%s%s%s", root, DEVICES, dev_path);
	/*
	 * if the device file already exists as given to us, there
	 * is nothing to do but return.
	 */
	if (stat(path, &stat_buf) == 0) {
		return (0);
	}
	/*
	 * if there is no ':' after the last '/' character, or if there is
	 * a ':' with no specifier, append the default segment specifier
	 * ; if there is a ':' followed by a digit, this indicates
	 * a partition number (which does not map into the /devices name
	 * space), so strip the number and replace it with the letter
	 * that represents the partition index
	 */
	if ((cp = strrchr(dev_path, '/')) != NULL) {
		if ((cp = strchr(cp, ':')) == NULL) {
			(void) strcat(dev_path, ":");
			(void) strcat(dev_path, default_minor_name);
		} else if (*++cp == '\0') {
			(void) strcat(dev_path, default_minor_name);
		} else if (isdigit(*cp)) {
			n = atoi(cp);
			/* make sure to squash the digit */
			*cp = '\0';
			switch (n) {
			case 0:	(void) strcat(dev_path, "q");
					break;
			case 1:	(void) strcat(dev_path, "r");
					break;
			case 2:	(void) strcat(dev_path, "s");
					break;
			case 3:	(void) strcat(dev_path, "t");
					break;
			case 4:	(void) strcat(dev_path, "u");
					break;
			default: (void) strcat(dev_path, "a");
					break;
			}
		}
	}
	/*
	 * see if we can find something now.
	 */
	(void) snprintf(path, sizeof (path), "%s%s%s", root, DEVICES, dev_path);

	if (stat(path, &stat_buf) == 0) {
		return (0);
	} else {
		return (-1);
	}
}

/*
 * for each entry in bootdev_array, convert the physical device
 * representation of the boot-device entry to one or more logical device
 * entries.  We use the hammer method - walk through the logical device
 * name space looking for matches (/dev).  We use nftw to do this.
 */
static int
devfs_phys_to_logical(struct boot_dev **bootdev_array, const int array_size,
    const char *default_root)
{
	int walk_flags = FTW_PHYS | FTW_MOUNT;
	char *full_path;
	struct name_list *list;
	int count, i;
	char **dev_name_array;
	size_t default_root_len;
	char *dev_dir = DEV;
	int len;

	if (array_size < 0) {
		return (-1);
	}

	if (bootdev_array == NULL) {
		return (-1);
	}
	if (default_root == NULL) {
		return (-1);
	}
	default_root_len = strlen(default_root);
	if ((default_root_len != 0) && (*default_root != '/')) {
		return (-1);
	}

	/* short cut for an empty array */
	if (*bootdev_array == NULL) {
		return (0);
	}

	/* tell nftw where to start (default: /dev) */
	len = default_root_len + strlen(dev_dir) + 1;
	if ((full_path = (char *)malloc(len)) == NULL) {
		return (-1);
	}

	/*
	 * if the default root path is terminated with a /, we have to
	 * make sure we don't end up with one too many slashes in the
	 * path we are building.
	 */
	if ((default_root_len > (size_t)0) &&
	    (default_root[default_root_len - 1] == '/')) {
		(void) snprintf(full_path, len, "%s%s", default_root,
		    &dev_dir[1]);
	} else {
		(void) snprintf(full_path, len, "%s%s", default_root, dev_dir);
	}

	/*
	 * we need to muck with global data to make nftw work
	 * so single thread access
	 */
	(void) mutex_lock(&dev_lists_lk);

	/*
	 * set the global vars bootdev_list and dev_list for use by nftw
	 * dev_list is an array of lists - one for each boot-device
	 * entry.  The nftw function will create a list of logical device
	 * entries for each boot-device and put all of the lists in
	 * dev_list.
	 */
	dev_list = (struct name_list **)
	    calloc(array_size, sizeof (struct name_list *));
	if (dev_list == NULL) {
		free(full_path);
		(void) mutex_unlock(&dev_lists_lk);
		return (-1);
	}
	bootdev_list = bootdev_array;

	if (nftw(full_path, check_logical_dev, FT_DEPTH, walk_flags) == -1) {
		bootdev_list = NULL;
		free(full_path);
		for (i = 0; i < array_size; i++) {
			free_name_list(dev_list[i], 1);
		}
		/* don't free dev_list here because it's been handed off */
		dev_list = NULL;
		(void) mutex_unlock(&dev_lists_lk);
		return (-1);
	}

	/*
	 * now we have a filled in dev_list.  So for each logical device
	 * list in dev_list, count the number of entries in the list,
	 * create an array of strings of logical devices, and save in the
	 * corresponding boot_dev structure.
	 */
	for (i = 0; i < array_size; i++) {
		/* get the next list */
		list = dev_list[i];
		count = 0;

		/* count the number of entries in the list */
		while (list != NULL) {
			count++;
			list = list->next;
		}
		if ((dev_name_array =
		    (char **)malloc((count + 1) * sizeof (char *)))
		    == NULL) {
			continue;
		}
		list = dev_list[i];
		count = 0;

		/* fill in the array */
		while (list != NULL) {
			dev_name_array[count] = list->name;
			count++;
			list = list->next;
		}

		/*
		 * null terminate the array
		 */
		dev_name_array[count] = NULL;
		if ((bootdev_array[i] != NULL) && (bootdev_array[i]->
		    bootdev_trans[0] != NULL)) {
			free(bootdev_array[i]->bootdev_trans[0]);
		}
		if (bootdev_array[i] != NULL) {
			free(bootdev_array[i]->bootdev_trans);
			bootdev_array[i]->bootdev_trans = dev_name_array;
		}
	}
	bootdev_list = NULL;
	free(full_path);
	for (i = 0; i < array_size; i++) {
		free_name_list(dev_list[i], 0);
	}
	free(dev_list);
	dev_list = NULL;
	(void) mutex_unlock(&dev_lists_lk);
	return (0);
}
/*
 * nftw function
 * for a logical dev entry, it walks the list of boot-devices and
 * sees if there are any matches.  If so, it saves the logical device
 * name off in the appropriate list in dev_list
 */
/* ARGSUSED */
static int
check_logical_dev(const char *node, const struct stat *node_stat, int flags,
    struct FTW *ftw_info)
{
	char link_buf[MAXPATHLEN];
	int link_buf_len;
	char *name;
	struct name_list *dev;
	char *physdev;
	int i;

	if (flags != FTW_SL) {
		return (0);
	}

	if ((link_buf_len = readlink(node, (void *)link_buf, MAXPATHLEN))
	    == -1) {
		return (0);
	}
	link_buf[link_buf_len] = '\0';
	if ((name = strstr(link_buf, DEVICES)) == NULL) {
		return (0);
	}
	name = (char *)(name + strlen(DEVICES));

	for (i = 0; bootdev_list[i] != NULL; i++) {
		if (bootdev_list[i]->bootdev_trans[0] == NULL) {
			continue;
		}
		/*
		 * compare the contents of the link with the physical
		 * device representation of this boot device
		 */
		physdev = bootdev_list[i]->bootdev_trans[0];
		if ((strcmp(name, physdev) == 0) &&
		    (strlen(name) == strlen(physdev))) {
			if ((dev = (struct name_list *)
			    malloc(sizeof (struct name_list))) == NULL) {
				return (-1);
			}
			if ((dev->name = strdup(node)) == NULL) {
				free(dev);
				return (-1);
			}
			if (dev_list[i] == NULL) {
				dev_list[i] = dev;
				dev_list[i]->next = NULL;
			} else {
				dev->next = dev_list[i];
				dev_list[i] = dev;
			}
		}
	}
	return (0);
}

/*
 * frees a list of boot_dev struct pointers
 */
void
devfs_bootdev_free_list(struct boot_dev **array)
{
	int i = 0;
	int j;

	if (array == NULL) {
		return;
	}

	while (array[i] != NULL) {
		free(array[i]->bootdev_element);
		j = 0;
		while (array[i]->bootdev_trans[j] != NULL) {
			free(array[i]->bootdev_trans[j++]);
		}
		free(array[i]->bootdev_trans);
		free(array[i]);
		i++;
	}
	free(array);
}
/*
 * allocates a boot_dev struct and fills in the bootdev_element portion
 */
static struct boot_dev *
alloc_bootdev(char *entry_name)
{
	struct boot_dev *entry;

	entry = (struct boot_dev *)calloc(1, sizeof (struct boot_dev));

	if (entry == NULL) {
		return (NULL);
	}
	if ((entry->bootdev_element = strdup(entry_name)) == NULL) {
		free(entry);
		return (NULL);
	}
	/*
	 * Allocate room for 1 name and a null terminator - the caller of
	 * this function will need the first slot right away.
	 */
	if ((entry->bootdev_trans = (char **)calloc(2, sizeof (char *)))
	    == NULL) {
		free(entry->bootdev_element);
		free(entry);
		return (NULL);
	}
	return (entry);
}

/*
 * will come back with a concatenated list of paths
 */
int
devfs_dev_to_prom_names(char *dev_path, char *prom_path, size_t len)
{
	Oppbuf oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int prom_fd;
	int ret = DEVFS_INVAL;
	int i;

	if (prom_path == NULL) {
		return (DEVFS_INVAL);
	}
	if (dev_path == NULL) {
		return (DEVFS_INVAL);
	}
	if (strlen(dev_path) >= MAXPATHLEN)
		return (DEVFS_INVAL);

	if (*dev_path != '/')
		return (DEVFS_INVAL);

	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	/* query the prom */
	(void) snprintf(opp->oprom_array, MAXVALSIZE, "%s", dev_path);
	opp->oprom_size = MAXVALSIZE;

	if (ioctl(prom_fd, OPROMDEV2PROMNAME, opp) == 0) {
		prom_close(prom_fd);

		/* return the prom path in prom_path */

		i = len - opp->oprom_size;
		if (i < 0) {
			bcopy(opp->oprom_array, prom_path, len);
			prom_path[len - 1] = '\0';
			return (len);
		} else {
			bcopy(opp->oprom_array, prom_path, len);
			return (opp->oprom_size);
		}
	}
	/*
	 * either the prom does not support this ioctl or the argument
	 * was invalid.
	 */
	if (errno == ENXIO) {
		ret = DEVFS_NOTSUP;
	}
	prom_close(prom_fd);
	return (ret);
}

/*
 * Convert a physical or logical device name to a name the prom would
 * understand.  Fail if this platform does not support a prom or if
 * the device does not correspond to a valid prom device.
 *      dev_path should be the name of a device in the logical or
 *              physical device namespace.
 *      prom_path is the prom version of the device name
 *      prom_path must be large enough to contain the result and is
 *      supplied by the user.
 *
 * This routine only supports converting leaf device paths
 */
int
devfs_dev_to_prom_name(char *dev_path, char *prom_path)
{
	int rval;

	rval = devfs_dev_to_prom_names(dev_path, prom_path, MAXPATHLEN);

	if (rval < 0)
		return (rval);
	else
		return (0);
}

/*
 * Use the openprom driver's OPROMPATH2DRV ioctl to convert a devfs
 * path to a driver name.
 * devfs_path - the pathname of interest.  This must be the physcical device
 * path with the mount point prefix (ie. /devices) stripped off.
 * drv_buf - user supplied buffer - the driver name will be stored here.
 *
 * If the prom lookup fails, we return the name of the last component in
 * the pathname.  This routine is useful for looking up driver names
 * associated with generically named devices.
 *
 * This routine returns driver names that have aliases resolved.
 */
int
devfs_path_to_drv(char *devfs_path, char *drv_buf)
{
	Oppbuf oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	char *slash, *colon, *dev_addr;
	char driver_path[MAXPATHLEN];
	int prom_fd;

	if (drv_buf == NULL) {
		return (-1);
	}
	if (devfs_path == NULL) {
		return (-1);
	}

	if (strlen(devfs_path) >= MAXPATHLEN)
		return (-1);

	if (*devfs_path != '/')
		return (-1);


	/* strip off any minor node info at the end of the path */
	(void) strcpy(driver_path, devfs_path);
	slash = strrchr(driver_path, '/');
	if (slash == NULL)
		return (-1);
	colon = strrchr(slash, ':');
	if (colon != NULL)
		*colon = '\0';

	/* query the prom */
	if ((prom_fd = prom_open(O_RDONLY)) >= 0) {
		(void) strcpy(opp->oprom_array, driver_path);
		opp->oprom_size = MAXVALSIZE;

		if (ioctl(prom_fd, OPROMPATH2DRV, opp) == 0) {
			prom_close(prom_fd);
			/* return the driver name in drv_buf */
			(void) strcpy(drv_buf, opp->oprom_array);
			return (0);
		}
		prom_close(prom_fd);
	} else if (prom_fd != DEVFS_NOTSUP)
		return (-1);
	/*
	 * If we get here, then either:
	 *	1. this platform does not support an openprom driver
	 *	2. we were asked to look up a device the prom does
	 *	   not know about (e.g. a pseudo device)
	 * In this case, we use the last component of the devfs path
	 * name and try to derive the driver name
	 */

	/* use the last component of devfs_path as the driver name */
	if ((dev_addr = strrchr(slash, '@')) != NULL)
		*dev_addr = '\0';
	slash++;

	/* use opp->oprom_array as a buffer */
	(void) strcpy(opp->oprom_array, slash);
	if (devfs_resolve_aliases(opp->oprom_array) == NULL)
		return (-1);
	(void) strcpy(drv_buf, opp->oprom_array);
	return (0);
}

/*
 * These modctl calls do the equivalent of:
 *	ddi_name_to_major()
 *	ddi_major_to_name()
 * This results in two things:
 *	- the driver name must be a valid one
 *	- any driver aliases are resolved.
 * drv is overwritten with the resulting name.
 */
char *
devfs_resolve_aliases(char *drv)
{
	major_t maj;
	char driver_name[MAXNAMELEN + 1];

	if (drv == NULL) {
		return (NULL);
	}

	if (modctl(MODGETMAJBIND, drv, strlen(drv) + 1, &maj) < 0)
		return (NULL);
	else if (modctl(MODGETNAME, driver_name, sizeof (driver_name), &maj)
	    < 0) {
		return (NULL);
	} else {
		(void) strcpy(drv, driver_name);
		return (drv);
	}
}

/*
 * open the openprom device.  and verify that we are on an
 * OBP/1275 OF machine.  If the prom does not exist, then we
 * return an error
 */
static int
prom_open(int oflag)
{
	int prom_fd = -1;
	char *promdev = "/dev/openprom";

	while (prom_fd < 0) {
		if ((prom_fd = open(promdev, oflag)) < 0)  {
			if (errno == EAGAIN)   {
				(void) sleep(5);
				continue;
			}
			if ((errno == ENXIO) || (errno == ENOENT)) {
				return (DEVFS_NOTSUP);
			}
			if ((errno == EPERM) || (errno == EACCES)) {
				return (DEVFS_PERM);
			}
			return (DEVFS_ERR);
		} else
			break;
	}
	if (is_openprom(prom_fd))
		return (prom_fd);
	else {
		prom_close(prom_fd);
		return (DEVFS_ERR);
	}
}

static void
prom_close(int prom_fd)
{
	(void) close(prom_fd);
}

/*
 * is this an OBP/1275 OF machine?
 */
static int
is_openprom(int prom_fd)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	unsigned int i;

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETCONS, opp) < 0)
		return (0);

	i = (unsigned int)((unsigned char)opp->oprom_array[0]);
	return ((i & OPROMCONS_OPENPROM) == OPROMCONS_OPENPROM);
}

/*
 * convert a prom device path name to an equivalent physical device
 * path in the kernel.
 */
static int
devfs_prom_to_dev_name(char *prom_path, char *dev_path)
{
	Oppbuf oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int prom_fd;
	int ret = DEVFS_INVAL;

	if (dev_path == NULL) {
		return (DEVFS_INVAL);
	}
	if (prom_path == NULL) {
		return (DEVFS_INVAL);
	}
	if (strlen(prom_path) >= MAXPATHLEN)
		return (DEVFS_INVAL);

	if (*prom_path != '/') {
		return (DEVFS_INVAL);
	}

	/* query the prom */
	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}
	(void) strcpy(opp->oprom_array, prom_path);
	opp->oprom_size = MAXVALSIZE;

	if (ioctl(prom_fd, OPROMPROM2DEVNAME, opp) == 0) {
		prom_close(prom_fd);
		/*
		 * success
		 * return the prom path in prom_path
		 */
		(void) strcpy(dev_path, opp->oprom_array);
		return (0);
	}
	/*
	 * either the argument was not a valid name or the openprom
	 * driver does not support this ioctl.
	 */
	if (errno == ENXIO) {
		ret = DEVFS_NOTSUP;
	}
	prom_close(prom_fd);
	return (ret);
}
/*
 * convert a prom device path to a list of equivalent alias names
 * If there is no alias node, or there are no aliases that correspond
 * to dev, we return empty lists.
 */
static int
prom_dev_to_alias(char *dev, uint_t options, char ***ret_buf)
{
	struct name_list *exact_list;
	struct name_list *inexact_list;
	struct name_list *list;
	char *ptr;
	char **array;
	int prom_fd;
	int count;
	int vers;

	vers = prom_obp_vers();
	if (vers < 0) {
		return (vers);
	}

	if (dev == NULL) {
		return (DEVFS_INVAL);
	}

	if (*dev != '/')
		return (DEVFS_INVAL);

	if (strlen(dev) >= MAXPATHLEN)
		return (DEVFS_INVAL);

	if ((ptr = strchr(dev, ':')) != NULL) {
		if (strchr(ptr, '/') != NULL)
			return (DEVFS_INVAL);
	}
	if (ret_buf == NULL) {
		return (DEVFS_INVAL);
	}

	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	(void) prom_srch_aliases_by_def(dev, &exact_list,
	    &inexact_list,  prom_fd);

	prom_close(prom_fd);

	if ((options & BOOTDEV_NO_EXACT_ALIAS) != 0) {
		free_name_list(exact_list, 1);
		exact_list = NULL;
	}

	if ((options & BOOTDEV_NO_INEXACT_ALIAS) != 0) {
		free_name_list(inexact_list, 1);
		inexact_list = NULL;
	}

	count = 0;
	list = exact_list;
	while (list != NULL) {
		list = list->next;
		count++;
	}
	list = inexact_list;
	while (list != NULL) {
		list = list->next;
		count++;
	}

	if ((*ret_buf = (char **)malloc((count + 1) * sizeof (char *)))
	    == NULL) {
		free_name_list(inexact_list, 1);
		free_name_list(exact_list, 1);
		return (DEVFS_NOMEM);
	}

	array = *ret_buf;
	count = 0;
	list = exact_list;
	while (list != NULL) {
		array[count] = list->name;
		list = list->next;
		count++;
	}
	list = inexact_list;
	while (list != NULL) {
		array[count] = list->name;
		list = list->next;
		count++;
	}
	array[count] = NULL;
	free_name_list(inexact_list, 0);
	free_name_list(exact_list, 0);

	return (0);
}

/*
 * determine the version of prom we are running on.
 * Also include any prom revision specific information.
 */
static int
prom_obp_vers(void)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int prom_fd;
	static int version = 0;

	/* cache version */
	if (version > 0) {
		return (version);
	}

	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	opp->oprom_size = MAXVALSIZE;

	if ((ioctl(prom_fd, OPROMGETVERSION, opp)) < 0) {
		prom_close(prom_fd);
		return (DEVFS_ERR);
	}
	prom_close(prom_fd);

	version |= OBP_OF;

	return (version);
}
/*
 * search the aliases node by definition - compile a list of
 * alias names that are both exact and inexact matches.
 */
static int
prom_srch_aliases_by_def(char *promdev_def, struct name_list **exact_list,
    struct name_list **inexact_list, int prom_fd)
{
	Oppbuf  oppbuf;
	Oppbuf  propdef_oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	struct openpromio *propdef_opp = &(propdef_oppbuf.opp);
	int *ip = (int *)((void *)opp->oprom_array);
	int ret;
	struct name_list *inexact_match = *inexact_list = NULL;
	struct name_list *exact_match = *exact_list = NULL;
	char alias_buf[MAXNAMELEN];
	int found = 0;

	if ((ret = prom_find_aliases_node(prom_fd)) < 0)
		return (0);

	(void) memset(oppbuf.buf, 0, BUFSIZE);
	opp->oprom_size = MAXPROPSIZE;
	*ip = 0;

	if ((ret = ioctl(prom_fd, OPROMNXTPROP, opp)) < 0)
		return (0);
	if (opp->oprom_size == 0)
		return (0);

	while ((ret >= 0) && (opp->oprom_size > 0)) {
		(void) strcpy(propdef_opp->oprom_array, opp->oprom_array);
		opp->oprom_size = MAXPROPSIZE;
		propdef_opp->oprom_size = MAXVALSIZE;
		if ((ioctl(prom_fd, OPROMGETPROP, propdef_opp) < 0) ||
		    (propdef_opp->oprom_size == 0)) {
			ret = ioctl(prom_fd, OPROMNXTPROP, opp);
			continue;
		}
		ret = prom_compare_devs(promdev_def, propdef_opp->oprom_array);
		if (ret == EXACT_MATCH) {
			found++;
			if (insert_alias_list(exact_list, opp->oprom_array)
			    != 0) {
				free_name_list(exact_match, 1);
				free_name_list(inexact_match, 1);
				return (-1);
			}
		}
		if (ret == INEXACT_MATCH) {
			found++;
			(void) strcpy(alias_buf, opp->oprom_array);
			options_override(promdev_def, alias_buf);
			if (insert_alias_list(inexact_list, alias_buf)
			    != 0) {
				free_name_list(exact_match, 1);
				free_name_list(inexact_match, 1);
				return (-1);
			}
		}
		ret = ioctl(prom_fd, OPROMNXTPROP, opp);
	}
	if (found) {
		return (0);
	} else {
		return (-1);
	}
}

/*
 * free a list of name_list structs and optionally
 * free the strings they contain.
 */
static void
free_name_list(struct name_list *list, int free_name)
{
	struct name_list *next = list;

	while (next != NULL) {
		list = list->next;
		if (free_name)
			free(next->name);
		free(next);
		next = list;
	}
}

/*
 * insert a new alias in a list of aliases - the list is sorted
 * in collating order (ignoring anything that comes after the
 * ':' in the name).
 */
static int
insert_alias_list(struct name_list **list, char *alias_name)
{
	struct name_list *entry = *list;
	struct name_list *new_entry, *prev_entry;
	int ret;
	char *colon1, *colon2;

	if ((new_entry =
	    (struct name_list *)malloc(sizeof (struct name_list)))
	    == NULL) {
		return (-1);
	}
	if ((new_entry->name = strdup(alias_name)) == NULL) {
		free(new_entry);
		return (-1);
	}
	new_entry->next = NULL;

	if (entry == NULL) {
		*list = new_entry;
		return (0);
	}

	if ((colon1 = strchr(alias_name, ':')) != NULL) {
		*colon1 = '\0';
	}
	prev_entry = NULL;
	while (entry != NULL) {
		if ((colon2 = strchr(entry->name, ':')) != NULL) {
			*colon2 = '\0';
		}
		ret = strcmp(alias_name, entry->name);
		if (colon2 != NULL) {
			*colon2 = ':';
		}
		/* duplicate */
		if (ret == 0) {
			free(new_entry->name);
			free(new_entry);
			if (colon1 != NULL) {
				*colon1 = ':';
			}
			return (0);
		}
		if (ret < 0) {
			new_entry->next = entry;
			if (prev_entry == NULL) {
				/* in beginning of list */
				*list = new_entry;
			} else {
				/* in middle of list */
				prev_entry->next = new_entry;
			}
			if (colon1 != NULL) {
				*colon1 = ':';
			}
			return (0);
		}
		prev_entry = entry;
		entry = entry->next;
	}
	/* at end of list */
	prev_entry->next = new_entry;
	new_entry->next = NULL;
	if (colon1 != NULL) {
		*colon1 = ':';
	}
	return (0);
}
/*
 * append :x to alias_name to override any default minor name options
 */
static void
options_override(char *prom_path, char *alias_name)
{
	char *colon;

	if ((colon = strrchr(alias_name, ':')) != NULL) {
		/*
		 * XXX - should alias names in /aliases ever have a
		 * : embedded in them?
		 * If so we ignore it.
		 */
		*colon = '\0';
	}

	if ((colon = strrchr(prom_path, ':')) != NULL) {
		(void) strcat(alias_name, colon);
	}
}

/*
 * compare to prom device names.
 * if the device names are not fully qualified. we convert them -
 * we only do this as a last resort though since it requires
 * jumping into the kernel.
 */
static int
prom_compare_devs(char *prom_dev1, char *prom_dev2)
{
	char *dev1, *dev2;
	char *ptr1, *ptr2;
	char *drvname1, *addrname1, *minorname1;
	char *drvname2, *addrname2, *minorname2;
	char component1[MAXNAMELEN], component2[MAXNAMELEN];
	char devname1[MAXPATHLEN], devname2[MAXPATHLEN];
	int unqualified_name = 0;
	int error = EXACT_MATCH;
	int len1, len2;
	char *wildcard = ",0";

	ptr1 = prom_dev1;
	ptr2 = prom_dev2;

	if ((ptr1 == NULL) || (*ptr1 != '/')) {
		return (NO_MATCH);
	}
	if ((ptr2 == NULL) || (*ptr2 != '/')) {
		return (NO_MATCH);
	}

	/*
	 * compare device names one component at a time.
	 */
	while ((ptr1 != NULL) && (ptr2 != NULL)) {
		*ptr1 = *ptr2 = '/';
		dev1 = ptr1 + 1;
		dev2 = ptr2 + 1;
		if ((ptr1 = strchr(dev1, '/')) != NULL)
			*ptr1 = '\0';
		if ((ptr2 = strchr(dev2, '/')) != NULL)
			*ptr2 = '\0';

		(void) strcpy(component1, dev1);
		(void) strcpy(component2, dev2);

		parse_name(component1, &drvname1, &addrname1, &minorname1);
		parse_name(component2, &drvname2, &addrname2, &minorname2);

		if ((drvname1 == NULL) && (addrname1 == NULL)) {
			error = NO_MATCH;
			break;
		}

		if ((drvname2 == NULL) && (addrname2 == NULL)) {
			error = NO_MATCH;
			break;
		}

		if (_prom_strcmp(drvname1, drvname2) != 0) {
			error = NO_MATCH;
			break;
		}

		/*
		 * a possible name is driver_name@address.  The address
		 * portion is optional (i.e. the name is not fully
		 * qualified.).  We have to deal with the case where
		 * the component name is either driver_name or
		 * driver_name@address
		 */
		if ((addrname1 == NULL) ^ (addrname2 == NULL)) {
			unqualified_name = 1;
		} else if (addrname1 &&
		    (_prom_strcmp(addrname1, addrname2) != 0)) {
			/*
			 * check to see if appending a ",0" to the
			 * shorter address causes a match to occur.
			 * If so succeed.
			 */
			len1 = strlen(addrname1);
			len2 = strlen(addrname2);
			if ((len1 < len2) &&
			    (strncmp(addrname1, addrname2, len1) == 0) &&
			    (strcmp(wildcard, &addrname2[len1]) == 0)) {
				continue;
			} else if ((len2 < len1) &&
			    (strncmp(addrname1, addrname2, len2) == 0) &&
			    (strcmp(wildcard, &addrname1[len2]) == 0)) {
				continue;
			}
			error = NO_MATCH;
			break;
		}
	}

	/*
	 * if either of the two device paths still has more components,
	 * then we do not have a match.
	 */
	if (ptr1 != NULL) {
		*ptr1 = '/';
		error = NO_MATCH;
	}
	if (ptr2 != NULL) {
		*ptr2 = '/';
		error = NO_MATCH;
	}
	if (error == NO_MATCH) {
		return (error);
	}

	/*
	 * OK - we found a possible match but one or more of the
	 * path components was not fully qualified (did not have any
	 * address information.  So we need to convert it to a form
	 * that is fully qualified and then compare the resulting
	 * strings.
	 */
	if (unqualified_name != 0) {
		if ((devfs_prom_to_dev_name(prom_dev1, devname1) < 0) ||
		    (devfs_prom_to_dev_name(prom_dev2, devname2) < 0)) {
			return (NO_MATCH);
		}
		if ((dev1 = strrchr(devname1, ':')) != NULL) {
			*dev1 = '\0';
		}
		if ((dev2 = strrchr(devname2, ':')) != NULL) {
			*dev2 = '\0';
		}
		if (strcmp(devname1, devname2) != 0) {
			return (NO_MATCH);
		}
	}
	/*
	 * the resulting strings matched.  If the minorname information
	 * matches, then we have an exact match, otherwise an inexact match
	 */
	if (_prom_strcmp(minorname1, minorname2) == 0) {
		return (EXACT_MATCH);
	} else {
		return (INEXACT_MATCH);
	}
}

/*
 * wrapper or strcmp - deals with null strings.
 */
static int
_prom_strcmp(char *s1, char *s2)
{
	if ((s1 == NULL) && (s2 == NULL))
		return (0);
	if ((s1 == NULL) && (s2 != NULL)) {
		return (-1);
	}
	if ((s1 != NULL) && (s2 == NULL)) {
		return (1);
	}
	return (strcmp(s1, s2));
}
/*
 * break device@a,b:minor into components
 */
static void
parse_name(char *name, char **drvname, char **addrname, char **minorname)
{
	char *cp, ch;

	cp = *drvname = name;
	*addrname = *minorname = NULL;
	if (*name == '@')
		*drvname = NULL;

	while ((ch = *cp) != '\0') {
		if (ch == '@')
			*addrname = ++cp;
		else if (ch == ':')
			*minorname = ++cp;
		++cp;
	}
	if (*addrname) {
		*((*addrname)-1) = '\0';
	}
	if (*minorname) {
		*((*minorname)-1) = '\0';
	}
}

/*
 * converts a prom alias to a prom device name.
 * if we find no matching device, then we fail since if were
 * given a valid alias, then by definition, there must be a
 * device pathname associated with it in the /aliases node.
 */
static int
alias_to_prom_dev(char *alias, char *ret_buf)
{
	char *options_ptr;
	char alias_buf[MAXNAMELEN];
	char alias_def[MAXPATHLEN];
	char options[16] = "";
	int prom_fd = -1;
	int ret;
	int i;

	if (strchr(alias, '/') != NULL)
		return (DEVFS_INVAL);

	if (strlen(alias) > (MAXNAMELEN - 1))
		return (DEVFS_INVAL);

	if (ret_buf == NULL) {
		return (DEVFS_INVAL);
	}

	prom_fd = prom_open(O_RDONLY);
	if (prom_fd < 0) {
		return (prom_fd);
	}

	(void) strlcpy(alias_buf, alias, sizeof (alias_buf));

	/*
	 * save off any options (minor name info) that is
	 * explicitly called out in the alias name
	 */
	if ((options_ptr = strchr(alias_buf, ':')) != NULL) {
		*options_ptr = '\0';
		(void) strlcpy(options, ++options_ptr, sizeof (options));
	}

	*alias_def = '\0';

	ret = prom_find_aliases_node(prom_fd);
	if (ret == 0) {
		/*
		 * we loop because one alias may define another... we have
		 * to work our way down to an actual device definition.
		 */
		for (i = 0; i <= 10; i++) {
			ret = prom_srch_node(prom_fd, alias_buf, alias_def);
			if (ret == -1) {
				break;
			}
			(void) strlcpy(alias_buf, alias_def,
			    sizeof (alias_buf));
			if (*alias_def == '/') {
				break;
			}

			/*
			 * save off any explicit options (minor name info)
			 * if none has been encountered yet
			 */
			if (options_ptr == NULL) {
				options_ptr = strchr(alias_buf, ':');
				if (options_ptr != NULL) {
					*options_ptr = '\0';
					(void) strlcpy(options, ++options_ptr,
					    sizeof (options));
				}
			}
		}
	}
	prom_close(prom_fd);

	/* error */
	if (ret == -1) {
		return (ret);
	}

	(void) strlcpy(ret_buf, alias_def, MAXPATHLEN);

	/* override minor name information */
	if (options_ptr != NULL) {
		if ((options_ptr = strrchr(ret_buf, ':')) == NULL) {
			(void) strcat(ret_buf, ":");
		} else {
			*(++options_ptr) = '\0';
		}
		(void) strcat(ret_buf, options);
	}
	return (0);
}

/*
 * search a prom node for a property name
 */
static int
prom_srch_node(int fd, char *prop_name, char *ret_buf)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	int *ip = (int *)((void *)opp->oprom_array);

	(void) memset(oppbuf.buf, 0, BUFSIZE);
	opp->oprom_size = MAXPROPSIZE;
	*ip = 0;

	if (ioctl(fd, OPROMNXTPROP, opp) < 0)
		return (-1);
	if (opp->oprom_size == 0)
		return (-1);

	while (strcmp(prop_name, opp->oprom_array) != 0) {
		opp->oprom_size = MAXPROPSIZE;
		if (ioctl(fd, OPROMNXTPROP, opp) < 0)
			return (-1);
		if (opp->oprom_size == 0)
			return (-1);
	}
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(fd, OPROMGETPROP, opp) < 0)
		return (-1);

	if (opp->oprom_size == 0)
		return (-1);
	(void) strlcpy(ret_buf, opp->oprom_array, MAXPATHLEN);
	return (0);
}

/*
 * return the aliases node.
 */
static int
prom_find_aliases_node(int fd)
{
	uint_t child_id;
	char buf[MAXPATHLEN];

	if ((child_id = prom_next_node(fd, 0)) == 0)
		return (-1);
	if ((child_id = prom_child_node(fd, child_id)) == 0)
		return (-1);

	while (child_id != 0) {
		if (prom_srch_node(fd, "name", buf) == 0) {
			if (strcmp(buf, "aliases") == 0) {
				return (0);
			}
		}
		child_id = prom_next_node(fd, child_id);
	}
	return (-1);
}

/*
 * get sibling
 */
static uint_t
prom_next_node(int fd, uint_t node_id)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	uint_t *ip = (uint_t *)((void *)opp->oprom_array);

	(void) memset(oppbuf.buf, 0, BUFSIZE);
	opp->oprom_size = MAXVALSIZE;
	*ip = node_id;

	if (ioctl(fd, OPROMNEXT, opp) < 0)
		return (0);

	return (*(uint_t *)((void *)opp->oprom_array));
}

/*
 * get child
 */
static uint_t
prom_child_node(int fd, uint_t node_id)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	uint_t *ip = (uint_t *)((void *)opp->oprom_array);

	(void) memset(oppbuf.buf, 0, BUFSIZE);
	opp->oprom_size = MAXVALSIZE;
	*ip = node_id;

	if (ioctl(fd, OPROMCHILD, opp) < 0)
		return (0);

	return (*(uint_t *)((void *)opp->oprom_array));
}

/*
 * only on sparc for now
 */
int
devfs_bootdev_modifiable(void)
{
#if defined(sparc)
	return (0);
#else
	return (DEVFS_NOTSUP);
#endif
}
