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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include "libzfs_jni_diskmgt.h"
#include "libzfs_jni_util.h"
#include <strings.h>
#include <libzfs.h>
#include <sys/mnttab.h>

/*
 * Function prototypes
 */

static char *get_device_name(dm_descriptor_t device, int *error);
static dmgt_disk_t *get_disk(dm_descriptor_t disk, int *error);
static char **get_disk_aliases(dm_descriptor_t disk, char *name, int *error);
static int get_disk_online(dm_descriptor_t disk, int *error);
static void remove_slice_from_list(dmgt_slice_t **slices, int index);
static dmgt_slice_t **get_disk_slices(dm_descriptor_t media,
    const char *name, uint32_t blocksize, int *error);
static dmgt_slice_t **get_disk_usable_slices(dm_descriptor_t media,
    const char *name, uint32_t blocksize, int *in_use, int *error);
static void get_disk_size(dm_descriptor_t media, char *name,
    uint64_t *size, uint32_t *blocksize, int *error);
static void get_slice_use(dm_descriptor_t slice, char *name,
    char **used_name, char **used_by, int *error);
static dmgt_slice_t *get_slice(
    dm_descriptor_t slice, uint32_t blocksize, int *error);
static void handle_error(const char *format, ...);
static int slice_in_use(dmgt_slice_t *slice, int *error);
static int slice_too_small(dmgt_slice_t *slice);

/*
 * Static data
 */

static void (*error_func)(const char *, va_list);

/*
 * Static functions
 */

static char *
get_device_name(dm_descriptor_t device, int *error)
{
	char *dup = NULL;
	char *name;

	*error = 0;
	name = dm_get_name(device, error);
	if (*error) {
		handle_error("could not determine name of device");
	} else {
		dup = strdup(name);
		if (dup == NULL) {
			handle_error("out of memory");
			*error = -1;
		}

		dm_free_name(name);
	}

	return (dup);
}

/*
 * Gets a dmgt_disk_t for the given disk dm_descriptor_t.
 *
 * Results:
 *
 *  1. Success: error is set to 0 and a dmgt_disk_t is returned
 *
 *  2. Failure: error is set to -1 and NULL is returned
 */
static dmgt_disk_t *
get_disk(dm_descriptor_t disk, int *error)
{
	dmgt_disk_t *dp;
	*error = 0;

	dp = (dmgt_disk_t *)calloc(1, sizeof (dmgt_disk_t));
	if (dp == NULL) {
		handle_error("out of memory");
		*error = -1;
	} else {

		/* Get name */
		dp->name = get_device_name(disk, error);
		if (!*error) {

			/* Get aliases */
			dp->aliases = get_disk_aliases(disk, dp->name, error);
			if (!*error) {

				/* Get media */
				dm_descriptor_t *media =
				    dm_get_associated_descriptors(disk,
				    DM_MEDIA, error);
				if (*error != 0 || media == NULL ||
				    *media == NULL) {
					handle_error(
					    "could not get media from disk %s",
					    dp->name);
					*error = -1;
				} else {
					/* Get size */
					get_disk_size(media[0], dp->name,
					    &(dp->size), &(dp->blocksize),
					    error);
					if (!*error) {
						/* Get free slices */
						dp->slices =
						    get_disk_usable_slices(
						    media[0], dp->name,
						    dp->blocksize,
						    &(dp->in_use), error);
					}
					dm_free_descriptors(media);
				}
			}
		}
	}

	if (*error) {
		/* Normalize error */
		*error = -1;

		if (dp != NULL) {
			dmgt_free_disk(dp);
			dp = NULL;
		}
	}

	return (dp);
}

static char **
get_disk_aliases(dm_descriptor_t disk, char *name, int *error)
{
	char **names = NULL;
	dm_descriptor_t *aliases;

	*error = 0;
	aliases = dm_get_associated_descriptors(disk, DM_ALIAS, error);
	if (*error || aliases == NULL) {
		*error = -1;
		handle_error("could not get aliases for disk %s", name);
	} else {

		int j;

		/* Count aliases */
		for (j = 0; aliases[j] != NULL; j++)
			;

		names = (char **)calloc(j + 1, sizeof (char *));
		if (names == NULL) {
			*error = -1;
			handle_error("out of memory");
		} else {

			/* For each alias... */
			for (j = 0; *error == 0 && aliases[j] != NULL; j++) {

				dm_descriptor_t alias = aliases[j];
				char *aname = dm_get_name(alias, error);
				if (*error) {
					handle_error("could not get alias %d "
					    "for disk %s", (j + 1), name);
				} else {
					names[j] = strdup(aname);
					if (names[j] == NULL) {
						*error = -1;
						handle_error("out of memory");
					}

					dm_free_name(aname);
				}
			}
		}

		dm_free_descriptors(aliases);
	}

	if (*error && names != NULL) {
		/* Free previously-allocated names */
		zjni_free_array((void **)names, free);
	}

	return (names);
}

static int
get_disk_online(dm_descriptor_t disk, int *error)
{
	uint32_t status = 0;

	nvlist_t *attrs;
	*error = 0;
	attrs = dm_get_attributes(disk, error);
	if (*error) {
		handle_error("could not get disk attributes for disk");
	} else {

		/* Try to get the status */
		nvpair_t *match = zjni_nvlist_walk_nvpair(
		    attrs, DM_STATUS, DATA_TYPE_UINT32, NULL);

		if (match == NULL || nvpair_value_uint32(match, &status)) {

			handle_error("could not get status of disk");
			*error = 1;
		}

		nvlist_free(attrs);
	}

	return (status != 0);
}

/*
 * Gets the slices for the given disk.
 *
 * Results:
 *
 *  1. Success: error is set to 0 and slices are returned
 *
 *  2. Failure: error is set to -1 and NULL is returned
 */
static dmgt_slice_t **
get_disk_slices(dm_descriptor_t media, const char *name, uint32_t blocksize,
    int *error)
{
	dm_descriptor_t *slices;
	dmgt_slice_t **sap = NULL;

	*error = 0;
	slices = dm_get_associated_descriptors(media, DM_SLICE, error);
	if (*error != 0) {
		handle_error("could not get slices of disk %s", name);
	} else {
		int j;
		int nslices = 0;

		/* For each slice... */
		for (j = 0; *error == 0 &&
		    slices != NULL && slices[j] != NULL; j++) {

			/* Get slice */
			dmgt_slice_t *slice =
			    get_slice(slices[j], blocksize, error);
			if (!*error) {

				dmgt_slice_t **mem =
				    (dmgt_slice_t **)realloc(sap,
				    (nslices + 2) * sizeof (dmgt_slice_t *));

				if (mem == NULL) {
					handle_error("out of memory");
					*error = -1;
				} else {

					sap = mem;

					/* NULL-terminated array */
					sap[nslices] = slice;
					sap[nslices + 1] = NULL;

					nslices++;
				}
			}
		}

		dm_free_descriptors(slices);
	}

	if (*error) {
		/* Normalize error */
		*error = -1;

		if (sap != NULL) {
			zjni_free_array((void **)sap,
			    (zjni_free_f)dmgt_free_slice);
			sap = NULL;
		}
	}

	return (sap);
}

static void
remove_slice_from_list(dmgt_slice_t **slices, int index)
{
	int i;
	for (i = index; slices[i] != NULL; i++) {
		slices[i] = slices[i + 1];
	}
}

static int
slices_overlap(dmgt_slice_t *slice1, dmgt_slice_t *slice2)
{

	uint64_t start1 = slice1->start;
	uint64_t end1 = start1 + slice1->size - 1;
	uint64_t start2 = slice2->start;
	uint64_t end2 = start2 + slice2->size - 1;

	int overlap = (start2 <= end1 && start1 <= end2);

#ifdef DEBUG
	if (overlap) {
		(void) fprintf(stderr, "can't use %s: overlaps with %s\n",
		    slice2->name, slice1->name);
		(void) fprintf(stderr, "  1: start: %llu - %llu\n",
		    (unsigned long long)start1, (unsigned long long)end1);
		(void) fprintf(stderr, "  2: start: %llu - %llu\n",
		    (unsigned long long)start2, (unsigned long long)end2);
	}
#endif

	return (overlap);
}

/*
 * Gets the slices for the given disk.
 *
 * Results:
 *
 *  1. Success: error is set to 0 and slices are returned
 *
 *  2. Failure: error is set to -1 and NULL is returned
 */
static dmgt_slice_t **
get_disk_usable_slices(dm_descriptor_t media, const char *name,
    uint32_t blocksize, int *in_use, int *error)
{
	dmgt_slice_t **slices = get_disk_slices(media, name, blocksize, error);
	if (*error) {
		slices = NULL;
	}

	*in_use = 0;

	if (slices != NULL) {
		int i, nslices;

		for (nslices = 0; slices[nslices] != NULL; nslices++)
			;

		/* Prune slices based on use */
		for (i = nslices - 1; i >= 0; i--) {
			dmgt_slice_t *slice = slices[i];
			int s_in_use;

			/*
			 * Slice at this index could be NULL if
			 * removed in earlier iteration
			 */
			if (slice == NULL) {
				continue;
			}

			s_in_use = slice_in_use(slice, error);
			if (*error) {
				break;
			}

			if (s_in_use) {
				int j;
				remove_slice_from_list(slices, i);

				/* Disk is in use */
				*in_use = 1;

				/*
				 * Remove any slice that overlaps with this
				 * in-use slice
				 */
				for (j = nslices - 1; j >= 0; j--) {
					dmgt_slice_t *slice2 = slices[j];

					if (slice2 != NULL &&
					    slices_overlap(slice, slice2)) {
						remove_slice_from_list(slices,
						    j);
						dmgt_free_slice(slice2);
					}
				}

				dmgt_free_slice(slice);
			} else if (slice_too_small(slice)) {
				remove_slice_from_list(slices, i);
				dmgt_free_slice(slice);
			}
		}
	}

	if (*error) {
		/* Normalize error */
		*error = -1;

		if (slices != NULL) {
			zjni_free_array((void **)slices,
			    (zjni_free_f)dmgt_free_slice);
			slices = NULL;
		}
	}

	return (slices);
}

static void
get_disk_size(dm_descriptor_t media, char *name, uint64_t *size,
    uint32_t *blocksize, int *error)
{
	nvlist_t *attrs;

	*size = 0;
	*error = 0;

	attrs = dm_get_attributes(media, error);

	if (*error) {
		handle_error("could not get media attributes from disk: %s",
		    name);
	} else {
		/* Try to get the number of accessible blocks */
		nvpair_t *match = zjni_nvlist_walk_nvpair(
		    attrs, DM_NACCESSIBLE, DATA_TYPE_UINT64, NULL);
		if (match == NULL || nvpair_value_uint64(match, size)) {

			/* Disk is probably not labeled, get raw size instead */
			match = zjni_nvlist_walk_nvpair(
			    attrs, DM_SIZE, DATA_TYPE_UINT64, NULL);
			if (match == NULL || nvpair_value_uint64(match, size)) {
				handle_error("could not get size of disk: %s",
				    name);
				*error = 1;
			}
		}

		if (*error == 0) {
			match = zjni_nvlist_walk_nvpair(
			    attrs, DM_BLOCKSIZE, DATA_TYPE_UINT32, NULL);
			if (match == NULL ||
			    nvpair_value_uint32(match, blocksize)) {
				handle_error("could not get "
				    "block size of disk: %s", name);
				*error = 1;
			} else {
				*size *= *blocksize;
			}
		}

		nvlist_free(attrs);
	}
}

static void
get_slice_use(dm_descriptor_t slice, char *name, char **used_name,
    char **used_by, int *error)
{
	/* Get slice use statistics */
	nvlist_t *stats = dm_get_stats(slice, DM_SLICE_STAT_USE, error);
	if (*error != 0) {
		handle_error("could not get stats of slice %s", name);
	} else {

		*used_name = NULL;
		*used_by = NULL;

		if (stats != NULL) {
			char *tmp;
			nvpair_t *match;

			/* Get the type of usage for this slice */
			match = zjni_nvlist_walk_nvpair(
			    stats, DM_USED_BY, DATA_TYPE_STRING, NULL);

			if (match != NULL &&
			    nvpair_value_string(match, &tmp) == 0) {

				*used_name = strdup(tmp);
				if (*used_name == NULL) {
					*error = -1;
					handle_error("out of memory");
				} else {

					/* Get the object using this slice */
					match =
					    zjni_nvlist_walk_nvpair(stats,
					    DM_USED_NAME, DATA_TYPE_STRING,
					    NULL);

					if (match != NULL &&
					    nvpair_value_string(match, &tmp) ==
					    0) {
						*used_by = strdup(tmp);
						if (*used_by == NULL) {
							*error = -1;
							handle_error(
							    "out of memory");
						}
					}
				}
			}
			nvlist_free(stats);
		}
	}
}

static dmgt_slice_t *
get_slice(dm_descriptor_t slice, uint32_t blocksize, int *error)
{
	dmgt_slice_t *sp;
	*error = 0;
	sp = (dmgt_slice_t *)calloc(1, sizeof (dmgt_slice_t));
	if (sp == NULL) {
		*error = -1;
		handle_error("out of memory");
	} else {

		/* Get name */
		sp->name = get_device_name(slice, error);
		if (!*error) {

			nvlist_t *attrs = dm_get_attributes(slice, error);
			if (*error) {
				handle_error("could not get "
				    "attributes from slice: %s", sp->name);
			} else {
				/* Get the size in blocks */
				nvpair_t *match = zjni_nvlist_walk_nvpair(
				    attrs, DM_SIZE, DATA_TYPE_UINT64, NULL);
				uint64_t size_blocks;

				sp->size = 0;

				if (match == NULL ||
				    nvpair_value_uint64(match, &size_blocks)) {
					handle_error("could not get "
					    "size of slice: %s", sp->name);
					*error = 1;
				} else {
					uint64_t start_blocks;

					/* Convert to bytes */
					sp->size = blocksize * size_blocks;

					/* Get the starting block */
					match = zjni_nvlist_walk_nvpair(
					    attrs, DM_START, DATA_TYPE_UINT64,
					    NULL);

					if (match == NULL ||
					    nvpair_value_uint64(match,
					    &start_blocks)) {
						handle_error(
						    "could not get "
						    "start block of slice: %s",
						    sp->name);
						*error = 1;
					} else {
						/* Convert to bytes */
						sp->start =
						    blocksize * start_blocks;

						/* Set slice use */
						get_slice_use(slice, sp->name,
						    &(sp->used_name),
						    &(sp->used_by), error);
					}
				}
			}
		}
	}

	if (*error && sp != NULL) {
		dmgt_free_slice(sp);
	}

	return (sp);
}

static void
handle_error(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	if (error_func != NULL) {
		error_func(format, ap);
	}

	va_end(ap);
}

/* Should go away once 6285992 is fixed */
static int
slice_too_small(dmgt_slice_t *slice)
{
	/* Check size */
	if (slice->size < SPA_MINDEVSIZE) {
#ifdef DEBUG
		(void) fprintf(stderr, "can't use %s: slice too small: %llu\n",
		    slice->name, (unsigned long long)slice->size);
#endif
		return (1);
	}

	return (0);
}

static int
slice_in_use(dmgt_slice_t *slice, int *error)
{
	char *msg = NULL;
	int in_use;

	/* Determine whether this slice could be passed to "zpool -f" */
	in_use = dm_inuse(slice->name, &msg, DM_WHO_ZPOOL_FORCE, error);
	if (*error) {
		handle_error("%s: could not determine usage", slice->name);
	}

#ifdef DEBUG
	if (in_use) {
		(void) fprintf(stderr,
		    "can't use %s: used name: %s: used by: %s\n  message: %s\n",
		    slice->name, slice->used_name, slice->used_by, msg);
	}
#endif

	if (msg != NULL) {
		free(msg);
	}

	return (in_use);
}

/*
 * Extern functions
 */

/*
 * Iterates through each available disk on the system.  For each free
 * dmgt_disk_t *, runs the given function with the dmgt_disk_t * as
 * the first arg and the given void * as the second arg.
 */
int
dmgt_avail_disk_iter(dmgt_disk_iter_f func, void *data)
{
	int error = 0;
	int filter[] = { DM_DT_FIXED, -1 };

	/* Search for fixed disks */
	dm_descriptor_t *disks = dm_get_descriptors(DM_DRIVE, filter, &error);

	if (error) {
		handle_error("unable to communicate with libdiskmgt");
	} else {
		int i;

		/* For each disk... */
		for (i = 0; disks != NULL && disks[i] != NULL; i++) {
			dm_descriptor_t disk = (dm_descriptor_t)disks[i];
			int online;

			/* Reset error flag for each disk */
			error = 0;

			/* Is this disk online? */
			online = get_disk_online(disk, &error);
			if (!error && online) {

				/* Get a dmgt_disk_t for this dm_descriptor_t */
				dmgt_disk_t *dp = get_disk(disk, &error);
				if (!error) {

					/*
					 * If this disk or any of its
					 * slices is usable...
					 */
					if (!dp->in_use ||
					    zjni_count_elements(
					    (void **)dp->slices) != 0) {

						/* Run the given function */
						if (func(dp, data)) {
							error = -1;
						}
						dmgt_free_disk(dp);
#ifdef DEBUG
					} else {
						(void) fprintf(stderr, "disk "
						    "has no available slices: "
						    "%s\n", dp->name);
#endif
					}

				}
			}
		}
		dm_free_descriptors(disks);
	}
	return (error);
}

void
dmgt_free_disk(dmgt_disk_t *disk)
{
	if (disk != NULL) {
		free(disk->name);
		zjni_free_array((void **)disk->aliases, free);
		zjni_free_array((void **)disk->slices,
		    (zjni_free_f)dmgt_free_slice);
		free(disk);
	}
}

void
dmgt_free_slice(dmgt_slice_t *slice)
{
	if (slice != NULL) {
		free(slice->name);
		free(slice->used_name);
		free(slice->used_by);
		free(slice);
	}
}

/*
 * For clients that need to capture error output.
 */
void
dmgt_set_error_handler(void (*func)(const char *, va_list))
{
	error_func = func;
}
