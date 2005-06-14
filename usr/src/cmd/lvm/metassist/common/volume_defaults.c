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

#include <string.h>
#include <libintl.h>
#include "volume_defaults.h"
#include "volume_error.h"

/*
 * Methods which manipulate a defaults_t struct
 */

static int defaults_get_singleton_component(
	defaults_t *defaults, char *disksetname,
	component_type_t type, devconfig_t **component, boolean_t create);

/*
 * Constructor: Create a defaults_t struct populated with default
 * values. This defaults_t must be freed.
 *
 * @param       defaults
 *              RETURN: a pointer to a new defaults_t
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
new_defaults(
	defaults_t **defaults)
{
	devconfig_t *diskset;
	int error = 0;

	*defaults = (defaults_t *)calloc(1, sizeof (defaults_t));
	if (*defaults == NULL) {
	    volume_set_error(gettext("new_defaults calloc() failed"));
	    return (-1);
	}

	/*
	 * Create initial "global" (disk set-independent) defaults, as
	 * a devconfig_t of type disk set with NULL name
	 */
	if ((error = new_devconfig(&diskset, TYPE_DISKSET)) != 0) {
	    free_defaults(*defaults);
	    return (error);
	}

	/* Append global defaults disk set to disksets */
	defaults_set_disksets(
	    *defaults, dlist_append(dlist_new_item(diskset),
	    defaults_get_disksets(*defaults), AT_TAIL));

	/* Set defaults */
	if ((error = defaults_set_mirror_nsubs(
		*defaults, NULL, DEFAULT_MIRROR_NSUBS)) != 0 ||

	    (error = defaults_set_mirror_read(
		*defaults, NULL, DEFAULT_MIRROR_READ)) != 0 ||

	    (error = defaults_set_mirror_write(
		*defaults, NULL, DEFAULT_MIRROR_WRITE)) != 0 ||

	    (error = defaults_set_mirror_pass(
		*defaults, NULL, DEFAULT_MIRROR_PASS)) != 0 ||

	    (error = defaults_set_mirror_usehsp(
		*defaults, NULL, DEFAULT_MIRROR_USEHSP)) != 0 ||

	    (error = defaults_set_concat_usehsp(
		*defaults, NULL, DEFAULT_CONCAT_USEHSP)) != 0 ||

	    (error = defaults_set_stripe_interlace(
		*defaults, NULL, DEFAULT_STRIPE_INTERLACE)) != 0 ||

	    (error = defaults_set_stripe_mincomp(
		*defaults, NULL, DEFAULT_STRIPE_MINCOMP)) != 0 ||

	    (error = defaults_set_stripe_maxcomp(
		*defaults, NULL, DEFAULT_STRIPE_MAXCOMP)) != 0 ||

	    (error = defaults_set_stripe_usehsp(
		*defaults, NULL, DEFAULT_STRIPE_USEHSP)) != 0 ||

	    (error = defaults_set_volume_redundancy_level(
		*defaults, NULL, DEFAULT_VOLUME_REDUND_LEVEL)) != 0 ||

	    (error = defaults_set_volume_npaths(
		*defaults, NULL, DEFAULT_VOLUME_NPATHS)) != 0 ||

	    (error = defaults_set_volume_usehsp(
		*defaults, NULL, DEFAULT_VOLUME_USEHSP)) != 0) {

	    free_defaults(*defaults);
	    return (error);
	}

	return (0);
}

/*
 * Free memory (recursively) allocated to a defaults_t struct
 *
 * @param       arg
 *              pointer to the defaults_t struct to free
 */
void
free_defaults(
	void *arg)
{
	defaults_t *defaults = (defaults_t *)arg;

	if (defaults == NULL) {
	    return;
	}

	/* Free the disksets */
	if (defaults->disksets != NULL) {
	    dlist_free_items(defaults->disksets, free_devconfig);
	}

	/* Free the devconfig itself */
	free(defaults);
}

/*
 * Set list of diskset specific defaults
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       disksets
 *              a dlist_t representing the defaults for specific
 *              named disk sets
 */
void
defaults_set_disksets(
	defaults_t *defaults,
	dlist_t *disksets)
{
	defaults->disksets = disksets;
}

/*
 * Get list of diskset specific defaults
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @return      a dlist_t representing the defaults for specific
 *              named disk sets
 */
dlist_t *
defaults_get_disksets(
	defaults_t *defaults)
{
	return (defaults->disksets);
}

/*
 * Get a disk set with the given name from the given defaults_t
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       name
 *              the name of the disk set whose defaults to retrieve,
 *              or NULL to get the defaults for all disk sets
 *
 * @param       diskset
 *              RETURN: defaults for the given named disk set, or
 *              defaults for all disk sets if name is NULL
 *
 * @return      ENOENT
 *              if the named disk set does not exist
 *
 * @return      0
 *              if the named disk set exists
 */
int
defaults_get_diskset_by_name(
	defaults_t *defaults,
	char *name,
	devconfig_t **diskset)
{
	dlist_t *list;
	*diskset = NULL;

	/* Get list of disk sets */
	list = defaults_get_disksets(defaults);
	if (list != NULL) {

	    /* For each disk set-specific defaults... */
	    for (; list != NULL; list = list->next) {

		char *dname = NULL;
		devconfig_t *d = (devconfig_t *)list->obj;

		/* Get the name if this disk set */
		devconfig_get_name(d, &dname);

		/* Do the names match? */
		if (
		    /* Global defaults disk set */
		    (name == NULL && dname == NULL) ||

		    /* Named disk set */
		    (name != NULL && dname != NULL &&
			strcmp(name, dname) == 0)) {

		    *diskset = d;
		    break;
		}
	    }
	}

	/* Diskset doesn't exist */
	if (*diskset == NULL) {
	    return (ENOENT);
	}

	return (0);
}

/*
 * Get the first component of the given type from the given disk set.
 * If not found, create the component if requested.
 *
 * @return      ENOENT
 *              if the given disk set does not exist, or it exists,
 *              but the requested component does not exist under it
 *              and its creation was not requested
 *
 * @return      0
 *              if the requested component exists or was created
 *
 * @return      non-zero
 *              if the requested component does not exist and could
 *              not be created
 */
static int
defaults_get_singleton_component(
	defaults_t *defaults,
	char *disksetname,
	component_type_t type,
	devconfig_t **component,
	boolean_t create)
{
	int error;
	devconfig_t *diskset;

	/* Get the disk set referred to */
	if ((error = defaults_get_diskset_by_name(
	    defaults, disksetname, &diskset)) != 0) {

	    volume_set_error(
		gettext("could not get defaults for disk set %s"),
		disksetname == NULL ? gettext("<NULL>") : disksetname);

	    return (error);
	}

	/*
	 * Get the singleton component under this disk set, create if
	 * requested
	 */
	return (devconfig_get_component(diskset, type, component, create));
}

/*
 * Set name of the the default HSP to use
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       name
 *              the name of the default HSP to use
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_hsp_name(
	defaults_t *defaults,
	char *diskset,
	char *name)
{
	devconfig_t *hsp = NULL;
	int error = 0;

	/* Get/create singleton HSP element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_HSP, &hsp, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the name attribute */
	return (devconfig_set_hsp_name(hsp, name));
}

/*
 * Get the name of the default HSP to use
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       name
 *              RETURN: the name of the default HSP to use
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_hsp_name(
    defaults_t *defaults,
    char *diskset,
    char **name)
{
	char *disksets[2];
	devconfig_t *hsp;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton HSP element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_HSP, &hsp, FALSE);

	    switch (error) {
		/* HSP found for this disk set */
		case 0:
		    /* Get the nsubs attribute */
		    if ((error = devconfig_get_name(hsp, name)) == 0) {
			/* nsubs attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* HSP not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or HSP couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default number of submirrors for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default number of submirrors
 *              for mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_mirror_nsubs(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *mirror = NULL;
	int error = 0;

	/* Get/create singleton mirror element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_MIRROR, &mirror, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the nsubs attribute */
	return (devconfig_set_mirror_nsubs(mirror, val));
}

/*
 * Get the default number of submirrors for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default number of submirrors for mirrored
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_mirror_nsubs(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *mirror;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton mirror element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_MIRROR, &mirror, FALSE);

	    switch (error) {
		/* mirror found for this disk set */
		case 0:
		    /* Get the nsubs attribute */
		    if ((error = devconfig_get_mirror_nsubs(
			    mirror, val)) == 0) {
			/* nsubs attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* mirror not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or mirror couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default read strategy for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default read strategy for
 *              mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_mirror_read(
	defaults_t *defaults,
	char *diskset,
	mirror_read_strategy_t val)
{
	devconfig_t *mirror = NULL;
	int error = 0;

	/* Get/create singleton mirror element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_MIRROR, &mirror, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the read attribute */
	return (devconfig_set_mirror_read(mirror, val));
}

/*
 * Get the default read strategy for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default read strategy for mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_mirror_read(
	defaults_t *defaults,
	char *diskset,
	mirror_read_strategy_t *val)
{
	char *disksets[2];
	devconfig_t *mirror;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton mirror element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_MIRROR, &mirror, FALSE);

	    switch (error) {
		/* mirror found for this disk set */
		case 0:
		    /* Get the read attribute */
		    if ((error = devconfig_get_mirror_read(mirror, val)) == 0) {
			/* read attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* mirror not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or mirror couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default write strategy for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default write strategy for
 *              mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_mirror_write(
	defaults_t *defaults,
	char *diskset,
	mirror_write_strategy_t val)
{
	devconfig_t *mirror = NULL;
	int error = 0;

	/* Get/create singleton mirror element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_MIRROR, &mirror, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the write attribute */
	return (devconfig_set_mirror_write(mirror, val));
}

/*
 * Get the default write strategy for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default write strategy for mirrored
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_mirror_write(
	defaults_t *defaults,
	char *diskset,
	mirror_write_strategy_t *val)
{
	char *disksets[2];
	devconfig_t *mirror;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton mirror element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_MIRROR, &mirror, FALSE);

	    switch (error) {
		/* mirror found for this disk set */
		case 0:
		    /* Get the write attribute */
		    if ((error = devconfig_get_mirror_write(
			    mirror, val)) == 0) {
			/* write attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* mirror not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or mirror couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default resync pass for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default resync pass for
 *              mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_mirror_pass(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *mirror = NULL;
	int error = 0;

	/* Get/create singleton mirror element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_MIRROR, &mirror, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the pass attribute */
	return (devconfig_set_mirror_pass(mirror, val));
}

/*
 * Get the default resync pass for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default resync pass for mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_mirror_pass(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *mirror;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton mirror element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_MIRROR, &mirror, FALSE);

	    switch (error) {
		/* mirror found for this disk set */
		case 0:
		    /* Get the pass attribute */
		    if ((error = devconfig_get_mirror_pass(mirror, val)) == 0) {
			/* pass attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* mirror not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or mirror couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default HSP creation flag for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default HSP creation flag for
 *              mirrored volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_mirror_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t val)
{
	devconfig_t *mirror = NULL;
	int error = 0;

	/* Get/create singleton mirror element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_MIRROR, &mirror, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the usehsp attribute */
	return (devconfig_set_volume_usehsp(mirror, val));
}

/*
 * Get the default HSP creation flag for mirrored volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default HSP creation flag for mirrored
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_mirror_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t *val)
{
	char *disksets[2];
	devconfig_t *mirror;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton mirror element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_MIRROR, &mirror, FALSE);

	    switch (error) {
		/* mirror found for this disk set */
		case 0:
		    /* Get the usehsp attribute */
		    if ((error = devconfig_get_volume_usehsp(
			    mirror, val)) == 0) {
			/* usehsp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* mirror not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or mirror couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default HSP creation flag for concatenated volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default HSP creation flag for
 *              concatenated volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_concat_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t val)
{
	devconfig_t *concat = NULL;
	int error = 0;

	/* Get/create singleton concat element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_CONCAT, &concat, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the usehsp attribute */
	return (devconfig_set_volume_usehsp(concat, val));
}

/*
 * Get the default HSP creation flag for concatenated volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default HSP creation flag for concatenated
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_concat_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t *val)
{
	char *disksets[2];
	devconfig_t *concat;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton concat element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_CONCAT, &concat, FALSE);

	    switch (error) {
		/* concat found for this disk set */
		case 0:
		    /* Get the usehsp attribute */
		    if ((error = devconfig_get_volume_usehsp(
			    concat, val)) == 0) {
			/* usehsp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* concat not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or concat couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default minimum number of components for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default minimum number of
 *              components for striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_stripe_mincomp(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *stripe = NULL;
	int error = 0;

	/* Get/create singleton stripe element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_STRIPE, &stripe, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the mincomp attribute */
	return (devconfig_set_stripe_mincomp(stripe, val));
}

/*
 * Get the default minimum number of components for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default minimum number of components for
 *              striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_stripe_mincomp(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *stripe;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton stripe element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_STRIPE, &stripe, FALSE);

	    switch (error) {
		/* stripe found for this disk set */
		case 0:
		    /* Get the mincomp attribute */
		    if ((error = devconfig_get_stripe_mincomp(
			    stripe, val)) == 0) {
			/* mincomp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* stripe not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or stripe couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default maximum number of components for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default maximum number of
 *              components for striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_stripe_maxcomp(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *stripe = NULL;
	int error = 0;

	/* Get/create singleton stripe element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_STRIPE, &stripe, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the maxcomp attribute */
	return (devconfig_set_stripe_maxcomp(stripe, val));
}

/*
 * Get the default maximum number of components for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default maximum number of components for
 *              striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_stripe_maxcomp(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *stripe;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton stripe element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_STRIPE, &stripe, FALSE);

	    switch (error) {
		/* stripe found for this disk set */
		case 0:
		    /* Get the maxcomp attribute */
		    if ((error = devconfig_get_stripe_maxcomp(
			    stripe, val)) == 0) {
			/* maxcomp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* stripe not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or stripe couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default interlace for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default interlace for striped
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_stripe_interlace(
	defaults_t *defaults,
	char *diskset,
	uint64_t val)
{
	devconfig_t *stripe = NULL;
	int error = 0;

	/* Get/create singleton stripe element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_STRIPE, &stripe, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the interlace attribute */
	return (devconfig_set_stripe_interlace(stripe, val));
}

/*
 * Get the default interlace for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default interlace for striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_stripe_interlace(
	defaults_t *defaults,
	char *diskset,
	uint64_t *val)
{
	char *disksets[2];
	devconfig_t *stripe;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton stripe element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_STRIPE, &stripe, FALSE);

	    switch (error) {
		/* stripe found for this disk set */
		case 0:
		    /* Get the interlace attribute */
		    if ((error = devconfig_get_stripe_interlace(
			    stripe, val)) == 0) {
			/* interlace attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* stripe not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or stripe couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default HSP creation flag for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default HSP creation flag for
 *              striped volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_stripe_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t val)
{
	devconfig_t *stripe = NULL;
	int error = 0;

	/* Get/create singleton stripe element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_STRIPE, &stripe, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the usehsp attribute */
	return (devconfig_set_volume_usehsp(stripe, val));
}

/*
 * Get the default HSP creation flag for striped volumes
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default HSP creation flag for striped
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_stripe_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t *val)
{
	char *disksets[2];
	devconfig_t *stripe;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton stripe element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_STRIPE, &stripe, FALSE);

	    switch (error) {
		/* stripe found for this disk set */
		case 0:
		    /* Get the usehsp attribute */
		    if ((error = devconfig_get_volume_usehsp(
			    stripe, val)) == 0) {
			/* usehsp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* stripe not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or stripe couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default redundancy level for generic volumes.
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              If 0, a stripe will be created by default.  If > 0, a
 *              mirror with this number of submirrors will be created
 *              by default.
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_volume_redundancy_level(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *volume = NULL;
	int error = 0;

	/* Get/create singleton volume element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_VOLUME, &volume, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the redundancy level */
	return (devconfig_set_volume_redundancy_level(volume, val));
}

/*
 * Get the default redundancy level for generic volumes.
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default redundancy level for generic
 *              volumes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_volume_redundancy_level(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *volume;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton volume element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_VOLUME, &volume, FALSE);

	    switch (error) {
		/* volume found for this disk set */
		case 0:
		    /* Get the redundancy level */
		    if ((error = devconfig_get_volume_redundancy_level(
			    volume, val)) == 0) {
			/* redundancy level found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* volume not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or volume couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default number of data paths for generic volume
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default number of data paths
 *              for generic volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_volume_npaths(
	defaults_t *defaults,
	char *diskset,
	uint16_t val)
{
	devconfig_t *volume = NULL;
	int error = 0;

	/* Get/create singleton volume element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_VOLUME, &volume, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the npaths attribute */
	return (devconfig_set_volume_npaths(volume, val));
}

/*
 * Get the default number of data paths for generic volume
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default number of data paths for generic
 *              volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_volume_npaths(
	defaults_t *defaults,
	char *diskset,
	uint16_t *val)
{
	char *disksets[2];
	devconfig_t *volume;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton volume element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_VOLUME, &volume, FALSE);

	    switch (error) {
		/* volume found for this disk set */
		case 0:
		    /* Get the npaths attribute */
		    if ((error = devconfig_get_volume_npaths(
			    volume, val)) == 0) {
			/* npaths attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* volume not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or volume couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}

/*
 * Set the default HSP creation flag for generic volume
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              the value to set as the default HSP creation flag for
 *              generic volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_set_volume_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t val)
{
	devconfig_t *volume = NULL;
	int error = 0;

	/* Get/create singleton volume element for this disk set */
	if ((error = defaults_get_singleton_component(
		defaults, diskset, TYPE_VOLUME, &volume, TRUE)) != 0) {
	    /* volume_set_error already called */
	    return (error);
	}

	/* Set the usehsp attribute */
	return (devconfig_set_volume_usehsp(volume, val));
}

/*
 * Get the default HSP creation flag for generic volume
 *
 * @param       defaults
 *              a defaults_t hierarchy representing default settings
 *              for all disk sets and specific disk sets
 *
 * @param       diskset
 *              the name of the disk set to which to apply this
 *              default setting, or NULL to apply default
 *              setting to all disk sets
 *
 * @param       val
 *              RETURN: the default HSP creation flag for generic
 *              volume
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
defaults_get_volume_usehsp(
	defaults_t *defaults,
	char *diskset,
	boolean_t *val)
{
	char *disksets[2];
	devconfig_t *volume;
	int error;
	int i = 0;

	/* Check both the given and global (NULL) disk sets for the value */
	disksets[0] = diskset;
	disksets[1] = NULL;
	do {
	    /* Get/create singleton volume element for this disk set */
	    error = defaults_get_singleton_component(
		defaults, disksets[i], TYPE_VOLUME, &volume, FALSE);

	    switch (error) {
		/* volume found for this disk set */
		case 0:
		    /* Get the usehsp attribute */
		    if ((error = devconfig_get_volume_usehsp(
			    volume, val)) == 0) {
			/* usehsp attribute found */
			return (0);
		    }

		/* FALLTHROUGH */

		/* volume not found for this disk set */
		case ENOENT:
		break;

		/* Invalid disk set, or volume couldn't be created */
		default:
		    /* volume_set_error already called */
		    return (error);
	    }

	/* Stop after the global (NULL) disk set has been searched */
	} while (disksets[i++] != NULL);

	return (ENOENT);
}
