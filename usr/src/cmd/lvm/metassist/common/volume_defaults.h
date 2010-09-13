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

#ifndef	_VOLUME_DEFAULTS_H
#define	_VOLUME_DEFAULTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "volume_devconfig.h"

#define	DEFAULT_MIRROR_NSUBS	    2
#define	DEFAULT_MIRROR_READ	    MIRROR_READ_ROUNDROBIN
#define	DEFAULT_MIRROR_WRITE	    MIRROR_WRITE_PARALLEL
#define	DEFAULT_MIRROR_PASS	    1
#define	DEFAULT_STRIPE_INTERLACE    1024 * 64
#define	DEFAULT_STRIPE_MINCOMP	    3
#define	DEFAULT_STRIPE_MAXCOMP	    10
#define	DEFAULT_VOLUME_REDUND_LEVEL 0
#define	DEFAULT_VOLUME_NPATHS	    1

/* For consistency, these should all have the same value */
#define	DEFAULT_MIRROR_USEHSP	    FALSE
#define	DEFAULT_CONCAT_USEHSP	    FALSE
#define	DEFAULT_STRIPE_USEHSP	    FALSE
#define	DEFAULT_VOLUME_USEHSP	    FALSE

/*
 * default_t - struct to hold layout defaults
 */
typedef struct defaults {
	/*
	 * List of devconfig_t, each of which represents disk set-
	 * specific defaults.  Each disk set has a name, except for
	 * the global set, whose name is NULL.
	 */
	dlist_t *disksets;
} defaults_t;

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
extern int new_defaults(defaults_t **defaults);

/*
 * Free memory (recursively) allocated to a defaults_t struct
 *
 * @param       arg
 *              pointer to the defaults_t struct to free
 */
extern void free_defaults(void *arg);

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
extern void defaults_set_disksets(defaults_t *defaults, dlist_t *disksets);
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
extern dlist_t *defaults_get_disksets(defaults_t *defaults);

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

extern int defaults_get_diskset_by_name(
    defaults_t *defaults, char *name, devconfig_t **diskset);

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
extern int defaults_set_hsp_name(
    defaults_t *defaults, char *diskset, char *name);
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
extern int defaults_get_hsp_name(
    defaults_t *defaults, char *diskset, char **name);

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
extern int defaults_set_mirror_nsubs(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_mirror_nsubs(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_mirror_read(
    defaults_t *defaults, char *diskset, mirror_read_strategy_t val);
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
extern int defaults_get_mirror_read(
    defaults_t *defaults, char *diskset, mirror_read_strategy_t *val);

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
extern int defaults_set_mirror_write(
    defaults_t *defaults, char *diskset, mirror_write_strategy_t val);
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
extern int defaults_get_mirror_write(
    defaults_t *defaults, char *diskset, mirror_write_strategy_t *val);

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
extern int defaults_set_mirror_pass(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_mirror_pass(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_mirror_usehsp(
    defaults_t *defaults, char *diskset, boolean_t val);
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
extern int defaults_get_mirror_usehsp(
    defaults_t *defaults, char *diskset, boolean_t *val);

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
extern int defaults_set_concat_usehsp(
    defaults_t *defaults, char *diskset, boolean_t val);
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
extern int defaults_get_concat_usehsp(
    defaults_t *defaults, char *diskset, boolean_t *val);

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
extern int defaults_set_stripe_mincomp(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_stripe_mincomp(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_stripe_maxcomp(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_stripe_maxcomp(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_stripe_interlace(
    defaults_t *defaults, char *diskset, uint64_t val);
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
extern int defaults_get_stripe_interlace(
    defaults_t *defaults, char *diskset, uint64_t *val);

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
extern int defaults_set_stripe_usehsp(
    defaults_t *defaults, char *diskset, boolean_t val);
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
extern int defaults_get_stripe_usehsp(
    defaults_t *defaults, char *diskset, boolean_t *val);

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
extern int defaults_set_volume_redundancy_level(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_volume_redundancy_level(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_volume_npaths(
    defaults_t *defaults, char *diskset, uint16_t val);
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
extern int defaults_get_volume_npaths(
    defaults_t *defaults, char *diskset, uint16_t *val);

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
extern int defaults_set_volume_usehsp(
    defaults_t *defaults, char *diskset, boolean_t val);
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
extern int defaults_get_volume_usehsp(
    defaults_t *defaults, char *diskset, boolean_t *val);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_DEFAULTS_H */
