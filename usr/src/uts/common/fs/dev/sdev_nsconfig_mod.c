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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this module implements the devname_ops to fetch
 * a specific entry from a /etc/dev/devname_map file or
 * a name service map.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/fs/sdev_impl.h>
#include <sys/fs/sdev_node.h>

static int devname_lookup(char *, devname_handle_t *, struct cred *);
static int devname_remove(devname_handle_t *);
static int devname_rename(devname_handle_t *, char *);
static int devname_readdir(devname_handle_t *, struct cred *);
static int devname_getattr(devname_handle_t *, struct vattr *,
    struct cred *);
static void devname_inactive(devname_handle_t *, struct cred *);

static struct devname_ops devname_ops = {
	DEVNOPS_REV,		/* devnops_rev, */
	devname_lookup,		/* devnops_lookup */
	devname_remove,		/* devnops_remove */
	devname_rename,		/* devnops_rename */
	devname_getattr,	/* devnops_getattr */
	devname_readdir,	/* devname_readdir */
	devname_inactive	/* devname_inactive */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldev modldev = {
	&mod_devfsops,
	"devname name service mod 1.0",
	&devname_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldev, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED2*/
static int
devname_lookup(char *nm, devname_handle_t *dhl, struct cred *cred)
{
	int error = 0;
	char *dir = NULL;
	devname_lkp_arg_t *args = NULL;
	devname_lkp_result_t *result = NULL;
	struct devname_nsmap *map = NULL;

	args = kmem_zalloc(sizeof (struct devname_lkp_arg), KM_SLEEP);
	if (args == NULL) {
		error = ENOENT;
		goto errout;
	}

	args->devname_name = i_ddi_strdup(nm, KM_SLEEP);
	error = devname_get_dir_path(dhl, &dir);
	if (error) {
		error = ENOENT;
		goto errout;
	}

	args->devname_dir = i_ddi_strdup(dir, KM_SLEEP);
	error = devname_get_dir_nsmap(dhl, &map);
	if (map && map->dir_map)
		args->devname_map = i_ddi_strdup(map->dir_map, KM_SLEEP);

	result = kmem_zalloc(sizeof (struct devname_lkp_result), KM_SLEEP);
	if (result == NULL) {
		error = ENOENT;
		goto errout;
	}


	error = devname_nsmap_lookup(args, &result);
	if (error) {
		error = ENOENT;
		goto errout;
	}

	devname_set_nodetype(dhl, (void *)result->devname_link,
	    (int)result->devname_spec);

errout:
	if (args->devname_name)
		kmem_free(args->devname_name, strlen(args->devname_name) + 1);
	if (args->devname_dir)
		kmem_free(args->devname_dir, strlen(args->devname_dir) + 1);
	if (args->devname_map)
		kmem_free(args->devname_map, strlen(args->devname_map) + 1);
	if (args)
		kmem_free(args, sizeof (struct devname_lkp_arg));
	if (result)
		kmem_free(result, sizeof (struct devname_lkp_result));
	return (error);
}

/*ARGSUSED*/
static int
devname_readdir(devname_handle_t *hdl, struct cred *cred)
{
	char *entry;
	char *dir;

	(void) devname_get_name(hdl, &entry);
	(void) devname_get_dir_name(hdl, &dir);

	/* do not waste to do the map check */
	return (0);
}

/*ARGSUSED*/
static int
devname_remove(devname_handle_t *hdl)
{
	char *entry;

	(void) devname_get_name(hdl, &entry);
	return (EROFS);
}

/*ARGSUSED*/
static int
devname_rename(devname_handle_t *ohdl, char *new_name)
{
	char *oname;

	(void) devname_get_name(ohdl, &oname);
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
devname_getattr(devname_handle_t *hdl, vattr_t *vap, struct cred *cred)
{
	return (0);
}

/*ARGSUSED*/
static void
devname_inactive(devname_handle_t *hdl, struct cred *cred)
{
}
