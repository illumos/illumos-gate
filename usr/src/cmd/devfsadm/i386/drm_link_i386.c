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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

/*
 * Note: separate from misc_link_i386.c because this will later
 * move to the gfx-drm gate.
 */

static int agp_process(di_minor_t minor, di_node_t node);
static int drm_node(di_minor_t minor, di_node_t node);

static devfsadm_create_t drm_cbt[] = {
	{ "drm", "ddi_display:drm", NULL,
	    TYPE_EXACT, ILEVEL_0,	drm_node
	},
	{ "agp", "ddi_agp:pseudo", NULL,
	    TYPE_EXACT, ILEVEL_0, agp_process
	},
	{ "agp", "ddi_agp:target", NULL,
	    TYPE_EXACT, ILEVEL_0, agp_process
	},
	{ "agp", "ddi_agp:cpugart", NULL,
	    TYPE_EXACT, ILEVEL_0, agp_process
	},
	{ "agp", "ddi_agp:master", NULL,
	    TYPE_EXACT, ILEVEL_0, agp_process
	},
};

DEVFSADM_CREATE_INIT_V0(drm_cbt);

/*
 * For debugging, run devfsadm like this:
 *  devfsadm -V drm_mid -V devfsadm:enum -c drm
 */
static char *debug_mid = "drm_mid";

typedef enum {
	DRIVER_AGPPSEUDO = 0,
	DRIVER_AGPTARGET,
	DRIVER_CPUGART,
	DRIVER_AGPMASTER_DRM_I915,
	DRIVER_AGPMASTER_DRM_RADEON,
	DRIVER_AGPMASTER_VGATEXT,
	DRIVER_UNKNOWN
} driver_defs_t;

typedef struct {
	char	*driver_name;
	int	index;
} driver_name_table_entry_t;

static driver_name_table_entry_t driver_name_table[] = {
	{ "agpgart",		DRIVER_AGPPSEUDO },
	{ "agptarget",		DRIVER_AGPTARGET },
	{ "amd64_gart",		DRIVER_CPUGART },
	/* AGP master device managed by drm driver */
	{ "i915",		DRIVER_AGPMASTER_DRM_I915 },
	{ "radeon",		DRIVER_AGPMASTER_DRM_RADEON },
	{ "vgatext",		DRIVER_AGPMASTER_VGATEXT },
	{ NULL,			DRIVER_UNKNOWN }
};

static devfsadm_enumerate_t agptarget_rules[1] =
	{ "^agp$/^agptarget([0-9]+)$", 1, MATCH_ALL };
static devfsadm_enumerate_t cpugart_rules[1] =
	{ "^agp$/^cpugart([0-9]+)$", 1, MATCH_ALL };
static devfsadm_enumerate_t agpmaster_rules[1] =
	{ "^agp$/^agpmaster([0-9]+)$", 1, MATCH_ALL };
static devfsadm_enumerate_t drm_rules[1] =
	{ "^dri$/^card([0-9]+)$", 1, MATCH_ALL };


/*
 * HOT auto cleanup of drm+agp links not desired.
 */
static devfsadm_remove_t drm_remove_cbt[] = {
	{ "agp", "^agpgart$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "agp", "^agp/agpmaster[0-9]+$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "agp", "^agp/agptarget[0-9]+$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "agp", "^agp/cpugart[0-9]+$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "drm", "^dri/card[0-9]+$", RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
};

DEVFSADM_REMOVE_INIT_V0(drm_remove_cbt);

static int
agp_process(di_minor_t minor, di_node_t node)
{
	char *minor_nm, *drv_nm;
	char *devfspath;
	char *I_path, *p_path, *buf;
	char *name = (char *)NULL;
	int i, index;
	devfsadm_enumerate_t rules[1];

	minor_nm = di_minor_name(minor);
	drv_nm = di_driver_name(node);

	if ((minor_nm == NULL) || (drv_nm == NULL)) {
		return (DEVFSADM_CONTINUE);
	}

	devfsadm_print(debug_mid, "agp_process: minor=%s node=%s\n",
	    minor_nm, di_node_name(node));

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_print(debug_mid, "agp_process: devfspath is NULL\n");
		return (DEVFSADM_CONTINUE);
	}

	I_path = (char *)malloc(PATH_MAX);

	if (I_path == NULL) {
		di_devfs_path_free(devfspath);
		devfsadm_print(debug_mid,  "agp_process: malloc failed\n");
		return (DEVFSADM_CONTINUE);
	}

	p_path = (char *)malloc(PATH_MAX);

	if (p_path == NULL) {
		devfsadm_print(debug_mid,  "agp_process: malloc failed\n");
		di_devfs_path_free(devfspath);
		free(I_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) strlcpy(p_path, devfspath, PATH_MAX);
	(void) strlcat(p_path, ":", PATH_MAX);
	(void) strlcat(p_path, minor_nm, PATH_MAX);
	di_devfs_path_free(devfspath);

	devfsadm_print(debug_mid, "agp_process: path %s\n", p_path);

	for (i = 0; ; i++) {
		if ((driver_name_table[i].driver_name == NULL) ||
		    (strcmp(drv_nm, driver_name_table[i].driver_name) == 0)) {
			index = driver_name_table[i].index;
			break;
		}
	}
	switch (index) {
	case DRIVER_AGPPSEUDO:
		devfsadm_print(debug_mid,
		    "agp_process: psdeudo driver name\n");
		name = "agpgart";
		(void) snprintf(I_path, PATH_MAX, "%s", name);
		devfsadm_print(debug_mid,
		    "mklink %s -> %s\n", I_path, p_path);

		(void) devfsadm_mklink(I_path, node, minor, 0);

		free(I_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	case DRIVER_AGPTARGET:
		devfsadm_print(debug_mid,
		    "agp_process: target driver name\n");
		rules[0] = agptarget_rules[0];
		name = "agptarget";
		break;
	case DRIVER_CPUGART:
		devfsadm_print(debug_mid,
		    "agp_process: cpugart driver name\n");
		rules[0] = cpugart_rules[0];
		name = "cpugart";
		break;
	case DRIVER_AGPMASTER_DRM_I915:
	case DRIVER_AGPMASTER_DRM_RADEON:
	case DRIVER_AGPMASTER_VGATEXT:
		devfsadm_print(debug_mid,
		    "agp_process: agpmaster driver name\n");
		rules[0] = agpmaster_rules[0];
		name = "agpmaster";
		break;
	case DRIVER_UNKNOWN:
		devfsadm_print(debug_mid,
		    "agp_process: unknown driver name=%s\n", drv_nm);
		free(I_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	}

	if (devfsadm_enumerate_int(p_path, 0, &buf, rules, 1)) {
		devfsadm_print(debug_mid, "agp_process: exit/coninue\n");
		free(I_path);
		free(p_path);
		return (DEVFSADM_CONTINUE);
	}


	(void) snprintf(I_path, PATH_MAX, "agp/%s%s", name, buf);

	devfsadm_print(debug_mid, "agp_process: p_path=%s buf=%s\n",
	    p_path, buf);

	free(buf);

	devfsadm_print(debug_mid, "mklink %s -> %s\n", I_path, p_path);

	(void) devfsadm_mklink(I_path, node, minor, 0);

	free(p_path);
	free(I_path);

	return (DEVFSADM_CONTINUE);
}

static int
drm_node(di_minor_t minor, di_node_t node)
{
	char *minor_nm, *drv_nm;
	char *devfspath;
	char *I_path, *p_path, *buf;
	char *name = "card";

	minor_nm = di_minor_name(minor);
	drv_nm = di_driver_name(node);
	if ((minor_nm == NULL) || (drv_nm == NULL)) {
		return (DEVFSADM_CONTINUE);
	}

	devfsadm_print(debug_mid, "drm_node: minor=%s node=%s type=%s\n",
	    minor_nm, di_node_name(node), di_minor_nodetype(minor));

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		devfsadm_print(debug_mid, "drm_node: devfspath is NULL\n");
		return (DEVFSADM_CONTINUE);
	}

	I_path = (char *)malloc(PATH_MAX);

	if (I_path == NULL) {
		di_devfs_path_free(devfspath);
		devfsadm_print(debug_mid,  "drm_node: malloc failed\n");
		return (DEVFSADM_CONTINUE);
	}

	p_path = (char *)malloc(PATH_MAX);

	if (p_path == NULL) {
		devfsadm_print(debug_mid,  "drm_node: malloc failed\n");
		di_devfs_path_free(devfspath);
		free(I_path);
		return (DEVFSADM_CONTINUE);
	}

	(void) strlcpy(p_path, devfspath, PATH_MAX);
	(void) strlcat(p_path, ":", PATH_MAX);
	(void) strlcat(p_path, minor_nm, PATH_MAX);
	di_devfs_path_free(devfspath);

	devfsadm_print(debug_mid, "drm_node: p_path %s\n", p_path);

	if (devfsadm_enumerate_int(p_path, 0, &buf, drm_rules, 1)) {
		free(p_path);
		devfsadm_print(debug_mid, "drm_node: exit/coninue\n");
		return (DEVFSADM_CONTINUE);
	}
	(void) snprintf(I_path, PATH_MAX, "dri/%s%s", name, buf);

	devfsadm_print(debug_mid, "drm_node: p_path=%s buf=%s\n",
	    p_path, buf);

	free(buf);

	devfsadm_print(debug_mid, "mklink %s -> %s\n", I_path, p_path);
	(void) devfsadm_mklink(I_path, node, minor, 0);

	free(p_path);
	free(I_path);

	return (0);
}
