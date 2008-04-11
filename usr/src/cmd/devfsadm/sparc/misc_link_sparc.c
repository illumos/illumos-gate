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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mkdev.h>
#include <bsm/devalloc.h>

extern int system_labeled;


static int ddi_other(di_minor_t minor, di_node_t node);
static int diskette(di_minor_t minor, di_node_t node);
static int ecpp_create(di_minor_t minor, di_node_t node);
static int mc_node(di_minor_t minor, di_node_t node);
static int ddi_cardreader(di_minor_t minor, di_node_t node);
static int starcat_sbbc_node(di_minor_t minor, di_node_t node);
static int lom(di_minor_t minor, di_node_t node);
static int ntwdt_create(di_minor_t minor, di_node_t node);
static int bmc(di_minor_t minor, di_node_t node);

static devfsadm_create_t misc_cbt[] = {
	{ "other", "ddi_other", NULL,
	    TYPE_EXACT, ILEVEL_0, ddi_other
	},
	{ "memory-controller", "ddi_mem_ctrl", NULL,
	    TYPE_EXACT, ILEVEL_0, mc_node
	},
	{ "pseudo", "ddi_pseudo", "sbbc",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, starcat_sbbc_node
	},
	{ "disk",  "ddi_block:diskette", NULL,
	    TYPE_EXACT, ILEVEL_1, diskette
	},
	{ "printer",  "ddi_printer", NULL,
	    TYPE_EXACT, ILEVEL_1, ecpp_create
	},
	{ "card-reader", "ddi_smartcard_reader", NULL,
		TYPE_EXACT, ILEVEL_0, ddi_cardreader
	},
	{ "pseudo", "ddi_pseudo", "lw8",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, lom
	},
	{ "pseudo", "ddi_pseudo", "ntwdt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, ntwdt_create
	},
	{ "pseudo", "ddi_pseudo", "bmc",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, bmc
	}
};

DEVFSADM_CREATE_INIT_V0(misc_cbt);

/* Smart Card Reader device link */
#define	CARDREADER_LINK		"^scmi2c[0-9]+$"

/* Rules for removing links */
static devfsadm_remove_t sparc_remove_cbt[] = {
	{ "card-reader", CARDREADER_LINK, RM_PRE | RM_ALWAYS,
		ILEVEL_0, devfsadm_rm_all }
};

DEVFSADM_REMOVE_INIT_V0(sparc_remove_cbt);


/*
 * Handles minor node type "ddi_other"
 * type=ddi_other;name=SUNW,pmc    pmc
 * type=ddi_other;name=SUNW,mic    mic\M0
 */
static int
ddi_other(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1];
	char *nn = di_node_name(node);
	char *mn = di_minor_name(minor);

	if (strcmp(nn, "SUNW,pmc") == 0) {
		(void) devfsadm_mklink("pcm", node, minor, 0);
	} else if (strcmp(nn, "SUNW,mic") == 0) {
		(void) strcpy(path, "mic");
		(void) strcat(path, mn);
		(void) devfsadm_mklink(path, node, minor, 0);
	}

	return (DEVFSADM_CONTINUE);
}

/*
 * This function is called for diskette nodes
 */
static int
diskette(di_minor_t minor, di_node_t node)
{
	int	flags = 0;
	char	*mn = di_minor_name(minor);

	if (system_labeled)
		flags = DA_ADD|DA_FLOPPY;

	if (strcmp(mn, "c") == 0) {
		(void) devfsadm_mklink("diskette", node, minor, flags);
		(void) devfsadm_mklink("diskette0", node, minor, flags);

	} else if (strcmp(mn, "c,raw") == 0) {
		(void) devfsadm_mklink("rdiskette", node, minor, flags);
		(void) devfsadm_mklink("rdiskette0", node, minor, flags);

	}
	return (DEVFSADM_CONTINUE);
}

/*
 * Handles links of the form:
 * type=ddi_printer;name=ecpp  ecpp\N0
 */
static int
ecpp_create(di_minor_t minor, di_node_t node)
{
	char *buf;
	char path[PATH_MAX + 1];
	devfsadm_enumerate_t rules[1] = {"^ecpp([0-9]+)$", 1, MATCH_ALL};

	if (strcmp(di_driver_name(node), "ecpp") != 0) {
		return (DEVFSADM_CONTINUE);
	}

	if ((buf = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "%s:%s",
	    buf, di_minor_name(minor));

	di_devfs_path_free(buf);

	if (devfsadm_enumerate_int(path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "ecpp%s", buf);
	free(buf);

	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/* Rules for memory controller */
static devfsadm_enumerate_t mc_rules[1] =
	{"^mc$/^mc([0-9]+)$", 1, MATCH_ALL};


static int
mc_node(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX], l_path[PATH_MAX], *buf, *devfspath;
	char *minor_nm;

	minor_nm = di_minor_name(minor);

	if (minor_nm == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	devfspath = di_devfs_path(node);

	(void) strcpy(path, devfspath);
	(void) strcat(path, ":");
	(void) strcat(path, minor_nm);
	di_devfs_path_free(devfspath);

	/* build the physical path from the components */
	if (devfsadm_enumerate_int(path, 0, &buf, mc_rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(l_path, "mc/mc");
	(void) strcat(l_path, buf);

	free(buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}


/*
 * This function is called for Smartcard card reader nodes
 * Handles minor node type "ddi_smartcard_reader"
 * type=ddi_smartcard_reader;name=card-reader   scmi2c\N0
 * Calls enumerate to assign logical card-reader id and then
 * devfsadm_mklink to make the link.
 */
static int
ddi_cardreader(di_minor_t minor, di_node_t node)
{
	char p_path[PATH_MAX +1], l_path[PATH_MAX +1];
	char *buf;
	char *ptr;
	char *nn, *mn;

	devfsadm_enumerate_t rules[1] = {"^scmi2c([0-9]+)$", 1, MATCH_ALL};

	nn = di_node_name(node);
	if (strcmp(nn, "card-reader")) {
		return (DEVFSADM_CONTINUE);
	}

	if (NULL == (ptr = di_devfs_path(node))) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(p_path, ptr);
	(void) strcat(p_path, ":");

	mn = di_minor_name(minor);

	(void) strcat(p_path, mn);
	di_devfs_path_free(ptr);

	if (devfsadm_enumerate_int(p_path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}
	(void) snprintf(l_path, sizeof (l_path), "scmi2c%s", buf);
	free(buf);
	(void) devfsadm_mklink(l_path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}








/*
 * Starcat sbbc node.  We only really care about generating a /dev
 * link for the lone sbbc on the SC (as opposed to the potentially
 * numerous sbbcs on the domain), so only operate on instance 0.
 */
static int
starcat_sbbc_node(di_minor_t minor, di_node_t node)
{
	char *mn;

	if (di_instance(node) == 0) {
		mn = di_minor_name(minor);
		(void) devfsadm_mklink(mn, node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);

}

/*
 * Creates /dev/lom nodes for Platform Specific lom driver
 */
static int
lom(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("lom", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Creates /dev/ntwdt nodes for Platform Specific ntwdt driver
 */
static int
ntwdt_create(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("ntwdt", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Creates /dev/bmc node.
 */
static int
bmc(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("bmc", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
