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

#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>

#define	SCSI_CFG_LINK_RE	"^cfg/c[0-9]+$"
#define	SBD_CFG_LINK_RE		"^cfg/((((N[0-9]+[.])?(SB|IB))?[0-9]+)|[abcd])$"
#define	USB_CFG_LINK_RE		"^cfg/((usb[0-9]+)/([0-9]+)([.]([0-9])+)*)$"
#define	PCI_CFG_LINK_RE		"^cfg/[:alnum:]$"
#define	IB_CFG_LINK_RE		"^cfg/(hca[0-9A-F]+)$"

#define	CFG_DIRNAME		"cfg"

static int	scsi_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	sbd_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	usb_cfg_creat_cb(di_minor_t minor, di_node_t node);
static char	*get_roothub(const char *path, void *cb_arg);
static int	pci_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	ib_cfg_creat_cb(di_minor_t minor, di_node_t node);

/*
 * NOTE: The CREATE_DEFER flag is private to this module.
 *	 NOT to be used by other modules
 */
static devfsadm_create_t cfg_create_cbt[] = {
	{ "attachment-point", "ddi_ctl:attachment_point:scsi", NULL,
	    TYPE_EXACT | CREATE_DEFER, ILEVEL_0, scsi_cfg_creat_cb
	},
	{ "attachment-point", "ddi_ctl:attachment_point:sbd", NULL,
	    TYPE_EXACT, ILEVEL_0, sbd_cfg_creat_cb
	},
	{ "fc-attachment-point", "ddi_ctl:attachment_point:fc", NULL,
	    TYPE_EXACT | CREATE_DEFER, ILEVEL_0, scsi_cfg_creat_cb
	},
	{ "attachment-point", "ddi_ctl:attachment_point:usb", NULL,
	    TYPE_EXACT, ILEVEL_0, usb_cfg_creat_cb
	},
	{ "attachment-point", "ddi_ctl:attachment_point:pci", NULL,
	    TYPE_EXACT, ILEVEL_0, pci_cfg_creat_cb
	},
	{ "attachment-point", "ddi_ctl:attachment_point:ib", NULL,
	    TYPE_EXACT, ILEVEL_0, ib_cfg_creat_cb
	}
};

DEVFSADM_CREATE_INIT_V0(cfg_create_cbt);

static devfsadm_remove_t cfg_remove_cbt[] = {
	{ "attachment-point", SCSI_CFG_LINK_RE, RM_POST,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", SBD_CFG_LINK_RE, RM_POST,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "fc-attachment-point", SCSI_CFG_LINK_RE, RM_POST,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", USB_CFG_LINK_RE, RM_POST|RM_HOT|RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", PCI_CFG_LINK_RE, RM_POST,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", IB_CFG_LINK_RE, RM_POST|RM_HOT|RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(cfg_remove_cbt);

static int
scsi_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1];
	char *c_num = NULL, *devfs_path, *mn;
	devfsadm_enumerate_t rules[3] = {
	    {"^r?dsk$/^c([0-9]+)", 1, MATCH_PARENT},
	    {"^cfg$/^c([0-9]+)$", 1, MATCH_ADDR},
	    {"^scsi$/^.+$/^c([0-9]+)", 1, MATCH_PARENT}
	};

	mn = di_minor_name(minor);

	if ((devfs_path = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}
	(void) strcpy(path, devfs_path);
	(void) strcat(path, ":");
	(void) strcat(path, mn);
	di_devfs_path_free(devfs_path);

	if (devfsadm_enumerate_int(path, 1, &c_num, rules, 3)
	    == DEVFSADM_FAILURE) {
		/*
		 * Unlike the disks module we don't retry on failure.
		 * If we have multiple "c" numbers for a single physical
		 * controller due to bug 4045879, we will not assign a
		 * c-number/symlink for the controller.
		 */
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(path, CFG_DIRNAME);
	(void) strcat(path, "/c");
	(void) strcat(path, c_num);

	free(c_num);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
sbd_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1];

	(void) strcpy(path, CFG_DIRNAME);
	(void) strcat(path, "/");
	(void) strcat(path, di_minor_name(minor));
	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}


static int
usb_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char *cp, path[PATH_MAX + 1];
	devfsadm_enumerate_t rules[1] =
		{"^cfg$/^usb([0-9]+)$", 1, MATCH_CALLBACK, NULL, get_roothub};

	if ((cp = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "%s:%s", cp, di_minor_name(minor));
	di_devfs_path_free(cp);

	if (devfsadm_enumerate_int(path, 0, &cp, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	/* create usbN and the symlink */
	(void) snprintf(path, sizeof (path), "%s/usb%s/%s", CFG_DIRNAME, cp,
	    di_minor_name(minor));
	free(cp);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}


/*
 * get_roothub:
 *	figure out the root hub path to calculate /dev/cfg/usbN
 */
/* ARGSUSED */
static char *
get_roothub(const char *path, void *cb_arg)
{
	int  i, count = 0;
	char *physpath, *cp;

	/* make a copy */
	if ((physpath = strdup(path)) == NULL) {
		return (NULL);
	}

	/*
	 * physpath must always have a minor name component
	 */
	if ((cp = strrchr(physpath, ':')) == NULL) {
		free(physpath);
		return (NULL);
	}
	*cp++ = '\0';

	/*
	 * No '.' in the minor name indicates a roothub port.
	 */
	if (strchr(cp, '.') == NULL) {
		/* roothub device */
		return (physpath);
	}

	while (*cp) {
		if (*cp == '.')
			count++;
		cp++;
	}

	/* Remove as many trailing path components as there are '.'s */
	for (i = 0; i < count; i++) {
		if ((cp = strrchr(physpath, '/')) == NULL || (cp == physpath)) {
			free(physpath);
			return (NULL);
		}
		*cp = '\0';
	}

	return (physpath);
}


/*
 * pci_cfg_creat_cb() search the <device mask> data from
 * "slot-names" PROM property for the match device number,
 * then create device link with the right slot label.
 */
static int
pci_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char		*minor_name, *dev_path;
	char		path[PATH_MAX + 1];
	int		*devlink_flags;
	minor_t		pci_dev;
	di_node_t	dev_node;

	minor_name = di_minor_name(minor);
	pci_dev = (minor->dev_minor) & 0xFF;

	dev_path = di_devfs_path(node);
	dev_node = di_init(dev_path, DINFOCPYALL);
	if ((di_prop_lookup_ints(DDI_DEV_T_ANY, dev_node,
			"ap-names", &devlink_flags)) > 0) {
		if ((*devlink_flags) & (1 << pci_dev)) {
			(void) snprintf(path, sizeof (path), "%s/%s",
			    CFG_DIRNAME, minor_name);
			(void) devfsadm_mklink(path, node, minor, 0);
		}
	}
	di_fini(dev_node);
	(void) di_devfs_path_free(dev_path);

	return (DEVFSADM_CONTINUE);
}


/*
 * ib_cfg_creat_cb() creates two types of links
 * One for the fabric as /dev/cfg/ib
 * Another for each HCA seen in the fabric as /dev/cfg/hca:<HCA-GUID>
 */
static int
ib_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char	*cp;
	char	path[PATH_MAX + 1];

	if ((cp = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(path, sizeof (path), "%s:%s", cp, di_minor_name(minor));
	di_devfs_path_free(cp);

	/* create fabric or hca:GUID and the symlink */
	if (strstr(path, "ib:fabric") != NULL) {
		(void) snprintf(path, sizeof (path), "%s/ib", CFG_DIRNAME);
	} else {
		(void) snprintf(path, sizeof (path), "%s/hca:%s", CFG_DIRNAME,
		    di_minor_name(minor));
	}

	(void) devfsadm_mklink(path, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
