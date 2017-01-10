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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <config_admin.h>
#include <cfg_link.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/hotplug/pci/pcihp.h>

#ifdef	DEBUG
#define	dprint(args)	devfsadm_errprint args
/*
 * for use in print routine arg list as a shorthand way to locate node via
 * "prtconf -D" to avoid messy and cluttered debugging code
 * don't forget the corresponding "%s%d" format
 */
#define	DRVINST(node)	di_driver_name(node), di_instance(node)
#else
#define	dprint(args)
#endif


static int	scsi_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	sbd_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	usb_cfg_creat_cb(di_minor_t minor, di_node_t node);
static char	*get_roothub(const char *path, void *cb_arg);
static int	pci_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	ib_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	sata_cfg_creat_cb(di_minor_t minor, di_node_t node);
static int	sdcard_cfg_creat_cb(di_minor_t minor, di_node_t node);

static di_node_t	pci_cfg_chassis_node(di_node_t, di_prom_handle_t);
static char 	*pci_cfg_slotname(di_node_t, di_prom_handle_t, minor_t);
static int	pci_cfg_ap_node(minor_t, di_node_t, di_prom_handle_t,
		    char *, int, int);
static int	pci_cfg_iob_name(di_minor_t, di_node_t, di_prom_handle_t,
		    char *, int);
static minor_t	pci_cfg_pcidev(di_node_t, di_prom_handle_t);
static int	pci_cfg_ap_path(di_minor_t, di_node_t, di_prom_handle_t,
		    char *, int, char **);
static char 	*pci_cfg_info_data(char *);
static int	pci_cfg_is_ap_path(di_node_t, di_prom_handle_t);
static int	pci_cfg_ap_legacy(di_minor_t, di_node_t, di_prom_handle_t,
		    char *, int);
static void	pci_cfg_rm_invalid_links(char *, char *);
static void	pci_cfg_rm_link(char *);
static void	pci_cfg_rm_all(char *);
static char	*pci_cfg_devpath(di_node_t, di_minor_t);
static di_node_t	pci_cfg_snapshot(di_node_t, di_minor_t,
			    di_node_t *, di_minor_t *);

/* flag definitions for di_propall_*(); value "0" is always the default flag */
#define	DIPROP_PRI_NODE		0x0
#define	DIPROP_PRI_PROM		0x1
static int	di_propall_lookup_ints(di_prom_handle_t, int,
		    dev_t, di_node_t, const char *, int **);
static int	di_propall_lookup_strings(di_prom_handle_t, int,
		    dev_t, di_node_t, const char *, char **);
static int 	serid_printable(uint64_t *seridp);
static int	di_propall_lookup_slot_names(di_prom_handle_t, int,
		    dev_t, di_node_t, di_slot_name_t **);


/*
 * NOTE: The CREATE_DEFER flag is private to this module.
 *	 NOT to be used by other modules
 */
static devfsadm_create_t cfg_create_cbt[] = {
	{ "attachment-point", DDI_NT_SCSI_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT | CREATE_DEFER, ILEVEL_0, scsi_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_SBD_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, sbd_cfg_creat_cb
	},
	{ "fc-attachment-point", DDI_NT_FC_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT | CREATE_DEFER, ILEVEL_0, scsi_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_USB_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, usb_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_PCI_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, pci_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_IB_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, ib_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_SATA_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, sata_cfg_creat_cb
	},
	{ "attachment-point", DDI_NT_SDCARD_ATTACHMENT_POINT, NULL,
	    TYPE_EXACT, ILEVEL_0, sdcard_cfg_creat_cb
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
	{ "attachment-point", PCI_CFG_PATH_LINK_RE, RM_POST|RM_HOT,
	    ILEVEL_0, pci_cfg_rm_all
	},
	{ "attachment-point", IB_CFG_LINK_RE, RM_POST|RM_HOT|RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", SATA_CFG_LINK_RE, RM_POST|RM_HOT|RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "attachment-point", SDCARD_CFG_LINK_RE, RM_POST|RM_HOT|RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all
	},
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

	if (ctrl_enumerate_int(path, 1, &c_num, rules, 3, 0, B_FALSE)
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

	if (ctrl_enumerate_int(path, 0, &cp, rules, 1, 0, B_FALSE)) {
		return (DEVFSADM_CONTINUE);
	}

	/* create usbN and the symlink */
	(void) snprintf(path, sizeof (path), "%s/usb%s/%s", CFG_DIRNAME, cp,
	    di_minor_name(minor));
	free(cp);

	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}


static int
sata_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX + 1], l_path[PATH_MAX], *buf, *devfspath;
	char *minor_nm;
	devfsadm_enumerate_t rules[1] =
		{"^cfg$/^sata([0-9]+)$", 1, MATCH_ADDR};

	minor_nm = di_minor_name(minor);
	if (minor_nm == NULL)
		return (DEVFSADM_CONTINUE);

	devfspath = di_devfs_path(node);
	if (devfspath == NULL)
		return (DEVFSADM_CONTINUE);

	(void) strlcpy(path, devfspath, sizeof (path));
	(void) strlcat(path, ":", sizeof (path));
	(void) strlcat(path, minor_nm, sizeof (path));
	di_devfs_path_free(devfspath);

	/* build the physical path from the components */
	if (ctrl_enumerate_int(path, 0, &buf, rules, 1, 0, B_FALSE) ==
	    DEVFSADM_FAILURE) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(l_path, sizeof (l_path), "%s/sata%s/%s", CFG_DIRNAME,
	    buf, minor_nm);
	free(buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
sdcard_cfg_creat_cb(di_minor_t minor, di_node_t node)
{
	char path[PATH_MAX +1], l_path[PATH_MAX], *buf, *devfspath;
	char *minor_nm;
	devfsadm_enumerate_t rules[1] =
	    {"^cfg$/^sdcard([0-9]+)$", 1, MATCH_ADDR};

	minor_nm = di_minor_name(minor);
	if (minor_nm == NULL)
		return (DEVFSADM_CONTINUE);

	devfspath = di_devfs_path(node);
	if (devfspath == NULL)
		return (DEVFSADM_CONTINUE);

	(void) snprintf(path, sizeof (path), "%s:%s", devfspath, minor_nm);
	di_devfs_path_free(devfspath);

	/* build the physical path from the components */
	if (ctrl_enumerate_int(path, 0, &buf, rules, 1, 0, B_FALSE) ==
	    DEVFSADM_FAILURE) {
		return (DEVFSADM_CONTINUE);
	}

	(void) snprintf(l_path, sizeof (l_path), "%s/sdcard%s/%s",
	    CFG_DIRNAME, buf, minor_nm);
	free(buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);

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
		/*
		 * Check if there is any usb_mid node in the middle
		 * and remove the node as if there is an extra '.'
		 */
		if (strstr(cp, "miscellaneous") != NULL) {
			count++;
		}
		*cp = '\0';
	}

	/* Remove the usb_mid node immediately before the trailing path */
	if ((cp = strrchr(physpath, '/')) != NULL && (cp != physpath)) {
		if (strstr(cp, "miscellaneous") != NULL) {
			*cp = '\0';
		}
	}

	return (physpath);
}


/*
 * returns an allocted string containing the device path for <node> and
 * <minor>
 */
static char *
pci_cfg_devpath(di_node_t node, di_minor_t minor)
{
	char *path;
	char *bufp;
	char *minor_nm;
	int buflen;

	path = di_devfs_path(node);
	minor_nm = di_minor_name(minor);
	buflen = snprintf(NULL, 0, "%s:%s", path, minor_nm) + 1;

	bufp = malloc(sizeof (char) * buflen);
	if (bufp != NULL)
		(void) snprintf(bufp, buflen, "%s:%s", path, minor_nm);

	di_devfs_path_free(path);
	return (bufp);
}


static int
di_propall_lookup_ints(di_prom_handle_t ph, int flags,
    dev_t dev, di_node_t node, const char *prop_name, int **prop_data)
{
	int rv;

	if (flags & DIPROP_PRI_PROM) {
		rv = di_prom_prop_lookup_ints(ph, node, prop_name, prop_data);
		if (rv < 0)
			rv = di_prop_lookup_ints(dev, node, prop_name,
			    prop_data);
	} else {
		rv = di_prop_lookup_ints(dev, node, prop_name, prop_data);
		if (rv < 0)
			rv = di_prom_prop_lookup_ints(ph, node, prop_name,
			    prop_data);
	}
	return (rv);
}


static int
di_propall_lookup_strings(di_prom_handle_t ph, int flags,
    dev_t dev, di_node_t node, const char *prop_name, char **prop_data)
{
	int rv;

	if (flags & DIPROP_PRI_PROM) {
		rv = di_prom_prop_lookup_strings(ph, node, prop_name,
		    prop_data);
		if (rv < 0)
			rv = di_prop_lookup_strings(dev, node, prop_name,
			    prop_data);
	} else {
		rv = di_prop_lookup_strings(dev, node, prop_name, prop_data);
		if (rv < 0)
			rv = di_prom_prop_lookup_strings(ph, node, prop_name,
			    prop_data);
	}
	return (rv);
}


static di_node_t
pci_cfg_chassis_node(di_node_t node, di_prom_handle_t ph)
{
	di_node_t curnode = node;
	int *firstchas;

	do {
		if (di_propall_lookup_ints(ph, 0, DDI_DEV_T_ANY, curnode,
		    DI_PROP_FIRST_CHAS, &firstchas) >= 0)
			return (curnode);
	} while ((curnode = di_parent_node(curnode)) != DI_NODE_NIL);

	return (DI_NODE_NIL);
}


static int
di_propall_lookup_slot_names(di_prom_handle_t ph, int flags,
    dev_t dev, di_node_t node, di_slot_name_t **prop_data)
{
	int rv;

	if (flags & DIPROP_PRI_PROM) {
		rv = di_prom_prop_lookup_slot_names(ph, node, prop_data);
		if (rv < 0)
			rv = di_prop_lookup_slot_names(dev, node, prop_data);
	} else {
		rv = di_prop_lookup_slot_names(dev, node, prop_data);
		if (rv < 0)
			rv = di_prom_prop_lookup_slot_names(ph, node,
			    prop_data);
	}
	return (rv);
}

/*
 * returns an allocated string containing the slot name for the slot with
 * device number <pci_dev> on bus <node>
 */
static char *
pci_cfg_slotname(di_node_t node, di_prom_handle_t ph, minor_t pci_dev)
{
#ifdef	DEBUG
	char *fnm = "pci_cfg_slotname";
#endif
	int i, count;
	char *name = NULL;
	di_slot_name_t *slot_names = NULL;

	count = di_propall_lookup_slot_names(ph, 0, DDI_DEV_T_ANY, node,
	    &slot_names);
	if (count < 0)
		return (NULL);

	for (i = 0; i < count; i++) {
		if (slot_names[i].num == (int)pci_dev) {
			name = strdup(slot_names[i].name);
			break;
		}
	}
#ifdef	DEBUG
	if (name == NULL)
		dprint(("%s: slot w/ pci_dev %d not found in %s for %s%d\n",
		    fnm, (int)pci_dev, DI_PROP_SLOT_NAMES, DRVINST(node)));
#endif
	if (count > 0)
		di_slot_names_free(count, slot_names);
	return (name);
}


/*
 * returns non-zero if we can return a valid attachment point name for <node>,
 * for its slot identified by child pci device number <pci_dev>, through <buf>
 *
 * prioritized naming scheme:
 *	1) <DI_PROP_SLOT_NAMES property>    (see pci_cfg_slotname())
 *	2) <device-type><DI_PROP_PHYS_SLOT property>
 *	3) <drv name><drv inst>.<device-type><pci_dev>
 *
 * where <device-type> is derived from the DI_PROP_DEV_TYPE property:
 *	if its value is "pciex" then <device-type> is "pcie"
 *	else the raw value is used
 *
 * if <flags> contains APNODE_DEFNAME, then scheme (3) is used
 */
static int
pci_cfg_ap_node(minor_t pci_dev, di_node_t node, di_prom_handle_t ph,
    char *buf, int bufsz, int flags)
{
	int *nump;
	int rv;
	char *str, *devtype;

	rv = di_propall_lookup_strings(ph, 0, DDI_DEV_T_ANY, node,
	    DI_PROP_DEV_TYPE, &devtype);
	if (rv < 1)
		return (0);

	if (strcmp(devtype, PROPVAL_PCIEX) == 0)
		devtype = DEVTYPE_PCIE;

	if (flags & APNODE_DEFNAME)
		goto DEF;

	str = pci_cfg_slotname(node, ph, pci_dev);
	if (str != NULL) {
		(void) strlcpy(buf, str, bufsz);
		free(str);
		return (1);
	}

	if (di_propall_lookup_ints(ph, 0, DDI_DEV_T_ANY, node,
	    DI_PROP_PHYS_SLOT, &nump) > 0) {
		if (*nump > 0) {
			(void) snprintf(buf, bufsz, "%s%d", devtype, *nump);
			return (1);
		}
	}
DEF:
	(void) snprintf(buf, bufsz, "%s%d.%s%d",
	    di_driver_name(node), di_instance(node), devtype, pci_dev);

	return (1);
}


/*
 * returns non-zero if we can return a valid expansion chassis name for <node>
 * through <buf>
 *
 * prioritized naming scheme:
 *	1) <IOB_PRE string><DI_PROP_SERID property: sun specific portion>
 *	2) <IOB_PRE string><full DI_PROP_SERID property in hex>
 *	3) <IOB_PRE string>
 *
 * DI_PROP_SERID encoding <64-bit int: msb ... lsb>:
 * <24 bits: IEEE company id><40 bits: serial number>
 *
 * sun encoding of 40 bit serial number:
 * first byte = device type indicator
 * next 4 bytes = 4 ascii characters
 *
 * In the unlikely event that serial id contains non-printable characters
 * the full 64 bit raw hex string will be used for the attachment point.
 */
/*ARGSUSED*/
static int
pci_cfg_iob_name(di_minor_t minor, di_node_t node, di_prom_handle_t ph,
    char *buf, int bufsz)
{
	int64_t *seridp;
	uint64_t serid;
	char *idstr;

	if (di_prop_lookup_int64(DDI_DEV_T_ANY, node, DI_PROP_SERID,
	    &seridp) < 1) {
		(void) strlcpy(buf, IOB_PRE, bufsz);
		return (1);
	}

	serid = (uint64_t)*seridp;

	if ((serid >> 40) != (uint64_t)IEEE_SUN_ID ||
	    !serid_printable(&serid)) {
		(void) snprintf(buf, bufsz, "%s%llx", IOB_PRE, serid);
		return (1);
	}

	/*
	 * the serial id is constructed from lower 40 bits of the serialid
	 * property and is represented by 5 ascii characters. The first
	 * character indicates if the IO Box is PCIe or PCI-X.
	 */

	serid <<= 24;
	idstr = (char *)&serid;
	idstr[sizeof (serid) -1] = '\0';

	(void) snprintf(buf, bufsz, "%s%s", IOB_PRE, idstr);

	return (1);
}


/*
 * returns the pci device number for <node> if found, else returns PCIDEV_NIL
 */
static minor_t
pci_cfg_pcidev(di_node_t node, di_prom_handle_t ph)
{
	int rv;
	int *regp;

	rv = di_propall_lookup_ints(ph, 0, DDI_DEV_T_ANY, node, DI_PROP_REG,
	    &regp);

	if (rv < 1) {
		dprint(("pci_cfg_pcidev: property %s not found "
		    "for %s%d\n", DI_PROP_REG, DRVINST(node)));
		return (PCIDEV_NIL);
	}

	return (REG_PCIDEV(regp));
}


/*
 * returns non-zero when it can successfully return an attachment point
 * through <ap_path> whose length is less than <ap_pathsz>; returns the full
 * path of the AP through <pathret> which may be larger than <ap_pathsz>.
 * Callers need to free <pathret>.  If it cannot return the full path through
 * <pathret> it will be set to NULL
 *
 * The ap path reflects a subset of the device path from an onboard host slot
 * up to <node>.  We traverse up the device tree starting from <node>, naming
 * each component using pci_cfg_ap_node().  If we detect that a certain
 * segment is contained within an expansion chassis, then we skip any bus
 * nodes in between our current node and the topmost node of the chassis,
 * which is identified by the DI_PROP_FIRST_CHAS property, and prepend the name
 * of the expansion chassis as given by pci_cfg_iob_name()
 *
 * This scheme is always used for <pathret>.  If however, the size of
 * <pathret> is greater than <ap_pathsz> then only the default name as given
 * by pci_cfg_ap_node() for <node> will be used
 */
static int
pci_cfg_ap_path(di_minor_t minor, di_node_t node, di_prom_handle_t ph,
    char *ap_path, int ap_pathsz, char **pathret)
{
#ifdef	DEBUG
	char *fnm = "pci_cfg_ap_path";
#endif
#define	seplen		(sizeof (AP_PATH_SEP) - 1)
#define	iob_pre_len	(sizeof (IOB_PRE) - 1)
#define	ap_path_iob_sep_len	(sizeof (AP_PATH_IOB_SEP) - 1)

	char *bufptr;
	char buf[MAXPATHLEN];
	char pathbuf[MAXPATHLEN];
	int bufsz;
	char *pathptr;
	char *pathend = NULL;
	int len;
	int rv = 0;
	int chasflag = 0;
	di_node_t curnode = node;
	di_node_t chasnode = DI_NODE_NIL;
	minor_t pci_dev;

	buf[0] = '\0';
	pathbuf[0] = '\0';
	pathptr = &pathbuf[sizeof (pathbuf) - 1];
	*pathptr = '\0';

	/*
	 * as we traverse up the device tree, we prepend components of our
	 * path inside pathbuf, using pathptr and decrementing
	 */
	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(di_minor_devt(minor));
	do {
		bufptr = buf;
		bufsz = sizeof (buf);

		chasnode = pci_cfg_chassis_node(curnode, ph);
		if (chasnode != DI_NODE_NIL) {
			rv = pci_cfg_iob_name(minor, chasnode, ph,
			    bufptr, bufsz);
			if (rv == 0) {
				dprint(("%s: cannot create iob name "
				    "for %s%d\n", fnm, DRVINST(node)));
				*pathptr = '\0';
				goto OUT;
			}

			(void) strncat(bufptr, AP_PATH_IOB_SEP, bufsz);
			len = strlen(bufptr);
			bufptr += len;
			bufsz -= len - 1;

			/* set chasflag when the leaf node is within an iob */
			if ((curnode == node) != NULL)
				chasflag = 1;
		}
		rv = pci_cfg_ap_node(pci_dev, curnode, ph, bufptr, bufsz, 0);
		if (rv == 0) {
			dprint(("%s: cannot create ap node name "
			    "for %s%d\n", fnm, DRVINST(node)));
			*pathptr = '\0';
			goto OUT;
		}

		/*
		 * if we can't fit the entire path in our pathbuf, then use
		 * the default short name and nullify pathptr; also, since
		 * we prepend in the buffer, we must avoid adding a null char
		 */
		if (curnode != node) {
			pathptr -= seplen;
			if (pathptr < pathbuf) {
				pathptr = pathbuf;
				*pathptr = '\0';
				goto DEF;
			}
			(void) memcpy(pathptr, AP_PATH_SEP, seplen);
		}
		len = strlen(buf);
		pathptr -= len;
		if (pathptr < pathbuf) {
			pathptr = pathbuf;
			*pathptr = '\0';
			goto DEF;
		}
		(void) memcpy(pathptr, buf, len);

		/* remember the leaf component */
		if (curnode == node)
			pathend = pathptr;

		/*
		 * go no further than the hosts' onboard slots
		 */
		if (chasnode == DI_NODE_NIL)
			break;
		curnode = chasnode;

		/*
		 * the pci device number of the current node is used to
		 * identify which slot of the parent's bus (next iteration)
		 * the current node is on
		 */
		pci_dev = pci_cfg_pcidev(curnode, ph);
		if (pci_dev == PCIDEV_NIL) {
			dprint(("%s: cannot obtain pci device number "
			    "for %s%d\n", fnm, DRVINST(node)));
			*pathptr = '\0';
			goto OUT;
		}
	} while ((curnode = di_parent_node(curnode)) != DI_NODE_NIL);

	pathbuf[sizeof (pathbuf) - 1] = '\0';
	if (strlen(pathptr) < ap_pathsz) {
		(void) strlcpy(ap_path, pathptr, ap_pathsz);
		rv = 1;
		goto OUT;
	}

DEF:
	/*
	 * when our name won't fit <ap_pathsz> we use the endpoint/leaf
	 * <node>'s name ONLY IF it has a serialid# which will make the apid
	 * globally unique
	 */
	if (chasflag && pathend != NULL) {
		if ((strncmp(pathend + iob_pre_len, AP_PATH_IOB_SEP,
		    ap_path_iob_sep_len) != 0) &&
		    (strlen(pathend) < ap_pathsz)) {
			(void) strlcpy(ap_path, pathend, ap_pathsz);
			rv = 1;
			goto OUT;
		}
	}

	/*
	 * if our name still won't fit <ap_pathsz>, then use the leaf <node>'s
	 * default name
	 */
	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(di_minor_devt(minor));
	rv = pci_cfg_ap_node(pci_dev, node, ph, buf, bufsz, APNODE_DEFNAME);
	if (rv == 0) {
		dprint(("%s: cannot create default ap node name for %s%d\n",
		    fnm, DRVINST(node)));
		*pathptr = '\0';
		goto OUT;
	}
	if (strlen(buf) < ap_pathsz) {
		(void) strlcpy(ap_path, buf, ap_pathsz);
		rv = 1;
		goto OUT;
	}

	/*
	 * in this case, cfgadm goes through an expensive process to generate
	 * a purely dynamic logical apid: the framework will look through
	 * the device tree for attachment point minor nodes and will invoke
	 * each plugin responsible for that attachment point class, and if
	 * the plugin returns a logical apid that matches the queried apid
	 * or matches the default apid generated by the cfgadm framework for
	 * that driver/class (occurs when plugin returns an empty logical apid)
	 * then that is what it will use
	 *
	 * it is doubly expensive because the cfgadm pci plugin itself will
	 * also search the entire device tree in the absence of a link
	 */
	rv = 0;
	dprint(("%s: cannot create apid for %s%d within length of %d\n",
	    fnm, DRVINST(node), ap_pathsz));

OUT:
	ap_path[ap_pathsz - 1] = '\0';
	*pathret = (*pathptr == '\0') ? NULL : strdup(pathptr);
	return (rv);

#undef	seplen
#undef	iob_pre_len
#undef	ap_path_iob_sep_len
}


/*
 * the DI_PROP_AP_NAMES property contains the first integer section of the
 * ieee1275 "slot-names" property and functions as a bitmask; see comment for
 * pci_cfg_slotname()
 *
 * we use the name of the attachment point minor node if its pci device
 * number (encoded in the minor number) is allowed by DI_PROP_AP_NAMES
 *
 * returns non-zero if we return a valid attachment point through <path>
 */
static int
pci_cfg_ap_legacy(di_minor_t minor, di_node_t node, di_prom_handle_t ph,
    char *ap_path, int ap_pathsz)
{
	minor_t pci_dev;
	int *anp;

	if (di_propall_lookup_ints(ph, 0, DDI_DEV_T_ANY, node, DI_PROP_AP_NAMES,
	    &anp) < 1)
		return (0);

	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(di_minor_devt(minor));
	if ((*anp & (1 << pci_dev)) == 0)
		return (0);

	(void) strlcpy(ap_path, di_minor_name(minor), ap_pathsz);
	return (1);
}


/*
 * determine if <node> qualifies for a path style apid
 */
static int
pci_cfg_is_ap_path(di_node_t node, di_prom_handle_t ph)
{
	char *devtype;
	di_node_t curnode = node;

	do {
		if (di_propall_lookup_strings(ph, 0, DDI_DEV_T_ANY, curnode,
		    DI_PROP_DEV_TYPE, &devtype) > 0)
			if (strcmp(devtype, PROPVAL_PCIEX) == 0)
				return (1);
	} while ((curnode = di_parent_node(curnode)) != DI_NODE_NIL);

	return (0);
}


/*
 * takes a full path as returned by <pathret> from pci_cfg_ap_path() and
 * returns an allocated string intendend to be stored in a devlink info (dli)
 * file
 *
 * data format: "Location: <transformed path>"
 * where <transformed path> is <path> with occurrances of AP_PATH_SEP
 * replaced by "/"
 */
static char *
pci_cfg_info_data(char *path)
{
#define	head	"Location: "
#define	headlen	(sizeof (head) - 1)
#define	seplen	(sizeof (AP_PATH_SEP) - 1)

	char *sep, *prev, *np;
	char *newpath;
	int pathlen = strlen(path);
	int len;

	newpath = malloc(sizeof (char) * (headlen + pathlen + 1));
	np = newpath;
	(void) strcpy(np, head);
	np += headlen;

	prev = path;
	while ((sep = strstr(prev, AP_PATH_SEP)) != NULL) {
		len = sep - prev;
		(void) memcpy(np, prev, len);
		np += len;
		*np++ = '/';
		prev = sep + seplen;
	}
	(void) strcpy(np, prev);
	return (newpath);

#undef	head
#undef	headlen
#undef	seplen
}


static void
pci_cfg_rm_link(char *file)
{
	char *dlipath;

	dlipath = di_dli_name(file);
	(void) unlink(dlipath);

	devfsadm_rm_all(file);
	free(dlipath);
}

/*
 * removes all registered devlinks to physical path <physpath> except for
 * the devlink <valid> if not NULL;
 * <physpath> must include the minor node
 */
static void
pci_cfg_rm_invalid_links(char *physpath, char *valid)
{
	char **dnp;
	char *cp, *vcp;
	int i, dnlen;

	dnp = devfsadm_lookup_dev_names(physpath, NULL, &dnlen);
	if (dnp == NULL)
		return;

	if (valid != NULL) {
		if (strncmp(valid, DEV "/", DEV_LEN + 1) == 0)
			vcp = valid + DEV_LEN + 1;
		else
			vcp = valid;
	}

	for (i = 0; i < dnlen; i++) {
		if (strncmp(dnp[i], DEV "/", DEV_LEN + 1) == 0)
			cp = dnp[i] + DEV_LEN + 1;
		else
			cp = dnp[i];

		if (valid != NULL) {
			if (strcmp(vcp, cp) == 0)
				continue;
		}
		pci_cfg_rm_link(cp);
	}
	devfsadm_free_dev_names(dnp, dnlen);
}


/*
 * takes a complete devinfo snapshot and returns the root node;
 * callers must do a di_fini() on the returned node;
 * if the snapshot failed, DI_NODE_NIL is returned instead
 *
 * if <pci_node> is not DI_NODE_NIL, it will search for the same devinfo node
 * in the new snapshot and return it through <ret_node> if it is found,
 * else DI_NODE_NIL is returned instead
 *
 * in addition, if <pci_minor> is not DI_MINOR_NIL, it will also return
 * the matching minor in the new snapshot through <ret_minor> if it is found,
 * else DI_MINOR_NIL is returned instead
 */
static di_node_t
pci_cfg_snapshot(di_node_t pci_node, di_minor_t pci_minor,
    di_node_t *ret_node, di_minor_t *ret_minor)
{
	di_node_t root_node;
	di_node_t node;
	di_minor_t minor;
	int pci_inst;
	dev_t pci_devt;

	*ret_node = DI_NODE_NIL;
	*ret_minor = DI_MINOR_NIL;

	root_node = di_init("/", DINFOCPYALL);
	if (root_node == DI_NODE_NIL)
		return (DI_NODE_NIL);

	/*
	 * narrow down search by driver, then instance, then minor
	 */
	if (pci_node == DI_NODE_NIL)
		return (root_node);

	pci_inst = di_instance(pci_node);
	node = di_drv_first_node(di_driver_name(pci_node), root_node);
	do {
		if (pci_inst == di_instance(node)) {
			*ret_node = node;
			break;
		}
	} while ((node = di_drv_next_node(node)) != DI_NODE_NIL);

	if (node == DI_NODE_NIL)
		return (root_node);

	/*
	 * found node, now search minors
	 */
	if (pci_minor == DI_MINOR_NIL)
		return (root_node);

	pci_devt = di_minor_devt(pci_minor);
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		if (pci_devt == di_minor_devt(minor)) {
			*ret_minor = minor;
			break;
		}
	}
	return (root_node);
}


static int
pci_cfg_creat_cb(di_minor_t pci_minor, di_node_t pci_node)
{
#ifdef	DEBUG
	char *fnm = "pci_cfg_creat_cb";
#endif
#define	ap_pathsz	(sizeof (ap_path))

	char ap_path[CFGA_LOG_EXT_LEN];
	char linkbuf[MAXPATHLEN];
	char *fullpath = NULL;
	char *pathinfo = NULL;
	char *devpath = NULL;
	int rv, fd = -1;
	size_t sz;
	di_prom_handle_t ph;
	di_node_t node;
	di_node_t root_node = DI_NODE_NIL;
	di_minor_t minor;

	ph = di_prom_init();
	if (ph == DI_PROM_HANDLE_NIL) {
		dprint(("%s: di_prom_init() failed for %s%d\n",
		    fnm, DRVINST(pci_node)));
		goto OUT;
	}

	/*
	 * Since incoming nodes from hotplug events are from snapshots that
	 * do NOT contain parent/ancestor data, we must retake our own
	 * snapshot and search for the target node
	 */
	root_node = pci_cfg_snapshot(pci_node, pci_minor, &node, &minor);
	if (root_node == DI_NODE_NIL || node == DI_NODE_NIL ||
	    minor == DI_MINOR_NIL) {
		dprint(("%s: devinfo snapshot or search failed for %s%d\n",
		    fnm, DRVINST(pci_node)));
		goto OUT;
	}

	if (pci_cfg_is_ap_path(node, ph)) {
		rv = pci_cfg_ap_path(minor, node, ph, ap_path, ap_pathsz,
		    &fullpath);
		if (rv == 0)
			goto OUT;

		(void) snprintf(linkbuf, sizeof (linkbuf), "%s/%s",
		    CFG_DIRNAME, ap_path);

		/*
		 * We must remove existing links because we may have invalid
		 * apids that are valid links.  Since these are not dangling,
		 * devfsadm will not invoke the remove callback on them.
		 *
		 * What are "invalid apids with valid links"?  Consider swapping
		 * an attachment point bus with another while the system is
		 * down, on the same device path bound to the same drivers
		 * but with the new AP bus having different properties
		 * (e.g. serialid#).  If the previous apid is not removed,
		 * there will now be two different links pointing to the same
		 * attachment point, but only one reflects the correct
		 * logical apid
		 */
		devpath = pci_cfg_devpath(node, minor);
		if (devpath == NULL)
			goto OUT;
		pci_cfg_rm_invalid_links(devpath, linkbuf);
		free(devpath);

		(void) devfsadm_mklink(linkbuf, node, minor, 0);

		/*
		 * we store the full logical path of the attachment point for
		 * cfgadm to display in its info field which is useful when
		 * the full logical path exceeds the size limit for logical
		 * apids (CFGA_LOG_EXT_LEN)
		 *
		 * for the cfgadm pci plugin to do the same would be expensive
		 * (i.e. devinfo snapshot + top down exhaustive minor search +
		 * equivalent of pci_cfg_ap_path() on every invocation)
		 *
		 * note that if we do not create a link (pci_cfg_ap_path() is
		 * not successful), that is what cfgadm will do anyways to
		 * create a purely dynamic apid
		 */
		pathinfo = pci_cfg_info_data(fullpath);
		fd = di_dli_openw(linkbuf);
		if (fd < 0)
			goto OUT;

		sz = strlen(pathinfo) + 1;
		rv = write(fd, pathinfo, sz);
		if (rv < sz) {
			dprint(("%s: could not write full pathinfo to dli "
			    "file for %s%d\n", fnm, DRVINST(node)));
			goto OUT;
		}
		di_dli_close(fd);
	} else {
		rv = pci_cfg_ap_legacy(minor, node, ph, ap_path,
		    ap_pathsz);
		if (rv == 0)
			goto OUT;

		(void) snprintf(linkbuf, sizeof (linkbuf), "%s/%s",
		    CFG_DIRNAME, ap_path);
		(void) devfsadm_mklink(linkbuf, node, minor, 0);
	}

OUT:
	if (fd >= 0)
		di_dli_close(fd);
	if (fullpath != NULL)
		free(fullpath);
	if (pathinfo != NULL)
		free(pathinfo);
	if (ph != DI_PROM_HANDLE_NIL)
		di_prom_fini(ph);
	if (root_node != DI_NODE_NIL)
		di_fini(root_node);
	return (DEVFSADM_CONTINUE);

#undef	ap_pathsz
}


static void
pci_cfg_rm_all(char *file)
{
	pci_cfg_rm_link(file);
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

/*
 * This function verifies if the serial id is printable.
 */

static int
serid_printable(uint64_t *seridp)
{

	char *ptr;
	int i = 0;

	for (ptr = (char *)seridp+3; i < 5; ptr++, i++)
		if (*ptr < 0x21 || *ptr >= 0x7f)
			return (0);

	return (1);

}
