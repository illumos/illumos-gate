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
#include <sys/mc_amd.h>
#include <bsm/devalloc.h>

extern int system_labeled;

static int lp(di_minor_t minor, di_node_t node);
static int serial_dialout(di_minor_t minor, di_node_t node);
static int serial(di_minor_t minor, di_node_t node);
static int diskette(di_minor_t minor, di_node_t node);
static int vt00(di_minor_t minor, di_node_t node);
static int kdmouse(di_minor_t minor, di_node_t node);
static int ipmi(di_minor_t minor, di_node_t node);
static int smbios(di_minor_t minor, di_node_t node);
static int mc_node(di_minor_t minor, di_node_t node);
static int xsvc(di_minor_t minor, di_node_t node);
static int srn(di_minor_t minor, di_node_t node);
static int ucode(di_minor_t minor, di_node_t node);
static int heci(di_minor_t minor, di_node_t node);


static devfsadm_create_t misc_cbt[] = {
	{ "vt00", "ddi_display", NULL,
	    TYPE_EXACT, ILEVEL_0,	vt00
	},
	{ "mouse", "ddi_mouse", "mouse8042",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, kdmouse
	},
	{ "pseudo", "ddi_pseudo", "ipmi",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, ipmi,
	},
	{ "pseudo", "ddi_pseudo", "smbios",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_1, smbios,
	},
	/* floppies share the same class, but not link regex, as hard disks */
	{ "disk",  "ddi_block:diskette", NULL,
	    TYPE_EXACT, ILEVEL_1, diskette
	},
	{ "parallel",  "ddi_printer", NULL,
	    TYPE_EXACT, ILEVEL_1, lp
	},
	{ "serial", "ddi_serial:mb", NULL,
	    TYPE_EXACT, ILEVEL_1, serial
	},
	{ "serial",  "ddi_serial:dialout,mb", NULL,
	    TYPE_EXACT, ILEVEL_1, serial_dialout
	},
	{ "pseudo", "ddi_pseudo", NULL,
	    TYPE_EXACT, ILEVEL_0, xsvc
	},
	{ "pseudo", "ddi_pseudo", NULL,
	    TYPE_EXACT, ILEVEL_0, srn
	},
	{ "memory-controller", "ddi_mem_ctrl", NULL,
	    TYPE_EXACT, ILEVEL_0, mc_node
	},
	{ "pseudo", "ddi_pseudo", "ucode",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, ucode,
	},
	{ "pseudo", "ddi_pseudo", "heci",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, heci,
	}
};

DEVFSADM_CREATE_INIT_V0(misc_cbt);

static devfsadm_remove_t misc_remove_cbt[] = {
	{ "vt", "vt[0-9][0-9]", RM_PRE|RM_ALWAYS,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "pseudo", "^ucode$", RM_ALWAYS | RM_PRE | RM_HOT,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "mouse", "^kdmouse$", RM_ALWAYS | RM_PRE,
		ILEVEL_0, devfsadm_rm_all
	},
	{ "disk", "^(diskette|rdiskette)([0-9]*)$",
		RM_ALWAYS | RM_PRE, ILEVEL_1, devfsadm_rm_all
	},
	{ "parallel", "^(lp|ecpp)([0-9]+)$", RM_ALWAYS | RM_PRE,
		ILEVEL_1, devfsadm_rm_all
	},
	{ "serial", "^(tty|ttyd)([0-9]+)$", RM_ALWAYS | RM_PRE,
		ILEVEL_1, devfsadm_rm_all
	},
	{ "serial", "^tty[a-z]$", RM_ALWAYS | RM_PRE,
		ILEVEL_1, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(misc_remove_cbt);

/*
 * Handles minor node type "ddi_display", in addition to generic processing
 * done by display().
 *
 * This creates a /dev/vt00 link to /dev/fb, for backwards compatibility.
 */
/* ARGSUSED */
int
vt00(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_secondary_link("vt00", "fb", 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * type=ddi_block:diskette;addr=0,0;minor=c        diskette
 * type=ddi_block:diskette;addr=0,0;minor=c,raw    rdiskette
 * type=ddi_block:diskette;addr1=0;minor=c diskette\A2
 * type=ddi_block:diskette;addr1=0;minor=c,raw     rdiskette\A2
 */
static int
diskette(di_minor_t minor, di_node_t node)
{
	int flags = 0;
	char *a2;
	char link[PATH_MAX];
	char *addr = di_bus_addr(node);
	char *mn = di_minor_name(minor);

	if (system_labeled)
		flags = DA_ADD|DA_FLOPPY;

	if (strcmp(addr, "0,0") == 0) {
		if (strcmp(mn, "c") == 0) {
			(void) devfsadm_mklink("diskette", node, minor, flags);
		} else if (strcmp(mn, "c,raw") == 0) {
			(void) devfsadm_mklink("rdiskette", node, minor, flags);
		}

	}

	if (addr[0] == '0') {
		if ((a2 = strchr(addr, ',')) != NULL) {
			a2++;
			if (strcmp(mn, "c") == 0) {
				(void) strcpy(link, "diskette");
				(void) strcat(link, a2);
				(void) devfsadm_mklink(link, node, minor,
				    flags);
			} else if (strcmp(mn, "c,raw") == 0) {
				(void) strcpy(link, "rdiskette");
				(void) strcat(link, a2);
				(void) devfsadm_mklink(link, node, minor,
				    flags);
			}
		}
	}

	return (DEVFSADM_CONTINUE);
}

/*
 * type=ddi_printer;name=lp;addr=1,3bc      lp0
 * type=ddi_printer;name=lp;addr=1,378      lp1
 * type=ddi_printer;name=lp;addr=1,278      lp2
 */
static int
lp(di_minor_t minor, di_node_t node)
{
	char *addr = di_bus_addr(node);
	char *buf;
	char path[PATH_MAX + 1];
	devfsadm_enumerate_t rules[1] = {"^ecpp([0-9]+)$", 1, MATCH_ALL};

	if (strcmp(addr, "1,3bc") == 0) {
		(void) devfsadm_mklink("lp0", node, minor, 0);

	} else if (strcmp(addr, "1,378") == 0) {
		(void) devfsadm_mklink("lp1", node, minor, 0);

	} else if (strcmp(addr, "1,278") == 0) {
		(void) devfsadm_mklink("lp2", node, minor, 0);
	}

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

/*
 * type=ddi_serial:mb;minor=a      tty00
 * type=ddi_serial:mb;minor=b      tty01
 * type=ddi_serial:mb;minor=c      tty02
 * type=ddi_serial:mb;minor=d      tty03
 */
static int
serial(di_minor_t minor, di_node_t node)
{

	char *mn = di_minor_name(minor);
	char link[PATH_MAX];

	(void) strcpy(link, "tty");
	(void) strcat(link, mn);
	(void) devfsadm_mklink(link, node, minor, 0);

	if (strcmp(mn, "a") == 0) {
		(void) devfsadm_mklink("tty00", node, minor, 0);

	} else if (strcmp(mn, "b") == 0) {
		(void) devfsadm_mklink("tty01", node, minor, 0);

	} else if (strcmp(mn, "c") == 0) {
		(void) devfsadm_mklink("tty02", node, minor, 0);

	} else if (strcmp(mn, "d") == 0) {
		(void) devfsadm_mklink("tty03", node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}

/*
 * type=ddi_serial:dialout,mb;minor=a,cu   ttyd0
 * type=ddi_serial:dialout,mb;minor=b,cu   ttyd1
 * type=ddi_serial:dialout,mb;minor=c,cu   ttyd2
 * type=ddi_serial:dialout,mb;minor=d,cu   ttyd3
 */
static int
serial_dialout(di_minor_t minor, di_node_t node)
{
	char *mn = di_minor_name(minor);

	if (strcmp(mn, "a,cu") == 0) {
		(void) devfsadm_mklink("ttyd0", node, minor, 0);
		(void) devfsadm_mklink("cua0", node, minor, 0);

	} else if (strcmp(mn, "b,cu") == 0) {
		(void) devfsadm_mklink("ttyd1", node, minor, 0);
		(void) devfsadm_mklink("cua1", node, minor, 0);

	} else if (strcmp(mn, "c,cu") == 0) {
		(void) devfsadm_mklink("ttyd2", node, minor, 0);
		(void) devfsadm_mklink("cua2", node, minor, 0);

	} else if (strcmp(mn, "d,cu") == 0) {
		(void) devfsadm_mklink("ttyd3", node, minor, 0);
		(void) devfsadm_mklink("cua3", node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}

static int
kdmouse(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("kdmouse", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
ipmi(di_minor_t minor, di_node_t node)
{
	/*
	 * Follow convention from other systems, and include an instance#,
	 * even though there will only be one.
	 */
	(void) devfsadm_mklink("ipmi0", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
smbios(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("smbios", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * /dev/mc/mc<chipid> -> /devices/.../pci1022,1102@<chipid+24>,2:mc-amd
 */
static int
mc_node(di_minor_t minor, di_node_t node)
{
	const char *minorname = di_minor_name(minor);
	const char *busaddr = di_bus_addr(node);
	char linkpath[PATH_MAX];
	int unitaddr;
	char *c;

	if (minorname == NULL || busaddr == NULL)
		return (DEVFSADM_CONTINUE);

	errno = 0;
	unitaddr = strtol(busaddr, &c, 16);

	if (errno != 0)
		return (DEVFSADM_CONTINUE);

	if (unitaddr == 0) {
		(void) snprintf(linkpath, sizeof (linkpath), "mc/mc");
	} else if (unitaddr >= MC_AMD_DEV_OFFSET) {
		(void) snprintf(linkpath, sizeof (linkpath), "mc/mc%u",
		    unitaddr - MC_AMD_DEV_OFFSET);
	} else {
		(void) snprintf(linkpath, sizeof (linkpath), "mc/mc%u",
		    minor->dev_minor);
	}
	(void) devfsadm_mklink(linkpath, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Creates \M0 devlink for xsvc node
 */
static int
xsvc(di_minor_t minor, di_node_t node)
{
	char *mn;

	if (strcmp(di_node_name(node), "xsvc") != 0)
		return (DEVFSADM_CONTINUE);

	mn = di_minor_name(minor);
	if (mn == NULL)
		return (DEVFSADM_CONTINUE);

	(void) devfsadm_mklink(mn, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 * Creates \M0 devlink for srn device
 */
static int
srn(di_minor_t minor, di_node_t node)
{
	char *mn;

	if (strcmp(di_node_name(node), "srn") != 0)
		return (DEVFSADM_CONTINUE);

	mn = di_minor_name(minor);
	if (mn == NULL)
		return (DEVFSADM_CONTINUE);

	(void) devfsadm_mklink(mn, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

/*
 *	/dev/ucode	->	/devices/pseudo/ucode@0:ucode
 */
static int
ucode(di_minor_t minor, di_node_t node)
{
	(void) devfsadm_mklink("ucode", node, minor, 0);
	return (DEVFSADM_CONTINUE);
}

static int
heci(di_minor_t minor, di_node_t node)
{
	if (strcmp(di_minor_name(minor), "AMT") == 0) {
		(void) devfsadm_mklink("heci", node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}
