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

#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <bsm/devalloc.h>

#define	DISK_SUBPATH_MAX 100
#define	RM_STALE 0x01
#define	DISK_LINK_RE	"^r?dsk/c[0-9]+(t[0-9A-F]+)?d[0-9]+(((s|p))[0-9]+)?$"
#define	DISK_LINK_TO_UPPER(ch)\
	(((ch) >= 'a' && (ch) <= 'z') ? (ch - 'a' + 'A') : ch)

#define	SLICE_SMI	"s7"
#define	SLICE_EFI	""

#define	MN_SMI		"h"
#define	MN_EFI		"wd"
#define	ASCIIWWNSIZE	255

extern int system_labeled;

static int disk_callback_chan(di_minor_t minor, di_node_t node);
static int disk_callback_nchan(di_minor_t minor, di_node_t node);
static int disk_callback_wwn(di_minor_t minor, di_node_t node);
static int disk_callback_fabric(di_minor_t minor, di_node_t node);
static void disk_common(di_minor_t minor, di_node_t node, char *disk,
				int flags);
static char *diskctrl(di_node_t node, di_minor_t minor);
extern void rm_link_from_cache(char *devlink, char *physpath);


static devfsadm_create_t disk_cbt[] = {
	{ "disk", "ddi_block", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", "ddi_block:channel", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
	{ "disk", "ddi_block:fabric", NULL,
		TYPE_EXACT, ILEVEL_0, disk_callback_fabric
	},
	{ "disk", "ddi_block:wwn", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_wwn
	},
	{ "disk", "ddi_block:cdrom", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", "ddi_block:cdrom:channel", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
};

DEVFSADM_CREATE_INIT_V0(disk_cbt);

/*
 * HOT auto cleanup of disks not desired.
 */
static devfsadm_remove_t disk_remove_cbt[] = {
	{ "disk", DISK_LINK_RE, RM_POST,
		ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(disk_remove_cbt);

static int
disk_callback_chan(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[20];
	uint_t targ;
	uint_t lun;

	addr = di_bus_addr(node);
	(void) sscanf(addr, "%X,%X", &targ, &lun);
	(void) sprintf(disk, "t%dd%d", targ, lun);
	disk_common(minor, node, disk, 0);
	return (DEVFSADM_CONTINUE);

}

static int
disk_callback_nchan(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[10];
	uint_t lun;

	addr = di_bus_addr(node);
	(void) sscanf(addr, "%X", &lun);
	(void) sprintf(disk, "d%d", lun);
	disk_common(minor, node, disk, 0);
	return (DEVFSADM_CONTINUE);

}

static int
disk_callback_wwn(di_minor_t minor, di_node_t node)
{
	char disk[10];
	int lun;
	int targ;
	int *intp;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		"target", &intp) <= 0) {
		return (DEVFSADM_CONTINUE);
	}
	targ = *intp;
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "lun", &intp) <= 0) {
		    lun = 0;
	} else {
		    lun = *intp;
	}
	(void) sprintf(disk, "t%dd%d", targ, lun);

	disk_common(minor, node, disk, RM_STALE);

	return (DEVFSADM_CONTINUE);
}

static int
disk_callback_fabric(di_minor_t minor, di_node_t node)
{
	char disk[DISK_SUBPATH_MAX];
	int lun;
	int count;
	int *intp;
	uchar_t *str;
	uchar_t *wwn;
	uchar_t ascii_wwn[ASCIIWWNSIZE];

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "client-guid", (char **)&wwn) > 0) {
		if (strlcpy((char *)ascii_wwn, (char *)wwn, sizeof (ascii_wwn))
			>= sizeof (ascii_wwn)) {
			devfsadm_errprint("SUNW_disk_link: GUID too long:%d",
				strlen((char *)wwn));
			return (DEVFSADM_CONTINUE);
		}
		lun = 0;
	} else if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "port-wwn", &wwn) > 0) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "lun", &intp) > 0) {
			lun = *intp;
		} else {
			lun = 0;
		}

		for (count = 0, str = ascii_wwn; count < 8; count++, str += 2) {
			(void) sprintf((caddr_t)str, "%02x", wwn[count]);
		}
		*str = '\0';
	} else {
		return (DEVFSADM_CONTINUE);
	}

	for (str = ascii_wwn; *str != '\0'; str++) {
		*str = DISK_LINK_TO_UPPER(*str);
	}

	(void) snprintf(disk, DISK_SUBPATH_MAX, "t%sd%d", ascii_wwn, lun);

	disk_common(minor, node, disk, RM_STALE);

	return (DEVFSADM_CONTINUE);
}

/*
 * This function is called for every disk minor node.
 * Calls enumerate to assign a logical controller number, and
 * then devfsadm_mklink to make the link.
 */
static void
disk_common(di_minor_t minor, di_node_t node, char *disk, int flags)
{
	char l_path[PATH_MAX + 1];
	char sec_path[PATH_MAX + 1];
	char stale_re[DISK_SUBPATH_MAX];
	char *dir;
	char slice[4];
	char *mn;
	char *ctrl;
	char *nt = NULL;
	int *int_prop;
	int  nflags = 0;

	if (strstr(mn = di_minor_name(minor), ",raw")) {
		dir = "rdsk";
	} else {
		dir = "dsk";
	}

	if (mn[0] < 113) {
		(void) sprintf(slice, "s%d", mn[0] - 'a');
	} else if (strncmp(mn, MN_EFI, 2) != 0) {
		(void) sprintf(slice, "p%d", mn[0] - 'q');
	} else {
		/* For EFI label */
		(void) sprintf(slice, SLICE_EFI);
	}

	if (NULL == (ctrl = diskctrl(node, minor)))
		return;

	(void) strcpy(l_path, dir);
	(void) strcat(l_path, "/c");
	(void) strcat(l_path, ctrl);
	(void) strcat(l_path, disk);

	/*
	 * If switching between SMI and EFI label or vice versa
	 * cleanup the previous label's devlinks.
	 */
	if (*mn == *(MN_SMI) || (strncmp(mn, MN_EFI, 2) == 0)) {
		char *s, tpath[PATH_MAX + 1];
		struct stat sb;

		s = l_path + strlen(l_path);
		(void) strcat(l_path, (*mn == *(MN_SMI))
		    ? SLICE_EFI : SLICE_SMI);
		/*
		 * Attempt the remove only if the stale link exists
		 */
		(void) snprintf(tpath, sizeof (tpath), "%s/dev/%s",
		    devfsadm_root_path(), l_path);
		if (lstat(tpath, &sb) != -1)
			devfsadm_rm_all(l_path);
		*s = '\0';
	}
	(void) strcat(l_path, slice);

	if (system_labeled) {
		nt = di_minor_nodetype(minor);
		if ((nt != NULL) &&
		    ((strcmp(nt, DDI_NT_CD) == 0) ||
		    (strcmp(nt, DDI_NT_CD_CHAN) == 0) ||
		    (strcmp(nt, DDI_NT_BLOCK_CHAN) == 0))) {
			nflags = DA_ADD|DA_CD;
		}
	}

	(void) devfsadm_mklink(l_path, node, minor, nflags);

	/* secondary links for removable and hotpluggable devices */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "removable-media",
	    &int_prop) >= 0) {
		(void) strcpy(sec_path, "removable-media/");
		(void) strcat(sec_path, l_path);
		(void) devfsadm_secondary_link(sec_path, l_path, 0);
	}
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "hotpluggable",
	    &int_prop) >= 0) {
		(void) strcpy(sec_path, "hotpluggable/");
		(void) strcat(sec_path, l_path);
		(void) devfsadm_secondary_link(sec_path, l_path, 0);
	}

	if ((flags & RM_STALE) == RM_STALE) {
		(void) strcpy(stale_re, "^");
		(void) strcat(stale_re, dir);
		(void) strcat(stale_re, "/c");
		(void) strcat(stale_re, ctrl);
		(void) strcat(stale_re, "t[0-9A-F]+d[0-9]+(s[0-9]+)?$");
		/*
		 * optimizations are made inside of devfsadm_rm_stale_links
		 * instead of before calling the function, as it always
		 * needs to add the valid link to the cache.
		 */
		devfsadm_rm_stale_links(stale_re, l_path, node, minor);
	}

	free(ctrl);
}


/* index of enumeration rule applicable to this module */
#define	RULE_INDEX	0

static char *
diskctrl(di_node_t node, di_minor_t minor)
{
	char path[PATH_MAX + 1];
	char *devfspath;
	char *buf, *mn;

	devfsadm_enumerate_t rules[3] = {
	    {"^r?dsk$/^c([0-9]+)", 1, MATCH_PARENT},
	    {"^cfg$/^c([0-9]+)$", 1, MATCH_ADDR},
	    {"^scsi$/^.+$/^c([0-9]+)", 1, MATCH_PARENT}
	};

	mn = di_minor_name(minor);

	if ((devfspath = di_devfs_path(node)) == NULL) {
		return (NULL);
	}
	(void) strcpy(path, devfspath);
	(void) strcat(path, ":");
	(void) strcat(path, mn);
	di_devfs_path_free(devfspath);

	/*
	 * Use controller component of disk path
	 */
	if (disk_enumerate_int(path, RULE_INDEX, &buf, rules, 3) ==
	    DEVFSADM_MULTIPLE) {

		/*
		 * We failed because there are multiple logical controller
		 * numbers for a single physical controller.  If we use node
		 * name also in the match it should fix this and only find one
		 * logical controller. (See 4045879).
		 * NOTE: Rules for controllers are not changed, as there is
		 * no unique controller number for them in this case.
		 *
		 * MATCH_UNCACHED flag is private to the "disks" and "sgen"
		 * modules. NOT to be used by other modules.
		 */

		rules[0].flags = MATCH_NODE | MATCH_UNCACHED; /* disks */
		rules[2].flags = MATCH_NODE | MATCH_UNCACHED; /* generic scsi */
		if (devfsadm_enumerate_int(path, RULE_INDEX, &buf, rules, 3)) {
			return (NULL);
		}
	}

	return (buf);
}
