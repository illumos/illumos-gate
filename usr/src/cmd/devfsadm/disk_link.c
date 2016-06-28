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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/int_fmtio.h>
#include <sys/stat.h>
#include <bsm/devalloc.h>
#include <sys/scsi/scsi_address.h>
#include <sys/libdevid.h>
#include <sys/lofi.h>

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
#if defined(__i386) || defined(__amd64)
/*
 * The number of minor nodes per LUN is defined by the disk drivers.
 * Currently it is set to 64. Refer CMLBUNIT_SHIFT (cmlb_impl.h)
 */
#define	NUM_MINORS_PER_INSTANCE	64
#endif


extern int system_labeled;

static int disk_callback_chan(di_minor_t minor, di_node_t node);
static int disk_callback_nchan(di_minor_t minor, di_node_t node);
static int disk_callback_wwn(di_minor_t minor, di_node_t node);
static int disk_callback_xvmd(di_minor_t minor, di_node_t node);
static int disk_callback_fabric(di_minor_t minor, di_node_t node);
static int disk_callback_sas(di_minor_t minor, di_node_t node);
static void disk_common(di_minor_t minor, di_node_t node, char *disk,
				int flags);
static char *diskctrl(di_node_t node, di_minor_t minor);
static int reserved_links_exist(di_node_t node, di_minor_t minor, int nflags);
static void disk_rm_lofi_all(char *file);


static devfsadm_create_t disk_cbt[] = {
	{ "disk", DDI_NT_BLOCK, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", DDI_NT_BLOCK_CHAN, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
	{ "disk", DDI_NT_BLOCK_FABRIC, NULL,
		TYPE_EXACT, ILEVEL_0, disk_callback_fabric
	},
	{ "disk", DDI_NT_BLOCK_WWN, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_wwn
	},
	{ "disk", DDI_NT_BLOCK_SAS, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_sas
	},
	{ "disk", DDI_NT_CD, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", DDI_NT_CD_CHAN, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
	{ "disk", DDI_NT_BLOCK_XVMD, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_xvmd
	},
	{ "disk", DDI_NT_CD_XVMD, NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_xvmd
	},
};

DEVFSADM_CREATE_INIT_V0(disk_cbt);

/*
 * HOT auto cleanup of disks is done for lofi devices only.
 */
static devfsadm_remove_t disk_remove_cbt[] = {
	{ "disk", DISK_LINK_RE, RM_HOT | RM_POST | RM_ALWAYS,
		ILEVEL_0, disk_rm_lofi_all
	},
	{ "disk", DISK_LINK_RE, RM_POST,
		ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(disk_remove_cbt);

static devlink_re_t disks_re_array[] = {
	{"^r?dsk/c([0-9]+)", 1},
	{"^cfg/c([0-9]+)$", 1},
	{"^scsi/.+/c([0-9]+)", 1},
	{NULL}
};

static char *disk_mid = "disk_mid";
static char *modname = "disk_link";

/*
 * Check if link is from lofi by checking path from readlink().
 */
static int
is_lofi_disk(char *file)
{
	char buf[PATH_MAX + 1];
	char filepath[PATH_MAX];
	char *ptr;
	ssize_t size;

	size = snprintf(filepath, sizeof (filepath), "%s/dev/%s",
	    devfsadm_root_path(), file);
	if (size > sizeof (filepath))
		return (0);

	size = readlink(filepath, buf, sizeof (buf) - 1);
	if (size == -1)
		return (0);
	buf[size] = '\0';
	ptr = strchr(buf, '@');
	if (ptr == NULL)
		return (0);
	ptr[1] = '\0';
	if (strcmp(buf, "../../devices/pseudo/lofi@") != 0)
		return (0);
	return (1);
}

/*
 * Wrapper around devfsadm_rm_link() for lofi devices.
 */
static void disk_rm_lofi_all(char *file)
{
	if (is_lofi_disk(file))
		devfsadm_rm_link(file);
}

int
minor_init()
{
	devfsadm_print(disk_mid,
	    "%s: minor_init(): Creating disks reserved ID cache\n",
	    modname);
	return (devfsadm_reserve_id_cache(disks_re_array, NULL));
}

static int
disk_callback_chan(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[23];
	char *driver;
	uint_t targ = 0;
	uint_t lun = 0;

	driver = di_driver_name(node);
	if (strcmp(driver, LOFI_DRIVER_NAME) != 0) {
		addr = di_bus_addr(node);
		(void) sscanf(addr, "%X,%X", &targ, &lun);
	} else {
		targ = di_instance(node);
	}

	(void) snprintf(disk, sizeof (disk), "t%dd%d", targ, lun);
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

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, SCSI_ADDR_PROP_TARGET,
	    &intp) <= 0) {
		return (DEVFSADM_CONTINUE);
	}
	targ = *intp;
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, SCSI_ADDR_PROP_LUN,
	    &intp) <= 0) {
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
		if (strlcpy((char *)ascii_wwn, (char *)wwn,
		    sizeof (ascii_wwn)) >= sizeof (ascii_wwn)) {
			devfsadm_errprint("SUNW_disk_link: GUID too long:%d",
			    strlen((char *)wwn));
			return (DEVFSADM_CONTINUE);
		}
		lun = 0;
	} else if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "port-wwn", &wwn) > 0) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    SCSI_ADDR_PROP_LUN, &intp) > 0) {
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

static int
disk_callback_sas(di_minor_t minor, di_node_t node)
{
	char disk[DISK_SUBPATH_MAX];
	int lun64_found = 0;
	scsi_lun64_t lun64, sl;
	scsi_lun_t lun;
	int64_t *lun64p;
	uint64_t wwn;
	int *intp;
	char *tgt_port;
	uchar_t addr_method;

	/* Get lun property */
	if (di_prop_lookup_int64(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_LUN64, &lun64p) > 0) {
		if (*lun64p != SCSI_LUN64_ILLEGAL) {
			lun64_found = 1;
			lun64 = (uint64_t)*lun64p;
		}
	}
	if ((!lun64_found) && (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_LUN, &intp) > 0)) {
		lun64 = (uint64_t)*intp;
	}

	lun = scsi_lun64_to_lun(lun64);

	addr_method = (lun.sl_lun1_msb & SCSI_LUN_AM_MASK);

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port) > 0) {
		(void) scsi_wwnstr_to_wwn(tgt_port, &wwn);
		if ((addr_method == SCSI_LUN_AM_PDEV) &&
		    (lun.sl_lun2_msb == 0) && (lun.sl_lun2_lsb == 0) &&
		    (lun.sl_lun3_msb == 0) && (lun.sl_lun3_lsb == 0) &&
		    (lun.sl_lun4_msb == 0) && (lun.sl_lun4_lsb == 0)) {
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%"PRIX64"d%"PRId64, wwn, lun64);
		} else if ((addr_method == SCSI_LUN_AM_FLAT) &&
		    (lun.sl_lun2_msb == 0) && (lun.sl_lun2_lsb == 0) &&
		    (lun.sl_lun3_msb == 0) && (lun.sl_lun3_lsb == 0) &&
		    (lun.sl_lun4_msb == 0) && (lun.sl_lun4_lsb == 0)) {
			sl = (lun.sl_lun1_msb << 8) | lun.sl_lun1_lsb;
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%"PRIX64"d%"PRIX16, wwn, sl);
		} else {
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%"PRIX64"d%"PRIX64, wwn, lun64);
		}
	} else if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    SCSI_ADDR_PROP_SATA_PHY, &intp) > 0) {
		/* Use phy format naming, for SATA devices without wwn */
		if ((addr_method == SCSI_LUN_AM_PDEV) &&
		    (lun.sl_lun2_msb == 0) && (lun.sl_lun2_lsb == 0) &&
		    (lun.sl_lun3_msb == 0) && (lun.sl_lun3_lsb == 0) &&
		    (lun.sl_lun4_msb == 0) && (lun.sl_lun4_lsb == 0)) {
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%dd%"PRId64, *intp, lun64);
		} else if ((addr_method == SCSI_LUN_AM_FLAT) &&
		    (lun.sl_lun2_msb == 0) && (lun.sl_lun2_lsb == 0) &&
		    (lun.sl_lun3_msb == 0) && (lun.sl_lun3_lsb == 0) &&
		    (lun.sl_lun4_msb == 0) && (lun.sl_lun4_lsb == 0)) {
			sl = (lun.sl_lun1_msb << 8) | lun.sl_lun1_lsb;
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%dd%"PRIX16, *intp, sl);
		} else {
			(void) snprintf(disk, DISK_SUBPATH_MAX,
			    "t%dd%"PRIX64, *intp, lun64);
		}
	} else {
		return (DEVFSADM_CONTINUE);
	}

	disk_common(minor, node, disk, RM_STALE);

	return (DEVFSADM_CONTINUE);
}

/*
 * xVM virtual block device
 *
 * Xen passes device number in next format:
 *
 *    1 << 28 | disk << 8 | partition      xvd, disks or partitions 16 onwards
 *  202 <<  8 | disk << 4 | partition      xvd, disks and partitions up to 15
 *    8 <<  8 | disk << 4 | partition      sd, disks and partitions up to 15
 *    3 <<  8 | disk << 6 | partition      hd, disks 0..1, partitions 0..63
 *   22 <<  8 | (disk-2) << 6 | partition  hd, disks 2..3, partitions 0..63
 *    2 << 28 onwards                      reserved for future use
 *   other values less than 1 << 28        deprecated / reserved
 *
 * The corresponding Solaris /dev/dsk name can be:
 *
 *          c0tYdXsN
 *
 * where Y,X >= 0.
 *
 * For PV guests using the legacy naming (0, 1, 2, ...)
 * the Solaris disk names created will be c0d[0..767]sN
 */

#define	HD_BASE		(3 << 8)
#define	XEN_EXT_SHIFT	(28)

/*
 * Return: Number of parsed and written parameters
 */
static int
decode_xen_device(uint_t device, uint_t *disk, uint_t *plun)
{
	uint_t dsk, lun = 0;
	int ret = 1;

	if ((device >> XEN_EXT_SHIFT) > 1)
		return (0);

	if (device < HD_BASE) {
		/* legacy device address */
		dsk = device;
		goto end;
	}

	ret = 2;
	if (device & (1 << XEN_EXT_SHIFT)) {
		/* extended */
		dsk = device & (~0xff);
		lun = device & 0xff;
		goto end;
	}

	switch (device >> 8) {
	case 202:				/* xvd */
		dsk = (device >> 4) & 0xf;
		lun =  device & 0xf;
		break;
	case 8:					/* sd */
		dsk = device & (~0xf);
		lun = device & 0xf;
		break;
	case 3:					/* hd, disk 0..1 */
		dsk = device & (~0x3f);
		lun = device & 0x3f;
		break;
	case 22:				/* hd, disk 2..3 */
		dsk = device & (~0x3f);
		lun = device & 0x3f;
		break;
	default:
		return (0);
	}
end:
	*disk = dsk;
	*plun = lun;
	return (ret);
}

static int
disk_callback_xvmd(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[16];
	uint_t targ;
	uint_t dsk, lun;
	int res;

	addr = di_bus_addr(node);
	targ = strtol(addr, (char **)NULL, 10);

	res = decode_xen_device(targ, &dsk, &lun);

	/* HVM device names are generated using the standard generator */

	if (res == 1)
		(void) snprintf(disk, sizeof (disk),  "d%d", dsk);
	else if (res == 2)
		(void) snprintf(disk, sizeof (disk), "t%dd%d", dsk, lun);
	else {
		devfsadm_errprint("%s: invalid disk device number (%s)\n",
		    modname, addr);
		return (DEVFSADM_CONTINUE);
	}
	disk_common(minor, node, disk, 0);
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
#if defined(__i386) || defined(__amd64)
	char mn_copy[4];
	char *part;
	int part_num;
#endif

	mn = di_minor_name(minor);
	if (strstr(mn, ",raw")) {
		dir = "rdsk";
#if defined(__i386) || defined(__amd64)
		(void) strncpy(mn_copy, mn, 4);
		part = strtok(mn_copy, ",");
#endif
	} else {
		dir = "dsk";
#if defined(__i386) || defined(__amd64)
		part = mn;
#endif
	}

#if defined(__i386) || defined(__amd64)
	/*
	 * The following is a table describing the allocation of
	 * minor numbers, minor names and /dev/dsk names for partitions
	 * and slices on x86 systems.
	 *
	 *	Minor Number	Minor Name	/dev/dsk name
	 *	---------------------------------------------
	 *	0 to 15		"a" to "p"	s0 to s15
	 *	16		"q"		p0
	 *	17 to 20	"r" to "u"	p1 to p4
	 *	21 to 52	"p5" to "p36"	p5 to p36
	 *
	 */
	part_num = atoi(part + 1);

	if ((mn[0] == 'p') && (part_num >= 5)) {
		/* logical drive */
		(void) snprintf(slice, 4, "%s", part);
	} else {
#endif
	if (mn[0] < 'q') {
		(void) sprintf(slice, "s%d", mn[0] - 'a');
	} else if (strncmp(mn, MN_EFI, 2) != 0) {
		(void) sprintf(slice, "p%d", mn[0] - 'q');
	} else {
		/* For EFI label */
		(void) sprintf(slice, SLICE_EFI);
	}
#if defined(__i386) || defined(__amd64)
	}
#endif

	nflags = 0;
	if (system_labeled) {
		nt = di_minor_nodetype(minor);
		if ((nt != NULL) &&
		    ((strcmp(nt, DDI_NT_CD) == 0) ||
		    (strcmp(nt, DDI_NT_CD_CHAN) == 0) ||
		    (strcmp(nt, DDI_NT_BLOCK_CHAN) == 0))) {
			nflags = DA_ADD|DA_CD;
		}
	}

	if (reserved_links_exist(node, minor, nflags) == DEVFSADM_SUCCESS) {
		devfsadm_print(disk_mid, "Reserved link exists. Not "
		    "creating links for slice %s\n", slice);
		return;
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

typedef struct dvlist {
	char *dv_link;
	struct dvlist *dv_next;
} dvlist_t;

static void
free_dvlist(dvlist_t **pp)
{
	dvlist_t *entry;

	while (*pp) {
		entry = *pp;
		*pp = entry->dv_next;
		assert(entry->dv_link);
		free(entry->dv_link);
		free(entry);
	}
}
static int
dvlink_cb(di_devlink_t devlink, void *arg)
{
	char *path;
	char *can_path;
	dvlist_t **pp = (dvlist_t **)arg;
	dvlist_t *entry = NULL;

	entry = calloc(1, sizeof (dvlist_t));
	if (entry == NULL) {
		devfsadm_errprint("%s: calloc failed\n", modname);
		goto error;
	}

	path = (char *)di_devlink_path(devlink);
	assert(path);
	if (path == NULL) {
		devfsadm_errprint("%s: di_devlink_path() returned NULL\n",
		    modname);
		goto error;
	}

	devfsadm_print(disk_mid, "%s: found link %s in reverse link cache\n",
	    modname, path);

	/*
	 * Return linkname in canonical form i.e. without the
	 * "/dev/" prefix
	 */
	can_path = strstr(path, "/dev/");
	if (can_path == NULL) {
		devfsadm_errprint("%s: devlink path %s has no /dev/\n",
		    modname, path);
		goto error;
	}

	entry->dv_link = s_strdup(can_path + strlen("/dev/"));
	entry->dv_next = *pp;
	*pp = entry;

	return (DI_WALK_CONTINUE);

error:
	free(entry);
	free_dvlist(pp);
	*pp = NULL;
	return (DI_WALK_TERMINATE);
}

/*
 * Returns success only if all goes well. If there is no matching reserved link
 * or if there is an error, we assume no match. It is better to err on the side
 * of caution by creating extra links than to miss out creating a required link.
 */
static int
reserved_links_exist(di_node_t node, di_minor_t minor, int nflags)
{
	di_devlink_handle_t dvlink_cache = devfsadm_devlink_cache();
	char phys_path[PATH_MAX];
	char *minor_path;
	dvlist_t *head;
	dvlist_t *entry;
	char *s;
	char l[PATH_MAX];
	int switch_link = 0;
	char *mn = di_minor_name(minor);

	if (dvlink_cache == NULL || mn == NULL) {
		devfsadm_errprint("%s: No minor or devlink cache\n", modname);
		return (DEVFSADM_FAILURE);
	}

	if (!devfsadm_have_reserved()) {
		devfsadm_print(disk_mid, "%s: No reserved links\n", modname);
		return (DEVFSADM_FAILURE);
	}

	minor_path = di_devfs_minor_path(minor);
	if (minor_path == NULL) {
		devfsadm_errprint("%s: di_devfs_minor_path failed\n", modname);
		return (DEVFSADM_FAILURE);
	}

	(void) strlcpy(phys_path, minor_path, sizeof (phys_path));

	di_devfs_path_free(minor_path);

	head = NULL;
	(void) di_devlink_cache_walk(dvlink_cache, DISK_LINK_RE, phys_path,
	    DI_PRIMARY_LINK, &head, dvlink_cb);

	/*
	 * We may be switching between EFI label and SMI label in which case
	 * we only have minors of the other type.
	 */
	if (head == NULL && (*mn == *(MN_SMI) ||
	    (strncmp(mn, MN_EFI, 2) == 0))) {
		devfsadm_print(disk_mid, "%s: No links for minor %s in /dev. "
		    "Trying another label\n", modname, mn);
		s = strrchr(phys_path, ':');
		if (s == NULL) {
			devfsadm_errprint("%s: invalid minor path: %s\n",
			    modname, phys_path);
			return (DEVFSADM_FAILURE);
		}
		(void) snprintf(s+1, sizeof (phys_path) - (s + 1 - phys_path),
		    "%s%s", *mn == *(MN_SMI) ? MN_EFI : MN_SMI,
		    strstr(s, ",raw") ? ",raw" : "");
		(void) di_devlink_cache_walk(dvlink_cache, DISK_LINK_RE,
		    phys_path, DI_PRIMARY_LINK, &head, dvlink_cb);
	}

	if (head == NULL) {
		devfsadm_print(disk_mid, "%s: minor %s has no links in /dev\n",
		    modname, phys_path);
		/* no links on disk */
		return (DEVFSADM_FAILURE);
	}

	/*
	 * It suffices to use 1 link to this minor, since
	 * we are matching with reserved IDs on the basis of
	 * the controller number which will be the same for
	 * all links to this minor.
	 */
	if (!devfsadm_is_reserved(disks_re_array, head->dv_link)) {
		/* not reserved links */
		devfsadm_print(disk_mid, "%s: devlink %s and its minor "
		    "are NOT reserved\n", modname, head->dv_link);
		free_dvlist(&head);
		return (DEVFSADM_FAILURE);
	}

	devfsadm_print(disk_mid, "%s: devlink %s and its minor are on "
	    "reserved list\n", modname, head->dv_link);

	/*
	 * Switch between SMI and EFI labels if required
	 */
	switch_link = 0;
	if (*mn == *(MN_SMI) || (strncmp(mn, MN_EFI, 2) == 0)) {
		for (entry = head; entry; entry = entry->dv_next) {
			s = strrchr(entry->dv_link, '/');
			assert(s);
			if (s == NULL) {
				devfsadm_errprint("%s: disk link %s has no "
				    "directory\n", modname, entry->dv_link);
				continue;
			}
			if (*mn == *(MN_SMI) && strchr(s, 's') == NULL) {
				(void) snprintf(l, sizeof (l), "%s%s",
				    entry->dv_link, SLICE_SMI);
				switch_link = 1;
				devfsadm_print(disk_mid, "%s: switching "
				    "reserved link from EFI to SMI label. "
				    "New link is %s\n", modname, l);
			} else if (strncmp(mn, MN_EFI, 2) == 0 &&
			    (s = strchr(s, 's'))) {
				*s = '\0';
				(void) snprintf(l, sizeof (l), "%s",
				    entry->dv_link);
				*s = 's';
				switch_link = 1;
				devfsadm_print(disk_mid, "%s: switching "
				    "reserved link from SMI to EFI label. "
				    "New link is %s\n", modname, l);
			}
			if (switch_link) {
				devfsadm_print(disk_mid, "%s: switching "
				    "link: deleting %s and creating %s\n",
				    modname, entry->dv_link, l);
				devfsadm_rm_link(entry->dv_link);
				(void) devfsadm_mklink(l, node, minor, nflags);
			}
		}
	}
	free_dvlist(&head);

	/*
	 * return SUCCESS to indicate that new links to this minor should not
	 * be created so that only compatibility links to this minor remain.
	 */
	return (DEVFSADM_SUCCESS);
}
