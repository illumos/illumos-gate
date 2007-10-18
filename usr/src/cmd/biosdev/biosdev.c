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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <libdevinfo.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/biosdisk.h>


/*
 * structure used for searching device tree for a node matching
 * pci bus/dev/fn
 */
typedef struct pcibdf {
	int busnum;
	int devnum;
	int funcnum;
	di_node_t	di_node;
} pcibdf_t;

/*
 * structure used for searching device tree for a node matching
 * USB serial number.
 */
typedef struct {
	uint64_t serialno;
	di_node_t	node;
} usbser_t;

/*
 * structure for holding the mapping info
 */
typedef struct {
	int disklist_index;	/* index to disk_list of the mapped path */
	int matchcount;		/* number of matches per this device number */
} mapinfo_t;

#define	DEVFS_PREFIX "/devices"
#define	DISKS_LIST_INCR		20	/* increment for resizing disk_list */

#define	BIOSPROPNAME_TMPL	"biosdev-0x%x"
#define	BIOSPROPNAME_TMPL_LEN	13
#define	BIOSDEV_NUM		8
#define	STARTING_DRVNUM		0x80

/*
 * array to hold mappings. Element at index X corresponds to BIOS device
 * number 0x80 + X
 */
static mapinfo_t mapinfo[BIOSDEV_NUM];

/*
 * Cache copy of kernel device tree snapshot root handle, includes devices
 * that are detached
 */
static di_node_t root_node = DI_NODE_NIL;

/*
 * kernel device tree snapshot with currently attached devices. Detached
 * devices are not included.
 */
static di_node_t root_allnode = DI_NODE_NIL;

/*
 * handle to retrieve prom properties
 */

static di_prom_handle_t prom_hdl = DI_PROM_HANDLE_NIL;

static char **disk_list = NULL;	/* array of physical device pathnames */
static int disk_list_len = 0;		/* length of disk_list */
static int disk_list_valid = 0;	/* number of valid entries in disk_list */

static int debug = 0;			/* used for enabling debug output */


/* Local function prototypes */
static void new_disk_list_entry(di_node_t node);
static int i_disktype(di_node_t node, di_minor_t minor, void *arg);
static void build_disk_list();
static int search_disklist_match_path(char *path);
static void free_disks();
static void cleanup_and_exit(int);

static int match_edd(biosdev_data_t *bd);
static int match_first_block(biosdev_data_t *bd);

static di_node_t search_tree_match_pcibdf(di_node_t node, int bus, int dev,
    int fn);
static int i_match_pcibdf(di_node_t node, void *arg);

static di_node_t search_tree_match_usbserialno(di_node_t node,
    uint64_t serialno);
static int i_match_usbserialno(di_node_t node, void *arg);

static di_node_t search_children_match_busaddr(di_node_t node,
    char *matchbusaddr);



static void
new_disk_list_entry(di_node_t node)
{
	size_t	newsize;
	char **newlist;
	int newlen;
	char *devfspath;

	if (disk_list_valid >= disk_list_len)	{
		/* valid should never really be larger than len */
		/* if they are equal we need to init or realloc */
		newlen = disk_list_len + DISKS_LIST_INCR;
		newsize = newlen * sizeof (*disk_list);

		newlist = (char **)realloc(disk_list, newsize);
		if (newlist == NULL) {
			(void) printf("realloc failed to resize disk table\n");
			cleanup_and_exit(1);
		}
		disk_list = newlist;
		disk_list_len = newlen;
	}

	devfspath = di_devfs_path(node);
	disk_list[disk_list_valid] = devfspath;
	if (debug)
		(void) printf("adding %s\n", devfspath);
	disk_list_valid++;
}

/* ARGSUSED */
static int
i_disktype(di_node_t node, di_minor_t minor, void *arg)
{
	char *minortype;

	if (di_minor_spectype(minor) == S_IFCHR) {
		minortype = di_minor_nodetype(minor);

		/* exclude CD's */
		if (strncmp(minortype, DDI_NT_CD, sizeof (DDI_NT_CD) - 1) != 0)
			/* only take p0 raw device */
			if (strcmp(di_minor_name(minor), "q,raw") == 0)
				new_disk_list_entry(node);
	}
	return (DI_WALK_CONTINUE);
}

static void
build_disk_list()
{
	int ret;
	ret = di_walk_minor(root_node, DDI_NT_BLOCK, 0, NULL,
	    i_disktype);
	if (ret != 0) {
		(void) fprintf(stderr, "di_walk_minor failed errno %d\n",
		    errno);
		cleanup_and_exit(1);
	}
}

static void
free_disks()
{
	int i;

	if (disk_list) {
		for (i = 0; i < disk_list_valid; i++)
			di_devfs_path_free(disk_list[i]);

		free(disk_list);
	}
}

static int
i_match_pcibdf(di_node_t node, void *arg)
{
	pcibdf_t *pbp;
	int len;
	uint32_t	regval;
	uint32_t	busnum, funcnum, devicenum;
	char *devtype;
	uint32_t *regbuf = NULL;
	di_node_t	parentnode;

	pbp = (pcibdf_t *)arg;

	parentnode = di_parent_node(node);

	len = di_prop_lookup_strings(DDI_DEV_T_ANY, parentnode,
	    "device_type", (char **)&devtype);

	if ((len <= 0) ||
	    ((strcmp(devtype, "pci") != 0) && (strcmp(devtype, "pciex") != 0)))
		return (DI_WALK_CONTINUE);

	len = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg",
	    (int **)&regbuf);

	if (len <= 0) {
		/* Try PROM property */
		len = di_prom_prop_lookup_ints(prom_hdl, node, "reg",
		    (int **)&regbuf);
	}


	if (len > 0) {
		regval = regbuf[0];

		busnum = PCI_REG_BUS_G(regval);
		devicenum = PCI_REG_DEV_G(regval);
		funcnum = PCI_REG_FUNC_G(regval);

		if ((busnum == pbp->busnum) &&
		    (devicenum == pbp->devnum) &&
		    (funcnum == pbp->funcnum)) {
			/* found it */
			pbp->di_node = node;
			return (DI_WALK_TERMINATE);
		}
	}

	return (DI_WALK_CONTINUE);
}

static di_node_t
search_tree_match_pcibdf(di_node_t node, int bus, int dev, int fn)
{
	pcibdf_t pb;
	pb.busnum = bus;
	pb.devnum = dev;
	pb.funcnum = fn;
	pb.di_node = DI_NODE_NIL;

	(void) di_walk_node(node, DI_WALK_CLDFIRST, &pb, i_match_pcibdf);
	return (pb.di_node);

}

static int
i_match_usbserialno(di_node_t node, void *arg)
{
	int len;
	char *serialp;
	usbser_t *usbsp;

	usbsp = (usbser_t *)arg;

	len = di_prop_lookup_bytes(DDI_DEV_T_ANY, node, "usb-serialno",
	    (uchar_t **)&serialp);

	if ((len > 0) && (strncmp((char *)&usbsp->serialno, serialp,
	    sizeof (uint64_t)) == 0)) {
		usbsp->node = node;
		return (DI_WALK_TERMINATE);
	}
	return (DI_WALK_CONTINUE);
}

static di_node_t
search_tree_match_usbserialno(di_node_t node, uint64_t serialno)
{

	usbser_t usbs;

	usbs.serialno = serialno;
	usbs.node = DI_NODE_NIL;

	(void) di_walk_node(node, DI_WALK_CLDFIRST, &usbs, i_match_usbserialno);
	return (usbs.node);
}

/*
 * returns the index to the disklist to the disk with matching path
 */
static int
search_disklist_match_path(char *path)
{
	int i;
	for (i = 0; i < disk_list_valid; i++)
		if (strcmp(disk_list[i], path) == 0) {
			return (i);
		}
	return (-1);
}

/*
 * Find first child of 'node' whose unit address is 'matchbusaddr'
 */
static di_node_t
search_children_match_busaddr(di_node_t node, char *matchbusaddr)
{
	di_node_t cnode;
	char *busaddr;

	if (matchbusaddr == NULL)
		return (DI_NODE_NIL);


	for (cnode = di_child_node(node); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode)) {
		busaddr = di_bus_addr(cnode);
		if (busaddr == NULL)
			continue;
		if (strncmp(busaddr, matchbusaddr, MAXNAMELEN) == 0)
			break;
	}
	return (cnode);
}

/*
 * Construct a physical device pathname from EDD and verify the
 * path exists. Return the index of in disk_list for the mapped
 * path on success, -1 on failure.
 */
static int
match_edd(biosdev_data_t *bdata)
{
	di_node_t node, cnode = DI_NODE_NIL;
	char *devfspath = NULL;
	fn48_t *bd;
	int index;
	char busaddrbuf[MAXNAMELEN];

	if (!bdata->edd_valid) {
		if (debug)
			(void) printf("edd not valid\n");
		return (-1);
	}

	bd = &bdata->fn48_dev_params;

	if (bd->magic != 0xBEDD || bd->pathinfo_len == 0) {
		/* EDD extensions for devicepath not present */
		if (debug)
			(void) printf("magic not valid %x pathinfolen %d\n",
			    bd->magic, bd->pathinfo_len);
		return (-1);
	}

	/* we handle only PCI scsi, ata or sata for now */
	if (strncmp(bd->bustype, "PCI", 3) != 0) {
		if (debug)
			(void) printf("was not pci %s\n", bd->bustype);
		return (-1);
	}
	if (debug)
		(void) printf("match_edd bdf %d %d %d\n",
		    bd->interfacepath.pci.bus,
		    bd->interfacepath.pci.device,
		    bd->interfacepath.pci.function);

	/* look into devinfo tree and find a node with matching pci b/d/f */
	node = search_tree_match_pcibdf(root_node, bd->interfacepath.pci.bus,
	    bd->interfacepath.pci.device, bd->interfacepath.pci.function);

	if (node == DI_NODE_NIL) {
		if (debug)
			(void) printf(" could not find a node in tree "
			    "matching bdf\n");
		return (-1);
	}

	if (debug) {
		int i;
		(void) printf("interface type ");
		for (i = 0; i < 8; i++)
			(void) printf("%c", bd->interface_type[i]);
		(void) printf(" pci channel %x target %x\n",
		    bd->interfacepath.pci.channel,
		    bd->devicepath.scsi.target);
	}

	if (strncmp(bd->interface_type, "SCSI", 4) == 0) {

		(void) snprintf(busaddrbuf, MAXNAMELEN, "%x,%x",
		    bd->devicepath.scsi.target, bd->devicepath.scsi.lun_lo);

		cnode = search_children_match_busaddr(node, busaddrbuf);

	} else if ((strncmp(bd->interface_type, "ATAPI", 5) == 0) ||
	    (strncmp(bd->interface_type, "ATA", 3) == 0) ||
	    (strncmp(bd->interface_type, "SATA", 4) == 0)) {

		if (strncmp(di_node_name(node), "pci-ide", 7) == 0) {
			/*
			 * Legacy using pci-ide
			 * the child should be ide@<x>, where x is
			 * the channel number
			 */
			(void) snprintf(busaddrbuf, MAXNAMELEN, "%d",
			    bd->interfacepath.pci.channel);

			if ((cnode = search_children_match_busaddr(node,
			    busaddrbuf)) != DI_NODE_NIL) {

				(void) snprintf(busaddrbuf, MAXNAMELEN, "%x,0",
				    bd->devicepath.ata.chan);
				cnode = search_children_match_busaddr(cnode,
				    busaddrbuf);

				if (cnode == DI_NODE_NIL)
					if (debug)
						(void) printf("Interface %s "
						    "using pci-ide no "
						    "grandchild at %s\n",
						    bd->interface_type,
						    busaddrbuf);
			} else {
				if (debug)
					(void) printf("Interface %s using "
					    "pci-ide, with no child at %s\n",
					    bd->interface_type, busaddrbuf);
			}
		} else {
			if (strncmp(bd->interface_type, "SATA", 4) == 0) {
				/*
				 * The current EDD (EDD-2) spec does not
				 * address port number. This is work in
				 * progress.
				 * Interprete the first field of device path
				 * as port number. Needs to be revisited
				 * with port multiplier support.
				 */
				(void) snprintf(busaddrbuf, MAXNAMELEN, "%x,0",
				    bd->devicepath.ata.chan);

				cnode = search_children_match_busaddr(node,
				    busaddrbuf);
			} else {
				if (debug)
					(void) printf("Interface %s, not using"
					    " pci-ide\n", bd->interface_type);
			}
		}

	} else if (strncmp(bd->interface_type, "USB", 3) == 0) {
		cnode = search_tree_match_usbserialno(node,
		    bd->devicepath.usb.usb_serial_id);
	} else {
		if (debug)
			(void) printf("sorry not supported interface %s\n",
			    bd->interface_type);
	}

	if (cnode != DI_NODE_NIL) {
		devfspath = di_devfs_path(cnode);
		index = search_disklist_match_path(devfspath);
		di_devfs_path_free(devfspath);
		if (index >= 0)
			return (index);
	}

	return (-1);
}

/*
 * For each disk in list of disks, compare the first block with the
 * one from bdd. On the first match, return the index of path in
 * disk_list. If none matched return -1.
 */
static int
match_first_block(biosdev_data_t *bd)
{

	char diskpath[MAXPATHLEN];
	int fd;
	char buf[512];
	ssize_t	num_read;
	int i;

	if (!bd->first_block_valid)
		return (-1);

	for (i = 0; i < disk_list_valid; i++) {
		(void) snprintf(diskpath, MAXPATHLEN, "%s/%s:q,raw",
		    DEVFS_PREFIX, disk_list[i]);
		fd = open(diskpath, O_RDONLY);
		if (fd  < 0) {
			(void) fprintf(stderr, "opening %s failed errno %d\n",
			    diskpath, errno);
			continue;
		}
		num_read = read(fd, buf, 512);
		if (num_read != 512) {
			(void) printf("read only %d bytes from %s\n", num_read,
			    diskpath);
			continue;
		}

		if (memcmp(buf, bd->first_block, 512) == 0)	 {
			/* found it */
			return (i);
		}
	}
	return (-1);
}


static void
cleanup_and_exit(int exitcode)
{

	free_disks();

	if (root_node != DI_NODE_NIL)
		di_fini(root_node);

	if (root_allnode != DI_NODE_NIL)
		di_fini(root_allnode);

	if (prom_hdl != DI_PROM_HANDLE_NIL)
		di_prom_fini(prom_hdl);
	exit(exitcode);

}


int
main(int argc, char *argv[])
{
	biosdev_data_t		*biosdata;
	int i, c, j;
	int matchedindex = -1;
	char biospropname[BIOSPROPNAME_TMPL_LEN];
	int totalmatches = 0;
	biosdev_data_t *biosdataarray[BIOSDEV_NUM];


	while ((c = getopt(argc, argv, "d")) != -1)  {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		default:
			(void) printf("unknown option %c\n", c);
			exit(1);
		}
	}

	if ((prom_hdl = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		(void) fprintf(stderr, "di_prom_init failed\n");
		cleanup_and_exit(1);
	}

	if ((root_node = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		(void) fprintf(stderr, "di_init failed\n");
		cleanup_and_exit(1);
	}

	if ((root_allnode = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		(void) fprintf(stderr, "di_init failed\n");
		cleanup_and_exit(1);
	}

	(void) memset(mapinfo, 0, sizeof (mapinfo));

	/* get a list of all disks in the system */
	build_disk_list();

	/*  Get property values that were created at boot up time */
	for (i = 0; i < BIOSDEV_NUM; i++) {

		(void) snprintf((char *)biospropname, BIOSPROPNAME_TMPL_LEN,
		    BIOSPROPNAME_TMPL, i + STARTING_DRVNUM);
		if (di_prop_lookup_bytes(DDI_DEV_T_ANY, root_allnode,
		    biospropname, (uchar_t **)&biosdataarray[i]) <= 0)
			biosdataarray[i] = NULL;
	}

	/* Try to match based on device/interface path info from BIOS */
	for (i = 0; i < BIOSDEV_NUM; i++) {

		if ((biosdata = biosdataarray[i]) == NULL)
			continue;
		if (debug)
			(void) printf("matching edd 0x%x\n",
			    i + STARTING_DRVNUM);

		matchedindex = match_edd(biosdata);

		if (matchedindex != -1) {
			if (debug) {
				(void) printf("matched by edd\n");
				(void) printf("0x%x %s\n", i + STARTING_DRVNUM,
				    disk_list[matchedindex]);
			}

			mapinfo[i].disklist_index = matchedindex;
			mapinfo[i].matchcount++;

			for (j = 0; j < i; j++) {
				if (mapinfo[j].matchcount > 0 &&
				    mapinfo[j].disklist_index == matchedindex) {
					mapinfo[j].matchcount++;
					mapinfo[i].matchcount++;
				}
			}

		} else
			if (debug)
				(void) printf("No matches by edd\n");
	}

	/*
	 * Go through the list and ignore any found matches that are dups.
	 * This is to workaround issues with BIOSes that do not implement
	 * providing interface/device path info correctly.
	 */

	for (i = 0; i < BIOSDEV_NUM; i++) {
		if (mapinfo[i].matchcount > 1) {
			if (debug)
				(void) printf("Ignoring dup match_edd\n(count "
				    "%d): 0x%x %s\n", mapinfo[i].matchcount,
				    i + STARTING_DRVNUM,
				    disk_list[mapinfo[i].disklist_index]);

			mapinfo[i].matchcount = 0;
			mapinfo[i].disklist_index = 0;
		}
	}


	/*
	 * For each bios dev number that we do not have exactly one match
	 * already, try to match based on first block
	 */
	for (i = 0; i < BIOSDEV_NUM; i++) {
		if (mapinfo[i].matchcount == 1)
			continue;

		if ((biosdata = biosdataarray[i]) == NULL)
			continue;

		if (debug)
			(void) printf("matching first block 0x%x\n",
			    i + STARTING_DRVNUM);

		matchedindex = match_first_block(biosdata);
		if (matchedindex != -1) {
			if (debug) {
				(void) printf("matched by first block\n");
				(void) printf("0x%x %s\n", i + STARTING_DRVNUM,
				    disk_list[matchedindex]);
			}

			mapinfo[i].disklist_index = matchedindex;
			mapinfo[i].matchcount++;

			for (j = 0; j < i; j++) {
				if (mapinfo[j].matchcount > 0 &&
				    mapinfo[j].disklist_index == matchedindex) {
					mapinfo[j].matchcount++;
					mapinfo[i].matchcount++;
				}
			}
		} else
			if (debug) {
				(void) printf(" No matches by first block\n");
				(void) fprintf(stderr, "Could not match 0x%x\n",
				    i + STARTING_DRVNUM);
			}
	}


	for (i = 0; i < BIOSDEV_NUM; i++) {
		if (mapinfo[i].matchcount == 1) {
			(void) printf("0x%x %s\n", i + STARTING_DRVNUM,
			    disk_list[mapinfo[i].disklist_index]);
			totalmatches++;
		} else if (debug && mapinfo[i].matchcount > 1) {
			(void) printf("0x%x %s matchcount %d\n",
			    i + STARTING_DRVNUM,
			    disk_list[mapinfo[i].disklist_index],
			    mapinfo[i].matchcount);
		}
	}

	if (totalmatches == 0) {
		(void) fprintf(stderr, "biosdev: Could not match any!!\n");
		cleanup_and_exit(1);
	}

	cleanup_and_exit(0);
	/* NOTREACHED */
	return (0);
}
