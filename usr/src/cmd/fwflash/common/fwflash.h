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

#ifndef	_FWFLASH_H
#define	_FWFLASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/queue.h>
#include <libdevinfo.h>


#define	MSG_INFO	0
#define	MSG_WARN	1
#define	MSG_ERROR	2
int fwflash_debug;

#define	FWFLASH_SUCCESS		0
#define	FWFLASH_FAILURE		1

#define	FWFLASH_FLASH_IMAGES	2


#define	FWPLUGINDIR		"/usr/lib/fwflash/identify"
#define	FWVERIFYPLUGINDIR	"/usr/lib/fwflash/verify"

/*
 * we search for a variable (fwplugin_version, type uint32_t)
 * which should equal FWPLUGIN_VERSION_1
 */

#define	FWPLUGIN_VERSION_1	1

struct devicelist;

struct fw_plugin {

	/*
	 * An opaque handle for dlopen()/dlclose() to use.
	 */
	void *handle;

	/*
	 * fully-qualified filename in /usr/lib/fwflash/identify
	 * made up of [drivername].so
	 *
	 * eg  /usr/lib/fwflash/identify/ses.so
	 * is the identification plugin for devices attached to
	 * the host using the ses(7D) driver.
	 */
	char *filename;

	/*
	 * The driver name that this plugin will search for in
	 * the device tree snapshot using di_drv_first_node(3DEVINFO)
	 * and di_drv_next_node(3DEVINFO).
	 */
	char *drvname; /* "ses" or "tavor" or .... */

	/*
	 * Function entry point to support the command-line "-r"
	 * option - read image from device to persistent storage.
	 *
	 * Not all plugins and devices will support this operation.
	 */
	int (*fw_readfw)(struct devicelist *device, char *filename);


	/*
	 * Function entry point to support the command-line "-f"
	 * option - writes from persistent storage to device
	 *
	 * All identification plugins must support this operation.
	 */
	int (*fw_writefw)(struct devicelist *device, char *filename);


	/*
	 * Function entry point used to build the list of valid, flashable
	 * devices attached to the system using the loadable module drvname.
	 * (Not all devices attached using drvname will be valid for this
	 * plugin to report.
	 *
	 * start allows us to display flashable devices attached with
	 * different drivers and provide the user with a visual clue
	 * that these devices are different to others that are detected.
	 *
	 * All identification plugins must support this operation.
	 */
	int (*fw_identify)(int start);

	/*
	 * Function entry point to support the command-line "-l"
	 * option - list/report flashable devices attached to the system.
	 *
	 * All identification plugins must support this operation.
	 */
	int (*fw_devinfo)(struct devicelist *thisdev);
};


struct pluginlist {
	/*
	 * fully qualified filename in /usr/lib/fwflash/identify
	 * made up of fwflash-[drivername].so
	 *
	 * eg  /usr/lib/fwflash/identify/ses.so
	 * is the identification plugin for devices attached to
	 * the host using the ses(7D) driver.
	 */
	char *filename;

	/*
	 * The driver name that this plugin will search for in
	 * the device tree snapshot using di_drv_first_node(3DEVINFO)
	 * and di_drv_next_node(3DEVINFO).
	 */
	char *drvname;

	/*
	 * pointer to the actual plugin, so we can access its
	 * function entry points
	 */
	struct fw_plugin *plugin;

	/* pointer to the next element in the list */
	TAILQ_ENTRY(pluginlist) nextplugin;
};


struct vpr {
	/* vendor ID, eg "HITACHI " */
	char *vid;

	/* product ID, eg "DK32EJ36NSUN36G " */
	char *pid;

	/* revision, eg "PQ08" */
	char *revid;

	/*
	 * Additional, encapsulated identifying information.
	 * This pointer allows us to add details such as the
	 * IB hba sector size, which command set should be
	 * used or a part number.
	 */
	void *encap_ident;
};




struct fwfile {
	/*
	 * The fully qualified filename. No default location for
	 * for the firmware image file is mandated.
	 */
	char *filename;

	/* Pointer to the identification plugin required */
	struct fw_plugin *plugin;

	/* pointer to the identification summary structure */
	struct vpr *ident;
};



struct devicelist {
	/*
	 * fully qualified pathname, with /devices/.... prefix
	 */
	char *access_devname;

	/*
	 * Which drivername did we find this device attached with
	 * in our device tree walk? Eg, ses or tavor or sgen...
	 */
	char *drvname;

	/*
	 * What class of device is this? For tavor-attached devices,
	 * we set this to "IB". For other devices, unless there is
	 * a common name to use, just make this the same as the
	 * drvname field.
	 */
	char *classname;

	/* pointer to the VPR structure */
	struct vpr *ident;

	/*
	 * In the original fwflash(1M), it was possible to select a
	 * device for flashing by using an index number called a
	 * dev_num. We retain that concept for pluggable fwflash, with
	 * the following change - whenever our identification plugin has
	 * finished and found at least one acceptable device, we bump the
	 * index number by 100. This provides the user with another key
	 * to distinguish the desired device from a potentially very large
	 * list of similar-looking devices.
	 */
	unsigned int index;

	/*
	 * Contains SAS or FC Port-WWNs, or IB GUIDS. Both SAS and FC only
	 * need one entry in this array since they really only have one
	 * address which we should track. IB devices can have 4 GUIDs
	 * (System Image, Node Image, Port 1 and Port 2).
	 */
	char *addresses[4];

	/*
	 * Pointer to the plugin needed to flash this device, and
	 * to use for printing appropriate device-specific information
	 * as required by the "-l" option to fwflash(1M).
	 */
	struct fw_plugin *plugin;

	/* Next entry in the list */
	TAILQ_ENTRY(devicelist) nextdev;
};


/*
 * this type of plugin is for the firmware image vendor-specific
 * verification functions, which we load from FWVERIFYPLUGINDIR
 */

struct vrfyplugin {

	/*
	 * fully-qualified filename in /usr/lib/fwflash/verify,
	 * made up of [drivername]-[vendorname].so
	 *
	 * eg  /usr/lib/fwflash/verify/ses-SUN.so
	 * is the verification plugin for ses-attached devices which
	 * have a vendorname of "SUN".
	 */
	char *filename;

	/*
	 * The vendor name, such as "SUN" or "MELLANOX"
	 */
	char *vendor;

	/*
	 * An opaque handle for dlopen()/dlclose() to use.
	 */
	void *handle;

	/*
	 * Firmware image size in bytes, as reported by
	 * stat().
	 */
	unsigned int imgsize;

	/*
	 * Flashable devices frequently have different buffers
	 * to use for different image types. We track the buffer
	 * required for this particular image with this variable.
	 *
	 * Once the verifier has figured out what sort of image
	 * it's been passed, it will know what value to use for
	 * this variable.
	 */
	unsigned int flashbuf;

	/*
	 * Points to the entire firmware image in memory.
	 * We do this so we can avoid multiple open()/close()
	 * operations, and to make it easier for checksum
	 * calculations.
	 */
	int *fwimage;

	/*
	 * We also store the name of the firmware file that
	 * we point to with *fwimage. This is needed in cases
	 * where we need to key off the name of the file to
	 * determine whether a different buffer in the target
	 * device should be targeted.
	 *
	 * For example, our "standard" firmware image (file.fw)
	 * might require use of buffer id 0, but a boot image
	 * (boot.fw) might require use of buffer id 17. In each
	 * case, it is the verifier plugin that determines the
	 * specific bufferid that is needed by that firmware image.
	 */
	char *imgfile;

	/*
	 * The verification function entry point. The code
	 * in fwflash.c calls this function to verify that
	 * the nominated firmware image file is valid for
	 * the selected devicenode.
	 *
	 * Note that if the verification fails, the image
	 * does _not_ get force-flashed to the device.
	 */
	int (*vendorvrfy)(struct devicelist *devicenode);
};



/* Flags for argument parsing */
#define	FWFLASH_HELP_FLAG	0x01
#define	FWFLASH_VER_FLAG	0x02
#define	FWFLASH_YES_FLAG	0x04
#define	FWFLASH_LIST_FLAG	0x08
#define	FWFLASH_CLASS_FLAG	0x10
#define	FWFLASH_DEVICE_FLAG	0x20
#define	FWFLASH_FW_FLAG		0x40
#define	FWFLASH_READ_FLAG	0x80

/* global variables for fwflash */

TAILQ_HEAD(PLUGINLIST, pluginlist);
TAILQ_HEAD(DEVICELIST, devicelist);
struct PLUGINLIST *fw_pluginlist;
struct DEVICELIST *fw_devices;


struct vrfyplugin *verifier;
di_node_t rootnode;
struct fw_plugin *self;


int manufacturing_mode;

/*
 * utility defines and macros, since the firmware image we get
 * from LSI is ARM-format and that means byte- and short-swapping
 * on sparc
 */

#define	HIGHBITS16		0xff00
#define	HIGHBITS32		0xffff0000
#define	HIGHBITS64		0xffffffff00000000ULL
#define	LOWBITS16		0x00ff
#define	LOWBITS32		0x0000ffff
#define	LOWBITS64		0x00000000ffffffffULL


#if defined(_LITTLE_ENDIAN)
#define	ARMSWAPBITS(bs)	(bs)
#define	MLXSWAPBITS16(bs)	\
	(BE_16(((bs) & LOWBITS16)) | BE_16(((bs) & HIGHBITS16)))
#define	MLXSWAPBITS32(bs)	\
	(BE_32(((bs) & LOWBITS32)) | BE_32(((bs) & HIGHBITS32)))
#define	MLXSWAPBITS64(bs)	\
	(BE_64(((bs) & LOWBITS64)) | BE_64(((bs) & HIGHBITS64)))
#else
#define	ARMSWAPBITS(bs)	(LE_32(((bs) & LOWBITS32)) | LE_32(((bs) & HIGHBITS32)))
#define	MLXSWAPBITS16(bs)	(bs)
#define	MLXSWAPBITS32(bs)	(bs)
#define	MLXSWAPBITS64(bs)	(bs)

#endif


/* common functions for fwflash */

void logmsg(int severity, char *msg, ...);


#ifdef __cplusplus
}
#endif

#endif /* _FWFLASH_H */
