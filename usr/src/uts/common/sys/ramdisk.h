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

#ifndef	_SYS_RAMDISK_H
#define	_SYS_RAMDISK_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * /dev names:
 *	/dev/ramdiskctl		- control device
 *	/dev/ramdisk/<name>	- block devices
 *	/dev/rramdisk/<name>	- character devices
 */
#define	RD_DRIVER_NAME		"ramdisk"
#define	RD_BLOCK_NAME		RD_DRIVER_NAME
#define	RD_CHAR_NAME		"r" RD_DRIVER_NAME

#define	RD_CTL_NODE		"ctl"
#define	RD_CTL_NAME		RD_DRIVER_NAME RD_CTL_NODE

/*
 * Minor number 0 is reserved for the controlling device.  All other ramdisks
 * are assigned minor numbers 1..rd_max_disks.  The minor number is used as
 * an index into the 'rd_devstate' structures.
 */
#define	RD_CTL_MINOR		0

/*
 * Maximum number of ramdisks supported by this driver.
 */
#define	RD_MAX_DISKS		1024

/*
 * Properties exported by the driver.
 */
#define	NBLOCKS_PROP_NAME	"Nblocks"
#define	SIZE_PROP_NAME		"Size"

/*
 * Strip any "ramdisk-" prefix from the name of OBP-created ramdisks.
 */
#define	RD_OBP_PFXSTR		"ramdisk-"
#define	RD_OBP_PFXLEN		(sizeof (RD_OBP_PFXSTR) - 1)

#define	RD_STRIP_PREFIX(newname, oldname) \
	{ \
		char	*onm = oldname; \
		newname = strncmp(onm, RD_OBP_PFXSTR, RD_OBP_PFXLEN) == 0 ? \
		    (onm + RD_OBP_PFXLEN) : onm; \
	}

/*
 * Strip any ",raw" suffix from the name of pseudo ramdisk devices.
 */
#define	RD_STRIP_SUFFIX(name) \
	{ \
		char	*str = strstr((name), ",raw"); \
		if (str != NULL) \
			*str = '\0'; \
	}

/*
 * Interface between the ramdisk(4D) driver and ramdiskadm(8).  Use is:
 *
 *	fd = open("/dev/ramdiskctl", O_RDWR | O_EXCL);
 *
 * 'ramdiskctl' must be opened exclusively. Access is controlled by permissions
 * on the device, which is 0644 by default.  Write-access is required for the
 * allocation and deletion of ramdisks, but only read-access is required for
 * the remaining ioctls which simply return information.
 *
 * ioctl usage:
 *
 *	struct rd_ioctl ri;
 *
 *	strlcpy(ri.ri_name, "somediskname", sizeof (ri.ri_name));
 *	ri.ri_size = somedisksize;
 *	ioctl(fd, RD_CREATE_DISK, &ri);
 *
 *	strlcpy(ri.ri_name, "somediskname", sizeof (ri.ri_name));
 *	ioctl(fd, RD_DELETE_DISK, &ri);
 *
 * (only ramdisks created using the RD_CREATE_DISK ioctl can be deleted
 *  by the RD_DELETE_DISK ioctl).
 *
 * Note that these ioctls are completely private, and only for the use of
 * ramdiskadm(8).
 */
#define	RD_IOC_BASE		(('R' << 16) | ('D' << 8))

#define	RD_CREATE_DISK		(RD_IOC_BASE | 0x01)
#define	RD_DELETE_DISK		(RD_IOC_BASE | 0x02)

#define	RD_NAME_LEN		32	/* Max length of ramdisk name */
#define	RD_NAME_PAD		7	/* Pad ri_name to 8-bytes */

struct rd_ioctl {
	char		ri_name[RD_NAME_LEN + 1];
	char		_ri_pad[RD_NAME_PAD];
	uint64_t	ri_size;
};

#if defined(_KERNEL)

/*
 * We limit the maximum number of active ramdisk devices to 32, tuneable
 * up to a maximum of 1023.  Minor 0 is always reserved for the controlling
 * device.  You can change this by setting a value for 'max_disks' in
 * ramdisk.conf.
 */
#define	RD_DFLT_DISKS	32

/*
 * The maximum amount of memory that can be consumed before starving the
 * kernel depends loosely on the number of cpus, the speed of those cpus,
 * and other hardware characteristics, and is thus highly machine-dependent.
 * The default value of 'rd_percent_physmem' is 25% of physical memory,
 * but this can be changed by setting a value for 'percent_physmem' in
 * ramdisk.conf.
 */
#define	RD_DEFAULT_PERCENT_PHYSMEM	25

/*
 * Maximum size of a physical transfer?
 */
#define	RD_DEFAULT_MAXPHYS	(63 * 1024)	/* '126b' */

/*
 * A real OBP-created ramdisk consists of one or more physical address
 * ranges; these are described by the 'existing' property, whose value
 * is a (corresponding) number of {phys,size} pairs.
 */
#define	OBP_EXISTING_PROP_NAME	"existing"
#define	OBP_ADDRESS_PROP_NAME	"address"
#define	OBP_SIZE_PROP_NAME	"size"

#define	RD_EXISTING_PROP_NAME	"existing"	/* for x86 */

typedef struct {
	uint64_t	phys;			/* Phys addr of range */
	uint64_t	size;			/* Size of range */
} rd_existing_t;


#define	RD_WINDOW_NOT_MAPPED	1	/* Valid window is on page boundary */

/*
 * The entire state of each ramdisk device.  The rd_dip field will reference
 * the actual devinfo for real OBP-created ramdisks, or the generic devinfo
 * 'rd_dip' for pseudo ramdisk devices.
 */
typedef struct rd_devstate {
	kmutex_t	rd_device_lock;		/* Per device lock */
	char		rd_name[RD_NAME_LEN + 1];
	dev_info_t	*rd_dip;		/* My devinfo handle */
	minor_t		rd_minor;		/* Full minor number */
	size_t		rd_size;		/* Size in bytes */
	/*
	 * {rd_nexisting, rd_existing} and {rd_npages, rd_ppa} are
	 * mutually exclusive; the former describe an OBP-created
	 * ramdisk, the latter a 'pseudo' ramdisk.
	 */
	uint_t		rd_nexisting;		/* # 'existing' structs */
	rd_existing_t	*rd_existing;
	pgcnt_t		rd_npages;		/* # physical pages */
	page_t		**rd_ppa;
	/*
	 * Fields describing a virtual window onto the physical ramdisk,
	 * giving the offset within the ramdisk of the window, its size,
	 * and its virtual address (in the kernel heap).
	 */
	uint_t		rd_window_obp;		/* using OBP's vaddr */
	offset_t	rd_window_base;
	uint64_t	rd_window_size;
	caddr_t		rd_window_virt;
	/*
	 * Fields to count opens/closes of the ramdisk.
	 */
	uint32_t	rd_blk_open;
	uint32_t	rd_chr_open;
	uint32_t	rd_lyr_open_cnt;
	/*
	 * Fields to maintain a faked geometry of the disk.
	 */
	struct dk_geom	rd_dkg;
	struct vtoc	rd_vtoc;
	struct dk_cinfo	rd_ci;
	/*
	 * Kstat stuff.
	 */
	kmutex_t	rd_kstat_lock;
	kstat_t		*rd_kstat;
} rd_devstate_t;

extern int	is_pseudo_device(dev_info_t *);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RAMDISK_H */
