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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PX_TOOLS_H
#define	_SYS_PX_TOOLS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Ioctls for PCI tools.
 */
#define	PCITOOL_IOC		(('P' << 24) | ('C' << 16) | ('T' << 8))

/* Read/write a device on a PCI bus, in physical space. */
#define	PCITOOL_DEVICE_GET_REG	(PCITOOL_IOC | 1)
#define	PCITOOL_DEVICE_SET_REG	(PCITOOL_IOC | 2)

/* Read/write the PCI nexus bridge, in physical space. */
#define	PCITOOL_NEXUS_GET_REG	(PCITOOL_IOC | 3)
#define	PCITOOL_NEXUS_SET_REG	(PCITOOL_IOC | 4)

/* Get/set interrupt-CPU mapping for PCI devices. */
#define	PCITOOL_DEVICE_GET_INTR	(PCITOOL_IOC | 5)
#define	PCITOOL_DEVICE_SET_INTR	(PCITOOL_IOC | 6)

/* Return the number of supported interrupts on a PCI bus. */
#define	PCITOOL_DEVICE_NUM_INTR	(PCITOOL_IOC | 7)


/*
 * This file contains data structures for the pci tool.
 */
#define	CONFIG	0
#define	BAR0	1
#define	BAR1	2
#define	BAR2	3
#define	BAR3	4
#define	BAR4	5
#define	BAR5	6
#define	ROM	7

/*
 * BAR corresponding to space desired.
 */
typedef enum {
    config = CONFIG,
    bar0 = BAR0,
    bar1 = BAR1,
    bar2 = BAR2,
    bar3 = BAR3,
    bar4 = BAR4,
    bar5 = BAR5,
    rom = ROM
} pcitool_bars_t;


/*
 * PCITOOL error numbers.
 */

typedef enum {
	PCITOOL_SUCCESS = 0x0,
	PCITOOL_INVALID_CPUID,
	PCITOOL_INVALID_INO,
	PCITOOL_PENDING_INTRTIMEOUT,
	PCITOOL_REGPROP_NOTWELLFORMED,
	PCITOOL_INVALID_ADDRESS,
	PCITOOL_NOT_ALIGNED,
	PCITOOL_OUT_OF_RANGE,
	PCITOOL_END_OF_RANGE,
	PCITOOL_ROM_DISABLED,
	PCITOOL_ROM_WRITE
} pcitool_errno_t;


/*
 * PCITOOL_DEVICE_SET_INTR ioctl data structure to re-assign the interrupts.
 */
typedef struct pci_intr_set {
	uint32_t ino;		/* interrupt to set - to kernel */
	uint32_t cpu_id;	/* to: cpu to set / from: old cpu returned */
	pcitool_errno_t status;	/* from kernel */
} pci_intr_set_t;


/*
 * PCITOOL_DEVICE_GET_INTR ioctl data structure to dump out the
 * ino mapping information.
 */

typedef struct pci_intr_dev {
	uint32_t	dev_inst;	/* device instance - from kernel */
	char		driver_name[MAXMODCONFNAME];	/* from kernel */
	char		path[MAXPATHLEN]; /* device path - from kernel */
} pci_intr_dev_t;


typedef struct pci_intr_get {
	uint32_t	ino;		/* interrupt number - to kernel */
	uint8_t		num_devs_ret;	/* room for this # of devs to be */
					/* returned - to kernel */
					/* # devs returned - from kernel */
	uint8_t		num_devs;	/* # devs on this ino - from kernel */
					/* intrs enabled for devs if > 0 */
	uint8_t		ctlr;		/* controller number - from kernel */
	uint32_t	cpu_id;		/* cpu of interrupt - from kernel */
	pcitool_errno_t status;		/* returned status - from kernel */
	pci_intr_dev_t	dev[1];		/* start of variable device list */
					/* from kernel */
} pci_intr_get_t;

/*
 * Get the size needed to return the number of devices wanted.
 * Can't say num_devs - 1 as num_devs may be unsigned.
 */
#define	IGET_SIZE(num_devs) \
	(sizeof (pci_intr_get_t) - \
	sizeof (pci_intr_dev_t) + \
	(num_devs * sizeof (pci_intr_dev_t)))

/*
 * Size and endian fields for acc_attr bitmask.
 */
#define	PX_ACC_ATTR_SIZE_MASK		0x3
#define	PX_ACC_ATTR_SIZE_1		0x0
#define	PX_ACC_ATTR_SIZE_2		0x1
#define	PX_ACC_ATTR_SIZE_4		0x2
#define	PX_ACC_ATTR_SIZE_8		0x3

#define	PX_ACC_ATTR_ENDN_MASK		0x100
#define	PX_ACC_ATTR_ENDN_LTL		0x0
#define	PX_ACC_ATTR_ENDN_BIG		0x100

#define	PX_ACC_ATTR_SIZE(x)	(1 << (x & PX_ACC_ATTR_SIZE_MASK))

/*
 * Data stucture to read and write to pci device registers.
 * This is the argument to the following ioctls:
 *	PCITOOL_DEVICE_SET/GET_REG
 *	PCITOOL_NEXUS_SET/GET_REG
 */
typedef struct pci_reg {
	uint8_t		bus_no;		/* pci bus - to kernel */
	uint8_t		dev_no;		/* pci dev - to kernel */
	uint8_t		func_no;	/* pci function - to kernel */
	uint8_t		barnum;		/* bank (DEVCTL_NEXUS_SET/GET_REG) or */
					/*   BAR from pcitools_bar_t */
					/*   (DEVCTL_DEVICE_SET/GET_REG) */
					/*   to kernel */
	uint32_t	offset;		/* to kernel */
	uint32_t	acc_attr;	/* access attributes - to kernel */
	uint64_t	data;		/* to/from kernel */
	uint32_t	status;		/* from kernel */
	uint64_t	phys_addr;	/* from kernel */
} pci_reg_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_TOOLS_H */
