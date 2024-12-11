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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MC_H
#define	_SYS_MC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interface of Memory Controller driver
 *
 * Logical view: memory -> segment -> bank -> device group -> device
 * physical view: mc -> device group -> device
 *
 * MCIOC_MEM, MCIOC_SEG, MCIOC_CTRLCONF, MCIOC_CONTROL are
 * associated with various length struct. If given number is less than the
 * number in kernel, kernel will update the number and return EINVAL so that
 * user could allocate enough space for the struct and fill the right number
 * of ids at the struct.
 *
 * All varaiable number ids will be paired, global and local. Global id is
 * unique in the same object list and local id is only unique to
 * its upper layer. For instance, one memory module group has N memory modules.
 * local ids of this memory module group is from 0 to N - 1, but global id
 * is unique in all memory modules. So global id will be the key in the list
 * and pass it to driver to search. Local id will be returned to user
 * application via ioctl.
 */

#define	MCIOC		('M' << 8)
#define	MCIOC_MEMCONF	(MCIOC|8)
#define	MCIOC_MEM	(MCIOC|9)
#define	MCIOC_SEG	(MCIOC|10)
#define	MCIOC_BANK	(MCIOC|11)
#define	MCIOC_DEVGRP	(MCIOC|12)
#define	MCIOC_CTRLCONF	(MCIOC|13)
#define	MCIOC_CONTROL	(MCIOC|14)
#define	MCIOC_ECFLUSH	(MCIOC|15)

/*
 * libdevinfo property name for exporting the Memory Address
 * Decode Registers for each Logical bank. An array of [NBANK]
 * uint64_t's is created for each memory-controller node.
 */
#define	MEM_CFG_PROP_NAME	"logical-bank-ma-regs"

struct mc_ids {
	int	globalid;
	int	localid;
};

/*
 * Enabled memory controller is able to get memory-layout property, and
 * it could be with or without memory.
 */
struct mc_memconf {
	int nmcs;	/* The number of enabled memory controllers */
	int nsegments;	/* The number of memory segments */
	int nbanks;	/* The max. number of banks per segment */
	int ndevgrps;	/* The max. number of device groups per mc */
	int ndevs;	/* The max. number of devices per device group */
	int len_dev;	/* The length of device label */
	int xfer_size;	/* Data transfer size in CPU cache line */
};

struct mc_memory {
	uint64_t size;		/* size of physical memory */
	int nsegments;		/* The number of memory segments */
	struct mc_ids segmentids[1]; /* segment ids for next iteration */
};

struct mc_segment {
	int id;			/* unique segment id */
	int ifactor;		/* interleave factor for this segment */
	uint64_t base;		/* starting physical address */
	uint64_t size;		/* in bytes */
	int nbanks;		/* The number of banks at this segment */
	struct mc_ids bankids[1]; /* logical bank ids for next iteration */
};

struct mc_bank {
	int id;			/* unique id for logic bank */
	struct mc_ids devgrpid;	/* Only one device group id per logical bank */
	uint64_t mask;		/* If (Physic Address & MASK) == MATCH, */
	uint64_t match;		/* Physic Address is located at this bank. */
	uint64_t size;		/* memory size per logical bank */
};

struct mc_ctrlconf {
	int nmcs;		/* The number of enabled memory controllers */
	struct mc_ids mcids[1];	/* mc ids for next iteration */
};

struct mc_control {
	int id;			/* unique id for memory controllers */
	int ndevgrps;		/* The number of device groups on this mc */
	struct mc_ids devgrpids[1]; /* device group ids for next iteration */
};

struct mc_devgrp {
	int id;		/* unique id for device groups */
	int ndevices;	/* The number of available devices on this dev group */
	uint64_t size;	/* memory size per physical dimm group */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MC_H */
