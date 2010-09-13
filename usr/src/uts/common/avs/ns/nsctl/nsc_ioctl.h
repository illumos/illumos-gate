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

#ifndef _NSC_IOCTL_H
#define	_NSC_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/dkio.h>
#include <sys/vtoc.h>
#ifdef DKIOCPARTITION
#include <sys/efi_partition.h>
#endif

/*
 * Ioctl definitions for Storage Device.
 */

#define	_NSC_(x)			(('S'<<16)|('D'<<8)|(x))

#define	NSCIOC_OPEN		_NSC_(1)
#define	NSCIOC_RESERVE		_NSC_(2)
#define	NSCIOC_RELEASE		_NSC_(3)
#define	NSCIOC_PARTSIZE		_NSC_(4)
#define	NSCIOC_FREEZE		_NSC_(5)
#define	NSCIOC_UNFREEZE		_NSC_(6)
#define	NSCIOC_ISFROZEN		_NSC_(7)
#define	NSCIOC_POWERMSG		_NSC_(8)	/* UPS/PCU power state */
#define	NSCIOC_NSKERND		_NSC_(9)
#define	NSCIOC_GLOBAL_SIZES	_NSC_(10)	/* size of RM segs */
#define	NSCIOC_GLOBAL_DATA	_NSC_(11)
#define	NSCIOC_NVMEM_CLEAN	_NSC_(12)	/* mark nvm nsc_global clean */
#define	NSCIOC_NVMEM_CLEANF	_NSC_(13)	/* force mark clean */
#define	NSCIOC_BSIZE		_NSC_(14)	/* get partition size */


/*
 * Structure definitions.
 */


struct nscioc_open {
	char	path[NSC_MAXPATH];	/* Pathname */
	int	flag;			/* Flags */
	int	mode;			/* Open modes */
	int	pad[15];
};


struct nscioc_partsize {
	uint64_t	partsize;
};


struct nskernd {
	uint64_t data1;
	uint64_t data2;
	char    char1[NSC_MAXPATH];
	char    char2[NSC_MAXPATH];
	int	command;
};


struct nscioc_bsize {
	uint64_t vtoc;		/* (struct vtoc *) */
	uint64_t dki_info;	/* (struct dk_cinfo *) */
	uint64_t raw_fd;	/* dev_t of slice/partition */
	uint64_t p64;		/* (struct partition64 *) */
	int	efi;		/* do we have an EFI partition table? */
};


#ifdef _KERNEL
extern int nskernd_command(intptr_t, int, int *);
extern int nskern_bsize(struct nscioc_bsize *, int *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _NSC_IOCTL_H */
